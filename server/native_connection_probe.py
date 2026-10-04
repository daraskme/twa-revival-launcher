"""Opt-in, loopback-only native protocol lab. Never a public game server.

Reuses the working offline profile/data responses but overrides only exact paths
listed in a JSON fixture file. Does not launch/stop games, edit DLLs, or accept
cloud credentials. Fixtures are read on each request to permit bounded trials.
The separate --relay-handshake switch permits one explicit diagnostic XMPP
notification per ready room. With --custom-lobby, --pve-battle-probe, --xmpp
and --local-region together, /start_game instead freezes one private CPU
battle in the durable local lifecycle before sending its XMPP start notice.
The same PvE flag also supports ordinary local matchmaking. Neither mode
exposes a public matchmaking or battle service.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import ssl
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

import local_stack as offline
from f2p_fake import active_identity
from native_career_stats import NativeCareerStats
from native_career_history import backfill_completed
from native_career_profile import build_career_profile
from native_career_response import is_career_request, decorate_career_response
from local_battle_state import (BattleStateError, DEFAULT_BATTLE_STATE_PATH,
                                LocalBattleState)
from local_economy import EconomyError, LocalEconomy
from economy_backend import CloudEconomyBackend
from specialization_economy import SpecializationEconomy
from native_battle_maps import is_private_cpu_lobby_map
from native_custom_lobby import NativeCustomLobby, NativeLobbyError, PATHS, UNSUPPORTED_PATHS, decode_native_request
from native_postbattle_maps import POSTBATTLE_UI_MAP_ALIASES
from native_economy_service import (NativeEconomyService,
                                    native_final_result_rows,
                                    native_result_schema_fingerprint,
                                    resolve_native_final_outcome)
from native_xmpp_probe import NativeXmppProbe
from native_social_party import (PATHS as SOCIAL_PARTY_PATHS, NATIVE_PARTY_CAPACITY,
                                 REQUEST_FIELDS as SOCIAL_PARTY_REQUEST_FIELDS, PartyError)
from native_matchmaking import (GAME_CONFIG_FILENAME, NativeMatchmaking, PATHS as MATCHMAKING_PATHS,
                                ARBITRATION_FIELDS, BATTLE_MODE_PRESETS,
                                NATIVE_SELECTOR_GAME_MODES,
                                build_matchmaking_game_config, decode_arbitration_request,
                                decode_matchmaking_request)
from native_region_ping import NativeRegionPing, local_server_list
from native_pvp_coordinator import PvpCoordinatorError, _roster_policy
from native_auto_announcer import AutoAnnouncer
from native_user_storage import NativeUserStorage, NativeUserStorageError, read_bounded_body


DEFAULT_ECONOMY_STATE_PATH = Path(__file__).resolve().parent / 'offline_economy.json'
_ECONOMY_GLOBALS_LOCK = threading.RLock()
_ECONOMY_GLOBALS_GENERATION: tuple[object, int] | None = None
# Serialize only expensive compatibility-view construction.  Request handlers
# do not acquire this mutex for authoritative economy operations or direct
# profile responses, and builders hold neither economy nor globals locks while
# doing heavy work.
_ECONOMY_REFRESH_BUILD_LOCK = threading.Lock()
_BATTLE_RESULTS_SERVICE_PREFIX = (
    f"/{offline.STACK['stack']}-twa-battle-results.{offline.STACK['domain']}"
)
_CANONICAL_UUID_PATH = (
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
)
_PRIVATE_CPU_USER_ID = re.compile(r'cpu-private-[1-9][0-9]*')
_BATTLE_MODE_CONTROL_PATH = '/native-probe/battle-mode'
_UNIT_LOADOUT_CONTROL_PATH = '/native-probe/loadout/unit'
_UNIT_CONTROL_HEADER = 'X-TWA-Unit-Control'
_HEX_256 = re.compile(r'[0-9a-f]{64}')
_SPECIALIZATION_CONTROL_PATH = '/native-probe/specialization'
_SPECIALIZATION_UI_STATUS_PATH = '/native-probe/specialization-ui-status'
_SPECIALIZATION_REFRESH_ACK_PATH = '/native-probe/specialization-refresh-ack'
# These routes read the authoritative ``NativeEconomyService`` directly.
# Rebuilding catalogue/default/validation compatibility views before them is
# both redundant and harmful to the stock unit-drag refresh: the companion
# cannot raise the deferred-profile flag until the control POST returns.
# Static game-data requests refresh these views only when the saved generation
# changed.  A successful /profile POST performs the same stale check after its
# response is written.
_DIRECT_ECONOMY_PATHS = frozenset((
    _UNIT_LOADOUT_CONTROL_PATH,
    _SPECIALIZATION_CONTROL_PATH,
    _SPECIALIZATION_UI_STATUS_PATH,
    '/profile',
    '/tutorial-progress',
))
_PRIVATE_CPU_ADD_CONTROL_PATH = '/native-probe/private-cpu/add'
_PRIVATE_CPU_REMOVE_CONTROL_PATH = '/native-probe/private-cpu/remove'
_PRIVATE_CPU_CONTROL_PATHS = frozenset((
    _PRIVATE_CPU_ADD_CONTROL_PATH, _PRIVATE_CPU_REMOVE_CONTROL_PATH,
))
_PRIVATE_PROFILE_READY_TIMEOUT_SECONDS = 12.0
# SQLite allocation-context keys owned by this process' battle lifecycle.
# ``native_economy_service._CONTEXT_FIELDS`` is a closed allowlist, so these
# are removed before any economy call (see _complete_economy_battle).
_LIFECYCLE_CONTEXT_FIELDS = frozenset((
    'cloud_battle_id', 'cloud_reward_policy', 'pvp'))


@dataclass(frozen=True)
class UnitControlGuard:
    """Digest-only authorization for one owned helper and bridge run."""

    capability_sha256: str
    native_user_id: str
    session_sha256: str

    @classmethod
    def from_capability(cls, capability: object, identity: object):
        native_user_id = getattr(identity, 'native_user_id', None)
        session_sha256 = getattr(identity, 'session_token_hash', None)
        if (not isinstance(capability, str)
                or _HEX_256.fullmatch(capability) is None
                or not isinstance(native_user_id, str)
                or not isinstance(session_sha256, str)
                or _HEX_256.fullmatch(session_sha256) is None):
            raise ValueError('invalid unit-control binding')
        return cls(
            hashlib.sha256(capability.encode('ascii')).hexdigest(),
            native_user_id, session_sha256,
        )

    def authorizes(self, capability: object, identity: object) -> bool:
        if not isinstance(capability, str) \
                or _HEX_256.fullmatch(capability) is None:
            return False
        native_user_id = getattr(identity, 'native_user_id', None)
        session_sha256 = getattr(identity, 'session_token_hash', None)
        return (
            isinstance(native_user_id, str)
            and isinstance(session_sha256, str)
            and hmac.compare_digest(
                hashlib.sha256(capability.encode('ascii')).hexdigest(),
                self.capability_sha256,
            )
            and hmac.compare_digest(native_user_id, self.native_user_id)
            and hmac.compare_digest(session_sha256, self.session_sha256)
        )


def _local_native_user_id() -> str:
    """The one native user id this process serves.

    ``ProbeHandler.identity_resolver`` is authoritative once the companion
    bridge resolved a real ``+auth`` session; without one this keeps returning
    the historical single-user lab value from the built profile.  The two are
    checked against each other rather than trusted independently: a
    disagreement is a server integration failure, so it fails closed instead of
    authorizing either candidate.
    """
    profile_user = offline.PROFILE['profile']['user_id']
    resolver = ProbeHandler.identity_resolver
    if resolver is None:
        return profile_user
    native = resolver.native_user_id
    if native != profile_user:
        raise NativeLobbyError(503, 'native_identity_mismatch')
    return native
_PROFILE_TRACE_BOOLEAN_KEYS = frozenset((
    'private_profile_gate_saved_matches_current',
    'profile_timestamp_zero',
    'profile_timestamp_matches_current',
    'timestamp_zero',
    'timestamp_matches_current',
))


def _profile_request_timestamp_is_zero(request: object) -> bool | None:
    """Classify only the native profile request's exact timestamp shape.

    The timestamp value itself is intentionally never returned to the trace.
    ``type(...) is int`` excludes JSON booleans, which are Python ``bool``
    instances, and any additional request field makes the shape ambiguous.
    """
    if not isinstance(request, dict) or set(request) != {'timestamp'}:
        return None
    timestamp = request['timestamp']
    if type(timestamp) is not int:
        return None
    return timestamp == 0


class _PrivateProfileReadyGate:
    """Release one private post-battle profile read at a causal UI boundary.

    The native return flow starts ``/profile`` before its profile-message
    target is installed.  It requests the versions manifest and then
    ``catalogue.json`` only after the game data manager has advanced far
    enough to create that target.  Requiring both requests for the same
    generation rejects an old catalogue fetch.  The HTTP server is threaded,
    so the profile request can wait here while asset requests continue on
    other handler threads.
    """

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._generation = 0
        self._states: dict[int, dict[str, bool | int]] = {}
        self._waiters: dict[int, int] = {}

    def arm(self, profile_saved: int) -> int:
        if type(profile_saved) is not int or profile_saved < 0:
            raise ValueError('invalid profile watermark')
        with self._condition:
            self._generation += 1
            self._states[self._generation] = {
                'versions_seen': False,
                'ready': False,
                'profile_saved': profile_saved,
            }
            # A local user can have only one current private round. Keep a few
            # completed generations for waiters already holding their token,
            # without allowing the state table to grow forever.
            for generation in sorted(self._states)[:-4]:
                if self._waiters.get(generation, 0) == 0:
                    self._states.pop(generation, None)
            return self._generation

    def observe_versions_request(self) -> int | None:
        with self._condition:
            state = self._states.get(self._generation)
            if state is None or state['versions_seen']:
                return None
            state['versions_seen'] = True
            return self._generation

    def observe_catalogue_request(self) -> int | None:
        with self._condition:
            state = self._states.get(self._generation)
            if (state is None or not state['versions_seen'] or state['ready']):
                return None
            state['ready'] = True
            self._condition.notify_all()
            return self._generation

    def wait(self, timeout: float) -> dict:
        started = time.monotonic()
        with self._condition:
            generation = self._generation
            state = self._states.get(generation)
            if state is None:
                return {
                    'generation': 0,
                    'ready': False,
                    'reason': 'unarmed',
                    'waited_ms': 0,
                    'profile_saved': None,
                }
            self._waiters[generation] = self._waiters.get(generation, 0) + 1
            try:
                deadline = started + max(0.0, timeout)
                while not state['ready']:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    self._condition.wait(remaining)
                ready = state['ready']
            finally:
                remaining_waiters = self._waiters[generation] - 1
                if remaining_waiters:
                    self._waiters[generation] = remaining_waiters
                else:
                    self._waiters.pop(generation, None)
        return {
            'generation': generation,
            'ready': ready,
            'reason': 'catalogue_request' if ready else 'timeout',
            'waited_ms': max(0, int((time.monotonic() - started) * 1000)),
            'profile_saved': state['profile_saved'],
        }

    def snapshot(self) -> dict:
        with self._condition:
            state = self._states.get(self._generation)
            ready_generations = [generation for generation, value
                                 in self._states.items() if value['ready']]
            return {
                'generation': self._generation,
                'versions_generation': (self._generation
                                        if state is not None
                                        and state['versions_seen'] else 0),
                'ready_generation': max(ready_generations, default=0),
                'waiters': sum(self._waiters.values()),
            }

# The loader validates the exact source-table pairs and physical terrain.  The
# mapping is response-only; battle/result authority remains the real key.
_POSTBATTLE_UI_MAP_ALIASES = POSTBATTLE_UI_MAP_ALIASES


def _split_postbattle_reward(amount: object, count: int) -> list[int] | None:
    """Split one trusted ``*_cents`` reward without changing its total.

    Arena's result model stores earnings on each unit row, while the local
    economy receipt stores the account-authoritative total.  Prefer whole
    display units (100 cents) when a total is shared by several rows so the
    three unit cards do not lose a point merely through integer truncation.
    """
    if (type(amount) is not int or amount < 0 or count < 1):
        return None
    whole, subcent = divmod(amount, 100)
    each, extra = divmod(whole, count)
    shares = [(each + (index < extra)) * 100 for index in range(count)]
    shares[0] += subcent
    return shares


def _postbattle_ui_result_rows(
    results: list,
    context: object,
    *,
    settlement: object = None,
    user_id: object = None,
) -> list:
    """Build the response-only compatibility view for Arena's result UI.

    Durable final events, canonical result rows, settlement validation and the
    frozen allocation context retain the real battle key and unadorned native
    unit rows.  A deep copy keeps this UI view from mutating any authoritative
    value.

    The native final report contains combat statistics but no economy fields.
    ``game.dll``'s battle-results parser reads an optional ``rewards`` object
    from every ``unit_results`` row.  Populate that view from the already
    verified, exactly-once settlement receipt; otherwise the result panel
    correctly parses the battle but displays zero Free XP, silver and unit XP.
    """
    alias = (_POSTBATTLE_UI_MAP_ALIASES.get(context.get('map'))
             if isinstance(context, dict) else None)
    reward = None
    if (isinstance(settlement, dict) and settlement.get('verified') is True
            and isinstance(user_id, str)
            and isinstance(settlement.get('rewards'), dict)):
        reward = settlement['rewards']
    if alias is None and reward is None:
        return results
    compatible = copy.deepcopy(results)
    for row in compatible:
        if not isinstance(row, dict) or row.get('type') != 'results':
            continue
        details = row.get('result_details')
        if not isinstance(details, dict):
            continue
        if alias is not None:
            details['battle_map_key'] = alias
        if reward is None or row.get('user_id') != user_id:
            continue
        units = details.get('unit_results')
        if not isinstance(units, list) or not units:
            continue
        free_xp = _split_postbattle_reward(reward.get('free_xp_cents'), len(units))
        silver = _split_postbattle_reward(reward.get('silver_cents'), len(units))
        unit_totals = reward.get('unit_xp_by_unit')
        if free_xp is None or silver is None or not isinstance(unit_totals, dict):
            continue
        by_key: dict[str, list[int]] = {}
        for index, unit in enumerate(units):
            if isinstance(unit, dict) and isinstance(unit.get('unit_record_key'), str):
                by_key.setdefault(unit['unit_record_key'], []).append(index)
        unit_shares: dict[int, int] = {}
        valid = True
        for unit_key, total in unit_totals.items():
            indices = by_key.get(unit_key)
            shares = (_split_postbattle_reward(total, len(indices))
                      if isinstance(unit_key, str) and indices else None)
            if shares is None:
                valid = False
                break
            unit_shares.update(zip(indices, shares, strict=True))
        if not valid:
            continue
        for index, unit in enumerate(units):
            if not isinstance(unit, dict):
                continue
            earnings = {}
            unit_xp = unit_shares.get(index, 0)
            if unit_xp:
                earnings['end_battle_uxp'] = {'unit_xp_cents': unit_xp}
            if free_xp[index]:
                earnings['end_battle_fxp'] = {'free_xp_cents': free_xp[index]}
            if silver[index]:
                earnings['end_battle_silver'] = {'silver_cents': silver[index]}
            if earnings:
                unit['rewards'] = earnings
    return compatible


def _native_service_path(raw_path: str) -> str:
    """Normalize only the host-prefixed result path observed from game.dll.

    The local TLS/proxy setup presents this one service URL as
    ``/<service-host>/battle_results/<uuid>``.  Do not accept an arbitrary
    host-like prefix: doing so would turn unrelated paths into trusted result
    lookups.  Ordinary origin-form requests remain unchanged.
    """
    path = urlparse(raw_path).path.rstrip('/') or '/'
    match = re.fullmatch(
        re.escape(_BATTLE_RESULTS_SERVICE_PREFIX)
        + rf'(/battle_results/{_CANONICAL_UUID_PATH})',
        path,
    )
    return match.group(1) if match else path


def _seed_legacy_economy_state(state_path: Path, progression_path: Path,
                               native: dict) -> bool:
    """Atomically migrate the old schema-1 file into a new economy path.

    The source is read-only.  LocalEconomy performs its full schema/catalog
    validation against a temporary copy before that migrated current state is
    installed.  A later restart always prefers the existing economy file.
    """
    state_path, progression_path = Path(state_path), Path(progression_path)
    if state_path.exists() or not progression_path.is_file():
        return False

    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise EconomyError('duplicate_legacy_seed_key')
            result[key] = value
        return result

    def constant(_value):
        raise EconomyError('invalid_legacy_seed_number')

    try:
        source_text = progression_path.read_text(encoding='utf-8-sig')
        legacy = json.loads(source_text, object_pairs_hook=pairs,
                            parse_constant=constant)
    except EconomyError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EconomyError('invalid_legacy_seed_json') from exc
    if (not isinstance(legacy, dict) or legacy.get('schema_version') != 1
            or not isinstance(legacy.get('commanders'), dict)):
        raise EconomyError('unsupported_legacy_seed_schema')

    state_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
                mode='w', encoding='utf-8', dir=state_path.parent,
                prefix=state_path.name + '.seed.', suffix='.tmp',
                delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(legacy, handle, ensure_ascii=False, sort_keys=True,
                      allow_nan=False)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())

        migrated = LocalEconomy(native, temporary)
        germanicus = legacy['commanders'].get('rom_germanicus')
        if isinstance(germanicus, dict) and isinstance(germanicus.get('abilities'), dict):
            actual = migrated.snapshot()['commanders'].get('rom_germanicus', {}).get('abilities')
            if (not isinstance(actual, dict)
                    or not germanicus['abilities'].items() <= actual.items()):
                raise EconomyError('legacy_ability_migration_mismatch')

        # Do not overwrite a state another process completed while validation
        # ran.  That file is the authoritative restart state.
        if state_path.exists():
            return False
        os.replace(temporary, state_path)
        temporary = None
        return True
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _persistent_economy_service(state_path: Path,
                                progression_path: Path = offline.OFFLINE_PROGRESSION,
                                *,
                                backend: object | None = None,
                                identity: object | None = None,
                                zero_pve_rewards: bool = False,
                                bootstrap_new_specializations: bool = False,
                                ) -> NativeEconomyService:
    if type(bootstrap_new_specializations) is not bool:
        raise EconomyError('invalid_specialization_bootstrap')
    state_path = Path(state_path)
    if backend is None:
        _seed_legacy_economy_state(state_path, progression_path, offline._NATIVE)
        return NativeEconomyService.persistent(
            state_path, offline._CATALOG, offline._OFFICIAL, offline._NATIVE,
            zero_pve_rewards=zero_pve_rewards)
    # A non-file backend owns the authoritative blob, so the one-shot legacy
    # migration is deliberately skipped: seeding it would create a second,
    # divergent starting account beside the remote one.
    if bootstrap_new_specializations and not isinstance(
            backend, CloudEconomyBackend):
        raise EconomyError('specialization_bootstrap_requires_cloud')
    economy_type = (SpecializationEconomy
                    if bootstrap_new_specializations else LocalEconomy)
    economy_kwargs = ({'bootstrap_new_specializations': True, 'bootstrap_new_premiums': True}
                      if bootstrap_new_specializations else {})
    economy = economy_type(
        offline._NATIVE, backend=backend, identity=identity,
        zero_pve_rewards=zero_pve_rewards, **economy_kwargs,
    )
    return NativeEconomyService(
        economy, offline._CATALOG, offline._OFFICIAL, offline._NATIVE)


def _refresh_offline_economy_views(service: NativeEconomyService) -> dict:
    """Build one coherent snapshot and publish it with a generation CAS.

    Profile and catalogue both contain loadout-dependent data.  Building them
    from separate calls to ``snapshot()`` could create a graph that never
    existed, while a slow old request could later overwrite a newer publish.
    Expensive construction stays outside both locks; the economy lock is held
    only for the final saved comparison and the six global assignments.
    """
    global _ECONOMY_GLOBALS_GENERATION
    while True:
        snapshot = service.economy.snapshot()
        raw_saved = snapshot['saved']
        profile = service.adapter._build_profile_from_snapshot(snapshot)
        catalogue = service.adapter._build_catalogue_from_snapshot(snapshot)
        mappings = service.adapter.build_mappings()
        defaults = offline.build_defaults(catalogue, profile, offline._NATIVE)
        validation = offline.build_validation(
            profile,
            native=offline._NATIVE,
            equipment=offline._NATIVE_EQUIPMENT,
            consumables=offline._NATIVE_CONSUMABLES,
            unit_abilities=offline._NATIVE_UNIT_ABILITIES,
        )
        published: dict[str, object] = {}

        def publish() -> None:
            nonlocal published
            global _ECONOMY_GLOBALS_GENERATION
            with _ECONOMY_GLOBALS_LOCK:
                generation = _ECONOMY_GLOBALS_GENERATION
                if (generation is not None
                        and generation[0] is service
                        and generation[1] > raw_saved):
                    # A newer build already won.  Return its coherent profile
                    # instead of regressing any member of the global bundle.
                    published['profile'] = offline.PROFILE
                    return
                offline.CATALOGUE = catalogue
                offline.MAPPINGS = mappings
                offline.PROFILE = profile
                offline.PROFILE_STATE = service
                offline.DEFAULTS = defaults
                offline.VALIDATION = validation
                _ECONOMY_GLOBALS_GENERATION = (service, raw_saved)
                published['profile'] = profile

        if service.economy.publish_projection_if_current(snapshot, publish):
            return published['profile']  # type: ignore[return-value]


def _refresh_offline_economy_views_if_stale(
    service: NativeEconomyService,
) -> dict:
    """Reuse the coherent published bundle while its saved generation matches.

    The native client requests several static game-data documents together.
    Rebuilding the same catalogue/default/validation bundle before every one
    needlessly monopolizes the Python process and can delay the authoritative
    unit-loadout control POST and its correlated profile response by seconds.
    A snapshot is still taken so the decision is based on authoritative state;
    mutations fall through to the existing full builder and publication CAS.
    """
    def current_profile() -> dict | None:
        snapshot = service.economy.snapshot()
        raw_saved = snapshot['saved']
        reused: dict[str, object] = {}

        def reuse_if_published() -> None:
            with _ECONOMY_GLOBALS_LOCK:
                generation = _ECONOMY_GLOBALS_GENERATION
                if (generation is not None
                        and generation[0] is service
                        and generation[1] == raw_saved):
                    reused['profile'] = offline.PROFILE

        # The service rechecks ``snapshot`` while holding the economy lock and
        # invokes the callback under that lock.  This preserves the established
        # economy -> globals lock order and closes the mutation window between
        # snapshot and cache-hit decision.
        current = service.economy.publish_projection_if_current(
            snapshot, reuse_if_published,
        )
        if current and 'profile' in reused:
            return reused['profile']  # type: ignore[return-value]
        return None

    profile = current_profile()
    if profile is not None:
        return profile
    # Concurrent requests may all observe one new saved generation.  Let one
    # build it, then recheck after waiting so followers reuse its publication.
    # The mutex is independent of the authoritative economy/profile path.
    with _ECONOMY_REFRESH_BUILD_LOCK:
        profile = current_profile()
        if profile is not None:
            return profile
        return _refresh_offline_economy_views(service)


# Types aid native parser diagnosis without copying identifiers or values.
_TRACE_REQUEST_TYPE_KEYS = frozenset((
    'build_id', 'commander_id', 'game_checksum', 'game_data_hash', 'game_group',
    'length', 'map', 'max_players', 'private', 'profile_timestamp', 'region',
    'sessionguid', 'title', 'username', 'xmpp_region', 'game_id', 'battle_key',
    'ready', 'relay_server', 'user_id', 'battle_id',
    'appid', 'autotest', 'game_data_version', 'game_mode', 'player_regions',
    'steamname', 'version',
))


class _EventPairs(list):
    """JSON object pairs retained until endpoint-specific duplicate checks."""


def decode_social_party_request(path: str, raw: bytes, content_type: str, *, metadata=None):
    """Accept the observed stock invitation reply's identical nickname pair.

    Only the JSON request envelope of /respond_to_party_invitation receives
    this exception. Preserve every other pair for the existing strict decoder.
    BCFA30 and its BDE8A0 helper both serialize nickname; the live owned-client
    trace confirms exactly two equal strings. Different values remain errors.
    """
    if metadata is not None:
        metadata.clear()
    try:
        return decode_matchmaking_request(raw, content_type)
    except NativeLobbyError as error:
        if (error.code != 'duplicate_json_key'
                or path != '/respond_to_party_invitation'
                or content_type.partition(';')[0].strip().lower() != 'application/json'):
            raise

    def invalid_constant(_value):
        raise NativeLobbyError(400, 'invalid_json_number')

    def emit(value):
        if isinstance(value, _EventPairs):
            return '{' + ','.join(json.dumps(key, ensure_ascii=False) + ':' + emit(item)
                                  for key, item in value) + '}'
        if isinstance(value, list):
            return '[' + ','.join(emit(item) for item in value) + ']'
        return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':'))

    try:
        pairs = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=_EventPairs,
                           parse_constant=invalid_constant)
        if (not isinstance(pairs, _EventPairs) or len(pairs) != 2
                or {key for key, _ in pairs} != {'headers', 'request'}):
            raise NativeLobbyError(400, 'duplicate_json_key')
        request = next(value for key, value in pairs if key == 'request')
        if not isinstance(request, _EventPairs):
            raise NativeLobbyError(400, 'duplicate_json_key')
        nicknames = [value for key, value in request if key == 'nickname']
        if (len(nicknames) != 2 or any(type(value) is not str for value in nicknames)
                or not 1 <= len(nicknames[0]) <= 256 or nicknames[0] != nicknames[1]):
            raise NativeLobbyError(400, 'duplicate_json_key')
        normalized_request = _EventPairs()
        seen = False
        for key, value in request:
            if key == 'nickname':
                if seen:
                    continue
                seen = True
            normalized_request.append((key, value))
        normalized = _EventPairs((key, normalized_request if key == 'request' else value)
                                 for key, value in pairs)
        result = decode_matchmaking_request(emit(normalized).encode('utf-8'), content_type)
        if metadata is not None:
            metadata.update(kind='request_nickname', count=2, same_value=True)
        return result
    except NativeLobbyError:
        raise
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise NativeLobbyError(400, 'invalid_json') from None



def _social_party_decode_metadata(raw: bytes, content_type: str, code: str) -> dict:
    """Describe a rejected party payload without retaining names or values.

    This is diagnostic-only: it returns no decoded request and never changes
    the existing decoder's decision. Comparisons use the first and current
    occurrences, preserve JSON types, and do not authenticate any header key.
    """
    errors = frozenset(('duplicate_json_key', 'invalid_json', 'invalid_json_number',
        'invalid_utf8', 'invalid_form', 'invalid_body_type', 'body_too_large',
        'unsupported_content_type', 'unsupported_charset', 'body_must_be_object',
        'ambiguous_request_envelope', 'invalid_request_envelope'))
    media = content_type.partition(';')[0].strip().lower() if isinstance(content_type, str) else ''
    result = {'error': code if code in errors else 'other',
              'format': {'application/json': 'json', 'application/x-www-form-urlencoded': 'form'}.get(media, 'other'),
              'analysis': 'not_needed', 'duplicates': [], 'duplicates_truncated': False}
    if code != 'duplicate_json_key':
        return result
    if type(raw) is not bytes or len(raw) > 65536 or result['format'] == 'other':
        result['analysis'] = 'unavailable'
        return result
    known_request = frozenset().union(*(fields[1] for fields in SOCIAL_PARTY_REQUEST_FIELDS.values()))
    remaining = 2048

    class DiagnosticLimit(Exception):
        pass

    def step(depth=0):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 32:
            raise DiagnosticLimit()

    def value_type(value):
        return {_EventPairs: 'object', list: 'list', str: 'str', int: 'int',
                float: 'float', bool: 'bool', type(None): 'null'}.get(type(value), 'other')

    def same_value(left, right, depth=0):
        step(depth)
        if type(left) is not type(right):
            return False
        if isinstance(left, _EventPairs):
            left_keys, right_keys = [key for key, _ in left], [key for key, _ in right]
            if len(set(left_keys)) == len(left_keys) and len(set(right_keys)) == len(right_keys):
                a, b = dict(left), dict(right)
                return a.keys() == b.keys() and all(same_value(a[key], b[key], depth + 1) for key in a)
            return len(left) == len(right) and all(a == b and same_value(x, y, depth + 1)
                for (a, x), (b, y) in zip(left, right))
        if isinstance(left, list):
            return len(left) == len(right) and all(same_value(a, b, depth + 1) for a, b in zip(left, right))
        return left == right

    def kind(path, key):
        if path == ('headers',):
            return 'header_' + key if key in ('key', 'user_id', 'request_version') else 'other_header_key'
        if path == ('request',):
            return 'request_' + key if key in known_request else 'other_request_key'
        if not path:
            if key in ('headers', 'request'):
                return 'envelope_' + key
            return 'request_' + key if key in known_request else 'other_envelope_key'
        if path == ('form',):
            return 'form_' + key if key in ('headers', 'request') or key in known_request else 'other_form_key'
        return 'other_nested_key'

    def walk(value, path=()):
        step(len(path))
        if isinstance(value, _EventPairs):
            first, counts = {}, {}
            for key, item in value:
                step(len(path))
                counts[key] = counts.get(key, 0) + 1
                if key in first:
                    if len(result['duplicates']) < 8:
                        old = first[key]
                        category = kind(path, key)
                        row = {'kind': category, 'count': counts[key],
                               'types': [value_type(old), value_type(item)],
                               'same_value': same_value(old, item), 'depth': len(path)}
                        if category == 'header_key':
                            row['no_key'] = [type(old) is str and old == 'no_key',
                                             type(item) is str and item == 'no_key']
                        result['duplicates'].append(row)
                    else:
                        result['duplicates_truncated'] = True
                else:
                    first[key] = item
                walk(item, path + (key,))
        elif isinstance(value, list):
            for item in value:
                walk(item, path + ('[]',))

    def invalid_constant(_value):
        raise ValueError()

    def read_json(text):
        return json.loads(text, object_pairs_hook=_EventPairs, parse_constant=invalid_constant)

    try:
        text = raw.decode('utf-8', 'strict')
        if result['format'] == 'form':
            if re.search(r'%(?![0-9a-fA-F]{2})', text):
                raise ValueError()
            fields = _EventPairs(parse_qsl(text, keep_blank_values=True, strict_parsing=True,
                encoding='utf-8', errors='strict', max_num_fields=64))
            walk(fields, ('form',))
            for key, item in fields:
                if key in ('headers', 'request'):
                    walk(read_json(item), (key,))
        else:
            walk(read_json(text))
        result['analysis'] = 'parsed'
    except DiagnosticLimit:
        result['analysis'] = 'limited'
        result['duplicates_truncated'] = True
    except (ValueError, TypeError, UnicodeError, RecursionError):
        result['analysis'] = 'invalid_input'
    return result


def _same_json_value(left: object, right: object) -> bool:
    """Compare decoded JSON without Python's ``True == 1`` coercion."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return (left.keys() == right.keys()
                and all(_same_json_value(left[key], right[key]) for key in left))
    if isinstance(left, list):
        return (len(left) == len(right)
                and all(_same_json_value(a, b) for a, b in zip(left, right)))
    return left == right


def decode_event_request(raw: bytes, content_type: str, *,
                         metadata: dict | None = None) -> tuple[dict, dict, bool]:
    """Decode native ``/event`` with two narrow serializer exceptions.

    The general native decoder remains strict.  This endpoint alone accepts:

    * the proven native header pair ``key=no_key`` followed by one string
      context key, retaining the latter.

    Request, envelope and form-field duplicates, other header duplicates and
    third copies remain errors. Canonicalizing only the deterministic native
    header bug keeps the durable final-event digest, party binding, exact-once
    settlement and strict economy schema unchanged.
    Metadata contains shapes and comparisons only, never keys or values.
    """
    if metadata is not None:
        metadata.clear()
        metadata['duplicates'] = []
    try:
        return decode_native_request(raw, content_type)
    except NativeLobbyError as error:
        if error.code != 'duplicate_json_key':
            raise

    def invalid_constant(_value):
        raise NativeLobbyError(400, 'invalid_json_number')

    def read_json(value: str):
        return json.loads(value, object_pairs_hook=_EventPairs,
                          parse_constant=invalid_constant)

    def record(kind: str, count: int, first: object, second: object,
               accepted: bool, depth: int) -> None:
        if metadata is None or len(metadata['duplicates']) >= 8:
            return
        metadata['duplicates'].append({
            'kind': kind,
            'count': count,
            'types': [type(first).__name__, type(second).__name__],
            'same_value': _same_json_value(first, second),
            'accepted': accepted,
            'depth': depth,
        })

    def collapse(value: object, path: tuple[str, ...] = ()) -> object:
        if isinstance(value, _EventPairs):
            result: dict[str, object] = {}
            counts: dict[str, int] = {}
            for key, item in value:
                item = collapse(item, path + (key,))
                counts[key] = counts.get(key, 0) + 1
                if key in result:
                    first = result[key]
                    native_header = path == ('headers',) and key == 'key'
                    native_header_pair = (
                        native_header and counts[key] == 2
                        and type(first) is str and type(item) is str
                        and first == 'no_key'
                        and len(first) <= 4096 and len(item) <= 4096)
                    accepted = native_header_pair
                    record('native_header_key' if native_header else 'other',
                           counts[key], first, item, accepted, len(path))
                    if not accepted:
                        raise NativeLobbyError(400, 'duplicate_json_key')
                result[key] = item
            return result
        if isinstance(value, list):
            return [collapse(item, path + ('[]',))
                    for item in value]
        return value

    try:
        text = raw.decode('utf-8', 'strict')
        media = content_type.partition(';')[0].strip().lower()
        if media == 'application/x-www-form-urlencoded':
            fields = _EventPairs(parse_qsl(
                text, keep_blank_values=True, strict_parsing=True,
                encoding='utf-8', errors='strict', max_num_fields=64))
            # Form and envelope keys are transport framing, never event data.
            body = collapse(fields)
            if not isinstance(body, dict):
                raise NativeLobbyError(400, 'invalid_json')
            if 'request' in body:
                body['request'] = collapse(read_json(body['request']),
                                           ('request',))
            if 'headers' in body:
                body['headers'] = collapse(read_json(body['headers']),
                                            ('headers',))
        else:
            parsed = read_json(text)
            if isinstance(parsed, _EventPairs):
                # A body with a request member is an envelope. Otherwise the
                # root object itself is the request supported by the strict
                # decoder's flat-JSON convention.
                body = collapse(parsed)
            else:
                body = collapse(parsed)
        normalized = json.dumps(
            body, separators=(',', ':'), ensure_ascii=False,
            allow_nan=False).encode('utf-8')
        return decode_native_request(normalized, 'application/json')
    except NativeLobbyError:
        raise
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise NativeLobbyError(400, 'invalid_json') from None


@dataclass(frozen=True)
class BattleCompletion:
    """Validated output of an optional, retry-safe economy callback.

    The callback may mutate a server-owned economy, but it must use battle_id
    as its idempotency key because an identical final HTTP request can be
    retried after a process or connection failure.
    """

    results: list
    settlement: dict | None = None


_PRIVATE_BATTLE_ENTITLEMENTS = {
    'scope': 'battle_only',
    'persist_to_profile': False,
    'all_units': True,
    'all_commander_abilities': True,
    'all_equipment': True,
    'all_consumables': True,
}
_PRIVATE_ZERO_REWARDS = {
    'free_xp_cents': 0,
    'silver_cents': 0,
    'commander_xp_cents': 0,
    'unit_xp_cents': 0,
    'unit_xp_by_unit': {},
}
_PRIVATE_ZERO_COST_FIELDS = (
    'room_creation_cost_silver_cents',
    'battle_cost_silver_cents',
    'commander_unlock_cost_silver_cents',
    'unit_unlock_cost_silver_cents',
    'ability_unlock_cost_silver_cents',
    'equipment_unlock_cost_silver_cents',
    'consumable_cost_silver_cents',
)


def _final_battle_key(value: object, context: object) -> int:
    """Decode the credential using only its frozen allocation mode.

    Normal matchmaking publishes a canonical lowercase hexadecimal string.
    Native custom games publish a canonical decimal uint64 string.  A decimal
    key containing only 0-9 is also syntactically valid hexadecimal, so the
    untrusted request cannot choose the radix itself.
    """
    private = isinstance(context, dict) and context.get('mode') == 'private'
    if private:
        if (type(value) is not str or not re.fullmatch(r'[1-9][0-9]{0,19}', value)
                or int(value) >= 1 << 64 or str(int(value)) != value):
            raise NativeLobbyError(400, 'invalid_battle_event_credential')
        return int(value)
    if (type(value) is not str or not 1 <= len(value) <= 16
            or any(char not in '0123456789abcdef' for char in value)):
        raise NativeLobbyError(400, 'invalid_battle_event_credential')
    result = int(value, 16)
    if result == 0 or format(result, 'x') != value:
        raise NativeLobbyError(400, 'invalid_battle_event_credential')
    return result


def _private_battle_manifest(game: object, lab_state: object
                             ) -> tuple[str, int, str, dict]:
    """Validate one server-built custom room and freeze its battle contract."""
    if not isinstance(game, dict) or not isinstance(lab_state, dict):
        raise BattleStateError('invalid_battle_roster')
    room_game_id = game.get('game_id')
    battle_id = lab_state.get('battle_instance_id')
    if (type(room_game_id) is not str
            or re.fullmatch(_CANONICAL_UUID_PATH, room_game_id) is None
            or type(battle_id) is not str
            or re.fullmatch(_CANONICAL_UUID_PATH, battle_id) is None):
        raise BattleStateError('invalid_battle_id')
    battle_key = _final_battle_key(game.get('battle_key'), {'mode': 'private'})
    try:
        local_user = _local_native_user_id()
    except NativeLobbyError:
        raise BattleStateError('invalid_battle_roster') from None
    players = game.get('players')
    settings = game.get('settings')
    cpu_opponents = lab_state.get('cpu_opponents')
    if (not isinstance(players, list) or not isinstance(settings, dict)
            or not is_private_cpu_lobby_map(settings.get('map'))
            or game.get('owner_id') != local_user
            # ``privacy`` controls whether the native custom room is listed;
            # it does not decide whether this trusted endpoint is a private
            # battle economically.  The shipped client defaults it to false.
            or type(settings.get('privacy')) is not bool
            or game.get('relay_server') != '127.0.0.1:19000'
            or lab_state.get('ready') is not True
            or lab_state.get('battle_started') is not False
            or lab_state.get('relay_probe') is not True
            or lab_state.get('reward_policy') != 'none'
            or type(cpu_opponents) is not int or not 1 <= cpu_opponents <= 10
            or any(type(lab_state.get(field)) is not int
                   or lab_state.get(field) != 0
                   for field in _PRIVATE_ZERO_COST_FIELDS)
            or not _same_json_value(lab_state.get('private_entitlements'),
                                    _PRIVATE_BATTLE_ENTITLEMENTS)):
        raise BattleStateError('invalid_battle_roster')
    humans = [row for row in players
              if isinstance(row, dict) and row.get('is_ai') is False]
    cpus = [row for row in players
            if isinstance(row, dict) and row.get('is_ai') is True]
    if (len(humans) != 1 or humans[0].get('user_id') != local_user
            or humans[0].get('team_id') != 1 or humans[0].get('ready') is not True
            or len(cpus) != cpu_opponents
            or any(row.get('team_id') != 2 or row.get('ready') is not True
                   for row in cpus)
            or len(players) != len(humans) + len(cpus)):
        raise BattleStateError('invalid_battle_roster')
    participant_ids = [row.get('user_id') for row in players]
    if (any(type(value) is not str or not 1 <= len(value) <= 128
            for value in participant_ids)
            or len(set(participant_ids)) != len(participant_ids)
            or any(_PRIVATE_CPU_USER_ID.fullmatch(row['user_id']) is None
                   for row in cpus)):
        raise BattleStateError('invalid_battle_roster')
    details = humans[0].get('profile_matchmaking_details')
    commander_key = lab_state.get('commander_key')
    unit_tiers = lab_state.get('unit_tiers')
    battle_tier = lab_state.get('battle_tier')
    if (not isinstance(details, dict)
            or not isinstance(commander_key, str) or not commander_key
            or type(details.get('commander_tier')) is not int
            or details.get('commander_tier') != lab_state.get('native_commander_tier')
            or not isinstance(details.get('full_squad_setup'), list)
            or not isinstance(unit_tiers, list) or len(unit_tiers) != 3
            or any(type(value) is not int or not 1 <= value <= 10
                   for value in unit_tiers)
            or type(battle_tier) is not int or battle_tier != max(unit_tiers)
            or lab_state.get('pve_enemy_tier') != battle_tier):
        raise BattleStateError('invalid_battle_roster')
    context = {
        'mode': 'private',
        'private': True,
        'lobby_visibility_private': settings['privacy'],
        'map': settings['map'],
        'party_id': room_game_id,
        'room_game_id': room_game_id,
        'battle_instance_id': battle_id,
        # Native custom battles do not create a matchmaking party.  Their
        # final results therefore report an empty party string for the local
        # human as well as server-authored CPU rows.  Keep the arbitration
        # identity above separate from this observed result identity.
        'result_party_id': '',
        'commander_key': commander_key,
        'commander_tier': details['commander_tier'],
        'unit_tiers': copy.deepcopy(unit_tiers),
        'battle_tier': battle_tier,
        'pve_enemy_tier': lab_state.get('pve_enemy_tier'),
        'full_squad_setup': copy.deepcopy(details['full_squad_setup']),
        'cpu_opponents': cpu_opponents,
        'result_participants': [{
            'user_id': row['user_id'],
            'party_id': '',
            'is_ai': row['is_ai'],
        } for row in players],
        'reward_policy': 'none',
        'reward_multiplier': 0,
        'room_creation_cost_silver_cents': 0,
        'battle_cost_silver_cents': 0,
        'commander_unlock_cost_silver_cents': 0,
        'unit_unlock_cost_silver_cents': 0,
        'ability_unlock_cost_silver_cents': 0,
        'equipment_unlock_cost_silver_cents': 0,
        'consumable_cost_silver_cents': 0,
        'private_entitlements': copy.deepcopy(_PRIVATE_BATTLE_ENTITLEMENTS),
    }
    launch_name = getattr(active_identity(), 'display_name', None)
    if launch_name is not None:
        context['display_name'] = launch_name
    return battle_id, battle_key, local_user, context


def _start_private_cpu_battle(
    state: LocalBattleState,
    notify: Callable[[str], int],
    trace: Callable[[dict], None],
    game: dict,
    lab_state: dict,
) -> int:
    """Allocate and enroll the human before publishing custom-game start."""
    battle_id, battle_key, user_id, context = _private_battle_manifest(
        game, lab_state)
    snapshot, allocated = state.allocate(
        battle_id, [user_id], context, battle_key=battle_key,
        # Native custom games serialize the complete room population in
        # GAME_JOIN, including server-authored CPU rows.  This differs from
        # ordinary PvE matchmaking, whose wire count contains humans only.
        expected_players=1 + context['cpu_opponents'])
    snapshot, enrolled = state.enroll(battle_id, user_id)
    if snapshot['phase'] in {
            'ticking', 'result_reported', 'result_ready', 'settled', 'delivered'}:
        # A custom XMPP send can fail after the client received enough bytes to
        # join the relay.  The verified relay transition is stronger evidence
        # than another notification; let the lobby mark its local start once.
        trace({'event': 'private_battle_start_recovered',
               'cpu_opponents': context['cpu_opponents']})
        return 1
    if snapshot['phase'] != 'enrolled':
        raise BattleStateError('battle_not_enrolled')
    # Publish the stable native room UUID only after this immutable round has
    # been durably allocated and enrolled.  The relay is a separate process
    # and resolves this alias from the same SQLite database before GAME_JOIN.
    state.bind_wire_battle_id(context['room_game_id'], battle_id)
    trace({'event': 'private_battle_prepared', 'allocated': allocated,
           'enrolled': enrolled, 'cpu_opponents': context['cpu_opponents']})
    return notify(context['room_game_id'])


def _complete_private_battle(
    state: LocalBattleState,
    battle_id: str,
    user_id: str,
    event: dict,
    rows: list,
) -> BattleCompletion:
    """Validate a private final and persist a deterministic zero settlement."""
    snapshot = state.snapshot(battle_id)
    context = snapshot['context']
    zero_fields = ('reward_multiplier',) + _PRIVATE_ZERO_COST_FIELDS
    if (context.get('mode') != 'private'
            or context.get('private') is not True
            or context.get('reward_policy') != 'none'
            or any(type(context.get(field)) is not int
                   or context.get(field) != 0 for field in zero_fields)
            or not isinstance(context.get('party_id'), str)
            or context.get('result_party_id') != ''
            or not is_private_cpu_lobby_map(context.get('map'))
            or not isinstance(context.get('commander_key'), str)
            or not _same_json_value(context.get('private_entitlements'),
                                    _PRIVATE_BATTLE_ENTITLEMENTS)):
        raise EconomyError('invalid_private_battle_context')
    outcome, verified = resolve_native_final_outcome(
        event,
        user_id=user_id,
        party_id=context.get('result_party_id'),
        map_key=context.get('map'),
        commander_key=context.get('commander_key'),
        result_participants=context.get('result_participants'),
        custom_battle_no_party=True,
        display_name=context.get('display_name'),
    )
    settlement = {
        'match_id': battle_id,
        'mode': 'private',
        'outcome': outcome,
        'verified': verified,
        'reward_policy': 'none',
        'rewards': copy.deepcopy(_PRIVATE_ZERO_REWARDS),
        'room_creation_cost_silver_cents': 0,
        'battle_cost_silver_cents': 0,
        'commander_unlock_cost_silver_cents': 0,
        'unit_unlock_cost_silver_cents': 0,
        'ability_unlock_cost_silver_cents': 0,
        'equipment_unlock_cost_silver_cents': 0,
        'consumable_cost_silver_cents': 0,
        'private_entitlements': copy.deepcopy(_PRIVATE_BATTLE_ENTITLEMENTS),
        'profile_persisted': False,
    }
    # Private results stay in LocalBattleState only.  In particular, do not
    # advance the economy/profile watermark: the battle-local result panel
    # needs performance rows, while the persistent account must remain byte
    # for byte unchanged.
    return BattleCompletion(rows, settlement)


def _new_private_battle_key() -> int:
    return secrets.randbelow((1 << 64) - 1) + 1


def _complete_economy_battle(
    service: NativeEconomyService,
    state: LocalBattleState,
    trace: Callable[[dict], None],
    battle_id: str,
    _user_id: str,
    event: dict,
    rows: list,
    authority: object | None = None,
) -> BattleCompletion:
    """Settle verified rewards while preserving the native result rows."""
    snapshot = state.snapshot(battle_id)
    context = snapshot['context']
    # ``cloud_battle_id`` / ``pvp`` are lifecycle metadata this process added;
    # the economy service validates its allocation context against a closed
    # allowlist and must never see them.
    economy_context = {key: value for key, value in context.items()
                       if key not in _LIFECYCLE_CONTEXT_FIELDS}
    decision = None
    if authority is not None:
        decision = _authorize_cloud_settlement(
            service, authority, trace, battle_id, context, event, rows)
    try:
        settlement = service.settle_native_public_result(
            battle_id, event, economy_context,
            battle_phase=snapshot['phase'])
    except EconomyError as error:
        # Unsupported or mismatched result data earns nothing, but the battle
        # report remains available to the native battle-results consumer.
        if authority is not None:
            service.economy.discard_settlement_award(battle_id)
        trace({'event': 'economy_settlement_rejected',
               'economy_error': error.code})
        return BattleCompletion(rows)
    if decision is not None:
        # The client's result screen must render even when the Worker never
        # answered; the pending marker is durable so an operator can replay.
        settlement = {**settlement,
                      'reward_authority': decision['authority'],
                      'settlement_pending': decision['settlement_pending']}
        if decision.get('disputed') is True:
            # PvP result_disagreement: zero was applied and the Worker holds
            # the battle for review; the rows still reach the result screen.
            settlement['disputed'] = True
    _refresh_offline_economy_views(service)
    return BattleCompletion(rows, settlement)


def _authorize_cloud_settlement(
    service: NativeEconomyService,
    authority: object,
    trace: Callable[[dict], None],
    battle_id: str,
    context: dict,
    event: dict,
    rows: list,
) -> dict:
    """Ask the Worker for this battle's amounts before the local settlement.

    The outcome is resolved here with exactly the same frozen-context rule the
    economy service applies moments later, so the amounts posted to the Worker
    describe the battle the settlement will actually record.
    """
    try:
        outcome, verified = resolve_native_final_outcome(
            event,
            user_id=service.user_id,
            party_id=context.get('party_id'),
            map_key=context.get('map'),
            commander_key=context.get('commander_key'),
            display_name=context.get('display_name'),
            result_participants=context.get('result_participants'),
            roster_policy=(context.get('pvp', {}).get('roster_policy')
                           if isinstance(context.get('pvp'), dict) else
                           context.get('roster_policy')),
        )
    except (EconomyError, KeyError, TypeError, ValueError) as error:
        # No verified outcome means no authorized amount: register zero so the
        # local quote can never be applied behind the authority's back.
        return authority.fail_closed(
            service.economy, battle_id,
            getattr(error, 'code', 'unresolved_outcome'))
    unit_item_ids = context.get('unit_item_ids')
    decision = authority.authorize(
        service.economy,
        match_id=battle_id,
        cloud_battle_id=context.get('cloud_battle_id'),
        battle_tier=context.get('battle_tier'),
        unit_item_ids=unit_item_ids if isinstance(unit_item_ids, list) else [],
        outcome=outcome,
        verified=verified,
        durable_event=event,
        result_rows=rows,
        reward_policy=(context.get('pvp', {}).get('reward_policy')
                       if isinstance(context.get('pvp'), dict)
                       else context.get('cloud_reward_policy')),
    )
    trace({'event': 'cloud_settlement_decision',
           'authority': decision['authority'],
           'settlement_pending': decision['settlement_pending'],
           'reason': decision['reason']})
    return decision


class ProbeHandler(offline.Handler):
    fixture_path: Path
    trace_path: Path
    trace_lock = threading.Lock()
    custom_lobby: NativeCustomLobby | None = None
    # Optional authenticated Worker-room projection.  It receives custom
    # lobby routes before the legacy single-owner local implementation; None
    # preserves that implementation byte-for-byte.
    private_cloud_adapter: object | None = None
    native_social_party: object | None = None
    party_loadout_changed: Callable[[], None] | None = None
    xmpp_hub: NativeXmppProbe | None = None
    relay_handshake_enabled = False
    matchmaking: NativeMatchmaking | None = None
    battle_state: LocalBattleState | None = None
    economy_service: NativeEconomyService | None = None
    completion_callback: Callable[[str, str, dict, list], BattleCompletion] | None = None
    local_region_enabled = False
    # Resolves the ``+auth`` session the running game presented.  ``None``
    # keeps the legacy single-user lab identity (``f2p_fake.PLAYER``).
    identity_resolver: object | None = None
    # ``None`` preserves the explicit local/manual helper contract.  An
    # authenticated owned launch installs a digest-only per-run guard.
    unit_control_guard: UnitControlGuard | None = None
    # Registers each standard-PvE battle with the Cloudflare Worker and applies
    # the settlement it returns.  ``None`` = pure-local lab behaviour.
    settlement_authority: object | None = None
    # Generated game_config is opt-in.  Private CPU battle setup consumes it
    # even though ordinary NativeMatchmaking is intentionally absent.
    game_config_enabled = False
    # Paired game.dll/UI capability.  False keeps the historical two-row
    # config and rejects the four direct selector tokens.
    native_five_mode_selector = False
    private_profile_ready_gate = _PrivateProfileReadyGate()
    private_profile_ready_timeout = _PRIVATE_PROFILE_READY_TIMEOUT_SECONDS
    # Party-id generation acknowledged only after its matchmake response body
    # is written. A delayed old response cannot release a replacement queue.
    auto_pve_queue_ack_lock = threading.Lock()
    auto_pve_queue_acks: set[str] = set()
    native_user_storage: NativeUserStorage | None = None
    career_store: NativeCareerStats | None = None
    career_cloud: object | None = None
    career_cloud_required = False

    def _request_cloud_career_refresh(self) -> None:
        cloud = type(self).career_cloud
        if cloud is not None:
            try:
                cloud.request_refresh()
            except (ValueError, TypeError, RuntimeError, OSError) as error:
                self._trace({'event': 'career_cloud_refresh_failed',
                             'error_type': type(error).__name__})

    def _add_career_response(self, code: int, body: bytes) -> bytes:
        self._career_response_applied = False
        store = type(self).career_store
        if ((store is None and not type(self).career_cloud_required)
                or code != 200 or self.command != 'POST'
                or _native_service_path(self.path).rstrip('/').lower() != '/profile'
                or not is_career_request(getattr(self, '_body', b''))):
            return body
        try:
            user_id = _local_native_user_id()
            if type(self).career_cloud_required:
                self._request_cloud_career_refresh()
                cloud = type(self).career_cloud
                summary = None if cloud is None else cloud.summary(user_id)
                if summary is None:
                    # An unscoped local history must never masquerade
                    # as another environment's cloud account snapshot.
                    return body
            else:
                summary = store.summary(user_id)
            career = build_career_profile(summary, user_id, offline._NATIVE)
            decorated = decorate_career_response(body, career)
        except (ValueError, TypeError, KeyError, RuntimeError, OSError, sqlite3.Error) as error:
            self._trace({'event': 'career_response_failed',
                         'error_type': type(error).__name__})
            return body
        self._career_response_applied = True
        self._trace({'event': 'career_profile_response',
                     'source': 'cloudflare' if type(self).career_cloud_required else 'local',
                     'battles': summary['overall']['battles'],
                     'last_updated': summary['last_updated']})
        return decorated

    def _record_career_completion(self, battle_id: str, user_id: str,
                                  event: dict, settlement: dict) -> None:
        # The Worker has already settled this result; refresh its
        # view even if the optional local archive write fails.
        self._request_cloud_career_refresh()
        store = type(self).career_store
        if store is None:
            return
        try:
            context = self.battle_state.snapshot(battle_id)['context']
            result = store.record_completed(context, event, settlement, user_id)
            self._trace({'event': 'career_completion_recorded', **result})
        except (ValueError, TypeError, KeyError, OSError, sqlite3.Error) as error:
            # The canonical final and settlement are already durable. Keep
            # native result delivery working; startup history replay repairs
            # a missed career write without issuing another economy award.
            self._trace({'event': 'career_completion_failed',
                         'error_type': type(error).__name__})

    @classmethod
    def _ack_auto_pve_queue_response(cls, generation: str) -> None:
        with cls.auto_pve_queue_ack_lock:
            cls.auto_pve_queue_acks.add(generation)

    @classmethod
    def _finish_auto_pve_queue_response(cls, generation: str | None,
                                        write_succeeded: bool) -> None:
        if write_succeeded and isinstance(generation, str):
            cls._ack_auto_pve_queue_response(generation)

    @classmethod
    def _clear_auto_pve_queue_response(cls, generation: str | None) -> None:
        if not isinstance(generation, str):
            return
        with cls.auto_pve_queue_ack_lock:
            cls.auto_pve_queue_acks.discard(generation)

    @classmethod
    def _auto_pve_queue_response_ready(cls, generation: str | None) -> bool:
        if not isinstance(generation, str):
            return False
        with cls.auto_pve_queue_ack_lock:
            return generation in cls.auto_pve_queue_acks

    def log_message(self, *_args):
        pass

    def _unit_control_authorized(self) -> bool:
        guard = type(self).unit_control_guard
        if guard is None:
            return True
        get_all = getattr(self.headers, 'get_all', None)
        if callable(get_all):
            values = get_all(_UNIT_CONTROL_HEADER, [])
        else:
            value = self.headers.get(_UNIT_CONTROL_HEADER)
            values = [] if value is None else [value]
        if len(values) != 1:
            return False
        try:
            resolver = type(self).identity_resolver
            identity = None if resolver is None else resolver.identity
        except Exception:
            return False
        return guard.authorizes(values[0], identity)

    @classmethod
    def _trace(cls, value: dict):
        # The HTTP handler and XMPP hub share one metadata-only trace sink.
        with cls.trace_lock:
            with cls.trace_path.open('a', encoding='utf-8') as stream:
                stream.write(json.dumps({'time': time.time(), **value}, separators=(',', ':')) + '\n')

    def _send(self, code: int, body: bytes, content_type: str = 'application/json',
              headers: dict[str, str] | None = None):
        original_body = body
        body = self._add_career_response(code, body)
        self._last_status = code
        self._last_write_succeeded = False
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        # A career overlay changes the encoded payload after upstream headers
        # were computed. Preserve explicit lengths (including HEAD) otherwise.
        content_length = (str(len(body)) if body != original_body else
                          (headers or {}).get('Content-Length', str(len(body))))
        self.send_header('Content-Length', content_length)
        self.send_header('Cache-Control', 'no-store')
        for key, value in (headers or {}).items():
            if key.lower() != 'content-length':
                self.send_header(key, value)
        self.end_headers()
        try:
            written = (len(body) if getattr(self, '_head_only', False)
                       else self.wfile.write(body))
        except (BrokenPipeError, ConnectionAbortedError,
                ConnectionResetError, ssl.SSLError):
            pass
        else:
            self._last_write_succeeded = written == len(body)
        # Do not inherit offline.Handler's request-body/token logging.
        raw = getattr(self, '_body', b'')
        path = _native_service_path(self.path)
        trace_path = ('/battle_results/:battle_id'
                      if re.fullmatch(r'/battle_results/[^/]+', path)
                      else path)
        record = {'method': self.command, 'path': trace_path, 'status': code,
                  'response_bytes': len(body),
                  'response_write_succeeded': self._last_write_succeeded,
                  'fixture': getattr(self, '_fixture', False)}
        if getattr(self, '_lobby_error', None):
            record['lobby_error'] = self._lobby_error
        if path.lower() == '/profile':
            # Profile values and identifiers remain private.  Record only the
            # request shape and the response discriminator needed to prove
            # whether the client saw ok, ok_resync, or out_of_sync.
            request = None
            try:
                request_root = json.loads(raw)
                request = (request_root.get('request')
                           if isinstance(request_root, dict) else None)
                if isinstance(request, dict):
                    allowed_fields = {
                        'profile_timestamp', 'timestamp',
                        'active_commander', 'active_title',
                    }
                    visible_fields = sorted(allowed_fields.intersection(request))
                    record['profile_request_fields'] = visible_fields
                    record['profile_request_types'] = {
                        key: type(request[key]).__name__ for key in visible_fields
                    }
                    record['profile_request_has_unknown_fields'] = any(
                        key not in allowed_fields for key in request)
                    timestamp_zero = _profile_request_timestamp_is_zero(request)
                    if timestamp_zero is not None:
                        record['profile_request_timestamp_is_zero'] = timestamp_zero
            except (UnicodeError, ValueError, TypeError):
                record['profile_request_decode_failed'] = True
            profile_trace_metadata = getattr(
                self, '_profile_trace_metadata', None)
            if isinstance(profile_trace_metadata, dict):
                for key in _PROFILE_TRACE_BOOLEAN_KEYS:
                    value = profile_trace_metadata.get(key)
                    if type(value) is bool:
                        record[key] = value
            try:
                response_root = json.loads(body)
                response = (response_root.get('response')
                            if isinstance(response_root, dict) else None)
                result = response.get('result') if isinstance(response, dict) else None
                if isinstance(result, str) and len(result) <= 64:
                    record['profile_result'] = result
                elif (isinstance(response, dict)
                      and response.get('profile') == 'already_in_sync'):
                    record['profile_result'] = 'already_in_sync'
            except (UnicodeError, ValueError, TypeError):
                record['profile_response_decode_failed'] = True
        if path.rstrip('/').lower() == '/tutorial-progress':
            try:
                response_root = json.loads(body)
                response = (response_root.get('response')
                            if isinstance(response_root, dict) else None)
                result = response.get('result') if isinstance(response, dict) else None
                if isinstance(result, str) and len(result) <= 64:
                    record['tutorial_progress_result'] = result
            except (UnicodeError, ValueError, TypeError):
                record['tutorial_progress_response_decode_failed'] = True
        if path.rstrip('/') in PATHS or path.rstrip('/') in UNSUPPORTED_PATHS:
            try:
                request, headers, _ = decode_native_request(raw, self.headers.get('Content-Type', ''))
                record['request_fields'] = sorted(request)
                record['header_fields'] = sorted(headers)
                record['request_types'] = {key: type(request[key]).__name__ for key in sorted(request)
                                           if key in _TRACE_REQUEST_TYPE_KEYS}
                # Only fixed-shape settings and local-fixture identity comparisons.
                record['settings'] = {key: request[key] for key in ('map', 'max_players', 'length', 'private')
                                      if type(request.get(key)) in (bool, int) or
                                      isinstance(request.get(key), str) and len(request[key]) <= 80}
                nested_settings = request.get('settings')
                if isinstance(nested_settings, dict):
                    # Include names only: the allowlisted values below cannot
                    # distinguish an empty object from unsupported extra keys.
                    record['lobby_settings_fields'] = sorted(nested_settings)
                    record['lobby_settings'] = {
                        key: nested_settings[key]
                        for key in ('map', 'max_players', 'length', 'privacy')
                        if type(nested_settings.get(key)) in (bool, int)
                        or isinstance(nested_settings.get(key), str)
                        and len(nested_settings[key]) <= 80
                    }
                local_user = _local_native_user_id()
                record['username_is_local'] = request.get('username') == local_user
                record['user_id_is_local'] = headers.get('user_id') == local_user
            except NativeLobbyError:
                record['request_decode_failed'] = True
        if path.rstrip('/') in MATCHMAKING_PATHS:
            try:
                decoded = getattr(self, '_decoded_arbitration', None)
                if decoded is None:
                    request, headers, _ = decode_matchmaking_request(raw, self.headers.get('Content-Type', ''))
                else:
                    request, headers, _ = decoded
                record['request_fields'] = sorted(key for key in request if key in _TRACE_REQUEST_TYPE_KEYS)
                record['request_types'] = {key: type(request[key]).__name__ for key in record['request_fields']}
                record['header_fields'] = sorted(key for key in headers
                                                if key in ('user_id', 'token', 'version', 'auth_token', 'session_id',
                                                           'key', 'request_version', 'timestamp', 'appid', 'key_type',
                                                           'region', 'client_build_id', 'data_set_name'))
                if decoded is not None:
                    record['header_types'] = {key: type(headers[key]).__name__ for key in record['header_fields']}
                    record['request_version_is_one'] = type(headers.get('request_version')) is int \
                        and headers['request_version'] == 1
                regions = request.get('player_regions')
                if isinstance(regions, dict):
                    record['player_region_types'] = {key: type(regions[key]).__name__ for key in regions
                                                     if key == 'local'}
                local_user = _local_native_user_id()
                record['user_id_is_local'] = headers.get('user_id') == local_user
                record['steamname_is_local'] = request.get('steamname') == local_user
            except NativeLobbyError:
                record['request_decode_failed'] = True
            if getattr(self, '_arbitration_metadata', None) is not None:
                record['arbitration_wire'] = self._arbitration_metadata
            if self.matchmaking is not None:
                state = self.matchmaking.lab_state
                record['queue_state'] = state['queue_state']
                record['enrolled_humans'] = state['enrolled_humans']
        if self.custom_lobby and path.rstrip('/') in PATHS:
            record['lobby_state'] = self.custom_lobby.lab_state
        if 'metrics' in path:
            record['metric_tags'] = sorted(set(re.findall(
                r'\b(?:relay|matchmake|custom|battle|game)_[a-z_]+\b', raw.decode('utf-8', 'replace'))))[:32]
        self._trace(record)

    @staticmethod
    def _state_http_status(error: BattleStateError) -> int:
        if error.code.startswith('invalid_') or error.code.endswith('_too_large'):
            return 400
        if (error.code.endswith('_conflict') or error.code in {
                'battle_not_found', 'battle_not_enrolled', 'battle_not_ticking',
                 'result_not_reported', 'results_not_ready', 'user_not_in_battle',
                 'user_not_settled', 'battle_id_reused', 'active_battle_not_found',
                 'active_battle_ambiguous', 'battle_not_joinable',
                 'battle_party_mismatch',
                 'battle_credentials_missing', 'battle_key_mismatch',
                'battle_roster_mismatch'}):
            return 409
        return 503

    def _send_state_error(self, error: BattleStateError) -> None:
        status = self._state_http_status(error)
        code = 'battle_state_' + error.code
        self._lobby_error = code
        body = NativeLobbyError(status, code).as_envelope()
        self._send(status, json.dumps(body, separators=(',', ':')).encode('utf-8'))

    @staticmethod
    def _economy_http_status(error: EconomyError) -> int:
        code = error.code
        if code == 'future_profile_timestamp':
            return 409
        if (code.startswith('invalid_') or code.startswith('unknown_')
                or code.startswith('unsupported_') or code.startswith('duplicate_')):
            return 400
        if code == 'consumable_not_available_to_unit':
            # The native client can submit a stale or incompatible consumable
            # choice after a unit change.  This is a rejected client option,
            # not an unavailable local economy service.
            return 400
        if (code.startswith('insufficient_') or code.endswith('_already_owned')
                or code.endswith('_not_owned') or code.endswith('_mismatch')
                or code in {'commander_tier_too_low', 'idempotency_conflict',
                            'unit_prerequisite_not_owned', 'battle_already_settled',
                            'battle_not_found', 'ability_tree_reset_state_changed',
                            'ability_tree_reset_incomplete'}):
            return 409
        return 503

    def _send_economy_error(self, error: EconomyError) -> None:
        status = self._economy_http_status(error)
        code = 'economy_' + error.code
        self._lobby_error = code
        body = NativeLobbyError(status, code).as_envelope()
        self._send(status, json.dumps(body, separators=(',', ':')).encode('utf-8'))

    @staticmethod
    def _registered_cloud_battle(state: LocalBattleState, authority: object,
                                 battle_id: str, context: dict) -> tuple[str | None, object]:
        """Reuse the durable cloud id and exact frozen reward policy."""
        try:
            frozen = state.snapshot(battle_id)['context']
        except (BattleStateError, sqlite3.Error):
            frozen = None
        if isinstance(frozen, dict) and isinstance(frozen.get('cloud_battle_id'), str):
            return frozen['cloud_battle_id'], frozen.get('cloud_reward_policy')
        cloud_id = authority.register_battle(battle_id, context)
        policy = (authority.registered_reward_policy(battle_id)
                  if isinstance(cloud_id, str) else None)
        return cloud_id, policy

    def _persist_matchmaking_transition(self, path: str, request: dict,
                                        profile: dict, response: dict) -> None:
        """Commit public matchmaking allocation/enrollment before HTTP 200."""
        state = self.battle_state
        if state is None:
            return
        try:
            payload = response.get('response') if isinstance(response, dict) else None
            if path == '/check' and isinstance(payload, dict) \
                    and payload.get('status') == 'battle_ready':
                battle_id = payload.get('battle_id')
                battle_users = payload.get('battle_users')
                teams = battle_users.get('teams') if isinstance(battle_users, dict) else None
                humans = []
                human_teams = {}
                if isinstance(teams, list):
                    for team_index, team in enumerate(teams):
                        if not isinstance(team, list):
                            raise BattleStateError('invalid_battle_roster')
                        for row in team:
                            if isinstance(row, dict) and row.get('is_ai') is False:
                                humans.append(row)
                                user_id = row.get('user_id')
                                if (not isinstance(user_id, str)
                                        or user_id in human_teams):
                                    raise BattleStateError('invalid_battle_roster')
                                human_teams[user_id] = team_index
                user_ids = [row.get('user_id') for row in humans]
                local_user = _local_native_user_id()
                lab = self.matchmaking.lab_state
                pvp = self.matchmaking.pvp_binding
                if pvp is None:
                    if user_ids != [local_user]:
                        raise BattleStateError('invalid_battle_roster')
                else:
                    frozen_ids = pvp.get('user_ids')
                    frozen_teams = pvp.get('teams')
                    policy = pvp.get('roster_policy')
                    if (not isinstance(frozen_ids, list)
                            or not isinstance(frozen_teams, list)
                            or len(frozen_ids) != len(frozen_teams)
                            or len(set(frozen_ids)) != len(frozen_ids)
                            or set(user_ids) != set(frozen_ids)
                            or local_user not in frozen_ids
                            or pvp['battle_id'] != battle_id
                            or any(type(team) is not int or team not in (0, 1)
                                   for team in frozen_teams)
                            or any(human_teams.get(user_id) != frozen_teams[index]
                                   for index, user_id in enumerate(frozen_ids))):
                        raise BattleStateError('invalid_battle_roster')
                    if policy is None:
                        if len(frozen_ids) != 2 or frozen_teams != [0, 1]:
                            raise BattleStateError('invalid_battle_roster')
                    else:
                        mode, assignment_id = lab.get('game_mode'), pvp.get('assignment_id')
                        if (mode not in ('pve', 'pvp')
                                or not isinstance(assignment_id, str) or not assignment_id
                                or not 1 <= len(frozen_ids) <= (10 if mode == 'pve' else 20)):
                            raise BattleStateError('invalid_battle_roster')
                        try:
                            # Recheck the exact frozen seven-field policy at
                            # durable enrollment; only the validated v2 seed
                            # permits group teams. Legacy v1 stays unchanged.
                            _roster_policy(policy, assignment_id, mode)
                        except PvpCoordinatorError:
                            raise BattleStateError('invalid_battle_roster') from None
                    # Matchmaking groups output by team, while Worker seat
                    # order alternates teams.  Persist the authoritative human
                    # order, never the incidental team-flatten order.
                    by_user = {row['user_id']: row for row in humans}
                    humans = [by_user[user_id] for user_id in frozen_ids]
                    user_ids = list(frozen_ids)
                participants = [row for team in teams for row in team
                                if isinstance(row, dict)]
                if (len(participants) != sum(len(team) for team in teams)
                        or not 1 <= len(participants) <= 20):
                    raise BattleStateError('invalid_battle_roster')
                participant_ids = [row.get('user_id') for row in participants]
                if (len(set(participant_ids)) != len(participant_ids)
                        or any(not isinstance(row.get('user_id'), str)
                               or not 1 <= len(row['user_id']) <= 128
                               or type(row.get('is_ai')) is not bool
                               for row in participants)):
                    raise BattleStateError('invalid_battle_roster')
                if (any(not isinstance(row.get('party_id'), str)
                        or (row['is_ai'] and row['party_id'] != '')
                        or (not row['is_ai'] and not 0 <= len(row['party_id']) <= 128)
                        for row in participants)
                        or lab.get('party_id') != battle_id):
                    raise BattleStateError('invalid_battle_roster')
                local_row = next(row for row in humans
                                 if row.get('user_id') == local_user)
                local_details = local_row.get('matchmaking_details', {}).get(
                    'profile_matchmaking_details', {})
                setup = local_details.get('full_squad_setup')
                loadout = None
                if self.economy_service is not None:
                    loadout = self.economy_service.economy.battle_loadout()
                context = {
                    'mode': lab.get('game_mode'),
                    'ruleset': lab.get('battle_ruleset'),
                    'map': battle_users.get('map'),
                    'party_id': local_row['party_id'],
                    # Freeze the watermark from queue entry.  It remains the
                    # immutable concurrency token even though begin_pve's
                    # server-only roster record does not advance the native
                    # profile watermark.
                    'profile_saved': lab.get('profile_saved'),
                    'commander_key': lab.get('commander_key'),
                    'commander_tier': local_details.get('commander_tier'),
                    'unit_tiers': lab.get('unit_tiers'),
                    'battle_tier': lab.get('battle_tier'),
                    # The Worker pairs humans and NativeMatchmaking renders
                    # the frozen v1 CPU fill; the economy's frozen loadout
                    # still mirrors the local human's battle tier.
                    'pve_enemy_tier': (lab.get('pve_enemy_tier') if pvp is None
                                       else lab.get('battle_tier')),
                    'full_squad_setup': setup,
                    # Freeze each native party separately from the battle ID.
                    # Solo humans and CPUs have no party badge.
                    'result_participants': [{
                        'user_id': row.get('user_id'),
                        'party_id': row['party_id'],
                        'is_ai': row.get('is_ai'),
                    } for row in participants],
                }
                launch_name = getattr(active_identity(), "display_name", None)
                if launch_name is not None:
                    context["display_name"] = launch_name
                if pvp is not None and pvp.get('roster_policy') is not None:
                    # This policy was validated by bind_pvp_battle from the
                    # assignment. Carry the exact object into the economy
                    # boundary; it is never accepted from native input.
                    context['roster_policy'] = copy.deepcopy(
                        pvp['roster_policy'])
                if loadout is not None:
                    context.update({
                        'commander_item_id': loadout.get('commander_item_id'),
                        'unit_item_ids': [row.get('item_id') for row in loadout.get('units', [])],
                        'unit_instance_ids': [row.get('instance_id') for row in loadout.get('units', [])],
                        'roster_hash': loadout.get('roster_hash'),
                    })
                    if pvp is None:
                        self.economy_service.begin_pve_allocation(battle_id, context)
                    else:
                        self.economy_service.begin_public_allocation(battle_id, context)
                # ``cloud_battle_id`` (and the PvP seat block) belong to the
                # durable lifecycle, not to the economy: NativeEconomyService
                # validates its allocation context against a closed field
                # allowlist, so they are only ever stored in (and read back
                # from) SQLite; see _LIFECYCLE_CONTEXT_FIELDS.
                state_context = context
                authority = type(self).settlement_authority
                if pvp is not None:
                    # The Worker created this battle from the assignment for
                    # both seats; its id is the native battle id.
                    if authority is not None:
                        authority.bind_assigned_battle(
                            battle_id, pvp.get('reward_policy'))
                    state_context = {
                        **context,
                        'cloud_battle_id': battle_id,
                        'pvp': {key: pvp[key] for key in (
                            'assignment_id', 'seat', 'team', 'player_id',
                            'opponent_user_id', 'reward_policy', 'user_ids',
                            'teams', 'roster_policy', 'roster_digest')},
                    }
                elif authority is not None:
                    cloud_battle_id, cloud_reward_policy = self._registered_cloud_battle(
                        state, authority, battle_id, context)
                    state_context = {**context,
                                     'cloud_battle_id': cloud_battle_id,
                                     'cloud_reward_policy': cloud_reward_policy}
                # The normal client parses the HTTP battle_key as radix 16
                # before serializing GAME_JOIN's uint64.  Arbitration keeps the
                # exact HTTP string, while SQLite stores only the matching
                # integer digest.  The matchmaking boundary isolates the
                # explicit historical fixed-key diagnostic.
                relay_battle_key = self.matchmaking.relay_battle_key_uint64(
                    battle_id, payload.get('battle_key'))
                snapshot, created = state.allocate(
                    battle_id, ([local_user] if pvp is not None else user_ids), state_context,
                    battle_key=relay_battle_key,
                    # GAME_JOIN counts only rows with is_ai == false.  The CPU
                    # is present in battle_users but never enrolls or joins as
                    # an arbitration participant.
                    expected_players=len(humans))
                if self.economy_service is not None:
                    _refresh_offline_economy_views(self.economy_service)
                if not created and snapshot['phase'] in {
                        'result_reported', 'result_ready', 'settled', 'delivered'}:
                    raise BattleStateError('battle_id_reused')
            elif path == '/enroll':
                snapshot, _ = state.enroll(request.get('battle_id'), request.get('user_id'))
        except BattleStateError as error:
            status = self._state_http_status(error)
            # Every value above comes from server-built matchmaking data or an
            # already validated arbitration request. Invalid shapes therefore
            # indicate a server integration failure rather than client input.
            if error.code.startswith('invalid_battle_'):
                status = 503
            raise NativeLobbyError(status, 'battle_state_' + error.code) from None
        except EconomyError as error:
            # Every allocation value is server-built.  A rejected cross-check
            # is an integration failure, while an exact retry remains valid.
            status = 409 if error.code in {
                'idempotency_conflict', 'battle_already_exists',
            } else 503
            raise NativeLobbyError(status, 'economy_' + error.code) from None
        except OSError:
            raise NativeLobbyError(503, 'economy_storage_error') from None
        except sqlite3.Error:
            raise NativeLobbyError(503, 'battle_state_storage_error') from None

    def _validated_final_event(self, request: dict, headers: dict
                               ) -> tuple[str, str, dict, list]:
        """Bind one native final to its battle and remove its credential.

        BCFFB0 emits ``battle_key`` in the POST request, but neither durable
        event storage nor ``GET /battle_results`` needs that secret. The first
        final validates it against the frozen relay credential. An identical
        retry after relay credential retirement remains safe because the
        durable event digest still has to match exactly.
        """
        state = self.battle_state
        if state is None:
            raise NativeLobbyError(503, 'battle_state_disabled')
        if not isinstance(request, dict) or set(request) != {
                'battle_id', 'battle_key', 'user_id', 'seq_id', 'events'}:
            raise NativeLobbyError(400, 'invalid_battle_event_schema')
        user_id = request.get('user_id')
        if headers.get('user_id') is not None and headers['user_id'] != user_id:
            raise NativeLobbyError(400, 'battle_event_user_mismatch')
        if user_id != _local_native_user_id():
            raise NativeLobbyError(403, 'native_user_mismatch')
        events = request.get('events')
        local = [event for event in events if isinstance(event, dict)
                 and event.get('type') == 'results'
                 and event.get('user_id') == user_id]
        if len(local) != 1:
            raise NativeLobbyError(400, 'invalid_battle_event_user')
        wire_battle_id = request.get('battle_id')
        lobby = self.custom_lobby
        if lobby is not None and lobby.game_id == wire_battle_id:
            # Preserve the native endpoint's malformed-credential 400 before
            # the lobby performs an identity lookup, which reports only a
            # well-formed but stale/mismatched credential as 409.
            _final_battle_key(request.get('battle_key'), {'mode': 'private'})
            battle_id = lobby.resolve_battle_instance(
                wire_battle_id, request.get('battle_key'),
                include_completed=True)
        else:
            battle_id = state.resolve_wire_battle_id(wire_battle_id)
        frozen = state.snapshot(battle_id)
        frozen_context = frozen['context']
        if frozen_context.get('mode') == 'private':
            # A native custom battle has no matchmaking party, so the live
            # final uses an empty local party_id.  Bind it through the explicit
            # server-created battle ID, frozen private context, enrolled user,
            # and (below) the decimal relay credential.  Public matchmaking
            # never takes this branch and validates its frozen native party.
            if (frozen_context.get('private') is not True
                    or frozen_context.get('room_game_id') != wire_battle_id
                    or frozen_context.get('battle_instance_id') != battle_id
                    or frozen_context.get('result_party_id') != ''
                    or local[0].get('party_id') != ''
                    or user_id not in frozen.get('user_ids', ())):
                raise BattleStateError('battle_party_mismatch')
            self._trace({
                'event': 'native_private_result_binding',
                'binding': 'explicit_battle_id_and_credential',
                'local_party_id_empty': True,
            })
        else:
            resolved = state.battle_for_user_party(
                user_id, local[0].get('party_id'), battle_id=battle_id)
            if wire_battle_id != resolved:
                raise NativeLobbyError(
                    409, 'battle_state_battle_party_mismatch')

        durable = {key: request[key]
                   for key in ('battle_id', 'seq_id', 'user_id', 'events')}
        try:
            rows = native_final_result_rows(
                durable,
                result_participants=frozen_context.get('result_participants'),
                roster_policy=(frozen_context.get('pvp', {}).get('roster_policy')
                               if isinstance(frozen_context.get('pvp'), dict)
                               else frozen_context.get('roster_policy')),
                custom_battle_no_party=(
                    frozen_context.get('mode') == 'private'
                    and frozen_context.get('result_party_id') == ''),
            )
        except EconomyError as error:
            self._trace({
                'event': 'native_battle_result_schema_rejected',
                'schema_fingerprint': native_result_schema_fingerprint(
                    durable, getattr(error, 'failure', error.code)),
            })
            raise NativeLobbyError(
                self._economy_http_status(error),
                'economy_' + error.code) from None

        # Public matchmaking uses canonical lowercase hex, while custom games
        # expose a canonical decimal uint64.  Select the radix exclusively
        # from the immutable allocation context, never from request syntax.
        relay_key = _final_battle_key(request.get('battle_key'), frozen_context)
        existing = state.final_event(battle_id, user_id)
        try:
            state.validate_final_credential(battle_id, relay_key, user_id)
        except BattleStateError as error:
            # A relay may retire its secret after the first accepted final.
            # Only the already-persisted exact event retry may proceed; the
            # durable digest check below still rejects any changed report.
            if error.code != 'battle_credentials_missing' or existing is None:
                raise
        return battle_id, user_id, durable, rows

    def _handle_battle_event(self) -> None:
        if self.command != 'POST':
            self._send(405, b'{"error":"method_not_allowed"}')
            return
        state = self.battle_state
        service = self.economy_service
        if state is None and service is None:
            self._send(503, b'{"error":"battle_state_disabled"}')
            return
        duplicate_metadata: dict = {}
        try:
            request, headers, form_scalars = decode_event_request(
                getattr(self, '_body', b''), self.headers.get('Content-Type', ''),
                metadata=duplicate_metadata)
            if duplicate_metadata.get('duplicates'):
                self._trace({
                    'event': 'native_event_duplicate_compatibility',
                    'duplicates': duplicate_metadata['duplicates'],
                })
            if form_scalars:
                raise NativeLobbyError(400, 'invalid_battle_event_envelope')
            if ('events' in request and 'profile_timestamp' in request):
                if service is None:
                    raise NativeLobbyError(503, 'economy_service_disabled')
                # Local protocol evidence for implementing non-unit purchase
                # variants.  These fields contain only catalogue/profile IDs;
                # authentication headers and values remain excluded.
                self._trace({
                    'event': 'native_economy_event_request',
                    'profile_timestamp': request.get('profile_timestamp'),
                    'events': request.get('events'),
                })
                response = service.handle_event_request(request)
                _refresh_offline_economy_views(service)
                body = offline.ca_envelope(response, time.time_ns() // 1_000_000)
                self._send(200, json.dumps(body, separators=(',', ':')).encode('utf-8'))
                self._notify_party_loadout_changed()
                return
            # Periodic BCF0F0 batches and final BCFFB0 reports share /event.
            # Only a typed results row marks the final request.
            events = request.get('events')
            if (not isinstance(events, list)
                    or not any(isinstance(event, dict)
                               and event.get('type') == 'results'
                               for event in events)):
                if state is None:
                    raise NativeLobbyError(503, 'battle_state_disabled')
                # Both periodic SEND_EVENTS and final SEND_RESULTS messages
                # parse the root ``result`` member and require the literal
                # string ``ok`` before the client advances its result flow.
                self._send(200, b'{"result":"ok"}')
                return
            if state is None:
                raise NativeLobbyError(503, 'battle_state_disabled')
            battle_id, user_id, durable, rows = self._validated_final_event(
                request, headers)
            seq_id = durable.get('seq_id')
            _, created = state.report_final_event(
                battle_id, user_id, seq_id, durable)
            # Read from the handler class so a plain function adapter is not
            # transformed into a bound HTTP-handler method.
            callback = type(self).completion_callback
            if callback is None:
                completion = BattleCompletion(rows)
            else:
                try:
                    completion = callback(battle_id, user_id, durable, rows)
                except Exception:
                    # Identical event retry enters the adapter again. Economy
                    # adapters must therefore settle by battle_id exactly once.
                    self._trace({'event': 'battle_completion_callback_failed'})
                    raise NativeLobbyError(503, 'battle_completion_callback_failed') from None
            if (not isinstance(completion, BattleCompletion)
                    or not isinstance(completion.results, list)
                    or completion.settlement is not None
                    and not isinstance(completion.settlement, dict)):
                raise NativeLobbyError(503, 'invalid_battle_completion_callback')
            rows, _ = state.publish_results(battle_id, completion.results)
            if completion.settlement is not None:
                _, settlement_created = state.settle_once(
                    battle_id, user_id, completion.settlement)
                self._record_career_completion(
                    battle_id, user_id, durable, completion.settlement)
                if (settlement_created
                        and completion.settlement.get('mode') == 'private'):
                    profile_saved = (service.economy.snapshot()['saved']
                                     if service is not None
                                     else offline.PROFILE['profile']['saved'])
                    generation = type(self).private_profile_ready_gate.arm(
                        profile_saved)
                    self._trace({
                        'event': 'native_private_profile_gate_armed',
                        'generation': generation,
                    })
            matchmaking = self.matchmaking
            if matchmaking is not None:
                matchmaking.complete_battle(battle_id)
            self._trace({'event': 'battle_final_event', 'created': created,
                         'settlement': completion.settlement is not None})
            self._send(200, b'{"result":"ok"}')
        except NativeLobbyError as error:
            self._lobby_error = error.code
            self._send(error.status, json.dumps(error.as_envelope(),
                                                separators=(',', ':')).encode('utf-8'))
        except EconomyError as error:
            self._send_economy_error(error)
        except BattleStateError as error:
            self._send_state_error(error)
        except OSError:
            error = NativeLobbyError(503, 'economy_storage_error')
            self._lobby_error = error.code
            self._send(error.status, json.dumps(error.as_envelope(),
                                                separators=(',', ':')).encode('utf-8'))
        except sqlite3.Error:
            error = NativeLobbyError(503, 'battle_state_storage_error')
            self._lobby_error = error.code
            self._send(error.status, json.dumps(error.as_envelope(),
                                                separators=(',', ':')).encode('utf-8'))

    def _handle_battle_results(self, battle_id: str) -> None:
        if self.command != 'GET':
            self._send(405, b'{"error":"method_not_allowed"}')
            return
        state = self.battle_state
        if state is None:
            self._send(503, b'{"error":"battle_state_disabled"}')
            return
        try:
            wire_battle_id = battle_id
            lobby = self.custom_lobby
            if lobby is not None and lobby.game_id == wire_battle_id:
                battle_id = lobby.resolve_result_battle_instance(
                    wire_battle_id)
            else:
                battle_id = state.resolve_wire_battle_id(wire_battle_id)
            results = state.get_battle_results(battle_id)
            if results is None:
                self._send(404, b'"not_ready"')
                return
            context = state.snapshot(battle_id)['context']
            user_id = _local_native_user_id()
            settlement = state.settlement(battle_id, user_id)
            if settlement is not None:
                results, _ = state.deliver_results(battle_id, user_id)
            results = _postbattle_ui_result_rows(
                results, context, settlement=settlement, user_id=user_id,
            )
            if context.get('mode') == 'private' and lobby is not None:
                phase = state.snapshot(battle_id)['phase']
                lobby.prepare_rematch(battle_id, phase)
            # BD4ED0 consumes a raw JSON array, not a CA response envelope.
            self._send(200, json.dumps(results, separators=(',', ':')).encode('utf-8'))
        except NativeLobbyError as error:
            self._lobby_error = error.code
            self._send(error.status, json.dumps(error.as_envelope(),
                                                separators=(',', ':')).encode('utf-8'))
        except BattleStateError as error:
            if error.code == 'battle_not_found':
                self._send(404, b'"not_ready"')
            else:
                self._send_state_error(error)
        except sqlite3.Error:
            error = NativeLobbyError(503, 'battle_state_storage_error')
            self._lobby_error = error.code
            self._send(error.status, json.dumps(error.as_envelope(),
                                                 separators=(',', ':')).encode('utf-8'))

    def _prepare_private_rematch_on_lobby_return(self) -> None:
        """Finish a private round at the first safe return-to-lobby read.

        Custom battles use the battle-local performance panel and therefore do
        not necessarily request the public ``/battle_results`` resource.  A
        subsequent ``/get_games`` is the native client's explicit transition
        back to the retained room.  Mark the already settled rows delivered at
        that boundary, then rotate only the internal round identity so the room
        UUID, settings and CPU roster remain available for a rematch.
        """
        lobby, state = self.custom_lobby, self.battle_state
        if lobby is None or state is None:
            return
        battle_id = lobby.battle_instance_id
        if battle_id is None:
            return
        try:
            snapshot = state.snapshot(battle_id)
        except BattleStateError as error:
            # A freshly created room and a prepared, not-yet-started rematch do
            # not have a durable battle row yet.
            if error.code == 'battle_not_found':
                return
            raise NativeLobbyError(
                self._state_http_status(error),
                'battle_state_' + error.code,
            ) from None
        except sqlite3.Error:
            raise NativeLobbyError(
                503, 'battle_state_storage_error',
            ) from None
        if snapshot['context'].get('mode') != 'private':
            return
        phase = snapshot['phase']
        try:
            if phase == 'settled':
                user_id = _local_native_user_id()
                state.deliver_results(battle_id, user_id)
                phase = state.snapshot(battle_id)['phase']
            if phase == 'delivered':
                receipt = lobby.prepare_rematch(battle_id, phase)
                self._trace({
                    'event': 'native_private_rematch_prepared',
                    'battle_round': receipt.get('battle_round'),
                })
        except BattleStateError as error:
            raise NativeLobbyError(
                self._state_http_status(error),
                'battle_state_' + error.code,
            ) from None
        except sqlite3.Error:
            raise NativeLobbyError(
                503, 'battle_state_storage_error',
            ) from None

    def _handle(self):
        self._fixture = False
        self._lobby_error = None
        self._decoded_arbitration = None
        self._arbitration_metadata = None
        self._profile_trace_metadata = None
        path = _native_service_path(self.path)
        if not ipaddress.ip_address(self.client_address[0]).is_loopback:
            self._send(403, b'{"error":"loopback_only"}')
            return
        if self.headers.get('Origin'):
            self._send(403, b'{"error":"native_client_only"}')
            return
        low_path = path.lower()
        if (self.command == 'GET'
                and low_path.startswith('/twa-game-data.localhost/')):
            game_data_name = low_path.rsplit('/', 1)[-1]
            if game_data_name.endswith('versions.json'):
                generation = (type(self).private_profile_ready_gate
                              .observe_versions_request())
                if generation is not None:
                    self._trace({
                        'event': 'native_private_profile_gate_versions',
                        'generation': generation,
                    })
            elif game_data_name == 'catalogue.json':
                generation = (type(self).private_profile_ready_gate
                              .observe_catalogue_request())
                if generation is not None:
                    self._trace({
                        'event': 'native_private_profile_gate_ready',
                        'generation': generation,
                        'boundary': 'versions_then_catalogue',
                    })
        if path.lower().startswith('/api/launch'):
            self._send(403, b'{"error":"launch_disabled_in_probe"}')
            return
        if (self.economy_service is not None
                and low_path not in _DIRECT_ECONOMY_PATHS):
            try:
                _refresh_offline_economy_views_if_stale(
                    self.economy_service,
                )
            except EconomyError as error:
                self._send_economy_error(error)
                return
            except (OSError, ValueError):
                error = NativeLobbyError(503, 'economy_profile_refresh_failed')
                self._lobby_error = error.code
                self._send(error.status, json.dumps(error.as_envelope(),
                                                    separators=(',', ':')).encode('utf-8'))
                return
        if path == '/native-probe/relay-handshake':
            self._notify_relay_handshake()
            return
        if path == '/native-probe/matchmaking-start':
            self._notify_matchmaking_start()
            return
        if path == _BATTLE_MODE_CONTROL_PATH:
            self._handle_battle_mode_selection()
            return
        if path == _UNIT_LOADOUT_CONTROL_PATH:
            if not self._unit_control_authorized():
                self._send(403, b'{"error":"unit_control_unauthorized"}')
                return
            self._handle_unit_loadout_selection()
            return
        if path == _SPECIALIZATION_CONTROL_PATH:
            self._handle_specialization_control()
            return
        if path == _SPECIALIZATION_UI_STATUS_PATH:
            self._handle_specialization_ui_status()
            return
        if path == _SPECIALIZATION_REFRESH_ACK_PATH:
            self._handle_specialization_refresh_ack()
            return
        if path in _PRIVATE_CPU_CONTROL_PATHS:
            self._handle_private_cpu_management(path)
            return
        if path == '/native-probe/status':
            status = {'ok': True, 'scope': 'local_protocol_lab',
                      'native_battles': False,
                      'custom_lobby_enabled': self.custom_lobby is not None,
                      'relay_handshake_enabled': self.relay_handshake_enabled,
                      'matchmaking_enabled': self.matchmaking is not None,
                      'queue_state': self.matchmaking.lab_state if self.matchmaking else None,
                      'bound_client_count': self.xmpp_hub.bound_client_count if self.xmpp_hub else 0,
                      'lobby_state': self.custom_lobby.lab_state if self.custom_lobby else None}
            if self.matchmaking is not None:
                status['battle_mode'] = self.matchmaking.battle_mode_status
            self._send(200, json.dumps(status).encode('utf-8'))
            return
        if path == '/event':
            self._handle_battle_event()
            return
        battle_results = re.fullmatch(r'/battle_results/([^/]+)', path)
        if battle_results:
            self._handle_battle_results(battle_results.group(1))
            return
        if path == '/public/server_list' and self.local_region_enabled:
            # The command-line fixture documents the conservative discovery-only
            # response (PvP).  Once the opt-in matchmaking service is active the
            # live client must see every wire value present in its paired game
            # config; otherwise a selectable row can be rendered unavailable.
            # Keep legacy discovery unchanged unless the reviewed five-mode
            # feature is explicitly enabled.
            # Resolve this runtime capability before consulting static fixtures.
            response = local_server_list()
            if self.matchmaking is not None:
                advertised_modes = self.matchmaking.advertised_game_modes
                response['response']['game_modes'] = [
                    {'name': mode, 'max_party_size': (
                        NATIVE_PARTY_CAPACITY if type(self).native_social_party is not None else 1),
                     'min_tier': 1, 'max_tier': 10}
                    for mode in advertised_modes]
            self._send(200, json.dumps(response, separators=(',', ':')).encode('utf-8'))
            return
        try:
            document = json.loads(self.fixture_path.read_text(encoding='utf-8-sig'))
            responses = document['responses']
            if not isinstance(responses, dict):
                raise ValueError('responses must be an object')
            if path in responses:
                self._fixture = True
                self._send(200, json.dumps(responses[path], separators=(',', ':')).encode('utf-8'))
                return
        except (OSError, ValueError, KeyError, TypeError):
            # Invalid fixtures must never silently become a success response.
            self._send(503, b'{"error":"invalid_probe_fixture"}')
            return
        if self.game_config_enabled:
            # Keep fixtures above this branch authoritative. Only this opt-in
            # probe advertises game_config; never mutate the normal manifest.
            low = path.lower()
            name = low.rsplit('/', 1)[-1]
            if ('twa-game-data' in low or low.endswith('versions.json')) and 'versions' in name:
                manifest = {**offline.VERSIONS, 'game_config': GAME_CONFIG_FILENAME}
                self._send(200, json.dumps(manifest, separators=(',', ':')).encode('utf-8'))
                return
            if name == GAME_CONFIG_FILENAME:
                self._send(200, json.dumps(build_matchmaking_game_config(
                                            native_five_mode_selector=
                                            self.native_five_mode_selector,
                                            public_pvp_only=bool(self.matchmaking and
                                                self.matchmaking.public_pvp_only)),
                                            separators=(',', ':')).encode('utf-8'))
                return
        if path in SOCIAL_PARTY_PATHS and type(self).native_social_party is not None:
            self._handle_social_party(path)
            return
        if path in MATCHMAKING_PATHS:
            self._handle_matchmaking(path)
            return
        if path in PATHS or path in UNSUPPORTED_PATHS:
            cloud = type(self).private_cloud_adapter
            if cloud is not None:
                try:
                    profile, _ = offline.PROFILE_STATE.respond()
                    projected = cloud.handle_native(
                        path, getattr(self, '_body', b''),
                        self.headers.get('Content-Type', ''),
                        profile['profile'], method=self.command)
                    if projected is not None:
                        self._send(200, json.dumps(projected, separators=(',', ':')).encode('utf-8'))
                        callback = getattr(cloud, 'after_native_response', None)
                        if callback is not None:
                            try:
                                callback(path)
                            except Exception:
                                # The HTTP response was already delivered. A queued
                                # chat notification retries on the lobby refresh.
                                self._lobby_error = 'private_chat_notification_pending'
                        return
                except NativeLobbyError as error:
                    self._lobby_error = error.code
                    self._send(error.status, json.dumps(error.as_envelope(), separators=(',', ':')).encode('utf-8'))
                    return
            if self.custom_lobby is None:
                self._send(503, b'{"error":"native_lobby_probe_disabled"}')
                return
            try:
                # The native client can return to a retained custom room in
                # two ways: its normal lobby refresh and a manually entered
                # game ID.  Both must rotate a completed round before handing
                # the room back; otherwise /join exposes battle_started=true
                # and the join UI can treat the remaining CPU row as host.
                if path in ('/get_games', '/join'):
                    self._prepare_private_rematch_on_lobby_return()
                profile, _ = offline.PROFILE_STATE.respond()
                leaving_game_id = (self.custom_lobby.game_id
                                   if path in ('/leave', '/unready') else None)
                result = self.custom_lobby.handle(path, getattr(self, '_body', b''),
                                                 self.headers.get('Content-Type', ''), profile['profile'],
                                                 method=self.command)
                cancel_start = (None if self.xmpp_hub is None else getattr(
                    self.xmpp_hub, 'cancel_queued_custom_starting', None))
                if leaving_game_id is not None and callable(cancel_start):
                    cancel_start(leaving_game_id)
                self._send(200, json.dumps(result, separators=(',', ':')).encode('utf-8'))
            except NativeLobbyError as error:
                self._lobby_error = error.code
                self._send(error.status, json.dumps(error.as_envelope(), separators=(',', ':')).encode('utf-8'))
            return
        if (path.lower() == '/profile' and self.command == 'POST'
                and self.economy_service is not None
                and self.battle_state is not None
                and self.battle_state.has_pending_settlement(
                    _local_native_user_id(), mode='private')):
            # Private battles award no progression and leave ``saved`` intact.
            # The live post-battle read can race the installation of the
            # native F2P_PROFILE_GET_MESSAGE target.  Wait for the concurrent
            # catalogue request, which is the first causal game-data boundary
            # after that target is created, then return an ordinary compact
            # acknowledgement.  A full replacement produces the visible
            # profile synchronization warning even though the graph is equal.
            gate_result = type(self).private_profile_ready_gate.wait(
                type(self).private_profile_ready_timeout)
            self._trace({
                'event': 'native_private_profile_gate_wait',
                **{key: gate_result[key] for key in (
                    'generation', 'ready', 'reason', 'waited_ms')},
            })
            if gate_result['reason'] == 'timeout':
                # Retain the pending settlement and ask the native HTTP layer
                # to retry. A successful compact response before readiness is
                # worse: Request:set() rejects it after HTTP 200 and cannot
                # distinguish that local apply failure from success.
                error = NativeLobbyError(503, 'private_profile_not_ready')
                self._lobby_error = error.code
                self._send(error.status, json.dumps(
                    error.as_envelope(), separators=(',', ':')).encode('utf-8'))
                return
            profile, _, profile_trace_metadata = (
                self.economy_service.respond_private_postbattle(
                    getattr(self, '_body', b''),
                    # ``unarmed`` means this server process did not observe
                    # the battle final (for example after a restart). Preserve
                    # normal bootstrap/full-read semantics in that recovery
                    # case. The service holds both economy locks while it
                    # compares this watermark and constructs the response.
                    profile_target_ready=(
                        gate_result['ready']
                        and gate_result['generation'] > 0
                    ),
                    expected_saved=gate_result['profile_saved'],
                )
            )
            self._profile_trace_metadata = profile_trace_metadata
            profile_unchanged = profile_trace_metadata[
                'private_profile_gate_saved_matches_current'
            ]
            if gate_result['ready'] and not profile_unchanged:
                self._trace({
                    'event': 'native_private_profile_gate_profile_changed',
                    'generation': gate_result['generation'],
                    'result': profile.get('result'),
                })
            if gate_result['reason'] == 'unarmed':
                self._trace({
                    'event': 'native_private_profile_gate_unarmed',
                    'result': profile.get('result'),
                })
            body = offline.ca_envelope(profile, time.time_ns() // 1_000_000)
            self._send(200, json.dumps(body, separators=(',', ':')).encode('utf-8'))
            self._notify_party_loadout_changed()
            # A different, fully validated commander selection still retains
            # its normal meaning while a result is pending. Mirror the common
            # post-profile hooks so that exceptional path cannot leave the
            # shared catalogue/defaults or private lobby roster stale.
            try:
                _refresh_offline_economy_views_if_stale(
                    self.economy_service,
                )
            except (EconomyError, OSError, ValueError):
                self._trace({'event': 'economy_profile_refresh_failed'})
            if self.custom_lobby is not None:
                try:
                    current_profile, _ = offline.PROFILE_STATE.respond()
                    before = self.custom_lobby.lab_state
                    after = self.custom_lobby.refresh(
                        current_profile['profile'])
                    if before != after:
                        self._trace({
                            'event': 'native_lobby_profile_sync',
                            'lobby_state': after,
                        })
                except NativeLobbyError as error:
                    self._trace({
                        'event': 'native_lobby_profile_sync_failed',
                        'error': error.code,
                    })
            return
        super()._handle()
        if (self.command == 'POST' and path.lower() == '/profile'
                and getattr(self, '_last_status', None) == 200
                and self.economy_service is not None):
            self._notify_party_loadout_changed()
            # respond() has already committed an accepted selection. Keep the
            # shared data views in step for the next defaults/validation read.
            try:
                _refresh_offline_economy_views_if_stale(
                    self.economy_service,
                )
            except (EconomyError, OSError, ValueError):
                # The profile response is already on the wire; report only
                # metadata and let the next request fail closed on refresh.
                self._trace({'event': 'economy_profile_refresh_failed'})
        if self.command == 'POST' and path.lower() == '/profile' \
                and getattr(self, '_last_status', None) == 200 and self.custom_lobby is not None:
            # The native UI can send /change_squad before the selection's
            # /profile request reaches us. Publish the committed selection too,
            # rather than leaving the room with that earlier, stale formation.
            try:
                profile, _ = offline.PROFILE_STATE.respond()
                before = self.custom_lobby.lab_state
                after = self.custom_lobby.refresh(profile['profile'])
                if before != after:
                    self._trace({'event': 'native_lobby_profile_sync', 'lobby_state': after})
            except NativeLobbyError as error:
                # The profile response has already been sent. Do not send a
                # second HTTP response or roll back a committed selection.
                self._trace({'event': 'native_lobby_profile_sync_failed', 'error': error.code})

    def _notify_party_loadout_changed(self):
        """Hint after persistence/response; never use request data as authority."""
        callback = type(self).party_loadout_changed
        if callback is None:
            return
        try:
            callback()
        except Exception as error:
            self._trace({"event": "native_party_loadout_hint_failed",
                         "error_type": type(error).__name__})

    def _notify_relay_handshake(self):
        """Explicit local diagnostic only; no matchmaking or start-game ack."""
        if not self.relay_handshake_enabled:
            self._send(409, b'{"error":"relay_handshake_disabled"}')
            return
        if self.command != 'POST':
            self._send(405, b'{"error":"method_not_allowed"}')
            return
        if getattr(self, '_body', b'').strip() not in (b'', b'{}'):
            self._send(400, b'{"error":"probe_takes_no_parameters"}')
            return
        lobby, hub = self.custom_lobby, self.xmpp_hub
        if lobby is None or hub is None:
            self._send(503, b'{"error":"probe_services_unavailable"}')
            return
        try:
            profile, _ = offline.PROFILE_STATE.respond()
            # The lobby holds its own mutation lock from profile refresh
            # through notification, so leave/unready cannot split the checks.
            sent = lobby.notify_relay_handshake(profile['profile'], hub.send_custom_starting)
            self._trace({'event': 'relay_start_notification', 'clients': sent})
            self._send(202, json.dumps({'notification_sent': sent, 'native_battles': False,
                                        'scope': 'relay_handshake_only'}).encode('utf-8'))
        except NativeLobbyError as error:
            self._lobby_error = error.code
            self._send(error.status, json.dumps(error.as_envelope(), separators=(',', ':')).encode('utf-8'))

    def _handle_social_party(self, path: str):
        controller = type(self).native_social_party
        if self.command != 'POST':
            self._send(405, b'{"error":"method_not_allowed"}')
            return
        try:
            try:
                compatibility = {}
                request, headers, scalars = decode_social_party_request(
                    path, getattr(self, '_body', b''), self.headers.get('Content-Type', ''),
                    metadata=compatibility)
            except NativeLobbyError as error:
                # Decoding previously failed before any party trace. Keep the
                # original rejection even if best-effort diagnostics fail.
                try:
                    self._trace({'event': 'native_social_party_decode_failed',
                        'path': path if path in SOCIAL_PARTY_PATHS else 'other',
                        **_social_party_decode_metadata(getattr(self, '_body', b''),
                            self.headers.get('Content-Type', ''), error.code)})
                except Exception:
                    pass
                raise
            resolver = type(self).identity_resolver
            identity = None if resolver is None else resolver.identity
            if (scalars or identity is None
                    or headers.get('user_id') != identity.native_user_id):
                raise PartyError('party_request_identity_mismatch', 403)
            if compatibility:
                self._trace({'event': 'native_social_party_compatibility', 'path': path,
                             **compatibility})
            # Fixed field names and types only: names, IDs and tokens stay private.
            from native_social_party import REQUEST_FIELDS
            allowed = REQUEST_FIELDS[path][1]
            self._trace({'event': 'native_social_party_request', 'path': path,
                         'request_fields': sorted(allowed.intersection(request)),
                         'request_types': {key: type(request[key]).__name__
                                           for key in sorted(allowed.intersection(request))},
                         'unknown_fields': bool(request.keys() - allowed)})
            raw = controller.handle_native(path, request,
                authenticated_native_user_id=identity.native_user_id)
            result = offline.ca_envelope(raw, time.time_ns() // 1_000_000)
        except (PartyError, NativeLobbyError) as error:
            self._lobby_error = error.code
            failure = NativeLobbyError(error.status, error.code)
            self._send(error.status, json.dumps(failure.as_envelope(),
                                               separators=(',', ':')).encode('utf-8'))
            return
        except Exception as error:
            self._trace({'event': 'native_social_party_failed',
                         'error_type': type(error).__name__})
            self._send(503, b'{"error":"social_party_unavailable"}')
            return
        try:
            self._send(200, json.dumps(result, separators=(',', ':')).encode('utf-8'))
        finally:
            try:
                if getattr(self, '_last_write_succeeded', False):
                    controller.flush_notifications()
                else:
                    controller.discard_notifications()
            except Exception as error:
                # A later bind can resynchronize; never send a second response.
                self._trace({'event': 'native_social_party_delivery_failed',
                             'error_type': type(error).__name__})

    def _handle_matchmaking(self, path: str):
        if self.command != 'POST':
            self._send(405, b'{"error":"method_not_allowed"}')
            return
        cloud_arbitrator = getattr(type(self).private_cloud_adapter, 'arbitrate_native', None)
        cloud_arbitration = (path in ('/enroll', '/check') and callable(cloud_arbitrator)
                             and self.battle_state is not None)
        private_arbitration = (
            self.matchmaking is None
            and path in ('/enroll', '/check')
            and self.custom_lobby is not None
            and self.battle_state is not None
        )
        if self.matchmaking is None and not private_arbitration and not cloud_arbitration:
            self._send(503, b'{"error":"native_matchmaking_probe_disabled"}')
            return

        def arbitration_request():
            self._arbitration_metadata = {}
            decoded = decode_arbitration_request(getattr(self, '_body', b''),
                                                self.headers.get('Content-Type', ''),
                                                metadata=self._arbitration_metadata)
            self._decoded_arbitration = decoded
            return decoded
        try:
            request = {}
            profile, _ = offline.PROFILE_STATE.respond()
            profile = profile['profile']
            queue_generation = None
            cancelled_generation = None
            used_cloud_arbitration = False
            if path == '/v8/matchmake':
                result, queue_generation = self.matchmaking.enter_with_generation(
                    getattr(self, '_body', b''),
                    self.headers.get('Content-Type', ''), profile)
            else:
                if path == '/cancel':
                    cancelled_generation = self.matchmaking.lab_state.get('party_id')
                if path == '/enroll':
                    request, headers, form_scalars = arbitration_request()
                else:
                    try:
                        request, headers, form_scalars = decode_matchmaking_request(
                            getattr(self, '_body', b''), self.headers.get('Content-Type', ''))
                    except NativeLobbyError as error:
                        if path != '/check' or error.code != 'duplicate_json_key':
                            raise
                        # A duplicate cannot select arbitration by itself:
                        # its decoder also requires canonical three-field request.
                        request, headers, form_scalars = arbitration_request()
                    if path == '/check' and request and self._decoded_arbitration is None:
                        request, headers, form_scalars = arbitration_request()
                if form_scalars or headers.get('user_id') != _local_native_user_id():
                    raise NativeLobbyError(400, 'invalid_matchmaking_control')
                cloud_result = (cloud_arbitrator(path, request, headers, self.battle_state)
                                if cloud_arbitration and request else None)
                if cloud_result is not None:
                    result = cloud_result
                    used_cloud_arbitration = True
                elif private_arbitration:
                    result = self._private_arbitration(path, request, headers)
                elif self.matchmaking is None:
                    raise NativeLobbyError(503, 'native_matchmaking_probe_disabled')
                elif path == '/enroll':
                    result = self.matchmaking.enroll(request, headers, profile)
                elif path == '/check' and request:
                    # CASA arbitration and ordinary matchmaking share /check.
                    # Only the exact three-field arbitration schema is accepted.
                    result = self.matchmaking.check_arbitration(request, headers, profile)
                elif request:
                    raise NativeLobbyError(400, 'invalid_matchmaking_control')
                else:
                    result = self.matchmaking.cancel(profile) if path == '/cancel' else self.matchmaking.check(profile)
            if self.matchmaking is not None and not used_cloud_arbitration:
                self._persist_matchmaking_transition(path, request, profile, result)
            self._send(200, json.dumps(result, separators=(',', ':')).encode('utf-8'))
            if path == '/v8/matchmake':
                type(self)._finish_auto_pve_queue_response(
                    queue_generation, self._last_write_succeeded)
            elif path == '/cancel':
                type(self)._clear_auto_pve_queue_response(cancelled_generation)
        except NativeLobbyError as error:
            self._lobby_error = error.code
            self._send(error.status, json.dumps(error.as_envelope(), separators=(',', ':')).encode('utf-8'))

    def _private_arbitration(self, path: str, request: dict,
                             headers: dict) -> dict:
        """Authenticate CASA enroll/check against one frozen private battle.

        Custom games bypass the ordinary matchmaking queue, but the native
        client still runs the same arbitration manager after GAME_JOIN.  The
        room UUID, canonical decimal key and sole human are verified against
        LocalBattleState before either acknowledgement is returned.
        """
        state, lobby = self.battle_state, self.custom_lobby
        if state is None or lobby is None or path not in ('/enroll', '/check'):
            raise NativeLobbyError(503, 'private_arbitration_unavailable')
        local_user = _local_native_user_id()
        if set(request) != ARBITRATION_FIELDS:
            raise NativeLobbyError(400, 'invalid_arbitration_fields')
        if (headers.get('user_id') != local_user
                or request.get('user_id') != local_user):
            raise NativeLobbyError(403, 'native_user_mismatch')
        if request.get('battle_id') != lobby.game_id:
            raise NativeLobbyError(409, 'arbitration_battle_mismatch')
        lab_state = lobby.lab_state
        if not isinstance(lab_state, dict) or lab_state.get('battle_started') is not True:
            raise NativeLobbyError(409, 'private_battle_not_started')
        try:
            battle_id = lobby.resolve_battle_instance(
                request['battle_id'], request.get('battle_key'))
            if state.resolve_wire_battle_id(request['battle_id']) != battle_id:
                raise BattleStateError('battle_alias_mismatch')
            snapshot = state.snapshot(battle_id)
            context = snapshot.get('context')
            cpu_opponents = lab_state.get('cpu_opponents')
            if (not isinstance(context, dict) or context.get('mode') != 'private'
                    or context.get('party_id') != request['battle_id']
                    or context.get('room_game_id') != request['battle_id']
                    or context.get('battle_instance_id') != battle_id
                    or type(cpu_opponents) is not int
                    or snapshot.get('expected_players')
                    != 1 + cpu_opponents):
                raise BattleStateError('battle_roster_mismatch')
            battle_key = _final_battle_key(request.get('battle_key'), context)
            state.validate_relay_join(
                battle_id, battle_key, local_user,
                snapshot['expected_players'])
            snapshot, _ = state.enroll(battle_id, local_user)
            if path == '/check' and (
                    snapshot.get('phase') not in {
                        'enrolled', 'ticking', 'result_reported',
                        'result_ready', 'settled', 'delivered'}
                    or snapshot.get('enrolled_user_ids')
                    != snapshot.get('user_ids')):
                raise BattleStateError('battle_not_enrolled')
        except NativeLobbyError:
            raise
        except BattleStateError as error:
            raise NativeLobbyError(
                self._state_http_status(error),
                'battle_state_' + error.code,
            ) from None
        payload = ({'result': 'ok'} if path == '/enroll'
                   else {'all_users_ready': True})
        return offline.ca_envelope(payload, time.time_ns() // 1_000_000)

    def _notify_matchmaking_start(self):
        if self.command != 'POST':
            self._send(405, b'{"error":"method_not_allowed"}')
            return
        if getattr(self, '_body', b'').strip() not in (b'', b'{}'):
            self._send(400, b'{"error":"probe_takes_no_parameters"}')
            return
        if self.matchmaking is None:
            self._send(409, b'{"error":"native_matchmaking_probe_disabled"}')
            return
        try:
            profile, _ = offline.PROFILE_STATE.respond()
            sent = self.matchmaking.announce(profile['profile'])
            self._trace({'event': 'matchmaking_start_notification', 'clients': sent})
            self._send(202, json.dumps({'notification_sent': sent, 'native_battles': False,
                                       'scope': 'pve_battle_loading_experiment'}).encode('utf-8'))
        except NativeLobbyError as error:
            self._lobby_error = error.code
            self._send(error.status, json.dumps(error.as_envelope(), separators=(',', ':')).encode('utf-8'))

    def _handle_battle_mode_selection(self):
        """Expose the missing ruleset axis through a loopback-only control.

        The game itself continues to supply ``pve`` or ``pvp`` from its native
        selector.  This endpoint chooses territory/annihilation and can also
        pin the expected native button, yielding four explicit presets without
        replacing Ranked or Private Lobby UI assets.
        """
        matchmaking = self.matchmaking
        if matchmaking is None:
            self._send(409, b'{"error":"native_matchmaking_probe_disabled"}')
            return
        if self.command == 'GET':
            body = {
                'ok': True,
                'presets': sorted(BATTLE_MODE_PRESETS),
                **matchmaking.battle_mode_status,
            }
            self._send(200, json.dumps(body, separators=(',', ':')).encode('utf-8'))
            return
        if self.command != 'POST':
            self._send(405, b'{"error":"method_not_allowed"}')
            return
        try:
            request, headers, form_scalars = decode_native_request(
                getattr(self, '_body', b''),
                self.headers.get('Content-Type', ''),
            )
            if headers or form_scalars or set(request) != {'mode', 'ruleset'}:
                raise NativeLobbyError(400, 'invalid_battle_mode_selection')
            selection = matchmaking.select_battle_mode(
                request.get('mode'), request.get('ruleset'))
            self._send(200, json.dumps({'ok': True, 'selection': selection},
                                       separators=(',', ':')).encode('utf-8'))
        except NativeLobbyError as error:
            self._lobby_error = error.code
            self._send(error.status, json.dumps(error.as_envelope(),
                                                 separators=(',', ':')).encode('utf-8'))

    def _handle_specialization_control(self) -> None:
        """Serve the loopback companion's strict specialization IPC."""
        service = self.economy_service
        if service is None:
            self._send(409, b'{"error":"economy_service_disabled"}')
            return
        try:
            if self.command == 'GET':
                result = service.specialization_control()
            elif self.command == 'POST':
                media_type = self.headers.get('Content-Type', '').split(
                    ';', 1,
                )[0].strip().lower()
                if media_type != 'application/json':
                    raise EconomyError(
                        'invalid_specialization_control_request',
                    )
                request, headers, form_scalars = decode_native_request(
                    getattr(self, '_body', b''),
                    self.headers.get('Content-Type', ''),
                )
                if headers or form_scalars:
                    raise EconomyError('invalid_specialization_control_request')
                result = service.specialization_control(request)
            else:
                self._send(405, b'{"error":"method_not_allowed"}')
                return
            self._send(200, json.dumps(
                result, separators=(',', ':'),
            ).encode('utf-8'))
        except EconomyError as error:
            self._send_economy_error(error)

    def _handle_specialization_ui_status(self) -> None:
        """Serve the existing read-only specialization presentation contract."""
        service = self.economy_service
        if service is None:
            self._send(409, b'{"error":"economy_service_disabled"}')
            return
        if self.command != 'GET':
            self._send(405, b'{"error":"method_not_allowed"}')
            return
        try:
            pairs = parse_qsl(urlparse(self.path).query,
                              keep_blank_values=True, strict_parsing=True)
            if (len(pairs) != 1 or pairs[0][0] != 'language'
                    or pairs[0][1] not in {'en', 'ja', 'ru'}):
                raise ValueError
            language = pairs[0][1]
        except (TypeError, ValueError):
            self._send(400,
                       b'{"error":"invalid_specialization_ui_status_query"}')
            return
        try:
            result = service.specialization_ui_status(language)
            if not isinstance(result, dict):
                raise EconomyError('invalid_specialization_ui_status')
            self._send(200, json.dumps(
                result, separators=(',', ':'), ensure_ascii=False,
            ).encode('utf-8'))
        except EconomyError as error:
            self._send_economy_error(error)

    def _handle_specialization_refresh_ack(self) -> None:
        """Expose only a fresh exact post-write specialization ACK."""
        service = self.economy_service
        if service is None:
            self._send(409, b'{"error":"economy_service_disabled"}')
            return
        if self.command != 'GET':
            self._send(405, b'{"error":"method_not_allowed"}')
            return
        try:
            pairs = parse_qsl(urlparse(self.path).query,
                              keep_blank_values=True, strict_parsing=True)
            if ([key for key, _value in pairs].count('operation_id') != 1
                    or [key for key, _value in pairs].count('saved') != 1
                    or len(pairs) != 2):
                raise ValueError
            values = dict(pairs)
            operation_id, raw_saved = values['operation_id'], values['saved']
            if (re.fullmatch(r'native-specialization-[0-9a-f]{32}',
                             operation_id) is None
                    or not raw_saved.isascii() or not raw_saved.isdigit()
                    or len(raw_saved) > 20):
                raise ValueError
            saved = int(raw_saved)
            if not 0 < saved < 2**64:
                raise ValueError
        except (KeyError, TypeError, ValueError):
            self._send(400, b'{"error":"invalid_specialization_refresh_ack_query"}')
            return
        result = service.specialization_profile_refresh_ack(operation_id, saved)
        if result is None:
            self._send(404, b'{"error":"specialization_refresh_unconfirmed"}')
            return
        self._send(200, json.dumps(result, separators=(',', ':')).encode('utf-8'))

    def _handle_unit_loadout_selection(self) -> None:
        """Persist one successful stock unit-card drag into a squad slot.

        Arena's retired backend protocol does not emit an HTTP mutation for
        this UI event.  The local companion reports the native unit and
        commander item IDs plus the destination slot recovered from that
        stock drag event.  The expected profile watermark closes the read /
        mutate race; all ownership, faction and Tier checks stay in
        :class:`LocalEconomy`.
        """
        service = self.economy_service
        if service is None:
            self._send(409, b'{"error":"economy_service_disabled"}')
            return
        economy = service.economy
        if self.command == 'GET':
            with service._lock, economy._lock:  # type: ignore[attr-defined]
                snapshot = economy.snapshot()
                commander_key = snapshot['active_commander']
                commander = economy.commanders[commander_key]
                refresh = service.external_profile_refresh_status()
                body = {
                    'ok': True,
                    'commander': commander_key,
                    'commander_item_id': str(commander['item_id']),
                    'faction': commander['faction'],
                    'saved': snapshot['saved'],
                    'refresh_pending': refresh['pending'],
                    'refresh_operation_id': refresh['operation_id'],
                    'refresh_ack': refresh['ack'],
                    'units': list(
                        snapshot['commanders'][commander_key]['equipped_units']
                    ),
                    # The game's replaced-unit id names the saved slot even
                    # after an in-game bar reorder moved the on-screen cards.
                    'slot_instance_ids': [
                        str(value) for value in
                        service.adapter.slot_instance_ids(commander_key)
                    ],
                }
            self._send(200, json.dumps(
                body, separators=(',', ':'),
            ).encode('utf-8'))
            return
        if self.command != 'POST':
            self._send(405, b'{"error":"method_not_allowed"}')
            return
        try:
            request, headers, form_scalars = decode_native_request(
                getattr(self, '_body', b''),
                self.headers.get('Content-Type', ''),
            )
            legacy_fields = {
                'item_id', 'slot', 'commander_item_id', 'expected_saved',
            }
            if headers or form_scalars:
                raise NativeLobbyError(400, 'invalid_unit_loadout_selection')
            if set(request) == legacy_fields:
                # A helper that cannot report the game's target slot item
                # would save by screen position without the reorder latch.
                raise NativeLobbyError(400, 'unit_loadout_target_required')
            if set(request) != legacy_fields | {'target_instance_id'}:
                raise NativeLobbyError(400, 'invalid_unit_loadout_selection')
            raw_item_id = request['item_id']
            raw_commander_item_id = request['commander_item_id']
            expected_saved = request['expected_saved']
            slot = request['slot']
            if (not isinstance(raw_item_id, str) or not raw_item_id.isdigit()
                    or len(raw_item_id) > 20):
                raise NativeLobbyError(400, 'invalid_unit_loadout_item')
            item_id = int(raw_item_id)
            if not 0 < item_id < 2**64:
                raise NativeLobbyError(400, 'invalid_unit_loadout_item')
            if (not isinstance(raw_commander_item_id, str)
                    or not raw_commander_item_id.isdigit()
                    or len(raw_commander_item_id) > 20):
                raise NativeLobbyError(400, 'invalid_unit_loadout_commander')
            commander_item_id = int(raw_commander_item_id)
            if not 0 < commander_item_id < 2**64:
                raise NativeLobbyError(400, 'invalid_unit_loadout_commander')
            if (type(expected_saved) is not int
                    or not 0 <= expected_saved < 2**64):
                raise NativeLobbyError(400, 'invalid_unit_loadout_watermark')
            if type(slot) is not int or not 0 <= slot < 3:
                raise NativeLobbyError(400, 'invalid_unit_loadout_slot')
            raw_target = request['target_instance_id']
            target_instance_id = None
            if raw_target is not None:
                if (not isinstance(raw_target, str)
                        or not raw_target.isascii()
                        or not raw_target.isdigit() or len(raw_target) > 20):
                    raise NativeLobbyError(400, 'invalid_unit_loadout_target')
                target_instance_id = int(raw_target)
                if not 0 < target_instance_id < 2**64:
                    raise NativeLobbyError(400, 'invalid_unit_loadout_target')

            with service._lock, economy._lock:  # type: ignore[attr-defined]
                snapshot = economy.snapshot()
                commander_key = snapshot['active_commander']
                commander = economy.commanders[commander_key]
                if commander.get('item_id') != commander_item_id:
                    raise NativeLobbyError(
                        409, 'unit_loadout_commander_mismatch',
                    )
                if snapshot['saved'] != expected_saved:
                    raise NativeLobbyError(
                        409, 'unit_loadout_state_changed',
                    )
                if target_instance_id is not None:
                    # The helper's slot came from the game's replaced-unit id;
                    # it must be this commander's deployed item for that slot.
                    deployed = service.adapter.deployed_slot_for_instance(
                        target_instance_id,
                    )
                    if deployed is None:
                        raise NativeLobbyError(
                            409, 'unit_loadout_target_unknown',
                        )
                    if deployed[0] != commander_key:
                        raise NativeLobbyError(
                            409, 'unit_loadout_target_commander_mismatch',
                        )
                    if deployed[1] != slot:
                        raise NativeLobbyError(
                            409, 'unit_loadout_target_slot_mismatch',
                        )
                candidates = [
                    key for key, row in economy.units.items()
                    if row.get('item_id') == item_id
                ]
                if len(candidates) != 1:
                    raise NativeLobbyError(400, 'unknown_unit_loadout_item')
                before_units = list(
                    snapshot['commanders'][commander_key]['equipped_units']
                )
                after_units = list(before_units)
                after_units[slot] = candidates[0]
                changed = after_units != before_units
                operation_id = None
                refresh_pending = False
                refresh_operation_id = None
                if changed:
                    operation_id = f'native-unit-drag-{secrets.token_hex(16)}'
                    receipt = economy.equip_units(
                        operation_id,
                        commander_key, after_units,
                    )
                    persisted = economy.snapshot()
                    if (persisted['active_commander'] != commander_key
                            or persisted['commanders'][commander_key][
                                'equipped_units'] != after_units):
                        raise EconomyError('unit_loadout_persistence_mismatch')
                    # Prove that the next stock deferred /profile request
                    # belongs to this exact durable equip_units operation.
                    # Arm before acknowledging the control POST.  The native
                    # /profile response is built directly from this service;
                    # compatibility views are non-authoritative and are
                    # republished after that profile response reaches the
                    # client (or on the next game-data request). Keeping them
                    # off this synchronous path lets the companion raise the
                    # stock deferred flag immediately after persistence.
                    try:
                        service.arm_external_profile_refresh(
                            operation_id,
                            previous_saved=expected_saved,
                            current_saved=receipt['saved'],
                            commander_key=commander_key,
                        )
                    except Exception as error:
                        # The equip_units receipt is already durable.  Report
                        # that truth with HTTP 200 instead of turning a
                        # non-authoritative live-refresh failure into a false
                        # 409. The bridge will log that UI catch-up is needed.
                        self._trace({
                            'event': 'native_unit_drag_refresh_unavailable',
                            'operation_id': operation_id,
                            'saved': receipt['saved'],
                            'error': type(error).__name__,
                        })
                    else:
                        refresh_pending = True
                        refresh_operation_id = operation_id
                else:
                    # Dropping the already-equipped unit is an acknowledged
                    # no-op.  Do not consume operation capacity, advance the
                    # profile watermark, or request a redundant native read.
                    receipt = {'saved': snapshot['saved']}
            self._trace({
                'event': ('native_unit_drag_persisted' if changed
                          else 'native_unit_drag_unchanged'),
                'slot': slot,
                'slot_source': (
                    'screen' if target_instance_id is None else 'native'
                ),
                'target_instance_id': (
                    None if target_instance_id is None
                    else str(target_instance_id)
                ),
            })
            body = {
                'ok': True,
                'slot': slot,
                'unit_item_id': str(item_id),
                'saved': receipt['saved'],
                'commander': commander_key,
                'commander_item_id': str(commander_item_id),
                'operation_id': operation_id,
                'refresh_pending': refresh_pending,
                'refresh_operation_id': refresh_operation_id,
                'before_units': before_units,
                'after_units': after_units,
            }
            self._send(200, json.dumps(
                body, separators=(',', ':'),
            ).encode('utf-8'))
            if changed:
                self._notify_party_loadout_changed()
        except NativeLobbyError as error:
            self._lobby_error = error.code
            self._send(error.status, json.dumps(
                error.as_envelope(), separators=(',', ':'),
            ).encode('utf-8'))
        except EconomyError as economy_error:
            if economy_error.code == 'saved_conflict':
                # A cloud writer won after this gesture captured its profile
                # watermark.  Refresh only our authoritative view; replaying
                # the equip would apply a gesture to a commander/loadout the
                # user did not see.  A later GET gives the helper a fresh
                # commander, units and watermark for a new gesture.
                try:
                    # Keep reload and stale correlation invalidation atomic
                    # with respect to a newer successful native POST.  This is
                    # the service -> economy lock order used by the ordinary
                    # handler path; a later arm waits, then survives this clear.
                    with service._lock:  # type: ignore[attr-defined]
                        economy.reload()
                        service._disarm_external_profile_refresh()
                        service._external_profile_refresh_ack = None
                except EconomyError:
                    error = NativeLobbyError(
                        503, 'unit_loadout_reload_failed',
                    )
                else:
                    self._trace({
                        'event': 'native_unit_drag_conflict_reloaded',
                    })
                    error = NativeLobbyError(
                        409, 'unit_loadout_state_changed',
                    )
            else:
                # Keep the helper's 409, but trace the economy code: a
                # failed cloud save (e.g. profile_body_too_large) must not
                # look like a validation refusal in the bridge log.
                self._trace({
                    'event': 'native_unit_drag_rejected',
                    'economy_error': economy_error.code,
                })
                error = NativeLobbyError(
                    409, 'unit_loadout_selection_rejected',
                )
            self._lobby_error = error.code
            self._send(error.status, json.dumps(
                error.as_envelope(), separators=(',', ':'),
            ).encode('utf-8'))
        except (KeyError, TypeError, ValueError) as unexpected:
            # Keep the helper's generic 409, but make the cause visible.
            self._trace({
                'event': 'native_unit_drag_rejected',
                'error_class': type(unexpected).__name__,
            })
            error = NativeLobbyError(409, 'unit_loadout_selection_rejected')
            self._lobby_error = error.code
            self._send(error.status, json.dumps(
                error.as_envelope(), separators=(',', ':'),
            ).encode('utf-8'))

    def _handle_private_cpu_management(self, path: str) -> None:
        """Loopback host control, deliberately separate from native CACUGS.

        No CPU-add HTTP operation exists in the native client protocol.  These
        exact ``/native-probe`` routes let a local room host manage trusted CPU
        rows without pretending that request fields came from the game.
        """
        if self.command != 'POST':
            self._send(405, b'{"error":"method_not_allowed"}')
            return
        if self.custom_lobby is None:
            self._send(409, b'{"error":"native_private_cpu_management_disabled"}')
            return
        if self.xmpp_hub is None:
            self._send(503, b'{"error":"native_private_cpu_notifications_unavailable"}')
            return
        try:
            request, headers, form_scalars = decode_native_request(
                getattr(self, '_body', b''),
                self.headers.get('Content-Type', ''),
            )
            if headers or form_scalars:
                raise NativeLobbyError(400, 'invalid_private_cpu_management_request')
            profile, _ = offline.PROFILE_STATE.respond()
            if path == _PRIVATE_CPU_ADD_CONTROL_PATH:
                if request:
                    raise NativeLobbyError(400, 'invalid_private_cpu_management_request')
                result = self.custom_lobby.host_add_cpu(profile['profile'])
            else:
                if (set(request) != {'user_id'}
                        or type(request.get('user_id')) is not str
                        or _PRIVATE_CPU_USER_ID.fullmatch(request['user_id']) is None):
                    raise NativeLobbyError(400, 'invalid_private_cpu_management_request')
                result = self.custom_lobby.host_remove_cpu(
                    request['user_id'], profile['profile'])
            response = {'ok': True, 'scope': 'loopback_host_management', **result}
            self._trace({'event': 'native_private_cpu_management',
                         'operation': result['operation'],
                         'cpu_opponents': result['cpu_opponents']})
            self._send(200, json.dumps(response, separators=(',', ':')).encode('utf-8'))
        except NativeLobbyError as error:
            self._lobby_error = error.code
            self._send(error.status, json.dumps(error.as_envelope(),
                                                separators=(',', ':')).encode('utf-8'))
        except (EconomyError, OSError, KeyError, TypeError, ValueError):
            error = NativeLobbyError(503, 'native_private_cpu_management_failed')
            self._lobby_error = error.code
            self._send(error.status, json.dumps(error.as_envelope(),
                                                separators=(',', ':')).encode('utf-8'))

    def do_POST(self):
        self._head_only = False
        path = _native_service_path(self.path).rstrip('/') or '/'
        storage = self.native_user_storage
        if storage is not None and storage.is_blob_path(path):
            if self.command != 'PUT':
                self.close_connection = True
                try:
                    response = storage.handle(self.command, path, b'')
                except NativeUserStorageError as error:
                    self._send(error.status, json.dumps({'error': error.code}).encode())
                    return
                self._head_only = False
                self._send(response.status, response.body, response.content_type,
                           response.headers)
                return
            try:
                self._body = read_bounded_body(
                    self.headers, self.rfile, timeout_socket=self.connection)
            except NativeUserStorageError as error:
                self.close_connection = True
                self._send(error.status, json.dumps({'error': error.code}).encode())
                return
            self._head_only = False
            self._handle()
            return
        try:
            size = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            self._send(400, b'{"error":"invalid_length"}')
            return
        if size < 0 or size > 2 * 1024 * 1024:
            self._send(413, b'{"error":"body_too_large"}')
            return
        self._body = self.rfile.read(size) if size else b''
        self._handle()

    do_PUT = do_POST


def _build_user_storage(args, economy_backend):
    root = getattr(args, 'native_user_storage', None)
    if root is None:
        if economy_backend is not None:
            return None
        root = Path(os.path.abspath(os.fspath(args.economy_state))).parent
    return NativeUserStorage(root, lambda: offline.active_native_user_id())


def _stop_http_servers(servers: list, serving: list, timeout: float = 2.0) -> None:
    """Stop the started serve loops, then close every bound listener."""
    try:
        # Closing a listener under a live select() raises WinError 10038 in
        # its serve thread, which diagnostics record as a bridge crash.  Not
        # shutdown(): it waits forever on a loop that never started, one loop
        # at a time (~2.7 s for six listeners), and without bound while an
        # idle client parks a TLS listener in get_request()'s blocking peek.
        # Raise socketserver's own stop flag everywhere first so the 0.5 s
        # polls overlap; a loop still parked at the deadline only rechecks
        # the flag, never select(), once its client sends or disconnects.
        for server, _thread in serving:
            server._BaseServer__shutdown_request = True
        deadline = time.monotonic() + timeout
        for _server, thread in serving:
            thread.join(max(0.0, deadline - time.monotonic()))
    finally:
        for server in servers:
            server.server_close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixtures', required=True, type=Path)
    parser.add_argument('--trace', required=True, type=Path)
    parser.add_argument('--ports', type=int, nargs='+', default=[18765, 80, 443])
    parser.add_argument('--xmpp', action='store_true', help='Offline XMPP on loopback only')
    parser.add_argument('--matchmaking', action='store_true', help='Enable local ordinary matchmaking protocol; requires --xmpp')
    parser.add_argument('--auto-pve-start', action='store_true',
                        help='Auto-announce accepted local PvE queues after HTTP/XMPP readiness')
    parser.add_argument('--pve-battle-probe', action='store_true',
                        help='Enable the local single-human/CPU lifecycle for ordinary matchmaking or a custom lobby')
    parser.add_argument('--pve-enemy-tier', type=int,
                        help='Live-test only: fix the PvE CPU roster to Tier 1-10 instead of matching the player')
    parser.add_argument('--battle-mode', choices=sorted(BATTLE_MODE_PRESETS),
                        help='Pin territory/annihilation and expected native PvE/PvP selection')
    parser.add_argument(
        '--native-five-mode-selector', action='store_true',
        help=('Enable the reviewed paired native five-row selector protocol; '
              'requires --matchmaking'),
    )
    parser.add_argument('--battle-state', type=Path, default=DEFAULT_BATTLE_STATE_PATH,
                        help='SQLite lifecycle shared with native_battle_probe')
    parser.add_argument('--economy-state', type=Path, default=DEFAULT_ECONOMY_STATE_PATH,
                        help='Persistent local progression/reward state (ignored by git)')
    parser.add_argument('--native-user-storage', type=Path,
                        help='Persistent process-bound native UI preference directory')
    parser.add_argument('--zero-pve-rewards', action='store_true',
                        help='Local diagnostic: zero all PvE battle rewards for newly begun battles; daily progress remains')
    parser.add_argument('--legacy-lab-credentials', action='store_true',
                        help='explicit diagnostic only: fixed historical battle ID/key')
    parser.add_argument('--local-region', action='store_true', help='Serve local region discovery and loopback UDP echo only')
    parser.add_argument('--custom-lobby', action='store_true',
                        help='Enable the single-user native lobby; add --pve-battle-probe for one private CPU battle')
    parser.add_argument('--relay-handshake', action='store_true',
                        help='Permit the explicit local relay-handshake notification; requires --xmpp --custom-lobby; no battles')
    return parser


def validate_args(parser: argparse.ArgumentParser, args) -> None:
    if args.relay_handshake and not (args.xmpp and args.custom_lobby):
        parser.error('--relay-handshake requires --xmpp and --custom-lobby')
    if args.relay_handshake and args.pve_battle_probe:
        parser.error('--relay-handshake is a diagnostic and cannot be combined with --pve-battle-probe')
    if args.matchmaking and (not args.xmpp or args.custom_lobby):
        parser.error('--matchmaking requires --xmpp and cannot use --custom-lobby')
    if args.auto_pve_start and not (args.matchmaking and args.pve_battle_probe and args.xmpp):
        parser.error('--auto-pve-start requires --xmpp --matchmaking --pve-battle-probe')
    if args.pve_battle_probe and not (
            (args.matchmaking or args.custom_lobby) and args.xmpp and args.local_region):
        parser.error('--pve-battle-probe requires --matchmaking or --custom-lobby, plus --xmpp --local-region')
    if args.pve_enemy_tier is not None and (not args.pve_battle_probe
                                             or not args.matchmaking
                                             or not 1 <= args.pve_enemy_tier <= 10):
        parser.error('--pve-enemy-tier requires matchmaking --pve-battle-probe and an integer from 1 to 10')
    if args.battle_mode is not None and not args.matchmaking:
        parser.error('--battle-mode requires --matchmaking')
    if args.native_five_mode_selector and not args.matchmaking:
        parser.error('--native-five-mode-selector requires --matchmaking')
    if args.legacy_lab_credentials and (not args.pve_battle_probe or not args.matchmaking):
        parser.error('--legacy-lab-credentials requires matchmaking --pve-battle-probe')
    if args.zero_pve_rewards and not args.pve_battle_probe:
        parser.error('--zero-pve-rewards requires --pve-battle-probe')


def main(argv: list[str] | None = None, *,
         identity_resolver: object | None = None,
         unit_control_guard: UnitControlGuard | None = None,
         economy_backend: object | None = None,
         settlement_authority: object | None = None,
         ready: Callable[[dict], None] | None = None,
         before_shutdown: Callable[[], None] | None = None,
         stop: threading.Event | None = None,
         pvp_enabled: bool = False,
         pve_enabled: bool | None = None,
         cloud_coop_pve: bool = False,
         public_pvp_only: bool = False,
         career_state_path: Path | None = None,
         career_history_root: Path | None = None,
         career_cloud_factory: Callable | None = None):
    """Serve the loopback lab, optionally as one companion user's bridge.

    The keyword arguments are the whole companion seam: a resolver for the
    presented ``+auth`` session, a non-file economy backend, a cloud
    settlement authority, and ``pvp_enabled`` (the companion's Worker PvP
    coordinator will bind Worker battles into the queue).  With all of them
    absent this is byte for byte the historical single-user lab process.
    """
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)
    if type(cloud_coop_pve) is not bool or type(public_pvp_only) is not bool:
        raise TypeError('cloud_coop_pve and public_pvp_only must be bool')
    if type(pvp_enabled) is not bool or pve_enabled is not None \
            and type(pve_enabled) is not bool:
        raise TypeError('pvp_enabled and pve_enabled must be bool')
    if unit_control_guard is not None \
            and not isinstance(unit_control_guard, UnitControlGuard):
        raise TypeError('unit_control_guard must be UnitControlGuard')
    if pve_enabled is None:
        # Omission preserves the probe's historical opt-in surface: a plain
        # HTTP/XMPP diagnostic does not become a battle service merely because
        # public PvP is disabled. Companion callers pass an explicit value.
        pve_enabled = bool(args.pve_battle_probe and not pvp_enabled)
    if pvp_enabled and not (args.matchmaking and args.pve_battle_probe):
        parser.error('pvp_enabled requires --matchmaking --pve-battle-probe')
    if pve_enabled and not args.pve_battle_probe:
        parser.error('pve_enabled requires --pve-battle-probe')
    # Importing the probe remains safe without client assets for pure server
    # tests. A live listener, however, must match the WAD that produced the
    # advertised type-19 catalogue exactly.
    offline.validate_deployed_unit_ability_wad(
        offline._NATIVE_UNIT_ABILITIES,
    )
    fixture = args.fixtures.resolve(strict=True)
    trace = args.trace.resolve()
    trace.parent.mkdir(parents=True, exist_ok=True)
    original_offline_globals = (
        offline.CATALOGUE, offline.MAPPINGS,
        offline.PROFILE, offline.PROFILE_STATE,
        offline.DEFAULTS, offline.VALIDATION)
    original_handler_globals = (
        ProbeHandler.custom_lobby, ProbeHandler.xmpp_hub,
        ProbeHandler.relay_handshake_enabled, ProbeHandler.matchmaking,
        ProbeHandler.battle_state, ProbeHandler.economy_service,
        ProbeHandler.completion_callback, ProbeHandler.private_cloud_adapter,
        ProbeHandler.native_social_party,
        ProbeHandler.party_loadout_changed,
        ProbeHandler.local_region_enabled,
        ProbeHandler.game_config_enabled,
        ProbeHandler.native_five_mode_selector,
        ProbeHandler.private_profile_ready_gate,
        ProbeHandler.identity_resolver, ProbeHandler.unit_control_guard,
        ProbeHandler.settlement_authority,
        ProbeHandler.auto_pve_queue_acks, ProbeHandler.native_user_storage)
    ProbeHandler.fixture_path = fixture
    ProbeHandler.trace_path = trace
    # MPFileStorage contains opaque UI preferences, never economy authority.
    # The launcher supplies a stable environment-scoped directory for cloud
    # sessions; NativeUserStorage binds each object to the authenticated user.
    ProbeHandler.native_user_storage = _build_user_storage(args, economy_backend)
    ProbeHandler.custom_lobby = None
    ProbeHandler.xmpp_hub = None
    ProbeHandler.relay_handshake_enabled = args.relay_handshake
    ProbeHandler.matchmaking = None
    ProbeHandler.battle_state = None
    ProbeHandler.economy_service = None
    ProbeHandler.completion_callback = None
    ProbeHandler.private_cloud_adapter = None
    ProbeHandler.native_social_party = None
    ProbeHandler.party_loadout_changed = None
    ProbeHandler.local_region_enabled = args.local_region
    ProbeHandler.game_config_enabled = bool(
        args.matchmaking or (args.custom_lobby and args.pve_battle_probe))
    ProbeHandler.native_five_mode_selector = args.native_five_mode_selector
    ProbeHandler.private_profile_ready_gate = _PrivateProfileReadyGate()
    ProbeHandler.identity_resolver = identity_resolver
    ProbeHandler.unit_control_guard = unit_control_guard
    ProbeHandler.settlement_authority = settlement_authority
    with ProbeHandler.auto_pve_queue_ack_lock:
        ProbeHandler.auto_pve_queue_acks = set()
    if identity_resolver is not None:
        # Bind before the economy service is built: every profile graph, XMPP
        # JID and matchmaking response is derived from this one identity.
        offline.bind_identity_resolver(identity_resolver)
    original_career_store = ProbeHandler.career_store
    original_career_cloud = (ProbeHandler.career_cloud, ProbeHandler.career_cloud_required)
    ProbeHandler.career_cloud = None
    ProbeHandler.career_cloud_required = (career_cloud_factory is not None
                                           and career_state_path is not None)
    career_cloud = None
    ProbeHandler.career_store = None
    career_store = None
    xmpp_hub = None
    region_ping = None
    battle_state = None
    economy_service = None
    auto_announcer = None
    servers = []
    serving = []
    try:
        if args.pve_battle_probe:
            economy_service = _persistent_economy_service(
                args.economy_state.resolve(), backend=economy_backend,
                identity=(None if identity_resolver is None
                          else identity_resolver.identity),
                zero_pve_rewards=args.zero_pve_rewards,
                bootstrap_new_specializations=(
                    unit_control_guard is not None
                    and isinstance(economy_backend, CloudEconomyBackend)
                ))
            if career_state_path is not None:
                if (identity_resolver is None
                        or economy_service.user_id != identity_resolver.identity.native_user_id):
                    raise ValueError('career_identity_mismatch')
                try:
                    career_store = NativeCareerStats(career_state_path, offline._NATIVE)
                    imported = backfill_completed(
                        career_store, economy_service.user_id,
                        args.battle_state.resolve(), career_history_root)
                    ProbeHandler.career_store = career_store
                    ProbeHandler._trace({'event': 'career_history_imported', **imported})
                except (ValueError, TypeError, KeyError, OSError, sqlite3.Error) as error:
                    if career_store is not None:
                        career_store.close()
                        career_store = None
                    ProbeHandler._trace({'event': 'career_startup_failed',
                                         'error_type': type(error).__name__})
                if career_cloud_factory is not None:
                    try:
                        career_cloud = career_cloud_factory(
                            career_state_path, offline._NATIVE, ProbeHandler._trace)
                        career_cloud.start()
                        ProbeHandler.career_cloud = career_cloud
                    except (ValueError, TypeError, KeyError, RuntimeError, OSError, sqlite3.Error) as error:
                        if career_cloud is not None:
                            career_cloud.close()
                            career_cloud = None
                        ProbeHandler._trace({'event': 'career_cloud_startup_failed',
                                             'error_type': type(error).__name__})
            _refresh_offline_economy_views(economy_service)
            ProbeHandler.economy_service = economy_service
        # Bind every requested listener before serving; conflicts fail closed.
        # Attach only bounded, public socket coordinates to an OS bind error;
        # the private child can report them without exposing exception text.
        for port in args.ports:
            if not 1 <= port <= 65535:
                raise ValueError('invalid port')
            for family, server_type, host in (
                    ('ipv4', offline.DualProtocolServer, '127.0.0.1'),
                    ('ipv6', offline.DualProtocolServer6, '::1')):
                try:
                    servers.append(server_type((host, port), ProbeHandler))
                except OSError as error:
                    from companion.loopback_ports import annotate_bind_error
                    annotate_bind_error(error, transport='tcp', family=family, port=port)
                    raise
        if args.xmpp:
            # A local fake-player hub, never production authentication.
            xmpp_hub = NativeXmppProbe(ProbeHandler._trace)
            xmpp_hub.start()
            ProbeHandler.xmpp_hub = xmpp_hub
        if args.local_region:
            region_ping = NativeRegionPing(on_first_echo=lambda: ProbeHandler._trace({
                'event': 'region_ping_echo', 'port': 19063, 'bytes': 4}))
            region_ping.start()
        if args.pve_battle_probe:
            battle_state = LocalBattleState(args.battle_state.resolve())
            ProbeHandler.battle_state = battle_state
        if args.matchmaking:
            selected_mode, battle_ruleset = (
                BATTLE_MODE_PRESETS[args.battle_mode]
                if args.battle_mode is not None else (None, 'annihilation')
            )
            ProbeHandler.matchmaking = NativeMatchmaking(
                offline._NATIVE, pve_battle_probe=args.pve_battle_probe,
                notify=xmpp_hub.send_matchmaking_state,
                legacy_battle_fixture=args.legacy_lab_credentials,
                pve_enemy_tier=args.pve_enemy_tier,
                selected_mode=selected_mode,
                battle_ruleset=battle_ruleset,
                pvp_enabled=bool(pvp_enabled),
                native_five_mode_selector=args.native_five_mode_selector,
                public_pvp_only=public_pvp_only,
                # The ordinary default remains one relay capability.  The
                # companion may explicitly enable both and arbitrate the one
                # loopback relay port during a five-selector session.
                pve_enabled=pve_enabled, cloud_coop_pve=cloud_coop_pve)
            if args.pve_battle_probe:
                def complete_battle(battle_id: str, _user_id: str,
                                    event: dict, rows: list) -> BattleCompletion:
                    return _complete_economy_battle(
                        economy_service, battle_state, ProbeHandler._trace,
                        battle_id, _user_id, event, rows,
                        ProbeHandler.settlement_authority)
                ProbeHandler.completion_callback = complete_battle
        if args.custom_lobby:
            private_battle = args.pve_battle_probe
            private_roster_builder = (NativeMatchmaking(offline._NATIVE)
                                      if private_battle else None)
            cpu_builder = (private_roster_builder._trusted_pve_enemy_squad
                           if private_roster_builder is not None else None)
            human_builder = ((lambda profile: private_roster_builder
                              ._trusted_battle_squad(profile)[0])
                             if private_roster_builder is not None else None)
            def start_private(game: dict, state: dict) -> int:
                return _start_private_cpu_battle(
                    battle_state, xmpp_hub.send_or_queue_custom_starting,
                    ProbeHandler._trace, game, state)
            ProbeHandler.custom_lobby = NativeCustomLobby(
                offline._CATALOG, offline._NATIVE,
                relay_probe=args.relay_handshake or private_battle,
                on_ready=xmpp_hub.send_player_ready if xmpp_hub else None,
                on_loadout=xmpp_hub.send_player_loadout if xmpp_hub else None,
                on_member_joined=xmpp_hub.send_cpu_member_joined if xmpp_hub else None,
                on_member_removed=xmpp_hub.send_cpu_member_removed if xmpp_hub else None,
                on_cpu_ready=xmpp_hub.send_cpu_ready if xmpp_hub else None,
                on_cpu_loadout=xmpp_hub.send_cpu_loadout if xmpp_hub else None,
                on_start=start_private if private_battle else None,
                human_squad_factory=human_builder,
                cpu_squad_factory=cpu_builder,
                cpu_opponents=1 if private_battle else 0,
                credential_factory=_new_private_battle_key if private_battle else None)
            if private_battle:
                def complete_private(battle_id: str, user_id: str,
                                     event: dict, rows: list) -> BattleCompletion:
                    return _complete_private_battle(
                        battle_state, battle_id, user_id, event, rows)
                ProbeHandler.completion_callback = complete_private
        for server in servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            serving.append((server, thread))
        print(json.dumps({'event': 'ready', 'scope': 'loopback-only', 'ports': args.ports}), flush=True)
        if ready is not None:
            ready({'ports': list(args.ports),
                   'xmpp': bool(args.xmpp),
                   'servers': tuple(servers),
                   'region_ping': region_ping,
                   'matchmaking': ProbeHandler.matchmaking,
                   'battle_state': battle_state,
                   'economy_service': economy_service,
                   'unit_control_capability_sha256': (
                       None if unit_control_guard is None
                       else unit_control_guard.capability_sha256
                   ),
                   'xmpp_hub': xmpp_hub})
        if args.auto_pve_start:
            def current_profile() -> dict:
                profile, _ = offline.PROFILE_STATE.respond()
                return profile['profile']
            auto_announcer = AutoAnnouncer(
                ProbeHandler.matchmaking, xmpp_hub,
                trace=ProbeHandler._trace,
                profile_source=current_profile,
                queue_response_ready=ProbeHandler._auto_pve_queue_response_ready,
                queue_response_consumed=ProbeHandler._clear_auto_pve_queue_response,
                allowed_modes={'pve'},
                fence_generation=True,
            )
            auto_announcer.start()
        (stop if stop is not None else threading.Event()).wait()
    except KeyboardInterrupt:
        pass
    finally:
        # Companion-owned workers and relay leases use XMPP and SQLite.  A
        # failed confirmation deliberately aborts teardown: closing their
        # dependencies or restoring class globals while they remain live is
        # unsafe and can orphan a listener or write through a closed DB.
        if before_shutdown is not None:
            before_shutdown()
        if career_cloud is not None:
            career_cloud.close()
        try:
            try:
                if auto_announcer is not None:
                    auto_announcer.stop()
                if region_ping is not None:
                    region_ping.stop()
            finally:
                if xmpp_hub is not None:
                    xmpp_hub.stop()
        finally:
            try:
                if battle_state is not None:
                    battle_state.close()
            finally:
                try:
                    _stop_http_servers(servers, serving)
                finally:
                    try:
                        if career_store is not None:
                            career_store.close()
                    finally:
                        ProbeHandler.career_store = original_career_store
                        (ProbeHandler.career_cloud, ProbeHandler.career_cloud_required) = original_career_cloud
                    if identity_resolver is not None:
                        offline.bind_identity_resolver(None)
                    with _ECONOMY_GLOBALS_LOCK:
                        (offline.CATALOGUE, offline.MAPPINGS, offline.PROFILE,
                         offline.PROFILE_STATE, offline.DEFAULTS,
                         offline.VALIDATION) = original_offline_globals
                    (ProbeHandler.custom_lobby, ProbeHandler.xmpp_hub,
                     ProbeHandler.relay_handshake_enabled, ProbeHandler.matchmaking,
                     ProbeHandler.battle_state, ProbeHandler.economy_service,
                     ProbeHandler.completion_callback,
                     ProbeHandler.private_cloud_adapter,
                     ProbeHandler.native_social_party,
                     ProbeHandler.party_loadout_changed,
                     ProbeHandler.local_region_enabled,
                     ProbeHandler.game_config_enabled,
                     ProbeHandler.native_five_mode_selector,
                     ProbeHandler.private_profile_ready_gate,
                     ProbeHandler.identity_resolver,
                     ProbeHandler.unit_control_guard,
                     ProbeHandler.settlement_authority,
                     ProbeHandler.auto_pve_queue_acks,
                     ProbeHandler.native_user_storage) = original_handler_globals


if __name__ == '__main__':
    main()
