"""Loopback-only native private-lobby state and trusted start boundary.

The host must restrict its listener to loopback. This module opens no sockets,
writes no profile, and grants no persistent items. A host may opt into a local
CPU battle by supplying the trusted ``on_start`` adapter; otherwise the lobby
remains a protocol diagnostic. The native commander tier is separate from the
highest deployed unit tier used for the CPU roster.
"""
from __future__ import annotations

import copy
import inspect
import json
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from collections.abc import Callable
from urllib.parse import parse_qsl

if __package__:
    from .f2p_fake import PLAYER, active_native_user_id, ca_envelope
    from .native_battle_maps import private_cpu_lobby_map_ids
    from .native_private_cpu_contract import (
        NativeKickRequest,
        PrivateCpuContractError,
        apply_cpu_kick,
        parse_native_kick_request,
    )
    from .native_private_cpu_notifications import CpuNotificationDeliveryUncertain
    from .native_private_rematch_contract import (
        PrivateRematchContractError,
        apply_private_rematch,
    )
else:
    from f2p_fake import PLAYER, active_native_user_id, ca_envelope
    from native_battle_maps import private_cpu_lobby_map_ids
    from native_private_cpu_contract import (
        NativeKickRequest,
        PrivateCpuContractError,
        apply_cpu_kick,
        parse_native_kick_request,
    )
    from native_private_cpu_notifications import CpuNotificationDeliveryUncertain
    from native_private_rematch_contract import (
        PrivateRematchContractError,
        apply_private_rematch,
    )

MAX_BODY_BYTES = 65536
UINT64_MASK = (1 << 64) - 1
EFFECTIVE_UNIT_TIER = 10
_PRIVATE_CPU_ID = re.compile(r"cpu-private-([1-9][0-9]*)\Z")
PATHS = frozenset(("/create", "/get_games", "/join", "/battle_check", "/ready", "/unready", "/leave",
                   "/change_squad", "/change_game_settings", "/start_game", "/kick_player"))
UNSUPPORTED_PATHS = frozenset(("/change_team", "/destroy",
                                "/invite"))

_PRIVATE_CPU_CONTRACT_ERRORS = {
    "invalid_kick_request": (400, "invalid_kick_request"),
    "invalid_game_id": (400, "invalid_game_id"),
    "invalid_kick_target": (400, "invalid_kick_target"),
    "invalid_native_metadata": (400, "invalid_native_metadata"),
    "native_lobby_actor_mismatch": (403, "native_lab_user_mismatch"),
    "native_lobby_not_found": (404, "native_lab_lobby_not_found"),
    "cpu_kick_target_not_found": (404, "native_cpu_target_not_found"),
    "private_battle_already_started": (409, "native_private_battle_already_started"),
    "cannot_kick_human_player": (409, "native_cpu_human_target_rejected"),
    "invalid_local_user_id": (503, "invalid_native_lobby_configuration"),
    "invalid_private_lobby_state": (503, "invalid_private_lobby_state"),
    "invalid_private_lobby_roster": (503, "invalid_private_lobby_roster"),
}


class NativeLobbyError(Exception):
    """Safe public failure: never includes request contents or credentials."""

    def __init__(self, status: int, code: str):
        self.status, self.code = status, code
        super().__init__(code)

    def as_envelope(self) -> dict:
        return ca_envelope({"error": self.code}, time.time_ns() // 1_000_000)


def _fail(status: int, code: str):
    raise NativeLobbyError(status, code)


def _cpu_contract_fail(error: PrivateCpuContractError) -> None:
    status, code = _PRIVATE_CPU_CONTRACT_ERRORS.get(
        error.code, (503, "invalid_private_cpu_operation"))
    _fail(status, code)


def _object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            _fail(400, "duplicate_json_key")
        value[key] = item
    return value


def _json(text: str) -> object:
    def bad_constant(_: str):
        _fail(400, "invalid_json_number")
    try:
        return json.loads(text, object_pairs_hook=_object, parse_constant=bad_constant)
    except (ValueError, RecursionError):
        _fail(400, "invalid_json")


def decode_native_request(raw: bytes, content_type: str) -> tuple[dict, dict, bool]:
    """Read JSON headers/request or form headers=<JSON>&request=<JSON>.

    Flat JSON/form fields are also supported for local protocol experiments.
    No ambiguous JSON-under-data/payload convention or MIME sniffing is used.
    The boolean says that direct form scalar values need strict conversion.
    """
    if not isinstance(raw, bytes):
        _fail(400, "invalid_body_type")
    if len(raw) > MAX_BODY_BYTES:
        _fail(413, "body_too_large")
    media, _, parameters = (content_type or "").partition(";")
    media = media.strip().lower()
    if media not in ("application/json", "application/x-www-form-urlencoded"):
        _fail(415, "unsupported_content_type")
    if parameters and not re.fullmatch(r'\s*charset\s*=\s*"?utf-8"?\s*', parameters, re.I):
        _fail(415, "unsupported_charset")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError:
        _fail(400, "invalid_utf8")
    form_scalars = media == "application/x-www-form-urlencoded"
    if not form_scalars:
        body = _json(text)
    else:
        if re.search(r"%(?![0-9a-fA-F]{2})", text):
            _fail(400, "invalid_form")
        try:
            pairs = parse_qsl(text, keep_blank_values=True, strict_parsing=True,
                              encoding="utf-8", errors="strict", max_num_fields=64)
        except (ValueError, UnicodeError):
            _fail(400, "invalid_form")
        body = _object(pairs)
        if "request" in body:
            body["request"] = _json(body["request"])
            form_scalars = False
        if "headers" in body:
            body["headers"] = _json(body["headers"])
    if not isinstance(body, dict):
        _fail(400, "body_must_be_object")
    if "request" in body:
        if set(body) - {"request", "headers"}:
            _fail(400, "ambiguous_request_envelope")
        request = body["request"]
    else:
        request = {key: value for key, value in body.items() if key != "headers"}
    headers = body.get("headers", {})
    if not isinstance(request, dict) or not isinstance(headers, dict):
        _fail(400, "invalid_request_envelope")
    return request, headers, form_scalars


def _uint64(value: object) -> int:
    if type(value) is not int or not -(1 << 63) <= value <= UINT64_MASK:
        _fail(503, "invalid_owned_profile")
    return value & UINT64_MASK


@dataclass(frozen=True)
class ActiveSquad:
    commander_instance_id: int
    commander_key: str
    commander_tier: int
    records: tuple[tuple[int, int, int, int], ...]
    unit_tiers: tuple[int, int, int]

    @property
    def battle_tier(self) -> int:
        return max(self.unit_tiers)

    @property
    def pve_enemy_tier(self) -> int:
        return self.battle_tier


def analyze_active_squad(profile: dict, native_hangar: dict) -> ActiveSquad:
    """Extract the selected owned subtree at the sandbox combat Tier, no writes.

    ``profile`` is the authoritative server projection produced by
    ``build_profile``; its ability-tree links were validated before this
    battle-boundary structural check.

    Requires exactly three direct equipped units of the commander's faction.
    Commander tier is the highest contiguous, owned type-12 progress marker;
    a legacy profile without one remains Tier I.  Owned ability levels must
    belong to that commander and cannot exceed this tier.  IDs are copied as
    integers; callers must not decode them via JS Number.
    """
    # The profile's user_id follows the identity bound into f2p_fake (a
    # companion PUID or the lab ``player``); comparing against the constant
    # rejected every resolver-derived profile before it could queue.
    if not isinstance(profile, dict) or profile.get("user_id") != active_native_user_id():
        _fail(503, "invalid_owned_profile")
    rows, props = profile.get("profile_records"), profile.get("properties")
    if not isinstance(rows, list) or not isinstance(props, list) or len(rows) > 10000:
        _fail(503, "invalid_owned_profile")
    selected = [row[3] for row in props if isinstance(row, list) and len(row) == 4
                and row[0] == "active_commander"]
    if len(selected) != 1:
        _fail(503, "invalid_owned_profile")
    active = _uint64(selected[0])
    records = {}
    for row in rows:
        if not isinstance(row, list) or len(row) != 4:
            _fail(503, "invalid_owned_profile")
        parent, item, instance = (_uint64(value) for value in row[:3])
        quantity = row[3]
        if not item or not instance or instance in records or type(quantity) is not int \
                or not 0 <= quantity <= UINT64_MASK:
            _fail(503, "invalid_owned_profile")
        records[instance] = (parent, item, instance, quantity)
    if active not in records or records[active][0] != 0 or records[active][3] <= 0:
        _fail(503, "invalid_owned_profile")
    try:
        commanders = {row["item_id"]: row for row in native_hangar["commanders"]
                      if row.get("build_state") == "live"}
        units = {row["item_id"]: row for row in native_hangar["units"]
                 if row.get("build_state") == "live"}
        commander = commanders[records[active][1]]
    except (KeyError, TypeError):
        _fail(503, "unknown_owned_commander")

    tier_definitions = {row.get("item_id"): row for row in native_hangar.get("commander_tiers", [])
                        if row.get("commander") == commander.get("key")}
    owned_tiers = []
    for row in records.values():
        definition = tier_definitions.get(row[1])
        if definition is None:
            continue
        tier = definition.get("tier")
        if row[0] != 0 or row[3] != 1 or type(tier) is not int or not 1 <= tier <= 10:
            _fail(503, "invalid_commander_progress")
        owned_tiers.append(tier)
    if len(owned_tiers) != len(set(owned_tiers)):
        _fail(503, "invalid_commander_progress")
    commander_tier = max(owned_tiers, default=1)
    if owned_tiers and set(owned_tiers) != set(range(1, commander_tier + 1)):
        _fail(503, "invalid_commander_progress")

    ability_definitions = {row.get("item_id"): row
                           for row in native_hangar.get("ability_levels", [])}
    owned_ability_levels: dict[str, set[int]] = {}
    for row in records.values():
        definition = ability_definitions.get(row[1])
        if definition is None or row[0] != active:
            continue
        metadata = definition.get("metadata")
        ability_key = metadata.get("ability_key") if isinstance(metadata, dict) else None
        required_tier = metadata.get(commander.get("key")) if isinstance(metadata, dict) else None
        ability_level = metadata.get("ability_level") if isinstance(metadata, dict) else None
        if (definition.get("commander") != commander.get("key") or row[3] != 1
                or not isinstance(ability_key, str) or not ability_key
                or type(required_tier) is not int or not 1 <= required_tier <= commander_tier
                or type(ability_level) is not int or ability_level < 1):
            _fail(503, "invalid_commander_progress")
        levels = owned_ability_levels.setdefault(ability_key, set())
        if ability_level in levels:
            _fail(503, "invalid_commander_progress")
        levels.add(ability_level)
    for levels in owned_ability_levels.values():
        highest = max(levels)
        if levels != set(range(1, highest + 1)):
            _fail(503, "invalid_commander_progress")
    direct_units = [row for row in records.values() if row[0] == active and row[1] in units]
    if len(direct_units) != 3:
        _fail(503, "invalid_equipped_squad")
    tiers = []
    for row in direct_units:
        unit = units[row[1]]
        tier = unit.get("tier")
        if row[3] != 1 or unit.get("faction") != commander.get("faction") \
                or type(tier) is not int or not 1 <= tier <= 10:
            _fail(503, "invalid_equipped_squad")
        # The native tier remains part of the trusted unit identity and is
        # validated above.  Both public and private battle allocation use the
        # Revival sandbox's effective Tier X, matching LocalEconomy and the
        # Cloudflare matchmaking contract.
        tiers.append(EFFECTIVE_UNIT_TIER)
    included = {active}
    while True:
        more = {instance for instance, row in records.items()
                if row[0] in included and instance not in included}
        if not more:
            break
        included.update(more)
    ordered = [active] + [instance for instance in records if instance in included and instance != active]
    for instance in ordered:
        row = records[instance]
        if row[3] <= 0 or (instance != active and row[1] in commanders):
            _fail(503, "invalid_equipped_squad")
    return ActiveSquad(active, commander["key"], commander_tier,
                       tuple(records[i] for i in ordered), tuple(tiers))


class NativeCustomLobby:
    """Single local user plus trusted CPU rows in one native private lobby.

    native_user_id is a trusted local session fixture value, not an auth token.
    username is always PLAYER. Commander tier normally comes from the trusted
    profile's progress markers. Tests and protocol experiments may pass an
    explicit native_commander_tier override.

    on_ready/on_loadout are trusted synchronous, idempotent callbacks, not
    supplied by HTTP. A complete lobby state is committed under the lock
    before notification. Callback errors leave that state committed, return
    a safe 503, and retain the latest notification for retry. Notifications
    cannot be rolled back after an external receiver observes them; there
    is no distributed transaction guarantee. The callback may read state
    properties but must not reenter mutations or perform a blocking wait.

    relay_probe=True is trusted host configuration only. Without ``on_start``
    it advertises the historical fixed loopback diagnostic listener and never
    starts a battle merely because a user readies up. With ``on_start``, the
    explicit ``/start_game`` request hands the frozen private roster to the
    local battle adapter and sends the native start notification exactly once.
    """

    def __init__(self, catalog: dict, native_hangar: dict, *, native_user_id: str = PLAYER,
                 on_ready: Callable[[str, bool], None] | None = None,
                 on_loadout: Callable[[str, dict], None] | None = None,
                 on_member_joined: Callable[[str, dict], int] | None = None,
                 on_member_removed: Callable[[str, str], int] | None = None,
                 on_cpu_ready: Callable[[str, str], int] | None = None,
                 on_cpu_loadout: Callable[[str, str, dict], int] | None = None,
                 on_start: Callable[[dict, dict], int] | None = None,
                 human_squad_factory: Callable[[dict], ActiveSquad] | None = None,
                 cpu_squad_factory: Callable[[int], ActiveSquad] | None = None,
                 cpu_opponents: int = 0,
                 credential_factory: Callable[[], int | str] | None = None,
                 relay_probe: bool = False):
        maps = private_cpu_lobby_map_ids(catalog)
        if not isinstance(native_user_id, str) or not native_user_id or len(native_user_id) > 128 \
                or any(ord(char) < 33 or ord(char) > 126 for char in native_user_id):
            raise ValueError("A known local native user ID is required")
        if on_ready is not None and (not callable(on_ready) or inspect.iscoroutinefunction(on_ready)
                                     or inspect.iscoroutinefunction(getattr(on_ready, "__call__", None))):
            raise ValueError("on_ready must be a synchronous callable")
        if on_loadout is not None and (not callable(on_loadout) or inspect.iscoroutinefunction(on_loadout)
                                       or inspect.iscoroutinefunction(getattr(on_loadout, "__call__", None))):
            raise ValueError("on_loadout must be a synchronous callable")
        for callback, name in ((on_member_joined, "on_member_joined"),
                               (on_member_removed, "on_member_removed"),
                               (on_cpu_ready, "on_cpu_ready"),
                               (on_cpu_loadout, "on_cpu_loadout"),
                               (on_start, "on_start"),
                               (human_squad_factory, "human_squad_factory"),
                               (cpu_squad_factory, "cpu_squad_factory"),
                               (credential_factory, "credential_factory")):
            if callback is not None and (
                    not callable(callback) or inspect.iscoroutinefunction(callback)
                    or inspect.iscoroutinefunction(getattr(callback, "__call__", None))):
                raise ValueError(f"{name} must be a synchronous callable")
        if type(cpu_opponents) is not int or not 0 <= cpu_opponents <= 10:
            raise ValueError("cpu_opponents must be an integer from 0 to 10")
        if cpu_opponents and cpu_squad_factory is None:
            raise ValueError("cpu_squad_factory is required for CPU opponents")
        if on_start is not None and not relay_probe:
            raise ValueError("on_start requires relay_probe")
        if type(relay_probe) is not bool:
            raise ValueError("relay_probe must be a boolean")
        self.native_user_id = native_user_id
        self._maps = tuple(maps)
        self._native = copy.deepcopy(native_hangar)
        self._lock = threading.RLock()
        self._game = None
        self._lab_state = None
        self._on_ready = on_ready
        self._on_loadout = on_loadout
        self._on_member_joined = on_member_joined
        self._on_member_removed = on_member_removed
        self._on_cpu_ready = on_cpu_ready
        self._on_cpu_loadout = on_cpu_loadout
        self._on_start = on_start
        self._human_squad_factory = human_squad_factory
        self._cpu_squad_factory = cpu_squad_factory
        # Constructor count is only the initial room population.  Live rows
        # thereafter are authoritative so removals, gaps and high-water IDs
        # survive every profile refresh.
        self._initial_cpu_opponents = cpu_opponents
        self._cpu_opponents = cpu_opponents
        self._credential_factory = credential_factory
        self._relay_probe = relay_probe
        self._ready_notification = None
        self._loadout_notification = None
        self._member_notifications: list[tuple[str, str, object]] = []
        self._cpu_loadout_notifications: dict[tuple[str, str], dict] = {}
        self._kick_receipts: set[tuple[str, str]] = set()
        self._management_retry: dict | None = None
        self._rematch_receipt: dict | None = None
        # These identifiers are excluded from lab_state because that diagnostic
        # object is written to metadata traces.
        self._battle_instance_id: str | None = None
        self._battle_round = 1
        self._completed_battle_instance_ids: list[str] = []
        self._completed_battle_rounds: list[dict] = []
        self._in_callback = False
        self._notified_game_id = None
        self._profile_saved = None

    @property
    def game_id(self) -> str | None:
        """Trusted host integration only; not included in diagnostic state."""
        with self._lock:
            return None if self._game is None else self._game["game_id"]

    @property
    def lab_state(self) -> dict | None:
        """Diagnostic/PvE preview only, intentionally absent from native JSON."""
        with self._lock:
            return copy.deepcopy(self._lab_state)

    @property
    def battle_instance_id(self) -> str | None:
        """Trusted result/relay integration only; never included in traces."""
        with self._lock:
            return self._battle_instance_id

    def resolve_battle_instance(self, room_game_id: str, battle_key: str, *,
                                include_completed: bool = False) -> str:
        """Map stable native wire identity to one unique SQLite battle key.

        Arbitration and relay joins use the current-only default. Final-event
        retries may set ``include_completed`` because their decimal credential
        disambiguates a retained earlier round using the same room UUID.
        """
        with self._lock:
            if (self._game is None or room_game_id != self._game.get("game_id")
                    or type(battle_key) is not str):
                _fail(409, "native_private_battle_identity_mismatch")
            if (battle_key == self._game.get("battle_key")
                    and self._battle_instance_id is not None):
                return self._battle_instance_id
            if include_completed:
                matches = [row["battle_instance_id"]
                           for row in self._completed_battle_rounds
                           if row.get("battle_key") == battle_key]
                if len(matches) == 1:
                    return matches[0]
            _fail(409, "native_private_battle_identity_mismatch")

    def latest_completed_battle_instance(self, room_game_id: str) -> str | None:
        """Resolve a credential-free result GET without changing wire IDs."""
        with self._lock:
            if self._game is None or room_game_id != self._game.get("game_id"):
                _fail(409, "native_private_battle_identity_mismatch")
            return (None if not self._completed_battle_rounds
                    else self._completed_battle_rounds[-1]["battle_instance_id"])

    def resolve_result_battle_instance(self, room_game_id: str) -> str:
        """Resolve the round represented by native's stable result URL.

        Before delivery the active round owns the URL.  ``prepare_rematch``
        then rotates the room, so idempotent result retries continue to read
        the most recently completed immutable round until the next start.
        """
        with self._lock:
            if self._game is None or room_game_id != self._game.get("game_id"):
                _fail(409, "native_private_battle_identity_mismatch")
            if (self._lab_state is not None
                    and self._lab_state.get("battle_started") is True
                    and self._battle_instance_id is not None):
                return self._battle_instance_id
            if self._completed_battle_rounds:
                return self._completed_battle_rounds[-1]["battle_instance_id"]
            _fail(409, "native_private_battle_not_started")

    def _owner(self, profile: dict, native_commander_tier: int | None) -> tuple[dict, dict]:
        try:
            squad = (analyze_active_squad(profile, self._native)
                     if self._human_squad_factory is None
                     else self._human_squad_factory(profile))
        except NativeLobbyError:
            raise
        except Exception:
            _fail(503, "invalid_private_human_roster")
        if not isinstance(squad, ActiveSquad) or len(squad.records) == 0:
            _fail(503, "invalid_private_human_roster")
        if native_commander_tier is None:
            native_commander_tier = squad.commander_tier
        if type(native_commander_tier) is not int or not 1 <= native_commander_tier <= 10:
            _fail(503, "unknown_native_commander_tier")
        owner = {
            "user_id": self.native_user_id, "display_name": PLAYER, "team_id": 1,
            "ready": False, "online_status": "online", "is_ai": False,
            "profile_matchmaking_details": {
                "commander_tier": native_commander_tier,
                "full_squad_setup": [list(row) for row in squad.records],
                "new_player": False, "premium": False,
            },
        }
        state = {"commander_key": squad.commander_key, "unit_tiers": list(squad.unit_tiers),
                 "battle_tier": squad.battle_tier, "pve_enemy_tier": squad.pve_enemy_tier,
                  "native_commander_tier": native_commander_tier, "battle_started": False,
                  "ready": False, "relay_probe": self._relay_probe,
                 "cpu_opponents": self._initial_cpu_opponents,
                 "cpu_id_high_watermark": self._initial_cpu_opponents,
                 "reward_policy": "none",
                 "room_creation_cost_silver_cents": 0,
                 "battle_cost_silver_cents": 0,
                 "commander_unlock_cost_silver_cents": 0,
                 "unit_unlock_cost_silver_cents": 0,
                 "ability_unlock_cost_silver_cents": 0,
                 "equipment_unlock_cost_silver_cents": 0,
                 "consumable_cost_silver_cents": 0,
                 "private_entitlements": {
                     "scope": "battle_only",
                     "persist_to_profile": False,
                     "all_units": True,
                     "all_commander_abilities": True,
                     "all_equipment": True,
                     "all_consumables": True,
                 }}
        return owner, state

    def _new_battle_key(self) -> str:
        try:
            value = (self._credential_factory() if self._credential_factory is not None
                     else (secrets.randbelow(UINT64_MASK) + 1
                           if self._on_start is not None else 1))
        except Exception:
            _fail(503, "native_private_credential_generation_failed")
        if type(value) is int:
            if not 1 <= value <= UINT64_MASK:
                _fail(503, "invalid_native_private_credentials")
            return str(value)
        if (not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", value)
                or int(value) > UINT64_MASK or value != str(int(value))):
            _fail(503, "invalid_native_private_credentials")
        return value

    def _cpu_details(self, battle_tier: int) -> dict:
        if self._cpu_squad_factory is None:
            _fail(409, "native_private_cpu_factory_unavailable")
        try:
            squad = self._cpu_squad_factory(battle_tier)
        except NativeLobbyError:
            raise
        except Exception:
            _fail(503, "invalid_private_cpu_roster")
        if (not isinstance(squad, ActiveSquad)
                or squad.battle_tier != battle_tier
                or len(squad.records) == 0):
            _fail(503, "invalid_private_cpu_roster")
        return {
            "commander_tier": squad.commander_tier,
            "full_squad_setup": [list(row) for row in squad.records],
            "new_player": False,
            "premium": False,
        }

    def _cpu_player(self, battle_tier: int, sequence: int,
                    details: dict | None = None) -> dict:
        if type(sequence) is not int or sequence < 1:
            _fail(503, "invalid_private_cpu_roster")
        if details is None:
            details = self._cpu_details(battle_tier)
        return {
            "user_id": f"cpu-private-{sequence}",
            "display_name": f"CPU {sequence}",
            "team_id": 2,
            "ready": True,
            "online_status": "online",
            "is_ai": True,
            "profile_matchmaking_details": copy.deepcopy(details),
        }

    def _cpu_players(self, battle_tier: int) -> list[dict]:
        if not self._initial_cpu_opponents:
            return []
        details = self._cpu_details(battle_tier)
        return [self._cpu_player(battle_tier, index, details)
                for index in range(1, self._initial_cpu_opponents + 1)]

    def _check_reentry(self) -> None:
        if self._in_callback:
            _fail(409, "native_lab_callback_reentry")

    def _profile_version(self, profile: dict) -> int:
        """Reject delayed snapshots, using only the trusted profile version.

        Equal versions may change formation in local fixtures. A rejected
        older /ready must not accidentally ready a newly selected formation.
        The watermark changes only alongside a fully validated roster commit.
        """
        saved = profile.get("saved") if isinstance(profile, dict) else None
        if type(saved) is not int or not 0 <= saved <= UINT64_MASK:
            _fail(503, "invalid_owned_profile")
        if self._profile_saved is not None and saved < self._profile_saved:
            _fail(409, "native_lab_stale_profile")
        return saved

    def _notify_members(self) -> None:
        """Flush committed roster mutations in order, retaining failures."""
        while self._member_notifications:
            kind, game_id, payload = self._member_notifications[0]
            callback = {
                "joined": self._on_member_joined,
                "removed": self._on_member_removed,
                "ready": self._on_cpu_ready,
            }.get(kind)
            if kind not in {"joined", "removed", "ready"}:
                _fail(503, "invalid_private_cpu_notification")
            if callback is not None:
                self._in_callback = True
                try:
                    value = copy.deepcopy(payload) if kind == "joined" else payload
                    recipients = callback(game_id, value)
                except CpuNotificationDeliveryUncertain:
                    # The native client may already have processed this stanza.
                    # Consume it and require an acknowledgement-only retry;
                    # resending player_joined_cg can duplicate a roster row.
                    self._member_notifications.pop(0)
                    _fail(503, "native_lab_roster_notification_uncertain")
                except Exception:
                    _fail(503, "native_lab_roster_notification_failed")
                finally:
                    self._in_callback = False
                if type(recipients) is not int or recipients <= 0:
                    _fail(503, "native_lab_roster_notification_failed")
            self._member_notifications.pop(0)
            receipt = self._management_retry
            if (isinstance(receipt, dict) and receipt.get("user_id") == payload
                    and ((kind == "removed" and receipt.get("operation") == "remove")
                         or (kind == "ready" and receipt.get("operation") == "add"))):
                # A management receipt is useful only while its final outbox
                # job remains. Other refresh/native paths may flush that job.
                self._management_retry = None

    def _notify_cpu_loadouts(self) -> None:
        """Flush latest committed loadout for each stable CPU identity."""
        while self._cpu_loadout_notifications:
            key = next(iter(self._cpu_loadout_notifications))
            game_id, player_id = key
            details = self._cpu_loadout_notifications[key]
            if self._on_cpu_loadout is not None:
                self._in_callback = True
                try:
                    recipients = self._on_cpu_loadout(
                        game_id, player_id, copy.deepcopy(details))
                except CpuNotificationDeliveryUncertain:
                    del self._cpu_loadout_notifications[key]
                    _fail(503, "native_lab_cpu_loadout_notification_uncertain")
                except Exception:
                    _fail(503, "native_lab_cpu_loadout_notification_failed")
                finally:
                    self._in_callback = False
                if type(recipients) is not int or recipients <= 0:
                    _fail(503, "native_lab_cpu_loadout_notification_failed")
            del self._cpu_loadout_notifications[key]

    def _notify_ready(self) -> None:
        """Flush the latest committed state; caller holds the lobby lock."""
        if self._ready_notification is None:
            return
        game_id, ready = self._ready_notification
        if self._on_ready is not None:
            self._in_callback = True
            try:
                self._on_ready(game_id, ready)
            except Exception:
                _fail(503, "native_lab_ready_notification_failed")
            finally:
                self._in_callback = False
        self._ready_notification = None

    def _notify_loadout(self) -> None:
        """Flush a copied, committed formation; callback cannot mutate it."""
        if self._loadout_notification is None:
            return
        game_id, details = self._loadout_notification
        if self._on_loadout is not None:
            self._in_callback = True
            try:
                self._on_loadout(game_id, copy.deepcopy(details))
            except Exception:
                _fail(503, "native_lab_loadout_notification_failed")
            finally:
                self._in_callback = False
        self._loadout_notification = None

    def _notify_all(self) -> None:
        # Native DDA1E0 rebuilds the row and clears its ready flags without
        # recomputing the overall button. Send not_ready after the loadout,
        # then allow any later ready=true only once both updates succeeded.
        self._notify_members()
        self._notify_cpu_loadouts()
        self._notify_loadout()
        self._notify_ready()

    def _refresh(self, profile: dict, native_commander_tier: int | None) -> bool:
        """Commit a complete refreshed roster and report a formation change."""
        if self._game is None:
            return False
        saved = self._profile_version(profile)
        owner, state = self._owner(profile, native_commander_tier)
        previous = self._game["players"][0]
        old_details, new_details = (value["profile_matchmaking_details"] for value in (previous, owner))
        changed = (old_details["commander_tier"] != new_details["commander_tier"]
                   or sorted(old_details["full_squad_setup"]) != sorted(new_details["full_squad_setup"]))
        # Mere source row ordering or a profile timestamp update is not a
        # formation change. Preserve the published order when nothing changed.
        if not changed:
            owner = copy.deepcopy(previous)
        published_players = self._game.get("players")
        if (not isinstance(published_players, list) or not published_players
                or not isinstance(published_players[0], dict)
                or published_players[0].get("user_id") != self.native_user_id
                or published_players[0].get("is_ai") is not False):
            _fail(503, "invalid_private_cpu_roster")
        cpu_players = [copy.deepcopy(player) for player in published_players[1:]]
        high_watermark = self._lab_state.get("cpu_id_high_watermark")
        if (type(high_watermark) is not int or high_watermark < 0
                or len(cpu_players) != self._lab_state.get("cpu_opponents")):
            _fail(503, "invalid_private_cpu_roster")
        cpu_ids = []
        for player in cpu_players:
            match = (_PRIVATE_CPU_ID.fullmatch(player.get("user_id", ""))
                     if isinstance(player, dict) else None)
            if (match is None or player.get("is_ai") is not True
                    or player.get("team_id") != 2 or player.get("ready") is not True
                    or int(match.group(1)) > high_watermark):
                _fail(503, "invalid_private_cpu_roster")
            cpu_ids.append(player["user_id"])
        if len(cpu_ids) != len(set(cpu_ids)):
            _fail(503, "invalid_private_cpu_roster")
        old_battle_tier = self._lab_state.get("battle_tier")
        cpu_loadout_updates = {}
        if old_battle_tier != state["battle_tier"] and cpu_players:
            cpu_details = self._cpu_details(state["battle_tier"])
            for player in cpu_players:
                player["profile_matchmaking_details"] = copy.deepcopy(cpu_details)
                cpu_loadout_updates[(self._game["game_id"],
                                     player["user_id"])] = copy.deepcopy(cpu_details)
        state["ready"] = owner["ready"]
        state["battle_started"] = self._lab_state["battle_started"]
        state["cpu_opponents"] = len(cpu_players)
        state["cpu_id_high_watermark"] = high_watermark
        game = copy.deepcopy(self._game)
        game["players"] = [owner, *cpu_players]
        self._game, self._lab_state = game, state
        self._cpu_loadout_notifications.update(cpu_loadout_updates)
        self._profile_saved = saved
        if changed:
            self._ready_notification = (game["game_id"], False)
            # Native /unready and /change_squad can precede the matching
            # /profile save. The post-save refresh must publish the newly
            # confirmed formation even when no earlier notification failed.
            self._loadout_notification = (game["game_id"], copy.deepcopy(new_details))
        return changed

    def _set_ready(self, ready: bool) -> None:
        if self._game["players"][0]["ready"] != ready:
            game, state = copy.deepcopy(self._game), copy.deepcopy(self._lab_state)
            game["players"][0]["ready"] = ready
            state["ready"] = ready
            self._game, self._lab_state = game, state
            self._ready_notification = (game["game_id"], ready)

    def refresh(self, profile: dict, *, native_commander_tier: int | None = None) -> dict | None:
        """Refresh owned formation; changed rosters clear readiness atomically."""
        with self._lock:
            self._check_reentry()
            self._refresh(profile, native_commander_tier)
            self._notify_all()
            return copy.deepcopy(self._lab_state)

    def _commit_cpu_kick(self, kick: NativeKickRequest) -> dict:
        try:
            mutation = apply_cpu_kick(self._game, self._lab_state, kick)
        except PrivateCpuContractError as error:
            _cpu_contract_fail(error)
        self._game, self._lab_state = mutation.game, mutation.lab_state
        target = mutation.removed_player["user_id"]
        self._kick_receipts.add((kick.game_id, target))
        self._member_notifications.append(("removed", kick.game_id, target))
        if mutation.ready_was_cleared:
            self._ready_notification = (kick.game_id, False)
        return {
            "operation": "remove",
            "cpu_opponents": mutation.cpu_opponents,
            "user_id": target,
        }

    def _management_retry_result(self, operation: str,
                                 target: str | None = None) -> dict | None:
        receipt = self._management_retry
        if receipt is None:
            return None
        if (receipt.get("operation") != operation
                or (operation == "remove" and receipt.get("user_id") != target)):
            _fail(409, "native_host_management_retry_pending")
        # A state mutation may already have committed before XMPP delivery
        # failed.  Retry only that outbox and acknowledge the prior mutation;
        # never allocate or remove a second CPU implicitly.
        self._notify_all()
        self._management_retry = None
        return copy.deepcopy(receipt)

    def host_add_cpu(self, profile: dict, *,
                     native_commander_tier: int | None = None) -> dict:
        """Explicit loopback host-management boundary; not a native HTTP API."""
        with self._lock:
            self._check_reentry()
            if self._on_member_joined is None or self._on_cpu_ready is None:
                _fail(503, "native_private_cpu_notifications_unavailable")
            retry = self._management_retry_result("add")
            if retry is not None:
                return retry
            self._notify_all()
            self._refresh(profile, native_commander_tier)
            self._notify_all()
            if self._game is None:
                _fail(404, "native_lab_lobby_not_found")
            if self._lab_state["battle_started"]:
                _fail(409, "native_private_battle_already_started")
            count = self._lab_state.get("cpu_opponents")
            if type(count) is not int or not 0 <= count <= 10:
                _fail(503, "invalid_private_cpu_roster")
            if count >= 10:
                _fail(409, "native_private_cpu_limit_reached")
            if len(self._game["players"]) >= self._game["settings"]["max_players"]:
                _fail(409, "private_cpu_capacity_exceeded")
            high_watermark = self._lab_state.get("cpu_id_high_watermark")
            if type(high_watermark) is not int or high_watermark < 0:
                _fail(503, "invalid_private_cpu_roster")
            sequence = high_watermark + 1
            player = self._cpu_player(self._lab_state["battle_tier"], sequence)
            game, state = copy.deepcopy(self._game), copy.deepcopy(self._lab_state)
            was_ready = game["players"][0]["ready"]
            game["players"].append(player)
            if was_ready:
                game["players"][0]["ready"] = False
            state["ready"] = False
            state["cpu_opponents"] = count + 1
            state["cpu_id_high_watermark"] = sequence
            self._game, self._lab_state = game, state
            self._member_notifications.append(
                ("joined", game["game_id"], copy.deepcopy(player)))
            self._member_notifications.append(
                ("ready", game["game_id"], player["user_id"]))
            if was_ready:
                self._ready_notification = (game["game_id"], False)
            receipt = {"operation": "add", "cpu_opponents": count + 1,
                       "user_id": player["user_id"]}
            self._management_retry = copy.deepcopy(receipt)
            self._notify_all()
            self._management_retry = None
            return receipt

    def host_remove_cpu(self, target_user_id: str, profile: dict, *,
                        native_commander_tier: int | None = None) -> dict:
        """Remove a stable CPU ID through the loopback host management API."""
        if type(target_user_id) is not str or _PRIVATE_CPU_ID.fullmatch(target_user_id) is None:
            _fail(400, "invalid_kick_target")
        with self._lock:
            self._check_reentry()
            if self._on_member_removed is None:
                _fail(503, "native_private_cpu_notifications_unavailable")
            retry = self._management_retry_result("remove", target_user_id)
            if retry is not None:
                return retry
            self._notify_all()
            self._refresh(profile, native_commander_tier)
            self._notify_all()
            if self._game is None:
                _fail(404, "native_lab_lobby_not_found")
            kick = NativeKickRequest(
                self._game["game_id"], self.native_user_id, target_user_id)
            receipt = self._commit_cpu_kick(kick)
            self._management_retry = copy.deepcopy(receipt)
            self._notify_all()
            self._management_retry = None
            return receipt

    def prepare_rematch(self, completed_battle_instance_id: str,
                        completed_phase: str) -> dict:
        """Rotate one delivered battle while preserving its native room.

        The result adapter calls this only after LocalBattleState has retained
        the old final and advanced it to ``delivered``. The native room UUID,
        settings and CPU identities remain stable; the next durable battle UUID
        and decimal credential are new. The not-ready event stays queued until
        the next lobby request, when the notification resource has returned.
        """
        with self._lock:
            self._check_reentry()
            receipt = self._rematch_receipt
            if receipt is not None:
                if (completed_phase != "delivered"
                        or receipt.get("completed_battle_instance_id")
                        != completed_battle_instance_id):
                    _fail(409, "native_private_rematch_pending")
                return copy.deepcopy(receipt)
            self._notify_all()
            if self._game is None or self._lab_state is None:
                _fail(404, "native_lab_lobby_not_found")
            if not self._relay_probe or self._on_start is None:
                _fail(409, "native_private_rematch_unavailable")
            if completed_phase != "delivered":
                _fail(409, "native_private_result_not_delivered")
            if (self._lab_state.get("battle_started") is not True
                    or self._battle_instance_id != completed_battle_instance_id):
                _fail(409, "native_private_battle_completion_mismatch")
            tracked_state = {
                **copy.deepcopy(self._lab_state),
                "battle_instance_id": self._battle_instance_id,
                "battle_round": self._battle_round,
                "completed_battle_instance_ids": copy.deepcopy(
                    self._completed_battle_instance_ids),
            }
            next_battle_key = self._new_battle_key()
            if next_battle_key in {
                    self._game.get("battle_key"),
                    *(row.get("battle_key")
                      for row in self._completed_battle_rounds)}:
                _fail(503, "native_duplicate_private_battle_credential")
            completed_round = {
                "battle_instance_id": self._battle_instance_id,
                "battle_key": self._game["battle_key"],
                "battle_round": self._battle_round,
            }
            try:
                mutation = apply_private_rematch(
                    self._game,
                    tracked_state,
                    completed_battle_instance_id=completed_battle_instance_id,
                    completed_phase=completed_phase,
                    next_battle_instance_id=str(uuid.uuid4()),
                    next_battle_key=next_battle_key,
                )
            except PrivateRematchContractError as error:
                status = (409 if error.code in {
                    "private_result_not_delivered",
                    "private_battle_completion_mismatch",
                    "duplicate_private_battle_instance_id",
                } else 503)
                _fail(status, "native_" + error.code)
            next_state = copy.deepcopy(mutation.lab_state)
            self._battle_instance_id = next_state.pop("battle_instance_id")
            self._battle_round = next_state.pop("battle_round")
            self._completed_battle_instance_ids = next_state.pop(
                "completed_battle_instance_ids")
            self._completed_battle_rounds.append(completed_round)
            self._game, self._lab_state = mutation.game, next_state
            self._ready_notification = (mutation.room_game_id, False)
            receipt = {
                "room_game_id": mutation.room_game_id,
                "completed_battle_instance_id": (
                    mutation.completed_battle_instance_id),
                "next_battle_instance_id": mutation.next_battle_instance_id,
                "battle_round": mutation.battle_round,
            }
            self._rematch_receipt = copy.deepcopy(receipt)
            return receipt

    def notify_relay_handshake(self, profile: dict, notify: Callable[[str], int], *,
                               native_commander_tier: int | None = None) -> int:
        """Explicit trusted loopback diagnostic, never a battle-start API.

        Refresh, readiness/identity checks and synchronous hub notification
        share the lobby lock, so leave/unready/recreate cannot interleave.
        A positive integer receiver count marks this lobby as notified once.
        Zero, invalid results or exceptions are safe retryable failures; an
        external partial send cannot be rolled back or exactly-once promised.
        The trusted notifier must not reenter mutations or block waiting for
        another lobby operation. No game ID or diagnostic key enters logs.
        """
        with self._lock:
            self._check_reentry()
            self._refresh(profile, native_commander_tier)
            self._notify_all()
            if not self._relay_probe:
                _fail(409, "native_lab_relay_probe_disabled")
            if self._game is None:
                _fail(404, "native_lab_lobby_not_found")
            if not self._lab_state["ready"]:
                _fail(409, "native_lab_not_ready")
            game_id = self._game["game_id"]
            if self._notified_game_id == game_id:
                _fail(409, "probe_already_notified")
            self._in_callback = True
            try:
                if not callable(notify) or inspect.iscoroutinefunction(notify) \
                        or inspect.iscoroutinefunction(getattr(notify, "__call__", None)):
                    _fail(503, "probe_client_not_connected")
                recipients = notify(game_id)
            except Exception:
                _fail(503, "probe_client_not_connected")
            finally:
                self._in_callback = False
            if type(recipients) is not int or recipients <= 0:
                _fail(503, "probe_client_not_connected")
            self._notified_game_id = game_id
            return recipients

    def handle(self, path: str, raw: bytes, content_type: str, profile: dict, *,
               method: str = "POST", native_commander_tier: int | None = None) -> dict | None:
        """Return a fresh native envelope, None for unknown path, or safe error.

        Exact CACUGS paths only: do not dispatch by substring or add /custom.
        The server must catch NativeLobbyError and use its non-success status.
        All state checks and mutations are atomic across HTTP handler threads.
        """
        if path not in PATHS and path not in UNSUPPORTED_PATHS:
            return None
        if path in UNSUPPORTED_PATHS:
            _fail(409, "native_lab_operation_disabled")
        if method != "POST":
            _fail(405, "method_not_allowed")
        request, headers, form = decode_native_request(raw, content_type)
        kick = None
        if path == "/kick_player":
            try:
                kick = parse_native_kick_request(
                    request, headers, local_user_id=self.native_user_id)
            except PrivateCpuContractError as error:
                _cpu_contract_fail(error)
            for source in (request, headers):
                if "username" in source and source["username"] != PLAYER:
                    _fail(403, "native_lab_user_mismatch")
        else:
            for source in (request, headers):
                if "user_id" in source and source["user_id"] != self.native_user_id:
                    _fail(403, "native_lab_user_mismatch")
                if "username" in source and source["username"] != PLAYER:
                    _fail(403, "native_lab_user_mismatch")
        if not isinstance(profile, dict) or profile.get("user_id") != PLAYER:
            _fail(503, "invalid_owned_profile")
        if path in ("/create", "/join") and request.get("username") != PLAYER:
            _fail(403, "native_lab_user_mismatch")
        if "relay_server" in request or not (request.get("ready", False) is False
                                             or (form and request.get("ready") == "false")):
            _fail(409, "native_lab_operation_disabled")
        if "battle_key" in request:
            if path != "/battle_check" or type(request["battle_key"]) is not str:
                _fail(409, "native_lab_operation_disabled")
        if path == "/change_game_settings":
            self._change_settings_fields(request, form)
        elif path in ("/ready", "/unready", "/leave", "/change_squad", "/start_game"):
            self._action_fields(request, form)
        with self._lock:
            self._check_reentry()
            if path == "/create":
                if self._game is not None:
                    _fail(409, "native_lab_lobby_exists")
                settings = self._settings(request, form)
                if settings["max_players"] < 1 + self._initial_cpu_opponents:
                    _fail(400, "private_cpu_capacity_exceeded")
                saved = self._profile_version(profile)
                owner, state = self._owner(profile, native_commander_tier)
                # A previous leave may have committed before notification
                # failed. Deliver its pending false before creating a room.
                self._notify_all()
                game_id = str(uuid.uuid4())
                self._game = {
                    "game_id": game_id, "owner_id": self.native_user_id,
                    "settings": settings,
                    "battle_key": self._new_battle_key() if self._relay_probe else "",
                    "maps": list(self._maps),
                    "teams": [{"team_id": 1, "team_name": "Team 1"},
                              {"team_id": 2, "team_name": "Team 2"}],
                    "players": [owner, *self._cpu_players(state["battle_tier"])],
                }
                if self._relay_probe:
                    self._game["relay_server"] = "127.0.0.1:19000"
                self._battle_instance_id = game_id
                self._battle_round = 1
                self._completed_battle_instance_ids = []
                self._completed_battle_rounds = []
                self._lab_state = state
                self._profile_saved = saved
                payload = {"result": self._game}
            elif path == "/get_games":
                self.refresh(profile, native_commander_tier=native_commander_tier)
                payload = {"result": [] if self._game is None else [self._game]}
            else:
                if not isinstance(request.get("game_id"), str) \
                        or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", request["game_id"]):
                    _fail(400, "invalid_game_id")
                if path == "/leave" and self._game is None \
                        and self._ready_notification == (request["game_id"], False):
                    self._notify_ready()
                    return ca_envelope({"result": "ok"}, time.time_ns() // 1_000_000)
                if self._game is None or request["game_id"] != self._game["game_id"]:
                    _fail(404, "native_lab_lobby_not_found")
                if ("battle_key" in request
                        and request["battle_key"] != self._game["battle_key"]):
                    _fail(409, "native_lab_operation_disabled")
                if self._game["owner_id"] != self.native_user_id:
                    _fail(403, "native_lab_user_mismatch")
                if (self._lab_state.get("battle_started") is True
                        and path in {"/leave", "/ready", "/unready",
                                     "/change_squad", "/change_game_settings",
                                     "/kick_player"}):
                    # Once /start_game has durably allocated the battle, its
                    # queued cg_starting notice is part of that frozen state.
                    # Lobby mutations must not delete/cancel it mid-rebind.
                    _fail(409, "native_private_battle_already_started")
                if path == "/leave":
                    had_ready = self._game["players"][0]["ready"]
                    self._game, self._lab_state = None, None
                    self._loadout_notification = None
                    self._member_notifications.clear()
                    self._cpu_loadout_notifications.clear()
                    self._kick_receipts.clear()
                    self._management_retry = None
                    self._rematch_receipt = None
                    self._battle_instance_id = None
                    self._battle_round = 1
                    self._completed_battle_instance_ids = []
                    self._completed_battle_rounds = []
                    if had_ready or self._ready_notification is not None:
                        self._ready_notification = (request["game_id"], False)
                    self._notify_ready()
                    payload = {"result": "ok"}
                else:
                    changed = self._refresh(profile, native_commander_tier)
                    if path == "/kick_player":
                        receipt_key = (kick.game_id, kick.target_user_id)
                        if receipt_key in self._kick_receipts:
                            self._notify_all()
                            payload = {"result": "ok"}
                        else:
                            # Flush any earlier committed formation before this
                            # independent roster mutation.  If delivery fails,
                            # no CPU has been removed yet.
                            self._notify_all()
                            self._commit_cpu_kick(kick)
                            self._notify_all()
                            payload = {"result": "ok"}
                        return ca_envelope(copy.deepcopy(payload),
                                           time.time_ns() // 1_000_000)
                    if path == "/start_game":
                        # Creation already restricts this value, but repeat the
                        # executable boundary here so a future settings route
                        # or corrupted in-memory room cannot reach on_start.
                        if self._game["settings"].get("map") not in self._maps:
                            _fail(409, "native_private_map_unverified")
                        if changed:
                            self._notify_all()
                            _fail(409, "native_lab_squad_changed_reprepare")
                        self._notify_all()
                        if self._lab_state["battle_started"]:
                            payload = {"result": "ok"}
                        else:
                            if (not self._relay_probe or self._on_start is None
                                    or not self._lab_state["ready"]
                                    or not any(player["is_ai"]
                                               for player in self._game["players"])):
                                _fail(409, "native_private_battle_not_ready")
                            self._in_callback = True
                            try:
                                battle_state = {
                                    **copy.deepcopy(self._lab_state),
                                    "battle_instance_id": self._battle_instance_id,
                                    "battle_round": self._battle_round,
                                    "completed_battle_instance_ids": copy.deepcopy(
                                        self._completed_battle_instance_ids),
                                }
                                recipients = self._on_start(
                                    copy.deepcopy(self._game),
                                    battle_state,
                                )
                            except Exception:
                                _fail(503, "native_private_start_failed")
                            finally:
                                self._in_callback = False
                            if type(recipients) is not int or recipients <= 0:
                                _fail(503, "native_private_start_failed")
                            state = copy.deepcopy(self._lab_state)
                            state["battle_started"] = True
                            self._lab_state = state
                            self._rematch_receipt = None
                            payload = {"result": "ok"}
                        return ca_envelope(copy.deepcopy(payload), time.time_ns() // 1_000_000)
                    if path == "/change_game_settings":
                        settings = self._validated_settings_update(
                            request["settings"],
                            cpu_opponents=self._lab_state["cpu_opponents"])
                        game = copy.deepcopy(self._game)
                        state = copy.deepcopy(self._lab_state)
                        was_ready = game["players"][0]["ready"]
                        game["settings"].update(settings)
                        if was_ready:
                            game["players"][0]["ready"] = False
                            state["ready"] = False
                            self._ready_notification = (game["game_id"], False)
                        self._game, self._lab_state = game, state
                        self._notify_all()
                        payload = {"result": "ok"}
                        return ca_envelope(copy.deepcopy(payload), time.time_ns() // 1_000_000)
                    if path == "/ready" and changed:
                        self._notify_all()
                        _fail(409, "native_lab_squad_changed_reprepare")
                    if path == "/change_squad":
                        self._set_ready(False)
                        # A native change request may precede /profile save.
                        # Reusing an unchanged roster would rebuild the same
                        # native models unnecessarily. _refresh schedules a
                        # validated change; existing failed sends still retry.
                    if path == "/ready":
                        # Deliver a previously changed formation before any
                        # new ready=true notification or diagnostic handshake.
                        self._notify_all()
                    if path in ("/ready", "/unready"):
                        self._set_ready(path == "/ready")
                    if path == "/unready":
                        # An explicit user action may reconfirm false after
                        # native profile/loadout processing left its button
                        # stale. Do not synthesize ready=true or delay work.
                        # This is a retry aid, not a profile-completion barrier.
                        self._ready_notification = (self._game["game_id"], False)
                    self._notify_all()
                    if path in ("/ready", "/unready", "/change_squad"):
                        payload = {"result": "ok"}
                    else:
                        payload = self._game if path == "/battle_check" else {"result": self._game}
            return ca_envelope(copy.deepcopy(payload), time.time_ns() // 1_000_000)

    def _action_fields(self, request: dict, form: bool) -> None:
        allowed = {"game_id", "xmpp_region", "game_group", "profile_timestamp",
                   "user_id", "username", "battle_key", "game_data_hash", "build_id", "game_checksum",
                   "commander_id"}
        if set(request) - allowed:
            _fail(400, "unknown_lobby_action_field")
        self._compatibility_metadata(request)
        for key in ("xmpp_region", "game_group"):
            if key in request:
                value = request[key]
                if not isinstance(value, str) or len(value) > 128 \
                        or any(ord(char) < 32 or ord(char) == 127 for char in value):
                    _fail(400, "invalid_native_metadata")
        if "profile_timestamp" in request:
            value = request["profile_timestamp"]
            if form and isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", value):
                value = int(value)
            if type(value) is not int or not 0 <= value <= UINT64_MASK:
                _fail(400, "invalid_profile_timestamp")

    def _change_settings_fields(self, request: dict, form: bool) -> None:
        allowed = {"game_id", "settings", "xmpp_region", "game_group",
                   "user_id", "build_id", "commander_id", "game_checksum",
                   "game_data_hash"}
        if set(request) - allowed or "settings" not in request:
            _fail(400, "unknown_lobby_settings_field")
        self._compatibility_metadata(request)
        for key in ("xmpp_region", "game_group"):
            if key in request:
                value = request[key]
                if not isinstance(value, str) or len(value) > 128 \
                        or any(ord(char) < 32 or ord(char) == 127 for char in value):
                    _fail(400, "invalid_native_metadata")
        if form:
            _fail(400, "invalid_lobby_settings")
        self._validated_settings_update(request["settings"])

    def _validated_settings_update(self, value: object, *,
                                   cpu_opponents: int | None = None) -> dict:
        if not isinstance(value, dict) or not value:
            _fail(400, "invalid_lobby_settings")
        if set(value) - {"map", "length", "max_players", "privacy"}:
            _fail(400, "unknown_lobby_settings_field")
        result = copy.deepcopy(value)
        if "map" in result and (
                not isinstance(result["map"], str) or result["map"] not in self._maps):
            _fail(400, "native_private_map_unverified")
        if "length" in result and (
                type(result["length"]) is not int or not 1 <= result["length"] <= 7200):
            _fail(400, "invalid_lobby_length")
        if "max_players" in result and (
                type(result["max_players"]) is not int
                or not 2 <= result["max_players"] <= 20
                or (cpu_opponents is not None
                    and result["max_players"] < 1 + cpu_opponents)):
            _fail(400, "invalid_lobby_capacity")
        if "privacy" in result and type(result["privacy"]) is not bool:
            _fail(400, "invalid_lobby_privacy")
        return result

    @staticmethod
    def _compatibility_metadata(request: dict) -> None:
        for key in ("build_id", "commander_id", "game_checksum", "game_data_hash"):
            if key not in request:
                continue
            value = request[key]
            if not ((isinstance(value, str) and len(value) <= 512)
                    or (type(value) is int and 0 <= value <= UINT64_MASK)):
                _fail(400, "invalid_native_metadata")

    def _settings(self, request: dict, form: bool) -> dict:
        allowed = {"username", "private", "sessionguid", "profile_timestamp", "region",
                   "xmpp_region", "game_group", "title", "max_players", "length", "map", "user_id",
                   "build_id", "commander_id", "game_checksum", "game_data_hash"}
        if set(request) - allowed:
            _fail(400, "unknown_create_field")
        # The real client sends these compatibility fields in /create. They do
        # not establish ownership or select a formation: _owner() always reads
        # the trusted profile snapshot. Keep their input bounded and discard it.
        self._compatibility_metadata(request)
        title, map_id = request.get("title"), request.get("map")
        if not isinstance(title, str) or not title.strip() or len(title) > 80 \
                or any(ord(char) < 32 or ord(char) == 127 for char in title):
            _fail(400, "invalid_lobby_title")
        if not isinstance(map_id, str) or map_id not in self._maps:
            _fail(400, "native_private_map_unverified")
        length, maximum, private = request.get("length"), request.get("max_players"), request.get("private")
        if form:
            for value in (length, maximum):
                if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]{0,4}", value):
                    _fail(400, "invalid_lobby_integer")
            length, maximum = int(length), int(maximum)
            if private not in ("true", "false"):
                _fail(400, "invalid_lobby_privacy")
            private = private == "true"
        # Conservative lab limits, not a claim about the original service API.
        if type(length) is not int or not 1 <= length <= 7200:
            _fail(400, "invalid_lobby_length")
        if type(maximum) is not int or not 2 <= maximum <= 20:
            _fail(400, "invalid_lobby_capacity")
        if type(private) is not bool:
            _fail(400, "invalid_lobby_privacy")
        return {"title": title, "map": map_id, "length": length,
                "max_players": maximum, "privacy": private}
