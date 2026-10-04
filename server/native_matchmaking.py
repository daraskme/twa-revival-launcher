"""Native ordinary matchmaking request decoding for the loopback lab.

The shipped client serializes request.version twice, as equal JSON integers.
Only that observed duplicate is accepted here. Other endpoints retain their
strict decoder; header duplicates, differing values and third copies fail.
"""
from __future__ import annotations

import json
import copy
import hashlib
import secrets
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from urllib.parse import parse_qsl

if __package__:
    from .native_battle_roster import (BattleRosterError, CpuCommander, CpuUnit,
                                       build_battle_roster, select_cpu_asset_palette_v3,
                                       select_cpu_asset_palette_v4)
    from .native_custom_lobby import NativeLobbyError, decode_native_request
    from .native_battle_maps import (
        NATIVE_BATTLE_RULESET_MAPS,
        choose_native_battle_map,
        is_native_battle_map,
        native_battle_map_key,
    )
    from .native_consumables import (load_native_battle_consumables,
                                     tier_equivalent_consumables_by_unit,
                                     validate_native_battle_consumables)
    from .native_equipment import (load_native_unit_equipment,
                                   validate_native_unit_equipment)
    from .native_unit_abilities import (load_native_unit_abilities,
                                        validate_native_unit_abilities)
else:
    from native_battle_roster import (BattleRosterError, CpuCommander, CpuUnit,
                                      build_battle_roster, select_cpu_asset_palette_v3,
                                      select_cpu_asset_palette_v4)
    from native_custom_lobby import NativeLobbyError, decode_native_request, analyze_active_squad
    from native_battle_maps import (
        NATIVE_BATTLE_RULESET_MAPS,
        choose_native_battle_map,
        is_native_battle_map,
        native_battle_map_key,
    )
    from native_consumables import (load_native_battle_consumables,
                                    tier_equivalent_consumables_by_unit,
                                    validate_native_battle_consumables)
    from native_equipment import (load_native_unit_equipment,
                                  validate_native_unit_equipment)
    from native_unit_abilities import (load_native_unit_abilities,
                                       validate_native_unit_abilities)

if __package__:
    from .native_custom_lobby import analyze_active_squad
    from .f2p_fake import (OFFLINE_PROGRESSION_SCHEMA_VERSION, PLAYER,
                           active_native_user_id, build_profile, ca_envelope)
else:
    from f2p_fake import (OFFLINE_PROGRESSION_SCHEMA_VERSION, PLAYER,
                          active_native_user_id, build_profile, ca_envelope)


MATCHMAKE_PATH = '/v8/matchmake'
CHECK_PATH = '/check'
CANCEL_PATH = '/cancel'
ENROLL_PATH = '/enroll'
PATHS = frozenset((MATCHMAKE_PATH, CHECK_PATH, CANCEL_PATH, ENROLL_PATH))
ARBITRATION_FIELDS = frozenset(('battle_id', 'battle_key', 'user_id'))
LAB_BATTLE_ID = '00000000-0000-4000-8000-000000000001'
LAB_BATTLE_KEY = '1'
LAB_RELAY_SERVER = '127.0.0.1:19000'
LAB_CPU_USER_ID = 'cpu-local-1'
PVE_ARCHER_COMMANDER_KEY = 'gre_cynane'
PVE_ARCHER_ROLE = 'archer'
QUEUE_SECONDS = 420  # 300s collection + bounded roster/admission grace
RECHECK_VALUE = 1  # Native parser requires an integer; its unit is not established.
UINT64_MAX = (1 << 64) - 1
EFFECTIVE_UNIT_TIER = 10
EFFECTIVE_CONSUMABLE_SLOTS = 2
GAME_CONFIG_FILENAME = 'game_config.json'
TERRITORY_DISPLAY_POINT_GOAL = 2500
# Native HUD E39431 -> AB0B50 divides the configured ticket goal by 100.
# Sending 2500 directly therefore ends the match at just 25 displayed points.
NATIVE_TICKET_UNITS_PER_POINT = 100
TERRITORY_TICKET_GOAL = TERRITORY_DISPLAY_POINT_GOAL * NATIVE_TICKET_UNITS_PER_POINT
BATTLE_RULESET_MAPS = dict(NATIVE_BATTLE_RULESET_MAPS)
BATTLE_MODE_PRESETS = {
    f'{ruleset}-{mode}': (mode, ruleset)
    for ruleset in BATTLE_RULESET_MAPS
    for mode in ('pve', 'pvp')
}
# The native five-row candidate needs one unambiguous wire value for each
# ordinary row.  Static analysis proves that the game-config parser stores
# ``matchmaking_game_mode`` separately from the stock four-value
# ``client_display_type`` enum.  The static request chain C4E070 -> C53CF0 ->
# BD5770 -> BFEC00 -> B99ED0 -> BA5940 -> BCF070 preserves the selected row's
# wire string as JSON ``game_mode``.  The feature remains disabled by default
# until the paired DLL/UIC candidates pass independent review and runtime use.
NATIVE_SELECTOR_GAME_MODES = {
    'territory_pve': ('pve', 'territory', 'pve'),
    'annihilation_pve': ('pve', 'annihilation', 'pvp'),
    'territory_pvp': ('pvp', 'territory', 'ranked'),
    'annihilation_pvp': ('pvp', 'annihilation', 'custom'),
}


def build_matchmaking_game_config(*, native_five_mode_selector: bool = False,
                                  public_pvp_only: bool = False) -> dict:
    """Raw, local-only display configuration, not recovered official settings.

    C4D470 reads these definitions before C47B20 assigns server-list display
    enums. Keep the losing-streak enum unset: a nonzero enum reaches BFB20F's
    profile-collection read before that collection necessarily exists. Both
    Tier fields must be explicit; their omission reads uninitialized locals.

    Empty battle points create an initialized object for UI paths that do not
    check its pointer. AFK 300 seconds is a local test policy, stored as a DWORD;
    it avoids the native omission fallback of 1. This does not enable rewards.
    Battle setup is separate from reward/decoration points. The native
    C4E023 -> 462610 parser initializes the ordinary defaults, then stores
    integer territory_ticket_goal at +0x30. Use native hundredth-point units
    (250000 tickets = 2500 displayed points). This is a first-to-points goal,
    without introducing a battle duration or a timeout winner.
    Return fresh containers so a caller cannot change subsequent responses.
    """
    return {'game_client_config': {
        'battle_points_config': {},
        'battle_setup_config': {'territory_ticket_goal': TERRITORY_TICKET_GOAL},
        'afk_time_s': 300,
        'game_modes_display_config': [
            {'matchmaking_game_mode': wire_mode,
             'client_display_type': display_type,
             'losing_streak_mode': '', 'losing_streak_min_tier': 1,
             'losing_streak_max_tier': 10, 'matchmaking_time_estimation_s': 0,
             'matchmaking_time_variance_s': 0}
            for wire_mode, display_type in (
                ((wire_mode, values[2])
                 for wire_mode, values in NATIVE_SELECTOR_GAME_MODES.items()
                 if not public_pvp_only or values[0] == 'pvp')
                if native_five_mode_selector else
                ((('pvp', 'pvp'),) if public_pvp_only else (('pve', 'pve'), ('pvp', 'pvp')))
            )],
    }}


def _fail(status: int, code: str):
    raise NativeLobbyError(status, code)


def _integer(value: object, code: str, maximum: int = UINT64_MAX) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        _fail(400, code)
    return value


def _text(value: object, code: str, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum \
            or any(ord(char) < 32 or ord(char) > 126 for char in value):
        _fail(400, code)
    return value


@dataclass(frozen=True)
class _PvpSeat:
    """One frozen seat of a Worker-assigned PvP battle (seat order == team)."""

    user_id: str
    seat: int
    team: int
    player_id: int
    # The native ``profile_matchmaking_details`` row this seat presents in
    # ``/check``: the local player's trusted squad, or the opponent's rows
    # exactly as the Worker roster returned them.
    details: dict
    is_ai: bool = False


@dataclass(frozen=True)
class _PvpBinding:
    assignment_id: str
    seats: tuple[_PvpSeat, ...]
    reward_policy: dict
    local_seat: int
    roster_policy: dict | None = None
    roster_digest: str | None = None
    party_groups: tuple[tuple[str, ...], ...] = ()


@dataclass(frozen=True)
class _PveSeat:
    """One frozen rendered PvE seat; only the local human authenticates."""

    user_id: str
    team: int
    is_ai: bool
    commander_key: str
    details: dict


@dataclass(frozen=True)
class _PveBinding:
    seats: tuple[_PveSeat, ...]
    roster_digest: str


@dataclass(frozen=True)
class _Queue:
    mode: str
    ruleset: str
    map_key: str
    started: float
    expires: float
    profile_saved: int
    commander_instance_id: int
    records: tuple[tuple[int, int, int, int], ...]
    commander_tier: int
    commander_key: str
    unit_tiers: tuple[int, int, int]
    cpu_records: tuple[tuple[int, int, int, int], ...]
    cpu_commander_tier: int
    cpu_commander_key: str
    cpu_unit_tiers: tuple[int, int, int]
    battle_id: str
    battle_key: str
    party_id: str
    # Standard PvP only: ``None`` while the Worker has not yet fixed the
    # battle (queue state ``matching``); the frozen two-seat roster afterwards.
    pvp: _PvpBinding | None = None
    # Local PvE only: one human plus nineteen rendered CPU seats.  CPU rows are
    # battle presentation data, never HTTP/relay authentication principals.
    pve: _PveBinding | None = None
    # bind_pvp_battle replaces this frozen record. Keep one private identity
    # for completion only; cancellation still uses the exact queue object.
    completion_generation: object = field(default_factory=object, compare=False, repr=False)


# Standard PvP seat rows come back from the Worker roster as opaque native
# ``full_squad_setup`` records; bound their count like the adapter contract.
_MAX_PVP_SQUAD_ROWS = 1000


class NativeMatchmaking:
    """Native ordinary-matchmaking adapter with explicit runtime gates.

    PvE uses the local CPU relay. PvP remains disabled unless the Companion
    injects its Worker coordinator and Durable Object relay path.
    """

    def __init__(self, native_hangar: dict, *, pve_battle_probe: bool = False,
                 notify: Callable[[str], int] | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 credential_factory: Callable[[], tuple[str, str]] | None = None,
                 legacy_battle_fixture: bool = False,
                 pve_enemy_tier: int | None = None,
                 selected_mode: str | None = None,
                 battle_ruleset: str = 'annihilation',
                 native_user_id: str | None = None,
                 pvp_enabled: bool = False,
                 pve_enabled: bool = True,
                 cloud_coop_pve: bool = False,
                 native_five_mode_selector: bool = False,
                 disabled_rulesets: frozenset[str] = frozenset(),
                 public_pvp_only: bool = False,
                 map_choice: Callable[[tuple[dict[str, str], ...]], object] | None = None):
        if native_user_id is not None and (not isinstance(native_user_id, str)
                                           or not 1 <= len(native_user_id) <= 36):
            raise ValueError('invalid matchmaking probe configuration')
        # ``None`` follows the identity bound into ``f2p_fake``, which is the
        # same source ``build_profile`` uses, so the queue can never disagree
        # with the profile it validated against.
        self._native_user_id = native_user_id
        if (type(pve_battle_probe) is not bool or notify is not None and not callable(notify)
                or not callable(clock) or type(legacy_battle_fixture) is not bool
                or credential_factory is not None and not callable(credential_factory)
                or legacy_battle_fixture and credential_factory is not None
                or selected_mode not in (None, 'pve', 'pvp')
                or not isinstance(battle_ruleset, str)
                or battle_ruleset not in BATTLE_RULESET_MAPS
                or type(pvp_enabled) is not bool
                or type(pve_enabled) is not bool
                or type(cloud_coop_pve) is not bool
                or type(native_five_mode_selector) is not bool
                or type(public_pvp_only) is not bool
                or not isinstance(disabled_rulesets, frozenset)
                or not disabled_rulesets <= BATTLE_RULESET_MAPS.keys()
                or map_choice is not None and not callable(map_choice)
                # Standard PvP credentials always come from the Worker; the
                # fixed lab tuple and a local factory cannot describe them.
                or pvp_enabled and (legacy_battle_fixture
                                    or credential_factory is not None)
                or (pve_enemy_tier is not None
                    and (not pve_battle_probe or type(pve_enemy_tier) is not int
                         or not 1 <= pve_enemy_tier <= 10))):
            raise ValueError('invalid matchmaking probe configuration')
        # Standard PvP is only playable through the companion's Worker
        # coordinator (native_pvp_coordinator).  Without it a native ``pvp``
        # entry keeps failing closed with ``pvp_players_unavailable``.
        self._pvp_enabled = pvp_enabled
        # The Companion starts a different relay implementation for each
        # mode.  In a PvP process there is no local CPU relay behind port
        # 19000, so a runtime mode switch to PvE must not be advertised as
        # playable.  Standalone/local probe users retain the historical PvE
        # default; companion_bridge passes False for its PvP-only process.
        self._pve_enabled = pve_enabled
        self._cloud_coop_pve = cloud_coop_pve
        # Capability-bound to a separately reviewed game.dll/UI candidate.
        # Default clients retain the two historical config rows and reject the
        # new wire tokens.  When enabled, a direct row token is authoritative
        # over the legacy control-endpoint pin, but availability gates below
        # still fail closed for a relay this process does not provide.
        self._native_five_mode_selector = native_five_mode_selector
        self._disabled_rulesets = disabled_rulesets
        self.public_pvp_only = public_pvp_only
        self._native = copy.deepcopy(native_hangar)
        equipment = validate_native_unit_equipment(
            load_native_unit_equipment(), self._native,
        )
        unit_items_by_key = {
            row.get('key'): row.get('item_id')
            for row in self._native.get('units', [])
            if isinstance(row, dict) and row.get('build_state', 'live') == 'live'
        }
        initial_equipment = equipment['all_live_nonpremium']
        self._equipment_tree_items = {
            row['item_id'] for row in initial_equipment
        }
        self._equipment_definition_items = {
            row['equipment_item_id'] for row in initial_equipment
        }
        self._equipment_rows_by_unit_item: dict[int, list[dict]] = {}
        for row in initial_equipment:
            unit_item = unit_items_by_key.get(row['source_unit'])
            if type(unit_item) is int:
                self._equipment_rows_by_unit_item.setdefault(unit_item, []).append(row)
        consumables = validate_native_battle_consumables(
            load_native_battle_consumables(), self._native,
        )
        self._consumables_by_item = {
            row['item_id']: row for row in consumables['definitions']
        }
        self._effective_consumable_items_by_unit = {
            unit_key: {candidate['item_id'] for candidate in candidates}
            for unit_key, candidates in tier_equivalent_consumables_by_unit(
                self._native, EFFECTIVE_UNIT_TIER, consumables,
            ).items()
        }
        unit_abilities = validate_native_unit_abilities(
            load_native_unit_abilities(), self._native,
        )
        self._unit_abilities_by_item = {
            row['item_id']: row for row in unit_abilities['items']
        }
        self._unit_ability_items = set(self._unit_abilities_by_item)
        self._units_by_item = {
            row['item_id']: row for row in self._native.get('units', [])
            if isinstance(row, dict) and row.get('build_state', 'live') == 'live'
        }
        self._enabled = pve_battle_probe
        self._notify = notify
        self._clock = clock
        self._credential_factory = credential_factory
        self._legacy_battle_fixture = legacy_battle_fixture
        # Opt-in live-test override only. Ordinary PvE continues to mirror the
        # highest deployed player Tier, preserving the public queue contract.
        self._pve_enemy_tier = pve_enemy_tier
        self._map_choice = map_choice
        # The native popup has fixed PvE/PvP/Ranked/Private slots, so there is
        # no safe data-only way to add two more labelled buttons while keeping
        # Private Lobby.  A loopback control endpoint selects the battle rules;
        # the existing native PvE/PvP button supplies the other axis.  Pinning
        # the optional mode catches a wrong native button before allocation.
        self._selected_mode = selected_mode
        self._battle_ruleset = battle_ruleset
        self._last_credentials: tuple[str, str] | None = None
        self._lock = threading.RLock()
        self._queue: _Queue | None = None
        self._last_cleared_queue: _Queue | None = None
        self._last_completed_cloud_queue: _Queue | None = None
        self._cancel_notified_queue: _Queue | None = None
        self._announced = False
        self._notification_uncertain = False
        self._enrolled_users: set[str] = set()
        self._in_callback = False
        self._last_clock = float('-inf')

    @staticmethod
    def _validated_credentials(battle_id: object, battle_key: object) -> tuple[str, str]:
        if type(battle_id) is not str or type(battle_key) is not str:
            _fail(503, 'invalid_matchmaking_credentials')
        try:
            parsed = uuid.UUID(battle_id)
        except (ValueError, AttributeError):
            _fail(503, 'invalid_matchmaking_credentials')
        # The ordinary native matchmaking path parses this HTTP string with
        # radix 16 before writing the uint64 GAME_JOIN field.  Preserve one
        # canonical wire spelling so arbitration compares the exact string and
        # persistence can recover the same integer without guessing a radix.
        if (str(parsed) != battle_id or not 1 <= len(battle_key) <= 16
                or any(char not in '0123456789abcdef' for char in battle_key)):
            _fail(503, 'invalid_matchmaking_credentials')
        key = int(battle_key, 16)
        if battle_key != format(key, 'x') or not 1 <= key <= UINT64_MAX:
            _fail(503, 'invalid_matchmaking_credentials')
        return battle_id, battle_key

    def _new_credentials(self) -> tuple[str, str]:
        if self._legacy_battle_fixture:
            return LAB_BATTLE_ID, LAB_BATTLE_KEY
        if self._credential_factory is None:
            # A collision is extraordinarily unlikely, but the queue contract
            # still guarantees rotation rather than relying on probability.
            for _attempt in range(2):
                credentials = (str(uuid.uuid4()),
                               format(secrets.randbelow(UINT64_MAX) + 1, 'x'))
                if (self._last_credentials is None
                        or (credentials[0] != self._last_credentials[0]
                            and credentials[1] != self._last_credentials[1])):
                    return credentials
            _fail(503, 'matchmaking_credential_generation_failed')
        try:
            credentials = self._credential_factory()
        except Exception:
            _fail(503, 'matchmaking_credential_generation_failed')
        if (not isinstance(credentials, tuple) or len(credentials) != 2):
            _fail(503, 'invalid_matchmaking_credentials')
        credentials = self._validated_credentials(*credentials)
        if (self._last_credentials is not None
                and (credentials[0] == self._last_credentials[0]
                     or credentials[1] == self._last_credentials[1])):
            _fail(503, 'matchmaking_credentials_reused')
        return credentials

    def relay_battle_key_uint64(self, battle_id: object, battle_key: object) -> int:
        """Convert this queue's HTTP credential to the native GAME_JOIN value.

        Ordinary matchmaking uses the client's proven radix-16 conversion.
        The historical fixed lab tuple remains an explicit decimal diagnostic;
        it is intentionally not allowed to redefine the normal wire contract.
        """
        with self._lock:
            queue = self._queue
            if (queue is None or battle_id != queue.battle_id
                    or battle_key != queue.battle_key):
                _fail(503, 'invalid_matchmaking_credentials')
            if self._legacy_battle_fixture:
                if (battle_id, battle_key) != (LAB_BATTLE_ID, LAB_BATTLE_KEY):
                    _fail(503, 'invalid_matchmaking_credentials')
                return int(LAB_BATTLE_KEY, 10)
            self._validated_credentials(battle_id, battle_key)
            return int(battle_key, 16)

    def _now(self) -> float:
        self._last_clock = max(self._last_clock, self._clock())
        return self._last_clock

    def _mutation(self) -> None:
        if self._in_callback:
            _fail(409, 'matchmaking_callback_reentry')

    @property
    def lab_state(self) -> dict:
        with self._lock:
            # A notifier may inspect metadata, but must not expire/mutate its
            # own in-flight operation by reentering this getter.
            if not self._in_callback:
                self._expire()
            queue = self._queue
            pve = queue is not None and queue.mode == 'pve'
            pve_binding = queue.pve if pve else None
            return {'queue_state': ('idle' if queue is None else
                                    'notification_uncertain' if self._notification_uncertain else
                                    'battle_ready' if self._announced else
                                    # A PvP entry the Worker has not yet
                                    # matched: nothing to announce or check.
                                    'matching' if self._is_cloud_queue(queue) and queue.pvp is None
                                    else 'queued'),
                    'game_mode': queue.mode if queue else None,
                    **({'cloud_matchmaking': self._is_cloud_queue(queue)} if self._cloud_coop_pve else {}),
                    'selected_game_mode': (queue.mode if queue else self._selected_mode),
                    'battle_ruleset': (queue.ruleset if queue else self._battle_ruleset),
                    'battle_map': (queue.map_key if queue else
                                   BATTLE_RULESET_MAPS[self._battle_ruleset]),
                    'profile_saved': queue.profile_saved if queue else None,
                    'commander_key': queue.commander_key if queue else None,
                    'unit_tiers': list(queue.unit_tiers) if queue else [],
                    'battle_tier': max(queue.unit_tiers) if queue else None,
                    'pve_enemy_tier': max(queue.cpu_unit_tiers, default=EFFECTIVE_UNIT_TIER) if pve else None,
                    'pve_enemy_commander_key': queue.cpu_commander_key if pve else None,
                    'pve_enemy_unit_tiers': list(queue.cpu_unit_tiers) if pve else [],
                    'pve_seats_per_team': ([sum(seat.team == team
                                                for seat in pve_binding.seats)
                                            for team in (0, 1)]
                                           if pve_binding is not None else []),
                    'pve_cpu_seats': (sum(seat.is_ai for seat in pve_binding.seats)
                                      if pve_binding is not None else 0),
                    'pve_total_units': (3 * len(pve_binding.seats)
                                        if pve_binding is not None else 0),
                    'pve_roster_digest': (pve_binding.roster_digest
                                          if pve_binding is not None else None),
                    'party_id': queue.party_id if queue and queue.party_id else None,
                    'enrolled_humans': len(self._enrolled_users),
                    'native_battles': False}

    def _is_cloud_queue(self, queue) -> bool:
        return queue is not None and (queue.mode == 'pvp' or self._cloud_coop_pve and queue.mode == 'pve')

    @property
    def pvp_binding(self) -> dict | None:
        """The frozen Worker roster of the current PvP queue, without the key."""
        with self._lock:
            queue = self._queue
            if queue is None or not self._is_cloud_queue(queue) or queue.pvp is None:
                return None
            binding = queue.pvp
            local = binding.seats[binding.local_seat]
            # build_battle_roster groups rendered rows by team.  Worker human
            # seat ordinals remain the canonical auth/reward order.
            humans = sorted(
                (seat for seat in binding.seats if not seat.is_ai),
                key=lambda seat: seat.seat,
            )
            return {
                'assignment_id': binding.assignment_id,
                'battle_id': queue.battle_id,
                'seat': local.seat,
                'team': local.team,
                'player_id': local.player_id,
                'user_ids': [seat.user_id for seat in humans],
                'teams': [seat.team for seat in humans],
                # Compatibility scalar for older two-player consumers.  In a
                # larger roster choose the first canonical opposite-team human.
                'opponent_user_id': next((seat.user_id for seat in humans
                                         if seat.team != local.team), ''),
                'reward_policy': copy.deepcopy(binding.reward_policy),
                'roster_policy': copy.deepcopy(binding.roster_policy),
                'roster_digest': binding.roster_digest,
            }

    @property
    def advertised_game_modes(self) -> tuple[str, ...]:
        """Keep locked rows in game config, but omit their availability advertisement."""
        if self._native_five_mode_selector:
            return tuple(wire for wire, (mode, ruleset, _) in NATIVE_SELECTOR_GAME_MODES.items()
                         if ruleset not in self._disabled_rulesets
                         and (not self.public_pvp_only or mode == 'pvp'))
        return (() if self._battle_ruleset in self._disabled_rulesets else
                ('pvp',) if self.public_pvp_only else ('pve', 'pvp'))

    @property
    def battle_mode_selection(self) -> dict:
        """Return the selected native-button/ruleset pair without secrets."""
        with self._lock:
            self._expire()
            queue = self._queue
            mode = queue.mode if queue else self._selected_mode
            ruleset = queue.ruleset if queue else self._battle_ruleset
            playable = bool(
                self._enabled
                and mode in ('pve', 'pvp')
                and ruleset not in self._disabled_rulesets
                and (mode != 'pve' or self._pve_enabled)
                and (mode != 'pvp' or self._pvp_enabled)
            )
            unavailable_reason = None
            if mode is not None and not self._enabled:
                unavailable_reason = 'pve_battle_probe_disabled'
            elif mode == 'pve' and not self._pve_enabled:
                unavailable_reason = 'pve_relay_unavailable'
            elif mode == 'pvp' and not self._pvp_enabled:
                unavailable_reason = 'pvp_players_unavailable'
            if ruleset in self._disabled_rulesets:
                unavailable_reason = 'battle_ruleset_locked'
            return {
                'mode': mode,
                'ruleset': ruleset,
                'map': queue.map_key if queue else BATTLE_RULESET_MAPS[ruleset],
                'locked': queue is not None or ruleset in self._disabled_rulesets,
                'playable': playable,
                'unavailable_reason': unavailable_reason,
            }

    @property
    def battle_mode_options(self) -> list[dict]:
        """Describe all four presets without changing the current selection.

        ``playable`` means this process is configured to admit the native
        button; it is not a relay-health or two-client E2E result.
        ``selectable`` additionally accounts for an already frozen queue.
        Keeping those concepts separate makes the loopback status useful
        without pretending that four new native menu rows exist.
        """
        with self._lock:
            self._expire()
            queue = self._queue
            selected = ((queue.mode, queue.ruleset) if queue is not None else
                        (self._selected_mode, self._battle_ruleset))
            options = []
            for preset, (mode, ruleset) in BATTLE_MODE_PRESETS.items():
                if self.public_pvp_only and mode != 'pvp':
                    continue
                enabled = bool(
                    self._enabled
                    and ruleset not in self._disabled_rulesets
                    and (mode != 'pve' or self._pve_enabled)
                    and (mode != 'pvp' or self._pvp_enabled)
                )
                reason = None
                if not self._enabled:
                    reason = 'pve_battle_probe_disabled'
                elif mode == 'pve' and not self._pve_enabled:
                    reason = 'pve_relay_unavailable'
                elif mode == 'pvp' and not self._pvp_enabled:
                    reason = 'pvp_players_unavailable'
                policy_locked = ruleset in self._disabled_rulesets
                if policy_locked:
                    reason = 'battle_ruleset_locked'
                same_selection = (mode, ruleset) == selected
                options.append({
                    'preset': preset,
                    'mode': mode,
                    'ruleset': ruleset,
                    'map': BATTLE_RULESET_MAPS[ruleset],
                    'native_button': mode,
                    'selected': same_selection,
                    'locked': queue is not None or policy_locked,
                    'selectable': not policy_locked and (queue is None or same_selection),
                    'playable': enabled,
                    'unavailable_reason': reason,
                    'selection_blocked_reason': (
                        'battle_ruleset_locked' if policy_locked else
                        None if queue is None or same_selection
                        else 'matchmaking_already_queued'
                    ),
                })
            return options

    @property
    def battle_mode_status(self) -> dict:
        """Return one coherent selection/options snapshot."""
        with self._lock:
            return {
                'selection': self.battle_mode_selection,
                'options': self.battle_mode_options,
            }

    def select_battle_mode(self, mode: object, ruleset: object) -> dict:
        """Select one of four ordinary modes while no other queue is active.

        An exact retry during an active queue is harmless.  A different
        selection cannot rewrite the map/rules of an allocated battle.
        """
        if (mode not in ('pve', 'pvp') or not isinstance(ruleset, str)
                or ruleset not in BATTLE_RULESET_MAPS):
            _fail(400, 'invalid_battle_mode_selection')
        if ruleset in self._disabled_rulesets:
            _fail(409, 'battle_ruleset_locked')
        if self.public_pvp_only and mode != 'pvp':
            _fail(409, 'battle_mode_removed')
        with self._lock:
            self._mutation()
            self._expire()
            queue = self._queue
            if queue is not None:
                if (mode, ruleset) != (queue.mode, queue.ruleset):
                    _fail(409, 'matchmaking_already_queued')
            else:
                self._selected_mode = mode
                self._battle_ruleset = ruleset
            return copy.deepcopy(self.battle_mode_selection)

    def _clear_queue(self) -> None:
        self._last_cleared_queue = self._queue
        self._queue = None
        self._announced = False
        self._notification_uncertain = False
        self._enrolled_users.clear()

    def _expire(self) -> None:
        # The 180-second deadline bounds queue formation, not a Worker battle
        # which has already been immutably bound and may run much longer.
        # Completion/expiry of that battle is driven by the coordinator and
        # LocalBattleState, then released through complete_battle/abort_pvp.
        if self._queue is not None and self._now() >= self._queue.expires:
            self._clear_queue()

    def _trusted_squad(self, profile: dict):
        squad = analyze_active_squad(profile, self._native)
        squad = replace(squad, unit_tiers=(
            EFFECTIVE_UNIT_TIER, EFFECTIVE_UNIT_TIER, EFFECTIVE_UNIT_TIER,
        ))
        saved = profile.get('saved')
        if type(saved) is not int or not 0 <= saved <= UINT64_MAX:
            _fail(503, 'invalid_owned_profile')
        return squad, saved

    def _validate_deployed_consumables(self, squad) -> None:
        """Accept only exact unit-linked type-11 rows under deployed roots."""
        deployed = {
            row[2]: self._units_by_item[row[1]]
            for row in squad.records
            if (row[0] == squad.commander_instance_id
                and row[1] in self._units_by_item)
        }
        selected_counts = {instance: 0 for instance in deployed}
        selected_items: dict[int, set[int]] = {
            instance: set() for instance in deployed
        }
        for parent, item, _instance, quantity in squad.records:
            definition = self._consumables_by_item.get(item)
            if definition is None:
                continue
            unit = deployed.get(parent)
            if unit is None:
                _fail(503, 'invalid_consumable_parent')
            if quantity != 1:
                _fail(503, 'invalid_consumable_quantity')
            if definition['tier'] != EFFECTIVE_UNIT_TIER:
                _fail(503, 'invalid_consumable_tier')
            if item not in self._effective_consumable_items_by_unit.get(
                    unit.get('key'), set()):
                _fail(503, 'invalid_consumable_unit')
            if item in selected_items[parent]:
                _fail(503, 'duplicate_consumable_selection')
            selected_items[parent].add(item)
            selected_counts[parent] += 1

        for instance, unit in deployed.items():
            capacity = EFFECTIVE_CONSUMABLE_SLOTS
            if type(capacity) is not int or capacity < 0:
                _fail(503, 'invalid_consumable_capacity')
            if selected_counts[instance] > capacity:
                _fail(503, 'consumable_slot_capacity_exceeded')

    def _validate_deployed_unit_abilities(self, squad) -> None:
        """Accept type-19 selections only below their exact deployed unit."""
        deployed = {
            row[2]: self._units_by_item[row[1]]
            for row in squad.records
            if (row[0] == squad.commander_instance_id
                and row[1] in self._units_by_item)
        }
        selected: dict[int, set[int]] = {
            instance: set() for instance in deployed
        }
        for parent, item, _instance, quantity in squad.records:
            ability = self._unit_abilities_by_item.get(item)
            if ability is None:
                continue
            unit = deployed.get(parent)
            if unit is None:
                _fail(503, 'invalid_deployed_unit_ability_parent')
            if (ability['mode'] not in {'additional', 'default'}
                    or ability['unit'] != unit['key']):
                _fail(503, 'invalid_deployed_unit_ability')
            if quantity != 1:
                _fail(503, 'invalid_deployed_unit_ability_quantity')
            if item in selected[parent]:
                _fail(503, 'duplicate_deployed_unit_ability')
            selected[parent].add(item)

    def _trusted_battle_squad(self, profile: dict):
        """Include the owned unit and commander-progress roots battle needs.

        BEB880 resolves equipped unit+68 from a parentless record with the
        same unit item ID (BEC070..BEC0D9). B33D49 later dereferences that
        pointer during army construction. Type-12 commander Tier rows are
        parentless too, and BEBA34 applies them to the reconstructed commander.
        The subtree alone omits both kinds. Never fabricate ownership or copy
        unrelated root unlocks here.
        """
        squad, saved = self._trusted_squad(profile)
        self._validate_deployed_consumables(squad)
        self._validate_deployed_unit_abilities(squad)
        unit_items = {row['item_id'] for row in self._native['units']
                      if row.get('build_state') == 'live'}
        required_units = {row[1] for row in squad.records
                          if row[0] == squad.commander_instance_id and row[1] in unit_items}
        required_progress = {row['item_id'] for row in self._native.get('commander_tiers', [])
                             if row.get('commander') == squad.commander_key
                             and type(row.get('tier')) is int
                             and 1 <= row['tier'] <= squad.commander_tier}
        if len(required_progress) != squad.commander_tier:
            _fail(503, 'invalid_commander_progress')
        required = required_units | required_progress
        roots = {item: [] for item in required}
        # analyze_active_squad has already validated every record and the
        # global uniqueness of instance IDs. Preserve exact uint64 bits.
        for parent, item, instance, quantity in profile['profile_records']:
            parent, item, instance = (value & UINT64_MAX for value in (parent, item, instance))
            if parent == 0 and item in roots and quantity > 0:
                roots[item].append((parent, item, instance, quantity))
        if any(not roots[item] for item in required_units):
            _fail(503, 'missing_owned_unit_unlock')
        if any(not roots[item] for item in required_progress):
            _fail(503, 'missing_owned_commander_progress')
        if any(len(roots[item]) != 1 for item in required_units):
            _fail(503, 'ambiguous_owned_unit_unlock')
        if any(len(roots[item]) != 1 for item in required_progress):
            _fail(503, 'ambiguous_owned_commander_progress')
        # B33CA0 and C48AB0 consume separate type-5 tree and type-9 definition
        # maps from the parentless unit root.  An explicit non-default choice
        # is represented by one matching type-5/type-9 pair.  After unequip,
        # the authoritative base choice has only its zero-cost type-5 row; it
        # still has to reach full_squad_setup or the battle silently loses the
        # selection which the hangar's silver frame displays.  Leave every
        # other unlocked parentless type-5 alternative and currency child out.
        by_parent: dict[int, list[tuple[int, int, int, int]]] = {}
        for parent, item, instance, quantity in profile['profile_records']:
            normalized = tuple(value & UINT64_MAX for value in (parent, item, instance)) \
                + (quantity,)
            by_parent.setdefault(normalized[0], []).append(normalized)
        root_records: list[tuple[int, int, int, int]] = []
        included_instances = {row[2] for row in squad.records}
        for item in sorted(required):
            root = roots[item][0]
            selected = [root]
            if item in required_units:
                unit = self._units_by_item[item]
                equipment_rows = self._equipment_rows_by_unit_item.get(item, [])
                tree_by_item: dict[int, dict] = {}
                definition_by_item: dict[int, dict] = {}
                for equipment in equipment_rows:
                    tree_by_item[equipment['item_id']] = equipment
                    definition_by_item[equipment['equipment_item_id']] = equipment
                children = by_parent.get(root[2], ())
                tree_children: dict[int, list[tuple[int, int, int, int]]] = {}
                definition_children: dict[int, list[tuple[int, int, int, int]]] = {}
                for child in children:
                    if child[1] in tree_by_item:
                        tree_children.setdefault(child[1], []).append(child)
                    elif child[1] in definition_by_item:
                        definition_children.setdefault(child[1], []).append(child)
                    elif child[1] in self._unit_ability_items:
                        _fail(503, 'invalid_deployed_unit_ability_parent')
                    elif (child[1] in self._equipment_tree_items
                          or child[1] in self._equipment_definition_items):
                        # A selected row belonging only to another unit must
                        # not be mistaken for an unrelated harmless child.
                        _fail(503, 'invalid_owned_unit_equipment')
                if any(len(rows) != 1 for rows in tree_children.values()):
                    _fail(503, 'ambiguous_owned_unit_equipment')
                if any(len(rows) != 1 for rows in definition_children.values()):
                    _fail(503, 'ambiguous_owned_unit_equipment')

                tree_by_group: dict[
                    tuple[str, str], tuple[dict, tuple[int, int, int, int]]
                ] = {}
                for tree_item, trees in tree_children.items():
                    equipment = tree_by_item[tree_item]
                    group = (equipment['scope'], equipment['slot'])
                    if group in tree_by_group:
                        _fail(503, 'ambiguous_owned_unit_equipment')
                    tree_by_group[group] = (equipment, trees[0])

                definition_by_group: dict[
                    tuple[str, str], tuple[dict, tuple[int, int, int, int]]
                ] = {}
                for definition_item, definitions in definition_children.items():
                    equipment = definition_by_item[definition_item]
                    group = (equipment['scope'], equipment['slot'])
                    if group in definition_by_group:
                        _fail(503, 'ambiguous_owned_unit_equipment')
                    definition_by_group[group] = (equipment, definitions[0])

                for group in sorted(set(tree_by_group) | set(definition_by_group)):
                    tree = tree_by_group.get(group)
                    definition = definition_by_group.get(group)
                    if tree is None:
                        _fail(503, 'incomplete_owned_unit_equipment')
                    equipment, tree_record = tree
                    if definition is None:
                        if (equipment['raw_cost_0'] != 0
                                or equipment['raw_cost_1'] != 0):
                            _fail(503, 'incomplete_owned_unit_equipment')
                        selected.append(tree_record)
                    else:
                        definition_equipment, definition_record = definition
                        if definition_equipment['db_key'] != equipment['db_key']:
                            _fail(503, 'incomplete_owned_unit_equipment')
                        selected.append(tree_record)
                        selected.append(definition_record)
                if any(row[3] != 1 for row in selected[1:]):
                    _fail(503, 'invalid_owned_unit_equipment_quantity')
            for row in selected:
                if row[2] in included_instances:
                    _fail(503, 'ambiguous_battle_profile_subtree')
                included_instances.add(row[2])
                root_records.append(row)
        records = squad.records + tuple(root_records)
        return replace(squad, records=records), saved

    def _trusted_pve_enemy_squad(self, battle_tier: int):
        """Build Cynane's same-Tier archer roster from the trusted catalogue.

        The native client reconstructs each AI army from the AI user's own
        ``full_squad_setup``. Reusing the human rows therefore gives the CPU
        the human units. Cynane has a non-premium, live ranged path at every
        Tier I-X in the shipped unit tree; resolve that path rather than
        accepting item IDs from matchmaking input or maintaining a second
        hand-written ID table.
        """
        if type(battle_tier) is not int or not 1 <= battle_tier <= 10:
            _fail(503, 'invalid_pve_enemy_tier')
        commanders = {row.get('key'): row for row in self._native.get('commanders', [])
                      if isinstance(row, dict) and row.get('build_state') == 'live'}
        commander = commanders.get(PVE_ARCHER_COMMANDER_KEY)
        if commander is None:
            _fail(503, 'missing_pve_archer_commander')
        units = {row.get('key'): row for row in self._native.get('units', [])
                 if isinstance(row, dict) and row.get('build_state') == 'live'}
        starts = commander.get('starting_units')
        if (not isinstance(starts, list) or len(starts) != 3
                or any(key not in units for key in starts)):
            _fail(503, 'invalid_pve_archer_roster')

        graph = {key: [] for key in units}
        for link in self._native.get('unit_tree_links', []):
            if not isinstance(link, dict):
                _fail(503, 'invalid_pve_archer_tree')
            parent, child = link.get('key_0'), link.get('key_1')
            if parent in units and child in units:
                if units[parent].get('faction') != units[child].get('faction'):
                    _fail(503, 'invalid_pve_archer_tree')
                graph[parent].append(child)
        reachable = set(starts)
        pending = list(dict.fromkeys(starts))
        while pending:
            parent = pending.pop(0)
            for child in sorted(graph[parent]):
                if child in reachable or units[child].get('is_premium') is True:
                    continue
                reachable.add(child)
                pending.append(child)
        candidates = [key for key in reachable
                      if units[key].get('tier') == battle_tier
                      and units[key].get('is_premium') is False
                      and units[key].get('faction') == commander.get('faction')
                      and units[key].get('metadata', {}).get('squad_role_string')
                      == PVE_ARCHER_ROLE]
        if not candidates:
            _fail(503, 'missing_same_tier_pve_archer')
        unit_key = min(candidates)
        return self._trusted_pve_cpu_squad(
            (unit_key, unit_key, unit_key), battle_tier,
        )

    def _trusted_pve_cpu_squad(
            self, unit_keys: tuple[str, str, str], commander_tier: int,
            commander_key: str = PVE_ARCHER_COMMANDER_KEY):
        """Render one server-authored CPU profile in its own identity space."""
        if (type(commander_tier) is not int or not 1 <= commander_tier <= 10
                or not isinstance(unit_keys, tuple) or len(unit_keys) != 3
                or any(not isinstance(key, str) or not key for key in unit_keys)):
            _fail(503, 'invalid_pve_cpu_roster')
        progression = {
            'schema_version': OFFLINE_PROGRESSION_SCHEMA_VERSION,
            'commanders': {commander_key: {
                'tier': commander_tier,
                'abilities': {},
                'equipped_units': list(unit_keys),
                'unlocked_units': [],
            }},
        }
        try:
            profile = build_profile({}, native=self._native,
                                    active_key=commander_key,
                                    progression=progression)['profile']
            squad, _saved = self._trusted_battle_squad(profile)
        except (KeyError, TypeError, ValueError, NativeLobbyError):
            _fail(503, 'invalid_pve_archer_roster')
        if (squad.commander_key != commander_key
                or squad.commander_tier != commander_tier
                or squad.unit_tiers != (
                    EFFECTIVE_UNIT_TIER,
                    EFFECTIVE_UNIT_TIER,
                    EFFECTIVE_UNIT_TIER,
                )):
            _fail(503, 'invalid_pve_archer_roster')
        return squad

    def _build_pve_binding(self, squad, battle_id: str, battle_key: str,
                           ruleset: str, commander_tier: int,
                           map_key: str) -> _PveBinding:
        """Freeze one human and nineteen independently rendered CPU armies."""
        cpu_user_ids = tuple(f'cpu-local-{index}' for index in range(1, 20))
        if self._player in cpu_user_ids:
            _fail(503, 'pve_cpu_identity_collision')
        commanders = {
            row.get('key'): row
            for row in self._native.get('commanders', [])
            if isinstance(row, dict) and row.get('build_state') == 'live'
        }
        human_commander = commanders.get(squad.commander_key)
        if human_commander is None or not commanders:
            _fail(503, 'invalid_pve_roster_commander')
        human_units = tuple(
            self._units_by_item[row[1]]['key']
            for row in squad.records
            if row[0] == squad.commander_instance_id and row[1] in self._units_by_item
        )
        if len(human_units) != 3:
            _fail(503, 'invalid_pve_human_roster')

        cpu_factions = {row.get('faction') for row in commanders.values()}
        cpu_units = [
            row for row in self._native.get('units', [])
            if (isinstance(row, dict) and row.get('build_state') == 'live'
                and row.get('is_premium') is False
                and row.get('faction') in cpu_factions
                and type(row.get('tier')) is int
                and 1 <= row['tier'] <= commander_tier)
        ]
        try:
            roster = build_battle_roster(
                mode='pve', ruleset=ruleset,
                battle_id=battle_id,
                humans=[{
                    'user_id': self._player,
                    'team': 0,
                    'commander_key': squad.commander_key,
                    'faction': human_commander.get('faction'),
                    'combat_tier': EFFECTIVE_UNIT_TIER,
                    'unit_keys': human_units,
                }],
                cpu_commander=[CpuCommander(key, row['faction'])
                               for key, row in commanders.items()],
                cpu_unit_pool=[CpuUnit(row['key'], row['faction'])
                               for row in cpu_units],
                seed=battle_key, map_key=map_key,
            )
        except (BattleRosterError, StopIteration, KeyError, TypeError, ValueError):
            _fail(503, 'invalid_pve_twenty_seat_roster')

        human_details = self._squad_details(squad.commander_tier, squad.records)
        seats: list[_PveSeat] = []
        cpu_index = 0
        for seat in roster.seats:
            if not seat.is_ai:
                if (seat.user_id != self._player or seat.unit_keys != human_units
                        or seat.team != 0):
                    _fail(503, 'invalid_pve_twenty_seat_roster')
                seats.append(_PveSeat(self._player, seat.team, False,
                                      squad.commander_key,
                                      human_details))
                continue
            cpu_index += 1
            cpu_squad = self._trusted_pve_cpu_squad(
                seat.unit_keys, commander_tier, seat.commander_key,
            )
            seats.append(_PveSeat(
                cpu_user_ids[cpu_index - 1], seat.team, True,
                seat.commander_key,
                self._squad_details(cpu_squad.commander_tier,
                                    cpu_squad.records),
            ))
        if cpu_index != 19 or len(seats) != 20:
            _fail(503, 'invalid_pve_twenty_seat_roster')
        return _PveBinding(tuple(seats), roster.digest)

    @property
    def _player(self) -> str:
        """The one native user id this queue serves (resolver-derived)."""
        if self._native_user_id is not None:
            return self._native_user_id
        return active_native_user_id()

    def _decode_requested_battle_mode(
            self, wire_mode: object) -> tuple[str, str, bool]:
        """Return the canonical mode/ruleset selected by the native row.

        Legacy ``pve``/``pvp`` requests remain valid for unmodified clients and
        use the explicitly selected/pinned ruleset.  The four selector tokens
        carry their own ruleset and therefore cannot be redirected by mutable
        server state between click and queue creation.
        """
        if wire_mode in ('pve', 'pvp'):
            return wire_mode, self._battle_ruleset, False
        if self._native_five_mode_selector and isinstance(wire_mode, str):
            decoded = NATIVE_SELECTOR_GAME_MODES.get(wire_mode)
            if decoded is not None:
                return decoded[0], decoded[1], True
        _fail(400, 'unsupported_game_mode')

    def _validate_entry(self, request: dict, headers: dict,
                        profile: dict) -> tuple[object, int, str, str]:
        expected = {'appid', 'autotest', 'build_id', 'commander_id', 'game_data_version',
                    'game_mode', 'player_regions', 'profile_timestamp', 'sessionguid',
                    'steamname', 'version'}
        if set(request) != expected:
            _fail(400, 'invalid_matchmaking_fields')
        player = self._player
        if headers.get('user_id') != player or profile.get('user_id') != player:
            _fail(403, 'native_user_mismatch')
        mode, ruleset, direct_selector = self._decode_requested_battle_mode(
            request.get('game_mode'))
        if self.public_pvp_only and mode != 'pvp':
            _fail(409, 'battle_mode_removed')
        if ruleset in self._disabled_rulesets:
            _fail(409, 'battle_ruleset_locked')
        if (not direct_selector and self._selected_mode is not None
                and (mode, ruleset) != (
                    self._selected_mode, self._battle_ruleset)):
            _fail(409, 'selected_battle_mode_mismatch')
        if mode == 'pve' and not self._pve_enabled:
            _fail(503, 'pve_relay_unavailable')
        if mode == 'pvp' and not self._pvp_enabled:
            _fail(503, 'pvp_players_unavailable')
        if not self._enabled:
            _fail(503, 'pve_battle_probe_disabled')
        if type(request.get('autotest')) is not bool or request['autotest']:
            _fail(400, 'invalid_autotest')
        _integer(request.get('appid'), 'invalid_appid', 0xffffffff)
        _integer(request.get('build_id'), 'invalid_build_id', 0xffffffff)
        _integer(request.get('version'), 'invalid_version', 0xffffffff)
        _integer(request.get('profile_timestamp'), 'invalid_profile_timestamp')
        _integer(request.get('commander_id'), 'invalid_commander_id')
        _text(request.get('game_data_version'), 'invalid_game_data_version', 80)
        _text(request.get('sessionguid'), 'invalid_sessionguid', 128)
        steamname = request.get('steamname')
        if not isinstance(steamname, str) or not steamname or len(steamname) > 128 \
                or any(ord(char) < 32 for char in steamname):
            _fail(400, 'invalid_steamname')
        regions = request.get('player_regions')
        if not isinstance(regions, dict) or set(regions) != {'local'}:
            _fail(400, 'invalid_player_regions')
        _integer(regions['local'], 'invalid_player_region_latency', 60000)
        squad, saved = self._trusted_battle_squad(profile)
        if request['commander_id'] != squad.commander_instance_id or request['profile_timestamp'] > saved:
            _fail(409, 'stale_matchmaking_profile')
        return squad, saved, mode, ruleset

    def enter(self, raw: bytes, content_type: str, profile: dict) -> dict:
        result, _generation = self.enter_with_generation(raw, content_type, profile)
        return result

    def enter_with_generation(self, raw: bytes, content_type: str,
                              profile: dict) -> tuple[dict, str]:
        """Enter and capture the server queue generation under the same lock."""
        request, headers, form_scalars = decode_matchmaking_request(raw, content_type)
        if form_scalars:
            _fail(400, 'invalid_matchmaking_envelope')
        with self._lock:
            self._mutation()
            self._expire()
            squad, saved, mode, ruleset = self._validate_entry(
                request, headers, profile,
            )
            now = self._now()
            if self._queue is not None:
                if saved < self._queue.profile_saved:
                    _fail(409, 'stale_matchmaking_profile')
                if (self._queue.mode, self._queue.ruleset,
                        self._queue.commander_instance_id, self._queue.records) != \
                        (mode, ruleset,
                         squad.commander_instance_id, squad.records):
                    _fail(409, 'matchmaking_already_queued')
                # Idempotent retry cannot extend the original deadline.
            elif mode == 'pvp' or self._cloud_coop_pve and mode == 'pve':
                # Standard PvP: the battle id/key, the opponent and the map
                # authority all come from the Worker assignment.  The queue
                # only freezes this player's trusted squad until
                # ``bind_pvp_battle`` installs the two-seat roster.
                self._queue = _Queue(
                    mode, ruleset,
                    BATTLE_RULESET_MAPS[ruleset],
                    now, now + QUEUE_SECONDS, saved,
                    squad.commander_instance_id, squad.records, squad.commander_tier,
                    squad.commander_key, squad.unit_tiers, (), 0, '', (0, 0, 0),
                    '', '', '')
                self._announced = False
                self._notification_uncertain = False
                self._enrolled_users.clear()
            else:
                battle_id, battle_key = self._new_credentials()
                map_key = (native_battle_map_key(ruleset)
                           if self._legacy_battle_fixture else
                           choose_native_battle_map(ruleset, choice=self._map_choice))
                cpu_tier = (self._pve_enemy_tier
                            if self._pve_enemy_tier is not None
                            else max(squad.unit_tiers))
                pve = self._build_pve_binding(
                    squad, battle_id, battle_key, ruleset, cpu_tier, map_key,
                )
                # Preserve the historical singular lab metadata as a genuine
                # opponent representative, not one of the nine allied CPUs.
                first_cpu = next(seat for seat in pve.seats
                                 if seat.is_ai and seat.team == 1)
                first_cpu_records = tuple(
                    tuple(row) for row in first_cpu.details['full_squad_setup']
                )
                self._last_credentials = (battle_id, battle_key)
                self._queue = _Queue(
                    'pve', ruleset,
                    map_key,
                    now, now + QUEUE_SECONDS, saved,
                    squad.commander_instance_id, squad.records, squad.commander_tier,
                    squad.commander_key, squad.unit_tiers, first_cpu_records,
                    first_cpu.details['commander_tier'], first_cpu.commander_key,
                    (EFFECTIVE_UNIT_TIER,) * 3, battle_id, battle_key,
                    # The native /check parser accepts a party_id string on
                    # each battle user row.  Reuse this server-generated UUID
                    # as the immutable party identity so the final /event can
                    # be verified without inventing a value later.
                    battle_id, None, pve)
                self._announced = False
                self._notification_uncertain = False
                self._enrolled_users.clear()
            if self._queue is None:
                _fail(503, 'matchmaking_generation_unavailable')
            generation = (self._queue.party_id or
                          f'pending-pvp-{id(self._queue):x}')
            return (ca_envelope({'user_id': self._player, 'recheck_in': RECHECK_VALUE},
                                time.time_ns() // 1_000_000),
                    generation)

    def cancel(self, profile: dict) -> dict:
        scope = getattr(self, 'party_cancel_scope', None)
        if callable(scope):
            with self._lock:
                self._mutation()
                self._trusted_squad(profile)
            with scope():
                with self._lock:
                    self._mutation()
                    self._trusted_squad(profile)
                    self._clear_queue()
                    return ca_envelope({'result': 'cancelled'}, time.time_ns() // 1_000_000)
        # Group cancellation is acknowledged by the Worker before removing the
        # local seat. Never perform network I/O while holding the queue lock.
        guard = getattr(self, 'party_cancel_guard', None)
        if callable(guard):
            with self._lock:
                self._trusted_squad(profile)
                generation = self._queue
            guard()
            with self._lock:
                if self._queue is not generation:
                    _fail(409, 'matchmaking_queue_replaced')
                self._mutation()
                self._trusted_squad(profile)
                self._clear_queue()
                return ca_envelope({'result': 'cancelled'}, time.time_ns() // 1_000_000)
        with self._lock:
            self._mutation()
            self._trusted_squad(profile)
            self._clear_queue()
            return ca_envelope({'result': 'cancelled'}, time.time_ns() // 1_000_000)

    def enter_party_attempt(self, profile: dict, *, mode: str, ruleset: str,
                            loadout: dict, expected_generation=None) -> bool:
        """Freeze this client's trusted squad for its own authenticated group seat.

        Internal bridge seam only. The caller has already verified the server's
        frozen attempt and own loadout revision. No peer profile or synthetic
        native HTTP request is accepted here.
        """
        with self._lock:
            self._mutation()
            self._expire()
            if (not self._enabled or ruleset not in BATTLE_RULESET_MAPS
                    or mode not in ('pve', 'pvp')
                    or mode == 'pvp' and not self._pvp_enabled
                    or mode == 'pve' and not (self._pve_enabled and self._cloud_coop_pve)):
                _fail(503, 'party_matchmaking_unavailable')
            if profile.get('user_id') != self._player:
                _fail(403, 'native_user_mismatch')
            if expected_generation is None:
                if self._queue is not None:
                    _fail(409, 'matchmaking_already_queued')
            elif (self._queue is not expected_generation
                    or not self._is_cloud_queue(self._queue)
                    or self._queue.pvp is not None or self._announced
                    or self._notification_uncertain):
                # Discovery may finish after native Cancel or another Play.
                # Its old generation may never replace or clear the new one.
                return False
            squad, saved = self._trusted_battle_squad(profile)
            commander = next((row for row in self._native.get('commanders', [])
                              if row.get('key') == squad.commander_key), None)
            items = [str(row[1]) for row in squad.records
                     if row[0] == squad.commander_instance_id and row[1] in self._units_by_item]
            if (commander is None or loadout != {
                    'commander_id': str(commander['item_id']), 'item_ids': items}):
                _fail(409, 'party_local_selection_changed')
            now = self._now()
            if expected_generation is not None:
                self._clear_queue()
            self._queue = _Queue(mode, ruleset, BATTLE_RULESET_MAPS[ruleset],
                now, now + QUEUE_SECONDS, saved,
                squad.commander_instance_id, squad.records, squad.commander_tier,
                squad.commander_key, squad.unit_tiers, (), 0, '', (0, 0, 0), '', '', '')
            self._announced = False
            self._notification_uncertain = False
            self._enrolled_users.clear()
            return True

    def announce(self, profile: dict, *, expected_party_id: str | None = None) -> int:
        with self._lock:
            self._mutation()
            self._expire()
            if self._queue is None:
                _fail(409, 'matchmaking_not_queued')
            if (expected_party_id is not None
                    and self._queue.party_id != expected_party_id):
                _fail(409, 'matchmaking_queue_replaced')
            if self._announced or self._notification_uncertain:
                _fail(409, 'matchmaking_notification_already_attempted')
            if self._is_cloud_queue(self._queue) and self._queue.pvp is None:
                # battle_ready makes the client fetch /check; without the
                # Worker roster there is no complete battle to hand it.
                _fail(409, 'pvp_battle_not_bound')
            try:
                squad, saved = self._trusted_battle_squad(profile)
            except NativeLobbyError:
                self._clear_queue()
                raise
            if saved < self._queue.profile_saved or squad.commander_instance_id != self._queue.commander_instance_id \
                    or squad.records != self._queue.records:
                self._clear_queue()
                _fail(409, 'matchmaking_profile_changed')
            if self._notify is None:
                _fail(503, 'matchmaking_notifier_unavailable')
            try:
                self._in_callback = True
                count = self._notify('battle_ready')
            except Exception:
                self._notification_uncertain = True
                _fail(503, 'matchmaking_notification_uncertain')
            finally:
                self._in_callback = False
            if type(count) is not int or not 0 <= count <= 32:
                self._notification_uncertain = True
                _fail(503, 'matchmaking_notification_uncertain')
            if count == 0:
                _fail(503, 'matchmaking_client_not_connected')
            self._announced = True
            return count

    def _announced_queue(self, profile: dict) -> _Queue:
        """Called under the mutation lock; enrollment shares roster validation."""
        self._expire()
        queue = self._queue
        if (not self._enabled or queue is None or not self._announced
                or queue.mode not in ('pve', 'pvp')
                or self._is_cloud_queue(queue) and queue.pvp is None):
            _fail(503, 'battle_details_not_ready')
        try:
            squad, saved = self._trusted_battle_squad(profile)
        except NativeLobbyError:
            self._clear_queue()
            raise
        if profile.get('user_id') != self._player or saved < queue.profile_saved \
                or squad.commander_instance_id != queue.commander_instance_id or squad.records != queue.records:
            self._clear_queue()
            _fail(409, 'matchmaking_profile_changed')
        return queue

    def check(self, profile: dict) -> dict:
        with self._lock:
            self._mutation()
            queue = self._announced_queue(profile)
            human_details = {'commander_tier': queue.commander_tier,
                             'full_squad_setup': [list(row) for row in queue.records],
                             'new_player': False, 'premium': False}
            def user(user_id: str, ai: bool, details: dict) -> dict:
                groups = queue.pvp.party_groups if queue.pvp else ()
                group = next((members for members in groups if user_id in members), ())
                # Any nonempty value draws a party badge, even a unique solo
                # UUID. Only a frozen multi-member social group has a party.
                party_id = '' if ai or not group else str(uuid.uuid5(
                    uuid.NAMESPACE_URL, 'twa-battle-party:' + queue.battle_id + ':' +
                    json.dumps(group, separators=(',', ':'))))
                return {'user_id': user_id, 'party_id': party_id,
                        'matchmaking_details': {
                    'profile_matchmaking_details': copy.deepcopy(details)}, 'is_ai': ai}
            if self._is_cloud_queue(queue):
                # Both companions build this from the same Worker roster, so
                # the two clients see one battle: identical id/key/map and
                # seat order, differing only in the top-level caller id.
                teams: list[list[dict]] = [[], []]
                for seat in queue.pvp.seats:
                    teams[seat.team].append(user(seat.user_id, seat.is_ai, seat.details))
            else:
                if queue.pve is None:
                    _fail(503, 'invalid_pve_twenty_seat_roster')
                teams = [[], []]
                for seat in queue.pve.seats:
                    teams[seat.team].append(
                        user(seat.user_id, seat.is_ai, seat.details),
                    )
            response = {'user_id': self._player, 'status': 'battle_ready',
                        'battle_id': queue.battle_id, 'battle_key': queue.battle_key,
                        'relay_server': LAB_RELAY_SERVER,
                        # Both records use Alps terrain. The selected record
                        # determines the native victory/recovery rules and is
                        # frozen with the queue before the start notification.
                        'battle_users': {'map': queue.map_key, 'teams': teams}}
            return ca_envelope(response, time.time_ns() // 1_000_000)

    def _arbitration_queue(self, request: dict, headers: dict, profile: dict) -> _Queue:
        if set(request) != ARBITRATION_FIELDS:
            _fail(400, 'invalid_arbitration_fields')
        for key in ARBITRATION_FIELDS:
            _text(request[key], 'invalid_arbitration_value')
        player = self._player
        if headers.get('user_id') != player or request['user_id'] != player:
            _fail(403, 'native_user_mismatch')
        queue = self._announced_queue(profile)
        if request['battle_id'] != queue.battle_id or request['battle_key'] != queue.battle_key:
            _fail(409, 'arbitration_battle_mismatch')
        return queue

    # -- standard PvP (Worker-assigned two-seat battles) ----------------------

    @staticmethod
    def _squad_details(commander_tier: int, records) -> dict:
        return {'commander_tier': commander_tier,
                'full_squad_setup': [list(row) for row in records],
                'new_player': False, 'premium': False}

    def pvp_local_details(self) -> dict:
        """This player's trusted ``profile_matchmaking_details`` for upload.

        Exactly the row ``check`` presents for the local human in PvE, built
        from the queue's frozen squad, so the Worker roster carries the same
        rows the local ``/check`` and the frozen SQLite context will use.
        """
        with self._lock:
            self._expire()
            queue = self._queue
            if queue is None or not self._is_cloud_queue(queue):
                _fail(409, 'pvp_not_queued')
            return self._squad_details(queue.commander_tier, queue.records)

    @property
    def pvp_queue_generation(self):
        """Opaque immutable queue token for in-process admission cancellation."""
        with self._lock:
            self._expire()
            if self._queue is None or not self._is_cloud_queue(self._queue):
                return None
            return self._queue

    def is_completed_pvp_generation(self, generation) -> bool:
        """Proof that this exact cloud queue completed, not merely went idle."""
        with self._lock:
            completed = self._last_completed_cloud_queue
            return (isinstance(generation, _Queue) and completed is not None
                    and generation.completion_generation is completed.completion_generation)

    def is_current_pvp_generation(self, generation) -> bool:
        """Match an admission token through binding, never across a new Play."""
        with self._lock:
            queue = self._queue
            return (isinstance(generation, _Queue) and self._is_cloud_queue(queue)
                    and generation.completion_generation is queue.completion_generation)

    def abort_prepared_pvp_generation(self, generation, battle_id: str) -> bool:
        """Clear only the exact bound queue whose remote lease was released.

        The coordinator separately proves that the remote admission ended
        (or that an unstarted party reservation was released).
        Exact object identity here also fences a queue replaced during its GET.
        This is an abort, not a native final or completion receipt.
        """
        with self._lock:
            self._mutation()
            queue = self._queue
            if (queue is None or queue is not generation
                    or not self._is_cloud_queue(queue) or queue.pvp is None
                    or queue.battle_id != battle_id):
                return False
            self._clear_queue()
            return True

    def is_cleared_pvp_generation(self, generation) -> bool:
        """Proof of the exact abort edge, without implying battle completion."""
        with self._lock:
            return (isinstance(generation, _Queue)
                    and self._last_cleared_queue is generation
                    and self._queue is not generation)

    def pvp_local_cloud_loadout(self) -> dict:
        """Return only Worker-authorized catalog type identities, in slot order."""
        with self._lock:
            self._expire()
            queue = self._queue
            if queue is None or not self._is_cloud_queue(queue):
                _fail(409, 'pvp_not_queued')
            commander = next((row for row in self._native.get('commanders', [])
                              if isinstance(row, dict)
                              and row.get('key') == queue.commander_key), None)
            item_ids = [str(row[1]) for row in queue.records
                        if row[0] == queue.commander_instance_id
                        and row[1] in self._units_by_item]
            if (commander is None or type(commander.get('item_id')) is not int
                    or len(item_ids) != 3):
                _fail(503, 'invalid_pvp_local_loadout')
            return {'commander_id': str(commander['item_id']),
                    'item_ids': item_ids}

    def pvp_rows_cloud_loadout(self, rows: object) -> dict:
        """Derive catalog type identity from already validated native rows."""
        details = self.pvp_opponent_details(rows)
        records = details['full_squad_setup']
        commanders = {row['item_id']: row for row in self._native.get('commanders', [])
                      if isinstance(row, dict) and row.get('build_state') == 'live'}
        roots = [row for row in records if row[0] == 0 and row[1] in commanders]
        if len(roots) != 1:
            _fail(503, 'invalid_pvp_roster')
        items = [str(row[1]) for row in records
                 if row[0] == roots[0][2] and row[1] in self._units_by_item]
        if len(items) != 3:
            _fail(503, 'invalid_pvp_roster')
        return {'commander_id': str(roots[0][1]), 'item_ids': items}

    def pvp_opponent_details(self, rows: object) -> dict:
        """Validate the opponent's roster rows and derive its commander Tier.

        The Worker stores the rows opaquely, so the shape is checked here
        against the shared native catalogue: one parentless live commander
        root, three of its equipped live units, and a contiguous run of
        parentless commander-Tier (type 12) progress rows whose length is the
        commander Tier.  Rows are otherwise forwarded verbatim; nothing is
        decrypted, re-priced or granted.
        """
        if isinstance(rows, dict) and isinstance(rows.get('full_squad_setup'), list):
            rows = rows['full_squad_setup']
        if not isinstance(rows, list) or not 1 <= len(rows) <= _MAX_PVP_SQUAD_ROWS:
            _fail(503, 'invalid_pvp_opponent_squad')
        records: list[tuple[int, int, int, int]] = []
        instances: set[int] = set()
        for row in rows:
            if (not isinstance(row, list) or len(row) != 4
                    or any(type(value) is not int for value in row)):
                _fail(503, 'invalid_pvp_opponent_squad')
            parent, item, instance, quantity = row
            if (not 0 <= parent <= UINT64_MAX or not 1 <= item <= UINT64_MAX
                    or not 1 <= instance <= UINT64_MAX or not 1 <= quantity <= UINT64_MAX
                    or instance in instances):
                _fail(503, 'invalid_pvp_opponent_squad')
            instances.add(instance)
            records.append((parent, item, instance, quantity))
        commanders = {row['item_id']: row for row in self._native.get('commanders', [])
                      if isinstance(row, dict) and row.get('build_state') == 'live'}
        roots = [row for row in records if row[0] == 0 and row[1] in commanders]
        if len(roots) != 1:
            _fail(503, 'invalid_pvp_opponent_commander')
        commander_root = roots[0]
        commander = commanders[commander_root[1]]
        equipped = [row for row in records
                    if row[0] == commander_root[2] and row[1] in self._units_by_item]
        if (len(equipped) != 3
                or any(self._units_by_item[row[1]].get('faction') != commander.get('faction')
                       for row in equipped)):
            _fail(503, 'invalid_pvp_opponent_units')
        tier_by_item = {row.get('item_id'): row.get('tier')
                        for row in self._native.get('commander_tiers', [])
                        if isinstance(row, dict) and row.get('commander') == commander.get('key')}
        owned_tiers = sorted(tier_by_item[row[1]] for row in records
                             if row[0] == 0 and row[1] in tier_by_item)
        commander_tier = max(owned_tiers, default=1)
        if (any(type(tier) is not int or not 1 <= tier <= 10 for tier in owned_tiers)
                or owned_tiers != list(range(1, len(owned_tiers) + 1))
                or commander_tier < max(self._units_by_item[row[1]].get('tier', 1)
                                        for row in equipped)):
            _fail(503, 'invalid_pvp_opponent_commander_tier')
        return self._squad_details(commander_tier, records)

    def _render_pvp_cpu_roster(self, queue: _Queue, battle_id: str,
                               policy: dict, humans: list[_PvpSeat]):
        """Render deterministic CPU rows without adding auth/reward humans."""
        commanders = {row['item_id']: row for row in self._native.get('commanders', [])
                      if isinstance(row, dict) and row.get('build_state') == 'live'}
        human_inputs = []
        for seat in humans:
            records = seat.details['full_squad_setup']
            roots = [row for row in records if row[0] == 0 and row[1] in commanders]
            if len(roots) != 1:
                _fail(503, 'invalid_pvp_roster')
            commander = commanders[roots[0][1]]
            units = tuple(self._units_by_item[row[1]]['key'] for row in records
                          if row[0] == roots[0][2] and row[1] in self._units_by_item)
            if len(units) != 3:
                _fail(503, 'invalid_pvp_roster')
            human_inputs.append({'user_id': seat.user_id, 'team': seat.team,
                                 'commander_key': commander['key'],
                                 'faction': commander['faction'],
                                 'combat_tier': EFFECTIVE_UNIT_TIER,
                                 'unit_keys': units})
        cpu_commanders = [CpuCommander(row['key'], row['faction'])
                          for row in commanders.values()]
        factions = {row.faction for row in cpu_commanders}
        cpu_units = [CpuUnit(row['key'], row['faction'])
                     for row in self._native.get('units', [])
                     if (isinstance(row, dict) and row.get('build_state') == 'live'
                         and row.get('is_premium') is False
                         and row.get('faction') in factions
                         and (policy['version'] not in (4, 5)
                              or (type(row.get('tier')) is int
                                  and row['tier'] == EFFECTIVE_UNIT_TIER)))]
        try:
            if policy['version'] == 3:
                cpu_commanders, cpu_units = select_cpu_asset_palette_v3(
                    cpu_commanders, cpu_units, policy['seed'])
            elif policy['version'] == 4:
                cpu_commanders, cpu_units = select_cpu_asset_palette_v4(
                    cpu_commanders, cpu_units, policy['seed'])
            rendered = build_battle_roster(
                mode=queue.mode, ruleset=queue.ruleset, battle_id=battle_id,
                humans=human_inputs, cpu_commander=cpu_commanders,
                cpu_unit_pool=cpu_units, seed=policy['seed'],
                map_key=queue.map_key, honor_explicit_teams=True,
                allow_one_sided_pvp=queue.mode == 'pvp' and policy['version'] in (2, 3, 4, 5),
                independent_cpu_commanders=policy['version'] == 5)
        except (BattleRosterError, KeyError, TypeError, ValueError):
            _fail(503, 'invalid_pvp_twenty_seat_roster')
        human_by_id = {seat.user_id: seat for seat in humans}
        result = []
        for seat in rendered.seats:
            if not seat.is_ai:
                result.append(human_by_id[seat.user_id])
                continue
            squad = self._trusted_pve_cpu_squad(
                seat.unit_keys, EFFECTIVE_UNIT_TIER, seat.commander_key)
            cpu_id = 'cpu-pvp-' + hashlib.sha256(
                (policy['seed'] + ':' + str(seat.roster_slot)).encode()
            ).hexdigest()[:24]
            result.append(_PvpSeat(
                cpu_id, seat.roster_slot, seat.team, 0,
                self._squad_details(squad.commander_tier, squad.records), True))
        if len(result) != 20 or sum(row.is_ai for row in result) != 20 - len(humans):
            _fail(503, 'invalid_pvp_twenty_seat_roster')
        return result, rendered.digest

    def bind_pvp_battle(self, *, assignment_id: object, battle_id: object,
                        battle_key: object, seats: object, reward_policy: object,
                        roster_policy: object = None,
                        party_groups: object = None,
                        battle_lifetime_seconds: object = None,
                        map_key: object = None) -> dict:
        """Install the Worker's frozen two-seat roster into the PvP queue.

        ``seats`` are dicts ``{user_id, seat, team, player_id, details}`` in
        seat order; the local seat's ``details`` must equal what this queue
        uploaded and the other seat's come from ``pvp_opponent_details``.
        An identical rebind is a no-op; a different one is refused because
        the announced credentials are already frozen for arbitration.
        """
        with self._lock:
            self._mutation()
            self._expire()
            queue = self._queue
            if queue is None or not self._is_cloud_queue(queue):
                _fail(409, 'pvp_not_queued')
            if self._announced or self._notification_uncertain:
                _fail(409, 'pvp_battle_already_announced')
            if self._legacy_battle_fixture:
                _fail(503, 'invalid_matchmaking_credentials')
            battle_id, battle_key = self._validated_credentials(battle_id, battle_key)
            if (not isinstance(assignment_id, str) or not assignment_id
                    or not isinstance(reward_policy, dict)
                    or type(battle_lifetime_seconds) is not float
                    or not 0 < battle_lifetime_seconds <= 24 * 60 * 60):
                _fail(503, 'invalid_pvp_assignment')
            requested_map = queue.map_key if map_key is None else map_key
            if not is_native_battle_map(requested_map, queue.ruleset):
                _fail(503, 'invalid_pvp_map_key')
            candidate_queue = replace(queue, map_key=requested_map)
            legacy = roster_policy is None
            version = roster_policy.get('version') if isinstance(roster_policy, dict) else None
            expected_policy = {'version': version, 'totalSeats': 20, 'seatsPerTeam': 10,
                               'unitsPerSeat': 3, 'humanParticipantsOnly': True,
                               'cpuFill': True,
                               'seed': queue.mode + '-roster-v' + str(version) + ':' + assignment_id}
            integer_keys = ('version', 'totalSeats', 'seatsPerTeam', 'unitsPerSeat')
            if (not legacy and (not isinstance(roster_policy, dict)
                    or version not in (1, 2, 3, 4, 5)
                    or set(roster_policy) != set(expected_policy)
                    or any(type(roster_policy.get(key)) is not int
                           for key in integer_keys)
                    or type(roster_policy.get('humanParticipantsOnly')) is not bool
                    or type(roster_policy.get('cpuFill')) is not bool
                    or not isinstance(roster_policy.get('seed'), str)
                    or roster_policy != expected_policy)):
                _fail(503, 'invalid_pvp_roster_policy')
            if (not isinstance(seats, list) or (legacy and len(seats) != 2)
                    or (not legacy and not 1 <= len(seats) <= (10 if queue.mode == 'pve' else 20))):
                _fail(503, 'invalid_pvp_roster')
            frozen: list[_PvpSeat] = []
            local_details = self._squad_details(queue.commander_tier, queue.records)
            for index, row in enumerate(seats):
                if (not isinstance(row, dict)
                        or set(row) != {'user_id', 'seat', 'team', 'player_id', 'details'}
                        or row['seat'] != index
                        or any(type(row[key]) is not int for key in ('seat', 'team', 'player_id'))
                        or row['team'] not in (0, 1)
                        or (queue.mode == 'pve' and row['team'] != 0)
                        or (queue.mode == 'pvp' and version not in (2, 3, 4, 5) and row['team'] != index % 2)
                        or row['player_id'] != index + 1
                        or not isinstance(row['details'], dict)
                        or set(row['details']) != set(local_details)):
                    _fail(503, 'invalid_pvp_roster')
                user_id = row['user_id']
                if (not isinstance(user_id, str) or not 1 <= len(user_id) <= 36
                        or any(ord(char) < 32 or ord(char) > 126 for char in user_id)):
                    _fail(503, 'invalid_pvp_roster')
                if user_id == self._player and row['details'] != local_details:
                    _fail(503, 'pvp_local_squad_mismatch')
                frozen.append(_PvpSeat(user_id, index, row['team'], index + 1,
                                       copy.deepcopy(row['details'])))
            user_ids = [seat.user_id for seat in frozen]
            if any(sum(seat.team == team for seat in frozen) > 10 for team in (0, 1)):
                _fail(503, 'invalid_pvp_roster')
            if len(set(user_ids)) != len(user_ids) or self._player not in user_ids:
                _fail(503, 'invalid_pvp_roster')
            groups = []
            grouped = set()
            teams_by_user = {seat.user_id: seat.team for seat in frozen}
            if party_groups is not None:
                if not isinstance(party_groups, list):
                    _fail(503, 'invalid_battle_party_groups')
                if party_groups and version not in (2, 3, 4, 5):
                    _fail(503, 'invalid_battle_party_groups')
                for group in party_groups:
                    if (not isinstance(group, list) or not 2 <= len(group) <= 4
                            or any(not isinstance(user, str) or user not in teams_by_user
                                   or user in grouped for user in group)
                            or len(set(group)) != len(group)
                            or len({teams_by_user[user] for user in group}) != 1):
                        _fail(503, 'invalid_battle_party_groups')
                    grouped.update(group)
                    groups.append(tuple(sorted(group)))
            roster_digest = None
            if not legacy:
                frozen, roster_digest = self._render_pvp_cpu_roster(
                    candidate_queue, battle_id, roster_policy, frozen)
            local_index = next(index for index, seat in enumerate(frozen)
                               if seat.user_id == self._player)
            binding = _PvpBinding(assignment_id, tuple(frozen),
                                  copy.deepcopy(reward_policy), local_index,
                                  copy.deepcopy(roster_policy), roster_digest,
                                  tuple(sorted(groups)))
            if queue.pvp is not None:
                if (queue.map_key != requested_map
                        or (queue.battle_id, queue.battle_key, queue.pvp)
                        != (battle_id, battle_key, binding)):
                    _fail(409, 'pvp_battle_already_bound')
                return self.pvp_binding
            if (self._last_credentials is not None
                    and (battle_id == self._last_credentials[0]
                         or battle_key == self._last_credentials[1])):
                _fail(503, 'matchmaking_credentials_reused')
            self._last_credentials = (battle_id, battle_key)
            # Keep the queue allocation ID separate from the native party IDs
            # rendered in /check and frozen for final result validation.
            self._queue = replace(candidate_queue, battle_id=battle_id, battle_key=battle_key,
                                  party_id=battle_id, pvp=binding,
                                  expires=self._now() + battle_lifetime_seconds)
            return self.pvp_binding

    def abort_pvp(self, reason: str) -> bool:
        """Drop the current PvP queue (roster timeout, Worker failure)."""
        if not isinstance(reason, str) or not reason:
            raise ValueError('abort reason required')
        with self._lock:
            self._mutation()
            queue = self._queue
            if queue is None or not self._is_cloud_queue(queue):
                return False
            self._clear_queue()
            return True

    def notify_cancelled_party_queue(self, generation, notify, *, stop,
                                     retry_if_no_recipient=False) -> int | None:
        """Notify only the exact, just-cleared public queue before a battle.

        The admission owner proves the authoritative cancelled attempt. This
        lock fences a newer native queue until the local XMPP send completes,
        just as announce() fences battle_ready. Unknown sends remain consumed.
        A native HTTP owner may allow an explicit retry after strict zero
        recipients; the existing peer-notification default stays one-shot.
        """
        with self._lock:
            self._mutation()
            if type(retry_if_no_recipient) is not bool:
                _fail(400, 'invalid_party_notification_retry_policy')
            if (stop.is_set() or generation is None or self._queue is not None
                    or self._last_cleared_queue is not generation
                    or self._cancel_notified_queue is generation
                    or not self._is_cloud_queue(generation)
                    or generation.pvp is not None or generation.battle_id):
                return None
            self._cancel_notified_queue = generation
            try:
                self._in_callback = True
                count = notify('cancelled')
            except Exception:
                _fail(503, 'party_cancel_notification_uncertain')
            finally:
                self._in_callback = False
            if type(count) is not int or not 0 <= count <= 32:
                _fail(503, 'party_cancel_notification_uncertain')
            if count == 0 and retry_if_no_recipient:
                self._cancel_notified_queue = None
            return count

    def complete_battle(self, battle_id: str) -> bool:
        """Release only the queue which produced this completed battle.

        A delayed duplicate final event must never clear a newer queue, so a
        nonmatching or already-completed ID is an idempotent no-op.
        """
        with self._lock:
            self._mutation()
            if self._queue is None or self._queue.battle_id != battle_id:
                return False
            if self._is_cloud_queue(self._queue):
                # Publish completion under the same lock as the idle edge.
                # Admission may poll before the coordinator's released()
                # callback and must not re-adopt this completed generation.
                self._last_completed_cloud_queue = self._queue
            self._clear_queue()
            return True

    def enroll(self, request: dict, headers: dict, profile: dict) -> dict:
        """Register the sole human in the announced local PvE experiment.

        The CPU is not an arbitration participant. Retries neither add users
        nor extend the queue deadline. This only records an HTTP enrollment;
        it is not proof of a working relay connection or running battle.
        """
        with self._lock:
            self._mutation()
            self._arbitration_queue(request, headers, profile)
            self._enrolled_users.add(self._player)
            return ca_envelope({'result': 'ok'}, time.time_ns() // 1_000_000)

    def check_arbitration(self, request: dict, headers: dict, profile: dict) -> dict:
        with self._lock:
            self._mutation()
            self._arbitration_queue(request, headers, profile)
            if self._enrolled_users != {self._player}:
                _fail(409, 'arbitration_not_enrolled')
            return ca_envelope({'all_users_ready': True}, time.time_ns() // 1_000_000)


class _Pairs(list):
    pass


def _collapse(value: object, path: tuple[str, ...] = ()) -> object:
    if isinstance(value, _Pairs):
        result, seen = {}, {}
        for key, item in value:
            item = _collapse(item, path + (key,))
            seen[key] = seen.get(key, 0) + 1
            if key in result:
                if not (path == ('request',) and key == 'version' and seen[key] == 2
                        and type(item) is int and type(result[key]) is int and item == result[key]):
                    raise NativeLobbyError(400, 'duplicate_json_key')
            result[key] = item
        return result
    if isinstance(value, list):
        return [_collapse(item, path + ('[]',)) for item in value]
    return value


def decode_matchmaking_request(raw: bytes, content_type: str) -> tuple[dict, dict, bool]:
    """Preserve strict body validation, narrowly normalize the native duplicate."""
    try:
        return decode_native_request(raw, content_type)
    except NativeLobbyError as error:
        if error.code != 'duplicate_json_key':
            raise
    # The strict decoder already checked MIME, size, encoding and form syntax.
    # Parse again preserving every pair so no ambiguous duplicate is hidden.
    text = raw.decode('utf-8', 'strict')
    def invalid_constant(_value):
        raise NativeLobbyError(400, 'invalid_json_number')
    def read_json(text):
        return json.loads(text, object_pairs_hook=_Pairs, parse_constant=invalid_constant)
    try:
        media = content_type.partition(';')[0].strip().lower()
        if media == 'application/x-www-form-urlencoded':
            fields = _Pairs(parse_qsl(text, keep_blank_values=True, strict_parsing=True,
                                     encoding='utf-8', errors='strict', max_num_fields=64))
            body = _collapse(fields)  # No duplicate form envelope fields.
            for key in ('request', 'headers'):
                if key in body:
                    body[key] = _collapse(read_json(body[key]), (key,))
        else:
            body = _collapse(read_json(text))
        normalized = json.dumps(body, separators=(',', ':'), allow_nan=False).encode('utf-8')
        return decode_native_request(normalized, 'application/json')
    except NativeLobbyError:
        raise
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise NativeLobbyError(400, 'invalid_json') from None


def decode_arbitration_request(raw: bytes, content_type: str, *,
                               metadata: dict | None = None) -> tuple[dict, dict, bool]:
    """Normalize only the native arbitration serializer's duplicate headers.key.

    BD1310 emits the fixed first string 'no_key'; BD2F49..76 appends the context
    key. Exactly that ordered pair is accepted, retaining the second string.
    This loopback fake-auth probe DOES NOT authenticate the context key. This
    exception is not suitable for a public server or a general JSON decoder.

    Require the complete arbitration envelope even without duplicates, so an
    empty ordinary /check cannot obtain this compatibility exception. Metadata
    contains only fixed duplicate categories, counts, types and comparisons.
    """
    if metadata is not None:
        metadata.clear()
        metadata['duplicates'] = []
    try:
        decode_native_request(raw, content_type)
    except NativeLobbyError as error:
        if error.code != 'duplicate_json_key':
            raise

    def collapse(value, path=()):
        if isinstance(value, _Pairs):
            groups = {}
            for key, item in value:
                groups.setdefault(key, []).append(item)
            for key, items in groups.items():
                if len(items) < 2:
                    continue
                native_key = path == ('headers',) and key == 'key'
                if metadata is not None and len(metadata['duplicates']) < 8:
                    metadata['duplicates'].append({
                        'kind': 'arbitration_header_key' if native_key else 'other',
                        'count': len(items),
                        'types': ['dict' if isinstance(item, _Pairs) else type(item).__name__
                                  for item in items[:3]],
                        'first_is_placeholder': type(items[0]) is str and items[0] == 'no_key',
                        'same_value': all(item == items[0] for item in items[1:]),
                    })
                if not (native_key and len(items) == 2
                        and all(type(item) is str and len(item) <= 4096 for item in items)
                        and items[0] == 'no_key'):
                    _fail(400, 'duplicate_json_key')
            return {key: collapse(items[-1], path + (key,)) for key, items in groups.items()}
        if isinstance(value, list):
            return [collapse(item, path + ('[]',)) for item in value]
        return value

    def invalid_constant(_value):
        _fail(400, 'invalid_json_number')

    def read_json(value):
        return json.loads(value, object_pairs_hook=_Pairs, parse_constant=invalid_constant)

    try:
        text = raw.decode('utf-8', 'strict')
        media = content_type.partition(';')[0].strip().lower()
        if media == 'application/x-www-form-urlencoded':
            fields = _Pairs(parse_qsl(text, keep_blank_values=True, strict_parsing=True,
                                     encoding='utf-8', errors='strict', max_num_fields=64))
            body = collapse(fields)
            for key in ('request', 'headers'):
                if key in body:
                    body[key] = collapse(read_json(body[key]), (key,))
        else:
            body = collapse(read_json(text))
        if not isinstance(body, dict) or set(body) != {'request', 'headers'}:
            _fail(400, 'invalid_arbitration_envelope')
        normalized = json.dumps(body, separators=(',', ':'), allow_nan=False).encode('utf-8')
        request, headers, scalars = decode_native_request(normalized, 'application/json')
        if scalars or set(request) != ARBITRATION_FIELDS:
            _fail(400, 'invalid_arbitration_fields')
        for value in request.values():
            _text(value, 'invalid_arbitration_value')
        if 'request_version' in headers and (type(headers['request_version']) is not int
                                             or headers['request_version'] != 1):
            _fail(400, 'invalid_arbitration_headers')
        for key, maximum in (('timestamp', UINT64_MAX), ('appid', 0xffffffff),
                             ('client_build_id', 0xffffffff)):
            if key in headers:
                _integer(headers[key], 'invalid_arbitration_headers', maximum)
        for key in ('key', 'key_type', 'region', 'data_set_name'):
            if key in headers and (type(headers[key]) is not str or len(headers[key]) > 4096):
                _fail(400, 'invalid_arbitration_headers')
        return request, headers, False
    except NativeLobbyError:
        raise
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise NativeLobbyError(400, 'invalid_json') from None
