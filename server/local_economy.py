"""Server-owned local economy and public-battle progression.

The native catalogue is trusted input.  Callers may name a purchase offer,
direct prerequisite, loadout, or settled battle, but they never supply an
item ID, Tier, price, balance, or reward amount.  All mutations are serialized,
persisted atomically, and idempotent by operation or match ID.

This module is deliberately independent of ``local_stack.py`` so the HTTP and
native-wire adapters can be added after their exact request shapes are proven.
"""
from __future__ import annotations

import copy
import calendar
import hashlib
import json
import re
import threading
import time
from collections import deque
from collections.abc import Callable
from pathlib import Path
from typing import Any

from economy_backend import (
    BackendConflict,
    BackendError,
    CloudEconomyBackend,
    EconomyBackend,
    FileEconomyBackend,
    read_state_json,
)
from native_consumables import (
    load_native_battle_consumables,
    tier_equivalent_consumables_by_unit,
    tier_equivalent_service_definitions,
    validate_native_battle_consumables,
)
from native_equipment import (
    equipment_for_units,
    load_native_unit_equipment,
    validate_native_unit_equipment,
)
from native_commander_talents import (
    ability_predecessors_by_commander,
    load_native_commander_talents,
    talent_rows_by_commander,
    validate_native_commander_talents,
)
from native_unit_abilities import (
    load_native_unit_abilities,
    validate_native_unit_abilities,
)

SCHEMA_VERSION = 12
LEGACY_SCHEMA_VERSION = 1
TIER_FIVE_GRANT_SCHEMA_VERSION = 2
MANDATORY_ABILITIES_SCHEMA_VERSION = 3
PREVIOUS_SCHEMA_VERSION = 4
LOADOUT_SELECTIONS_SCHEMA_VERSION = 5
TALENT_POINTS_SCHEMA_VERSION = 6
ABILITY_TREE_SCHEMA_VERSION = 7
REWARD_POLICY_SCHEMA_VERSION = 8
FULL_UNLOCK_SCHEMA_VERSION = 9
TIER_X_SANDBOX_SCHEMA_VERSION = 10
UNIT_ABILITIES_SCHEMA_VERSION = 11
PREMIUM_POLICY_SCHEMA_VERSION = 12
PRICE_VERSION = "revival-v1"
REWARD_VERSION = "revival-v1"
# BD7940 rejects an older profile, and the wire adapter clamps timestamps to
# this value.  Keep authoritative saved values strictly above the same floor
# so every real mutation has a distinct native watermark even if the system
# clock moves backwards or a valid hand-built state starts below it.
NATIVE_SAVED_FLOOR = 1_788_186_881_000
DEFAULT_COMMANDER = "rom_germanicus"
INITIAL_TIER = 10
EFFECTIVE_UNIT_TIER = 10
EFFECTIVE_CONSUMABLE_SLOTS = 2
LEGACY_FREE_EQUIPMENT_TIER = 5
PREMIUM_UNIT_GOLD_COST = 100_000
# Explicit local-operator reset targets.  Keep this closed rather than
# accepting arbitrary balances through the audited reset path.
LOCAL_COMMANDER_TALENT_RESET_TARGETS = frozenset((100, 120))

EQUIPMENT_RESEARCH_COST_BY_TIER = {
    5: 50_000,
    6: 80_000,
    7: 120_000,
    8: 180_000,
    9: 250_000,
    10: 350_000,
}
# Gold is stored in cents. These three once-per-UTC-day milestones total
# 10,000 cents (100 Gold): useful, but still keeps premium units aspirational.
DAILY_QUESTS = (
    ("first_battle", "verified_battles", 1, 2_000),
    ("three_battles", "verified_battles", 3, 3_000),
    ("first_victory", "victories", 1, 5_000),
)

# Lower medians of the usable legacy, non-premium unit prices.  Current-DB
# normal units use 100 as a local extraction sentinel at Tier II+, so those
# values must never be charged directly.
UNIT_COST_BY_TIER = {
    1: 0,
    2: 100_000,
    3: 220_000,
    4: 550_000,
    5: 1_200_000,
    6: 2_200_000,
    7: 3_800_000,
    8: 6_400_000,
    9: 10_900_000,
    10: 19_700_000,
}

WALLET_CURRENCIES = (
    "silver_cents",
    "gold_cents",
    "free_xp_cents",
    "battle_points_cents",
)
OUTCOMES = ("victory", "defeat", "draw", "aborted")
# The four amounts a settlement applies.  A remote reward authority may only
# replace these; it can never name a unit, Tier, item or currency.
REWARD_AMOUNT_FIELDS = ("unit_xp_cents", "commander_xp_cents",
                        "free_xp_cents", "silver_cents")
OUTCOME_PERCENT = {"victory": 100, "defeat": 60, "draw": 80, "aborted": 0}
REWARD_POLICIES = {
    "pve": (1, 1),
    "pvp": (3, 2),
    "private": (0, 1),
}
MAX_BALANCE = 2**63 - 1
MAX_OPERATIONS = 100_000
IDENTIFIER = re.compile(r"^[A-Za-z0-9:_-]{1,128}$")
HEX_256 = re.compile(r"^[0-9a-f]{64}$")


class EconomyError(ValueError):
    """A fail-closed economy error with a stable adapter-facing code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _plain_int(value: object, *, minimum: int = 0, maximum: int = MAX_BALANCE) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise EconomyError("invalid_integer")
    return value


def _checked_add(value: int, delta: int) -> int:
    result = value + delta
    if not 0 <= result <= MAX_BALANCE:
        raise EconomyError("balance_out_of_range")
    return result


def _identifier(value: object, code: str = "invalid_operation_id") -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise EconomyError(code)
    return value


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _read_json(path: Path) -> dict:
    """Strict state read.  The implementation now lives in the backend module
    so ``FileEconomyBackend`` and this constructor cannot drift apart."""
    try:
        return read_state_json(Path(path))
    except BackendError as error:
        raise EconomyError(error.code) from None


class LocalEconomy:
    """One local account's authoritative progression state."""

    def __init__(
        self,
        native: dict,
        path: Path | None = None,
        *,
        active_commander: str = DEFAULT_COMMANDER,
        now_ms: Callable[[], int] | None = None,
        backend: EconomyBackend | None = None,
        identity: object = None,
        zero_pve_rewards: bool = False,
        bootstrap_new_premiums: bool = False,
    ) -> None:
        if type(zero_pve_rewards) is not bool:
            raise EconomyError("invalid_local_reward_policy")
        if type(bootstrap_new_premiums) is not bool:
            raise EconomyError("invalid_premium_bootstrap")
        self._lock = threading.RLock()
        self.path = Path(path) if path is not None else None
        # ``path`` stays the compatible constructor: it is now just the file
        # backend.  An explicit backend wins so the companion can persist to
        # the Worker profile API instead.
        if backend is None and self.path is not None:
            backend = FileEconomyBackend(self.path)
        if bootstrap_new_premiums and not isinstance(backend, CloudEconomyBackend):
            raise EconomyError("premium_bootstrap_requires_cloud")
        if (zero_pve_rewards and backend is not None
                and not isinstance(backend, FileEconomyBackend)):
            raise EconomyError("local_reward_policy_requires_file_backend")
        self._backend = backend
        self._identity = identity
        self._backend_saved = 0
        # Reward amounts a settlement authority (the Cloudflare Worker) has
        # already decided for one match.  Never persisted: an award that is
        # not consumed by a first settlement is discarded with the process.
        self._pending_awards: dict[str, dict] = {}
        # Local diagnostic policy only.  The flag is copied into each newly
        # begun PvE receipt so settlement stays durable across restart; it is
        # never consulted for an existing battle or for remote awards.
        self.zero_pve_rewards = zero_pve_rewards
        self._now_ms = now_ms or (lambda: time.time_ns() // 1_000_000)
        self._build_catalog(native)

        needs_persist = False
        loaded, stored_saved = self._backend_load()
        loaded_schema: int | None = None
        if loaded is not None:
            self._backend_saved = stored_saved
            schema_version = loaded.get("schema_version")
            if type(schema_version) is not int:
                raise EconomyError("unsupported_state_schema")
            loaded_schema = schema_version
            if schema_version == LEGACY_SCHEMA_VERSION:
                state = self._migrate_v1(loaded, active_commander)
                needs_persist = True
            elif schema_version == TIER_FIVE_GRANT_SCHEMA_VERSION:
                state = self._migrate_v2(loaded)
                needs_persist = True
            elif schema_version == MANDATORY_ABILITIES_SCHEMA_VERSION:
                state = self._migrate_v3(loaded)
                needs_persist = True
            elif schema_version == PREVIOUS_SCHEMA_VERSION:
                state = self._migrate_v4(loaded)
                needs_persist = True
            elif schema_version == LOADOUT_SELECTIONS_SCHEMA_VERSION:
                state = self._migrate_v5(loaded)
                needs_persist = True
            elif schema_version == TALENT_POINTS_SCHEMA_VERSION:
                state = self._migrate_v6(loaded)
                needs_persist = True
            elif schema_version == ABILITY_TREE_SCHEMA_VERSION:
                state = self._migrate_v7(loaded)
                needs_persist = True
            elif schema_version == REWARD_POLICY_SCHEMA_VERSION:
                state = self._migrate_v8(loaded)
                needs_persist = True
            elif schema_version == FULL_UNLOCK_SCHEMA_VERSION:
                state = self._migrate_v9(loaded)
                needs_persist = True
            elif schema_version == TIER_X_SANDBOX_SCHEMA_VERSION:
                state = self._migrate_v10(loaded)
                needs_persist = True
            elif schema_version == UNIT_ABILITIES_SCHEMA_VERSION:
                state = self._migrate_v11(loaded)
                needs_persist = True
            elif schema_version == SCHEMA_VERSION:
                state = copy.deepcopy(loaded)
            else:
                raise EconomyError("unsupported_state_schema")
        else:
            state = self._fresh_state(active_commander)
            needs_persist = self._backend is not None
        if loaded_schema == SCHEMA_VERSION:
            # A current save is already authoritative. Validate it before any
            # initializer can turn missing entitlements or schema-12 fields
            # into an apparently valid account.
            self._validate_state(state)
        else:
            # Revival's current sandbox policy starts every implemented
            # commander at Tier X, owns every normal live unit and all of its
            # equipment, while premium units remain explicit Gold purchases.
            # Apply it only while creating or migrating an account; current
            # schema corruption must fail closed above rather than self-heal.
            if self._initialize_full_unlock(state):
                needs_persist = self._backend is not None
            if self._initialize_premium_entitlements(state):
                needs_persist = self._backend is not None
            if self._initialize_unit_ability_selections(state):
                needs_persist = self._backend is not None
            self._initialize_equipment_unlocks(state)
            self._initialize_daily_quests(state)
            if loaded is None and bootstrap_new_premiums:
                # Operator-selected public rules. Add an auditable grant before
                # the first cloud write, never repair or reset existing saves.
                self._prepare_new_premium_account(state)
                needs_persist = True
            if (loaded is None and self._backend is not None
                    and self._prepare_new_account(state)):
                needs_persist = True
            self._validate_state(state)
        self._state = state
        if needs_persist:
            self._persist(state)

    # ---- backend plumbing --------------------------------------------------

    def _prepare_new_premium_account(self, state: dict) -> None:
        keys = sorted(key for key, unit in self.units.items()
                      if unit.get("is_premium") is True)
        request = {"units": keys, "reason": "public-player-initial-catalog-v1",
                   "source": "sandbox_catalog"}
        self._grant_premium_catalog_state(state, keys)
        operation_id = "bootstrap-public-premium-catalog-v1"
        kind = "grant_sandbox_premium_units"
        state["operations"][operation_id] = {
            "request_hash": _canonical_hash({"kind": kind, "request": request}),
            "receipt": {"operation_id": operation_id, "kind": kind,
                        "saved": state["saved"], **request},
        }

    def _prepare_new_account(self, state: dict) -> bool:
        """Subclass hook for atomic first-persist account preparation.

        Called only after standard initialization when an authoritative
        backend returned no blob. Existing and migrated blobs never enter it.
        """
        return False

    def _backend_load(self) -> tuple[dict | None, int]:
        if self._backend is None:
            return None, 0
        try:
            loaded, stored_saved = self._backend.load(self._identity)
        except BackendError as error:
            raise EconomyError(error.code) from None
        if loaded is None:
            return None, 0
        if not isinstance(loaded, dict):
            raise EconomyError("invalid_state_schema")
        if type(stored_saved) is not int or stored_saved < 0:
            raise EconomyError("invalid_state_schema")
        return loaded, stored_saved

    def reload(self) -> dict:
        """Re-read the authoritative blob after a ``saved_conflict``.

        The stored blob carries the same ``operations`` map, so replaying a
        rejected operation with its original ``operation_id`` stays idempotent
        and can never award a second time.
        """
        with self._lock:
            loaded, stored_saved = self._backend_load()
            if loaded is None:
                raise EconomyError("state_not_found")
            if loaded.get("schema_version") != SCHEMA_VERSION:
                raise EconomyError("unsupported_state_schema")
            state = copy.deepcopy(loaded)
            self._validate_state(state)
            self._state = state
            self._backend_saved = stored_saved
            return copy.deepcopy(state)

    def run_with_reload(self, operation: Callable[[], dict], *, retries: int = 1) -> dict:
        """Run one economy operation, reloading once per ``saved_conflict``.

        ``operation`` must be a zero-argument closure over a *stable*
        ``operation_id``: the retry relies on that idempotency key, so a caller
        that generates a fresh id per attempt would double-apply.
        """
        if type(retries) is not int or not 0 <= retries <= 8:
            raise EconomyError("invalid_retry_budget")
        attempt = 0
        while True:
            try:
                return operation()
            except EconomyError as error:
                if error.code != "saved_conflict" or attempt >= retries:
                    raise
                attempt += 1
                self.reload()

    # ---- trusted catalogue -------------------------------------------------

    def _load_native_equipment_catalogue(self) -> dict:
        """Return the standard extracted catalogue; subclasses may opt in."""
        return load_native_unit_equipment()

    def _build_catalog(self, native: dict) -> None:
        if not isinstance(native, dict):
            raise EconomyError("invalid_native_catalog")
        commander_rows = [row for row in native.get("commanders", [])
                          if isinstance(row, dict) and row.get("build_state", "live") == "live"]
        unit_rows = [row for row in native.get("units", [])
                     if isinstance(row, dict) and row.get("build_state", "live") == "live"]
        self.commanders = {row.get("key"): copy.deepcopy(row) for row in commander_rows}
        self.units = {row.get("key"): copy.deepcopy(row) for row in unit_rows}
        if (None in self.commanders or len(self.commanders) != len(commander_rows)
                or None in self.units or len(self.units) != len(unit_rows)):
            raise EconomyError("duplicate_native_key")
        if DEFAULT_COMMANDER not in self.commanders:
            raise EconomyError("missing_default_commander")
        # Keep the shipped Tier for tree identity and display metadata, while
        # exposing the Tier-X sandbox's two loadout slots to every live unit.
        for unit in self.units.values():
            unit["native_num_consumable_slots"] = unit.get(
                "num_consumable_slots"
            )
            unit["num_consumable_slots"] = EFFECTIVE_CONSUMABLE_SLOTS
            unit["effective_tier"] = EFFECTIVE_UNIT_TIER

        self.commander_tiers: dict[tuple[str, int], dict] = {}
        for row in native.get("commander_tiers", []):
            if not isinstance(row, dict) or row.get("commander") not in self.commanders:
                continue
            commander_key = row.get("commander")
            tier = row.get("tier")
            item_id = row.get("item_id")
            expected_key = (
                f"tier_{tier}_{commander_key}"
                if type(tier) is int else None
            )
            if (type(tier) is not int or not 1 <= tier <= 10
                    or row.get("key") != expected_key
                    or type(item_id) is not int or not 0 < item_id < 2**64
                    or (commander_key, tier) in self.commander_tiers):
                raise EconomyError("invalid_commander_tier_catalog")
            self.commander_tiers[(commander_key, tier)] = copy.deepcopy(row)
        expected_tiers = {
            (commander_key, tier)
            for commander_key in self.commanders for tier in range(1, 11)
        }
        if set(self.commander_tiers) != expected_tiers:
            raise EconomyError("invalid_commander_tier_catalog")

        try:
            equipment = validate_native_unit_equipment(
                self._load_native_equipment_catalogue(), native,
            )
            consumables = validate_native_battle_consumables(
                load_native_battle_consumables(), native,
            )
            talents = validate_native_commander_talents(
                load_native_commander_talents(), native,
            )
            unit_abilities = validate_native_unit_abilities(
                load_native_unit_abilities(), native,
            )
        except (TypeError, ValueError) as exc:
            raise EconomyError("invalid_native_loadout_catalog") from exc
        self.native_equipment = equipment
        self.native_consumables = consumables
        self.native_commander_talents = talents
        self.native_unit_abilities = unit_abilities
        self.unit_abilities_by_db_key = {
            row["db_key"]: copy.deepcopy(row)
            for row in unit_abilities["items"]
            if row["mode"] in {"additional", "default"}
        }
        self.unit_abilities_by_unit: dict[str, list[dict]] = {
            key: [] for key in self.units
        }
        for row in self.unit_abilities_by_db_key.values():
            self.unit_abilities_by_unit[row["unit"]].append(row)
        for rows in self.unit_abilities_by_unit.values():
            rows.sort(key=lambda row: (row["ability"], row["item_id"]))
        if any(not rows for rows in self.unit_abilities_by_unit.values()):
            raise EconomyError("missing_trainable_unit_abilities")
        self.talent_rows = talent_rows_by_commander(talents)
        self.equipment_by_db_key = {
            row["db_key"]: copy.deepcopy(row)
            for row in equipment["all_live_nonpremium"]
        }
        self.equipment_by_unit: dict[str, list[dict]] = {}
        for row in self.equipment_by_db_key.values():
            self.equipment_by_unit.setdefault(row["source_unit"], []).append(row)
        for rows in self.equipment_by_unit.values():
            rows.sort(key=lambda row: (row["scope"], row["slot"],
                                       row["placement_0"], row["placement_1"], row["db_key"]))
        self.default_equipment: dict[str, dict[str, str]] = {
            key: {} for key in self.units
        }
        grouped: dict[tuple[str, str], list[dict]] = {}
        for row in self.equipment_by_db_key.values():
            if self._is_initial_equipment(row):
                grouped.setdefault(
                    (row["source_unit"], self._equipment_slot_key(row)), [],
                ).append(row)
        for (unit_key, slot), rows in grouped.items():
            highest = max(row["placement_1"] for row in rows)
            choices = [row for row in rows if row["placement_1"] == highest]
            if len(choices) != 1:
                raise EconomyError("ambiguous_default_equipment")
            self.default_equipment[unit_key][slot] = choices[0]["db_key"]

        self.consumables_by_unit = tier_equivalent_consumables_by_unit(
            native, EFFECTIVE_UNIT_TIER, consumables,
        )
        if any(not rows for rows in self.consumables_by_unit.values()):
            raise EconomyError("missing_tier_equivalent_consumables")
        self.consumable_keys_by_unit = {
            unit_key: {row["db_key"] for row in rows}
            for unit_key, rows in self.consumables_by_unit.items()
        }
        definitions = tier_equivalent_service_definitions(
            native, EFFECTIVE_UNIT_TIER, consumables,
        )
        self.consumables_by_db_key = {
            row["db_key"]: copy.deepcopy(row) for row in definitions
        }
        self.default_consumables: dict[str, dict[str, str]] = {
            key: {} for key in self.units
        }

        self.parents: dict[str, set[str]] = {key: set() for key in self.units}
        self.children: dict[str, list[str]] = {key: [] for key in self.units}
        seen_edges: set[tuple[str, str]] = set()
        for link in native.get("unit_tree_links", []):
            if not isinstance(link, dict):
                raise EconomyError("invalid_unit_tree")
            parent, child = link.get("key_0"), link.get("key_1")
            # The extracted source has nine links involving disabled/missing
            # nodes.  Only live-to-live edges can authorize a purchase.
            if parent not in self.units or child not in self.units:
                continue
            if self.units[parent].get("faction") != self.units[child].get("faction"):
                raise EconomyError("cross_faction_unit_tree")
            edge = (parent, child)
            if edge in seen_edges:
                raise EconomyError("duplicate_unit_tree_edge")
            seen_edges.add(edge)
            self.parents[child].add(parent)
            self.children[parent].append(child)
        for values in self.children.values():
            values.sort()

        self._paths: dict[tuple[str, str], tuple[str, ...]] = {}
        self.reachable: dict[str, set[str]] = {}
        for commander_key, commander in self.commanders.items():
            starters = commander.get("starting_units")
            if (not isinstance(starters, list) or len(starters) != 3
                    or any(key not in self.units for key in starters)
                    or any(self.units[key].get("faction") != commander.get("faction") for key in starters)):
                raise EconomyError("invalid_commander_starters")
            available: set[str] = set()
            for starter in dict.fromkeys(starters):
                paths = self._paths_from(starter)
                for unit_key, path in paths.items():
                    old = self._paths.get((commander_key, unit_key))
                    if old is None or (len(path), path) < (len(old), old):
                        self._paths[(commander_key, unit_key)] = path
                available.update(paths)
            # The Revival Tier-X sandbox exposes every live unit of the
            # commander's faction in the native Army list.  Keep the shipped
            # tree paths above for prerequisite/history metadata, but make
            # loadout eligibility agree with what the client visibly offers.
            # Cross-faction units remain unavailable.
            available.update(
                key for key, unit in self.units.items()
                if unit.get("faction") == commander.get("faction")
            )
            self.reachable[commander_key] = available

        self.ability_required_tier: dict[tuple[str, str, int], int] = {}
        self.ability_levels_by_key: dict[str, dict] = {}
        self.ability_levels_by_identity: dict[tuple[str, str, int], dict] = {}
        mandatory_candidates: dict[str, dict[int, tuple[str, int]]] = {
            key: {} for key in self.commanders
        }
        for row in native.get("ability_levels", []):
            if not isinstance(row, dict) or row.get("commander") not in self.commanders:
                continue
            metadata = row.get("metadata")
            if not isinstance(metadata, dict):
                raise EconomyError("invalid_ability_catalog")
            commander_key = row["commander"]
            level_key = row.get("key")
            item_id = row.get("item_id")
            ability_key, level = metadata.get("ability_key"), metadata.get("ability_level")
            required = metadata.get(commander_key)
            cost = metadata.get("free_xp_cents")
            if (not isinstance(level_key, str) or not level_key
                    or type(item_id) is not int or not 0 < item_id < 2**64
                    or not isinstance(ability_key, str) or type(level) is not int or level < 1
                    or type(required) is not int or not 1 <= required <= 10
                    or type(cost) is not int or not 0 <= cost <= MAX_BALANCE):
                raise EconomyError("invalid_ability_catalog")
            index = (commander_key, ability_key, level)
            if (index in self.ability_required_tier
                    or level_key in self.ability_levels_by_key):
                raise EconomyError("duplicate_ability_level")
            self.ability_required_tier[index] = required
            self.ability_levels_by_key[level_key] = copy.deepcopy(row)
            self.ability_levels_by_identity[index] = copy.deepcopy(row)
            # The shipped tree has one base command ability at commander
            # Tiers I, III and V. Modifier nodes encode their tree position as
            # ``_<tier>-<column>_``; base abilities do not. These three rows
            # are the actual battle abilities, while the intervening tree
            # nodes only modify them. They must be present before a Tier-V
            # commander enters battle or the unit HUD exposes only the Tier-I
            # ability.
            if (level == 1 and required in (1, 3, 5)
                    and re.search(r"_\d+-\d+_", ability_key) is None):
                if required in mandatory_candidates[commander_key]:
                    raise EconomyError("duplicate_base_commander_ability")
                mandatory_candidates[commander_key][required] = (ability_key, level)

        self.mandatory_abilities: dict[str, tuple[tuple[int, str, int], ...]] = {}
        for commander_key, by_tier in mandatory_candidates.items():
            if set(by_tier) != {1, 3, 5}:
                raise EconomyError("missing_base_commander_ability")
            self.mandatory_abilities[commander_key] = tuple(
                (tier, *by_tier[tier]) for tier in (1, 3, 5)
            )

        self.ability_predecessors = ability_predecessors_by_commander(
            talents, native,
        )
        expected_ability_nodes = {
            (commander_key, ability_key)
            for commander_key, ability_key, _level
            in self.ability_levels_by_identity
        }
        if set(self.ability_predecessors) != expected_ability_nodes:
            raise EconomyError("invalid_ability_tree")
        for commander_key, mandatory in self.mandatory_abilities.items():
            roots = {
                ability_key
                for (owner, ability_key), parents
                in self.ability_predecessors.items()
                if owner == commander_key and not parents
            }
            if roots != {ability_key for _tier, ability_key, _level in mandatory}:
                raise EconomyError("invalid_ability_tree_roots")

        occupied: set[int] = set()
        for kind in ("commanders", "units", "abilities", "ability_levels", "commander_tiers"):
            for row in native.get(kind, []):
                if isinstance(row, dict) and type(row.get("item_id")) is int:
                    occupied.add(row["item_id"])
        for row in unit_rows:
            if type(row.get("strength_item_id")) is int:
                occupied.add(row["strength_item_id"])
        occupied.update(row["item_id"] for row in self.talent_rows.values())
        self.slot_instances: dict[tuple[str, int], int] = {}
        for commander_key in sorted(self.commanders):
            for slot in range(3):
                value = int.from_bytes(hashlib.sha256(
                    f"revival:starter:{commander_key}:{slot}".encode("utf-8")).digest()[:8], "little")
                while value == 0 or value in occupied:
                    value = (value + 1) % 2**64
                occupied.add(value)
                self.slot_instances[(commander_key, slot)] = value

    def _paths_from(self, start: str) -> dict[str, tuple[str, ...]]:
        paths = {start: (start,)}
        queue: deque[str] = deque([start])
        while queue:
            parent = queue.popleft()
            for child in self.children.get(parent, []):
                if child in paths or self.units[child].get("is_premium") is True:
                    continue
                paths[child] = paths[parent] + (child,)
                queue.append(child)
        return paths

    @staticmethod
    def _equipment_slot_key(row: dict) -> str:
        return f"{row['scope']}:{row['slot']}"

    @staticmethod
    def _is_initial_equipment(row: dict) -> bool:
        """Identify the one legacy base path used to choose default gear.

        Ownership no longer depends on this predicate: every equipment row is
        granted by ``_initialize_equipment_unlocks``.  Keeping the historical
        Tier-V boundary here prevents multiple higher-tree branches from being
        mistaken for one default selection.
        """
        return (row["source_tier"] < LEGACY_FREE_EQUIPMENT_TIER
                or (row["raw_cost_0"] == 0 and row["raw_cost_1"] == 0))

    # ---- price and reward policy ------------------------------------------

    def unit_offer(self, unit_key: str) -> dict:
        unit = self.units.get(unit_key)
        if unit is None:
            raise EconomyError("unknown_unit")
        metadata = unit.get("metadata")
        if not isinstance(metadata, dict):
            raise EconomyError("invalid_unit_price")
        premium = unit.get("is_premium") is True
        currency = "gold_cents" if premium else "unit_xp_cents"
        source = unit.get("price_source")
        if premium:
            cost = PREMIUM_UNIT_GOLD_COST
        elif source == "legacy_metadata":
            cost = metadata.get(currency)
        else:
            cost = UNIT_COST_BY_TIER.get(unit.get("tier"))
        _plain_int(cost)
        return {
            "kind": "unit",
            "id": f"purchase_{unit['faction']}_{unit['unit_key']}_{currency}",
            "unit_key": unit_key,
            "item_id": unit["item_id"],
            "faction": unit["faction"],
            "tier": unit["tier"],
            "is_premium": premium,
            "currency": currency,
            "cost": cost,
            "silver_cost": 0,
            "price_source": source,
            "price_version": PRICE_VERSION,
        }

    def equipment_offer(self, equipment_db_key: str, currency: str) -> dict:
        row = self.equipment_by_db_key.get(equipment_db_key)
        if row is None:
            raise EconomyError("unknown_equipment")
        if self._is_initial_equipment(row):
            raise EconomyError("equipment_is_initially_unlocked")
        if currency not in {"unit_xp_cents", "free_xp_cents"}:
            raise EconomyError("invalid_purchase_currency")
        cost = EQUIPMENT_RESEARCH_COST_BY_TIER.get(row["source_tier"])
        if cost is None:
            raise EconomyError("invalid_equipment_tier")
        return {
            "kind": "equipment_unlock",
            "id": f"purchase_{equipment_db_key}_{currency}",
            "equipment_db_key": equipment_db_key,
            "equipment_key": row["equipment_key"],
            "unit_key": row["source_unit"],
            "item_id": row["item_id"],
            "tier": row["source_tier"],
            "currency": currency,
            "cost": cost,
            "silver_cost": 0,
            "price_version": PRICE_VERSION,
        }

    def ability_offer(self, level_key: str) -> dict:
        """Return one native ``unlock_ability`` commander-tree offer.

        The native executor applies no rank-based currency rule. Every manual
        rank spends the PO-defined one point from this commander's type-21
        pool; its three base rank-one abilities are granted at ownership.
        """
        row = self.ability_levels_by_key.get(level_key)
        if row is None:
            raise EconomyError("unknown_ability_level")
        metadata = row["metadata"]
        commander_key = row["commander"]
        level = metadata["ability_level"]
        currency = "commander_talent_points"
        return {
            "kind": "ability",
            "id": f"unlock_ability_{metadata['ability_key']}_{level}",
            "level_key": level_key,
            "commander_key": commander_key,
            "ability_key": metadata["ability_key"],
            "ability_level": level,
            "required_tier": metadata[commander_key],
            "item_id": row["item_id"],
            "currency": currency,
            "currency_item_id": self.talent_rows[commander_key]["item_id"],
            "cost": 1,
            "price_version": PRICE_VERSION,
        }

    def ability_refund_offer(self, level_key: str) -> dict:
        """Return the exact native refund option for one owned rank."""
        unlock = self.ability_offer(level_key)
        return {
            **unlock,
            "kind": "ability_refund",
            "id": (
                f"refund_ability_{unlock['ability_key']}_"
                f"{unlock['ability_level']}"
            ),
            "currency": "ability_level",
            "currency_item_id": unlock["item_id"],
            "receiving_item_id": self.talent_rows[
                unlock["commander_key"]
            ]["item_id"],
        }

    def commander_offers(self, commander_key: str) -> list[dict]:
        commander = self.commanders.get(commander_key)
        if commander is None:
            raise EconomyError("unknown_commander")
        metadata = commander.get("metadata")
        if not isinstance(metadata, dict):
            raise EconomyError("invalid_commander_price")
        gold = _plain_int(metadata.get("gold_cents"))
        extracted = _plain_int(metadata.get("silver_cents"))
        source = commander.get("price_source")
        # Legacy purchase-option names prove that the larger metadata value is
        # spent as free XP.  The current DB's value 100 is a local sentinel;
        # preserve the legacy 30:1 free-XP/gold ratio for revival-v1.
        free_xp = extracted if source == "legacy_metadata" else (0 if gold == 0 else gold * 30)
        _plain_int(free_xp)
        result = [{
            "kind": "commander",
            "id": f"purchase_{commander_key}_free_xp_cents",
            "commander_key": commander_key,
            "item_id": commander["item_id"],
            "faction": commander["faction"],
            "currency": "free_xp_cents",
            "cost": free_xp,
            "price_source": source,
            "price_version": PRICE_VERSION,
        }]
        if gold > 0:
            result.append({**result[0], "id": f"purchase_{commander_key}_gold_cents",
                           "currency": "gold_cents", "cost": gold})
        return result

    @staticmethod
    def commander_xp_threshold(tier: int) -> int:
        if type(tier) is not int or not 1 <= tier <= 10:
            raise EconomyError("invalid_commander_tier")
        return sum(UNIT_COST_BY_TIER[value] for value in range(2, tier + 1))

    @classmethod
    def commander_tier_for_xp(cls, xp: int) -> int:
        _plain_int(xp)
        tier = 1
        for candidate in range(2, 11):
            if xp < cls.commander_xp_threshold(candidate):
                break
            tier = candidate
        return tier

    def commander_tier_offer(self, commander_key: str, tier: int) -> dict:
        """Return the native cumulative commander-XP option for one Tier."""
        if commander_key not in self.commanders:
            raise EconomyError("unknown_commander")
        if type(tier) is not int or not 2 <= tier <= 10:
            raise EconomyError("invalid_commander_tier")
        row = self.commander_tiers[(commander_key, tier)]
        return {
            "kind": "commander_tier",
            "id": f"tier_{tier}_{commander_key}_cxp",
            "commander_key": commander_key,
            "tier": tier,
            "item_id": row["item_id"],
            "currency": "commander_xp_cents",
            # The native UI subtracts the commander's existing XP from this
            # cumulative threshold and offers to cover the remainder with
            # account Free XP.
            "cost": self.commander_xp_threshold(tier),
            "price_version": PRICE_VERSION,
        }

    @staticmethod
    def reward_quote(
        battle_tier: int,
        outcome: str,
        verified: bool = True,
        *,
        reward_policy: str = "pve",
    ) -> dict:
        if type(battle_tier) is not int or not 1 <= battle_tier <= 10:
            raise EconomyError("invalid_battle_tier")
        if outcome not in OUTCOMES:
            raise EconomyError("invalid_battle_outcome")
        if type(verified) is not bool:
            raise EconomyError("invalid_battle_verification")
        multiplier = REWARD_POLICIES.get(reward_policy)
        if multiplier is None:
            raise EconomyError("invalid_reward_policy")
        next_cost = UNIT_COST_BY_TIER[min(battle_tier + 1, 10)]
        base = ((next_cost + 3) // 4 + 9_999) // 10_000 * 10_000
        percent = OUTCOME_PERCENT[outcome] if verified else 0

        def scaled(value: int) -> int:
            pve_value = value * percent // 100
            return pve_value * multiplier[0] // multiplier[1]

        return {
            "unit_xp_cents": scaled(base),
            "commander_xp_cents": scaled(base),
            "free_xp_cents": scaled(max(100_000, base // 4)),
            "silver_cents": scaled(50_000 * battle_tier),
            "reward_version": REWARD_VERSION,
        }

    # ---- initial state and migration --------------------------------------

    def _base_state(self, active_commander: str) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "saved": self._next_saved(0),
            "price_version": PRICE_VERSION,
            "reward_version": REWARD_VERSION,
            "active_commander": active_commander,
            "wallet": {key: 0 for key in WALLET_CURRENCIES},
            "commanders": {},
            "units": {},
            "equipment": {},
            "unlocked_equipment": [],
            "consumables": {},
            "unit_abilities": {},
            "removed_legacy_premium_units": [],
            "daily": {},
            "operations": {},
            "battles": {},
        }

    def _new_commander_state(self, commander_key: str, tier: int = INITIAL_TIER) -> dict:
        return {
            "tier": tier,
            "commander_xp_cents": self.commander_xp_threshold(tier),
            "abilities": self._with_mandatory_abilities(commander_key, tier, {}),
            "talent_points": self._talent_total(commander_key, tier),
            "equipped_units": self._default_loadout(commander_key, tier),
        }

    def _with_mandatory_abilities(
        self,
        commander_key: str,
        tier: int,
        selected: dict,
    ) -> dict:
        """Add unlocked base abilities without replacing a user's choices."""
        result = copy.deepcopy(selected)
        for required_tier, ability_key, level in self.mandatory_abilities[commander_key]:
            if required_tier <= tier:
                result.setdefault(ability_key, level)
        return result

    def _talent_points_spent(self, commander_key: str, abilities: dict) -> int:
        """Count manual ranks; the three granted active rank-ones are free."""
        granted = {
            ability_key for _tier, ability_key, _level
            in self.mandatory_abilities[commander_key]
        }
        return sum(
            max(level - 1, 0) if ability_key in granted else level
            for ability_key, level in abilities.items()
        )

    def _talent_total(self, commander_key: str, tier: int) -> int:
        if type(tier) is not int or not 1 <= tier <= 10:
            raise EconomyError("invalid_commander_tier")
        try:
            return self.talent_rows[commander_key]["cumulative_points"][tier - 1]
        except (KeyError, IndexError, TypeError) as exc:
            raise EconomyError("invalid_commander_talent_pool") from exc

    def _orphaned_ability_nodes(
        self, commander_key: str, abilities: dict,
    ) -> list[str]:
        """Return selected manual nodes with no owned incoming source node."""
        result = []
        for ability_key, level in abilities.items():
            parents = self.ability_predecessors.get((commander_key, ability_key))
            if (type(level) is int and level >= 1 and parents
                    and not any(type(abilities.get(parent)) is int
                                and abilities[parent] >= 1
                                for parent in parents)):
                result.append(ability_key)
        return sorted(result)

    def _grant_starters(self, state: dict, commander_key: str) -> None:
        for unit_key in self.commanders[commander_key]["starting_units"]:
            state["units"].setdefault(unit_key, {"unit_xp_cents": 0})

    def _fresh_state(self, active_commander: str) -> dict:
        state = self._base_state(active_commander)
        for commander_key in sorted(self.commanders):
            state["commanders"][commander_key] = self._new_commander_state(commander_key)
        self._grant_initial_units(state)
        self._initialize_loadout_selections(state)
        if active_commander not in state["commanders"]:
            raise EconomyError("active_commander_not_owned")
        return state

    def _migrate_v1(self, legacy: dict, active_commander: str) -> dict:
        if (set(legacy) != {"schema_version", "commanders"}
                or type(legacy.get("schema_version")) is not int or legacy.get("schema_version") != 1):
            raise EconomyError("invalid_legacy_schema")
        configured = legacy.get("commanders")
        if not isinstance(configured, dict) or any(key not in self.commanders for key in configured):
            raise EconomyError("invalid_legacy_commander")
        # v1's native profile implicitly owned all live commanders.  Preserve
        # that entitlement so upgrading the state never revokes user access.
        state = self._base_state(active_commander)
        for commander_key in sorted(self.commanders):
            value = configured.get(commander_key)
            if value is None:
                legacy_tier, abilities, explicit, extra = 1, {}, None, []
            else:
                required = {"tier", "abilities"}
                allowed = required | {"equipped_units", "unlocked_units"}
                if not isinstance(value, dict) or not required <= set(value) or not set(value) <= allowed:
                    raise EconomyError("invalid_legacy_progression")
                legacy_tier, abilities = value["tier"], value["abilities"]
                explicit, extra = value.get("equipped_units"), value.get("unlocked_units", [])
            if (type(legacy_tier) is not int or not 1 <= legacy_tier <= 10
                    or not isinstance(abilities, dict)):
                raise EconomyError("invalid_legacy_progression")
            tier = max(legacy_tier, INITIAL_TIER)
            if explicit is None:
                equipped = self._default_loadout(commander_key, tier)
            elif (not isinstance(explicit, list) or len(explicit) != 3
                  or any(not isinstance(key, str) for key in explicit)):
                raise EconomyError("invalid_legacy_loadout")
            else:
                equipped = (self._default_loadout(commander_key, tier)
                            if legacy_tier < INITIAL_TIER else list(explicit))
            if (not isinstance(extra, list) or len(extra) > len(self.units)
                    or any(not isinstance(key, str) for key in extra) or len(extra) != len(set(extra))):
                raise EconomyError("invalid_legacy_units")
            state["commanders"][commander_key] = {
                "tier": tier,
                "commander_xp_cents": self.commander_xp_threshold(tier),
                "abilities": self._with_mandatory_abilities(
                    commander_key, tier, abilities),
                "talent_points": 0,
                "equipped_units": equipped,
            }
            # Explicit v1 entitlements are checked against the old Tier before
            # the one-way Tier 5 grant.  Only a generated default loadout is
            # authorized at the upgraded Tier.
            if explicit is None:
                unlocked = self._legacy_unlock_closure(
                    commander_key, tier, equipped, [])
                unlocked.update(self._legacy_unlock_closure(
                    commander_key, legacy_tier, [], extra))
            else:
                unlocked = self._legacy_unlock_closure(
                    commander_key, legacy_tier, list(explicit), extra)
            for unit_key in unlocked:
                state["units"].setdefault(unit_key, {"unit_xp_cents": 0})
        self._grant_initial_units(state)
        self._prune_orphaned_ability_subtrees(state)
        self._initialize_talent_points(state)
        self._initialize_loadout_selections(state)
        self._initialize_battle_reward_policies(state)
        if active_commander not in state["commanders"]:
            raise EconomyError("active_commander_not_owned")
        return state

    def _migrate_v2(self, previous: dict) -> dict:
        self._validate_state(previous, expected_schema=TIER_FIVE_GRANT_SCHEMA_VERSION,
                             require_initial_grants=False,
                             require_mandatory_abilities=False)
        state = copy.deepcopy(previous)
        state["schema_version"] = SCHEMA_VERSION
        minimum_xp = self.commander_xp_threshold(INITIAL_TIER)
        for commander_key in sorted(self.commanders):
            commander_state = state["commanders"].get(commander_key)
            if commander_state is None:
                state["commanders"][commander_key] = self._new_commander_state(commander_key)
                continue
            was_below_initial = commander_state["commander_xp_cents"] < minimum_xp
            if was_below_initial:
                commander_state["equipped_units"] = self._default_loadout(commander_key, INITIAL_TIER)
            commander_state["commander_xp_cents"] = max(
                commander_state["commander_xp_cents"], minimum_xp)
            commander_state["tier"] = self.commander_tier_for_xp(
                commander_state["commander_xp_cents"])
            commander_state["abilities"] = self._with_mandatory_abilities(
                commander_key, commander_state["tier"], commander_state["abilities"])
        self._grant_initial_units(state)
        self._prune_orphaned_ability_subtrees(state)
        self._initialize_talent_points(state)
        self._initialize_loadout_selections(state)
        self._initialize_battle_reward_policies(state)
        state["saved"] = self._next_saved(state["saved"])
        return state

    def _migrate_v3(self, previous: dict) -> dict:
        """Add the missing Tier-I/III/V battle abilities exactly once.

        Schema 3 already owns all commanders at at least Tier V. Add absent
        base ability keys, then preserve only modifier nodes reachable through
        native ability-tree links.
        """
        self._validate_state(previous, expected_schema=MANDATORY_ABILITIES_SCHEMA_VERSION,
                             require_mandatory_abilities=False)
        state = copy.deepcopy(previous)
        for commander_key, commander_state in state["commanders"].items():
            commander_state["abilities"] = self._with_mandatory_abilities(
                commander_key, commander_state["tier"], commander_state["abilities"])
        self._prune_orphaned_ability_subtrees(state)
        self._initialize_talent_points(state)
        self._initialize_loadout_selections(state)
        self._initialize_battle_reward_policies(state)
        state["saved"] = self._next_saved(state["saved"])
        return state

    def _migrate_v4(self, previous: dict) -> dict:
        """Persist the equipment and consumables that schema 4 implied."""
        self._validate_state(previous, expected_schema=PREVIOUS_SCHEMA_VERSION)
        state = copy.deepcopy(previous)
        self._prune_orphaned_ability_subtrees(state)
        self._initialize_talent_points(state)
        self._initialize_loadout_selections(state)
        self._initialize_battle_reward_policies(state)
        state["saved"] = self._next_saved(state["saved"])
        return state

    def _promote_legacy_consumable_selections(self, state: dict) -> None:
        """Translate persisted Tier-I-through-IX selections to Tier X.

        Persisted loadouts first appeared in schema 5, so every later legacy
        schema can contain a valid selection that the current Tier-X-only
        validator would otherwise reject before its schema migration runs.
        Frozen battle hashes and retry receipts are part of the same snapshot
        and must move with the selected definitions.
        """
        definitions = {
            row["db_key"]: row for row in self.native_consumables["definitions"]
        }

        def promote(unit_key: str, selections: object) -> None:
            if not isinstance(selections, dict):
                raise EconomyError("invalid_consumable_selections")
            allowed = self.consumable_keys_by_unit.get(unit_key, set())
            for slot, old_key in list(selections.items()):
                if not isinstance(old_key, str) or old_key not in definitions:
                    raise EconomyError("invalid_consumable_selection")
                family, separator, tier_text = old_key.rpartition("_")
                promoted = f"{family}_{EFFECTIVE_UNIT_TIER}"
                if (not separator or not tier_text.isdigit()
                        or promoted not in allowed):
                    raise EconomyError("invalid_consumable_selection")
                selections[slot] = promoted

        consumables = state.get("consumables")
        if not isinstance(consumables, dict):
            raise EconomyError("invalid_consumable_selections")
        for commander_key, deployed in consumables.items():
            commander = state.get("commanders", {}).get(commander_key)
            if not isinstance(commander, dict) or not isinstance(deployed, list):
                raise EconomyError("invalid_consumable_selections")
            for unit_key, selections in zip(
                commander.get("equipped_units", []), deployed,
            ):
                promote(unit_key, selections)

        battles = state.get("battles")
        if not isinstance(battles, dict):
            raise EconomyError("invalid_battles")
        for match_id, battle in battles.items():
            if not isinstance(battle, dict):
                raise EconomyError("invalid_battle")
            unit_keys = battle.get("units")
            unit_loadouts = battle.get("unit_loadouts")
            if (not isinstance(unit_keys, list)
                    or not isinstance(unit_loadouts, list)
                    or len(unit_keys) != 3 or len(unit_loadouts) != 3):
                raise EconomyError("invalid_battle_loadouts")
            for unit_key, loadout in zip(unit_keys, unit_loadouts):
                if not isinstance(loadout, dict):
                    raise EconomyError("invalid_battle_loadouts")
                promote(unit_key, loadout.get("consumables"))
            old_hash = battle.get("roster_hash")
            if not isinstance(old_hash, str):
                raise EconomyError("invalid_battle_roster")
            battle["roster_hash"] = self._roster_hash(
                battle.get("commander"), unit_keys,
                battle.get("battle_tier"), unit_loadouts,
            )
            self._migrate_battle_operation_receipts(
                state, match_id, battle, old_hash,
            )

    def _migrate_v5(self, previous: dict) -> dict:
        """Add persisted type-21 balances to the schema-5 loadout state."""
        state = copy.deepcopy(previous)
        self._promote_legacy_consumable_selections(state)
        self._validate_state(
            state, expected_schema=LOADOUT_SELECTIONS_SCHEMA_VERSION,
        )
        self._prune_orphaned_ability_subtrees(state)
        self._initialize_talent_points(state)
        self._initialize_battle_reward_policies(state)
        state["schema_version"] = SCHEMA_VERSION
        state["saved"] = self._next_saved(state["saved"])
        return state

    def _migrate_v6(self, previous: dict) -> dict:
        """Remove any legacy orphan subtree before enforcing native links."""
        state = copy.deepcopy(previous)
        self._promote_legacy_consumable_selections(state)
        self._validate_state(
            state, expected_schema=TALENT_POINTS_SCHEMA_VERSION,
        )
        self._prune_orphaned_ability_subtrees(state)
        self._initialize_talent_points(state)
        self._initialize_battle_reward_policies(state)
        state["schema_version"] = SCHEMA_VERSION
        state["saved"] = self._next_saved(state["saved"])
        return state

    def _migrate_v7(self, previous: dict) -> dict:
        """Freeze the public reward policy for every existing PvE battle."""
        state = copy.deepcopy(previous)
        self._promote_legacy_consumable_selections(state)
        self._validate_state(
            state, expected_schema=ABILITY_TREE_SCHEMA_VERSION,
        )
        self._initialize_battle_reward_policies(state)
        # The policy is server-only battle metadata and is not projected into
        # the native profile, so migration must not manufacture a stale-client
        # warning by advancing the profile watermark.
        return state

    def _migrate_v8(self, previous: dict) -> dict:
        """Add explicit equipment research and daily quest state."""
        state = copy.deepcopy(previous)
        self._promote_legacy_consumable_selections(state)
        self._validate_state(
            state, expected_schema=REWARD_POLICY_SCHEMA_VERSION,
        )
        state["schema_version"] = SCHEMA_VERSION
        state["saved"] = self._next_saved(state["saved"])
        return state

    def _migrate_v9(self, previous: dict) -> dict:
        """Move the former Tier-V/research economy to the full-unlock policy."""
        state = copy.deepcopy(previous)
        self._promote_legacy_consumable_selections(state)
        self._validate_state(
            state, expected_schema=FULL_UNLOCK_SCHEMA_VERSION,
            require_initial_grants=False,
        )
        state["schema_version"] = SCHEMA_VERSION
        state["saved"] = self._next_saved(state["saved"])
        return state

    def _migrate_v10(self, previous: dict) -> dict:
        """Add persisted type-19 selections to the Tier-X state."""
        state = copy.deepcopy(previous)
        try:
            self._validate_state(
                state, expected_schema=TIER_X_SANDBOX_SCHEMA_VERSION,
            )
        except EconomyError as error:
            if error.code != "invalid_battle_roster":
                raise
            # Early schema-10 builds granted the Tier-X sandbox but left
            # already-frozen battles under schema 9's native-unit-tier hash
            # contract.  Accept only a state that is otherwise completely
            # valid *and* whose every frozen roster satisfies that exact old
            # contract, then migrate the tier, hash, and durable retry receipt
            # together.  A mixed or corrupt roster therefore still fails
            # closed instead of being repaired speculatively.
            self._validate_state(
                state,
                expected_schema=TIER_X_SANDBOX_SCHEMA_VERSION,
                legacy_native_battle_tiers=True,
            )
            self._normalize_effective_battle_tiers(state)
            self._validate_state(
                state, expected_schema=TIER_X_SANDBOX_SCHEMA_VERSION,
            )
        state["schema_version"] = SCHEMA_VERSION
        state["saved"] = self._next_saved(state["saved"])
        return state

    def _migrate_v11(self, previous: dict) -> dict:
        """Prepare schema 11 for receipt-authoritative premium ownership.

        Schema 11 automatically granted every premium unit in the copied
        sandbox data.  Schema 12 keeps only premiums backed by an exact durable
        Gold-purchase receipt; the initializer records and removes the rest.
        """
        self._validate_state(
            previous, expected_schema=UNIT_ABILITIES_SCHEMA_VERSION,
        )
        state = copy.deepcopy(previous)
        state["schema_version"] = SCHEMA_VERSION
        state["saved"] = self._next_saved(state["saved"])
        return state

    def _normalize_effective_battle_tiers(self, state: dict) -> None:
        """Move valid frozen battles and retry receipts to Tier-X semantics."""
        for match_id, battle in state.get("battles", {}).items():
            if not isinstance(battle, dict):
                continue
            unit_keys = battle.get("units")
            unit_loadouts = battle.get("unit_loadouts")
            if (not isinstance(unit_keys, list) or len(unit_keys) != 3
                    or any(key not in self.units for key in unit_keys)
                    or not isinstance(unit_loadouts, list)):
                continue
            old_hash = battle.get("roster_hash")
            battle_tier = max(
                self.units[key]["effective_tier"] for key in unit_keys
            )
            battle["battle_tier"] = battle_tier
            battle["roster_hash"] = self._roster_hash(
                battle.get("commander"), unit_keys, battle_tier, unit_loadouts,
            )
            if isinstance(old_hash, str):
                self._migrate_battle_operation_receipts(
                    state, match_id, battle, old_hash,
                    effective_tier=True,
                )

    def _initialize_full_unlock(self, state: dict) -> bool:
        """Grant all normal live units without replacing user loadouts."""
        before = copy.deepcopy(state)
        state["schema_version"] = SCHEMA_VERSION

        for commander_key in sorted(self.commanders):
            commander_state = state["commanders"].get(commander_key)
            if commander_state is None:
                state["commanders"][commander_key] = self._new_commander_state(
                    commander_key, INITIAL_TIER,
                )
                continue
            commander_state["tier"] = INITIAL_TIER
            # Raising an older commander to Tier X needs the cumulative floor,
            # but loading an already-current account must not erase XP earned
            # after reaching the cap.
            commander_state["commander_xp_cents"] = max(
                _plain_int(commander_state.get("commander_xp_cents")),
                self.commander_xp_threshold(INITIAL_TIER),
            )
            commander_state["abilities"] = self._with_mandatory_abilities(
                commander_key, INITIAL_TIER, commander_state["abilities"],
            )
            if "talent_points" in commander_state:
                spent = self._talent_points_spent(
                    commander_key, commander_state["abilities"],
                )
                commander_state["talent_points"] = (
                    self._talent_total_with_local_grants(
                        state, commander_key, INITIAL_TIER,
                    ) - spent
                )

        for unit_key in sorted(
            key for key, unit in self.units.items()
            if unit.get("is_premium") is not True
        ):
            state["units"].setdefault(unit_key, {"unit_xp_cents": 0})

        if "equipment" in state:
            state["equipment"] = {
                unit_key: copy.deepcopy(
                    state["equipment"].get(
                        unit_key, self._default_equipment_for_unit(unit_key),
                    )
                )
                for unit_key in sorted(state["units"])
            }
        if "consumables" in state:
            for commander_key, commander_state in state["commanders"].items():
                deployed = state["consumables"].get(commander_key)
                if not isinstance(deployed, list) or len(deployed) != 3:
                    deployed = [{}, {}, {}]
                state["consumables"][commander_key] = [
                    copy.deepcopy(selected) if isinstance(selected, dict) else {}
                    for selected in deployed
                ]

        # Schema 10 changes only the battle-facing tier semantics. Preserve
        # unit IDs and native tree tiers, but migrate frozen roster hashes so a
        # pending/settled schema-9 battle remains internally consistent.
        self._normalize_effective_battle_tiers(state)

        state["unlocked_equipment"] = sorted(
            row["db_key"] for row in self.equipment_by_db_key.values()
            if row["source_unit"] in state["units"]
        )
        changed = state != before
        if changed and before.get("schema_version") == SCHEMA_VERSION:
            state["saved"] = self._next_saved(state["saved"])
        return changed

    def _proven_purchased_premium_units(self, state: dict) -> set[str]:
        """Return premiums backed by an exact durable Gold-purchase receipt."""
        proven: set[str] = set()
        operations = state.get("operations")
        if not isinstance(operations, dict):
            return proven
        for operation_id, entry in operations.items():
            receipt = entry.get("receipt") if isinstance(entry, dict) else None
            if not isinstance(receipt, dict) or receipt.get("kind") != "purchase_unit":
                continue
            unit_key = receipt.get("unit")
            unit = self.units.get(unit_key)
            commander_key = receipt.get("commander")
            if (unit is None or unit.get("is_premium") is not True
                    or commander_key not in self.commanders
                    or unit_key not in self.reachable.get(commander_key, set())
                    or unit.get("faction")
                    != self.commanders[commander_key].get("faction")):
                continue
            offer = self.unit_offer(unit_key)
            spent = receipt.get("spent")
            expected_request = {
                "offer_id": offer["id"],
                "commander": commander_key,
                "unit": unit_key,
                "parent_unit": None,
            }
            expected_hash = _canonical_hash({
                "kind": "purchase_unit", "request": expected_request,
            })
            expected_receipt_fields = {
                "operation_id", "kind", "saved", "offer_id", "commander",
                "unit", "tier", "spent", "silver_cost", "price_version",
            }
            if (set(receipt) != expected_receipt_fields
                    or type(receipt.get("saved")) is not int
                    or not 1 <= receipt["saved"] <= state.get("saved", 0)
                    or entry.get("request_hash") != expected_hash
                    or receipt.get("operation_id") != operation_id
                    or receipt.get("offer_id") != offer["id"]
                    or receipt.get("tier") != unit["tier"]
                    or receipt.get("silver_cost") != 0
                    or receipt.get("price_version") != PRICE_VERSION
                    or not isinstance(spent, dict)
                    or set(spent) != {"currency", "scope", "amount", "balance"}
                    or spent.get("currency") != "gold_cents"
                    or spent.get("scope") != "account"
                    or spent.get("amount") != PREMIUM_UNIT_GOLD_COST
                    or type(spent.get("balance")) is not int
                    or not 0 <= spent["balance"] <= MAX_BALANCE):
                continue
            proven.add(unit_key)
        return proven

    def _initialize_premium_entitlements(self, state: dict) -> bool:
        """Remove legacy auto-grants and keep only receipt-proven premiums.

        ``removed_legacy_premium_units`` is an audit trail, never an ownership
        source.  A settled battle may retain an unproven premium only inside
        its immutable historical roster.  A pending battle still needs live
        unit state for settlement, so that conflict fails closed instead of
        resurrecting ownership or rewriting the frozen battle.  Equipped
        unproven premiums are replaced by the deterministic normal Tier-X
        default for the same commander slot.
        """
        before = copy.deepcopy(state)
        existing = state.get("removed_legacy_premium_units", [])
        if not isinstance(existing, list):
            return False
        owned_premium = {
            key for key in state.get("units", {})
            if self.units.get(key, {}).get("is_premium") is True
        }
        removed = owned_premium - (
            self._proven_purchased_premium_units(state)
            | self._proven_local_premium_grants(state)
            | self._proven_sandbox_premium_grants(state)
        )

        if any(
            removed & set(battle.get("units", []))
            for battle in state.get("battles", {}).values()
            if isinstance(battle, dict)
            and isinstance(battle.get("units"), list)
            and battle.get("status") != "settled"
        ):
            raise EconomyError("unproven_premium_battle_conflict")

        for commander_key, commander_state in state.get("commanders", {}).items():
            equipped = commander_state.get("equipped_units")
            if not isinstance(equipped, list) or len(equipped) != 3:
                continue
            defaults = self._default_loadout(
                commander_key, commander_state.get("tier", INITIAL_TIER),
            )
            deployed_consumables = state.get("consumables", {}).get(commander_key)
            for slot, unit_key in enumerate(equipped):
                if unit_key not in removed:
                    continue
                replacement = defaults[slot]
                equipped[slot] = replacement
                if (isinstance(deployed_consumables, list)
                        and len(deployed_consumables) == 3):
                    deployed_consumables[slot] = (
                        self._default_consumables_for_unit(replacement)
                    )

        for unit_key in removed:
            state["units"].pop(unit_key, None)
            state.get("equipment", {}).pop(unit_key, None)
            state.get("unit_abilities", {}).pop(unit_key, None)
        if isinstance(state.get("unlocked_equipment"), list):
            state["unlocked_equipment"] = [
                key for key in state["unlocked_equipment"]
                if self.equipment_by_db_key.get(key, {}).get("source_unit")
                not in removed
            ]
        state["removed_legacy_premium_units"] = sorted(set(existing) | removed)
        return state != before

    def _proven_local_premium_grants(self, state: dict) -> set[str]:
        """Validate explicit local-operator grants, never paid-shop receipts.

        Schema 12's operation journal already stores typed receipts, so this
        opt-in operation needs no global state migration or default grant.
        This LocalEconomy validator rejects local testing grants when using
        a non-file backend. This is not a Worker-side ownership guarantee:
        the remote profile API stores opaque blobs, while the separate cloud
        roster authority still needs its own entitlement integration.
        """
        proven: set[str] = set()
        for operation_id, entry in state.get("operations", {}).items():
            receipt = entry.get("receipt") if isinstance(entry, dict) else None
            if not isinstance(receipt, dict) or receipt.get("kind") != "grant_local_premium_units":
                continue
            if self._backend is not None and not isinstance(self._backend, FileEconomyBackend):
                raise EconomyError("local_premium_grant_requires_local_backend")
            keys = receipt.get("units")
            reason = receipt.get("reason")
            if (set(receipt) != {"operation_id", "kind", "saved", "units", "reason", "source"}
                    or receipt.get("operation_id") != operation_id
                    or receipt.get("source") != "local_operator"
                    or type(receipt.get("saved")) is not int
                    or not 1 <= receipt["saved"] <= state.get("saved", 0)
                    or not isinstance(keys, list) or not keys
                    or any(not isinstance(key, str) or key not in self.units
                           or self.units[key].get("is_premium") is not True for key in keys)
                    or keys != sorted(set(keys))
                    or not isinstance(reason, str) or not 1 <= len(reason) <= 64
                    or any(ord(char) < 32 for char in reason)):
                raise EconomyError("invalid_local_premium_grant")
            request = {"units": keys, "reason": reason, "source": "local_operator"}
            if entry.get("request_hash") != _canonical_hash({
                "kind": "grant_local_premium_units", "request": request,
            }):
                raise EconomyError("invalid_local_premium_grant")
            proven.update(keys)
        return proven

    def _proven_sandbox_premium_grants(self, state: dict) -> set[str]:
        """Validate an explicit all-premium sandbox grant in the operation journal."""
        proven: set[str] = set()
        for operation_id, entry in state.get("operations", {}).items():
            receipt = entry.get("receipt") if isinstance(entry, dict) else None
            if not isinstance(receipt, dict) or receipt.get("kind") != "grant_sandbox_premium_units":
                continue
            keys = receipt.get("units")
            reason = receipt.get("reason")
            if (set(receipt) != {"operation_id", "kind", "saved", "units", "reason", "source"}
                    or receipt.get("operation_id") != operation_id
                    or receipt.get("source") != "sandbox_catalog"
                    or type(receipt.get("saved")) is not int
                    or not 1 <= receipt["saved"] <= state.get("saved", 0)
                    or not isinstance(keys, list) or not keys
                    or any(not isinstance(key, str) or key not in self.units
                           or self.units[key].get("is_premium") is not True for key in keys)
                    or keys != sorted(key for key, unit in self.units.items()
                                      if unit.get("is_premium") is True)
                    or not isinstance(reason, str) or not 1 <= len(reason) <= 64
                    or any(ord(char) < 32 for char in reason)):
                raise EconomyError("invalid_sandbox_premium_grant")
            request = {"units": keys, "reason": reason, "source": "sandbox_catalog"}
            if entry.get("request_hash") != _canonical_hash({
                "kind": "grant_sandbox_premium_units", "request": request,
            }):
                raise EconomyError("invalid_sandbox_premium_grant")
            proven.update(keys)
        return proven

    def _proven_local_commander_talent_point_grants(
        self, state: dict,
    ) -> dict[str, int]:
        """Return ordered, receipt-proven local talent bonuses by commander.

        The schema-12 operation journal is the authority for these explicit
        local-operator grants and resets.  A reset supersedes earlier bonuses
        for its named Tier-X commanders with the exact adjustment needed for
        a 100-point total; a later audited grant remains additive.  No
        catalogue total or global default is changed: removing or corrupting
        an exact receipt therefore makes a stored boosted balance fail
        validation rather than silently becoming a permanent entitlement.
        """
        operations = state.get("operations")
        if not isinstance(operations, dict):
            raise EconomyError("invalid_operations")
        owned = state.get("commanders")
        if not isinstance(owned, dict):
            raise EconomyError("invalid_owned_commanders")
        receipts: list[tuple[int, str, dict]] = []
        for operation_id, entry in operations.items():
            receipt = entry.get("receipt") if isinstance(entry, dict) else None
            if (not isinstance(receipt, dict)
                    or receipt.get("kind") not in {
                        "grant_local_commander_talent_points",
                        "reset_local_commander_talent_points",
                    }):
                continue
            if (self._backend is not None
                    and not isinstance(self._backend, FileEconomyBackend)):
                raise EconomyError(
                    "local_commander_talent_grant_requires_local_backend"
                )
            saved = receipt.get("saved")
            if (receipt.get("operation_id") != operation_id
                    or receipt.get("source") != "local_operator"
                    or type(saved) is not int
                    or not 1 <= saved <= state.get("saved", 0)):
                raise EconomyError("invalid_local_commander_talent_grant")
            receipts.append((saved, operation_id, receipt))

        receipts.sort(key=lambda row: (row[0], row[1]))
        if len({saved for saved, _operation_id, _receipt in receipts}) != len(receipts):
            raise EconomyError("invalid_local_commander_talent_grant")

        totals: dict[str, int] = {}
        for _saved, operation_id, receipt in receipts:
            entry = operations[operation_id]
            commanders = receipt.get("commanders")
            reason = receipt.get("reason")
            if (not isinstance(commanders, list) or not commanders
                    or any(not isinstance(key, str)
                           or key not in self.commanders or key not in owned
                           for key in commanders)
                    or commanders != sorted(set(commanders))
                    or not isinstance(reason, str)
                    or not 1 <= len(reason) <= 64
                    or any(ord(char) < 32 for char in reason)):
                raise EconomyError("invalid_local_commander_talent_grant")

            if receipt["kind"] == "grant_local_commander_talent_points":
                amount = receipt.get("amount")
                grants = receipt.get("grants")
                if (set(receipt) != {
                        "operation_id", "kind", "saved", "commanders", "amount",
                        "grants", "granted_total", "reason", "source",
                        }
                        or type(amount) is not int
                        or not 1 <= amount <= MAX_BALANCE
                        or not isinstance(grants, dict)
                        or set(grants) != set(commanders)
                        or any(type(value) is not int or value != amount
                               for value in grants.values())
                        or type(receipt.get("granted_total")) is not int
                        or receipt["granted_total"] != amount * len(commanders)
                        or receipt["granted_total"] > MAX_BALANCE):
                    raise EconomyError("invalid_local_commander_talent_grant")
                request = {
                    "commanders": commanders,
                    "amount": amount,
                    "reason": reason,
                    "source": "local_operator",
                }
                if (not isinstance(entry, dict)
                        or entry.get("request_hash") != _canonical_hash({
                            "kind": receipt["kind"], "request": request,
                        })):
                    raise EconomyError("invalid_local_commander_talent_grant")
                for commander_key in commanders:
                    totals[commander_key] = _checked_add(
                        totals.get(commander_key, 0), amount,
                    )
                continue

            target = receipt.get("target_unspent")
            previous = receipt.get("previous_bonuses")
            native_totals = receipt.get("native_totals")
            effective = receipt.get("effective_bonuses")
            mandatory = receipt.get("mandatory_abilities")
            expected_keys = set(commanders)
            if (set(receipt) != {
                    "operation_id", "kind", "saved", "commanders",
                    "target_unspent", "previous_bonuses", "native_totals",
                    "effective_bonuses", "mandatory_abilities", "reason",
                    "source",
                    }
                    or type(target) is not int
                    or target not in LOCAL_COMMANDER_TALENT_RESET_TARGETS
                    or not all(isinstance(value, dict) for value in (
                        previous, native_totals, effective, mandatory,
                    ))
                    or any(set(value) != expected_keys for value in (
                        previous, native_totals, effective, mandatory,
                    ))):
                raise EconomyError("invalid_local_commander_talent_reset")
            request = {
                "commanders": commanders,
                "target_unspent": target,
                "reason": reason,
                "source": "local_operator",
            }
            if (not isinstance(entry, dict)
                    or entry.get("request_hash") != _canonical_hash({
                        "kind": receipt["kind"], "request": request,
                    })):
                raise EconomyError("invalid_local_commander_talent_reset")
            for commander_key in commanders:
                commander = owned[commander_key]
                if (not isinstance(commander, dict)
                        or commander.get("tier") != 10
                        or type(previous.get(commander_key)) is not int
                        or previous[commander_key] != totals.get(commander_key, 0)):
                    raise EconomyError("invalid_local_commander_talent_reset")
                base = self._talent_total(commander_key, 10)
                bonus = target - base
                expected_mandatory = self._with_mandatory_abilities(
                    commander_key, 10, {},
                )
                if (bonus < 0
                        or type(native_totals.get(commander_key)) is not int
                        or native_totals.get(commander_key) != base
                        or type(effective.get(commander_key)) is not int
                        or effective.get(commander_key) != bonus
                        or not isinstance(mandatory.get(commander_key), dict)
                        or set(mandatory[commander_key])
                        != set(expected_mandatory)
                        or any(type(value) is not int for value in
                               mandatory[commander_key].values())
                        or mandatory.get(commander_key) != expected_mandatory):
                    raise EconomyError("invalid_local_commander_talent_reset")
                totals[commander_key] = bonus
        return totals

    def _talent_total_with_local_grants(
        self, state: dict, commander_key: str, tier: int,
        grants: dict[str, int] | None = None,
    ) -> int:
        """Return the native Tier total plus exact local-operator bonuses."""
        proven = (
            self._proven_local_commander_talent_point_grants(state)
            if grants is None else grants
        )
        return _checked_add(
            self._talent_total(commander_key, tier),
            proven.get(commander_key, 0),
        )

    def _initialize_unit_ability_selections(self, state: dict) -> bool:
        """Add schema-11 unit selections and migrate every frozen roster."""
        before = copy.deepcopy(state)
        selections = state.get("unit_abilities")
        if selections is None:
            selections = {}
            state["unit_abilities"] = selections
        if not isinstance(selections, dict):
            return False
        for unit_key in sorted(state.get("units", {})):
            selections.setdefault(unit_key, [])

        for match_id, battle in state.get("battles", {}).items():
            if not isinstance(battle, dict):
                continue
            unit_keys = battle.get("units")
            loadouts = battle.get("unit_loadouts")
            if (not isinstance(unit_keys, list) or len(unit_keys) != 3
                    or not isinstance(loadouts, list) or len(loadouts) != 3):
                continue
            old_hash = battle.get("roster_hash")
            changed = False
            for unit_key, loadout in zip(unit_keys, loadouts):
                if isinstance(loadout, dict) and "abilities" not in loadout:
                    # Schema 10 predates type-19 persistence, so an already
                    # frozen battle receives the only truthful prior value.
                    loadout["abilities"] = []
                    changed = True
            if changed:
                battle["roster_hash"] = self._roster_hash(
                    battle.get("commander"), unit_keys,
                    battle.get("battle_tier"), loadouts,
                )
                if isinstance(old_hash, str):
                    self._migrate_battle_operation_receipts(
                        state, match_id, battle, old_hash,
                    )
        return state != before

    @staticmethod
    def _initialize_battle_reward_policies(state: dict) -> None:
        for battle in state["battles"].values():
            battle["reward_policy"] = "pve"
        state["schema_version"] = SCHEMA_VERSION

    def _initialize_equipment_unlocks(self, state: dict) -> None:
        state["unlocked_equipment"] = sorted(
            row["db_key"] for row in self.equipment_by_db_key.values()
            if row["source_unit"] in state["units"]
        )

    @staticmethod
    def _utc_day(now_ms: int) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime(_plain_int(now_ms) // 1000))

    def _initialize_daily_quests(self, state: dict) -> None:
        if not state.get("daily"):
            state["daily"] = {
                "day": self._utc_day(self._now_ms()),
                "verified_battles": 0,
                "victories": 0,
                "claimed": [],
            }

    def _prune_orphaned_ability_subtrees(self, state: dict) -> None:
        """Drop legacy selections that cannot be reached from a base root."""
        for commander_key, commander_state in state["commanders"].items():
            abilities = commander_state["abilities"]
            while True:
                orphaned = self._orphaned_ability_nodes(
                    commander_key, abilities,
                )
                if not orphaned:
                    break
                for ability_key in orphaned:
                    del abilities[ability_key]

    def _initialize_talent_points(self, state: dict) -> None:
        """Reconstruct the exact unspent balance while migrating to schema 7."""
        grants = self._proven_local_commander_talent_point_grants(state)
        for commander_key, commander_state in state["commanders"].items():
            total = self._talent_total_with_local_grants(
                state, commander_key, commander_state["tier"], grants,
            )
            spent = self._talent_points_spent(
                commander_key, commander_state["abilities"],
            )
            if spent > total:
                raise EconomyError("commander_talent_points_overspent")
            commander_state["talent_points"] = total - spent

    def _initialize_loadout_selections(self, state: dict) -> None:
        """Add the former implicit max-equipment and consumable defaults."""
        state["schema_version"] = SCHEMA_VERSION
        state["equipment"] = {
            unit_key: self._default_equipment_for_unit(unit_key)
            for unit_key in sorted(state["units"])
        }
        state["consumables"] = {
            commander_key: self._default_consumables_for_units(
                commander_state["equipped_units"],
            )
            for commander_key, commander_state in sorted(state["commanders"].items())
        }
        for match_id, battle in state["battles"].items():
            old_hash = battle["roster_hash"]
            unit_loadouts = self._default_unit_loadouts(battle["units"])
            battle["unit_loadouts"] = unit_loadouts
            battle["roster_hash"] = self._roster_hash(
                battle["commander"], battle["units"], battle["battle_tier"],
                unit_loadouts,
            )
            self._migrate_battle_operation_receipts(
                state, match_id, battle, old_hash,
            )

    def _migrate_battle_operation_receipts(
        self, state: dict, match_id: str, battle: dict, old_hash: str,
        *, effective_tier: bool = False,
    ) -> None:
        """Keep durable retry receipts aligned with a migrated frozen roster."""
        new_hash = battle["roster_hash"]
        begin_entry = state["operations"].get(battle["begin_operation"], {})
        begin = begin_entry.get("receipt")
        if isinstance(begin, dict):
            loadout = begin.get("loadout")
            if isinstance(loadout, dict):
                loadout["roster_hash"] = new_hash
                loadout["battle_tier"] = battle["battle_tier"]
                loadout["enemy_tier"] = battle["battle_tier"]
                if effective_tier:
                    commander = state.get("commanders", {}).get(
                        battle.get("commander"),
                    )
                    if isinstance(commander, dict):
                        loadout["commander_tier"] = commander.get("tier")
                for row, frozen in zip(loadout.get("units", []), battle["unit_loadouts"]):
                    if isinstance(row, dict):
                        if effective_tier:
                            row["tier"] = EFFECTIVE_UNIT_TIER
                        row["equipment"] = copy.deepcopy(frozen["equipment"])
                        row["consumables"] = copy.deepcopy(frozen["consumables"])
                        if "abilities" in frozen:
                            row["abilities"] = copy.deepcopy(
                                frozen["abilities"]
                            )
            begin_entry["request_hash"] = _canonical_hash({
                "kind": f"begin_{battle.get('reward_policy', 'pve')}",
                "request": {
                    "match_id": match_id,
                    "commander": battle["commander"],
                    "units": battle["units"],
                    "unit_loadouts": battle["unit_loadouts"],
                    "roster_hash": new_hash,
                },
            })
        settlement_id = battle.get("settlement_operation")
        settlement_entry = state["operations"].get(settlement_id, {})
        settlement = settlement_entry.get("receipt")
        if isinstance(settlement, dict) and settlement.get("roster_hash") == old_hash:
            settlement["roster_hash"] = new_hash
            settlement["battle_tier"] = battle["battle_tier"]
            settlement_entry["request_hash"] = _canonical_hash({
                "kind": f"settle_{battle.get('reward_policy', 'pve')}",
                "request": {
                    "match_id": match_id,
                    "outcome": battle["outcome"],
                    "roster_hash": new_hash,
                    "verified": battle["verified"],
                },
            })

    def _grant_initial_units(self, state: dict) -> None:
        for unit_key, unit in self.units.items():
            if unit.get("is_premium") is True:
                continue
            state["units"].setdefault(unit_key, {"unit_xp_cents": 0})

    def _default_loadout(self, commander_key: str, tier: int) -> list[str]:
        result = []
        for starter in self.commanders[commander_key]["starting_units"]:
            paths = self._paths_from(starter)
            role = self.units[starter].get("metadata", {}).get("squad_role")
            candidates = [key for key in paths if self.units[key].get("tier") == tier
                          and self.units[key].get("is_premium") is not True]
            if not candidates:
                raise EconomyError("legacy_tier_not_reachable")
            result.append(min(candidates, key=lambda key: (
                self.units[key].get("metadata", {}).get("squad_role") != role,
                len(paths[key]), key,
            )))
        return result

    def _default_equipment_for_unit(self, unit_key: str) -> dict[str, str]:
        return copy.deepcopy(self.default_equipment.get(unit_key, {}))

    def _default_consumables_for_unit(self, unit_key: str) -> dict[str, str]:
        return copy.deepcopy(self.default_consumables.get(unit_key, {}))

    def _default_consumables_for_units(self, unit_keys: list[str]) -> list[dict[str, str]]:
        return [self._default_consumables_for_unit(unit_key) for unit_key in unit_keys]

    def _default_unit_loadouts(self, unit_keys: list[str]) -> list[dict]:
        return [{
            "equipment": self._default_equipment_for_unit(unit_key),
            "consumables": self._default_consumables_for_unit(unit_key),
            "abilities": [],
        } for unit_key in unit_keys]

    def _legacy_unlock_closure(
        self, commander_key: str, tier: int, equipped: list[str], extra: list[str]
    ) -> set[str]:
        commander = self.commanders[commander_key]
        result: set[str] = set()
        for unit_key in equipped + extra:
            unit = self.units.get(unit_key)
            if (unit is None or unit.get("faction") != commander.get("faction")
                    or type(unit.get("tier")) is not int or not 1 <= unit["tier"] <= tier):
                raise EconomyError("invalid_legacy_unit")
            path = self._paths.get((commander_key, unit_key))
            if path is not None:
                result.update(path)
            elif unit.get("is_premium") is True and unit_key in extra:
                result.add(unit_key)
            else:
                raise EconomyError("legacy_unit_not_reachable")
        return result

    # ---- validation and persistence ---------------------------------------

    def _validate_equipment_selections(
        self, unit_key: str, selections: object,
        unlocked: set[str] | None = None,
    ) -> None:
        if not isinstance(selections, dict):
            raise EconomyError("invalid_equipment_selections")
        known_slots = {
            self._equipment_slot_key(row)
            for row in self.equipment_by_unit.get(unit_key, [])
        }
        if any(not isinstance(slot, str) or slot not in known_slots
               for slot in selections):
            raise EconomyError("invalid_equipment_slot")
        for slot, db_key in selections.items():
            row = self.equipment_by_db_key.get(db_key)
            if (not isinstance(db_key, str) or row is None
                    or row["source_unit"] != unit_key
                    or self._equipment_slot_key(row) != slot):
                raise EconomyError("invalid_equipment_selection")
            if unlocked is not None and db_key not in unlocked:
                raise EconomyError("equipment_not_unlocked")

    def _validate_consumable_selections(self, unit_key: str, selections: object) -> None:
        if not isinstance(selections, dict):
            raise EconomyError("invalid_consumable_selections")
        unit = self.units.get(unit_key)
        if unit is None:
            raise EconomyError("invalid_consumable_selection")
        capacity = unit.get("num_consumable_slots")
        if type(capacity) is not int or not 0 <= capacity <= 10:
            raise EconomyError("invalid_consumable_capacity")
        for slot, db_key in selections.items():
            row = self.consumables_by_db_key.get(db_key)
            if (not isinstance(slot, str) or not slot.isascii() or not slot.isdigit()
                    or str(int(slot)) != slot or not 0 <= int(slot) < capacity
                    or not isinstance(db_key, str) or row is None
                    or unit.get("build_state", "live") != "live"
                    or row["tier"] != EFFECTIVE_UNIT_TIER
                    or db_key not in self.consumable_keys_by_unit.get(unit_key, set())):
                raise EconomyError("invalid_consumable_selection")
        # A type-11 profile instance is stable per commander/deployed-unit and
        # consumable definition; it has no separate identity for consumable
        # slot 0 versus slot 1.  Persisting the same definition in both slots
        # would therefore project the same instance twice and only fail later
        # while the native profile is being assembled.  Reject that corrupt
        # two-slot state at the persistence boundary instead.
        if len(selections.values()) != len(set(selections.values())):
            raise EconomyError("duplicate_consumable_selection")

    def _validate_unit_ability_selections(
        self, unit_key: str, selections: object,
        owned_units: set[str] | None = None,
    ) -> None:
        if (not isinstance(selections, list)
                or selections != sorted(set(selections))):
            raise EconomyError("invalid_unit_ability_selections")
        for db_key in selections:
            row = self.unit_abilities_by_db_key.get(db_key)
            if (not isinstance(db_key, str) or row is None
                    or row["unit"] != unit_key):
                raise EconomyError("invalid_unit_ability_selection")
            required = row["alias_unit"]
            if required and owned_units is not None and required not in owned_units:
                raise EconomyError("unit_ability_required_unit_not_owned")

    def _validate_unit_loadouts(
        self, unit_keys: list[str], unit_loadouts: object, *,
        has_unit_abilities: bool,
    ) -> None:
        if not isinstance(unit_loadouts, list) or len(unit_loadouts) != 3:
            raise EconomyError("invalid_battle_loadouts")
        fields = {"equipment", "consumables"}
        if has_unit_abilities:
            fields.add("abilities")
        for unit_key, loadout in zip(unit_keys, unit_loadouts):
            if not isinstance(loadout, dict) or set(loadout) != fields:
                raise EconomyError("invalid_battle_loadouts")
            self._validate_equipment_selections(unit_key, loadout["equipment"])
            self._validate_consumable_selections(unit_key, loadout["consumables"])
            if has_unit_abilities:
                self._validate_unit_ability_selections(
                    unit_key, loadout["abilities"],
                )

    def _validate_state(
        self,
        state: dict,
        *,
        expected_schema: int = SCHEMA_VERSION,
        require_initial_grants: bool = True,
        require_mandatory_abilities: bool = True,
        legacy_native_battle_tiers: bool = False,
    ) -> None:
        if (legacy_native_battle_tiers
                and expected_schema != TIER_X_SANDBOX_SCHEMA_VERSION):
            raise EconomyError("invalid_state_schema")
        has_persisted_loadouts = expected_schema >= LOADOUT_SELECTIONS_SCHEMA_VERSION
        has_talent_points = expected_schema >= TALENT_POINTS_SCHEMA_VERSION
        requires_ability_tree = expected_schema >= ABILITY_TREE_SCHEMA_VERSION
        has_reward_policy = expected_schema >= REWARD_POLICY_SCHEMA_VERSION
        has_research_state = expected_schema >= FULL_UNLOCK_SCHEMA_VERSION
        has_unit_abilities = expected_schema >= UNIT_ABILITIES_SCHEMA_VERSION
        has_premium_policy = expected_schema >= PREMIUM_POLICY_SCHEMA_VERSION
        expected = {"schema_version", "saved", "price_version", "reward_version", "active_commander",
                    "wallet", "commanders", "units", "operations", "battles"}
        if has_persisted_loadouts:
            expected.update({"equipment", "consumables"})
        if has_research_state:
            expected.update({"unlocked_equipment", "daily"})
        if has_unit_abilities:
            expected.add("unit_abilities")
        if has_premium_policy:
            expected.add("removed_legacy_premium_units")
        if (not isinstance(state, dict) or set(state) != expected
                or type(state.get("schema_version")) is not int
                or state.get("schema_version") != expected_schema):
            raise EconomyError("invalid_state_schema")
        if state.get("price_version") != PRICE_VERSION or state.get("reward_version") != REWARD_VERSION:
            raise EconomyError("unsupported_policy_version")
        _plain_int(state.get("saved"), minimum=1)
        wallet = state.get("wallet")
        if not isinstance(wallet, dict) or set(wallet) != set(WALLET_CURRENCIES):
            raise EconomyError("invalid_wallet")
        for value in wallet.values():
            _plain_int(value)

        owned_units = state.get("units")
        if not isinstance(owned_units, dict) or len(owned_units) > len(self.units):
            raise EconomyError("invalid_owned_units")
        for unit_key, value in owned_units.items():
            if unit_key not in self.units or not isinstance(value, dict) or set(value) != {"unit_xp_cents"}:
                raise EconomyError("invalid_owned_unit")
            _plain_int(value["unit_xp_cents"])

        unlocked_equipment: set[str] | None = None
        if has_research_state:
            raw_unlocked = state.get("unlocked_equipment")
            if (not isinstance(raw_unlocked, list)
                    or len(raw_unlocked) != len(set(raw_unlocked))
                    or any(not isinstance(key, str)
                           or key not in self.equipment_by_db_key
                           for key in raw_unlocked)):
                raise EconomyError("invalid_unlocked_equipment")
            unlocked_equipment = set(raw_unlocked)
            if any(self.equipment_by_db_key[key]["source_unit"] not in owned_units
                   for key in unlocked_equipment):
                raise EconomyError("equipment_unit_not_owned")
            required_equipment = {
                row["db_key"] for unit_key in owned_units
                for row in self.equipment_by_unit.get(unit_key, [])
                if self._is_initial_equipment(row)
            }
            if not required_equipment <= unlocked_equipment:
                raise EconomyError("missing_initial_equipment")
            if has_premium_policy:
                full_owned_equipment = {
                    row["db_key"] for unit_key in owned_units
                    for row in self.equipment_by_unit.get(unit_key, [])
                }
                if unlocked_equipment != full_owned_equipment:
                    raise EconomyError("missing_full_equipment_unlock")

            daily = state.get("daily")
            if (not isinstance(daily, dict)
                    or set(daily) != {"day", "verified_battles", "victories", "claimed"}
                    or not isinstance(daily["day"], str)
                    or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", daily["day"])
                    or not isinstance(daily["claimed"], list)
                    or len(daily["claimed"]) != len(set(daily["claimed"]))
                    or any(key not in {row[0] for row in DAILY_QUESTS}
                           for key in daily["claimed"])):
                raise EconomyError("invalid_daily_quests")
            _plain_int(daily["verified_battles"])
            _plain_int(daily["victories"])

        equipment = state.get("equipment") if has_persisted_loadouts else None
        if has_persisted_loadouts:
            if not isinstance(equipment, dict) or set(equipment) != set(owned_units):
                raise EconomyError("invalid_equipment_selections")
            for unit_key, selections in equipment.items():
                self._validate_equipment_selections(
                    unit_key, selections, unlocked_equipment,
                )

        if has_unit_abilities:
            unit_abilities = state.get("unit_abilities")
            if (not isinstance(unit_abilities, dict)
                    or set(unit_abilities) != set(owned_units)):
                raise EconomyError("invalid_unit_ability_selections")
            for unit_key, selections in unit_abilities.items():
                self._validate_unit_ability_selections(
                    unit_key, selections, set(owned_units),
                )

        commanders = state.get("commanders")
        if not isinstance(commanders, dict) or not commanders or len(commanders) > len(self.commanders):
            raise EconomyError("invalid_owned_commanders")
        local_talent_grants = (
            self._proven_local_commander_talent_point_grants(state)
            if has_premium_policy else {}
        )
        for commander_key, value in commanders.items():
            if commander_key not in self.commanders or not isinstance(value, dict):
                raise EconomyError("invalid_owned_commander")
            commander_fields = {
                "tier", "commander_xp_cents", "abilities", "equipped_units",
            }
            if has_talent_points:
                commander_fields.add("talent_points")
            if set(value) != commander_fields:
                raise EconomyError("invalid_commander_state")
            xp = _plain_int(value["commander_xp_cents"])
            tier = value["tier"]
            if type(tier) is not int or tier != self.commander_tier_for_xp(xp):
                raise EconomyError("commander_tier_xp_mismatch")
            abilities = value["abilities"]
            if not isinstance(abilities, dict) or len(abilities) > len(self.ability_required_tier):
                raise EconomyError("invalid_commander_abilities")
            for ability_key, level in abilities.items():
                if not isinstance(ability_key, str) or type(level) is not int:
                    raise EconomyError("invalid_commander_ability")
                required = self.ability_required_tier.get((commander_key, ability_key, level))
                if required is None or required > tier:
                    raise EconomyError("invalid_commander_ability")
            if has_talent_points:
                remaining = _plain_int(value["talent_points"])
                total = self._talent_total_with_local_grants(
                    state, commander_key, tier, local_talent_grants,
                )
                spent = self._talent_points_spent(commander_key, abilities)
                if remaining != total - spent:
                    raise EconomyError("commander_talent_points_mismatch")
            if (requires_ability_tree
                    and self._orphaned_ability_nodes(commander_key, abilities)):
                raise EconomyError("ability_tree_prerequisite_missing")
            if require_mandatory_abilities:
                mandatory = {
                    ability_key: level
                    for required_tier, ability_key, level
                    in self.mandatory_abilities[commander_key]
                    if required_tier <= tier
                }
                if any(abilities.get(key) != level for key, level in mandatory.items()):
                    raise EconomyError("missing_base_commander_ability")
            equipped = value["equipped_units"]
            if not isinstance(equipped, list) or len(equipped) != 3:
                raise EconomyError("invalid_loadout_size")
            for unit_key in equipped:
                unit = self.units.get(unit_key)
                if (not isinstance(unit_key, str) or unit_key not in owned_units or unit is None
                        or unit.get("faction") != self.commanders[commander_key].get("faction")
                        or unit_key not in self.reachable[commander_key]
                        or type(unit.get("tier")) is not int or unit["tier"] > tier):
                    raise EconomyError("invalid_loadout_unit")

        consumables = state.get("consumables") if has_persisted_loadouts else None
        if has_persisted_loadouts:
            if not isinstance(consumables, dict) or set(consumables) != set(commanders):
                raise EconomyError("invalid_consumable_selections")
            for commander_key, deployed in consumables.items():
                if not isinstance(deployed, list) or len(deployed) != 3:
                    raise EconomyError("invalid_consumable_selections")
                for unit_key, selections in zip(
                    commanders[commander_key]["equipped_units"], deployed,
                ):
                    self._validate_consumable_selections(unit_key, selections)

        if require_initial_grants:
            if set(commanders) != set(self.commanders):
                raise EconomyError("missing_initial_commander")
            if any(value["tier"] < INITIAL_TIER for value in commanders.values()):
                raise EconomyError("commander_below_initial_tier")
            required_units = {key for key, unit in self.units.items()
                              if unit.get("is_premium") is not True
                              and unit.get("tier") <= INITIAL_TIER}
            if not required_units <= set(owned_units):
                raise EconomyError("missing_initial_unit")

        active = state.get("active_commander")
        if active not in commanders:
            raise EconomyError("active_commander_not_owned")
        for unit_key in owned_units:
            unit = self.units[unit_key]
            if not any(self.commanders[key].get("faction") == unit.get("faction")
                       and unit_key in self.reachable[key] for key in commanders):
                raise EconomyError("orphaned_owned_unit")

        operations = state.get("operations")
        if not isinstance(operations, dict) or len(operations) > MAX_OPERATIONS:
            raise EconomyError("invalid_operations")
        for operation_id, entry in operations.items():
            if (not isinstance(operation_id, str) or not IDENTIFIER.fullmatch(operation_id)
                    or not isinstance(entry, dict) or set(entry) != {"request_hash", "receipt"}
                    or not isinstance(entry["request_hash"], str) or not HEX_256.fullmatch(entry["request_hash"])
                    or not isinstance(entry["receipt"], dict)):
                raise EconomyError("invalid_operation")

        historical_removed_premium: set[str] = set()
        if has_premium_policy:
            removed_legacy_premium = state.get(
                "removed_legacy_premium_units",
            )
            if (not isinstance(removed_legacy_premium, list)
                    or any(not isinstance(key, str)
                           or key not in self.units
                           or self.units[key].get("is_premium") is not True
                           for key in removed_legacy_premium)
                    or removed_legacy_premium != sorted(
                        set(removed_legacy_premium)
                    )):
                raise EconomyError("invalid_removed_legacy_premium_units")
            historical_removed_premium = set(removed_legacy_premium)
            owned_premium = {
                key for key in owned_units
                if self.units[key].get("is_premium") is True
            }
            proven_premium = (
                self._proven_purchased_premium_units(state)
                | self._proven_local_premium_grants(state)
                | self._proven_sandbox_premium_grants(state)
            )
            if owned_premium != proven_premium:
                raise EconomyError("unproven_premium_entitlement")

        battles = state.get("battles")
        if not isinstance(battles, dict) or len(battles) > MAX_OPERATIONS:
            raise EconomyError("invalid_battles")
        battle_fields = {"commander", "units", "battle_tier", "roster_hash", "status", "outcome",
                         "verified", "begin_operation", "settlement_operation"}
        if has_persisted_loadouts:
            battle_fields.add("unit_loadouts")
        if has_reward_policy:
            battle_fields.add("reward_policy")
        for match_id, battle in battles.items():
            if not isinstance(match_id, str) or not IDENTIFIER.fullmatch(match_id) or not isinstance(battle, dict):
                raise EconomyError("invalid_battle")
            if set(battle) != battle_fields or battle["commander"] not in commanders:
                raise EconomyError("invalid_battle")
            if has_reward_policy and battle["reward_policy"] not in REWARD_POLICIES:
                raise EconomyError("invalid_reward_policy")
            if battle["status"] not in ("pending", "settled"):
                raise EconomyError("invalid_battle_status")
            unit_keys = battle["units"]
            allowed_frozen_units = set(owned_units)
            if battle["status"] == "settled":
                # Removed schema-11 auto-grants survive only as immutable
                # historical identifiers. They are absent from current unit,
                # equipment, ability and commander-loadout ownership maps.
                allowed_frozen_units.update(historical_removed_premium)
            if (not isinstance(unit_keys, list) or len(unit_keys) != 3
                    or any(key not in allowed_frozen_units for key in unit_keys)):
                raise EconomyError("invalid_battle")
            battle_commander = battle["commander"]
            if any(self.units[key]["faction"] != self.commanders[battle_commander]["faction"]
                   or key not in self.reachable[battle_commander]
                   or self.units[key]["tier"] > commanders[battle_commander]["tier"] for key in unit_keys):
                raise EconomyError("invalid_battle_unit")
            tier_field = (
                "effective_tier"
                if (expected_schema >= TIER_X_SANDBOX_SCHEMA_VERSION
                    and not legacy_native_battle_tiers)
                else "tier"
            )
            tier = max(self.units[key][tier_field] for key in unit_keys)
            if has_persisted_loadouts:
                unit_loadouts = battle["unit_loadouts"]
                self._validate_unit_loadouts(
                    unit_keys, unit_loadouts,
                    has_unit_abilities=has_unit_abilities,
                )
                expected_roster_hash = self._roster_hash(
                    battle["commander"], unit_keys, tier, unit_loadouts,
                )
            else:
                expected_roster_hash = self._legacy_roster_hash(
                    battle["commander"], unit_keys, tier,
                )
            if (battle["battle_tier"] != tier
                    or battle["roster_hash"] != expected_roster_hash):
                raise EconomyError("invalid_battle_roster")
            _identifier(battle["begin_operation"])
            if battle["begin_operation"] not in operations:
                raise EconomyError("invalid_battle_operation")
            if battle["status"] == "pending":
                if battle["outcome"] is not None or battle["verified"] is not None or battle["settlement_operation"] is not None:
                    raise EconomyError("invalid_pending_battle")
            else:
                if (battle["outcome"] not in OUTCOMES or type(battle["verified"]) is not bool
                        or not isinstance(battle["settlement_operation"], str)
                        or battle["settlement_operation"] not in operations):
                    raise EconomyError("invalid_settled_battle")
        self._validate_extended_state(state)

    def _validate_extended_state(self, state: dict) -> None:
        """Subclass-only durable invariants; legacy LocalEconomy is unchanged."""
        return None

    def _persist(self, state: dict) -> None:
        """Write through the backend, leaving ``self._state`` alone on failure.

        ``_run_operation`` calls this before it swaps in ``next_state``, so a
        rejected write (a watermark another writer already advanced) raises
        ``saved_conflict`` with the in-memory account still exactly as it was.
        """
        if self._backend is None:
            return
        try:
            written = self._backend.save(self._identity, state, self._backend_saved)
        except BackendConflict:
            raise EconomyError("saved_conflict") from None
        except BackendError as error:
            raise EconomyError(error.code) from None
        self._backend_saved = (written if type(written) is int and written >= 0
                               else _plain_int(state.get("saved")))

    def _next_saved(self, previous: int) -> int:
        return max(
            _plain_int(self._now_ms()),
            previous + 1,
            NATIVE_SAVED_FLOOR + 1,
        )

    # ---- idempotent mutation core -----------------------------------------

    def _run_operation(
        self,
        operation_id: str,
        kind: str,
        request: dict,
        apply: Callable[[dict], dict],
        *,
        advance_saved: bool = True,
    ) -> dict:
        operation_id = _identifier(operation_id)
        digest = _canonical_hash({"kind": kind, "request": request})
        with self._lock:
            existing = self._state["operations"].get(operation_id)
            if existing is not None:
                if existing["request_hash"] != digest:
                    raise EconomyError("idempotency_conflict")
                return copy.deepcopy(existing["receipt"])
            if len(self._state["operations"]) >= MAX_OPERATIONS:
                raise EconomyError("operation_capacity_reached")
            next_state = copy.deepcopy(self._state)
            details = apply(next_state)
            # ``saved`` is the native profile watermark, rather than a generic
            # persistence revision.  Durable server-only bookkeeping (such as
            # freezing a battle roster) and an acknowledged no-op must not make
            # an otherwise identical profile look stale to the client.
            saved = (self._next_saved(next_state["saved"])
                     if advance_saved else next_state["saved"])
            next_state["saved"] = saved
            receipt = {"operation_id": operation_id, "kind": kind, "saved": saved, **details}
            next_state["operations"][operation_id] = {"request_hash": digest, "receipt": receipt}
            self._validate_state(next_state)
            self._persist(next_state)
            self._state = next_state
            return copy.deepcopy(receipt)

    # ---- public account mutations -----------------------------------------

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._state)

    def publish_projection_if_current(
        self, snapshot: dict, publish: Callable[[], None],
    ) -> bool:
        """Run a lightweight projection publish only while ``snapshot`` is current.

        Building the native compatibility graph is intentionally done outside
        the economy lock.  Every change visible in that graph advances
        ``saved``, so a short compare-and-publish section is enough to prevent
        an older, slower build from overwriting a newer one.  ``publish`` must
        not perform expensive work; it runs while mutations are briefly held.
        """
        candidate_saved = _plain_int(snapshot.get("saved"), minimum=1)
        with self._lock:
            if self._state["saved"] != candidate_saved:
                return False
            publish()
            return True

    def daily_missions(self) -> dict:
        """Return the legacy daily envelope with no active missions."""
        with self._lock:
            day = self._utc_day(self._now_ms())
            reset_at = (calendar.timegm(time.strptime(day, "%Y-%m-%d"))
                    + 86_400) * 1000
            return {"day": day, "reset_at_ms": reset_at,
                    "missions": [], "max_gold_cents": 0}

    def select_commander(self, operation_id: str, commander_key: str) -> dict:
        request = {"commander": commander_key}

        def apply(state: dict) -> dict:
            if commander_key not in state["commanders"]:
                raise EconomyError("commander_not_owned")
            state["active_commander"] = commander_key
            return {"active_commander": commander_key}

        # Hold the same mutation lock while deciding whether this operation is
        # profile-visible and while recording it.  The operation is still
        # persisted when it is a no-op, so a delayed identical retry can never
        # become a commander switch after another request changes the account.
        with self._lock:
            if commander_key not in self._state["commanders"]:
                raise EconomyError("commander_not_owned")
            changed = self._state["active_commander"] != commander_key
            return self._run_operation(
                operation_id, "select_commander", request, apply,
                advance_saved=changed,
            )

    def grant_wallet(self, operation_id: str, currency: str, amount: int, *, reason: str) -> dict:
        """Trusted server/admin credit.  Never expose amount through a player API."""
        if currency not in WALLET_CURRENCIES:
            raise EconomyError("invalid_wallet_currency")
        _plain_int(amount, minimum=1)
        if not isinstance(reason, str) or not 1 <= len(reason) <= 64 or any(ord(char) < 32 for char in reason):
            raise EconomyError("invalid_grant_reason")
        request = {"currency": currency, "amount": amount, "reason": reason}

        def apply(state: dict) -> dict:
            state["wallet"][currency] = _checked_add(state["wallet"][currency], amount)
            return {"currency": currency, "amount": amount, "balance": state["wallet"][currency],
                    "reason": reason}

        return self._run_operation(operation_id, "grant_wallet", request, apply)

    def grant_local_premium_units(
        self, operation_id: str, unit_keys: list[str], *, reason: str,
    ) -> dict:
        """Explicit local operator/test grant; never expose through player APIs.

        Only named live premium units are granted. Wallets, existing XP,
        commanders, current squad selections and frozen battles are untouched.
        The normal premium shop remains 1,000 Gold for accounts without this
        auditable grant. Repeating the same operation ID is idempotent.
        """
        if self._backend is not None and not isinstance(self._backend, FileEconomyBackend):
            raise EconomyError("local_premium_grant_requires_local_backend")
        if (not isinstance(unit_keys, list) or not unit_keys
                or any(not isinstance(key, str) or key not in self.units
                       or self.units[key].get("is_premium") is not True for key in unit_keys)
                or len(unit_keys) != len(set(unit_keys))):
            raise EconomyError("invalid_local_premium_units")
        if (not isinstance(reason, str) or not 1 <= len(reason) <= 64
                or any(ord(char) < 32 for char in reason)):
            raise EconomyError("invalid_grant_reason")
        keys = sorted(unit_keys)
        request = {"units": keys, "reason": reason, "source": "local_operator"}

        def apply(state: dict) -> dict:
            self._grant_premium_catalog_state(state, keys)
            return copy.deepcopy(request)

        with self._lock:
            changed = any(key not in self._state["units"] for key in keys)
            return self._run_operation(
                operation_id, "grant_local_premium_units", request, apply,
                advance_saved=changed,
            )

    def _grant_premium_catalog_state(self, state: dict, keys: list[str]) -> None:
        unlocked = set(state["unlocked_equipment"])
        for unit_key in keys:
            if unit_key in state["units"]:
                continue
            state["units"][unit_key] = {"unit_xp_cents": 0}
            state["equipment"][unit_key] = self._default_equipment_for_unit(unit_key)
            state["unit_abilities"][unit_key] = []
            unlocked.update(row["db_key"] for row in self.equipment_by_unit.get(unit_key, []))
        state["unlocked_equipment"] = sorted(unlocked)

    def grant_sandbox_premium_units(
        self, operation_id: str, *, reason: str,
    ) -> dict:
        """Explicit operator grant of the complete live premium catalog.

        This is for the revival sandbox, whose server accepts the full catalog.
        It is not exposed through the native shop or a public player endpoint.
        Existing balances, XP, loadouts and battle records remain unchanged.
        """
        unit_keys = [key for key, unit in self.units.items()
                     if unit.get("is_premium") is True]
        if (not isinstance(reason, str) or not 1 <= len(reason) <= 64
                or any(ord(char) < 32 for char in reason)):
            raise EconomyError("invalid_grant_reason")
        keys = sorted(unit_keys)
        request = {"units": keys, "reason": reason, "source": "sandbox_catalog"}

        def apply(state: dict) -> dict:
            self._grant_premium_catalog_state(state, keys)
            return copy.deepcopy(request)

        with self._lock:
            changed = any(key not in self._state["units"] for key in keys)
            return self._run_operation(
                operation_id, "grant_sandbox_premium_units", request, apply,
                advance_saved=changed,
            )

    def grant_local_commander_talent_points(
        self,
        operation_id: str,
        commander_keys: list[str],
        amount: int = 100,
        *,
        reason: str,
    ) -> dict:
        """Add an audited local-only bonus to each named owned commander.

        This is an additive operator grant, not a new default or a reset to a
        fixed balance.  Purchased ranks and prior refunds remain intact.  The
        exact receipt in the operation journal is required to validate the
        boosted balances after restart, and the stable operation ID makes an
        identical retry idempotent.
        """
        if (self._backend is not None
                and not isinstance(self._backend, FileEconomyBackend)):
            raise EconomyError(
                "local_commander_talent_grant_requires_local_backend"
            )
        if (not isinstance(commander_keys, list) or not commander_keys
                or any(not isinstance(key, str) or key not in self.commanders
                       for key in commander_keys)
                or len(commander_keys) != len(set(commander_keys))):
            raise EconomyError("invalid_local_commander_talent_grant")
        amount = _plain_int(amount, minimum=1)
        if amount > MAX_BALANCE // len(commander_keys):
            raise EconomyError("balance_out_of_range")
        if (not isinstance(reason, str) or not 1 <= len(reason) <= 64
                or any(ord(char) < 32 for char in reason)):
            raise EconomyError("invalid_grant_reason")
        keys = sorted(commander_keys)
        request = {
            "commanders": keys,
            "amount": amount,
            "reason": reason,
            "source": "local_operator",
        }

        def apply(state: dict) -> dict:
            if any(key not in state["commanders"] for key in keys):
                raise EconomyError("commander_not_owned")
            for commander_key in keys:
                commander = state["commanders"][commander_key]
                commander["talent_points"] = _checked_add(
                    commander["talent_points"], amount,
                )
            return {
                **copy.deepcopy(request),
                "grants": {key: amount for key in keys},
                "granted_total": amount * len(keys),
            }

        return self._run_operation(
            operation_id,
            "grant_local_commander_talent_points",
            request,
            apply,
        )

    def reset_local_commander_talent_points(
        self,
        operation_id: str,
        commander_keys: list[str],
        target_unspent: int = 100,
        *,
        reason: str,
    ) -> dict:
        """Reset Tier-X commanders to free roots and an approved balance.

        This local-operator operation preserves earlier grant receipts but
        supersedes their effective bonus at its journal position.  The exact
        native totals, earlier bonuses and mandatory roots are recorded so a
        forged or reordered reset cannot validate a boosted balance.
        """
        if (self._backend is not None
                and not isinstance(self._backend, FileEconomyBackend)):
            raise EconomyError(
                "local_commander_talent_grant_requires_local_backend"
            )
        if (not isinstance(commander_keys, list) or not commander_keys
                or any(not isinstance(key, str) or key not in self.commanders
                       for key in commander_keys)
                or len(commander_keys) != len(set(commander_keys))):
            raise EconomyError("invalid_local_commander_talent_reset")
        target_unspent = _plain_int(target_unspent, minimum=1)
        if target_unspent not in LOCAL_COMMANDER_TALENT_RESET_TARGETS:
            raise EconomyError("invalid_local_commander_talent_reset")
        if (not isinstance(reason, str) or not 1 <= len(reason) <= 64
                or any(ord(char) < 32 for char in reason)):
            raise EconomyError("invalid_grant_reason")
        keys = sorted(commander_keys)
        request = {
            "commanders": keys,
            "target_unspent": target_unspent,
            "reason": reason,
            "source": "local_operator",
        }

        def apply(state: dict) -> dict:
            if any(key not in state["commanders"] for key in keys):
                raise EconomyError("commander_not_owned")
            if any(state["commanders"][key].get("tier") != 10 for key in keys):
                raise EconomyError("commander_talent_reset_requires_tier_x")
            previous = self._proven_local_commander_talent_point_grants(state)
            native_totals = {
                key: self._talent_total(key, 10) for key in keys
            }
            effective = {
                key: target_unspent - native_totals[key] for key in keys
            }
            if any(value < 0 for value in effective.values()):
                raise EconomyError("invalid_local_commander_talent_reset")
            mandatory = {
                key: self._with_mandatory_abilities(key, 10, {}) for key in keys
            }
            for key in keys:
                state["commanders"][key]["abilities"] = copy.deepcopy(
                    mandatory[key]
                )
                state["commanders"][key]["talent_points"] = target_unspent
            return {
                **copy.deepcopy(request),
                "previous_bonuses": {
                    key: previous.get(key, 0) for key in keys
                },
                "native_totals": native_totals,
                "effective_bonuses": effective,
                "mandatory_abilities": mandatory,
            }

        return self._run_operation(
            operation_id,
            "reset_local_commander_talent_points",
            request,
            apply,
        )

    def purchase_commander(self, operation_id: str, commander_key: str, currency: str) -> dict:
        offers = {row["currency"]: row for row in self.commander_offers(commander_key)}
        offer = offers.get(currency)
        if offer is None:
            raise EconomyError("invalid_purchase_currency")
        request = {"offer_id": offer["id"], "commander": commander_key, "currency": currency}

        def apply(state: dict) -> dict:
            if commander_key in state["commanders"]:
                raise EconomyError("commander_already_owned")
            cost = offer["cost"]
            balance = state["wallet"][currency]
            if balance < cost:
                raise EconomyError("insufficient_funds")
            state["wallet"][currency] = balance - cost
            state["commanders"][commander_key] = self._new_commander_state(commander_key)
            self._grant_starters(state, commander_key)
            for unit_key in self.commanders[commander_key]["starting_units"]:
                state["equipment"].setdefault(
                    unit_key, self._default_equipment_for_unit(unit_key),
                )
            state["consumables"][commander_key] = self._default_consumables_for_units(
                state["commanders"][commander_key]["equipped_units"],
            )
            return {
                "offer_id": offer["id"], "commander": commander_key,
                "spent": {"currency": currency, "amount": cost, "balance": state["wallet"][currency]},
                "granted_units": list(dict.fromkeys(self.commanders[commander_key]["starting_units"])),
                "price_version": PRICE_VERSION,
            }

        return self._run_operation(operation_id, "purchase_commander", request, apply)

    def upgrade_commander_tier(
        self, operation_id: str, commander_key: str, target_tier: int,
    ) -> dict:
        """Buy exactly the next commander Tier with any missing account Free XP."""
        offer = self.commander_tier_offer(commander_key, target_tier)
        request = {
            "offer_id": offer["id"], "commander": commander_key,
            "target_tier": target_tier,
        }

        def apply(state: dict) -> dict:
            commander = state["commanders"].get(commander_key)
            if commander is None:
                raise EconomyError("commander_not_owned")
            current_tier = commander["tier"]
            if target_tier != current_tier + 1:
                if target_tier <= current_tier:
                    raise EconomyError("commander_tier_already_owned")
                raise EconomyError("commander_tier_prerequisite_missing")
            current_xp = commander["commander_xp_cents"]
            threshold = offer["cost"]
            missing = max(threshold - current_xp, 0)
            balance = state["wallet"]["free_xp_cents"]
            if balance < missing:
                raise EconomyError("insufficient_funds")
            state["wallet"]["free_xp_cents"] = balance - missing
            commander["commander_xp_cents"] = max(current_xp, threshold)
            commander["tier"] = self.commander_tier_for_xp(
                commander["commander_xp_cents"]
            )
            if commander["tier"] != target_tier:
                raise EconomyError("commander_tier_xp_mismatch")
            commander["abilities"] = self._with_mandatory_abilities(
                commander_key, target_tier, commander["abilities"],
            )
            point_grant = (
                self._talent_total(commander_key, target_tier)
                - self._talent_total(commander_key, current_tier)
            )
            commander["talent_points"] = _checked_add(
                commander["talent_points"], point_grant,
            )
            return {
                "offer_id": offer["id"],
                "commander": commander_key,
                "tier_before": current_tier,
                "tier_after": target_tier,
                "commander_xp_cents": commander["commander_xp_cents"],
                "talent_points_granted": point_grant,
                "spent": {
                    "currency": "free_xp_cents",
                    "scope": "account",
                    "amount": missing,
                    "balance": state["wallet"]["free_xp_cents"],
                },
                "price_version": PRICE_VERSION,
            }

        return self._run_operation(
            operation_id, "upgrade_commander_tier", request, apply,
        )

    def purchase_ability(self, operation_id: str, level_key: str) -> dict:
        """Unlock the next level through the native commander talent economy.

        The native tree names a concrete ``arena_commander_ability_levels``
        row in its purchase option.  Resolve that row through the trusted
        catalogue, require a sequential level and persist only the canonical
        ``ability_key -> level`` selection.  The profile adapter recreates the
        type-6 child with a stable instance on every subsequent profile and
        battle snapshot.
        """
        offer = self.ability_offer(level_key)
        request = {"offer_id": offer["id"], "ability_level": level_key}

        def apply(state: dict) -> dict:
            commander_key = offer["commander_key"]
            commander = state["commanders"].get(commander_key)
            if commander is None:
                raise EconomyError("commander_not_owned")
            if offer["required_tier"] > commander["tier"]:
                raise EconomyError("commander_tier_too_low")

            ability_key = offer["ability_key"]
            target_level = offer["ability_level"]
            current_level = commander["abilities"].get(ability_key)
            expected_level = 1 if current_level is None else current_level + 1
            if target_level != expected_level:
                if target_level == current_level:
                    raise EconomyError("ability_level_already_owned")
                raise EconomyError("ability_level_prerequisite_missing")
            if (target_level == 1
                    and self._orphaned_ability_nodes(
                        commander_key, {**commander["abilities"], ability_key: 1},
                    )):
                raise EconomyError("ability_tree_prerequisite_missing")

            currency = offer["currency"]
            cost = offer["cost"]
            if currency != "commander_talent_points":
                raise EconomyError("invalid_ability_currency")
            self._prepare_ability_purchase_balance(state, offer)
            balance = commander["talent_points"]
            if balance < cost:
                raise EconomyError("insufficient_commander_talent_points")
            commander["talent_points"] = balance - cost
            new_balance = commander["talent_points"]
            scope = commander_key
            commander["abilities"][ability_key] = target_level
            return {
                "offer_id": offer["id"],
                "commander": commander_key,
                "ability_key": ability_key,
                "ability_level": target_level,
                "ability_level_key": level_key,
                "item_id": offer["item_id"],
                "spent": {
                    "currency": currency,
                    "scope": scope,
                    "amount": cost,
                    "balance": new_balance,
                },
                "price_version": PRICE_VERSION,
            }

        return self._run_operation(
            operation_id, "purchase_ability", request, apply,
        )

    def refund_ability(self, operation_id: str, level_key: str) -> dict:
        """Remove exactly the selected highest rank and return one point."""
        offer = self.ability_refund_offer(level_key)
        request = {"offer_id": offer["id"], "ability_level": level_key}

        def apply(state: dict) -> dict:
            commander_key = offer["commander_key"]
            commander = state["commanders"].get(commander_key)
            if commander is None:
                raise EconomyError("commander_not_owned")
            ability_key = offer["ability_key"]
            target_level = offer["ability_level"]
            current_level = commander["abilities"].get(ability_key)
            if current_level != target_level:
                raise EconomyError("ability_refund_not_highest_rank")

            granted = {
                key for _tier, key, _level
                in self.mandatory_abilities[commander_key]
            }
            if target_level == 1:
                if ability_key in granted:
                    raise EconomyError("cannot_refund_base_commander_ability")
                del commander["abilities"][ability_key]
                resulting_level = 0
            else:
                if (commander_key, ability_key, target_level - 1) \
                        not in self.ability_levels_by_identity:
                    raise EconomyError("ability_level_prerequisite_missing")
                commander["abilities"][ability_key] = target_level - 1
                resulting_level = target_level - 1

            if self._orphaned_ability_nodes(
                    commander_key, commander["abilities"]):
                raise EconomyError("ability_refund_would_orphan_tree")

            total = self._talent_total_with_local_grants(
                state, commander_key, commander["tier"],
            )
            self._prepare_ability_refund_balance(state, offer, total)
            commander["talent_points"] = _checked_add(
                commander["talent_points"], 1,
            )
            if commander["talent_points"] > total:
                raise EconomyError("commander_talent_points_overflow")
            return {
                "offer_id": offer["id"],
                "commander": commander_key,
                "ability_key": ability_key,
                "ability_level": target_level,
                "ability_level_key": level_key,
                "resulting_level": resulting_level,
                "item_id": offer["item_id"],
                "refunded": {
                    "currency": "commander_talent_points",
                    "scope": commander_key,
                    "amount": 1,
                    "balance": commander["talent_points"],
                },
                "price_version": PRICE_VERSION,
            }

        return self._run_operation(
            operation_id, "refund_ability", request, apply,
        )

    def refund_ability_tree(
        self, operation_id: str, commander_key: str, level_keys: list[str],
        *, expected_saved: int,
    ) -> dict:
        """Atomically refund every manual rank in one native stock reset.

        The client submits all owned rank objects, not one highest rank per
        talent. Removing their complete set together preserves prerequisite
        integrity regardless of the client's iteration order.
        """
        if (not isinstance(level_keys, list) or not level_keys
                or any(not isinstance(key, str) for key in level_keys)
                or len(level_keys) != len(set(level_keys))
                or type(expected_saved) is not int):
            raise EconomyError("invalid_ability_tree_reset")
        request = {"commander": commander_key, "levels": sorted(level_keys),
                   "expected_saved": expected_saved}

        def apply(state: dict) -> dict:
            if state["saved"] != expected_saved:
                raise EconomyError("ability_tree_reset_state_changed")
            if state["active_commander"] != commander_key:
                raise EconomyError("active_commander_mismatch")
            commander = state["commanders"].get(commander_key)
            if commander is None:
                raise EconomyError("commander_not_owned")
            granted = self._with_mandatory_abilities(commander_key, commander["tier"], {})
            expected = {
                self.ability_levels_by_identity[(commander_key, ability, rank)]["key"]
                for ability, level in commander["abilities"].items()
                for rank in range(granted.get(ability, 0) + 1, level + 1)
            }
            if set(level_keys) != expected:
                raise EconomyError("ability_tree_reset_incomplete")
            total = self._talent_total_with_local_grants(
                state, commander_key, commander["tier"],
            )
            previous_points = commander["talent_points"]
            commander["abilities"] = granted
            commander["talent_points"] = total
            return {"commander": commander_key, "levels": sorted(level_keys),
                    "expected_saved": expected_saved,
                    "refunded_points": total - previous_points,
                    "balance": total}

        return self._run_operation(
            operation_id, "refund_ability_tree", request, apply,
        )

    def _prepare_ability_purchase_balance(self, state: dict, offer: dict) -> None:
        """Extension hook; the legacy economy requires no pre-purchase adjustment."""

    def _prepare_ability_refund_balance(self, state: dict, offer: dict, total: int) -> None:
        """Extension hook; the legacy economy requires no pre-refund adjustment."""

    def purchase_unit(
        self,
        operation_id: str,
        commander_key: str,
        unit_key: str,
        *,
        parent_unit_key: str | None = None,
    ) -> dict:
        offer = self.unit_offer(unit_key)
        request = {"offer_id": offer["id"], "commander": commander_key,
                   "unit": unit_key, "parent_unit": parent_unit_key}

        def apply(state: dict) -> dict:
            commander_state = state["commanders"].get(commander_key)
            if commander_state is None:
                raise EconomyError("commander_not_owned")
            unit = self.units[unit_key]
            if unit_key in state["units"]:
                raise EconomyError("unit_already_owned")
            if (unit["faction"] != self.commanders[commander_key]["faction"]
                    or unit_key not in self.reachable[commander_key]):
                raise EconomyError("unit_not_available_to_commander")
            if unit["tier"] > commander_state["tier"]:
                raise EconomyError("commander_tier_too_low")
            cost = offer["cost"]
            if offer["is_premium"]:
                if parent_unit_key is not None:
                    raise EconomyError("premium_unit_has_no_parent")
                balance = state["wallet"]["gold_cents"]
                if balance < cost:
                    raise EconomyError("insufficient_funds")
                state["wallet"]["gold_cents"] = balance - cost
                spent = {"currency": "gold_cents", "scope": "account", "amount": cost,
                         "balance": state["wallet"]["gold_cents"]}
            else:
                if parent_unit_key not in self.parents[unit_key]:
                    raise EconomyError("invalid_unit_prerequisite")
                if (parent_unit_key not in state["units"]
                        or parent_unit_key not in self.reachable[commander_key]):
                    raise EconomyError("unit_prerequisite_not_owned")
                balance = state["units"][parent_unit_key]["unit_xp_cents"]
                if balance < cost:
                    raise EconomyError("insufficient_unit_xp")
                state["units"][parent_unit_key]["unit_xp_cents"] = balance - cost
                spent = {"currency": "unit_xp_cents", "scope": parent_unit_key, "amount": cost,
                         "balance": state["units"][parent_unit_key]["unit_xp_cents"]}
            state["units"][unit_key] = {"unit_xp_cents": 0}
            state["equipment"][unit_key] = self._default_equipment_for_unit(unit_key)
            state["unit_abilities"][unit_key] = []
            unlocked = set(state["unlocked_equipment"])
            unlocked.update(
                row["db_key"] for row in self.equipment_by_unit.get(unit_key, [])
            )
            state["unlocked_equipment"] = sorted(unlocked)
            return {"offer_id": offer["id"], "commander": commander_key, "unit": unit_key,
                    "tier": unit["tier"], "spent": spent, "silver_cost": 0,
                    "price_version": PRICE_VERSION}

        return self._run_operation(operation_id, "purchase_unit", request, apply)

    def purchase_equipment(
        self, operation_id: str, equipment_db_key: str, currency: str,
    ) -> dict:
        offer = self.equipment_offer(equipment_db_key, currency)
        row = self.equipment_by_db_key[equipment_db_key]
        request = {"offer_id": offer["id"], "equipment": equipment_db_key,
                   "currency": currency}

        def apply(state: dict) -> dict:
            unit_key = row["source_unit"]
            if unit_key not in state["units"]:
                raise EconomyError("unit_not_owned")
            if equipment_db_key in state["unlocked_equipment"]:
                raise EconomyError("equipment_already_unlocked")
            candidates = [
                candidate for candidate in self.equipment_by_unit.get(unit_key, [])
                if candidate["scope"] == row["scope"]
                and candidate["slot"] == row["slot"]
                and candidate["placement_1"] < row["placement_1"]
            ]
            if candidates:
                prerequisite = max(
                    candidates,
                    key=lambda candidate: (
                        candidate["placement_1"], candidate["placement_0"],
                        candidate["db_key"],
                    ),
                )["db_key"]
                if prerequisite not in state["unlocked_equipment"]:
                    raise EconomyError("equipment_prerequisite_missing")

            cost = offer["cost"]
            if currency == "unit_xp_cents":
                account = state["units"][unit_key]
                if account["unit_xp_cents"] < cost:
                    raise EconomyError("insufficient_unit_xp")
                account["unit_xp_cents"] -= cost
                balance = account["unit_xp_cents"]
                scope = unit_key
            else:
                if state["wallet"]["free_xp_cents"] < cost:
                    raise EconomyError("insufficient_funds")
                state["wallet"]["free_xp_cents"] -= cost
                balance = state["wallet"]["free_xp_cents"]
                scope = "account"
            state["unlocked_equipment"].append(equipment_db_key)
            state["unlocked_equipment"].sort()
            return {
                "offer_id": offer["id"], "equipment": equipment_db_key,
                "unit": unit_key, "silver_cost": 0,
                "spent": {"currency": currency, "scope": scope,
                          "amount": cost, "balance": balance},
                "price_version": PRICE_VERSION,
            }

        return self._run_operation(
            operation_id, "purchase_equipment", request, apply,
        )

    def convert_unit_xp(
        self, operation_id: str, unit_key: str, amount: int,
    ) -> dict:
        """Convert earned unit XP to Free XP at 25 XP per Gold."""
        amount = _plain_int(amount, minimum=1)
        gold_cost = (amount + 24) // 25
        request = {"unit": unit_key, "amount": amount,
                   "gold_cost": gold_cost}

        def apply(state: dict) -> dict:
            unit = state["units"].get(unit_key)
            if unit is None:
                raise EconomyError("unit_not_owned")
            if unit["unit_xp_cents"] < amount:
                raise EconomyError("insufficient_unit_xp")
            if state["wallet"]["gold_cents"] < gold_cost:
                raise EconomyError("insufficient_funds")
            unit["unit_xp_cents"] -= amount
            state["wallet"]["gold_cents"] -= gold_cost
            state["wallet"]["free_xp_cents"] = _checked_add(
                state["wallet"]["free_xp_cents"], amount,
            )
            return {
                "unit": unit_key, "converted_unit_xp_cents": amount,
                "received_free_xp_cents": amount,
                "spent_gold_cents": gold_cost,
                "balances": {
                    "unit_xp_cents": unit["unit_xp_cents"],
                    "free_xp_cents": state["wallet"]["free_xp_cents"],
                    "gold_cents": state["wallet"]["gold_cents"],
                },
            }

        return self._run_operation(
            operation_id, "convert_unit_xp", request, apply,
        )

    def equip_units(self, operation_id: str, commander_key: str, unit_keys: list[str]) -> dict:
        if (not isinstance(unit_keys, list) or len(unit_keys) != 3
                or any(not isinstance(key, str) for key in unit_keys)):
            raise EconomyError("invalid_loadout_size")
        selected = list(unit_keys)
        request = {"commander": commander_key, "units": selected}

        def apply(state: dict) -> dict:
            commander_state = state["commanders"].get(commander_key)
            if commander_state is None:
                raise EconomyError("commander_not_owned")
            for unit_key in selected:
                unit = self.units.get(unit_key)
                if unit_key not in state["units"]:
                    raise EconomyError("unit_not_owned")
                if (unit is None or unit["faction"] != self.commanders[commander_key]["faction"]
                        or unit_key not in self.reachable[commander_key]):
                    raise EconomyError("loadout_faction_mismatch")
                if unit["tier"] > commander_state["tier"]:
                    raise EconomyError("commander_tier_too_low")
            previous_units = list(commander_state["equipped_units"])
            previous_consumables = state["consumables"][commander_key]
            # The native client emits delayed unequip/refund notifications for
            # the rows that belonged to the old deployed unit.  Keep the
            # before-image in the durable operation receipt so the adapter can
            # acknowledge those notifications after one or more rapid swaps
            # without treating them as current selections.  This is metadata
            # only: it is never used to resurrect a selection.
            changed_slots = [
                {
                    "slot": slot,
                    "unit": previous_units[slot],
                    "consumables": copy.deepcopy(previous_consumables[slot]),
                    "abilities": copy.deepcopy(
                        state["unit_abilities"].get(previous_units[slot], [])
                    ),
                }
                for slot, unit_key in enumerate(selected)
                if unit_key != previous_units[slot]
            ]
            updated_consumables: list[dict[str, str]] = []
            for slot, unit_key in enumerate(selected):
                # Consumables are deployment-slot state.  A unit-card drop
                # replaces the old unit and starts that slot empty; only
                # unchanged slots carry their existing selections forward.
                selections = (
                    copy.deepcopy(previous_consumables[slot])
                    if unit_key == previous_units[slot] else {}
                )
                updated_consumables.append(selections)
            commander_state["equipped_units"] = selected
            # A unit-card drop changes only its destination slot. Preserve the
            # other two deployed instances and their consumables exactly;
            # changed slots intentionally remain empty until explicitly filled.
            state["consumables"][commander_key] = updated_consumables
            return {"commander": commander_key, "units": selected,
                    "unit_change_cleanup": {
                        "commander": commander_key,
                        "previous_saved": state["saved"],
                        "previous_units": previous_units,
                        "changed_slots": changed_slots,
                    },
                    "battle_tier": max(
                        self.units[key]["effective_tier"] for key in selected
                    )}

        return self._run_operation(operation_id, "equip_units", request, apply)

    def select_equipment(
        self, operation_id: str, unit_key: str, equipment_db_key: str,
    ) -> dict:
        row = self.equipment_by_db_key.get(equipment_db_key)
        if row is None:
            raise EconomyError("unknown_equipment")
        slot = self._equipment_slot_key(row)
        request = {"unit": unit_key, "equipment": equipment_db_key}

        def apply(state: dict) -> dict:
            if unit_key not in state["units"]:
                raise EconomyError("unit_not_owned")
            if row["source_unit"] != unit_key:
                raise EconomyError("equipment_unit_mismatch")
            if equipment_db_key not in state["unlocked_equipment"]:
                raise EconomyError("equipment_not_unlocked")
            previous = state["equipment"][unit_key].get(slot)
            state["equipment"][unit_key][slot] = equipment_db_key
            return {
                "unit": unit_key,
                "equipment": equipment_db_key,
                "previous_equipment": previous,
                "scope": row["scope"],
                "slot": row["slot"],
            }

        with self._lock:
            if unit_key not in self._state["units"]:
                raise EconomyError("unit_not_owned")
            if row["source_unit"] != unit_key:
                raise EconomyError("equipment_unit_mismatch")
            changed = self._state["equipment"][unit_key].get(slot) != equipment_db_key
            return self._run_operation(
                operation_id, "select_equipment", request, apply,
                advance_saved=changed,
            )

    def clear_equipment(
        self, operation_id: str, unit_key: str, equipment_db_key: str,
    ) -> dict:
        row = self.equipment_by_db_key.get(equipment_db_key)
        if row is None:
            raise EconomyError("unknown_equipment")
        slot = self._equipment_slot_key(row)
        request = {"unit": unit_key, "equipment": equipment_db_key}

        def apply(state: dict) -> dict:
            if unit_key not in state["units"]:
                raise EconomyError("unit_not_owned")
            if row["source_unit"] != unit_key:
                raise EconomyError("equipment_unit_mismatch")
            if state["equipment"][unit_key].get(slot) != equipment_db_key:
                raise EconomyError("equipment_not_selected")
            del state["equipment"][unit_key][slot]
            return {
                "unit": unit_key,
                "equipment": None,
                "previous_equipment": equipment_db_key,
                "scope": row["scope"],
                "slot": row["slot"],
            }

        return self._run_operation(
            operation_id, "clear_equipment", request, apply,
        )

    def unequip_equipment(
        self, operation_id: str, unit_key: str, requested_db_key: str,
    ) -> dict:
        """Clear the authoritative selection in one native equipment group.

        Selecting a unit's shipped/default item is encoded by the native panel
        as one standalone ``unequip`` event.  The event names the comparison
        row retained by the panel, which can lag the authoritative type-9 row.
        Resolve only the trusted unit/scope/slot from that row and remove the
        actual current selection in that group.  The resulting receipt is
        persisted under ``operation_id`` so a delayed retry cannot clear a
        later selection.
        """
        row = self.equipment_by_db_key.get(requested_db_key)
        if row is None:
            raise EconomyError("unknown_equipment")
        slot = self._equipment_slot_key(row)
        request = {"unit": unit_key, "equipment": requested_db_key}

        def apply(state: dict) -> dict:
            if unit_key not in state["units"]:
                raise EconomyError("unit_not_owned")
            if row["source_unit"] != unit_key:
                raise EconomyError("equipment_unit_mismatch")
            current = state["equipment"][unit_key].get(slot)
            if current is not None:
                del state["equipment"][unit_key][slot]
            return {
                "unit": unit_key,
                "equipment": None,
                "previous_equipment": current,
                "requested_equipment": requested_db_key,
                "scope": row["scope"],
                "slot": row["slot"],
            }

        with self._lock:
            if unit_key not in self._state["units"]:
                raise EconomyError("unit_not_owned")
            if row["source_unit"] != unit_key:
                raise EconomyError("equipment_unit_mismatch")
            changed = self._state["equipment"][unit_key].get(slot) is not None
            return self._run_operation(
                operation_id, "unequip_equipment", request, apply,
                advance_saved=changed,
            )

    def update_unit_abilities(
        self,
        operation_id: str,
        unit_key: str,
        *,
        equip_db_key: str | None = None,
        unequip_db_key: str | None = None,
        advance_native_binding: bool = False,
    ) -> dict:
        """Atomically equip, unequip, or swap type-19 unit abilities.

        The WAD has no server-visible conflict-group column.  The native
        picker decides when a replacement is required and emits its old/new
        pair; this method validates both junction identities and commits the
        pair in one durable operation without inventing a grouping rule.
        """
        if equip_db_key is None and unequip_db_key is None:
            raise EconomyError("invalid_unit_ability_update")
        if (type(advance_native_binding) is not bool
                or (advance_native_binding
                    and (equip_db_key is None or unequip_db_key is not None))):
            raise EconomyError("invalid_unit_ability_update")
        equip = (
            self.unit_abilities_by_db_key.get(equip_db_key)
            if equip_db_key is not None else None
        )
        unequip = (
            self.unit_abilities_by_db_key.get(unequip_db_key)
            if unequip_db_key is not None else None
        )
        if equip_db_key is not None and equip is None:
            raise EconomyError("unknown_unit_ability")
        if unequip_db_key is not None and unequip is None:
            raise EconomyError("unknown_unit_ability")
        if any(row is not None and row["unit"] != unit_key
               for row in (equip, unequip)):
            raise EconomyError("unit_ability_unit_mismatch")
        if equip_db_key == unequip_db_key and equip_db_key is not None:
            raise EconomyError("invalid_unit_ability_swap")
        request = {
            "unit": unit_key,
            "equip": equip_db_key,
            "unequip": unequip_db_key,
        }
        if advance_native_binding:
            # A new native picker gesture may need to bind an already-owned
            # type-19 row to a different deployed occurrence.  Keep that
            # transport-only acknowledgement distinct in the durable digest;
            # ordinary callers retain the historical no-op watermark behavior.
            request["advance_native_binding"] = True

        def apply(state: dict) -> dict:
            if unit_key not in state["units"]:
                raise EconomyError("unit_not_owned")
            selected = state["unit_abilities"][unit_key]
            if unequip_db_key is not None and unequip_db_key not in selected:
                raise EconomyError("unit_ability_not_selected")
            if equip is not None:
                required = equip["alias_unit"]
                if required and required not in state["units"]:
                    raise EconomyError("unit_ability_required_unit_not_owned")
            result = set(selected)
            if unequip_db_key is not None:
                result.remove(unequip_db_key)
            if equip_db_key is not None:
                result.add(equip_db_key)
            state["unit_abilities"][unit_key] = sorted(result)
            return {
                "unit": unit_key,
                "equipped_ability": equip_db_key,
                "unequipped_ability": unequip_db_key,
                "abilities": copy.deepcopy(state["unit_abilities"][unit_key]),
            }

        with self._lock:
            normalized_operation = _identifier(operation_id)
            if unit_key not in self._state["units"]:
                raise EconomyError("unit_not_owned")
            before = self._state["unit_abilities"][unit_key]
            is_retry = normalized_operation in self._state["operations"]
            if (not is_retry and unequip_db_key is not None
                    and unequip_db_key not in before):
                raise EconomyError("unit_ability_not_selected")
            after = set(before)
            if unequip_db_key is not None:
                # A completed unequip/swap no longer contains this row when a
                # byte-for-byte retry reaches the receipt replay below.
                after.discard(unequip_db_key)
            if equip_db_key is not None:
                after.add(equip_db_key)
            return self._run_operation(
                normalized_operation, "update_unit_abilities", request, apply,
                advance_saved=(sorted(after) != before
                               or advance_native_binding),
            )

    def bind_unit_ability_pair(
        self, operation_id: str, unit_key: str, db_keys: tuple[str, str],
    ) -> dict:
        """Persist both native Swap bindings in one durable operation.

        Initial default skills can exist only in the native WAD until their
        first reorder. That gesture emits two equip offers rather than an
        unequip/equip replacement. Hotkey positions remain native UI storage.
        """
        if (not isinstance(db_keys, tuple) or len(db_keys) != 2
                or any(not isinstance(key, str) for key in db_keys)
                or db_keys[0] == db_keys[1]):
            raise EconomyError("invalid_unit_ability_swap")
        rows = [self.unit_abilities_by_db_key.get(key) for key in db_keys]
        if any(row is None for row in rows):
            raise EconomyError("unknown_unit_ability")
        if any(row["unit"] != unit_key for row in rows):
            raise EconomyError("unit_ability_unit_mismatch")

        def apply(state: dict) -> dict:
            if unit_key not in state["units"]:
                raise EconomyError("unit_not_owned")
            for row in rows:
                if row["alias_unit"] and row["alias_unit"] not in state["units"]:
                    raise EconomyError("unit_ability_required_unit_not_owned")
            selected = sorted(set(state["unit_abilities"][unit_key]) | set(db_keys))
            state["unit_abilities"][unit_key] = selected
            return {"unit": unit_key, "bound_abilities": list(db_keys),
                    "abilities": list(selected)}

        # Even an already-owned pair needs a fresh watermark to distinguish
        # the next deliberate native binding gesture from this exact retry.
        return self._run_operation(
            operation_id, "bind_unit_ability_pair",
            {"unit": unit_key, "abilities": list(db_keys)}, apply,
        )

    def equip_unit_ability(
        self,
        operation_id: str,
        unit_key: str,
        ability_db_key: str,
        *,
        advance_native_binding: bool = False,
    ) -> dict:
        return self.update_unit_abilities(
            operation_id,
            unit_key,
            equip_db_key=ability_db_key,
            advance_native_binding=advance_native_binding,
        )

    def unequip_unit_ability(
        self, operation_id: str, unit_key: str, ability_db_key: str,
    ) -> dict:
        return self.update_unit_abilities(
            operation_id, unit_key, unequip_db_key=ability_db_key,
        )

    def swap_unit_ability(
        self,
        operation_id: str,
        unit_key: str,
        previous_db_key: str,
        selected_db_key: str,
    ) -> dict:
        return self.update_unit_abilities(
            operation_id, unit_key,
            equip_db_key=selected_db_key,
            unequip_db_key=previous_db_key,
        )

    def select_consumable(
        self,
        operation_id: str,
        commander_key: str,
        deployed_slot: int,
        consumable_db_key: str,
    ) -> dict:
        if type(deployed_slot) is not int or not 0 <= deployed_slot < 3:
            raise EconomyError("invalid_deployed_slot")
        row = self.consumables_by_db_key.get(consumable_db_key)
        if row is None:
            raise EconomyError("unknown_consumable")
        request = {
            "commander": commander_key,
            "deployed_slot": deployed_slot,
            "consumable": consumable_db_key,
        }

        def target(state: dict) -> tuple[str, str]:
            commander = state["commanders"].get(commander_key)
            if commander is None:
                raise EconomyError("commander_not_owned")
            unit_key = commander["equipped_units"][deployed_slot]
            unit = self.units[unit_key]
            capacity = unit.get("num_consumable_slots")
            if unit.get("build_state", "live") != "live":
                raise EconomyError("consumable_not_available_to_unit")
            if row["tier"] != EFFECTIVE_UNIT_TIER:
                raise EconomyError("consumable_tier_mismatch")
            if type(capacity) is not int or capacity <= 0:
                raise EconomyError("consumable_slot_unavailable")
            if consumable_db_key not in self.consumable_keys_by_unit.get(unit_key, set()):
                raise EconomyError("consumable_not_available_to_unit")
            selected = state["consumables"][commander_key][deployed_slot]
            existing = [slot for slot, key in selected.items()
                        if key == consumable_db_key]
            if existing:
                return unit_key, min(existing, key=int)
            empty = [str(slot) for slot in range(capacity)
                     if str(slot) not in selected]
            if empty:
                return unit_key, empty[0]
            # No slot identity is present on the native purchase event. Every
            # currently supported Tier-I--V unit has at most one slot, so a
            # full one-slot picker means replacement of that sole selection.
            if capacity == 1:
                return unit_key, "0"
            raise EconomyError("consumable_slot_ambiguous")

        def apply(state: dict) -> dict:
            unit_key, consumable_slot = target(state)
            selected = state["consumables"][commander_key][deployed_slot]
            previous = selected.get(consumable_slot)
            selected[consumable_slot] = consumable_db_key
            return {
                "commander": commander_key,
                "deployed_slot": deployed_slot,
                "unit": unit_key,
                "consumable": consumable_db_key,
                "previous_consumable": previous,
                "slot": int(consumable_slot),
            }

        with self._lock:
            normalized_operation = _identifier(operation_id)
            digest = _canonical_hash({"kind": "select_consumable", "request": request})
            existing_operation = self._state["operations"].get(normalized_operation)
            if existing_operation is not None:
                if existing_operation["request_hash"] != digest:
                    raise EconomyError("idempotency_conflict")
                return copy.deepcopy(existing_operation["receipt"])
            _unit_key, consumable_slot = target(self._state)
            changed = (self._state["consumables"][commander_key][deployed_slot]
                       .get(consumable_slot) != consumable_db_key)
            return self._run_operation(
                normalized_operation, "select_consumable", request, apply,
                advance_saved=changed,
            )

    def select_consumables(
        self, operation_id: str, commander_key: str, deployed_slot: int,
        consumable_db_keys: list[str], *, expected_saved: int,
    ) -> dict:
        """Install one native multi-consumable purchase in a single commit."""
        if type(deployed_slot) is not int or not 0 <= deployed_slot < 3:
            raise EconomyError("invalid_deployed_slot")
        if (not isinstance(consumable_db_keys, list)
                or not 2 <= len(consumable_db_keys) <= 3
                or any(not isinstance(key, str) for key in consumable_db_keys)
                or len(set(consumable_db_keys)) != len(consumable_db_keys)):
            raise EconomyError("invalid_consumable_batch")
        keys = list(consumable_db_keys)
        request = {"commander": commander_key, "deployed_slot": deployed_slot,
                   "consumables": keys, "expected_saved": expected_saved}

        def apply(state: dict) -> dict:
            if type(expected_saved) is not int or state["saved"] != expected_saved:
                raise EconomyError("consumable_state_changed")
            commander = state["commanders"].get(commander_key)
            if commander is None:
                raise EconomyError("commander_not_owned")
            unit_key = commander["equipped_units"][deployed_slot]
            capacity = self.units[unit_key].get("num_consumable_slots")
            if type(capacity) is not int or len(keys) > capacity:
                raise EconomyError("consumable_slot_unavailable")
            selected = state["consumables"][commander_key][deployed_slot]
            added = []
            for key in keys:
                if key in selected.values():
                    continue
                empty = next((str(slot) for slot in range(capacity)
                              if str(slot) not in selected), None)
                if empty is None:
                    raise EconomyError("consumable_slot_ambiguous")
                selected[empty] = key
                added.append(key)
            # Validate the complete candidate before _run_operation performs
            # its one durable write. A bad last row cannot save earlier rows.
            self._validate_consumable_selections(unit_key, selected)
            return {"commander": commander_key, "deployed_slot": deployed_slot,
                    "unit": unit_key, "consumables": keys, "added": added,
                    "saved_before": expected_saved}

        return self._run_operation(
            operation_id, "select_consumables", request, apply,
        )

    def clear_consumable(
        self,
        operation_id: str,
        commander_key: str,
        deployed_slot: int,
        consumable_db_key: str,
    ) -> dict:
        if type(deployed_slot) is not int or not 0 <= deployed_slot < 3:
            raise EconomyError("invalid_deployed_slot")
        row = self.consumables_by_db_key.get(consumable_db_key)
        if row is None:
            raise EconomyError("unknown_consumable")
        request = {
            "commander": commander_key,
            "deployed_slot": deployed_slot,
            "consumable": consumable_db_key,
        }

        def target(state: dict) -> tuple[str, str]:
            commander = state["commanders"].get(commander_key)
            if commander is None:
                raise EconomyError("commander_not_owned")
            unit_key = commander["equipped_units"][deployed_slot]
            unit = self.units[unit_key]
            if (unit.get("build_state", "live") != "live"
                    or row["tier"] != EFFECTIVE_UNIT_TIER
                    or consumable_db_key not in self.consumable_keys_by_unit.get(
                        unit_key, set()
                    )):
                raise EconomyError("consumable_not_available_to_unit")
            selected = state["consumables"][commander_key][deployed_slot]
            slots = [slot for slot, key in selected.items()
                     if key == consumable_db_key]
            if not slots:
                raise EconomyError("consumable_not_selected")
            return unit_key, min(slots, key=int)

        def apply(state: dict) -> dict:
            unit_key, consumable_slot = target(state)
            del state["consumables"][commander_key][deployed_slot][consumable_slot]
            return {
                "commander": commander_key,
                "deployed_slot": deployed_slot,
                "unit": unit_key,
                "consumable": None,
                "previous_consumable": consumable_db_key,
                "slot": int(consumable_slot),
            }

        return self._run_operation(
            operation_id, "clear_consumable", request, apply,
        )

    # ---- frozen PvE roster and exactly-once settlement ---------------------

    @staticmethod
    def _legacy_roster_hash(
        commander_key: str, unit_keys: list[str], battle_tier: int,
    ) -> str:
        return _canonical_hash({"commander": commander_key, "units": unit_keys,
                                "battle_tier": battle_tier, "policy": "highest_deployed_unit"})

    def _roster_hash(
        self,
        commander_key: str,
        unit_keys: list[str],
        battle_tier: int,
        unit_loadouts: list[dict],
    ) -> str:
        return _canonical_hash({
            "commander": commander_key,
            "units": unit_keys,
            "unit_loadouts": unit_loadouts,
            "battle_tier": battle_tier,
            "policy": "highest_deployed_unit_with_persisted_loadout_v1",
        })

    def _battle_loadout_locked(self, commander_key: str) -> dict:
        commander_state = self._state["commanders"].get(commander_key)
        if commander_state is None:
            raise EconomyError("commander_not_owned")
        selected = list(commander_state["equipped_units"])
        # ``tier`` in the native catalog remains the shipped progression/tree
        # identity.  Battle allocation uses the sandbox combat tier instead so
        # the economy snapshot agrees with NativeMatchmaking for every roster.
        effective_tiers = [
            self.units[key]["effective_tier"] for key in selected
        ]
        battle_tier = max(effective_tiers)
        unit_loadouts = [{
            "equipment": copy.deepcopy(self._state["equipment"][key]),
            "consumables": copy.deepcopy(
                self._state["consumables"][commander_key][slot]
            ),
            "abilities": copy.deepcopy(self._state["unit_abilities"][key]),
        } for slot, key in enumerate(selected)]
        return {
            "commander": commander_key,
            "commander_item_id": self.commanders[commander_key]["item_id"],
            "faction": self.commanders[commander_key]["faction"],
            "commander_tier": commander_state["tier"],
            "units": [{
                "slot": slot,
                "instance_id": self.slot_instances[(commander_key, slot)],
                "key": key,
                "item_id": self.units[key]["item_id"],
                "tier": effective_tiers[slot],
                "faction": self.units[key]["faction"],
                "equipment": copy.deepcopy(unit_loadouts[slot]["equipment"]),
                "consumables": copy.deepcopy(unit_loadouts[slot]["consumables"]),
                "abilities": copy.deepcopy(unit_loadouts[slot]["abilities"]),
            } for slot, key in enumerate(selected)],
            "battle_tier": battle_tier,
            "enemy_tier": battle_tier,
            "tier_policy": "highest_deployed_unit",
            "roster_hash": self._roster_hash(
                commander_key, selected, battle_tier, unit_loadouts,
            ),
        }

    def battle_loadout(self, commander_key: str | None = None) -> dict:
        with self._lock:
            return copy.deepcopy(self._battle_loadout_locked(commander_key or self._state["active_commander"]))

    @staticmethod
    def _battle_operation(prefix: str, match_id: str) -> str:
        return f"{prefix}:{hashlib.sha256(match_id.encode('utf-8')).hexdigest()[:40]}"

    def begin_battle(self, match_id: str, *, reward_policy: str) -> dict:
        match_id = _identifier(match_id, "invalid_match_id")
        if reward_policy not in REWARD_POLICIES:
            raise EconomyError("invalid_reward_policy")
        with self._lock:
            existing_battle = self._state["battles"].get(match_id)
            if existing_battle is not None:
                if existing_battle["reward_policy"] != reward_policy:
                    raise EconomyError("battle_reward_policy_mismatch")
                entry = self._state["operations"].get(existing_battle["begin_operation"])
                if entry is None:
                    raise EconomyError("invalid_battle_operation")
                existing_receipt = entry.get("receipt")
                if not isinstance(existing_receipt, dict):
                    raise EconomyError("invalid_battle_operation")
                existing_zero = existing_receipt.get("zero_rewards", False)
                if (type(existing_zero) is not bool
                        or (existing_zero and reward_policy != "pve")):
                    raise EconomyError("invalid_battle_operation")
                return copy.deepcopy(entry["receipt"])
            loadout = self._battle_loadout_locked(self._state["active_commander"])
            selected = [row["key"] for row in loadout["units"]]
            unit_loadouts = [{
                "equipment": copy.deepcopy(row["equipment"]),
                "consumables": copy.deepcopy(row["consumables"]),
                "abilities": copy.deepcopy(row["abilities"]),
            } for row in loadout["units"]]
            operation_id = self._battle_operation(f"{reward_policy}_begin", match_id)
            zero_rewards = (
                reward_policy == "pve" and self.zero_pve_rewards
            )
            request = {"match_id": match_id, "commander": loadout["commander"],
                       "units": selected, "unit_loadouts": unit_loadouts,
                       "roster_hash": loadout["roster_hash"]}

            def apply(state: dict) -> dict:
                if match_id in state["battles"]:
                    raise EconomyError("battle_already_exists")
                state["battles"][match_id] = {
                    "commander": loadout["commander"], "units": selected,
                    "unit_loadouts": unit_loadouts,
                    "battle_tier": loadout["battle_tier"], "roster_hash": loadout["roster_hash"],
                    "reward_policy": reward_policy,
                    "status": "pending", "outcome": None, "verified": None,
                    "begin_operation": operation_id, "settlement_operation": None,
                }
                result = {"match_id": match_id, "loadout": loadout}
                if zero_rewards:
                    result["zero_rewards"] = True
                result.update(self._battle_begin_reward_metadata(state, reward_policy))
                return result

            # The frozen roster is durable authority for settlement, but it is
            # not projected into the native profile.  Advancing the profile
            # watermark here made a client that had just queued appear stale
            # before it had earned or changed anything.
            return self._run_operation(
                operation_id, f"begin_{reward_policy}", request, apply,
                advance_saved=False,
            )

    def register_settlement_award(self, match_id: str, amounts: dict, *,
                                  authority: str) -> dict:
        """Pre-authorize the exact amounts the next settlement must apply.

        ``settle_battle`` normally derives amounts from ``reward_quote``.  When
        a remote authority owns them (the Cloudflare Worker applies the mode
        multiplier and the AFK/abort zeroing, see
        ``private-server/src/settlement.ts``), the caller registers them here
        first and the very next *first-time* settlement of that match consumes
        the record.  An idempotent replay returns the stored receipt without
        ever reaching it, so a second Worker reply cannot re-award.
        """
        match_id = _identifier(match_id, "invalid_match_id")
        if not isinstance(amounts, dict) or set(amounts) != set(REWARD_AMOUNT_FIELDS):
            raise EconomyError("invalid_settlement_award")
        award = {key: _plain_int(amounts[key]) for key in REWARD_AMOUNT_FIELDS}
        if (not isinstance(authority, str) or not 1 <= len(authority) <= 64
                or any(ord(char) < 32 or ord(char) > 126 for char in authority)):
            raise EconomyError("invalid_settlement_authority")
        record = {"amounts": award, "authority": authority}
        with self._lock:
            self._pending_awards[match_id] = record
        return copy.deepcopy(record)

    def discard_settlement_award(self, match_id: str) -> None:
        with self._lock:
            self._pending_awards.pop(match_id, None)

    def begin_pve(self, match_id: str) -> dict:
        return self.begin_battle(match_id, reward_policy="pve")

    def begin_pvp(self, match_id: str) -> dict:
        return self.begin_battle(match_id, reward_policy="pvp")

    def settle_battle(
        self,
        match_id: str,
        outcome: str,
        roster_hash: str,
        *,
        verified: bool,
        reward_policy: str,
    ) -> dict:
        match_id = _identifier(match_id, "invalid_match_id")
        if outcome not in OUTCOMES:
            raise EconomyError("invalid_battle_outcome")
        if not isinstance(roster_hash, str) or not HEX_256.fullmatch(roster_hash):
            raise EconomyError("invalid_roster_hash")
        if type(verified) is not bool:
            raise EconomyError("invalid_battle_verification")
        if reward_policy not in REWARD_POLICIES:
            raise EconomyError("invalid_reward_policy")
        operation_id = self._battle_operation(f"{reward_policy}_settle", match_id)
        request = {"match_id": match_id, "outcome": outcome,
                   "roster_hash": roster_hash, "verified": verified}

        def apply(state: dict) -> dict:
            battle = state["battles"].get(match_id)
            if battle is None:
                raise EconomyError("battle_not_found")
            if battle["status"] != "pending":
                raise EconomyError("battle_already_settled")
            if battle["reward_policy"] != reward_policy:
                raise EconomyError("battle_reward_policy_mismatch")
            begin_entry = state["operations"].get(battle["begin_operation"])
            begin_receipt = (
                begin_entry.get("receipt")
                if isinstance(begin_entry, dict) else None
            )
            if not isinstance(begin_receipt, dict):
                raise EconomyError("invalid_battle_operation")
            zero_rewards = begin_receipt.get("zero_rewards", False)
            if type(zero_rewards) is not bool:
                raise EconomyError("invalid_battle_operation")
            if (zero_rewards
                    and (reward_policy != "pve"
                         or begin_receipt.get("kind") != "begin_pve")):
                raise EconomyError("invalid_battle_operation")
            if battle["roster_hash"] != roster_hash:
                raise EconomyError("roster_hash_mismatch")
            quote = self.reward_quote(
                battle["battle_tier"], outcome, verified,
                reward_policy=reward_policy,
            )
            if zero_rewards:
                quote = {
                    **quote,
                    **{key: 0 for key in REWARD_AMOUNT_FIELDS},
                }
            award = self._pending_awards.get(match_id)
            if award is not None:
                # The authority replaces amounts only.  Roster, Tier, outcome
                # verification and the exactly-once rule stay local.
                quote = {**quote, **award["amounts"]}
            quote = self._adjust_local_reward_quote(
                state, battle, begin_receipt, outcome, verified,
                reward_policy, quote, award,
            )
            unit_rewards = {}
            for unit_key in sorted(set(battle["units"])):
                amount = quote["unit_xp_cents"]
                state["units"][unit_key]["unit_xp_cents"] = _checked_add(
                    state["units"][unit_key]["unit_xp_cents"], amount)
                unit_rewards[unit_key] = amount
            commander = state["commanders"][battle["commander"]]
            previous_tier = commander["tier"]
            commander["commander_xp_cents"] = _checked_add(
                commander["commander_xp_cents"], quote["commander_xp_cents"])
            commander["tier"] = self.commander_tier_for_xp(commander["commander_xp_cents"])
            previous_total = self._talent_total(battle["commander"], previous_tier)
            current_total = self._talent_total(battle["commander"], commander["tier"])
            commander["talent_points"] = _checked_add(
                commander["talent_points"], current_total - previous_total,
            )
            for currency in ("free_xp_cents", "silver_cents"):
                state["wallet"][currency] = _checked_add(state["wallet"][currency], quote[currency])
            # Daily missions are retained as read-compatible legacy state, but
            # no longer advance or award from battle settlement.
            daily_awards: list[dict] = []
            daily_gold = 0
            battle.update({"status": "settled", "outcome": outcome, "verified": verified,
                           "settlement_operation": operation_id})
            details = {
                "match_id": match_id, "outcome": outcome, "verified": verified,
                "battle_tier": battle["battle_tier"], "roster_hash": roster_hash,
                "rewards": {**quote, "gold_cents": daily_gold,
                            "unit_xp_by_unit": unit_rewards},
                "daily_quests": daily_awards,
                "commander": battle["commander"], "commander_tier_before": previous_tier,
                "commander_tier_after": commander["tier"],
                "balances": {"free_xp_cents": state["wallet"]["free_xp_cents"],
                             "silver_cents": state["wallet"]["silver_cents"],
                             "gold_cents": state["wallet"]["gold_cents"]},
            }
            if award is not None:
                details["reward_authority"] = award["authority"]
            return details

        receipt = self._run_operation(
            operation_id, f"settle_{reward_policy}", request, apply,
        )
        # Only a durable settlement consumes the award; a rejected write keeps
        # it so the reload-and-retry path applies the same authorized amounts.
        self.discard_settlement_award(match_id)
        return receipt

    def _battle_begin_reward_metadata(self, state: dict, reward_policy: str) -> dict:
        """Frozen receipt metadata for optional local reward policies."""
        return {}

    def _adjust_local_reward_quote(
        self, state: dict, battle: dict, begin_receipt: dict,
        outcome: str, verified: bool, reward_policy: str,
        quote: dict, award: dict | None,
    ) -> dict:
        """Optional local-only quote adjustment; remote awards stay authoritative."""
        return quote

    def settle_pve(
        self,
        match_id: str,
        outcome: str,
        roster_hash: str,
        *,
        verified: bool,
    ) -> dict:
        return self.settle_battle(
            match_id, outcome, roster_hash,
            verified=verified, reward_policy="pve",
        )

    def settle_pvp(
        self,
        match_id: str,
        outcome: str,
        roster_hash: str,
        *,
        verified: bool,
    ) -> dict:
        return self.settle_battle(
            match_id, outcome, roster_hash,
            verified=verified, reward_policy="pvp",
        )

    # ---- projection for the existing native profile builder ---------------

    def legacy_progression(self) -> dict:
        """Return the v1 Tier/ability/loadout shape for owned commanders.

        The current ``build_profile`` still grants every commander root.  A
        later native adapter must use ``snapshot()['commanders']`` as the
        actual ownership authority; this projection only supplies progression
        records without weakening the v2 economy checks.
        """
        with self._lock:
            result: dict[str, dict] = {}
            for commander_key, commander_state in self._state["commanders"].items():
                tier = commander_state["tier"]
                available = [key for key in self._state["units"]
                             if self.units[key]["faction"] == self.commanders[commander_key]["faction"]
                             and key in self.reachable[commander_key] and self.units[key]["tier"] <= tier]
                result[commander_key] = {
                    "tier": tier,
                    "abilities": copy.deepcopy(commander_state["abilities"]),
                    "talent_points": commander_state["talent_points"],
                    "equipped_units": list(commander_state["equipped_units"]),
                    "unlocked_units": sorted(available),
                }
            return {"schema_version": 1, "commanders": result}
