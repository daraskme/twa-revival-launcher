"""Native profile and purchase-event adapter for :mod:`local_economy`.

``LocalEconomy`` owns every balance, unlock and price.  This module only
translates that trusted state to the numeric profile graph consumed by the
original client, and translates the client's purchase-event wire shape back
to catalogue keys.  Client supplied item IDs, prices and prerequisite units
are never used as authority.

The adapter deliberately has no HTTP or ``local_stack`` dependency.  A
handler can pass the decoded inner ``request`` object to
``handle_purchase_request`` and wrap the returned object with ``ca_envelope``.
"""
from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from f2p_fake import build_catalogue as build_legacy_catalogue
from f2p_fake import build_profile as build_legacy_profile
from f2p_fake import build_mappings as build_legacy_mappings
from f2p_fake import (
    COMMANDER_TRIAL_TOKEN_ITEM_ID,
    COMMANDER_TRIAL_TOKEN_KEY,
    numeric_ids_by_type_and_key,
    require_uint64,
)
from local_economy import (
    EFFECTIVE_UNIT_TIER,
    EconomyError,
    LocalEconomy,
    NATIVE_SAVED_FLOOR,
    WALLET_CURRENCIES,
)
from native_equipment import (
    load_native_unit_equipment,
    validate_native_unit_equipment,
)
from native_consumables import (
    load_native_battle_consumables,
    tier_equivalent_consumables_by_unit,
    tier_equivalent_service_definitions,
    validate_native_battle_consumables,
)
from native_commander_talents import (
    load_native_commander_talents,
    talent_rows_by_commander,
    validate_native_commander_talents,
)
from native_unit_abilities import (
    ITEM_TYPE as UNIT_ABILITY_ITEM_TYPE,
    load_native_unit_abilities,
    validate_native_unit_abilities,
)


UINT64_MAX = 2**64 - 1

_EVENT_FIELDS = {
    "parent_id",
    "po",
    "po_quantity",
    "currency_instance_id",
    "receiving_instance_id",
}
_REQUEST_FIELDS = {"profile_timestamp", "events"}
_OPTIONAL_REQUEST_FIELDS = {"active_commander", "active_title"}


def _uint64(value: object, code: str, *, allow_zero: bool = True) -> int:
    minimum = 0 if allow_zero else 1
    if type(value) is not int or not minimum <= value <= UINT64_MAX:
        raise EconomyError(code)
    return value


def _stable_instance(label: str, occupied: set[int]) -> int:
    """Allocate the same nonzero uint64 for the same canonical label."""
    value = int.from_bytes(hashlib.sha256(label.encode("utf-8")).digest()[:8], "little")
    while value == 0 or value in occupied:
        value = (value + 1) % 2**64
    occupied.add(value)
    return value


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                         allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class NativeEconomyAdapter:
    """Project one authoritative local account onto the native CA schemas."""

    def __init__(
        self,
        economy: LocalEconomy,
        catalog: dict,
        official: dict,
        native: dict,
    ) -> None:
        if not isinstance(economy, LocalEconomy):
            raise TypeError("economy must be LocalEconomy")
        if not all(isinstance(value, dict) for value in (catalog, official, native)):
            raise TypeError("catalog, official and native must be objects")
        self.economy = economy
        self.catalog = copy.deepcopy(catalog)
        self.official = copy.deepcopy(official)
        self.native = copy.deepcopy(native)
        self.equipment = validate_native_unit_equipment(
            economy.native_equipment, self.native,
        )
        self.commander_talents = validate_native_commander_talents(
            load_native_commander_talents(), self.native,
        )
        self.talent_rows = talent_rows_by_commander(self.commander_talents)
        self.unit_abilities = validate_native_unit_abilities(
            load_native_unit_abilities(), self.native, self.official,
        )
        self.unit_abilities_by_db_key = {
            row["db_key"]: row for row in self.unit_abilities["items"]
            if row["mode"] in {"additional", "default"}
        }
        self.unit_ability_by_option: dict[str, tuple[str, dict]] = {}
        for row in self.unit_abilities_by_db_key.values():
            for action in ("equip", "unequip"):
                option = f"{action}_ability_{row['db_key']}"
                if option in self.unit_ability_by_option:
                    raise ValueError(
                        f"Duplicate native unit-ability option: {option}"
                    )
                self.unit_ability_by_option[option] = (action, row)

        # ``items`` is the historical unit-tree junction set.  Schema v2 also
        # publishes every initially owned Tier-I--V equipment row.  Keep the
        # historical rows first so their instance allocation, and every
        # wallet/unit-XP identity allocated before them, remains unchanged.
        # Cross-list aliases must describe the same native item; a reused item
        # or key with conflicting identity fails before any profile is built.
        equipment_by_key: dict[str, dict] = {}
        equipment_key_by_item: dict[int, str] = {}
        initial_only: list[dict] = []
        higher_only: list[dict] = []
        for collection_name in (
            "items", "initial_nonpremium_tier_1_to_5", "all_live_nonpremium",
        ):
            for row in self.equipment[collection_name]:
                key = row["db_key"]
                item_id = require_uint64(row["item_id"])
                previous = equipment_by_key.get(key)
                if previous is not None:
                    if (previous["item_id"] != item_id
                            or previous["equipment_key"] != row["equipment_key"]
                            or previous["source_unit"] != row["source_unit"]):
                        raise ValueError(f"Conflicting native equipment alias: {key}")
                    continue
                prior_key = equipment_key_by_item.get(item_id)
                if prior_key is not None and prior_key != key:
                    raise ValueError(
                        f"Native equipment item ID collision: {prior_key}, {key}"
                    )
                equipment_by_key[key] = row
                equipment_key_by_item[item_id] = key
                if collection_name != "items":
                    if collection_name == "initial_nonpremium_tier_1_to_5":
                        initial_only.append(row)
                    else:
                        higher_only.append(row)
        self._initial_only_equipment = initial_only
        self._higher_only_equipment = higher_only
        self.equipment_by_db_key = {
            row["db_key"]: row
            for row in self.equipment["all_live_nonpremium"]
        }
        if len(self.equipment_by_db_key) != len(
                self.equipment["all_live_nonpremium"]):
            raise ValueError("Native selectable equipment keys must be unique")
        self.equipment_by_option: dict[str, tuple[str, dict]] = {}
        for row in self.equipment_by_db_key.values():
            for action in ("equip", "unequip"):
                option = f"{action}_{row['source_unit']}_{row['equipment_key']}"
                if option in self.equipment_by_option:
                    raise ValueError(f"Duplicate native equipment option: {option}")
                self.equipment_by_option[option] = (action, row)

        ids = numeric_ids_by_type_and_key(self.official)
        needed_currencies = set(WALLET_CURRENCIES) | {
            "commander_xp_cents",
            "unit_xp_cents",
        }
        try:
            self.currency_item_ids = {
                currency: require_uint64(ids[("arena_currencies", currency)])
                for currency in sorted(needed_currencies)
            }
        except KeyError as exc:
            raise ValueError(f"Missing native currency mapping: {exc.args[0][1]}") from exc
        self.commander_trial_item_id = require_uint64(
            ids.get(("arena_tokens", COMMANDER_TRIAL_TOKEN_KEY))
        )
        if self.commander_trial_item_id != COMMANDER_TRIAL_TOKEN_ITEM_ID:
            raise ValueError("Invalid native commander trial token mapping")
        for commander_key, row in self.talent_rows.items():
            if ids.get(("arena_commander_talent_points", commander_key)) != row["item_id"]:
                raise ValueError(
                    f"Missing native commander talent mapping: {commander_key}"
                )
        for row in equipment_by_key.values():
            mapped = ids.get(("arena_unit_equipment_trees", row["db_key"]))
            if mapped != row["item_id"]:
                raise ValueError(f"Missing native equipment mapping: {row['db_key']}")
            definition = ids.get(("arena_unit_equipments", row["equipment_key"]))
            if definition != row["equipment_item_id"]:
                raise ValueError(
                    f"Missing native equipment-definition mapping: {row['equipment_key']}"
                )
        for row in self.unit_abilities["items"]:
            if ids.get((UNIT_ABILITY_ITEM_TYPE, row["db_key"])) != row["item_id"]:
                raise ValueError(
                    f"Missing native unit-ability mapping: {row['db_key']}"
                )
        self.consumables = validate_native_battle_consumables(
            load_native_battle_consumables(), self.native, self.official,
        )
        self.consumables_by_unit = tier_equivalent_consumables_by_unit(
            self.native, EFFECTIVE_UNIT_TIER, self.consumables,
        )
        definitions = tier_equivalent_service_definitions(
            self.native, EFFECTIVE_UNIT_TIER, self.consumables,
        )
        self.consumables_by_db_key = {
            row["db_key"]: row for row in definitions
        }
        if len(self.consumables_by_db_key) != len(definitions):
            raise ValueError("Native consumable keys must be unique")
        ability_counts: dict[str, int] = {}
        for row in self.unit_abilities["items"]:
            ability_counts[row["unit"]] = ability_counts.get(row["unit"], 0) + 1
        cleanup_bounds = []
        for unit_key, unit in economy.units.items():
            capacity = unit.get("num_consumable_slots")
            if type(capacity) is not int or not 0 <= capacity <= 10:
                raise ValueError("Invalid native consumable slot capacity")
            cleanup_bounds.append(ability_counts.get(unit_key, 0) + capacity)
        if not cleanup_bounds or not 1 <= max(cleanup_bounds) <= 100:
            raise ValueError("Invalid native unit cleanup bound")
        # Bound against every validated junction row, including stock default
        # abilities, rather than merely the four rows visible in the latest
        # live request.  Exact cleanup proof below remains restricted to rows
        # present in the durable before-image and published cleanup offers.
        # Bound the exceptional old-child cleanup batch from that trusted
        # catalogue plus the unit's native consumable capacity.  Ordinary
        # purchases remain capped at three after cleanup classification.
        self.max_unit_change_cleanup_events = max(cleanup_bounds)
        rank_counts: dict[str, int] = {}
        for level in economy.ability_levels_by_key.values():
            commander = level["commander"]
            rank_counts[commander] = rank_counts.get(commander, 0) + 1
        self.max_ability_tree_reset_events = max(rank_counts.values())
        self.max_unit_change_cleanup_emissions = (
            3 * self.max_unit_change_cleanup_events
        )
        self.ability_levels_by_item = {
            require_uint64(row["item_id"]): copy.deepcopy(row)
            for row in economy.ability_levels_by_key.values()
        }
        if len(self.ability_levels_by_item) != len(economy.ability_levels_by_key):
            raise ValueError("Native commander ability level IDs must be unique")

        occupied = {
            require_uint64(row["item_id"])
            for row in self.official.get("item_mappings", [])
            if isinstance(row, dict) and row.get("item_id") is not None
        }
        for kind in ("commanders", "units", "abilities", "ability_levels", "commander_tiers"):
            for row in self.native.get(kind, []):
                if isinstance(row, dict) and row.get("item_id") is not None:
                    occupied.add(require_uint64(row["item_id"]))
        for row in self.native.get("units", []):
            if isinstance(row, dict) and row.get("strength_item_id") is not None:
                occupied.add(require_uint64(row["strength_item_id"]))
        occupied.update(require_uint64(value) for value in economy.slot_instances.values())

        self.wallet_instances = {
            currency: _stable_instance(f"revival:wallet:{currency}", occupied)
            for currency in sorted(WALLET_CURRENCIES)
        }
        self.unit_xp_instances = {
            unit_key: _stable_instance(f"revival:unit-xp:{unit_key}", occupied)
            for unit_key in sorted(economy.units)
        }
        # Allocate after the established wallet/unit-XP identities so adding
        # equipment cannot perturb their stable instance IDs.
        self.equipment_instances = {
            row["db_key"]: _stable_instance(
                f"revival:unit-equipment:{row['db_key']}", occupied,
            )
            for row in self.equipment["items"]
        }
        # Keep all previously established identities unchanged.  Commander XP
        # retains the position it had when it shipped; consumables are added
        # only afterwards so an upgrade cannot perturb any prior instance ID.
        self.commander_xp_instances = {
            commander_key: _stable_instance(
                f"revival:commander-xp:{commander_key}", occupied,
            )
            for commander_key in sorted(economy.commanders)
        }
        # New schema-v2 initial equipment is allocated only after every
        # pre-v2 identity above.  This prevents a catalogue expansion from
        # renumbering existing commander XP rows in persisted client profiles.
        self.equipment_instances.update({
            row["db_key"]: _stable_instance(
                f"revival:unit-equipment:{row['db_key']}", occupied,
            )
            for row in self._initial_only_equipment
        })
        self.consumable_instances = {
            (commander_key, slot, consumable["db_key"]): _stable_instance(
                f"revival:unit-consumable:{commander_key}:{slot}:"
                f"{consumable['db_key']}", occupied,
            )
            for commander_key in sorted(economy.commanders)
            for slot in range(3)
            for consumable in definitions
        }
        # A type-9 selected definition is a separate child of the owned-unit
        # root. Allocate a stable identity for every possible selection after
        # every pre-existing identity so changing a loadout never renumbers
        # wallets, XP, unlocks or consumables.
        self.selected_equipment_instances = {
            row["db_key"]: _stable_instance(
                f"revival:selected-unit-equipment:{row['db_key']}", occupied,
            )
            for row in self.equipment["initial_nonpremium_tier_1_to_5"]
        }
        # Append post-v2 equipment identities last so every identity already
        # shipped by the local profile stays stable across this expansion.
        self.equipment_instances.update({
            row["db_key"]: _stable_instance(
                f"revival:unit-equipment:{row['db_key']}", occupied,
            )
            for row in self._higher_only_equipment
        })
        self.selected_equipment_instances.update({
            row["db_key"]: _stable_instance(
                f"revival:selected-unit-equipment:{row['db_key']}", occupied,
            )
            for row in self._higher_only_equipment
        })
        # Allocate this new account item after every previously shipped local
        # identity so adding the token cannot renumber existing profile rows.
        self.commander_trial_instance = _stable_instance(
            "revival:token:commander_trial", occupied,
        )
        # Historical tree-junction rows can also be valid live selections.
        # They already had owned-equipment identities before schema v2, but
        # were omitted from the newer type-9 selected-definition allocation
        # when they appeared in ``items`` first.  Append only those missing
        # identities after every shipped allocation (including the trial
        # token), so repairing profile projection cannot renumber anything.
        self.selected_equipment_instances.update({
            row["db_key"]: _stable_instance(
                f"revival:selected-unit-equipment:{row['db_key']}", occupied,
            )
            for row in self.equipment["all_live_nonpremium"]
            if row["db_key"] not in self.selected_equipment_instances
        })
        # Type-19 rows are the newest persisted identity.  Allocate them only
        # after every previously shipped local instance so this catalogue
        # expansion cannot renumber wallets, XP, equipment, or consumables.
        self.unit_ability_instances = {
            row["db_key"]: _stable_instance(
                f"revival:selected-unit-ability:{row['db_key']}", occupied,
            )
            for row in self.unit_abilities_by_db_key.values()
        }
        # Live type-19 rows are children of the commander-slot deployed unit,
        # not of the parentless owned-unit record.  Keep the historical global
        # identities allocated above, then allocate stable per-slot identities
        # so a commander may legally deploy the same unit in multiple slots.
        self.deployed_unit_ability_instances = {}
        for commander_key in sorted(economy.commanders):
            for slot in range(3):
                for row in sorted(
                        self.unit_abilities_by_db_key.values(),
                        key=lambda value: value["db_key"]):
                    if row["unit"] not in economy.reachable[commander_key]:
                        continue
                    key = (commander_key, slot, row["db_key"])
                    self.deployed_unit_ability_instances[key] = _stable_instance(
                        "revival:deployed-unit-ability:"
                        f"{commander_key}:{slot}:{row['db_key']}", occupied,
                    )
        self._unit_by_xp_instance = {
            instance: unit_key for unit_key, instance in self.unit_xp_instances.items()
        }
        self._deployed_by_instance = {
            require_uint64(instance): (commander_key, slot)
            for (commander_key, slot), instance in economy.slot_instances.items()
        }

        unit_offers = [economy.unit_offer(key) for key in sorted(economy.units)]
        commander_offers = [offer for key in sorted(economy.commanders)
                            for offer in economy.commander_offers(key)]
        commander_tier_offers = [
            economy.commander_tier_offer(key, tier)
            for key in sorted(economy.commanders)
            for tier in range(2, 11)
        ]
        ability_offers = [
            economy.ability_offer(key)
            for key in sorted(economy.ability_levels_by_key)
        ]
        ability_refund_offers = [
            economy.ability_refund_offer(key)
            for key in sorted(economy.ability_levels_by_key)
        ]
        equipment_offers = [{
            "kind": "equipment",
            "id": option,
            "action": action,
            "unit_key": row["source_unit"],
            "equipment_db_key": row["db_key"],
            "equipment_key": row["equipment_key"],
            "item_id": row["equipment_item_id"],
            "currency": "silver_cents",
            "cost": 0,
        } for option, (action, row) in self.equipment_by_option.items()]
        equipment_unlock_offers = [
            economy.equipment_offer(row["db_key"], currency)
            for row in self.equipment_by_db_key.values()
            if (not economy._is_initial_equipment(row)
                and not getattr(economy, "is_nonresearchable_equipment", lambda _row: False)(row))
            for currency in ("unit_xp_cents", "free_xp_cents")
        ]
        unit_ability_offers = [{
            "kind": "unit_ability",
            "id": option,
            "action": action,
            "unit_key": row["unit"],
            "ability_db_key": row["db_key"],
            "item_id": row["item_id"],
            "currency": "silver_cents",
            "cost": 0,
        } for option, (action, row) in self.unit_ability_by_option.items()]
        consumable_offers = []
        for row in self.consumables_by_db_key.values():
            for currency in ("silver_cents", "gold_cents"):
                consumable_offers.append({
                    "kind": "consumable",
                    "id": f"purchase_consumable_{row['db_key']}{currency}",
                    "consumable_db_key": row["db_key"],
                    "item_id": row["item_id"],
                    "currency": currency,
                    # The revival baseline treats verified battle loadout
                    # choices as unlocked; the option remains currency-shaped
                    # because that is the native picker protocol.
                    "cost": 0,
                })
            consumable_offers.append({
                "kind": "consumable_refund",
                "id": f"refund_consumable_{row['db_key']}silver_cents",
                "consumable_db_key": row["db_key"],
                "item_id": row["item_id"],
                "currency": "silver_cents",
                "cost": 0,
            })
        # Fixed-budget talents are not sold, including to pre-migration clients.
        # Keep historical receipt decoding separate from advertised offers.
        offers = (unit_offers + commander_offers + commander_tier_offers
                  + ability_offers
                  + ability_refund_offers
                  + equipment_offers + equipment_unlock_offers
                  + unit_ability_offers
                  + consumable_offers)
        if len({offer["id"] for offer in offers}) != len(offers):
            raise ValueError("Native purchase option IDs must be unique")
        self.offers = {offer["id"]: copy.deepcopy(offer) for offer in offers}

    def build_mappings(self) -> dict:
        """Publish equipment research costs from the enforced local policy."""
        result = build_legacy_mappings(
            self.catalog, official=self.official,
        )
        rows = result.get("item_mappings")
        if not isinstance(rows, list):
            raise EconomyError("invalid_native_mappings")
        seen: set[str] = set()
        for row in rows:
            if (not isinstance(row, dict)
                    or row.get("type") != "arena_unit_equipment_trees"):
                continue
            db_key = row.get("db_key")
            equipment = self.equipment_by_db_key.get(db_key)
            if equipment is None:
                continue
            if db_key in seen or not isinstance(row.get("metadata"), dict):
                raise EconomyError("invalid_native_mappings")
            seen.add(db_key)
            if self.economy._is_initial_equipment(equipment):
                unit_xp_cost = free_xp_cost = 0
            else:
                unit_xp_cost = self.economy.equipment_offer(
                    db_key, "unit_xp_cents",
                )["cost"]
                free_xp_cost = self.economy.equipment_offer(
                    db_key, "free_xp_cents",
                )["cost"]
            row["metadata"] = {
                **row["metadata"],
                "silver_cents": 0,
                "unit_xp_cents": unit_xp_cost,
                "free_xp_cents": free_xp_cost,
            }
        if seen != set(self.equipment_by_db_key):
            raise EconomyError("missing_native_equipment_mapping")
        return result

    def build_catalogue(self) -> dict:
        return self._build_catalogue_from_snapshot(self.economy.snapshot())

    def _specialization_talent_totals(
        self, snapshot: dict,
    ) -> dict[str, int] | None:
        enabled = getattr(self.economy, "specialization_enabled", None)
        totals = getattr(self.economy, "talent_point_totals", None)
        if not callable(enabled) or not enabled(snapshot):
            return None
        if not callable(totals):
            raise EconomyError("specialization_totals_unavailable")
        result = totals(snapshot)
        expected = set(snapshot["commanders"])
        if (not isinstance(result, dict) or set(result) != expected
                or any(type(key) is not str or type(value) is not int
                       or not 0 <= value <= 2**63 - 1
                       for key, value in result.items())):
            raise EconomyError("invalid_specialization_totals")
        return dict(result)

    def _build_catalogue_from_snapshot(self, snapshot: dict) -> dict:
        """Publish the same progression prices enforced by purchases.

        The extracted current database contains ``100`` as a local sentinel for
        many normal-unit prices.  :class:`LocalEconomy` deliberately replaces
        those values with the versioned revival Tier policy, so serving the raw
        extracted catalogue would make the native UI quote a different amount
        from the one an ``/event`` purchase actually spends.  Commander offers
        also need to remain present even though the playable baseline initially
        owns every commander; this keeps the catalogue complete for restored or
        diagnostic pre-purchase profiles. Commander ability unlock/refund
        offers use their exact native names and the extracted commander-
        specific type-21 pool, so every faction's tree uses the same
        server-enforced one-point rank policy.

        Equipment and consumable options retain their independently validated
        legacy shapes. Only trusted unit, commander and ability offers are
        replaced or added here, and every numeric identity comes from this adapter's
        validated mappings.
        """
        talent_totals = self._specialization_talent_totals(snapshot)
        result = build_legacy_catalogue(
            self.catalog,
            official=self.official,
            native=self.native,
            talent_point_totals=talent_totals,
        )
        options = result.get("purchase_options")
        if not isinstance(options, list):
            raise EconomyError("invalid_native_catalogue")
        # The native client caches this catalogue independently of commander
        # and unit selection.  Publish every already validated Tier-X service
        # consumable as selectable; the purchase handler remains authoritative
        # for the exact deployed parent/unit compatibility.
        visible_consumable_items = {
            row["item_id"] for row in self.consumables_by_db_key.values()
        }
        by_id: dict[str, dict] = {}
        for row in options:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                raise EconomyError("invalid_native_catalogue")
            if row["id"].startswith("purchase_consumable_"):
                compatible = row.get("receiving_item_id") in visible_consumable_items
                silver = row["id"].endswith("silver_cents")
                row = copy.deepcopy(row)
                row["is_visible"] = compatible and silver
                row["allow_from_client"] = compatible
            option_id = row["id"]
            if option_id in by_id:
                raise EconomyError("duplicate_native_purchase_option")
            by_id[option_id] = copy.deepcopy(row)

        authoritative = [
            offer for offer in self.offers.values()
            if offer.get("kind") in {
                "unit", "commander", "ability", "ability_refund",
                "equipment_unlock", "commander_tier", "unit_ability",
                "talent_point",
            }
        ]
        for offer in authoritative:
            option_id = offer["id"]
            item_id = require_uint64(
                offer.get("receiving_item_id")
                if offer["kind"] == "ability_refund"
                else offer["item_id"]
            )
            currency = offer["currency"]
            cost = _uint64(offer["cost"], "invalid_purchase_cost")
            previous = by_id.get(option_id)
            if previous is not None and (
                    previous.get("receiving_item_id") != item_id
                    or previous.get("receiving_quantity") != 1):
                raise EconomyError("native_purchase_option_identity_mismatch")
            by_id[option_id] = {
                "id": option_id,
                "currency_item_id": require_uint64(
                    offer.get("currency_item_id")
                    if currency in {
                        "commander_talent_points", "ability_level",
                    }
                    else self.currency_item_ids[currency]
                ),
                "currency_quantity": cost,
                "receiving_item_id": item_id,
                "receiving_quantity": 1,
                "allow_from_client": True,
                "is_visible": (
                    offer["kind"] != "ability_refund"
                    and not (
                        offer["kind"] == "unit_ability"
                        and offer.get("action") == "unequip"
                    )
                ),
                "metadata": {},
            }

        expected_ids = {offer["id"] for offer in authoritative}
        if not expected_ids <= set(by_id):
            raise EconomyError("missing_native_purchase_option")
        result["purchase_options"] = [
            by_id[key] for key in sorted(by_id)
        ]
        return result

    @staticmethod
    def wire_saved(saved: object) -> int:
        return max(_uint64(saved, "invalid_saved", allow_zero=False), NATIVE_SAVED_FLOOR)

    def wallet_instance_id(self, currency: str) -> int:
        try:
            return self.wallet_instances[currency]
        except KeyError as exc:
            raise EconomyError("invalid_wallet_currency") from exc

    def unit_xp_instance_id(self, unit_key: str) -> int:
        try:
            return self.unit_xp_instances[unit_key]
        except KeyError as exc:
            raise EconomyError("unknown_unit") from exc

    def equipment_instance_id(self, equipment_db_key: str) -> int:
        try:
            return self.equipment_instances[equipment_db_key]
        except KeyError as exc:
            raise EconomyError("unknown_unit_equipment") from exc

    def commander_xp_instance_id(self, commander_key: str) -> int:
        try:
            return self.commander_xp_instances[commander_key]
        except KeyError as exc:
            raise EconomyError("unknown_commander") from exc

    def consumable_instance_id(
        self, commander_key: str, slot: int, consumable_db_key: str,
    ) -> int:
        try:
            return self.consumable_instances[(commander_key, slot, consumable_db_key)]
        except KeyError as exc:
            raise EconomyError("unknown_unit_consumable") from exc

    def selected_equipment_instance_id(self, equipment_db_key: str) -> int:
        try:
            return self.selected_equipment_instances[equipment_db_key]
        except KeyError as exc:
            raise EconomyError("unknown_selected_unit_equipment") from exc

    def unit_ability_instance_id(self, ability_db_key: str) -> int:
        try:
            return self.unit_ability_instances[ability_db_key]
        except KeyError as exc:
            raise EconomyError("unknown_selected_unit_ability") from exc

    def deployed_unit_ability_instance_id(
        self, commander_key: str, slot: int, ability_db_key: str,
    ) -> int:
        try:
            return self.deployed_unit_ability_instances[
                (commander_key, slot, ability_db_key)
            ]
        except KeyError as exc:
            raise EconomyError("unknown_deployed_unit_ability") from exc

    def deployed_slot_for_instance(
        self, instance_id: int,
    ) -> tuple[str, int] | None:
        """Return ``(commander, slot)`` for one deployed-slot instance id."""
        return self._deployed_by_instance.get(instance_id)

    def slot_instance_ids(self, commander_key: str) -> list[int]:
        """The three deployed-slot instance ids, in saved slot order."""
        return [
            require_uint64(self.economy.slot_instances[(commander_key, slot)])
            for slot in range(3)
        ]

    def _selected_equipment_from_snapshot(self, snapshot: dict) -> list[dict]:
        selected: list[dict] = []
        for unit_key in sorted(snapshot["equipment"]):
            choices = snapshot["equipment"][unit_key]
            for group in sorted(choices):
                db_key = choices[group]
                row = self.equipment_by_db_key.get(db_key)
                if (row is None or row["source_unit"] != unit_key
                        or group != f"{row['scope']}:{row['slot']}"):
                    raise EconomyError("invalid_equipment_selection")
                selected.append(row)
        return selected

    def _selected_tree_equipment_from_snapshot(self, snapshot: dict) -> list[dict]:
        """Return the one type-5 row that owns each unit equipment group.

        Type-9 rows carry the explicit 3D/battle definition, but the hangar's
        ``selected_overlay`` does not inspect that map.  C49710 reads the
        selected unit model's type-5 group map instead.  C46410 builds that
        map with first-insertion-wins semantics, so attaching every unlocked
        type-5 row directly to the unit makes an arbitrary catalogue row look
        selected forever.

        Keep every unlocked type-5 profile row globally owned, while linking
        exactly one row per ``(unit, scope, slot)`` directly to the unit.  An
        absent explicit type-9 choice means the shipped free/base item; every
        validated Tier-I--V group has exactly one such row.
        """
        unlocked = set(snapshot.get("unlocked_equipment", []))
        owned = [
            self.equipment_by_db_key[key] for key in sorted(unlocked)
            if key in self.equipment_by_db_key
            and self.equipment_by_db_key[key]["source_unit"] in snapshot["units"]
        ]
        explicit = {
            (row["source_unit"], row["scope"], row["slot"]): row
            for row in self._selected_equipment_from_snapshot(snapshot)
        }
        grouped: dict[tuple[str, str, str], list[dict]] = {}
        for row in owned:
            grouped.setdefault(
                (row["source_unit"], row["scope"], row["slot"]), [],
            ).append(row)

        selected: list[dict] = []
        for group, candidates in sorted(grouped.items()):
            row = explicit.get(group)
            if row is None:
                defaults = [
                    candidate for candidate in candidates
                    if candidate["raw_cost_0"] == 0
                    and candidate["raw_cost_1"] == 0
                ]
                if len(defaults) != 1:
                    raise EconomyError("ambiguous_default_equipment")
                row = defaults[0]
            elif row["db_key"] not in {
                    candidate["db_key"] for candidate in candidates}:
                raise EconomyError("invalid_equipment_selection")
            selected.append(row)
        if not set(explicit) <= set(grouped):
            raise EconomyError("invalid_equipment_selection")
        return selected

    @property
    def selected_equipment(self) -> list[dict]:
        """Return the authoritative current type-9 equipment selections."""
        return self._selected_equipment_from_snapshot(self.economy.snapshot())

    def _owned_native_catalog(self, snapshot: dict) -> dict:
        """Return a builder input containing only economy-owned commanders."""
        owned = set(snapshot["commanders"])
        result = copy.deepcopy(self.native)
        result["commanders"] = [row for row in result.get("commanders", [])
                                if row.get("key") in owned]
        for kind in ("abilities", "ability_levels", "commander_tiers"):
            result[kind] = [row for row in result.get(kind, [])
                            if row.get("commander") in owned]
        if {row.get("key") for row in result["commanders"]
                if row.get("build_state", "live") == "live"} != owned:
            raise EconomyError("owned_commander_missing_from_catalog")
        return result

    def _progression_from_snapshot(self, snapshot: dict) -> dict:
        """Freeze LocalEconomy's legacy projection to the same snapshot."""
        result: dict[str, dict] = {}
        for commander_key, commander_state in snapshot["commanders"].items():
            tier = commander_state["tier"]
            available = [
                unit_key for unit_key in snapshot["units"]
                if (self.economy.units[unit_key]["faction"]
                    == self.economy.commanders[commander_key]["faction"]
                    and unit_key in self.economy.reachable[commander_key]
                    and self.economy.units[unit_key]["tier"] <= tier)
            ]
            result[commander_key] = {
                "tier": tier,
                "abilities": copy.deepcopy(commander_state["abilities"]),
                "talent_points": commander_state["talent_points"],
                "equipped_units": list(commander_state["equipped_units"]),
                "unlocked_units": sorted(available),
            }
        return {"schema_version": 1, "commanders": result}

    def build_profile(self) -> dict:
        """Build the native profile graph from the current economy snapshot.

        Wallet currencies are account roots.  Unit XP is deliberately a child
        of each owned unit's root unlock, because the native unit-tree purchase
        path supplies that child instance as ``currency_instance_id``.
        Commander XP is a child of its owned commander root.
        """
        return self._build_profile_from_snapshot(self.economy.snapshot())

    def _build_profile_from_snapshot(self, snapshot: dict) -> dict:
        commander_order = sorted(snapshot["commanders"])
        owned_native = self._owned_native_catalog(snapshot)
        talent_point_totals = self._specialization_talent_totals(snapshot)
        talent_point_bonuses = (None if talent_point_totals is not None else
            self.economy._proven_local_commander_talent_point_grants(snapshot))
        profile = build_legacy_profile(
            self.catalog,
            self.official,
            owned_native,
            active_key=snapshot["active_commander"],
            progression=self._progression_from_snapshot(snapshot),
            talent_point_bonuses=talent_point_bonuses,
            talent_point_totals=talent_point_totals,
        )
        inner = profile["profile"]
        inner["saved"] = self.wire_saved(snapshot["saved"])
        records = inner["profile_records"]

        instances = {row[2] for row in records}
        if len(instances) != len(records):
            raise EconomyError("duplicate_profile_instance")
        roots = {row[1]: row[2] for row in records if row[0] == 0 and row[3] > 0}

        additions: list[list[int]] = []
        for currency in sorted(WALLET_CURRENCIES):
            instance = self.wallet_instances[currency]
            additions.append([
                0,
                self.currency_item_ids[currency],
                instance,
                _uint64(snapshot["wallet"][currency], "invalid_wallet_balance"),
            ])

        # Native code looks up the arena_tokens definition by
        # ``commander_trial`` and then reads this profile model's quantity.
        # A missing model returns the -1 sentinel displayed as 4294967295.
        # The stock client also skips its label formatter for a valid zero;
        # the Revival client patch lets this explicit record render as 0.
        additions.append([
            0,
            self.commander_trial_item_id,
            self.commander_trial_instance,
            0,
        ])

        for unit_key in sorted(snapshot["units"]):
            unit = self.economy.units.get(unit_key)
            if unit is None:
                raise EconomyError("owned_unit_missing_from_catalog")
            item_id = require_uint64(unit["item_id"])
            parent_instance = roots.get(item_id)
            if parent_instance is None:
                raise EconomyError("owned_unit_missing_from_profile")
            additions.append([
                parent_instance,
                self.currency_item_ids["unit_xp_cents"],
                self.unit_xp_instances[unit_key],
                _uint64(snapshot["units"][unit_key]["unit_xp_cents"],
                        "invalid_unit_xp_balance"),
            ])

        # Static native consumer proof: DEB880/DEBA0C resolves the selected
        # commander profile object, then calls C4C220 with that object and the
        # ``commander_xp_cents`` key. C4C220 -> BD5610 searches a type-2
        # commander's child map, and C54CC0 reads the child's quantity at
        # +0x20/+0x24 for the Tier-progress calculation.  The wire parent must
        # therefore be the commander root *instance*, not an account root or
        # commander item ID inferred independently of the profile graph.
        for commander_key in commander_order:
            commander = self.economy.commanders.get(commander_key)
            if commander is None:
                raise EconomyError("owned_commander_missing_from_catalog")
            parent_instance = roots.get(require_uint64(commander["item_id"]))
            if parent_instance is None:
                raise EconomyError("owned_commander_missing_from_profile")
            additions.append([
                parent_instance,
                self.currency_item_ids["commander_xp_cents"],
                self.commander_xp_instances[commander_key],
                _uint64(
                    snapshot["commanders"][commander_key]["commander_xp_cents"],
                    "invalid_commander_xp_balance",
                ),
            ])

        # BD6850 sends each four-number profile row through C4DB40. Native
        # type index 5 selects C4DC0F/C3B470, the equipment constructor, while
        # C4D9A0 supplies the same parent/item/instance/quantity fields used
        # here. Auto-own every enabled initial row whose live, non-premium
        # Tier-I--V source unit is currently owned. Only the current row for
        # each equipment group is a direct child of the unit root. Other
        # unlocked rows remain parentless/global type-5 ownership candidates.
        # BEC480 therefore gives C49710 exactly one silver-frame entry per
        # group without hiding the alternatives from C498F0's global lookup.
        owned_equipment = [
            self.equipment_by_db_key[key]
            for key in sorted(snapshot.get("unlocked_equipment", []))
            if key in self.equipment_by_db_key
            and self.equipment_by_db_key[key]["source_unit"] in snapshot["units"]
        ]
        selected_tree_keys = {
            row["db_key"]
            for row in self._selected_tree_equipment_from_snapshot(snapshot)
        }
        for equipment in owned_equipment:
            source = self.economy.units.get(equipment["source_unit"])
            if source is None:
                raise EconomyError("equipment_source_missing_from_catalog")
            unit_root = roots.get(require_uint64(source["item_id"]))
            if unit_root is None:
                raise EconomyError("equipment_source_missing_from_profile")
            parent_instance = (
                unit_root if equipment["db_key"] in selected_tree_keys else 0
            )
            additions.append([
                parent_instance,
                require_uint64(equipment["item_id"]),
                self.equipment_instances[equipment["db_key"]],
                1,
            ])

        # B33CA0 consumes the unit-root type-5 tree map and C48AB0 consumes
        # its separate type-9 definition map. Keep every unlocked type-5 row
        # above in the profile, but select only the highest placement in each
        # unit slot as one type-9 child. Matchmaking sends the matching pair.
        for equipment in self._selected_equipment_from_snapshot(snapshot):
            if equipment["source_unit"] not in snapshot["units"]:
                continue
            source = self.economy.units[equipment["source_unit"]]
            parent_instance = roots.get(require_uint64(source["item_id"]))
            if parent_instance is None:
                raise EconomyError("equipment_source_missing_from_profile")
            additions.append([
                parent_instance,
                require_uint64(equipment["equipment_item_id"]),
                self.selected_equipment_instance_id(equipment["db_key"]),
                1,
            ])

        # BEB880 consumes a type-11 consumable only when it is directly below
        # the deployed unit. The unit DB row supplies the slot capacity rather
        # than the wire. Equipment remains on the parentless owned-unit root;
        # matchmaking selects one type-5/type-9 pair per slot from that root,
        # so no duplicate deployed-unit equipment record is added here.
        record_by_instance = {row[2]: row for row in records}
        for commander_key in commander_order:
            commander_state = snapshot["commanders"][commander_key]
            commander_item_id = require_uint64(
                self.economy.commanders[commander_key]["item_id"]
            )
            for slot, unit_key in enumerate(commander_state["equipped_units"]):
                unit_instance = self.economy.slot_instances[(commander_key, slot)]
                unit = self.economy.units[unit_key]
                unit_record = record_by_instance.get(unit_instance)
                if unit_record != [
                    commander_item_id,
                    require_uint64(unit["item_id"]),
                    unit_instance,
                    1,
                ]:
                    raise EconomyError("equipped_unit_missing_from_profile")
                for db_key in snapshot["unit_abilities"][unit_key]:
                    ability = self.unit_abilities_by_db_key.get(db_key)
                    if ability is None or ability["unit"] != unit_key:
                        raise EconomyError("invalid_unit_ability_selection")
                    additions.append([
                        unit_instance,
                        require_uint64(ability["item_id"]),
                        self.deployed_unit_ability_instance_id(
                            commander_key, slot, db_key,
                        ),
                        1,
                    ])
                selected_consumables = snapshot["consumables"][commander_key][slot]
                capacity = unit.get("num_consumable_slots")
                if type(capacity) is not int or not 0 <= capacity <= 10:
                    raise EconomyError("invalid_consumable_capacity")
                for consumable_slot in sorted(selected_consumables, key=int):
                    consumable = self.consumables_by_db_key.get(
                        selected_consumables[consumable_slot]
                    )
                    if (consumable is None
                            or not isinstance(consumable_slot, str)
                            or not consumable_slot.isascii()
                            or not consumable_slot.isdigit()
                            or str(int(consumable_slot)) != consumable_slot
                            or not 0 <= int(consumable_slot) < capacity
                            or unit.get("build_state", "live") != "live"
                            or consumable["tier"] != EFFECTIVE_UNIT_TIER
                            or consumable["db_key"] not in {
                                row["db_key"]
                                for row in self.consumables_by_unit.get(unit_key, [])
                            }):
                        raise EconomyError("invalid_consumable_selection")
                    additions.append([
                        unit_instance,
                        require_uint64(consumable["item_id"]),
                        self.consumable_instance_id(
                            commander_key, slot, consumable["db_key"],
                        ),
                        consumable["quantity"],
                    ])

        new_instances = [row[2] for row in additions]
        if (len(new_instances) != len(set(new_instances))
                or instances.intersection(new_instances)):
            raise EconomyError("profile_instance_collision")
        records.extend(additions)
        return profile

    def _validate_request(
        self, request: object, *, validate_current_properties: bool = True,
    ) -> tuple[dict, list[dict], dict]:
        if not isinstance(request, dict):
            raise EconomyError("invalid_purchase_request")
        keys = set(request)
        if (not _REQUEST_FIELDS <= keys
                or not keys <= _REQUEST_FIELDS | _OPTIONAL_REQUEST_FIELDS):
            raise EconomyError("invalid_purchase_request")
        timestamp = _uint64(request.get("profile_timestamp"), "invalid_profile_timestamp")
        snapshot = self.economy.snapshot()
        current = self.wire_saved(snapshot["saved"])
        if timestamp > current:
            raise EconomyError("future_profile_timestamp")
        events = request.get("events")
        # Equipment swaps normally arrive as one atomic unequip/equip pair.
        # A larger form is also emitted by the stock hangar when an old unit
        # carries several abilities and consumables.  Its ceiling is derived
        # from the validated catalogue and unit capacity, not a generic batch
        # allowance.  The
        # cleanup response path proves that larger batch against a durable
        # before-image and a single parent before acknowledging it; arbitrary
        # larger purchase batches still fail closed below. The stock talent
        # reset has its own catalogue-derived ceiling and exact complete-rank
        # proof; it cannot authorize equipment or generic purchase batches.
        if (not isinstance(events, list)
                or not 1 <= len(events) <= max(
                    self.max_unit_change_cleanup_events, self.max_ability_tree_reset_events)
                or any(not isinstance(event, dict) for event in events)):
            raise EconomyError("invalid_purchase_events")
        for event in events:
            if set(event) != _EVENT_FIELDS:
                raise EconomyError("invalid_purchase_event")
            _uint64(event.get("parent_id"), "invalid_purchase_parent")
            _uint64(event.get("currency_instance_id"), "invalid_currency_instance")
            _uint64(event.get("receiving_instance_id"), "invalid_receiving_instance")
            if (type(event.get("po_quantity")) is not int
                    or not 1 <= event["po_quantity"] <= 100):
                raise EconomyError("invalid_purchase_quantity")
            if (not isinstance(event.get("po"), str) or not event["po"]
                    or len(event["po"]) > 256):
                raise EconomyError("invalid_purchase_option")
        if "active_commander" in request:
            _uint64(
                request["active_commander"], "invalid_active_commander",
                allow_zero=False,
            )
        if "active_title" in request:
            _uint64(
                request["active_title"], "invalid_active_title",
                allow_zero=False,
            )
        if validate_current_properties:
            self._validate_optional_properties(request, snapshot)
        return request, events, snapshot

    def _validate_optional_properties(self, request: dict, snapshot: dict) -> None:
        if "active_commander" in request:
            value = _uint64(request["active_commander"], "invalid_active_commander",
                            allow_zero=False)
            expected = require_uint64(self.economy.commanders[snapshot["active_commander"]]["item_id"])
            if value != expected:
                raise EconomyError("active_commander_mismatch")
        if "active_title" in request:
            value = _uint64(request["active_title"], "invalid_active_title", allow_zero=False)
            properties = self._build_profile_from_snapshot(snapshot)["profile"]["properties"]
            titles = {row[3] for row in properties if row[0] == "active_title"}
            if value not in titles:
                raise EconomyError("active_title_mismatch")

    def _resolve_event(self, event: dict) -> tuple[dict, str | None]:
        offer = self.offers.get(event["po"])
        if offer is None:
            raise EconomyError("unknown_purchase_option")
        if offer["kind"] not in {"unit", "commander"}:
            raise EconomyError("invalid_purchase_events")
        # The normal unit path is statically proven at C47E40 -> C56060 ->
        # BD2C30: parent=0, receiving=0, quantity=1.  The playable baseline
        # owns every commander, so its purchase path is unreachable; keep the
        # same zero-only rule fail-closed until a distinct wire shape is proven.
        # This check stays separate from the unit-XP scope resolver.
        if event["po_quantity"] != 1:
            raise EconomyError("invalid_purchase_quantity")
        if event["parent_id"] != 0:
            raise EconomyError("invalid_purchase_parent")
        if event["receiving_instance_id"] != 0:
            raise EconomyError("invalid_receiving_instance")

        currency = offer["currency"]
        if offer["kind"] == "unit" and not offer["is_premium"]:
            source = self._unit_by_xp_instance.get(event["currency_instance_id"])
            if source is None:
                raise EconomyError("invalid_currency_instance")
            if source not in self.economy.parents[offer["unit_key"]]:
                raise EconomyError("invalid_unit_xp_scope")
            return offer, source

        expected = self.wallet_instances.get(currency)
        if expected is None or event["currency_instance_id"] != expected:
            raise EconomyError("invalid_currency_instance")
        return offer, None

    @staticmethod
    def _operation_id(event: dict) -> str:
        return "native-purchase:" + _canonical_hash({key: event[key] for key in sorted(_EVENT_FIELDS)})

    @staticmethod
    def _loadout_operation_id(kind: str, request: dict, events: list[dict]) -> str:
        canonical = [
            {key: event[key] for key in sorted(_EVENT_FIELDS)}
            for event in events
        ]
        # The same selection event is legitimate again after an intervening
        # loadout change. The client's profile timestamp identifies that
        # mutation epoch while keeping a byte-for-byte HTTP retry idempotent.
        return f"native-{kind}:" + _canonical_hash({
            "profile_timestamp": request["profile_timestamp"],
            "events": canonical,
        })

    def _existing_receipt(self, operation_id: str, offer: dict, source: str | None) -> dict | None:
        entry = self.economy.snapshot()["operations"].get(operation_id)
        if entry is None:
            return None
        receipt = entry.get("receipt") if isinstance(entry, dict) else None
        expected_kind = "purchase_unit" if offer["kind"] == "unit" else "purchase_commander"
        if (not isinstance(receipt, dict) or receipt.get("kind") != expected_kind
                or receipt.get("offer_id") != offer["id"]):
            raise EconomyError("idempotency_conflict")
        if offer["kind"] == "unit":
            spent = receipt.get("spent")
            if (receipt.get("unit") != offer["unit_key"] or not isinstance(spent, dict)
                    or spent.get("scope") != ("account" if offer["is_premium"] else source)):
                raise EconomyError("idempotency_conflict")
        elif receipt.get("commander") != offer["commander_key"]:
            raise EconomyError("idempotency_conflict")
        return receipt

    def _apply_purchase(
        self,
        event: dict,
        offer: dict,
        source: str | None,
        active_commander: str,
    ) -> dict:
        operation_id = self._operation_id(event)
        previous = self._existing_receipt(operation_id, offer, source)
        if offer["kind"] == "commander":
            return self.economy.purchase_commander(
                operation_id, offer["commander_key"], offer["currency"]
            )

        if previous is not None:
            commander_key = previous["commander"]
        else:
            commander_key = active_commander
        return self.economy.purchase_unit(
            operation_id,
            commander_key,
            offer["unit_key"],
            parent_unit_key=source,
        )

    def _response_properties(self, request: dict) -> list[list[Any]]:
        result: list[list[Any]] = []
        for key in ("active_commander", "active_title"):
            if key in request:
                result.append([key, 0, 0, request[key]])
        return result

    def _authoritative_resync_response(
        self, request: dict, profile: dict,
    ) -> dict:
        """Return the current graph when replaying an old additive delta."""
        _ = request
        return {
            "result": "ok_resync",
            "profile": profile,
            "saved": profile["saved"],
            "events": [],
            # The embedded current profile owns active commander/title. Never
            # echo stale selection properties from the original request after
            # applying that authoritative graph.
            "properties": [],
        }

    @staticmethod
    def _validate_ability_receipt(receipt: dict, offer: dict) -> dict:
        spent = receipt.get("spent")
        if (receipt.get("commander") != offer["commander_key"]
                or receipt.get("ability_key") != offer["ability_key"]
                or receipt.get("ability_level") != offer["ability_level"]
                or not isinstance(spent, dict)
                or spent.get("currency") != "commander_talent_points"
                or spent.get("amount") != offer["cost"]):
            raise EconomyError("invalid_purchase_receipt")
        return spent

    @staticmethod
    def _validate_ability_refund_receipt(receipt: dict, offer: dict) -> dict:
        refunded = receipt.get("refunded")
        if (receipt.get("commander") != offer["commander_key"]
                or receipt.get("ability_key") != offer["ability_key"]
                or receipt.get("ability_level") != offer["ability_level"]
                or not isinstance(refunded, dict)
                or refunded.get("currency") != "commander_talent_points"
                or refunded.get("amount") != 1):
            raise EconomyError("invalid_purchase_receipt")
        return refunded

    def _ability_retry_response(
        self, request: dict, event: dict, snapshot: dict, offer: dict,
    ) -> dict | None:
        kind = offer["kind"]
        if kind not in {"ability", "ability_refund"}:
            return None
        operation_kind = "ability" if kind == "ability" else "ability-refund"
        operation_id = self._loadout_operation_id(
            operation_kind, request, [event],
        )
        if operation_id not in snapshot["operations"]:
            return None
        if kind == "ability":
            receipt = self.economy.purchase_ability(
                operation_id, offer["level_key"],
            )
            self._validate_ability_receipt(receipt, offer)
        else:
            receipt = self.economy.refund_ability(
                operation_id, offer["level_key"],
            )
            self._validate_ability_refund_receipt(receipt, offer)
        return self._authoritative_resync_response(
            request, self.build_profile()["profile"],
        )

    def _standard_purchase_response(
        self, request: dict, event: dict, snapshot: dict,
    ) -> dict:
        offer, source = self._resolve_event(event)
        receipt = self._apply_purchase(
            event, offer, source, snapshot["active_commander"],
        )
        spent = receipt.get("spent")
        if (not isinstance(spent, dict) or spent.get("currency") != offer["currency"]
                or spent.get("amount") != offer["cost"]):
            raise EconomyError("invalid_purchase_receipt")

        response_event = {
            "currency_quantity": offer["cost"],
            "currency_instance_id": event["currency_instance_id"],
            "currency_item_id": self.currency_item_ids[offer["currency"]],
            "receiving_instance_id": require_uint64(offer["item_id"]),
            "receiving_quantity": 1,
            "receiving_item_id": require_uint64(offer["item_id"]),
        }
        if offer["kind"] == "unit":
            response_event["parent_id"] = 0
        return {
            "result": "ok",
            "saved": self.wire_saved(receipt["saved"]),
            "events": [response_event],
            "properties": self._response_properties(request),
        }

    def _ability_response(
        self, request: dict, event: dict, snapshot: dict,
    ) -> dict:
        """Persist one native commander-tree choice and rebuild its graph."""
        offer = self.offers.get(event["po"])
        if offer is None:
            raise EconomyError("unknown_purchase_option")
        if offer["kind"] != "ability":
            raise EconomyError("invalid_purchase_events")

        commander_key = offer["commander_key"]
        commander_item = require_uint64(
            self.economy.commanders[commander_key]["item_id"]
        )
        before = self._build_profile_from_snapshot(snapshot)["profile"]
        commander_roots = [
            row for row in before["profile_records"]
            if row[0] == 0 and row[1] == commander_item and row[3] > 0
        ]
        if len(commander_roots) != 1:
            raise EconomyError("owned_commander_missing_from_profile")
        commander_instance = require_uint64(commander_roots[0][2])
        # 10C5B380 resolves the exact unlock_ability PO, passes the commander
        # profile object as parent, the PO's currency profile row, quantity 1
        # and a zero receiving instance to 10C56C60. The event serializer maps
        # those fields directly; there is no generic-tree or rank branch here.
        if event["parent_id"] != commander_instance:
            raise EconomyError("invalid_purchase_parent")
        if event["po_quantity"] != 1:
            raise EconomyError("invalid_purchase_quantity")
        pool_item = require_uint64(self.talent_rows[commander_key]["item_id"])
        pool_rows = [
            row for row in before["profile_records"]
            if row[0] == 0 and row[1] == pool_item
        ]
        if len(pool_rows) != 1:
            raise EconomyError("commander_talent_pool_missing_from_profile")
        pool_instance = require_uint64(pool_rows[0][2])
        if (pool_rows[0][3]
                != snapshot["commanders"][commander_key]["talent_points"]):
            raise EconomyError("commander_talent_pool_mismatch")
        if event["currency_instance_id"] != pool_instance:
            raise EconomyError("invalid_currency_instance")

        current_level = snapshot["commanders"][commander_key]["abilities"].get(
            offer["ability_key"]
        )
        current_instance = 0
        if current_level is not None:
            current_definition = self.economy.ability_levels_by_identity.get((
                commander_key, offer["ability_key"], current_level,
            ))
            if current_definition is None:
                raise EconomyError("invalid_commander_ability")
            current_rows = [
                row for row in before["profile_records"]
                if row[0] == commander_instance
                and row[1] == require_uint64(current_definition["item_id"])
                and row[3] == 1
            ]
            if len(current_rows) != 1:
                raise EconomyError("owned_ability_missing_from_profile")
            current_instance = require_uint64(current_rows[0][2])
        if event["receiving_instance_id"] != 0:
            raise EconomyError("invalid_receiving_instance")

        operation_id = self._loadout_operation_id(
            "ability", request, [event],
        )
        is_retry = operation_id in snapshot["operations"]
        receipt = self.economy.purchase_ability(
            operation_id, offer["level_key"],
        )
        spent = self._validate_ability_receipt(receipt, offer)

        profile = self.build_profile()["profile"]
        if is_retry:
            # BFEF50 deltas are additive and can never be returned twice.
            # This also covers a same-watermark full-profile/no-op between the
            # original response and its retry, which a saved comparison cannot
            # distinguish from an immediate lost-response retry.
            return self._authoritative_resync_response(request, profile)
        resulting_pool_rows = [
            row for row in profile["profile_records"]
            if row[0] == 0 and row[1] == pool_item
        ]
        if (len(resulting_pool_rows) != 1
                or require_uint64(resulting_pool_rows[0][2]) != pool_instance
                or resulting_pool_rows[0][3] != spent.get("balance")):
            raise EconomyError("commander_talent_pool_mismatch")
        pool_decrease = pool_rows[0][3] - resulting_pool_rows[0][3]
        if type(pool_decrease) is not int or pool_decrease <= 0:
            raise EconomyError("invalid_commander_talent_pool_delta")
        selected_rows = [
            row for row in profile["profile_records"]
            if row[0] == commander_instance
            and row[1] == require_uint64(offer["item_id"])
            and row[3] == 1
        ]
        if len(selected_rows) != 1:
            raise EconomyError("selected_ability_missing_from_profile")
        selected_instance = require_uint64(selected_rows[0][2])
        if current_instance:
            if selected_instance == current_instance:
                raise EconomyError("ability_rank_instance_reused")
            previous_rows = [
                row for row in profile["profile_records"]
                if row[0] == commander_instance
                and row[1] == require_uint64(current_definition["item_id"])
                and row[2] == current_instance
                and row[3] == 1
            ]
            if len(previous_rows) != 1:
                raise EconomyError("previous_ability_rank_missing_from_profile")

        # Keep the commander's existing type-21 pool object alive and apply
        # the stock purchase delta in place.  BFEF50 processes the currency
        # half first, creates the new type-6 child with the server-assigned
        # instance, then runs BD30C0/BEC480 to rebuild the derived tree.  A
        # full BD8540 replacement destroys the pool object without emitting
        # this normal purchase notification; the open ability panel can then
        # retain a zero-valued/stale balance after the first purchase even
        # though the durable profile contains the correct remaining points.
        return {
            "result": "ok",
            "saved": self.wire_saved(receipt["saved"]),
            "events": [{
                "parent_id": commander_instance,
                # Selecting the first node can activate a specialization whose
                # route capacity is lower than the previous entitlement.  The
                # durable purchase still costs one point, but the native pool
                # object must receive the complete authoritative balance delta.
                "currency_quantity": pool_decrease,
                "currency_instance_id": pool_instance,
                "currency_item_id": pool_item,
                "receiving_instance_id": selected_instance,
                "receiving_quantity": 1,
                "receiving_item_id": require_uint64(offer["item_id"]),
            }],
            "properties": self._response_properties(request),
        }

    def _talent_point_response(
        self, request: dict, event: dict, snapshot: dict,
    ) -> dict:
        if any(row.get("status") == "pending"
               for row in snapshot.get("battles", {}).values()):
            raise EconomyError("specialization_change_pending_battle")
        offer = self.offers.get(event["po"])
        if offer is None or offer.get("kind") != "talent_point":
            raise EconomyError("unknown_purchase_option")
        commander_key = offer["commander_key"]
        before = self._build_profile_from_snapshot(snapshot)["profile"]
        commander_item = require_uint64(
            self.economy.commanders[commander_key]["item_id"]
        )
        roots = [row for row in before["profile_records"]
                 if row[0] == 0 and row[1] == commander_item and row[3] > 0]
        pool_item = require_uint64(self.talent_rows[commander_key]["item_id"])
        pools = [row for row in before["profile_records"]
                 if row[0] == 0 and row[1] == pool_item]
        if len(roots) != 1 or len(pools) != 1:
            raise EconomyError("commander_talent_pool_missing_from_profile")
        pool_instance = require_uint64(pools[0][2])
        if (event["parent_id"] != require_uint64(roots[0][2])
                or event["po_quantity"] != 1
                or event["currency_instance_id"]
                != self.wallet_instance_id("free_xp_cents")
                or event["receiving_instance_id"] != pool_instance):
            raise EconomyError("invalid_talent_point_purchase_shape")
        operation_id = self._loadout_operation_id(
            "talent-point", request, [event],
        )
        is_retry = operation_id in snapshot["operations"]
        purchase = getattr(self.economy, "purchase_talent_point", None)
        if not callable(purchase):
            raise EconomyError("specialization_purchase_unavailable")
        receipt = purchase(operation_id, commander_key)
        if (receipt.get("commander") != commander_key
                or receipt.get("amount") != 1
                or receipt.get("price_free_xp_cents") != offer["cost"]):
            raise EconomyError("invalid_purchase_receipt")
        profile = self.build_profile()["profile"]
        if is_retry:
            return self._authoritative_resync_response(request, profile)
        after = [row for row in profile["profile_records"]
                 if row[0] == 0 and row[1] == pool_item]
        if (len(after) != 1 or after[0][2] != pool_instance
                or after[0][3] - pools[0][3] != 1):
            raise EconomyError("commander_talent_pool_mismatch")
        return {
            "result": "ok",
            "saved": self.wire_saved(receipt["saved"]),
            "events": [{
                "parent_id": require_uint64(roots[0][2]),
                "currency_quantity": offer["cost"],
                "currency_instance_id": event["currency_instance_id"],
                "currency_item_id": self.currency_item_ids["free_xp_cents"],
                "receiving_instance_id": pool_instance,
                "receiving_quantity": 1,
                "receiving_item_id": pool_item,
            }],
            "properties": self._response_properties(request),
        }

    def _equipment_response(
        self, request: dict, events: list[dict], snapshot: dict,
    ) -> dict:
        resolved: list[tuple[str, dict]] = []
        for event in events:
            offer = self.offers.get(event["po"])
            if offer is None:
                raise EconomyError("unknown_purchase_option")
            if offer["kind"] != "equipment":
                raise EconomyError("invalid_purchase_events")
            action, row = self.equipment_by_option[event["po"]]
            expected_parent = require_uint64(
                self.economy.units[row["source_unit"]]["item_id"]
            )
            if event["parent_id"] != expected_parent:
                raise EconomyError("invalid_purchase_parent")
            if event["po_quantity"] != 1:
                raise EconomyError("invalid_purchase_quantity")
            if action == "unequip":
                if event["currency_instance_id"] != 0:
                    raise EconomyError("invalid_currency_instance")
                if event["receiving_instance_id"] != self.equipment_instance_id(
                        row["db_key"]):
                    raise EconomyError("invalid_receiving_instance")
            else:
                if event["currency_instance_id"] != self.wallet_instance_id(
                        "silver_cents"):
                    raise EconomyError("invalid_currency_instance")
                if event["receiving_instance_id"] != 0:
                    raise EconomyError("invalid_receiving_instance")
            resolved.append((action, row))

        if len(resolved) == 2:
            (first_action, previous), (second_action, selected) = resolved
            if (first_action, second_action) != ("unequip", "equip"):
                raise EconomyError("invalid_equipment_swap")
            if (previous["source_unit"] != selected["source_unit"]
                    or (previous["scope"], previous["slot"])
                    != (selected["scope"], selected["slot"])):
                raise EconomyError("invalid_equipment_swap")
        elif len(resolved) == 1:
            action, selected = resolved[0]
            previous = selected if action == "unequip" else None
        else:  # guarded by _validate_request; retained for fail-closed clarity
            raise EconomyError("invalid_purchase_events")

        unit_key = selected["source_unit"]
        operation_id = self._loadout_operation_id("equipment", request, events)

        if resolved[-1][0] == "equip":
            self.economy.select_equipment(
                operation_id, unit_key, selected["db_key"],
            )
        else:
            # Persist the first standalone decision even when the panel names
            # a stale comparison row.  A delayed identical request must replay
            # that decision rather than clearing whichever row is current by
            # the time the retry arrives.
            self.economy.unequip_equipment(
                operation_id, unit_key, selected["db_key"],
            )

        # Compact type-9 deltas were live-measured not to move C49710/C49530:
        # the client retried 3-4 s later and only then a 107 KB ok_resync
        # rebuilt the overlay, which looked like delayed batched updates.
        # Always send the silent full replacement.  BD8540 rebuilds the
        # silver frame from the authoritative graph.
        profile = self.build_profile()["profile"]
        return {
            "result": "ok_resync",
            "profile": profile,
            "saved": profile["saved"],
            "events": [],
            "properties": self._response_properties(request),
        }

    def _unit_ability_response(
        self, request: dict, events: list[dict], snapshot: dict,
    ) -> dict:
        """Apply the native type-19 equip protocol as one atomic mutation.

        Live equip captures use the commander-slot deployed-unit instance as
        parent and the native sentinel pair currency=0/receiving=1.  Return an
        ordinary typed profile delta: the native ``ok`` path mutates the
        existing raw objects before rebuilding its derived relationships.
        The observed crash is consistent with the previous full replacement
        recreating those objects and then dispatching a positive type-19
        unit-details callback while current-selection rebinding was absent;
        the complete native lifetime ordering remains runtime-unverified.
        Type-19 selections are shared by unit key, so a state-changing delta
        covers every deployed occurrence of that unit, with the clicked slot
        first so the stock pending GUI binding is consumed by the right row.
        """
        resolved: list[tuple[str, dict, str, int]] = []
        for event in events:
            offer = self.offers.get(event["po"])
            if offer is None:
                raise EconomyError("unknown_purchase_option")
            if offer["kind"] != "unit_ability":
                raise EconomyError("invalid_purchase_events")
            action, row = self.unit_ability_by_option[event["po"]]
            deployed = self._deployed_by_instance.get(event["parent_id"])
            if deployed is None:
                raise EconomyError("invalid_purchase_parent")
            commander_key, deployed_slot = deployed
            deployed_unit = snapshot["commanders"][commander_key][
                "equipped_units"
            ][deployed_slot]
            if deployed_unit != row["unit"]:
                raise EconomyError("unit_ability_unit_mismatch")
            if event["po_quantity"] != 1:
                raise EconomyError("invalid_purchase_quantity")
            if action == "unequip":
                if event["currency_instance_id"] != 0:
                    raise EconomyError("invalid_currency_instance")
                if event["receiving_instance_id"] != (
                        self.deployed_unit_ability_instance_id(
                            commander_key, deployed_slot, row["db_key"],
                        )):
                    raise EconomyError("invalid_receiving_instance")
            else:
                if event["currency_instance_id"] != 0:
                    raise EconomyError("invalid_currency_instance")
                if event["receiving_instance_id"] != 1:
                    raise EconomyError("invalid_receiving_instance")
            resolved.append((action, row, commander_key, deployed_slot))

        operation_id = self._loadout_operation_id(
            "unit-ability", request, events,
        )
        is_retry = operation_id in snapshot["operations"]
        previous_db_key: str | None = None
        selected_db_key: str | None = None
        binding_pair: tuple[str, str] | None = None
        if len(resolved) == 2:
            (first_action, previous, previous_commander, previous_slot), (
                second_action, selected, selected_commander, selected_slot,
            ) = resolved
            if ((first_action, second_action) not in {
                        ("unequip", "equip"), ("equip", "equip"),
                    }
                    or previous["unit"] != selected["unit"]
                    or (previous_commander, previous_slot)
                    != (selected_commander, selected_slot)):
                raise EconomyError("invalid_unit_ability_swap")
            if first_action == "equip":
                binding_pair = (previous["db_key"], selected["db_key"])
                self.economy.bind_unit_ability_pair(
                    operation_id, selected["unit"], binding_pair,
                )
            else:
                self.economy.swap_unit_ability(
                    operation_id, selected["unit"], previous["db_key"],
                    selected["db_key"],
                )
                previous_db_key = previous["db_key"]
                selected_db_key = selected["db_key"]
        elif len(resolved) == 1:
            action, selected, _commander_key, _deployed_slot = resolved[0]
            if action == "equip":
                self.economy.equip_unit_ability(
                    operation_id,
                    selected["unit"],
                    selected["db_key"],
                    advance_native_binding=True,
                )
                selected_db_key = selected["db_key"]
            else:
                self.economy.unequip_unit_ability(
                    operation_id, selected["unit"], selected["db_key"],
                )
                previous_db_key = selected["db_key"]
        else:
            raise EconomyError("invalid_purchase_events")

        profile = self.build_profile()["profile"]
        if is_retry:
            # Generic ``ok`` events are additive.  Never replay them.  The
            # established retry fallback is an authoritative current graph
            # with no positive notification; its native runtime behavior is
            # intentionally not inferred beyond avoiding duplicate deltas.
            return self._authoritative_resync_response(request, profile)

        before = self._build_profile_from_snapshot(snapshot)["profile"]
        if binding_pair is not None:
            response_events = self.unit_ability_pair_delta_events(
                before, profile, resolved[-1][1]["unit"],
                binding_pair=binding_pair,
                preferred_parent=events[-1]["parent_id"],
            )
        else:
            response_events = self.unit_ability_delta_events(
                before,
                profile,
                resolved[-1][1]["unit"],
                previous_db_key=previous_db_key,
                selected_db_key=selected_db_key,
                preferred_parent=events[-1]["parent_id"],
            )
        return {
            "result": "ok",
            "saved": profile["saved"],
            "events": response_events,
            # BFF78B rebuilds the native profile before the outer response
            # handler dispatches the type-19 notification.  That rebuild
            # clears profile+0x60/+0x64.  BD8940 consumes these authoritative
            # properties immediately afterwards and resolves the selected
            # commander from the freshly rebuilt profile before BE66E0 can
            # notify the unit-details UI.  A captured ability request usually
            # omits both selection fields, so merely echoing request fields
            # would leave the current-commander lookup empty.
            "properties": copy.deepcopy(profile["properties"]),
        }

    def _unit_ability_delta_rows(
        self, before: dict, after: dict, unit_key: str, preferred_parent: int,
    ) -> tuple[dict, dict, dict]:
        """Validate the complete profile graph before emitting bounded deltas."""
        required = {"saved", "profile_records"}
        if (not isinstance(before, dict) or not isinstance(after, dict)
                or set(before) != set(after)
                or not required <= set(before)):
            raise EconomyError("invalid_unit_ability_delta")
        before_meta = {key: value for key, value in before.items()
                       if key not in {"saved", "profile_records"}}
        after_meta = {key: value for key, value in after.items()
                      if key not in {"saved", "profile_records"}}
        if before_meta != after_meta:
            raise EconomyError("invalid_unit_ability_delta")
        try:
            before_saved = _uint64(
                before["saved"], "invalid_unit_ability_delta", allow_zero=False,
            )
            after_saved = _uint64(
                after["saved"], "invalid_unit_ability_delta", allow_zero=False,
            )
        except EconomyError:
            raise EconomyError("invalid_unit_ability_delta") from None
        # Every first native binding gesture advances the client watermark,
        # including an already-owned equip whose canonical rows do not change.
        # This is what distinguishes the next deliberate click from an exact
        # transport retry of the current operation.
        if after_saved <= before_saved:
            raise EconomyError("invalid_unit_ability_delta")

        snapshot = self.economy.snapshot()
        affected: dict[int, tuple[str, int]] = {}
        for parent, (commander, slot) in self._deployed_by_instance.items():
            state = snapshot["commanders"].get(commander)
            units = state.get("equipped_units") if isinstance(state, dict) else None
            if (isinstance(units, list) and 0 <= slot < len(units)
                    and units[slot] == unit_key):
                affected[parent] = (commander, slot)
        if not affected or len(affected) > len(snapshot["commanders"]) * 3:
            raise EconomyError("invalid_unit_ability_delta")
        if (type(preferred_parent) is not int
                or preferred_parent not in affected):
            raise EconomyError("invalid_unit_ability_delta")

        ability_by_item = {
            require_uint64(row["item_id"]): row
            for row in self.unit_abilities_by_db_key.values()
        }
        if len(ability_by_item) != len(self.unit_abilities_by_db_key):
            raise EconomyError("invalid_unit_ability_delta")

        def split(profile: dict) -> tuple[list[list[int]], dict[int, dict[str, list[int]]]]:
            records = profile.get("profile_records")
            if (not isinstance(records, list)
                    or not 1 <= len(records) <= 10_000):
                raise EconomyError("invalid_unit_ability_delta")
            unrelated: list[list[int]] = []
            selected: dict[int, dict[str, list[int]]] = {
                parent: {} for parent in affected
            }
            for record in records:
                if (not isinstance(record, list) or len(record) != 4
                        or any(type(value) is not int for value in record)):
                    raise EconomyError("invalid_unit_ability_delta")
                parent, item_id, instance_id, quantity = record
                try:
                    _uint64(parent, "invalid_unit_ability_delta")
                    _uint64(item_id, "invalid_unit_ability_delta", allow_zero=False)
                    _uint64(instance_id, "invalid_unit_ability_delta", allow_zero=False)
                    _uint64(quantity, "invalid_unit_ability_delta")
                except EconomyError:
                    raise EconomyError("invalid_unit_ability_delta") from None
                row = ability_by_item.get(item_id)
                if parent not in affected or row is None:
                    unrelated.append(record)
                    continue
                if (row["unit"] != unit_key or quantity != 1
                        or row["db_key"] in selected[parent]):
                    raise EconomyError("invalid_unit_ability_delta")
                commander, slot = affected[parent]
                if instance_id != self.deployed_unit_ability_instance_id(
                        commander, slot, row["db_key"]):
                    raise EconomyError("invalid_unit_ability_delta")
                selected[parent][row["db_key"]] = record
            return unrelated, selected

        before_unrelated, before_rows = split(before)
        after_unrelated, after_rows = split(after)
        if before_unrelated != after_unrelated:
            raise EconomyError("invalid_unit_ability_delta")

        return before_rows, after_rows, affected

    def unit_ability_pair_delta_events(
        self, before: dict, after: dict, unit_key: str, *,
        binding_pair: tuple[str, str], preferred_parent: int,
    ) -> list[dict]:
        """Acknowledge native Swap's two equips without dropping either row."""
        if (not isinstance(binding_pair, tuple) or len(binding_pair) != 2
                or len(set(binding_pair)) != 2):
            raise EconomyError("invalid_unit_ability_delta")
        definitions = [self.unit_abilities_by_db_key.get(key) for key in binding_pair]
        if any(row is None or row["unit"] != unit_key for row in definitions):
            raise EconomyError("invalid_unit_ability_delta")
        before_rows, after_rows, affected = self._unit_ability_delta_rows(
            before, after, unit_key, preferred_parent,
        )
        result: list[dict] = []
        for parent in [preferred_parent, *sorted(p for p in affected if p != preferred_parent)]:
            expected = dict(before_rows[parent])
            commander, slot = affected[parent]
            for key, row in zip(binding_pair, definitions):
                expected[key] = [
                    parent, require_uint64(row["item_id"]),
                    self.deployed_unit_ability_instance_id(commander, slot, key), 1,
                ]
            if after_rows[parent] != expected:
                raise EconomyError("invalid_unit_ability_delta")
            for key in binding_pair:
                new = after_rows[parent][key]
                existed = key in before_rows[parent]
                if existed and parent != preferred_parent:
                    continue
                # Consume both pending bindings on the clicked occurrence in
                # request order before notifying another deployed occurrence.
                result.append({
                    "parent_id": parent, "receiving_instance_id": new[2],
                    "receiving_quantity": 1, "receiving_item_id": new[1],
                })
                if existed:
                    # Match the existing single-binding pulse: 1 -> 2 -> 1,
                    # never remove/recreate an already bound native object.
                    result.append({
                        "parent_id": parent, "currency_instance_id": new[2],
                        "currency_quantity": 1, "currency_item_id": new[1],
                    })
        return result

    def unit_ability_delta_events(
        self,
        before: dict,
        after: dict,
        unit_key: str,
        *,
        previous_db_key: str | None,
        selected_db_key: str | None,
        preferred_parent: int,
    ) -> list[dict]:
        """Return the exact bounded type-19 profile delta for one unit.

        This comparison is deliberately over the complete profile records.
        Removing the affected type-19 rows must leave byte-for-byte equal
        unrelated records and metadata; a unit-ability operation may not
        smuggle another profile mutation into an ordinary delta.
        """
        if previous_db_key is None and selected_db_key is None:
            raise EconomyError("invalid_unit_ability_delta")
        before_rows, after_rows, affected = self._unit_ability_delta_rows(
            before, after, unit_key, preferred_parent,
        )

        existing_selected_swap = (
            previous_db_key is not None
            and selected_db_key is not None
            and previous_db_key != selected_db_key
            and all(
                selected_db_key in before_rows[parent]
                for parent in affected
            )
        )

        if (previous_db_key is None and selected_db_key is not None
                and before_rows == after_rows):
            if not all(
                selected_db_key in before_rows[parent]
                for parent in affected
            ):
                raise EconomyError("invalid_unit_ability_delta")
            # Type-19 ownership is global by unit key, but the stock picker has
            # one pending GUI binding for the exact deployed parent clicked by
            # the user.  A positive-first pulse on that already-existing row
            # lets BE5B40 consume the binding without changing the canonical
            # profile: BFEF50 applies +1 then -1 before its derived rebuild, so
            # the quantity is 1 -> 2 -> 1 and never reaches the destructive
            # zero/remove path.  Do not generalize this to arbitrary net-zero
            # events or a combined remove/add event, which destroys the row.
            existing = before_rows[preferred_parent][selected_db_key]
            return [{
                "parent_id": preferred_parent,
                "receiving_instance_id": existing[2],
                "receiving_quantity": 1,
                "receiving_item_id": existing[1],
            }, {
                "parent_id": preferred_parent,
                "currency_quantity": 1,
                "currency_instance_id": existing[2],
                "currency_item_id": existing[1],
            }]

        result: list[dict] = []
        ordered_parents = [preferred_parent, *sorted(
            parent for parent in affected if parent != preferred_parent
        )]
        for parent in ordered_parents:
            expected = dict(before_rows[parent])
            if previous_db_key is not None:
                if previous_db_key not in expected:
                    raise EconomyError("invalid_unit_ability_delta")
                del expected[previous_db_key]
            if selected_db_key is not None:
                if selected_db_key in expected:
                    if not existing_selected_swap:
                        raise EconomyError("invalid_unit_ability_delta")
                else:
                    row = self.unit_abilities_by_db_key.get(selected_db_key)
                    if row is None or row["unit"] != unit_key:
                        raise EconomyError("invalid_unit_ability_delta")
                    commander, slot = affected[parent]
                    expected[selected_db_key] = [
                        parent,
                        require_uint64(row["item_id"]),
                        self.deployed_unit_ability_instance_id(
                            commander, slot, selected_db_key,
                        ),
                        1,
                    ]
            if after_rows[parent] != expected:
                raise EconomyError("invalid_unit_ability_delta")

            if existing_selected_swap:
                # Validate every parent before constructing the special pulse
                # below.  The canonical B row already survives A -> B, so a
                # combined remove-A/receive-B event would incorrectly leave B
                # at quantity two.
                continue

            delta: dict[str, int] = {"parent_id": parent}
            if previous_db_key is not None:
                old = before_rows[parent][previous_db_key]
                delta.update({
                    "currency_quantity": 1,
                    "currency_instance_id": old[2],
                    "currency_item_id": old[1],
                })
            if selected_db_key is not None:
                new = after_rows[parent][selected_db_key]
                delta.update({
                    "receiving_instance_id": new[2],
                    "receiving_quantity": 1,
                    "receiving_item_id": new[1],
                })
            result.append(delta)
        if existing_selected_swap:
            # The clicked parent still needs a positive type-19 notification
            # for its pending picker binding.  Pulse the existing B row
            # positive-first (1 -> 2 -> 1), then remove A from every deployed
            # parent.  No B row reaches zero and no object is recreated.
            existing = before_rows[preferred_parent][selected_db_key]
            result.extend([{
                "parent_id": preferred_parent,
                "receiving_instance_id": existing[2],
                "receiving_quantity": 1,
                "receiving_item_id": existing[1],
            }, {
                "parent_id": preferred_parent,
                "currency_quantity": 1,
                "currency_instance_id": existing[2],
                "currency_item_id": existing[1],
            }])
            for parent in ordered_parents:
                old = before_rows[parent][previous_db_key]
                result.append({
                    "parent_id": parent,
                    "currency_quantity": 1,
                    "currency_instance_id": old[2],
                    "currency_item_id": old[1],
                })
        return result

    @staticmethod
    def _cleanup_receipt_shape(receipt: object) -> tuple[str, list[dict]] | None:
        """Validate and unpack one durable unit-change before-image.

        The operation journal is the durable source for this metadata.  Keep
        this validator intentionally strict: a malformed or hand-edited
        receipt must never turn an arbitrary refund into an acknowledgement.
        """
        if not isinstance(receipt, dict):
            return None
        details = receipt.get("unit_change_cleanup")
        if (receipt.get("kind") != "equip_units"
                or not isinstance(details, dict)
                or set(details) != {
                    "commander", "previous_saved", "previous_units",
                    "changed_slots",
                }):
            return None
        commander = details.get("commander")
        previous_saved = details.get("previous_saved")
        previous_units = details.get("previous_units")
        changed_slots = details.get("changed_slots")
        units = receipt.get("units")
        if (not isinstance(commander, str) or not commander
                or receipt.get("commander") != commander
                or type(previous_saved) is not int
                or not 1 <= previous_saved <= UINT64_MAX
                or not isinstance(previous_units, list)
                or len(previous_units) != 3
                or any(not isinstance(value, str) or not value
                       for value in previous_units)
                or not isinstance(units, list) or len(units) != 3
                or any(not isinstance(value, str) or not value for value in units)
                or not isinstance(changed_slots, list)
                or not 1 <= len(changed_slots) <= 3):
            return None
        seen: set[int] = set()
        normalized: list[dict] = []
        for row in changed_slots:
            if (not isinstance(row, dict)
                    or set(row) != {"slot", "unit", "consumables", "abilities"}
                    or type(row.get("slot")) is not int
                    or not 0 <= row["slot"] < 3
                    or row["slot"] in seen
                    or not isinstance(row.get("unit"), str)
                    or not row["unit"]
                    or row["unit"] != previous_units[row["slot"]]
                    or row["unit"] == units[row["slot"]]
                    or not isinstance(row.get("consumables"), dict)
                    or not isinstance(row.get("abilities"), list)
                    or any(not isinstance(key, str)
                           for key in row["abilities"])
                    or row["abilities"] != sorted(set(row["abilities"]))
                    or any(not isinstance(key, str) for key in row["consumables"])
                    or any(not isinstance(key, str) for key in row["consumables"].values())
                    ):
                return None
            seen.add(row["slot"])
            normalized.append(copy.deepcopy(row))
        if seen != {
                slot for slot in range(3)
                if previous_units[slot] != units[slot]
        }:
            return None
        return commander, normalized

    def _unit_change_cleanup_images(
        self, snapshot: dict, profile_timestamp: int, *,
        require_current: bool = True,
    ) -> list[dict]:
        """Return before-images in the proven swap chain for this request.

        A stock hangar can issue several slot drops before its first profile
        watermark is consumed.  Follow only durable equip receipts whose
        previous units/watermarks join exactly; an arbitrary older receipt is
        not enough to authorize cleanup.
        """
        if type(profile_timestamp) is not int:
            return []
        operations = snapshot.get("operations")
        if not isinstance(operations, dict):
            return []
        records: list[tuple[dict, str, list[dict]]] = []
        for entry in operations.values():
            receipt = entry.get("receipt") if isinstance(entry, dict) else None
            parsed = self._cleanup_receipt_shape(receipt)
            if parsed is None:
                continue
            commander, rows = parsed
            expected_hash = _canonical_hash({
                "kind": "equip_units",
                "request": {
                    "commander": receipt.get("commander"),
                    "units": receipt.get("units"),
                },
            })
            if (isinstance(entry, dict)
                    and entry.get("request_hash") == expected_hash
                    and isinstance(receipt.get("operation_id"), str)
                    and type(receipt.get("saved")) is int
                    and 1 <= receipt["saved"] <= UINT64_MAX
                    and receipt["saved"] > receipt["unit_change_cleanup"]["previous_saved"]):
                records.append((receipt, commander, rows))
        if not records:
            return []
        by_start: dict[tuple[str, int, tuple[str, ...]], tuple[dict, list[dict]]] = {}
        for receipt, commander, rows in records:
            details = receipt["unit_change_cleanup"]
            key = (commander, details["previous_saved"],
                   tuple(details["previous_units"]))
            if key in by_start:
                # A duplicate start watermark would make the causal chain
                # ambiguous; fail closed rather than choosing by journal order.
                return []
            by_start[key] = (receipt, rows)

        result: list[dict] = []
        current_units_by_commander = snapshot.get("commanders", {})
        for commander in {commander for _receipt, commander, _rows in records}:
            starts = [
                (receipt, rows) for receipt, owner, rows in records
                if owner == commander
                and self.wire_saved(
                    receipt["unit_change_cleanup"]["previous_saved"]
                ) == profile_timestamp
            ]
            for first, first_rows in starts:
                receipt = first
                rows = first_rows
                visited: set[str] = set()
                chain_rows: list[dict] = []
                while True:
                    operation_id = receipt.get("operation_id")
                    if not isinstance(operation_id, str) or operation_id in visited:
                        break
                    visited.add(operation_id)
                    chain_rows.extend(
                        {**copy.deepcopy(row), "commander": commander,
                         "_receipt_id": operation_id}
                        for row in rows
                    )
                    details = receipt["unit_change_cleanup"]
                    next_key = (commander, receipt["saved"], tuple(receipt["units"]))
                    next_entry = by_start.get(next_key)
                    if next_entry is None:
                        break
                    receipt, rows = next_entry
                current = current_units_by_commander.get(commander)
                current_units = (
                    current.get("equipped_units")
                    if isinstance(current, dict) else None
                )
                if (not require_current
                        or (isinstance(current_units, list)
                            and tuple(receipt.get("units", ()))
                            == tuple(current_units))):
                    result.extend(chain_rows)
        # Multiple starts can converge only through a corrupt journal.  The
        # caller treats duplicate event identities as invalid below.
        return result

    def _cleanup_event_candidate_ids(
        self, event: dict, offer: dict, images: list[dict],
    ) -> set[str]:
        candidates: set[str] = set()
        if offer.get("kind") == "consumable_refund":
            row = self.consumables_by_db_key.get(offer.get("consumable_db_key"))
            if row is None or event["po_quantity"] != row["quantity"]:
                return candidates
            if event["currency_instance_id"] != 0:
                return candidates
            deployed = self._deployed_by_instance.get(event["parent_id"])
            if deployed is None or event["receiving_instance_id"] != self.consumable_instance_id(
                    deployed[0], deployed[1], row["db_key"]):
                return candidates
            commander, slot = deployed
            for image in images:
                if (
                image.get("commander") == commander
                and image.get("slot") == slot
                and row["db_key"] in self.economy.consumable_keys_by_unit.get(
                    image.get("unit"), set()
                )
                and row["db_key"] in image.get("consumables", {}).values()
                ):
                    candidates.add(image["_receipt_id"])
            return candidates
        if offer.get("kind") == "unit_ability":
            action, row = self.unit_ability_by_option.get(event["po"], (None, None))
            if action != "unequip" or row is None:
                return candidates
            deployed = self._deployed_by_instance.get(event["parent_id"])
            if deployed is None:
                return candidates
            commander, slot = deployed
            if (event["po_quantity"] != 1 or event["currency_instance_id"] != 0
                    or event["receiving_instance_id"] != self.deployed_unit_ability_instance_id(
                        commander, slot, row["db_key"])):
                return candidates
            for image in images:
                if (image.get("commander") == commander
                and image.get("slot") == slot
                and image.get("unit") == row["unit"]
                and row["db_key"] in image.get("abilities", [])):
                    candidates.add(image["_receipt_id"])
            return candidates
        return candidates

    def _cleanup_event_matches(
        self, event: dict, offer: dict, images: list[dict], snapshot: dict,
    ) -> bool:
        _ = snapshot
        return bool(self._cleanup_event_candidate_ids(event, offer, images))

    def is_unit_change_cleanup_request(self, request: object) -> bool:
        """Return whether a request is a fully proven old-unit cleanup ACK."""
        try:
            request, events, snapshot = self._validate_request(
                request, validate_current_properties=False,
            )
        except EconomyError:
            return False
        images = self._unit_change_cleanup_images(
            snapshot, self.wire_saved(request["profile_timestamp"]),
        )
        if not images:
            # The old cleanup can legitimately arrive after an intervening
            # non-loadout mutation. It is still a cleanup proof, but the
            # response path will reject it rather than let it become a normal
            # current refund; keeping this classification lets the service
            # preserve an unrelated pending refresh gate.
            images = self._unit_change_cleanup_images(
                snapshot, self.wire_saved(request["profile_timestamp"]),
                require_current=False,
            )
        if not images or not events:
            return False
        seen: set[str] = set()
        common_receipts: set[str] | None = None
        batch_parent: int | None = None
        for event in events:
            fingerprint = _canonical_hash(event)
            if fingerprint in seen:
                return False
            seen.add(fingerprint)
            if batch_parent is not None and event["parent_id"] != batch_parent:
                return False
            batch_parent = event["parent_id"]
            offer = self.offers.get(event["po"])
            candidates = (
                self._cleanup_event_candidate_ids(event, offer, images)
                if offer is not None else set()
            )
            if not candidates:
                return False
            common_receipts = candidates if common_receipts is None else (
                common_receipts & candidates
            )
            if not common_receipts:
                return False
        return True

    def unit_change_cleanup_covers_operation(
        self, request: object, operation_id: object,
    ) -> bool:
        """Prove a cleanup chain includes one pending drag operation."""
        if not isinstance(operation_id, str):
            return False
        try:
            request, events, snapshot = self._validate_request(
                request, validate_current_properties=False,
            )
        except EconomyError:
            return False
        if not self.is_unit_change_cleanup_request(request):
            return False
        images = self._unit_change_cleanup_images(
            snapshot, self.wire_saved(request["profile_timestamp"]),
        )
        return operation_id in {
            image.get("_receipt_id") for image in images
        }

    def _validated_unit_change_cleanup_deltas(
        self, events: list[dict], images: list[dict],
    ) -> list[dict] | None:
        """Build exact old-child removals for one proven cleanup batch.

        The native request names the type-11/type-19 rows which still belong
        to the old deployed-unit root.  Emit only the currency/removal half of
        the stock purchase delta for those exact rows.  This lets the retired
        client destroy each child while its old type-3 parent still exists;
        the later correlated profile refresh remains solely responsible for
        replacing the unit root.
        """
        seen_requests: set[str] = set()
        seen_instances: set[int] = set()
        common_receipts: set[str] | None = None
        batch_parent: int | None = None
        deltas: list[dict] = []
        for event in events:
            fingerprint = _canonical_hash(event)
            if fingerprint in seen_requests:
                raise EconomyError("invalid_purchase_events")
            seen_requests.add(fingerprint)
            if batch_parent is not None and event["parent_id"] != batch_parent:
                raise EconomyError("invalid_purchase_events")
            batch_parent = event["parent_id"]
            offer = self.offers.get(event["po"])
            candidates = (
                self._cleanup_event_candidate_ids(event, offer, images)
                if offer is not None else set()
            )
            if not candidates:
                return None
            common_receipts = candidates if common_receipts is None else (
                common_receipts & candidates
            )
            if not common_receipts:
                return None

            if offer["kind"] == "consumable_refund":
                row = self.consumables_by_db_key.get(
                    offer.get("consumable_db_key")
                )
                if row is None:
                    return None
                quantity = require_uint64(row.get("quantity"))
                item_id = require_uint64(row.get("item_id"))
            elif offer["kind"] == "unit_ability":
                action, row = self.unit_ability_by_option.get(
                    event["po"], (None, None)
                )
                if action != "unequip" or row is None:
                    return None
                quantity = 1
                item_id = require_uint64(row.get("item_id"))
            else:
                return None
            instance_id = require_uint64(event["receiving_instance_id"])
            if quantity <= 0 or instance_id in seen_instances:
                raise EconomyError("invalid_purchase_events")
            seen_instances.add(instance_id)
            deltas.append({
                "parent_id": require_uint64(event["parent_id"]),
                "currency_quantity": quantity,
                "currency_instance_id": instance_id,
                "currency_item_id": item_id,
            })
        return deltas if events else None

    def unit_change_cleanup_delta_events(self, request: object) -> list[dict]:
        """Recompute canonical removal events for service-level validation."""
        request, events, snapshot = self._validate_request(
            request, validate_current_properties=False,
        )
        images = self._unit_change_cleanup_images(
            snapshot, self.wire_saved(request["profile_timestamp"]),
        )
        if not images:
            raise EconomyError("stale_unit_change_cleanup")
        deltas = self._validated_unit_change_cleanup_deltas(events, images)
        if deltas is None:
            raise EconomyError("invalid_purchase_events")
        return deltas

    def _unit_change_cleanup_response(
        self, request: dict, events: list[dict], snapshot: dict,
    ) -> dict | None:
        images = self._unit_change_cleanup_images(
            snapshot, self.wire_saved(request["profile_timestamp"]),
        )
        if not images:
            # A historical cleanup that no longer reaches the current saved
            # watermark must never fall through to the ordinary refund path:
            # if the same definition was selected again, that path would
            # erase the newer selection. Reject it atomically instead.
            historical = self._unit_change_cleanup_images(
                snapshot, self.wire_saved(request["profile_timestamp"]),
                require_current=False,
            )
            if historical and any(
                    offer is not None
                    and self._cleanup_event_candidate_ids(
                        event, offer, historical
                    )
                    for event in events
                    for offer in [self.offers.get(event["po"])]
            ):
                raise EconomyError("stale_unit_change_cleanup")
            return None
        if self._validated_unit_change_cleanup_deltas(events, images) is None:
            return None
        return {
            "result": "ok",
            "saved": self.wire_saved(snapshot["saved"]),
            # Direct adapter callers retain the legacy non-additive ACK.
            # Native child removals are injected only by the service while it
            # holds an exact live external-refresh generation and replay
            # ledger; emitting them here would make direct retries unsafe.
            "events": [],
            # The ordinary native event-result parser rebuilds derived
            # profile maps even for an empty event list.  Reapply the trusted
            # current properties so this acknowledgement cannot leave the
            # current commander cleared after a delayed old-unit cleanup.
            "properties": self._build_profile_from_snapshot(snapshot)[
                "profile"
            ]["properties"],
        }

    def _equipment_unlock_response(
        self, request: dict, event: dict, snapshot: dict,
    ) -> dict:
        offer = self.offers.get(event["po"])
        if offer is None or offer.get("kind") != "equipment_unlock":
            raise EconomyError("invalid_purchase_events")
        if event["parent_id"] != 0 or event["po_quantity"] != 1:
            raise EconomyError("invalid_purchase_parent")
        if event["receiving_instance_id"] != 0:
            raise EconomyError("invalid_receiving_instance")
        if offer["currency"] == "unit_xp_cents":
            expected_currency = self.unit_xp_instance_id(offer["unit_key"])
        else:
            expected_currency = self.wallet_instance_id("free_xp_cents")
        if event["currency_instance_id"] != expected_currency:
            raise EconomyError("invalid_currency_instance")
        operation_id = self._loadout_operation_id(
            "equipment-unlock", request, [event],
        )
        self.economy.purchase_equipment(
            operation_id, offer["equipment_db_key"], offer["currency"],
        )
        profile = self.build_profile()["profile"]
        return {
            "result": "ok_resync", "profile": profile,
            "saved": profile["saved"], "events": [], "properties": [],
        }

    def _commander_tier_response(
        self, request: dict, event: dict, snapshot: dict,
    ) -> dict:
        offer = self.offers.get(event["po"])
        if offer is None or offer.get("kind") != "commander_tier":
            raise EconomyError("invalid_purchase_events")
        commander_key = offer["commander_key"]
        before = self._build_profile_from_snapshot(snapshot)["profile"]
        commander_item = require_uint64(
            self.economy.commanders[commander_key]["item_id"]
        )
        commander_roots = [
            row for row in before["profile_records"]
            if row[0] == 0 and row[1] == commander_item and row[3] > 0
        ]
        if len(commander_roots) != 1:
            raise EconomyError("owned_commander_missing_from_profile")
        commander_instance = require_uint64(commander_roots[0][2])
        if event["parent_id"] != commander_instance:
            raise EconomyError("invalid_purchase_parent")
        if event["po_quantity"] != 1:
            raise EconomyError("invalid_purchase_quantity")
        if event["currency_instance_id"] != self.commander_xp_instance_id(
                commander_key):
            raise EconomyError("invalid_currency_instance")
        if event["receiving_instance_id"] != 0:
            raise EconomyError("invalid_receiving_instance")
        operation_id = self._loadout_operation_id(
            "commander-tier", request, [event],
        )
        self.economy.upgrade_commander_tier(
            operation_id, commander_key, offer["tier"],
        )
        profile = self.build_profile()["profile"]
        return {
            "result": "ok_resync", "profile": profile,
            "saved": profile["saved"], "events": [], "properties": [],
        }

    def _ability_refund_response(
        self, request: dict, event: dict, snapshot: dict,
    ) -> dict:
        """Consume the exact highest type-6 rank and return one pool point."""
        offer = self.offers.get(event["po"])
        if offer is None:
            raise EconomyError("unknown_purchase_option")
        if offer["kind"] != "ability_refund":
            raise EconomyError("invalid_purchase_events")
        commander_key = offer["commander_key"]
        operation_id = self._loadout_operation_id(
            "ability-refund", request, [event],
        )
        is_retry = operation_id in snapshot["operations"]
        if (not is_retry
                and snapshot["commanders"][commander_key]["abilities"].get(
                    offer["ability_key"]) != offer["ability_level"]):
            raise EconomyError("ability_refund_not_highest_rank")

        before = self._build_profile_from_snapshot(snapshot)["profile"]
        commander_item = require_uint64(
            self.economy.commanders[commander_key]["item_id"]
        )
        commander_roots = [
            row for row in before["profile_records"]
            if row[0] == 0 and row[1] == commander_item and row[3] > 0
        ]
        if len(commander_roots) != 1:
            raise EconomyError("owned_commander_missing_from_profile")
        commander_instance = require_uint64(commander_roots[0][2])
        pool_item = require_uint64(self.talent_rows[commander_key]["item_id"])
        pool_rows = [
            row for row in before["profile_records"]
            if row[0] == 0 and row[1] == pool_item
        ]
        if len(pool_rows) != 1:
            raise EconomyError("commander_talent_pool_missing_from_profile")
        pool_instance = require_uint64(pool_rows[0][2])
        if (pool_rows[0][3]
                != snapshot["commanders"][commander_key]["talent_points"]):
            raise EconomyError("commander_talent_pool_mismatch")
        owned_rows = [
            row for row in before["profile_records"]
            if row[0] == commander_instance
            and row[1] == require_uint64(offer["item_id"])
            and row[3] == 1
        ]
        if not is_retry and len(owned_rows) != 1:
            raise EconomyError("owned_ability_missing_from_profile")

        # 10C55510 passes the refund PO, parent zero, the selected type-6
        # profile row as currency, quantity one and receiving instance zero.
        if event["parent_id"] != 0:
            raise EconomyError("invalid_purchase_parent")
        if event["po_quantity"] != 1:
            raise EconomyError("invalid_purchase_quantity")
        if (not is_retry
                and event["currency_instance_id"]
                != require_uint64(owned_rows[0][2])):
            raise EconomyError("invalid_currency_instance")
        if event["receiving_instance_id"] != 0:
            raise EconomyError("invalid_receiving_instance")

        receipt = self.economy.refund_ability(
            operation_id, offer["level_key"],
        )
        refunded = self._validate_ability_refund_receipt(receipt, offer)

        profile = self.build_profile()["profile"]
        if is_retry:
            return self._authoritative_resync_response(request, profile)
        if any(
            row[0] == commander_instance
            and row[1] == require_uint64(offer["item_id"])
            for row in profile["profile_records"]
        ):
            raise EconomyError("refunded_ability_still_in_profile")
        resulting_level = receipt.get("resulting_level")
        if type(resulting_level) is not int or resulting_level < 0:
            raise EconomyError("invalid_purchase_receipt")
        if resulting_level:
            previous = self.economy.ability_levels_by_identity.get((
                commander_key, offer["ability_key"], resulting_level,
            ))
            if previous is None or not any(
                row[0] == commander_instance
                and row[1] == require_uint64(previous["item_id"])
                and row[3] == 1
                for row in profile["profile_records"]
            ):
                raise EconomyError("previous_ability_rank_missing_from_profile")
        resulting_pool_rows = [
            row for row in profile["profile_records"]
            if row[0] == 0 and row[1] == pool_item
        ]
        if (len(resulting_pool_rows) != 1
                or require_uint64(resulting_pool_rows[0][2]) != pool_instance
                or resulting_pool_rows[0][3] != refunded.get("balance")):
            raise EconomyError("commander_talent_pool_mismatch")
        pool_increase = resulting_pool_rows[0][3] - pool_rows[0][3]
        if type(pool_increase) is not int or pool_increase <= 0:
            raise EconomyError("invalid_commander_talent_pool_delta")
        return {
            "result": "ok",
            "saved": self.wire_saved(receipt["saved"]),
            "events": [{
                "parent_id": 0,
                "currency_quantity": 1,
                "currency_instance_id": event["currency_instance_id"],
                "currency_item_id": require_uint64(offer["item_id"]),
                "receiving_instance_id": pool_instance,
                # A refund can reopen/bank points when specialization capacity
                # changes.  Preserve the existing type-21 object and publish
                # the full authoritative increase rather than a fixed +1.
                "receiving_quantity": pool_increase,
                "receiving_item_id": pool_item,
            }],
            "properties": self._response_properties(request),
        }

    def _ability_tree_reset_response(
        self, request: dict, events: list[dict], snapshot: dict,
    ) -> dict:
        """Recognize only the stock reset's complete owned rank vector.

        DD3660 -> C55320 appends each refundable rank at C554B6 and submits
        that vector once at C554E6. Its ordinary single-rank counterpart
        remains handled separately; mixed purchases never enter this path.
        """
        offers = [self.offers[event["po"]] for event in events]
        commanders = {offer["commander_key"] for offer in offers}
        if len(commanders) != 1:
            raise EconomyError("invalid_ability_tree_reset")
        commander = next(iter(commanders))
        levels = [offer["level_key"] for offer in offers]
        if len(levels) != len(set(levels)):
            raise EconomyError("invalid_ability_tree_reset")
        for event in events:
            if (event["parent_id"] != 0 or event["po_quantity"] != 1
                    or event["receiving_instance_id"] != 0):
                raise EconomyError("invalid_ability_tree_reset")
        operation = self._loadout_operation_id("ability-tree-reset", request, events)
        existing = snapshot["operations"].get(operation)
        if existing is not None:
            receipt = existing.get("receipt", {})
            if (receipt.get("kind") != "refund_ability_tree"
                    or type(receipt.get("expected_saved")) is not int):
                raise EconomyError("invalid_purchase_receipt")
            self.economy.refund_ability_tree(
                operation, commander, levels, expected_saved=receipt["expected_saved"],
            )
            return self._authoritative_resync_response(request, self.build_profile()["profile"])
        # Commander selection can advance the durable profile while the stock
        # tree still submits its previous watermark. Prove every owned rank
        # and instance below, then let the atomic economy operation check the
        # complete rank set against this snapshot. A global watermark mismatch
        # alone does not mean the displayed tree changed.
        stale_profile = request["profile_timestamp"] != self.wire_saved(snapshot["saved"])
        self._validate_optional_properties(request, snapshot)
        before = self._build_profile_from_snapshot(snapshot)["profile"]
        commander_instance = require_uint64(self.economy.commanders[commander]["item_id"])
        pool_item = require_uint64(self.talent_rows[commander]["item_id"])
        pool = [row for row in before["profile_records"] if row[0] == 0 and row[1] == pool_item]
        if len(pool) != 1:
            raise EconomyError("commander_talent_pool_missing_from_profile")
        for event, offer in zip(events, offers):
            owned = [row for row in before["profile_records"]
                     if row[0] == commander_instance and row[1] == require_uint64(offer["item_id"])
                     and row[2] == event["currency_instance_id"] and row[3] == 1]
            if len(owned) != 1:
                raise EconomyError("invalid_currency_instance")
        receipt = self.economy.refund_ability_tree(
            operation, commander, levels, expected_saved=snapshot["saved"],
        )
        if stale_profile:
            # Unrelated properties may also have changed since the old UI
            # watermark. Install the authoritative graph instead of applying
            # additive refund deltas to an older graph.
            return self._authoritative_resync_response(request, self.build_profile()["profile"])
        increase = receipt["refunded_points"]
        if type(increase) is not int or increase < len(events):
            raise EconomyError("invalid_purchase_receipt")
        deltas = [{"parent_id": 0, "currency_quantity": 1,
                   "currency_instance_id": event["currency_instance_id"],
                   "currency_item_id": require_uint64(offer["item_id"]),
                   "receiving_instance_id": require_uint64(pool[0][2]),
                   "receiving_quantity": 1, "receiving_item_id": pool_item}
                  for event, offer in zip(events, offers)]
        deltas[-1]["receiving_quantity"] += increase - len(events)
        return {"result": "ok", "saved": self.wire_saved(receipt["saved"]),
                "events": deltas, "properties": self._response_properties(request)}

    def _validate_consumable_purchase(
        self, request: dict, event: dict, snapshot: dict,
    ) -> tuple[str, int, dict, int]:
        offer = self.offers.get(event["po"])
        if offer is None:
            raise EconomyError("unknown_purchase_option")
        if offer["kind"] != "consumable":
            raise EconomyError("invalid_purchase_events")
        row = self.consumables_by_db_key[offer["consumable_db_key"]]
        deployed = self._deployed_by_instance.get(event["parent_id"])
        if deployed is None:
            raise EconomyError("invalid_purchase_parent")
        commander_key, deployed_slot = deployed
        unit_key = snapshot["commanders"][commander_key]["equipped_units"][deployed_slot]
        unit = self.economy.units.get(unit_key)
        capacity = unit.get("num_consumable_slots") if isinstance(unit, dict) else None
        if (unit is None
                or unit.get("build_state", "live") != "live"
                or type(capacity) is not int or capacity <= 0):
            raise EconomyError("consumable_not_available_to_unit")
        if (row["tier"] != EFFECTIVE_UNIT_TIER
                or row["db_key"] not in {
                    candidate["db_key"]
                    for candidate in self.consumables_by_unit.get(unit_key, [])
                }):
            raise EconomyError("consumable_tier_mismatch")
        # A live picker purchase sends the catalogue receiving quantity and
        # asks the server to allocate the selected type-11 instance.
        if event["po_quantity"] != 1:
            raise EconomyError("invalid_purchase_quantity")
        if event["receiving_instance_id"] != 0:
            raise EconomyError("invalid_receiving_instance")
        if event["currency_instance_id"] != self.wallet_instance_id(offer["currency"]):
            raise EconomyError("invalid_currency_instance")
        return commander_key, deployed_slot, row, capacity

    def _consumable_response(
        self, request: dict, event: dict, snapshot: dict,
    ) -> dict:
        commander_key, deployed_slot, row, capacity = (
            self._validate_consumable_purchase(request, event, snapshot)
        )
        operation_id = self._loadout_operation_id(
            "consumable", request, [event],
        )
        receipt = self.economy.select_consumable(
            operation_id, commander_key, deployed_slot, row["db_key"],
        )
        receipt_slot = receipt.get("slot")
        if type(receipt_slot) is not int or not 0 <= receipt_slot < capacity:
            raise EconomyError("invalid_consumable_receipt")
        old_key = receipt.get("previous_consumable")
        new_key = receipt.get("consumable")
        if old_key == new_key:
            response_events: list[dict] = []
        else:
            delta: dict[str, int] = {"parent_id": event["parent_id"]}
            if old_key is not None:
                old = self.consumables_by_db_key.get(old_key)
                if old is None:
                    raise EconomyError("invalid_consumable_receipt")
                delta.update({
                    "currency_quantity": 1,
                    "currency_instance_id": self.consumable_instance_id(
                        commander_key, deployed_slot, old_key,
                    ),
                    "currency_item_id": require_uint64(old["item_id"]),
                })
            if new_key is not None:
                new = self.consumables_by_db_key.get(new_key)
                if new is None or new["tier"] != EFFECTIVE_UNIT_TIER:
                    raise EconomyError("invalid_consumable_receipt")
                delta.update({
                    "receiving_instance_id": self.consumable_instance_id(
                        commander_key, deployed_slot, new_key,
                    ),
                    "receiving_quantity": 1,
                    "receiving_item_id": require_uint64(new["item_id"]),
                })
            response_events = [delta]
        return {
            "result": "ok",
            "saved": self.wire_saved(receipt["saved"]),
            "events": response_events,
            "properties": self._response_properties(request),
        }

    def _consumable_batch_response(
        self, request: dict, events: list[dict], snapshot: dict,
    ) -> dict:
        """The stock unit replacement re-equips compatible type-11 rows together."""
        if len({event["parent_id"] for event in events}) != 1:
            raise EconomyError("invalid_purchase_parent")
        keys = [self.offers[event["po"]]["consumable_db_key"] for event in events]
        if len(set(keys)) != len(keys):
            raise EconomyError("invalid_consumable_batch")
        operation = self._loadout_operation_id("consumable-batch", request, events)
        existing = snapshot["operations"].get(operation)
        if existing is not None:
            receipt = existing["receipt"]
            # An additive type-11 delta must never run twice, including after
            # a restart or a subsequent unit swap. Replay the current graph.
            self.economy.select_consumables(
                operation, receipt["commander"], receipt["deployed_slot"], keys,
                expected_saved=receipt["saved_before"],
            )
            return self._authoritative_resync_response(request, self.build_profile()["profile"])
        validated = [self._validate_consumable_purchase(request, event, snapshot)
                     for event in events]
        commander, slot, _row, capacity = validated[0]
        if len(events) > capacity:
            raise EconomyError("consumable_slot_unavailable")
        if request["profile_timestamp"] != self.wire_saved(snapshot["saved"]):
            raise EconomyError("consumable_state_changed")
        receipt = self.economy.select_consumables(
            operation, commander, slot, keys, expected_saved=snapshot["saved"],
        )
        return {
            "result": "ok", "saved": self.wire_saved(receipt["saved"]),
            "events": [{
                "parent_id": events[0]["parent_id"],
                "receiving_instance_id": self.consumable_instance_id(commander, slot, key),
                "receiving_quantity": 1,
                "receiving_item_id": require_uint64(self.consumables_by_db_key[key]["item_id"]),
            } for key in receipt["added"]],
            "properties": self._response_properties(request),
        }

    def _consumable_refund_response(
        self, request: dict, event: dict, snapshot: dict,
    ) -> dict:
        offer = self.offers.get(event["po"])
        if offer is None:
            raise EconomyError("unknown_purchase_option")
        if offer["kind"] != "consumable_refund":
            raise EconomyError("invalid_purchase_events")
        row = self.consumables_by_db_key[offer["consumable_db_key"]]
        deployed = self._deployed_by_instance.get(event["parent_id"])
        if deployed is None:
            raise EconomyError("invalid_purchase_parent")
        commander_key, deployed_slot = deployed
        unit_key = snapshot["commanders"][commander_key]["equipped_units"][
            deployed_slot
        ]
        unit = self.economy.units.get(unit_key)
        if (unit is None
                or unit.get("build_state", "live") != "live"
                or row["tier"] != EFFECTIVE_UNIT_TIER
                or row["db_key"] not in {
                    candidate["db_key"]
                    for candidate in self.consumables_by_unit.get(unit_key, [])
                }):
            raise EconomyError("consumable_not_available_to_unit")

        # C4BC60 builds the refund request with the deployed unit as parent,
        # no input instance, the profile quantity as PO quantity, and the
        # selected type-11 profile instance in ``receiving_instance_id``.
        # Despite the generic field name this is the row being removed, not
        # the silver wallet: a live Epona refund carried the exact instance
        # from [deployed parent, arena_consumables item, instance, quantity].
        # Resolve that identity from the authoritative commander/slot/PO
        # tuple so a client cannot nominate another profile row.
        if event["po_quantity"] != row["quantity"]:
            raise EconomyError("invalid_purchase_quantity")
        if event["currency_instance_id"] != 0:
            raise EconomyError("invalid_currency_instance")
        if event["receiving_instance_id"] != self.consumable_instance_id(
                commander_key, deployed_slot, row["db_key"]):
            raise EconomyError("invalid_receiving_instance")

        operation_id = self._loadout_operation_id(
            "consumable-refund", request, [event],
        )
        receipt = self.economy.clear_consumable(
            operation_id, commander_key, deployed_slot, row["db_key"],
        )
        if (receipt.get("previous_consumable") != row["db_key"]
                or receipt.get("consumable") is not None):
            raise EconomyError("invalid_consumable_receipt")
        return {
            "result": "ok",
            "saved": self.wire_saved(receipt["saved"]),
            "events": [{
                "parent_id": event["parent_id"],
                "currency_quantity": row["quantity"],
                "currency_instance_id": self.consumable_instance_id(
                    commander_key, deployed_slot, row["db_key"],
                ),
                "currency_item_id": require_uint64(row["item_id"]),
            }],
            "properties": self._response_properties(request),
        }

    def handle_purchase_request(self, request: object) -> dict:
        """Validate and apply one decoded native ``/event`` request."""
        request, events, snapshot = self._validate_request(
            request, validate_current_properties=False,
        )
        offers = [self.offers.get(event["po"]) for event in events]
        if any(offer is None for offer in offers):
            raise EconomyError("unknown_purchase_option")
        cleanup = self._unit_change_cleanup_response(
            request, events, snapshot,
        )
        if cleanup is not None:
            return cleanup
        kinds = {offer["kind"] for offer in offers if offer is not None}
        if len(events) > 1 and kinds == {"ability_refund"}:
            return self._ability_tree_reset_response(request, events, snapshot)
        # Four/five-event requests are reserved for the fully proven cleanup
        # path above.  Never let an unproven larger batch reach a kind-specific
        # handler (or become an accidental partial transaction).
        if len(events) > 3:
            raise EconomyError("invalid_purchase_events")
        if len(events) == 1 and kinds <= {"ability", "ability_refund"}:
            retry = self._ability_retry_response(
                request, events[0], snapshot, offers[0],
            )
            if retry is not None:
                return retry
        # Equipment and consumables are keyed by the on-screen unit, not the
        # durable active commander.  The hangar posts the commander currently
        # shown in the panel, which diverges while faction tabs hop (R21 live:
        # Persian camel-lancer armour and later consumable picks 409
        # ``active_commander_mismatch``, so the overlay never rebuilt).
        # Ability purchases stay commander-scoped and still require a match.
        if kinds not in ({"equipment"}, {"equipment_unlock"},
                          {"unit_ability"},
                          {"consumable"}, {"consumable_refund"}):
            self._validate_optional_properties(request, snapshot)
        if kinds == {"equipment"}:
            return self._equipment_response(request, events, snapshot)
        if kinds == {"unit_ability"}:
            return self._unit_ability_response(request, events, snapshot)
        if kinds == {"equipment_unlock"} and len(events) == 1:
            return self._equipment_unlock_response(request, events[0], snapshot)
        if kinds == {"commander_tier"} and len(events) == 1:
            return self._commander_tier_response(request, events[0], snapshot)
        if kinds == {"consumable"} and len(events) == 1:
            return self._consumable_response(request, events[0], snapshot)
        if kinds == {"consumable"}:
            return self._consumable_batch_response(request, events, snapshot)
        if kinds == {"consumable_refund"} and len(events) == 1:
            return self._consumable_refund_response(
                request, events[0], snapshot,
            )
        if kinds == {"ability"} and len(events) == 1:
            return self._ability_response(request, events[0], snapshot)
        if kinds == {"ability_refund"} and len(events) == 1:
            return self._ability_refund_response(
                request, events[0], snapshot,
            )
        if kinds == {"talent_point"} and len(events) == 1:
            return self._talent_point_response(request, events[0], snapshot)
        if len(events) == 1 and kinds <= {"unit", "commander"}:
            return self._standard_purchase_response(
                request, events[0], snapshot,
            )
        raise EconomyError("invalid_purchase_events")

    def settlement_reward_events(self, receipt: object) -> list[dict]:
        """Encode one trusted PvE receipt as native positive item deltas.

        Static consumer proof is in ``game.dll`` BFEF50.  Its ``result=ok``
        path iterates ``events`` at BFF3D6.  BFF5D1 reads
        ``receiving_instance_id``; when that instance already exists, BFF673
        reads ``receiving_quantity`` and BCABB0 applies it to the profile row.
        BFF6E1 also reads ``receiving_item_id`` for the new-row path.  The
        separate ``currency_*`` branch at BFF3F0 negates its quantity and is
        therefore the proven purchase/spend side, not a reward grant.

        Every local reward target below is already projected by build_profile:
        account wallets are roots, and unit/commander XP are child rows.  No
        client-supplied ID, quantity or target participates in this encoding.
        """
        receipt_fields = {
            "operation_id", "kind", "saved", "match_id", "outcome", "verified",
            "battle_tier", "roster_hash", "rewards", "commander",
            "commander_tier_before", "commander_tier_after", "balances",
            "daily_quests",
        }
        if (not isinstance(receipt, dict)
                or not receipt_fields <= set(receipt)
                or not set(receipt) <= receipt_fields | {"reward_authority"}
                or receipt.get("kind") not in {"settle_pve", "settle_pvp"}
                or not isinstance(receipt.get("rewards"), dict)
                or not isinstance(receipt.get("commander"), str)):
            raise EconomyError("invalid_settlement_receipt")
        rewards = receipt["rewards"]
        expected = {
            "unit_xp_cents", "commander_xp_cents", "free_xp_cents",
            "silver_cents", "gold_cents", "reward_version", "unit_xp_by_unit",
        }
        if set(rewards) != expected or not isinstance(rewards["unit_xp_by_unit"], dict):
            raise EconomyError("invalid_settlement_receipt")

        events: list[dict] = []

        def append(instance: int, item: int, quantity: object) -> None:
            amount = _uint64(quantity, "invalid_settlement_reward")
            if amount:
                events.append({
                    "receiving_instance_id": require_uint64(instance),
                    "receiving_quantity": amount,
                    "receiving_item_id": require_uint64(item),
                })

        for currency in ("free_xp_cents", "silver_cents", "gold_cents"):
            append(
                self.wallet_instance_id(currency),
                self.currency_item_ids[currency],
                rewards.get(currency),
            )

        commander_key = receipt["commander"]
        if commander_key not in self.commander_xp_instances:
            raise EconomyError("invalid_settlement_receipt")
        append(
            self.commander_xp_instance_id(commander_key),
            self.currency_item_ids["commander_xp_cents"],
            rewards.get("commander_xp_cents"),
        )
        unit_rewards = rewards["unit_xp_by_unit"]
        if (len(unit_rewards) > 3
                or any(not isinstance(key, str) or key not in self.unit_xp_instances
                       for key in unit_rewards)):
            raise EconomyError("invalid_settlement_receipt")
        for unit_key in sorted(unit_rewards):
            append(
                self.unit_xp_instance_id(unit_key),
                self.currency_item_ids["unit_xp_cents"],
                unit_rewards[unit_key],
            )
        return events


__all__ = ["NATIVE_SAVED_FLOOR", "NativeEconomyAdapter"]
