"""Validated native equipment ownership and unit-tree prerequisites.

The complete set covers every equipment row owned by a live, non-premium
unit. The Tier-I-through-V list is retained as a compatibility subset, while
the separate ``items`` set records the narrower upgrade-junction prerequisites
for all tiers. Keeping all three makes Tier-V+ equipment research persistent
without losing the exact row that unlocks a successor unit.
"""
from __future__ import annotations

import copy
import json
from collections import Counter
from pathlib import Path


DEFAULT_NATIVE_EQUIPMENT = (
    Path(__file__).resolve().parents[1] / "catalog" / "native_unit_equipment.json"
)


def load_native_unit_equipment(path: Path | None = None) -> dict:
    source = path if path is not None else DEFAULT_NATIVE_EQUIPMENT
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid native unit-equipment catalogue") from exc
    return validate_native_unit_equipment(value)


def validate_native_unit_equipment(value: object, native: dict | None = None) -> dict:
    if not isinstance(value, dict) or value.get("schema_version") != 3:
        raise ValueError("Unsupported native unit-equipment schema")
    items = value.get("items")
    all_items = value.get("all_live_nonpremium")
    compatibility_items = value.get("initial_nonpremium_tier_1_to_5")
    excluded = value.get("excluded")
    validation = value.get("validation")
    if (not isinstance(items, list) or not isinstance(all_items, list)
            or not isinstance(compatibility_items, list)
            or not isinstance(excluded, list) or not isinstance(validation, dict)):
        raise ValueError("Incomplete native unit-equipment catalogue")

    required = {
        "equipment_key", "db_key", "placement_0", "placement_1", "item_id",
        "effect", "source_unit", "raw_cost_0", "raw_cost_1", "enabled",
        "scope", "target_unit", "faction", "source_tier", "target_tier",
        "slot", "equipment_item_id", "equipment_raw_cost_0",
        "equipment_raw_cost_1", "equipment_raw_cost_2", "price_source",
    }
    keys: set[str] = set()
    item_ids: set[int] = set()
    item_key_by_id: dict[int, str] = {}
    items_by_key: dict[str, dict] = {}
    equipment_definitions: dict[str, tuple[int, str, int, int, int]] = {}
    pairs: set[tuple[str, str]] = set()
    factions: Counter[str] = Counter()
    for row in items:
        if not isinstance(row, dict) or set(row) != required:
            raise ValueError("Invalid native unit-equipment row")
        key, item_id = row["db_key"], row["item_id"]
        equipment_item_id = row["equipment_item_id"]
        source, target = row["source_unit"], row["target_unit"]
        if (not isinstance(key, str) or not key
                or not isinstance(row["equipment_key"], str) or not row["equipment_key"]
                or not isinstance(source, str) or not source
                or not isinstance(target, str) or not target
                or type(item_id) is not int or not 0 < item_id < 2**64
                or type(equipment_item_id) is not int
                or not 0 < equipment_item_id < 2**64
                or key in keys or item_id in item_ids
                or (source, target) in pairs
                or type(row["source_tier"]) is not int
                or type(row["target_tier"]) is not int
                or not 1 <= row["source_tier"] <= 10
                or not 1 <= row["target_tier"] <= 10
                or row["target_tier"] < row["source_tier"]
                or type(row["placement_0"]) is not int
                or type(row["placement_1"]) is not int
                or type(row["raw_cost_0"]) is not int or row["raw_cost_0"] < 0
                or type(row["raw_cost_1"]) is not int or row["raw_cost_1"] < 0
                or type(row["equipment_raw_cost_0"]) is not int
                or row["equipment_raw_cost_0"] < 0
                or type(row["equipment_raw_cost_1"]) is not int
                or row["equipment_raw_cost_1"] < 0
                or type(row["equipment_raw_cost_2"]) is not int
                or row["equipment_raw_cost_2"] < 0
                or row["enabled"] is not True
                or row["scope"] not in {"unit_only", "dogs_only"}
                or not isinstance(row["slot"], str) or not row["slot"]
                or not isinstance(row["faction"], str) or not row["faction"]
                or not isinstance(row["price_source"], str)):
            raise ValueError(f"Invalid native unit-equipment identity: {key!r}")
        if row["effect"] is not None and not isinstance(row["effect"], str):
            raise ValueError(f"Invalid native unit-equipment effect: {key}")
        keys.add(key)
        item_ids.add(item_id)
        item_key_by_id[item_id] = key
        items_by_key[key] = row
        definition = (
            equipment_item_id,
            row["slot"],
            row["equipment_raw_cost_0"],
            row["equipment_raw_cost_1"],
            row["equipment_raw_cost_2"],
        )
        previous_definition = equipment_definitions.setdefault(row["equipment_key"], definition)
        if previous_definition != definition:
            raise ValueError(f"Conflicting equipment definition: {row['equipment_key']}")
        pairs.add((source, target))
        factions[row["faction"]] += 1

    initial_required = required - {"target_unit", "target_tier"}
    initial_items = all_items
    initial_keys: set[str] = set()
    initial_item_ids: set[int] = set()
    initial_factions: Counter[str] = Counter()
    for row in initial_items:
        if not isinstance(row, dict) or set(row) != initial_required:
            raise ValueError("Invalid initial native unit-equipment row")
        key, item_id = row["db_key"], row["item_id"]
        equipment_item_id = row["equipment_item_id"]
        if (not isinstance(key, str) or not key
                or not isinstance(row["equipment_key"], str) or not row["equipment_key"]
                or not isinstance(row["source_unit"], str) or not row["source_unit"]
                or type(item_id) is not int or not 0 < item_id < 2**64
                or type(equipment_item_id) is not int
                or not 0 < equipment_item_id < 2**64
                or key in initial_keys or item_id in initial_item_ids
                or item_id in item_key_by_id and item_key_by_id[item_id] != key
                or type(row["source_tier"]) is not int
                or not 1 <= row["source_tier"] <= 10
                or type(row["placement_0"]) is not int
                or type(row["placement_1"]) is not int
                or row["placement_0"] < 0 or row["placement_1"] < 0
                or type(row["raw_cost_0"]) is not int or row["raw_cost_0"] < 0
                or type(row["raw_cost_1"]) is not int or row["raw_cost_1"] < 0
                or any(type(row[field]) is not int or row[field] < 0 for field in (
                    "equipment_raw_cost_0", "equipment_raw_cost_1", "equipment_raw_cost_2"))
                or row["enabled"] is not True
                or row["scope"] not in {"unit_only", "dogs_only"}
                or not isinstance(row["slot"], str) or not row["slot"]
                or not isinstance(row["faction"], str) or not row["faction"]
                or not isinstance(row["price_source"], str)
                or row["effect"] is not None and not isinstance(row["effect"], str)):
            raise ValueError(f"Invalid live native unit-equipment identity: {key!r}")
        definition = (
            equipment_item_id,
            row["slot"],
            row["equipment_raw_cost_0"],
            row["equipment_raw_cost_1"],
            row["equipment_raw_cost_2"],
        )
        previous_definition = equipment_definitions.setdefault(row["equipment_key"], definition)
        if previous_definition != definition:
            raise ValueError(f"Conflicting equipment definition: {row['equipment_key']}")
        initial_keys.add(key)
        initial_item_ids.add(item_id)
        initial_factions[row["faction"]] += 1

        shared = items_by_key.get(key)
        if shared is not None:
            shared_fields = {field: shared[field] for field in initial_required}
            if row != shared_fields:
                raise ValueError(f"Shared native equipment mismatch: {key}")

    all_by_key = {row["db_key"]: row for row in all_items}
    for row in compatibility_items:
        canonical = all_by_key.get(row.get("db_key")) if isinstance(row, dict) else None
        if canonical is None:
            raise ValueError("Initial equipment/unit metadata mismatch")
        if row != canonical:
            raise ValueError(f"Shared native equipment mismatch: {row['db_key']}")
    expected_compatibility = [
        row for row in all_items if row["source_tier"] <= 5
    ]
    if compatibility_items != expected_compatibility:
        raise ValueError("Tier-I-through-V equipment subset mismatch")
    compatibility_keys = {row["db_key"] for row in compatibility_items}

    if validation.get("live_required_equipment") != len(items):
        raise ValueError("Native unit-equipment count mismatch")
    if validation.get("all_live_nonpremium_equipment") != len(all_items):
        raise ValueError("All native unit-equipment count mismatch")
    if validation.get("initial_nonpremium_tier_1_to_5_equipment") != len(compatibility_items):
        raise ValueError("Initial native unit-equipment count mismatch")
    if validation.get("shared_initial_and_upgrade_equipment") != len(compatibility_keys & keys):
        raise ValueError("Shared native unit-equipment count mismatch")
    if validation.get("excluded_non_live_junctions") != len(excluded):
        raise ValueError("Native unit-equipment exclusion count mismatch")
    if validation.get("factions") != dict(sorted(factions.items())):
        raise ValueError("Native unit-equipment faction count mismatch")
    if set(initial_factions) != set(factions):
        raise ValueError("Initial native unit-equipment faction coverage mismatch")
    if not {row["db_key"] for row in items if row["source_tier"] <= 5} <= compatibility_keys:
        raise ValueError("Required equipment is missing from initial ownership")

    if native is not None:
        if not isinstance(native, dict):
            raise TypeError("native must be an object")
        units = {
            row["key"]: row for row in native.get("units", [])
            if isinstance(row, dict) and row.get("build_state", "live") == "live"
        }
        links = {
            (row.get("key_0"), row.get("key_1"))
            for row in native.get("unit_tree_links", []) if isinstance(row, dict)
        }
        for row in items:
            source = units.get(row["source_unit"])
            target = units.get(row["target_unit"])
            if source is None or target is None:
                raise ValueError(f"Equipment references a non-live unit: {row['db_key']}")
            if (row["source_unit"], row["target_unit"]) not in links:
                raise ValueError(f"Equipment is not on a direct unit-tree edge: {row['db_key']}")
            if (source["faction"] != target["faction"]
                    or source["faction"] != row["faction"]
                    or source["tier"] != row["source_tier"]
                    or target["tier"] != row["target_tier"]
                    or source.get("is_premium") or target.get("is_premium")):
                raise ValueError(f"Equipment/unit metadata mismatch: {row['db_key']}")
        for row in initial_items:
            source = units.get(row["source_unit"])
            if (source is None or source["faction"] != row["faction"]
                    or source["tier"] != row["source_tier"]
                    or source.get("is_premium") is not False
                    or not 1 <= source["tier"] <= 10):
                raise ValueError(f"Equipment/unit metadata mismatch: {row['db_key']}")
    return copy.deepcopy(value)


def equipment_for_owned_units(equipment: dict, owned_units: set[str]) -> list[dict]:
    validated = validate_native_unit_equipment(equipment)
    if (not isinstance(owned_units, set)
            or any(not isinstance(key, str) for key in owned_units)):
        raise TypeError("owned_units must be a set of unit keys")
    return [
        row for row in validated["initial_nonpremium_tier_1_to_5"]
        if row["source_unit"] in owned_units
    ]


def equipment_for_units(equipment: dict, unit_keys: set[str]) -> list[dict]:
    """Return every selectable row for the named live non-premium units."""
    validated = validate_native_unit_equipment(equipment)
    if (not isinstance(unit_keys, set)
            or any(not isinstance(key, str) for key in unit_keys)):
        raise TypeError("unit_keys must be a set of unit keys")
    return [
        row for row in validated["all_live_nonpremium"]
        if row["source_unit"] in unit_keys
    ]


def selected_equipment_for_owned_units(
    equipment: dict, owned_units: set[str],
) -> list[dict]:
    """Resolve one highest-placement unit-only item for every unit slot.

    The type-5 row proves that unit-specific tree item is unlocked. Its
    referenced type-9 definition is the selected equipment definition. Native
    battle setup consumes both maps from the parentless owned-unit root.
    """
    by_slot: dict[tuple[str, str, str], list[dict]] = {}
    for row in equipment_for_owned_units(equipment, owned_units):
        by_slot.setdefault(
            (row["source_unit"], row["scope"], row["slot"]), [],
        ).append(row)
    selected: list[dict] = []
    for key, candidates in sorted(by_slot.items()):
        if len({row["placement_0"] for row in candidates}) != 1:
            raise ValueError(f"Conflicting native equipment slot placement: {key!r}")
        highest = max(row["placement_1"] for row in candidates)
        matches = [row for row in candidates if row["placement_1"] == highest]
        if len(matches) != 1:
            raise ValueError(f"Ambiguous native equipment slot selection: {key!r}")
        selected.append(matches[0])
    return selected


def augment_native_equipment_mappings(official: dict, equipment: dict) -> dict:
    """Overlay exact current prerequisite IDs onto the served mapping table.

    Legacy production metadata is preserved when present and structurally
    agrees with the current DB.  New-faction rows use the current DB's local
    fallback costs; profile projection owns these rows, so they do not define
    a chargeable server purchase path.
    """
    if not isinstance(official, dict):
        raise TypeError("official must be an object")
    equipment = validate_native_unit_equipment(equipment)
    result = copy.deepcopy(official)
    rows = result.setdefault("item_mappings", [])
    if not isinstance(rows, list):
        raise ValueError("item_mappings must be a list")
    indices: dict[tuple[str, str], int] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError("Invalid item mapping")
        typed = (row.get("type"), row.get("db_key"))
        # The recovered legacy file contains unrelated duplicate keys (for
        # example arena_frontend_scenes/test). Preserve those byte-for-byte;
        # only this function's equipment namespace must be unambiguous.
        if typed[0] not in {"arena_unit_equipment_trees", "arena_unit_equipments"}:
            continue
        if typed in indices:
            raise ValueError(f"Duplicate item mapping: {typed!r}")
        indices[typed] = index

    mapped_items = list(equipment["all_live_nonpremium"])
    known_mapped_keys = {row["db_key"] for row in mapped_items}
    mapped_items.extend(row for row in equipment["items"]
                        if row["db_key"] not in known_mapped_keys)
    for item in mapped_items:
        typed = ("arena_unit_equipment_trees", item["db_key"])
        previous = rows[indices[typed]] if typed in indices else None
        if previous is not None:
            if previous.get("item_id") != item["item_id"]:
                raise ValueError(f"Stale native equipment ID: {item['db_key']}")
            metadata = previous.get("metadata")
            if (not isinstance(metadata, dict)
                    or metadata.get("equipment_key") != item["equipment_key"]
                    or metadata.get("slot") != item["slot"]):
                raise ValueError(f"Stale native equipment metadata: {item['db_key']}")
            new_row = copy.deepcopy(previous)
            # Several Roman artillery units moved tiers while retaining the
            # same canonical equipment ID. Keep known legacy service prices,
            # but take structural tier placement from the current DB.
            new_row["metadata"]["tier"] = item["source_tier"]
        else:
            new_row = {
                "allow_from_api": False,
                "db_key": item["db_key"],
                "item_id": item["item_id"],
                "metadata": {
                    "equipment_key": item["equipment_key"],
                    "gold_cents": item["raw_cost_1"],
                    "silver_cents": item["raw_cost_0"],
                    "slot": item["slot"],
                    "tier": item["source_tier"],
                },
                "type": "arena_unit_equipment_trees",
            }
        if previous is None:
            indices[typed] = len(rows)
            rows.append(new_row)
        else:
            rows[indices[typed]] = new_row

    definitions: dict[str, dict] = {}
    for item in mapped_items:
        key = item["equipment_key"]
        definition = {
            "item_id": item["equipment_item_id"],
            "slot": item["slot"],
            "raw_cost_0": item["equipment_raw_cost_0"],
        }
        previous_definition = definitions.setdefault(key, definition)
        if previous_definition != definition:
            raise ValueError(f"Conflicting equipment definition: {key}")

    for key, definition in sorted(definitions.items()):
        typed = ("arena_unit_equipments", key)
        previous = rows[indices[typed]] if typed in indices else None
        if previous is not None:
            if previous.get("item_id") != definition["item_id"]:
                raise ValueError(f"Stale native equipment-definition ID: {key}")
            metadata = previous.get("metadata")
            if not isinstance(metadata, dict) or metadata.get("slot") != definition["slot"]:
                raise ValueError(f"Stale native equipment-definition metadata: {key}")
            new_row = copy.deepcopy(previous)
        else:
            # Current DB costs are a local compatibility fallback, not a
            # recovered service economy. These definitions are dependencies
            # of already-owned type-5 rows and have no purchase endpoint.
            new_row = {
                "allow_from_api": False,
                "db_key": key,
                "item_id": definition["item_id"],
                "metadata": {
                    "free_xp_cents": definition["raw_cost_0"],
                    "slot": definition["slot"],
                    "unit_xp_cents": definition["raw_cost_0"],
                },
                "type": "arena_unit_equipments",
            }
        if previous is None:
            indices[typed] = len(rows)
            rows.append(new_row)
        else:
            rows[indices[typed]] = new_row
    return result


__all__ = [
    "DEFAULT_NATIVE_EQUIPMENT",
    "augment_native_equipment_mappings",
    "equipment_for_owned_units",
    "equipment_for_units",
    "load_native_unit_equipment",
    "selected_equipment_for_owned_units",
    "validate_native_unit_equipment",
]
