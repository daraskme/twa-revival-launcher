"""Native consumables and exact shipped unit compatibility.

Every enabled inventory definition is retained, including Tier VI through X.
The initially served set is narrower: live, non-premium Tier-I-through-V units
receive only definitions linked to their exact DB key through the shipped
metagame group tables. This preserves faction, Tier, role and unit-specific
differences without inferring them from names.
"""
from __future__ import annotations

import copy
import json
import re
from collections import Counter
from pathlib import Path


DEFAULT_NATIVE_BATTLE_CONSUMABLES = (
    Path(__file__).resolve().parents[1] / "catalog" / "native_battle_consumables.json"
)

_TIERED_KEY = re.compile(r"(?P<base>.+)_(?P<tier>[1-9]|10)\Z")
_DEFINITION_FIELDS = {
    "tier", "db_key", "quantity", "item_id", "ability", "effect", "amount",
    "enabled", "metagame_groups", "unit_keys", "consumable_row_index",
    "consumable_row_offset",
}
_SOURCE_FIELDS = {
    "tables", "join_evidence", "sentinel_evidence",
    "schema_compatibility_evidence",
}
_SOURCE_TABLES = {
    "arena_consumables", "arena_consumables_to_units", "unique_id_lookups",
    "metagame_groups_to_land_units", "metagame_groups_to_unit_effects",
}
_COMPATIBILITY_FIELDS = {
    "mode", "definition_scope", "service_unit_scope", "tier_rule",
    "premium_and_late_policy", "sentinel_groups_excluded",
    "legacy_direct_links", "legacy_direct_link_semantics",
}
_VALIDATION_FIELDS = {
    "verified_definitions", "verified_defaults", "disabled_definitions",
    "family_count", "tier_counts", "definitions_with_playable_unit_links",
    "definition_unit_links", "service_definitions", "service_unit_links",
    "service_candidate_count_distribution",
    "live_nonpremium_tier_1_to_5_units",
    "live_nonpremium_tier_1_to_5_factions",
    "bar_mounted_warband_tier_5_candidates",
    "all_definition_item_ids_verified_against_current_lookup",
    "all_consumable_effects_have_metagame_links", "all_definitions_enabled",
    "all_initial_units_match_slot_availability",
}


def load_native_battle_consumables(path: Path | None = None) -> dict:
    source = DEFAULT_NATIVE_BATTLE_CONSUMABLES if path is None else path
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid native battle-consumables catalogue") from exc
    return validate_native_battle_consumables(value)


def _validate_source(source: object) -> None:
    if not isinstance(source, dict) or set(source) != _SOURCE_FIELDS:
        raise ValueError("Invalid native battle-consumables source")
    tables = source["tables"]
    if not isinstance(tables, dict) or set(tables) != _SOURCE_TABLES:
        raise ValueError("Invalid native battle-consumables source tables")
    for field in _SOURCE_FIELDS - {"tables"}:
        if not isinstance(source[field], str) or not source[field]:
            raise ValueError("Incomplete native battle-consumables evidence")
    for name, table in tables.items():
        if (not isinstance(table, dict)
                or not isinstance(table.get("entry"), str)
                or not isinstance(table.get("guid"), str)
                or type(table.get("version")) is not int
                or type(table.get("count")) is not int or table["count"] <= 0
                or type(table.get("bytes")) is not int or table["bytes"] <= 0
                or type(table.get("body_offset")) is not int
                or not isinstance(table.get("sha256"), str)
                or len(table["sha256"]) != 64
                or table.get("complete_cursor") != table["bytes"]):
            raise ValueError(f"Invalid native battle-consumables table: {name}")


def _validate_compatibility(value: object, definition_keys: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != _COMPATIBILITY_FIELDS:
        raise ValueError("Invalid native consumable compatibility")
    if (value["mode"] != "exact_metagame_group_join"
            or value["definition_scope"] != "all_enabled_tier_1_to_10_rows"
            or value["service_unit_scope"] != "live_nonpremium_tier_1_to_5"
            or value["tier_rule"] != "definition_tier_equals_selected_unit_tier"
            or value["premium_and_late_policy"]
            != "catalogued_not_initially_served"
            or value["sentinel_groups_excluded"] != ["NOBODY"]
            or not isinstance(value["legacy_direct_link_semantics"], str)
            or not value["legacy_direct_link_semantics"]):
        raise ValueError("Unsupported native consumable compatibility")
    links = value["legacy_direct_links"]
    if not isinstance(links, list):
        raise ValueError("Invalid native consumable legacy links")
    identities: set[tuple[str, str]] = set()
    for row in links:
        identity = (
            row.get("consumable_key"), row.get("unit_key")
        ) if isinstance(row, dict) else (None, None)
        if (not isinstance(row, dict)
                or set(row) != {"consumable_key", "raw_value", "unit_key"}
                or not isinstance(identity[0], str) or not identity[0]
                or not isinstance(identity[1], str) or not identity[1]
                or type(row["raw_value"]) is not int or row["raw_value"] <= 0
                or identity in identities or identity[0] in definition_keys):
            raise ValueError("Invalid native consumable legacy link")
        identities.add(identity)


def _validate_string_list(value: object, *, allow_empty: bool) -> bool:
    return (isinstance(value, list)
            and (allow_empty or bool(value))
            and all(isinstance(item, str) and item for item in value)
            and value == sorted(set(value)))


def _initial_units(native: dict) -> list[dict]:
    return [
        row for row in native.get("units", [])
        if (isinstance(row, dict)
            and row.get("build_state", "live") == "live"
            and row.get("is_premium") is False
            and type(row.get("tier")) is int
            and row["tier"] in range(1, 6))
    ]


def _candidates(definitions: list[dict], unit: dict) -> list[dict]:
    return [
        row for row in definitions
        if row["tier"] == unit["tier"] and unit["key"] in row["unit_keys"]
    ]


def _live_units(native: dict) -> dict[str, dict]:
    rows = [
        row for row in native.get("units", [])
        if isinstance(row, dict) and row.get("build_state", "live") == "live"
    ]
    units = {row.get("key"): row for row in rows}
    if None in units or len(units) != len(rows):
        raise ValueError("Duplicate live consumable unit")
    return units


def _tier_equivalent_candidates(
    definitions: list[dict], native: dict, unit_key: str, effective_tier: int,
) -> list[dict]:
    """Promote a unit's exact native consumable families to another Tier.

    The DB links every Tier-II-through-X live unit to its compatible effect
    families. Tier-I units deliberately have no consumable slots, so for the
    Revival Tier-X sandbox they inherit the families of their direct Tier-II
    successor. The final rows are always the same families' real Tier-X DB
    definitions; no compatibility is inferred from display names.
    """
    if type(effective_tier) is not int or not 1 <= effective_tier <= 10:
        raise ValueError("Invalid effective consumable tier")
    units = _live_units(native)
    unit = units.get(unit_key)
    if unit is None:
        return []

    source_rows = _candidates(definitions, unit)
    if not source_rows and unit.get("tier") == 1:
        children = sorted({
            row.get("key_1") for row in native.get("unit_tree_links", [])
            if (isinstance(row, dict) and row.get("key_0") == unit_key
                and row.get("key_1") in units
                and units[row["key_1"]].get("tier") == 2)
        })
        source_rows = [
            candidate for child in children
            for candidate in _candidates(definitions, units[child])
        ]

    families = {
        match.group("base")
        for row in source_rows
        if (match := _TIERED_KEY.fullmatch(row["db_key"])) is not None
    }
    promoted = [
        row for row in definitions
        if row["tier"] == effective_tier
        and (match := _TIERED_KEY.fullmatch(row["db_key"])) is not None
        and match.group("base") in families
    ]
    if len(promoted) != len(families):
        raise ValueError(f"Incomplete Tier-equivalent consumables: {unit_key}")
    return sorted(promoted, key=lambda row: row["db_key"])


def validate_native_battle_consumables(
    value: object, native: dict | None = None, official: dict | None = None,
) -> dict:
    if not isinstance(value, dict) or value.get("schema_version") != 4:
        raise ValueError("Unsupported native battle-consumables schema")
    if set(value) != {
        "schema_version", "source", "compatibility", "definitions",
        "defaults", "exclusions", "validation",
    }:
        raise ValueError("Invalid native battle-consumables catalogue")
    _validate_source(value["source"])

    definitions = value["definitions"]
    if not isinstance(definitions, list) or not definitions:
        raise ValueError("Incomplete native battle-consumables catalogue")
    db_keys: set[str] = set()
    item_ids: set[int] = set()
    tier_counts: Counter[int] = Counter()
    family_tiers: dict[str, set[int]] = {}
    for row in definitions:
        if not isinstance(row, dict) or set(row) != _DEFINITION_FIELDS:
            raise ValueError("Invalid native battle-consumable definition")
        db_key = row["db_key"]
        match = _TIERED_KEY.fullmatch(db_key) if isinstance(db_key, str) else None
        if (match is None or type(row["tier"]) is not int
                or not 1 <= row["tier"] <= 10
                or int(match.group("tier")) != row["tier"]
                or not isinstance(row["ability"], str) or not row["ability"]
                or row["effect"] != db_key
                or type(row["item_id"]) is not int
                or not 0 < row["item_id"] < 2**64
                or type(row["quantity"]) is not int or row["quantity"] != 1
                or type(row["amount"]) is not int or row["amount"] <= 0
                or row["enabled"] is not True
                or not _validate_string_list(
                    row["metagame_groups"], allow_empty=True,
                )
                or "NOBODY" in row["metagame_groups"]
                or not _validate_string_list(row["unit_keys"], allow_empty=True)
                or any(type(row[field]) is not int or row[field] < 0 for field in (
                    "consumable_row_index", "consumable_row_offset",
                ))
                or db_key in db_keys or row["item_id"] in item_ids):
            raise ValueError(f"Invalid native battle-consumable identity: {db_key!r}")
        db_keys.add(db_key)
        item_ids.add(row["item_id"])
        tier_counts[row["tier"]] += 1
        family_tiers.setdefault(match.group("base"), set()).add(row["tier"])
    if definitions != sorted(
        definitions, key=lambda row: (row["tier"], row["db_key"])
    ):
        raise ValueError("Native battle-consumable definitions are not canonical")
    if any(tiers != set(range(1, 11)) for tiers in family_tiers.values()):
        raise ValueError("Incomplete native consumable Tier-I-through-X family")

    _validate_compatibility(value["compatibility"], db_keys)
    if value["defaults"] != []:
        raise ValueError("Schema 4 has no inferred native consumable defaults")

    exclusions = value["exclusions"]
    if not isinstance(exclusions, dict) or set(exclusions) != {
        "disabled_definitions", "enabled_without_playable_unit_links",
    }:
        raise ValueError("Invalid native consumable exclusions")
    disabled = exclusions["disabled_definitions"]
    if not isinstance(disabled, list):
        raise ValueError("Invalid disabled native consumables")
    disabled_keys: set[str] = set()
    for row in disabled:
        key = row.get("db_key") if isinstance(row, dict) else None
        if (not isinstance(row, dict)
                or set(row) != {
                    "db_key", "consumable_row_index", "consumable_row_offset",
                    "reason",
                }
                or not isinstance(key, str) or not key
                or row["reason"] != "arena_consumables_row_disabled"
                or type(row["consumable_row_index"]) is not int
                or row["consumable_row_index"] < 0
                or type(row["consumable_row_offset"]) is not int
                or row["consumable_row_offset"] < 0
                or key in db_keys or key in disabled_keys):
            raise ValueError("Invalid disabled native consumable exclusion")
        disabled_keys.add(key)
    if disabled != sorted(disabled, key=lambda row: row["db_key"]):
        raise ValueError("Disabled native consumables are not canonical")
    without_links = sum(not row["unit_keys"] for row in definitions)
    if exclusions["enabled_without_playable_unit_links"] != without_links:
        raise ValueError("Native consumable unlinked count mismatch")

    validation = value["validation"]
    if not isinstance(validation, dict) or set(validation) != _VALIDATION_FIELDS:
        raise ValueError("Invalid native battle-consumables validation")
    factions = validation["live_nonpremium_tier_1_to_5_factions"]
    candidate_distribution = validation["service_candidate_count_distribution"]
    mounted = validation["bar_mounted_warband_tier_5_candidates"]
    if (not isinstance(factions, dict) or not factions
            or any(not isinstance(key, str) or not key
                   or type(count) is not int or count <= 0
                   for key, count in factions.items())
            or not isinstance(candidate_distribution, dict)
            or any(not isinstance(key, str) or not key.isdigit()
                   or type(count) is not int or count <= 0
                   for key, count in candidate_distribution.items())
            or not _validate_string_list(mounted, allow_empty=False)
            or any(validation[field] is not True for field in (
                "all_definition_item_ids_verified_against_current_lookup",
                "all_consumable_effects_have_metagame_links",
                "all_definitions_enabled",
                "all_initial_units_match_slot_availability",
            ))):
        raise ValueError("Invalid native consumable validation evidence")
    expected_embedded = {
        "verified_definitions": len(definitions),
        "verified_defaults": 0,
        "disabled_definitions": len(disabled),
        "family_count": len(family_tiers),
        "tier_counts": {
            str(key): tier_counts[key] for key in sorted(tier_counts)
        },
        "definitions_with_playable_unit_links": sum(
            bool(row["unit_keys"]) for row in definitions
        ),
        "definition_unit_links": sum(len(row["unit_keys"]) for row in definitions),
        "bar_mounted_warband_tier_5_candidates": sorted(
            row["db_key"] for row in definitions
            if (row["tier"] == 5
                and "bar_mounted_warband" in row["unit_keys"])
        ),
    }
    for field, expected in expected_embedded.items():
        if validation[field] != expected:
            raise ValueError("Native battle-consumables validation mismatch")
    if (type(validation["service_definitions"]) is not int
            or validation["service_definitions"] <= 0
            or type(validation["service_unit_links"]) is not int
            or validation["service_unit_links"] <= 0
            or type(validation["live_nonpremium_tier_1_to_5_units"]) is not int
            or validation["live_nonpremium_tier_1_to_5_units"] <= 0
            or sum(factions.values())
            != validation["live_nonpremium_tier_1_to_5_units"]
            or sum(candidate_distribution.values())
            != validation["live_nonpremium_tier_1_to_5_units"]):
        raise ValueError("Invalid native consumable service coverage")

    if native is not None:
        if not isinstance(native, dict):
            raise TypeError("native must be an object")
        initial_units = _initial_units(native)
        units = {row.get("key"): row for row in initial_units}
        if len(units) != len(initial_units):
            raise ValueError("Duplicate live consumable unit")
        actual_factions = Counter(row.get("faction") for row in initial_units)
        candidates_by_unit = {
            key: _candidates(definitions, unit) for key, unit in units.items()
        }
        for key, rows in candidates_by_unit.items():
            capacity = units[key].get("num_consumable_slots")
            if (type(capacity) is not int or not 0 <= capacity <= 10
                    or (capacity > 0) != bool(rows)):
                raise ValueError(
                    f"Native consumable slot/link mismatch: {key}"
                )
        actual_distribution = Counter(len(rows) for rows in candidates_by_unit.values())
        actual_service_keys = {
            row["db_key"] for rows in candidates_by_unit.values() for row in rows
        }
        if (len(initial_units)
                != validation["live_nonpremium_tier_1_to_5_units"]
                or dict(sorted(actual_factions.items())) != factions
                or len(actual_service_keys) != validation["service_definitions"]
                or sum(len(rows) for rows in candidates_by_unit.values())
                != validation["service_unit_links"]
                or {str(key): actual_distribution[key]
                    for key in sorted(actual_distribution)}
                != candidate_distribution):
            raise ValueError("Native consumable service coverage mismatch")

    if official is not None:
        if not isinstance(official, dict):
            raise TypeError("official must be an object")
        mappings: dict[str, list[dict]] = {}
        for row in official.get("item_mappings", []):
            if isinstance(row, dict) and row.get("type") == "arena_consumables":
                mappings.setdefault(row.get("db_key"), []).append(row)
        for definition in definitions:
            rows = mappings.get(definition["db_key"], [])
            if len(rows) > 1:
                raise ValueError(
                    f"Duplicate native consumable mapping: {definition['db_key']}"
                )
            if not rows:
                continue
            metadata = rows[0].get("metadata")
            if (rows[0].get("item_id") != definition["item_id"]
                    or rows[0].get("allow_from_api") is not False
                    or not isinstance(metadata, dict)
                    or any(type(metadata.get(currency)) is not int
                           or metadata[currency] < 0
                           for currency in ("silver_cents", "gold_cents"))):
                raise ValueError(
                    f"Conflicting native consumable mapping: {definition['db_key']}"
                )
    return copy.deepcopy(value)


def consumable_definitions(catalogue: dict | None = None) -> list[dict]:
    """Return all 1,070 enabled Tier-I-through-X DB definitions."""
    validated = validate_native_battle_consumables(
        load_native_battle_consumables() if catalogue is None else catalogue
    )
    return copy.deepcopy(validated["definitions"])


def service_consumable_definitions(
    native: dict, official: dict, catalogue: dict | None = None,
) -> list[dict]:
    """Return the union used by the initial Tier-I-through-V service policy."""
    validated = validate_native_battle_consumables(
        load_native_battle_consumables() if catalogue is None else catalogue,
        native, official,
    )
    units = _initial_units(native)
    keys = {
        row["db_key"] for unit in units
        for row in _candidates(validated["definitions"], unit)
    }
    return [copy.deepcopy(row) for row in validated["definitions"]
            if row["db_key"] in keys]


def augment_native_consumable_mappings(
    official: dict, catalogue: dict | None = None,
) -> dict:
    """Add every missing enabled current DB identity to legacy mappings.

    Recovered prices are preserved. Definitions absent from the historical
    economy snapshot receive an explicit local zero price; this does not make
    premium or Tier-VI-through-X units part of the initial service policy.
    """
    if not isinstance(official, dict):
        raise TypeError("official must be an object")
    validated = validate_native_battle_consumables(
        load_native_battle_consumables() if catalogue is None else catalogue
    )
    result = copy.deepcopy(official)
    rows = result.setdefault("item_mappings", [])
    if not isinstance(rows, list):
        raise ValueError("item_mappings must be a list")

    indices: dict[str, int] = {}
    owners_by_id: dict[int, tuple[object, object]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError("Invalid item mapping")
        item_id = row.get("item_id")
        if type(item_id) is int:
            owner = (row.get("type"), row.get("db_key"))
            previous_owner = owners_by_id.setdefault(item_id, owner)
            if previous_owner != owner:
                owners_by_id[item_id] = ("<ambiguous>", "<ambiguous>")
        if row.get("type") != "arena_consumables":
            continue
        key = row.get("db_key")
        if not isinstance(key, str) or not key or key in indices:
            raise ValueError(f"Duplicate native consumable mapping: {key!r}")
        indices[key] = index

    for definition in validated["definitions"]:
        key, item_id = definition["db_key"], definition["item_id"]
        previous = rows[indices[key]] if key in indices else None
        owner = owners_by_id.get(item_id)
        if owner is not None and owner != ("arena_consumables", key):
            raise ValueError(
                f"Native consumable item ID collision: {key} -> {owner!r}"
            )
        if previous is not None:
            if previous.get("item_id") != item_id:
                raise ValueError(f"Stale native consumable ID: {key}")
            metadata = previous.get("metadata")
            if (previous.get("allow_from_api") is not False
                    or not isinstance(metadata, dict)
                    or any(type(metadata.get(currency)) is not int
                           or metadata[currency] < 0
                           for currency in ("silver_cents", "gold_cents"))):
                raise ValueError(f"Stale native consumable metadata: {key}")
            continue
        rows.append({
            "allow_from_api": False,
            "db_key": key,
            "item_id": item_id,
            "metadata": {
                "gold_cents": 0,
                "price_source": "local_unlocked_zero_price",
                "silver_cents": 0,
            },
            "type": "arena_consumables",
        })
        indices[key] = len(rows) - 1
        owners_by_id[item_id] = ("arena_consumables", key)

    validate_native_battle_consumables(validated, official=result)
    return result


def consumables_for_unit(
    native: dict, official: dict, unit_key: str, catalogue: dict | None = None,
) -> list[dict]:
    """Return the exact shipped candidates for one initially served unit."""
    if not isinstance(unit_key, str):
        raise TypeError("unit_key must be a string")
    validated = validate_native_battle_consumables(
        load_native_battle_consumables() if catalogue is None else catalogue,
        native, official,
    )
    units = [row for row in _initial_units(native) if row.get("key") == unit_key]
    if len(units) != 1:
        return []
    return copy.deepcopy(_candidates(validated["definitions"], units[0]))


def tier_equivalent_consumables_for_unit(
    native: dict, unit_key: str, effective_tier: int = 10,
    catalogue: dict | None = None,
) -> list[dict]:
    """Return real definitions for a live unit under a uniform Tier policy."""
    if not isinstance(unit_key, str):
        raise TypeError("unit_key must be a string")
    validated = validate_native_battle_consumables(
        load_native_battle_consumables() if catalogue is None else catalogue,
        native,
    )
    return copy.deepcopy(_tier_equivalent_candidates(
        validated["definitions"], native, unit_key, effective_tier,
    ))


def tier_equivalent_consumables_by_unit(
    native: dict, effective_tier: int = 10, catalogue: dict | None = None,
) -> dict[str, list[dict]]:
    """Return every live unit's promoted candidates after one validation."""
    validated = validate_native_battle_consumables(
        load_native_battle_consumables() if catalogue is None else catalogue,
        native,
    )
    return {
        unit_key: copy.deepcopy(_tier_equivalent_candidates(
            validated["definitions"], native, unit_key, effective_tier,
        ))
        for unit_key in sorted(_live_units(native))
    }


def tier_equivalent_service_definitions(
    native: dict, effective_tier: int = 10, catalogue: dict | None = None,
) -> list[dict]:
    """Return the canonical union served to every live unit at one Tier."""
    validated = validate_native_battle_consumables(
        load_native_battle_consumables() if catalogue is None else catalogue,
        native,
    )
    keys = {
        row["db_key"] for unit_key in _live_units(native)
        for row in _tier_equivalent_candidates(
            validated["definitions"], native, unit_key, effective_tier,
        )
    }
    return [copy.deepcopy(row) for row in validated["definitions"]
            if row["db_key"] in keys]


def default_consumables_for_unit(
    native: dict, official: dict, unit_key: str, catalogue: dict | None = None,
) -> list[dict]:
    """Schema 4 deliberately starts with no inferred selected consumable."""
    if not isinstance(unit_key, str):
        raise TypeError("unit_key must be a string")
    validate_native_battle_consumables(
        load_native_battle_consumables() if catalogue is None else catalogue,
        native, official,
    )
    return []


__all__ = [
    "DEFAULT_NATIVE_BATTLE_CONSUMABLES",
    "augment_native_consumable_mappings",
    "consumable_definitions",
    "consumables_for_unit",
    "default_consumables_for_unit",
    "load_native_battle_consumables",
    "service_consumable_definitions",
    "tier_equivalent_consumables_by_unit",
    "tier_equivalent_consumables_for_unit",
    "tier_equivalent_service_definitions",
    "validate_native_battle_consumables",
]
