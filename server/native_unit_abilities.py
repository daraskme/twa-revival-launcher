"""Validated type-19 unit-trainable ability junctions.

The catalogue is generated from the same final WAD that the native client
loads.  Commander talents are intentionally absent: those are type-6
``arena_commander_ability_levels`` children with a type-21 point pool, while
this module owns only ``land_units_to_unit_abilites_junctions`` records.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


ITEM_TYPE = "land_units_to_unit_abilites_junctions"
DEFAULT_NATIVE_UNIT_ABILITIES = (
    Path(__file__).resolve().parents[1] / "catalog" / "native_unit_abilities.json"
)
DEFAULT_DEPLOYED_CLIENT_WAD = (
    Path(__file__).resolve().parents[1] / "client" / "data" / "wad.pack"
)
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ROW_FIELDS = {
    "ability", "alias_unit", "db_key", "enabled", "item_id", "mode",
    "unit",
}
_SOURCE_FIELDS = {
    "ability_entry", "ability_table_sha256", "lookup_entry",
    "lookup_table_sha256", "pack", "pack_sha256",
}
_VALIDATION_FIELDS = {
    "additional_links", "all_item_ids_signed_64_safe",
    "all_live_units_have_additional", "item_type", "live_links",
    "live_units", "minimum_additional_per_unit", "mode_counts",
}


def load_native_unit_abilities(path: Path | None = None) -> dict:
    source = DEFAULT_NATIVE_UNIT_ABILITIES if path is None else Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid native unit-ability catalogue") from exc
    return validate_native_unit_abilities(value)


def validate_native_unit_abilities(
    value: object,
    native: dict | None = None,
    official: dict | None = None,
) -> dict:
    if (not isinstance(value, dict) or set(value) != {
            "schema_version", "source", "items", "validation"}
            or value.get("schema_version") != 1):
        raise ValueError("Unsupported native unit-ability schema")
    source = value.get("source")
    items = value.get("items")
    validation = value.get("validation")
    if (not isinstance(source, dict) or set(source) != _SOURCE_FIELDS
            or not isinstance(items, list)
            or not isinstance(validation, dict)
            or set(validation) != _VALIDATION_FIELDS):
        raise ValueError("Incomplete native unit-ability catalogue")
    if (not isinstance(source["pack"], str) or not source["pack"]
            or not isinstance(source["ability_entry"], str)
            or not source["ability_entry"]
            or not isinstance(source["lookup_entry"], str)
            or not source["lookup_entry"]
            or any(not isinstance(source[field], str)
                   or not _HASH.fullmatch(source[field])
                   for field in (
                       "pack_sha256", "ability_table_sha256",
                       "lookup_table_sha256",
                   ))):
        raise ValueError("Invalid native unit-ability source")

    keys: set[str] = set()
    item_ids: set[int] = set()
    identities: set[tuple[str, str]] = set()
    modes: Counter[str] = Counter()
    additional: Counter[str] = Counter()
    previous_sort: tuple[str, str, int] | None = None
    for row in items:
        if not isinstance(row, dict) or set(row) != _ROW_FIELDS:
            raise ValueError("Invalid native unit-ability row")
        unit, ability = row["unit"], row["ability"]
        key, item_id = row["db_key"], row["item_id"]
        sort_key = (unit, ability, item_id)
        if (not isinstance(unit, str) or not unit
                or not isinstance(ability, str) or not ability
                or key != unit + ability
                or row["mode"] not in {
                    "default", "additional", "irreplaceable",
                }
                or row["enabled"] is not True
                or not isinstance(row["alias_unit"], str)
                or type(item_id) is not int or not 0 < item_id < 2**64
                or key in keys or item_id in item_ids
                or (unit, ability) in identities
                or previous_sort is not None and sort_key <= previous_sort):
            raise ValueError(f"Invalid native unit-ability identity: {key!r}")
        previous_sort = sort_key
        keys.add(key)
        item_ids.add(item_id)
        identities.add((unit, ability))
        modes[row["mode"]] += 1
        if row["mode"] == "additional":
            additional[unit] += 1

    if (validation["item_type"] != ITEM_TYPE
            or validation["live_links"] != len(items)
            or validation["additional_links"] != modes["additional"]
            or validation["mode_counts"] != dict(sorted(modes.items()))
            or validation["all_item_ids_signed_64_safe"] != all(
                item_id < 2**63 for item_id in item_ids
            )):
        raise ValueError("Native unit-ability validation mismatch")

    if native is not None:
        if not isinstance(native, dict):
            raise TypeError("native must be an object")
        live_rows = [
            row for row in native.get("units", [])
            if isinstance(row, dict) and row.get("build_state", "live") == "live"
        ]
        live = {row.get("key") for row in live_rows}
        if None in live or len(live) != len(live_rows):
            raise ValueError("Invalid live unit catalogue")
        if ({row["unit"] for row in items} != live
                or any(row["alias_unit"] and row["alias_unit"] not in live
                       for row in items)
                or set(additional) != live):
            raise ValueError("Unit-ability catalogue does not cover live units")
        minimum = min(additional.values()) if additional else 0
        if (validation["live_units"] != len(live)
                or validation["minimum_additional_per_unit"] != minimum
                or validation["all_live_units_have_additional"] is not True):
            raise ValueError("Native unit-ability live coverage mismatch")
    else:
        if (type(validation["live_units"]) is not int
                or validation["live_units"] <= 0
                or type(validation["minimum_additional_per_unit"]) is not int
                or validation["minimum_additional_per_unit"] <= 0
                or validation["all_live_units_have_additional"] is not True):
            raise ValueError("Invalid native unit-ability coverage evidence")

    if official is not None:
        if not isinstance(official, dict):
            raise TypeError("official must be an object")
        mapped: dict[str, list[dict]] = {}
        for row in official.get("item_mappings", []):
            if isinstance(row, dict) and row.get("type") == ITEM_TYPE:
                mapped.setdefault(row.get("db_key"), []).append(row)
        if set(mapped) != keys:
            raise ValueError(
                "Native unit-ability mappings must exactly match the catalogue"
            )
        for item in items:
            rows = mapped.get(item["db_key"], [])
            if len(rows) != 1 or rows[0].get("item_id") != item["item_id"]:
                raise ValueError(
                    f"Missing native unit-ability mapping: {item['db_key']}"
                )
    return copy.deepcopy(value)


def validate_deployed_unit_ability_wad(
    catalogue: dict | None = None,
    path: Path | None = None,
) -> str:
    """Require the deployed client WAD to match the catalogue's source WAD.

    Only the Revival-owned copy under ``client/data`` is read. The original
    game installation remains outside server startup validation and is never
    modified.
    """
    validated = validate_native_unit_abilities(
        load_native_unit_abilities() if catalogue is None else catalogue
    )
    deployed = DEFAULT_DEPLOYED_CLIENT_WAD if path is None else Path(path)
    digest = hashlib.sha256()
    try:
        with deployed.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise ValueError("Missing deployed unit-ability WAD") from exc
    actual = digest.hexdigest()
    if actual != validated["source"]["pack_sha256"]:
        raise ValueError("Deployed unit-ability WAD hash mismatch")
    return actual


def additional_unit_abilities(catalogue: dict | None = None) -> list[dict]:
    validated = validate_native_unit_abilities(
        load_native_unit_abilities() if catalogue is None else catalogue
    )
    return copy.deepcopy([
        row for row in validated["items"] if row["mode"] == "additional"
    ])


def augment_native_unit_ability_mappings(
    official: dict, catalogue: dict | None = None,
) -> dict:
    if not isinstance(official, dict):
        raise TypeError("official must be an object")
    validated = validate_native_unit_abilities(
        load_native_unit_abilities() if catalogue is None else catalogue
    )
    result = copy.deepcopy(official)
    rows = result.setdefault("item_mappings", [])
    if not isinstance(rows, list):
        raise ValueError("item_mappings must be a list")
    indices: dict[str, int] = {}
    owners: dict[int, tuple[object, object]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError("Invalid item mapping")
        item_id = row.get("item_id")
        if type(item_id) is int:
            owner = (row.get("type"), row.get("db_key"))
            previous = owners.setdefault(item_id, owner)
            if previous != owner:
                owners[item_id] = ("<ambiguous>", "<ambiguous>")
        if row.get("type") == ITEM_TYPE:
            key = row.get("db_key")
            if not isinstance(key, str) or not key or key in indices:
                raise ValueError(f"Duplicate native unit-ability mapping: {key!r}")
            indices[key] = index
    for item in validated["items"]:
        key, item_id = item["db_key"], item["item_id"]
        owner = owners.get(item_id)
        if owner is not None and owner != (ITEM_TYPE, key):
            raise ValueError(f"Native unit-ability item ID collision: {key}")
        previous = rows[indices[key]] if key in indices else None
        metadata = {
            "ability": item["ability"],
            "alias_unit": item["alias_unit"],
            "enabled": True,
            "mode": item["mode"],
            "unit": item["unit"],
        }
        if previous is not None:
            if (previous.get("item_id") != item_id
                    or previous.get("allow_from_api") is not False
                    or previous.get("metadata") != metadata):
                raise ValueError(f"Stale native unit-ability mapping: {key}")
            continue
        rows.append({
            "allow_from_api": False,
            "db_key": key,
            "item_id": item_id,
            "metadata": metadata,
            "type": ITEM_TYPE,
        })
        indices[key] = len(rows) - 1
        owners[item_id] = (ITEM_TYPE, key)
    validate_native_unit_abilities(validated, official=result)
    return result


__all__ = [
    "DEFAULT_DEPLOYED_CLIENT_WAD", "DEFAULT_NATIVE_UNIT_ABILITIES", "ITEM_TYPE",
    "additional_unit_abilities", "augment_native_unit_ability_mappings",
    "load_native_unit_abilities", "validate_deployed_unit_ability_wad",
    "validate_native_unit_abilities",
]
