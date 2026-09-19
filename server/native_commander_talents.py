"""Validated commander talent-point pools extracted from the shipped DB."""
from __future__ import annotations

import copy
import json
import re
from collections import defaultdict
from pathlib import Path


DEFAULT_NATIVE_COMMANDER_TALENTS = (
    Path(__file__).resolve().parents[1] / "catalog" / "native_commander_talents.json"
)
TALENT_POOL_TYPE = "arena_commander_talent_points"
TALENT_POINT_CURRENCY = "commander_talent_points"
TALENT_TRACK_CURRENCY = "commander_talents_track"


def load_native_commander_talents(path: Path | None = None) -> dict:
    source = path if path is not None else DEFAULT_NATIVE_COMMANDER_TALENTS
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid native commander-talents catalogue") from exc
    return validate_native_commander_talents(value)


def validate_native_commander_talents(
    value: object,
    native: dict | None = None,
) -> dict:
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "source", "currencies", "commanders",
        "ability_links", "validation",
    } or value.get("schema_version") != 1:
        raise ValueError("Unsupported native commander-talents schema")
    source = value.get("source")
    currencies = value.get("currencies")
    commanders = value.get("commanders")
    ability_links = value.get("ability_links")
    validation = value.get("validation")
    if (not isinstance(source, dict) or not isinstance(source.get("tables"), dict)
            or not isinstance(source.get("join"), str)
            or not isinstance(source.get("native_ability_catalog"), dict)
            or not isinstance(currencies, dict)
            or set(currencies) != {TALENT_POINT_CURRENCY, TALENT_TRACK_CURRENCY}
            or not isinstance(commanders, list) or not isinstance(ability_links, list)
            or not isinstance(validation, dict)):
        raise ValueError("Incomplete native commander-talents catalogue")

    talent_source = source["tables"].get("arena_commander_talent_points")
    lookup_source = source["tables"].get("unique_id_lookups")
    link_source = source["tables"].get("arena_commander_abilities_tree_links")
    ability_source = source["native_ability_catalog"]
    expected_source_fields = {
        "pack", "entry", "guid", "version", "count", "bytes", "sha256",
        "body_offset", "complete_cursor",
    }
    if (not isinstance(talent_source, dict)
            or set(talent_source) != expected_source_fields
            or talent_source.get("version") != 1
            or talent_source.get("count") != 25
            or talent_source.get("bytes") != 1632
            or talent_source.get("complete_cursor") != 1632
            or talent_source.get("sha256")
            != "7c6077958fca67dac7f69d9ad5d13a10d09fba1b6f501d167c0f60cd5ca52ad7"
            or not isinstance(lookup_source, dict)
            or set(lookup_source) != expected_source_fields
            or lookup_source.get("version") != 1
            or lookup_source.get("count") != 15489
            or lookup_source.get("bytes") != 1020263
            or lookup_source.get("complete_cursor") != 1020263
            or lookup_source.get("sha256")
            != "cc53fd9c34f7f74ea8bf3c19dd5f65a04d45878e92bc419a405c2d24eb48f016"
            or not isinstance(link_source, dict)
            or set(link_source) != expected_source_fields
            or link_source.get("version") != 0
            or link_source.get("count") != 1324
            or link_source.get("bytes") != 111595
            or link_source.get("body_offset") != 83
            or link_source.get("complete_cursor") != 111595
            or link_source.get("sha256")
            != "88b895b662297838668dd1364eebb466dcdb05e9d3f0512bd3efadd65d82a2a4"
            or set(ability_source) != {
                "pack", "entry", "version", "count", "bytes", "sha256",
                "complete_cursor",
            }
            or ability_source.get("version") != 1
            or ability_source.get("count") != 1251
            or ability_source.get("bytes") != 74815
            or ability_source.get("complete_cursor") != 74815
            or ability_source.get("sha256")
            != "d3bfb8fe2b1a6ec17dd79f613abdc06cd3612a38c47b76ac653bf339e91575fb"):
        raise ValueError("Native commander-talents source mismatch")

    for key, item_id in currencies.items():
        if type(item_id) is not int or not 0 < item_id < 2**64:
            raise ValueError(f"Invalid native talent currency: {key}")
    if len(set(currencies.values())) != len(currencies):
        raise ValueError("Duplicate native talent currency ID")

    required_row = {
        "commander", "item_id", "tier_grants", "cumulative_points",
        "row_index", "row_offset",
    }
    keys: set[str] = set()
    item_ids: set[int] = set()
    for row in commanders:
        if not isinstance(row, dict) or set(row) != required_row:
            raise ValueError("Invalid native commander-talents row")
        key = row["commander"]
        item_id = row["item_id"]
        grants = row["tier_grants"]
        cumulative = row["cumulative_points"]
        if (not isinstance(key, str) or not key or key in keys
                or type(item_id) is not int or not 0 < item_id < 2**64
                or item_id in item_ids
                or not isinstance(grants, list) or len(grants) != 10
                or any(type(point) is not int or point < 0 for point in grants)
                or not isinstance(cumulative, list) or len(cumulative) != 10
                or cumulative != [sum(grants[:tier]) for tier in range(1, 11)]
                or type(row["row_index"]) is not int or row["row_index"] < 0
                or type(row["row_offset"]) is not int or row["row_offset"] < 0):
            raise ValueError(f"Invalid native commander talent identity: {key!r}")
        keys.add(key)
        item_ids.add(item_id)

    required_link = {
        "source", "target", "placement_0", "placement_1",
        "source_row", "source_offset", "source_end",
    }
    edges: set[tuple[str, str]] = set()
    incoming: dict[str, set[str]] = defaultdict(set)
    outgoing: dict[str, set[str]] = defaultdict(set)
    ability_nodes: set[str] = set()
    previous_end = link_source["body_offset"]
    for index, row in enumerate(ability_links):
        if not isinstance(row, dict) or set(row) != required_link:
            raise ValueError("Invalid native commander ability-tree link")
        source_key, target_key = row["source"], row["target"]
        edge = (source_key, target_key)
        if (not isinstance(source_key, str) or not source_key
                or not isinstance(target_key, str) or not target_key
                or source_key == target_key or edge in edges
                or type(row["placement_0"]) is not int
                or row["placement_0"] not in range(1, 5)
                or type(row["placement_1"]) is not int
                or row["placement_1"] not in range(1, 5)
                or row["source_row"] != index
                or row["source_offset"] != previous_end
                or type(row["source_end"]) is not int
                or row["source_end"] <= row["source_offset"]):
            raise ValueError(f"Invalid native commander ability-tree edge: {edge!r}")
        previous_end = row["source_end"]
        edges.add(edge)
        ability_nodes.update(edge)
        incoming[target_key].add(source_key)
        outgoing[source_key].add(target_key)
    roots = ability_nodes - set(incoming)
    indegree = {key: len(incoming[key]) for key in ability_nodes}
    queue = sorted(key for key, degree in indegree.items() if degree == 0)
    visited = []
    while queue:
        source_key = queue.pop(0)
        visited.append(source_key)
        for target_key in sorted(outgoing[source_key]):
            indegree[target_key] -= 1
            if indegree[target_key] == 0:
                queue.append(target_key)
        queue.sort()
    if (len(ability_links) != 1324 or previous_end != link_source["complete_cursor"]
            or len(ability_nodes) != 1251 or len(roots) != 75
            or roots != {key for key in ability_nodes
                          if re.search(r"_\d+-\d+_", key) is None}
            or len(visited) != len(ability_nodes)
            or sum(len(parents) > 1 for parents in incoming.values()) != 138):
        raise ValueError("Native commander ability-tree graph mismatch")

    if (len(commanders) != 25
            or validation.get("live_commanders") != 25
            or validation.get("tiers_per_commander") != 10
            or validation.get("ability_nodes") != 1251
            or validation.get("ability_links") != 1324
            or validation.get("ability_roots") != 75
            or validation.get("manual_ability_nodes") != 1176
            or validation.get("multi_parent_ability_nodes") != 138
            or validation.get("ability_graph_is_acyclic") is not True
            or validation.get("all_ability_links_within_one_commander") is not True
            or validation.get("all_pool_and_currency_ids_verified_against_current_lookup") is not True
            or validation.get("all_tier_grants_nonnegative") is not True
            or validation.get("arminius_tier_6_total") != 30):
        raise ValueError("Native commander-talents validation mismatch")

    if native is not None:
        if not isinstance(native, dict):
            raise TypeError("native must be an object")
        live_keys = {
            row.get("key") for row in native.get("commanders", [])
            if isinstance(row, dict) and row.get("build_state", "live") == "live"
        }
        if keys != live_keys:
            raise ValueError("Native commander-talents commander coverage mismatch")
        ability_owners: dict[str, str] = {}
        for row in native.get("abilities", []):
            if not isinstance(row, dict):
                raise ValueError("Invalid native commander ability catalogue")
            key, commander = row.get("key"), row.get("commander")
            if (not isinstance(key, str) or not key or key in ability_owners
                    or commander not in live_keys):
                raise ValueError("Invalid native commander ability catalogue")
            ability_owners[key] = commander
        if (set(ability_owners) != ability_nodes
                or any(ability_owners[source_key] != ability_owners[target_key]
                       for source_key, target_key in edges)
                or any(sum(ability_owners[root] == commander for root in roots) != 3
                       for commander in live_keys)):
            raise ValueError("Native commander ability-tree coverage mismatch")
    return copy.deepcopy(value)


def talent_rows_by_commander(catalogue: dict | None = None) -> dict[str, dict]:
    value = validate_native_commander_talents(
        load_native_commander_talents() if catalogue is None else catalogue
    )
    return {row["commander"]: copy.deepcopy(row) for row in value["commanders"]}


def commander_talent_total(catalogue: dict, commander: str, tier: int) -> int:
    if type(tier) is not int or not 1 <= tier <= 10:
        raise ValueError("Invalid commander Tier")
    rows = talent_rows_by_commander(catalogue)
    try:
        return rows[commander]["cumulative_points"][tier - 1]
    except KeyError as exc:
        raise ValueError(f"Unknown commander talent pool: {commander}") from exc


def ability_predecessors_by_commander(
    catalogue: dict,
    native: dict,
) -> dict[tuple[str, str], frozenset[str]]:
    """Return exact source-to-target incoming edges from the shipped graph."""
    value = validate_native_commander_talents(catalogue, native)
    owners = {row["key"]: row["commander"] for row in native["abilities"]}
    result: dict[tuple[str, str], set[str]] = {
        (commander, key): set() for key, commander in owners.items()
    }
    for row in value["ability_links"]:
        result[owners[row["target"]], row["target"]].add(row["source"])
    return {key: frozenset(parents) for key, parents in result.items()}


def augment_native_commander_talent_mappings(
    official: dict,
    catalogue: dict | None = None,
) -> dict:
    """Overlay exact current type-21 pool and hidden currency identities."""
    if not isinstance(official, dict):
        raise TypeError("official must be an object")
    talents = validate_native_commander_talents(
        load_native_commander_talents() if catalogue is None else catalogue
    )
    result = copy.deepcopy(official)
    rows = result.setdefault("item_mappings", [])
    if not isinstance(rows, list):
        raise ValueError("item_mappings must be a list")

    indices: dict[tuple[str, str], int] = {}
    owners: dict[int, set[tuple[object, object]]] = {}
    desired_keys = {
        ("arena_currencies", key) for key in talents["currencies"]
    } | {
        (TALENT_POOL_TYPE, row["commander"])
        for row in talents["commanders"]
    }
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError("Invalid item mapping")
        typed_key = (row.get("type"), row.get("db_key"))
        if typed_key in desired_keys:
            if typed_key in indices:
                raise ValueError(f"Duplicate native item mapping: {typed_key!r}")
            indices[typed_key] = index
        item_id = row.get("item_id")
        if type(item_id) is int:
            owners.setdefault(item_id, set()).add(typed_key)

    additions = [
        ("arena_currencies", key, item_id)
        for key, item_id in talents["currencies"].items()
    ] + [
        (TALENT_POOL_TYPE, row["commander"], row["item_id"])
        for row in talents["commanders"]
    ]
    for item_type, key, item_id in additions:
        typed_key = (item_type, key)
        conflicting = owners.get(item_id, set()) - {typed_key}
        if conflicting:
            raise ValueError(f"Native talent item ID collision: {key} / {conflicting}")
        entry = {
            "allow_from_api": False,
            "db_key": key,
            "item_id": item_id,
            "metadata": None,
            "type": item_type,
        }
        index = indices.get(typed_key)
        if index is None:
            indices[typed_key] = len(rows)
            rows.append(entry)
        else:
            previous = rows[index]
            if previous.get("item_id") != item_id:
                raise ValueError(f"Conflicting native talent mapping: {key}")
            rows[index] = {**previous, **entry}
        owners.setdefault(item_id, set()).add(typed_key)
    return result


__all__ = [
    "DEFAULT_NATIVE_COMMANDER_TALENTS",
    "TALENT_POINT_CURRENCY",
    "TALENT_POOL_TYPE",
    "TALENT_TRACK_CURRENCY",
    "augment_native_commander_talent_mappings",
    "ability_predecessors_by_commander",
    "commander_talent_total",
    "load_native_commander_talents",
    "talent_rows_by_commander",
    "validate_native_commander_talents",
]
