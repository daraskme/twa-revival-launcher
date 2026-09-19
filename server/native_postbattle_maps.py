"""Strict, read-only loader for native postbattle UI map aliases.

The playable battle pool and this response-only compatibility view are
separate authorities.  The pool is in ``catalog/native_battle_maps.json``;
this module loads the independently audited aliases and validates their keys
and physical terrain against that pool.  It never derives a ``_territory``
suffix and never changes durable battle context.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import MappingProxyType


_ROOT = Path(__file__).resolve().parents[1]
_POOL_PATH = _ROOT / "catalog" / "native_battle_maps.json"
_ALIAS_PATH = _ROOT / "catalog" / "native_postbattle_map_aliases.json"

# Exact source-table pairs.  Keeping this closed set makes a catalog typo or
# an accidental future suffix convention fail closed at import time.
_EXPECTED_ALIASES = {
    "alps": "alps_territory",
    "capitoline_hill": "capitoline_hill_territory",
    "capua": "capua_territory",
    "changban": "changban_territory",
    "gergovia": "gergovia_territory",
    "germania": "germania_territory",
    "hadrians_wall": "hadrians_wall_territory",
    "marathon": "marathon_territory",
    "oasis": "oasis_territory",
    "passage_of_augustus": "passage_of_augustus_territory",
    "rubicon": "rubicon_territory",
    "salernum": "salernum_territory",
    "teutoburg_forest": "teutoburg_forest_territory",
    "thermopylae": "thermopylae_territory",
}


def _read_object(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"invalid native map catalog object: {path}")
    return value


def _load_aliases() -> dict[str, str]:
    pool = _read_object(_POOL_PATH)
    if (set(pool) != {"schema_version", "maps"}
            or type(pool["schema_version"]) is not int
            or pool["schema_version"] != 1):
        raise RuntimeError("invalid native_battle_maps schema")
    pool_rows = pool["maps"]
    if not isinstance(pool_rows, list):
        raise RuntimeError("native_battle_maps.maps must be a list")
    pool_by_key: dict[str, dict] = {}
    for row in pool_rows:
        if (not isinstance(row, dict)
                or set(row) != {"key", "ruleset", "terrain"}
                or not all(isinstance(row.get(field), str)
                           for field in ("key", "ruleset", "terrain"))
                or row["key"] in pool_by_key):
            raise RuntimeError("invalid native battle map row")
        pool_by_key[row["key"]] = row

    aliases = _read_object(_ALIAS_PATH)
    if (set(aliases) != {"schema_version", "aliases"}
            or type(aliases["schema_version"]) is not int
            or aliases["schema_version"] != 1):
        raise RuntimeError("invalid native_postbattle_map_aliases schema")
    rows = aliases["aliases"]
    if not isinstance(rows, list) or len(rows) != len(_EXPECTED_ALIASES):
        raise RuntimeError("native postbattle alias count mismatch")
    loaded: dict[str, str] = {}
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {"key", "ui_key"}
                or not isinstance(row.get("key"), str)
                or not isinstance(row.get("ui_key"), str)
                or row["key"] in loaded):
            raise RuntimeError("invalid native postbattle alias row")
        loaded[row["key"]] = row["ui_key"]
    if loaded != _EXPECTED_ALIASES:
        raise RuntimeError("native postbattle aliases are not the audited pairs")

    for key, ui_key in loaded.items():
        classic = pool_by_key.get(key)
        if (classic is None or classic["ruleset"] != "annihilation"):
            raise RuntimeError(f"alias source is not a playable classic row: {key}")
        territory = pool_by_key.get(ui_key)
        if territory is None:
            # changban_territory is intentionally UI-only: its source row is
            # unreleased, but it is the exact paired record for result lookup.
            if ui_key != "changban_territory":
                raise RuntimeError(f"alias target missing from battle pool: {ui_key}")
            terrain = classic["terrain"]
        else:
            if territory["ruleset"] != "territory":
                raise RuntimeError(f"alias target is not territory: {ui_key}")
            terrain = territory["terrain"]
        if terrain != classic["terrain"]:
            raise RuntimeError(f"alias terrain mismatch: {key} -> {ui_key}")
    return loaded


POSTBATTLE_UI_MAP_ALIASES = MappingProxyType(_load_aliases())
