"""Server-owned native battle-map compatibility boundaries.

The checked-in ``catalog/native_battle_maps.json`` is the authoritative
playable pool. It is required at runtime: silently falling back to Alps would
make a missing or stale package look like a successful all-map deployment.
The two Alps records remain explicit legacy defaults for old callers that have
not yet received a frozen map choice.
"""
from __future__ import annotations

import re
import json
import secrets
from collections.abc import Callable, Sequence
from pathlib import Path
from types import MappingProxyType


_MAP_ID = re.compile(r"[A-Za-z0-9_-]{1,80}")
_TERRAIN_PREFIX = "terrain\\tiles\\battle\\battlefields\\"
_MANIFEST_PATH = Path(__file__).resolve().parents[1] / "catalog" / "native_battle_maps.json"

# These records have both shipped battle/terrain data and live native battle
# evidence in the current probe path.  Do not infer more records from pack
# presence alone.
NATIVE_BATTLE_RULESET_MAPS = MappingProxyType({
    "territory": "alps_territory",
    "annihilation": "alps",
})


def _manifest_records() -> tuple[dict[str, str], ...]:
    """Read and validate the required server-owned map manifest."""
    path = _MANIFEST_PATH
    if not path.is_file():
        raise ValueError("native battle map manifest missing")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError("invalid native battle map manifest") from error
    rows = document.get("maps") if isinstance(document, dict) else None
    if (not isinstance(document, dict)
            or set(document) != {"schema_version", "maps"}
            or type(document.get("schema_version")) is not int
            or document.get("schema_version") != 1
            or not isinstance(rows, list) or not rows):
        raise ValueError("invalid native battle map manifest")
    records: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"key", "ruleset", "terrain"}:
            raise ValueError("invalid native battle map manifest")
        key, ruleset, terrain = row["key"], row["ruleset"], row["terrain"]
        if (not isinstance(key, str) or _MAP_ID.fullmatch(key) is None
                or key in seen
                or not isinstance(ruleset, str)
                or ruleset not in NATIVE_BATTLE_RULESET_MAPS
                or not isinstance(terrain, str)
                or _MAP_ID.fullmatch(terrain) is None):
            raise ValueError("invalid native battle map manifest")
        seen.add(key)
        records.append({"key": key, "ruleset": ruleset, "terrain": terrain})
    if any(not any(row["ruleset"] == ruleset for row in records)
           for ruleset in NATIVE_BATTLE_RULESET_MAPS):
        raise ValueError("native battle map manifest omits a ruleset")
    return tuple(records)


def native_battle_maps_for_ruleset(ruleset: object) -> tuple[dict[str, str], ...]:
    """Return the immutable server-owned map pool for one ruleset."""
    if not isinstance(ruleset, str) or ruleset not in NATIVE_BATTLE_RULESET_MAPS:
        raise ValueError("unsupported_battle_ruleset")
    return tuple(row for row in _manifest_records() if row["ruleset"] == ruleset)


def is_native_battle_map(map_key: object, ruleset: object) -> bool:
    return (isinstance(map_key, str) and isinstance(ruleset, str)
            and ruleset in NATIVE_BATTLE_RULESET_MAPS
            and any(row["key"] == map_key
                    for row in native_battle_maps_for_ruleset(ruleset)))


def choose_native_battle_map(
        ruleset: object,
        *,
        choice: Callable[[Sequence[dict[str, str]]], object] | None = None,
) -> str:
    """Choose one map uniformly, or use a validated deterministic test choice.

    Callers must persist the returned key for the allocation. ``choice`` is
    trusted test/host injection only; it cannot introduce a key outside the
    manifest pool.
    """
    pool = native_battle_maps_for_ruleset(ruleset)
    selected = (pool[secrets.randbelow(len(pool))]
                if choice is None else choice(pool))
    key = selected.get("key") if isinstance(selected, dict) else selected
    if not isinstance(key, str) or key not in {row["key"] for row in pool}:
        raise ValueError("invalid native battle map choice")
    return key


def native_battle_map_key(ruleset: object) -> str:
    """Historic deterministic key for legacy allocations only."""
    if not isinstance(ruleset, str) or ruleset not in NATIVE_BATTLE_RULESET_MAPS:
        raise ValueError("unsupported_battle_ruleset")
    return NATIVE_BATTLE_RULESET_MAPS[ruleset]

# The native custom-lobby wire has no independent ruleset field. The selected
# battle record is the ruleset selector; expose the complete audited pool.
PRIVATE_CPU_LOBBY_MAP_IDS = tuple(row["key"] for row in _manifest_records())


def catalog_map_ids(catalog: object) -> tuple[str, ...]:
    """Validate and return the recovered map IDs without treating them as safe.

    Paths are checked because the private allowlist relies on the catalog row
    as evidence for the physical terrain identity.  This remains a structural
    check; it deliberately does not promote every valid row to the executable
    private-lobby allowlist.
    """
    if not isinstance(catalog, dict) or not isinstance(catalog.get("maps"), list):
        raise ValueError("Valid map catalog required")
    result: list[str] = []
    for row in catalog["maps"]:
        if not isinstance(row, dict):
            raise ValueError("Valid map catalog rows required")
        map_id, path = row.get("id"), row.get("path")
        if (not isinstance(map_id, str) or _MAP_ID.fullmatch(map_id) is None
                or not isinstance(path, str)
                or path.replace("/", "\\").lower()
                != (_TERRAIN_PREFIX + map_id).lower()):
            raise ValueError("Valid native map IDs and terrain paths required")
        result.append(map_id)
    if not result or len(set(result)) != len(result):
        raise ValueError("Valid unique map IDs required")
    return tuple(result)


def private_cpu_lobby_map_ids(catalog: object) -> tuple[str, ...]:
    """Return the full manifest pool after verifying physical terrain rows."""
    discovered = set(catalog_map_ids(catalog))
    required_terrain = {row["terrain"] for row in _manifest_records()}
    if any(terrain not in discovered for terrain in required_terrain):
        raise ValueError("Verified private CPU map missing from catalog")
    return PRIVATE_CPU_LOBBY_MAP_IDS


def is_private_cpu_lobby_map(map_id: object) -> bool:
    """True only for a map record admitted to the conservative private gate."""
    return isinstance(map_id, str) and map_id in PRIVATE_CPU_LOBBY_MAP_IDS
