"""Offline CA_AUTH / F2P bodies for the original hangar."""
from __future__ import annotations

import copy
import hashlib
import json
import re
import time
import uuid
from pathlib import Path

from native_equipment import (
    augment_native_equipment_mappings,
    load_native_unit_equipment,
    validate_native_unit_equipment,
)
from native_consumables import (
    augment_native_consumable_mappings,
    load_native_battle_consumables,
    tier_equivalent_consumables_by_unit,
    tier_equivalent_service_definitions,
    validate_native_battle_consumables,
)
from native_commander_talents import (
    TALENT_TRACK_CURRENCY,
    ability_predecessors_by_commander,
    augment_native_commander_talent_mappings,
    load_native_commander_talents,
    talent_rows_by_commander,
    validate_native_commander_talents,
)
from native_unit_abilities import (
    augment_native_unit_ability_mappings,
    load_native_unit_abilities,
    validate_native_unit_abilities,
)

PLAYER = "player"
TOKEN = "revival-token"
# The identity every default body below describes.  ``bind_identity`` swaps it
# for a resolver-derived one (companion_bridge) before the first request is
# served; everything that used to hard-code ``PLAYER`` now reads
# ``active_native_user_id()`` so one process still serves exactly one player.
_ACTIVE_IDENTITY: object | None = None


def bind_identity(identity: object) -> None:
    """Bind the resolved player for this process (``None`` = legacy lab)."""
    global _ACTIVE_IDENTITY
    if identity is not None:
        native_user_id = getattr(identity, "native_user_id", None)
        if not isinstance(native_user_id, str) or not native_user_id:
            raise ValueError("identity must expose a native_user_id")
    _ACTIVE_IDENTITY = identity


def active_identity() -> object | None:
    return _ACTIVE_IDENTITY


def active_native_user_id() -> str:
    """The wire identity this process serves.  Defaults to the lab ``player``."""
    identity = _ACTIVE_IDENTITY
    return PLAYER if identity is None else identity.native_user_id


def active_display_name() -> str:
    """The authenticated launch name; never used as a transport identity."""
    return getattr(_ACTIVE_IDENTITY, "display_name", None) or active_native_user_id()


OFFLINE_PORTRAIT_KEY = "default_portrait"
OFFLINE_PROGRESSION_SCHEMA_VERSION = 1
SANDBOX_UNIT_TIER = 10
SANDBOX_CONSUMABLE_SLOTS = 2
PREMIUM_UNIT_GOLD_COST = 100_000
# Exact enabled row recovered read-only from the shipped
# arena_tokens/unique_id_lookups tables.  This is not a wallet currency:
# omitting its profile record makes the native UI render its missing-value
# sentinel (-1) as uint32 4294967295.
COMMANDER_TRIAL_TOKEN_KEY = "commander_trial"
COMMANDER_TRIAL_TOKEN_ITEM_ID = 630099746992321623
# Domain-separated SHA-256 prefix with the sign bit cleared. This is an
# explicit local-server ID because the recovered official mappings contain no
# arena_portraits rows; it is not presented as an original service item ID.
OFFLINE_PORTRAIT_ITEM_ID = 4072408941116258269
STACK_HOST = "127.0.0.1:18765"
# No port in domain: service hosts become revival-casag.localhost (port 443).
# A port here is copied into twa-game-data.{domain} and the engine tears down
# EMPIRE_MP right after building those URLs.
STACK_DOMAIN = "localhost"
STACK_URL = f"http://{STACK_HOST}"
CASAG_URL = f"https://revival-casag.{STACK_DOMAIN}"


def ca_json(obj: dict) -> str:
    """Match the original stack_config.json spacing (tab + ' : ')."""
    inner = ",\n".join(f'\t"{key}" : {json.dumps(value)}' for key, value in obj.items())
    return "{\n" + inner + "\n}\n"


# Official local file is only config_domain. Extra keys made the engine skip
# /gameid_registry/ and jump straight to CASAG, then tear down EMPIRE_MP.
# Strings only — booleans / arrays trigger 0xf000.
LOCAL_STACK_FILE = {
    "config_domain": STACK_HOST,
}

# HTTP CASAG body. Parser at game.dll 0xBE5140 requires stack, domain,
# regions, spa_game_id, twas_url, aws_s3_host, aws_region, then xmpp +
# xmpp_jid_domain. Each regions[] object needs id, description, wgni,
# xmpp, image_url, shop_url, xmpp_jid_domain. Incomplete region objects
# crashed the engine; missing required keys return 0xf003.
STACK = {
    "stack": "revival",
    "domain": STACK_DOMAIN,
    "config_domain": STACK_HOST,
    "spa_game_id": "67",
    "twas_url": STACK_URL,
    "twas_url_with_schema": STACK_URL,
    "aws_s3_host": "127.0.0.1",
    "aws_region": "local",
    "casag_url": CASAG_URL,
    "auth_url": f"{STACK_URL}/login",
    "xmpp": "127.0.0.1",
    "xmpp_jid_domain": "127.0.0.1",
    "image_url": STACK_URL,
    "shop_url": STACK_URL,
    "camm": STACK_URL,
    "casa": STACK_URL,
    "casag": CASAG_URL,
    "cacugs": STACK_URL,
    "casteampayment": STACK_URL,
    "calb": STACK_URL,
    "caprofile": STACK_URL,
    "stackname": "revival",
    "fake_auth": True,
    "easy_anti_cheat": False,
    "regions": [
        {
            "id": "local",
            "description": "local",
            "wgni": "false",
            "xmpp": "127.0.0.1",
            "image_url": STACK_URL,
            "shop_url": STACK_URL,
            "xmpp_jid_domain": "127.0.0.1",
        }
    ],
}

STATUS = {
    "status": "online",
    "online": True,
    "service_available": True,
    "check_build_ids": False,
    "allowed_build_ids": [35732, 2508072],
    "heading": "",
    "maintenance_critical": False,
    "maintenance_routine": False,
}

def ca_envelope(response: dict, timestamp: int = 1_787_760_241_000) -> dict:
    """CASAG/CAMM Request:set() at game.dll 0x11825B0.

    Root must be an object with a nested `response` object. A top-level
    `errors` array — including empty `[]` — makes set() return 0 and the
    client shows authentication_failed. Do not send `ok` / `success`.
    """
    return {"timestamp": timestamp, "response": response}


# TWAS /netease/login_netease looks up twas_token at top level (already worked).
# The request body carries the ``+auth <token>`` value as ``netease_token``:
# that is the one secret the client presents, so it is the identity root.
def login_netease_response(user_id: str | None = None, token: str = TOKEN) -> dict:
    user_id = active_native_user_id() if user_id is None else user_id
    return {
        "twas_token": token,
        "twas_user_id": user_id,
        "user_id": user_id,
        "access_token": token,
        "backend_access_token": token,
        "backend_user_id": user_id,
    }


LOGIN_NETEASE = login_netease_response(PLAYER)


# CASAG /auth/twa/verify and /refresh. The parser needs user_id + access_token
# inside `response`. Do not send `backend`: "twa" — that writes 2 into the
# token object and the client treats status 2 as invalid (the "… 2" dialog).
def verify_response(user_id: str | None = None, token: str = TOKEN) -> dict:
    user_id = active_native_user_id() if user_id is None else user_id
    return ca_envelope(
        {
            "user_id": user_id,
            "backend_user_id": user_id,
            "backend_access_token": token,
            "access_token": token,
            "refresh_token": "revival-refresh",
            "expires_at_access": 2_000_000_000_000,
            "session_length": 86400,
            "wg_auth_token": token,
            "nick": user_id,
        }
    )


VERIFY = verify_response(PLAYER)

# CAMM /public/server_list. Parser at game.dll file offset 0xBF9C60
# requires BOTH arrays inside `response` or set() returns 0:
#   relay_server_list[] with host, region
#   game_modes[] with name, max_party_size, min_tier, max_tier
# Non-empty lists have since passed native startup with a loopback UDP ping
# responder and complete startup data. Keep the normal offline list empty:
# the opt-in protocol probe does not yet provide a playable match backend.
SERVER_LIST = ca_envelope(
    {
        "relay_server_list": [],
        "game_modes": [],
    }
)

# Generic leftover login body. Do not use for /verify — errors:[] fails set().
def login_response(user_id: str | None = None, token: str = TOKEN) -> dict:
    user_id = active_native_user_id() if user_id is None else user_id
    return {
        "access_token": token,
        "refresh_token": "revival-refresh",
        "backend_access_token": token,
        "backend_refresh_token": "revival-refresh",
        "backend_user_id": user_id,
        "wg_auth_token": token,
        "twas_token": token,
        "twas_user_id": user_id,
        "netease_token": token,
        "user_id": user_id,
        "casag_id": user_id,
        "session_guid": "revival-session",
        "machine_fingerprint": f"{uuid.getnode():012x}",
        "session_length": 86400,
        "expires_at_access": 2000000000,
        "nickname": active_display_name() if user_id == active_native_user_id() else user_id,
        "display_name": active_display_name() if user_id == active_native_user_id() else user_id,
    }


LOGIN = login_response(PLAYER)


def load_catalog(path: Path) -> dict:
    if not path.is_file():
        return {"commanders": [], "units": [], "maps": []}
    return json.loads(path.read_text(encoding="utf-8"))


def load_item_ids(path: Path) -> dict:
    if not path.is_file():
        return {"currencies": [], "equipment": []}
    return json.loads(path.read_text(encoding="utf-8"))


def load_official_mappings(path: Path) -> dict:
    if not path.is_file():
        return {"item_mappings": []}
    return json.loads(path.read_text(encoding="utf-8"))


def load_native_hangar(path: Path | None = None) -> dict:
    if path is None:
        path = Path(__file__).resolve().parents[1] / "catalog" / "native_hangar.json"
    return json.loads(path.read_text(encoding="utf-8"))


def load_offline_progression(path: Path) -> dict:
    """Load server-owned commander progress; an absent file means Tier I.

    Item IDs never appear in this file.  ``build_profile`` resolves the
    commander and ability keys against the extracted native database and
    rejects an invalid or stale selection before the HTTP stack starts.
    """
    if not path.is_file():
        return {"schema_version": OFFLINE_PROGRESSION_SCHEMA_VERSION, "commanders": {}}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid offline progression JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("Offline progression must be an object")
    return value


def native_live_rows(native: dict, kind: str) -> list[dict]:
    return sorted(
        (row for row in native[kind] if row.get("build_state", "live") == "live"),
        key=lambda row: row["key"],
    )


def require_uint64(value: object) -> int:
    if type(value) is not int or not 0 < value < 2**64:
        raise ValueError(f"Expected nonzero numeric uint64: {value!r}")
    return value


def augment_native_mappings(
    official: dict,
    native: dict,
    equipment: dict | None = None,
    consumables: dict | None = None,
    commander_talents: dict | None = None,
    unit_abilities: dict | None = None,
) -> dict:
    """Preserve legacy mappings and overlay current live hangar dependencies.

    The extracted dataset identifies local fallback prices explicitly; it is
    not an original server catalogue or a reconstruction of its economy.
    """
    result = copy.deepcopy(official)
    rows = result.setdefault("item_mappings", [])
    indices = {(row["type"], row["db_key"]): index for index, row in enumerate(rows)}
    canonical_keys = {}

    def upsert(item_type: str, key: str, item_id: int, metadata: dict | None) -> None:
        item_id = require_uint64(item_id)
        canonical_keys[(item_type, item_id)] = key
        entry = {"allow_from_api": False, "db_key": key, "item_id": item_id,
                 "metadata": copy.deepcopy(metadata), "type": item_type}
        index = indices.get((item_type, key))
        if index is None:
            indices[(item_type, key)] = len(rows)
            rows.append(entry)
        else:
            rows[index] = {**rows[index], **entry}

    commanders = native_live_rows(native, "commanders")
    commander_keys = {row["key"] for row in commanders}
    for row in commanders:
        upsert("arena_commanders", row["key"], row["item_id"], row["metadata"])
    for row in native_live_rows(native, "units"):
        metadata = copy.deepcopy(row["metadata"])
        metadata.update({
            "tier": SANDBOX_UNIT_TIER,
            "num_consumable_slots": SANDBOX_CONSUMABLE_SLOTS,
            "free_xp_cents": 0,
            "unit_xp_cents": 0,
            "silver_cents": 0,
        })
        upsert("arena_unit_trees", row["key"], row["item_id"], metadata)
        upsert("main_units", row["unit_key"], row["main_unit_id"], None)
        upsert("arena_unit_strength", row["unit_key"] + "_strength", row["strength_item_id"],
               {"unit_record_key": row["unit_key"], "silver_cents": 0})
    for row in native["abilities"]:
        if row["commander"] in commander_keys:
            upsert("arena_commander_abilities", row["key"], row["item_id"], None)
    for row in native["ability_levels"]:
        if row["commander"] in commander_keys:
            upsert("arena_commander_ability_levels", row["key"], row["item_id"], row["metadata"])
    for row in native["commander_tiers"]:
        if row["commander"] in commander_keys:
            upsert("arena_commander_tiers", row["key"], row["item_id"], None)
            upsert("arena_commander_tiers_unique_ids", row["lookup_key"], row["item_id"],
                   {"commander": row["commander"], "tier": row["tier"]})
    upsert(
        "arena_tokens",
        COMMANDER_TRIAL_TOKEN_KEY,
        COMMANDER_TRIAL_TOKEN_ITEM_ID,
        None,
    )
    portrait_rows = [row for row in rows if row.get("type") == "arena_portraits"
                     and row.get("db_key") == OFFLINE_PORTRAIT_KEY]
    if len(portrait_rows) > 1:
        raise ValueError("Duplicate default portrait mappings")
    portrait_id = (require_uint64(portrait_rows[0].get("item_id")) if portrait_rows
                   else OFFLINE_PORTRAIT_ITEM_ID)
    conflicts = [row for row in rows if row.get("item_id") == portrait_id
                 and (row.get("type"), row.get("db_key")) !=
                 ("arena_portraits", OFFLINE_PORTRAIT_KEY)]
    if conflicts:
        raise ValueError("Offline portrait item ID collides with another mapping")
    upsert("arena_portraits", OFFLINE_PORTRAIT_KEY, portrait_id, None)
    # Some current IDs reuse a renamed legacy key (rom_spartacus ->
    # gla_spartacus, for example). Do not publish both keys for that type/ID.
    result["item_mappings"] = [
        row for row in rows
        if canonical_keys.get((row["type"], row["item_id"]), row["db_key"]) == row["db_key"]
    ]
    equipment = validate_native_unit_equipment(
        load_native_unit_equipment() if equipment is None else equipment,
        native,
    )
    # Equipment mappings must be present before type-5 profile records are
    # constructed. The catalogue contains exact current DB rows for every
    # live non-premium unit in the Tier-X sandbox.
    result = augment_native_equipment_mappings(result, equipment)
    consumables = validate_native_battle_consumables(
        load_native_battle_consumables() if consumables is None else consumables
    )
    # The legacy mapping snapshot lacks current China, Gladiator and Persia
    # consumables. Add their exact shipped IDs with explicit local zero-price
    # metadata before any catalogue/profile consumer resolves item IDs.
    result = augment_native_consumable_mappings(result, consumables)
    commander_talents = validate_native_commander_talents(
        load_native_commander_talents()
        if commander_talents is None else commander_talents,
        native,
    )
    result = augment_native_commander_talent_mappings(
        result, commander_talents,
    )
    unit_abilities = validate_native_unit_abilities(
        load_native_unit_abilities() if unit_abilities is None
        else unit_abilities,
        native,
    )
    return augment_native_unit_ability_mappings(result, unit_abilities)


def numeric_ids_by_type_and_key(official: dict) -> dict[tuple[str, str], int]:
    # A db_key can occur in both main_units and arena_unit_trees with
    # different IDs. Native profile records need the ID for the right type.
    out: dict[tuple[str, str], int] = {}
    for row in official.get("item_mappings") or []:
        item_type = row.get("type")
        key = row.get("db_key")
        item_id = row.get("item_id")
        if item_type and key and item_id is not None:
            typed_key = (str(item_type), str(key))
            out[typed_key] = int(item_id)
    return out


def build_versions() -> dict:
    """Object keys downloaded before the native profile's initial fetch.

    Catalogue/defaults populate the default-option list; rules_engine_stable
    initializes the achievements manager even when its JSON array is empty.
    Both are prerequisites of the normal, non-forced profile fetch.
    Validation supplies the canonical item relationships needed when the
    fetched profile's unit children are published into native models.
    """
    return {
        "catalogue": "catalogue.json",
        "defaults": "defaults.json",
        "mappings": "mappings.json",
        "rules_engine_stable": "rules_engine_stable.json",
        "validation": "validation.json",
    }


def build_defaults(catalogue: dict, profile: dict, native: dict | None = None) -> dict:
    """Choose one existing option for an already owned, equipped root unit.

    Native BD7C60 resolves these IDs against purchase_options, and BEF280
    waits for at least one resolved option. This is not an inert readiness
    flag: BE5AE0 can grant a missing receiving item later. Therefore require
    positive root ownership as well as a unit in the selected commander's
    squad, and fail rather than invent an option or select an unowned item.

    `profile` is a build_profile body or SelectionState.respond snapshot;
    only the latter may encode active_commander as signed int64 on the wire.
    No profile records, purchase options or balances are changed here.
    """
    native = native if native is not None else load_native_hangar()
    inner = profile["profile"]
    selections = [row[3] for row in inner["properties"] if row[0] == "active_commander"]
    if len(selections) != 1 or type(selections[0]) is not int:
        raise ValueError("Expected one numeric active_commander property")
    active = selections[0]
    if not -(2**63) <= active < 2**64 or active == 0:
        raise ValueError("active_commander must be a nonzero 64-bit instance ID")
    active %= 2**64

    records = inner["profile_records"]
    instances = set()
    for record in records:
        if not isinstance(record, list) or len(record) != 4:
            raise ValueError("Expected four numeric fields in a profile record")
        parent, item, instance, quantity = record
        require_uint64(item)
        require_uint64(instance)
        if (type(parent) is not int or not 0 <= parent < 2**64
                or type(quantity) is not int or not 0 <= quantity < 2**64):
            raise ValueError("Profile parent and quantity must be uint64")
        if instance in instances:
            raise ValueError("Profile instance IDs must be unique")
        instances.add(instance)
    roots = {row[2]: row[1] for row in records if row[0] == 0 and row[3] > 0}
    commander = next((row for row in native_live_rows(native, "commanders")
                      if row["item_id"] == roots.get(active)), None)
    if commander is None:
        raise ValueError("The active commander must be an owned live root instance")
    unit_items = {row["item_id"] for row in native_live_rows(native, "units")
                  if row["faction"] == commander["faction"]}
    owned_items = set(roots.values())

    options = catalogue["purchase_options"]
    option_ids = [row["id"] for row in options]
    if (any(not isinstance(key, str) or not key for key in option_ids)
            or len(set(option_ids)) != len(option_ids)):
        raise ValueError("Purchase option IDs must be nonempty unique strings")
    selected_option = None
    for parent, item, _instance, quantity in records:
        if parent != active or quantity <= 0 or item not in owned_items or item not in unit_items:
            continue
        matches = [row["id"] for row in options
                   if type(row.get("receiving_item_id")) is int and row["receiving_item_id"] == item
                   and type(row.get("receiving_quantity")) is int and row["receiving_quantity"] == 1]
        if matches:
            selected_option = min(matches)
            break
    if selected_option is None:
        raise ValueError("No existing purchase option for an owned root unit in the selected squad")
    return {
        "default_profile": [selected_option],
        "server_config": {},
        "seasons": [],
        "frontend_version": 1,
    }


def build_validation(
    profile: dict,
    *,
    native: dict | None = None,
    equipment: dict | None = None,
    consumables: dict | None = None,
    unit_abilities: dict | None = None,
) -> dict:
    """Describe trusted parent/child item pairs for the native profile.

    Native BD8540 reads a raw object and replaces its allowed_items map.
    BDD960 then checks canonical item IDs, while profile records link
    instances. Resolve those links first, including commander -> unit and
    unit -> strength; the default call never grants a wider catalogue or a
    cross-faction set.

    Production may explicitly provide all three validated native catalogues.
    That adds only relationships which a trusted economy mutation can create:
    each live commander -> its same-faction units and own ability levels,
    every live unit -> its exact native strength definition, each live
    non-premium unit -> its equipment definitions, and every live unit -> only
    the consumables mapped to its Tier-X-equivalent family. These
    relationships do
    not grant an instance, quantity, ownership or purchase permission.  They
    let the client validate a server-approved replacement *before* the new
    selected record exists in the next profile snapshot.

    Reject ambiguous, orphaned or cyclic instance graphs rather than emit
    partial permissions. Zero quantities remain valid (for example depleted
    strength): this describes a relationship, not a grant or replenishment.
    No profile records, quantities, ownership or balances are changed. The
    caller supplies server-owned state, never a client's proposed records.
    Passing only part of the opt-in catalog set is rejected.
    """
    inner = profile.get("profile") if isinstance(profile, dict) else None
    records = inner.get("profile_records") if isinstance(inner, dict) else None
    if not isinstance(records, list):
        raise ValueError("Expected a profile_records list")
    instances: dict[int, list[int]] = {}
    for record in records:
        if not isinstance(record, list) or len(record) != 4:
            raise ValueError("Expected four numeric fields in a profile record")
        parent, item, instance, quantity = record
        require_uint64(item)
        require_uint64(instance)
        if (type(parent) is not int or not 0 <= parent < 2**64
                or type(quantity) is not int or not 0 <= quantity < 2**64):
            raise ValueError("Profile parent and quantity must be uint64")
        if instance in instances:
            raise ValueError("Profile instance IDs must be unique")
        instances[instance] = record
    for parent, _item, _instance, _quantity in records:
        if parent != 0 and parent not in instances:
            raise ValueError("Profile parent instance is missing")

    # Iterative traversal avoids a recursion limit for valid deep graphs.
    # Each completed path reaches a root; every instance is visited once.
    rooted: set[int] = set()
    for instance in instances:
        path: set[int] = set()
        cursor = instance
        while cursor != 0 and cursor not in rooted:
            if cursor in path:
                raise ValueError("Profile parent links must not contain cycles")
            path.add(cursor)
            cursor = instances[cursor][0]
        rooted.update(path)

    allowed: dict[int, set[int]] = {}
    for parent, item, _instance, _quantity in records:
        if parent != 0:
            parent_item = instances[parent][1]
            allowed.setdefault(parent_item, set()).add(item)

    loadout_arguments = (native, equipment, consumables)
    if any(value is not None for value in loadout_arguments):
        if any(value is None for value in loadout_arguments):
            raise ValueError(
                "native, equipment and consumables are required together"
            )
        assert native is not None and equipment is not None and consumables is not None
        verified_equipment = validate_native_unit_equipment(equipment, native)
        verified_consumables = validate_native_battle_consumables(
            consumables, native,
        )
        verified_unit_abilities = (
            validate_native_unit_abilities(unit_abilities, native)
            if unit_abilities is not None else None
        )

        # A newly selected type-6 ability level is attached directly to its
        # owned commander root. The initial profile contains only mandatory
        # base abilities, so derive the complete set of legal future children
        # from the same trusted native catalogue used by the economy adapter.
        # This authorizes graph shape only; it grants no row or purchase.
        live_commanders: dict[str, dict] = {}
        commander_ids: set[int] = set()
        for commander in native.get("commanders", []):
            if not isinstance(commander, dict):
                raise ValueError("Invalid native validation commander")
            if commander.get("build_state", "live") != "live":
                continue
            key = commander.get("key")
            faction = commander.get("faction")
            item_id = require_uint64(commander.get("item_id"))
            if (not isinstance(key, str) or not key or key in live_commanders
                    or not isinstance(faction, str) or not faction
                    or item_id in commander_ids):
                raise ValueError("Invalid native validation commander")
            live_commanders[key] = commander
            commander_ids.add(item_id)
        for level in native.get("ability_levels", []):
            if not isinstance(level, dict):
                raise ValueError("Invalid native commander ability level")
            commander = live_commanders.get(level.get("commander"))
            if commander is None:
                continue
            allowed.setdefault(
                require_uint64(commander.get("item_id")), set(),
            ).add(require_uint64(level.get("item_id")))

        equipment_units: dict[str, dict] = {}
        eligible_units: dict[str, dict] = {}
        unit_ids: set[int] = set()
        strength_ids: set[int] = set()
        for unit in native.get("units", []):
            if not isinstance(unit, dict):
                raise ValueError("Invalid native validation unit")
            if unit.get("build_state", "live") != "live":
                continue
            key = unit.get("key")
            faction = unit.get("faction")
            item_id = require_uint64(unit.get("item_id"))
            strength_id = require_uint64(unit.get("strength_item_id"))
            if (not isinstance(key, str) or not key or key in eligible_units
                    or not isinstance(faction, str) or not faction
                    or type(unit.get("tier")) is not int
                    or unit["tier"] not in range(1, 11)
                    or item_id in unit_ids or strength_id in strength_ids):
                raise ValueError("Invalid native validation unit")
            unit_ids.add(item_id)
            strength_ids.add(strength_id)
            eligible_units[key] = unit
            if unit.get("is_premium") is False:
                equipment_units[key] = unit
        if (unit_ids & commander_ids
                or strength_ids & (unit_ids | commander_ids)):
            raise ValueError("Invalid native validation unit identity")

        # validation.json is cached at startup. A hot profile replacement
        # validates canonical parent/child IDs before attaching a deployed
        # unit's strength (RVA BECD6C -> BDE560 -> C5A230). Restricting these
        # pairs to the initial squad leaves a newly selected unit with zero
        # native strength despite a full-strength wire record, disabling Play
        # with the stock silver-replenishment warning. Pre-authorize the
        # server's legal future graph; ownership and premium purchases remain
        # enforced by LocalEconomy and require actual profile records.
        units_by_faction: dict[str, set[int]] = {}
        for unit in eligible_units.values():
            units_by_faction.setdefault(unit["faction"], set()).add(unit["item_id"])
            allowed.setdefault(unit["item_id"], set()).add(unit["strength_item_id"])
        for commander in live_commanders.values():
            allowed.setdefault(commander["item_id"], set()).update(
                units_by_faction.get(commander["faction"], set()),
            )

        # The selected type-5 tree row and its type-9 equipment definition are
        # attached to the owned unit root.  Unselected but already-owned
        # type-5 rows remain parentless so the native silver-frame group map
        # contains one entry per slot.  Pre-authorize both halves of every
        # concrete unit junction so a later trusted selection can move that
        # type-5 row under the unit and replace its type-9 definition in one
        # full profile without requiring a validation refresh.
        for row in verified_equipment["all_live_nonpremium"]:
            unit = equipment_units.get(row["source_unit"])
            if unit is None:
                raise ValueError("Invalid native validation equipment source")
            allowed.setdefault(unit["item_id"], set()).update({
                require_uint64(row["item_id"]),
                require_uint64(row["equipment_item_id"]),
            })

        consumables_by_unit = tier_equivalent_consumables_by_unit(
            native, 10, verified_consumables,
        )
        for unit_key, unit in eligible_units.items():
            candidates = consumables_by_unit.get(unit_key, [])
            if not candidates:
                raise ValueError("Missing native validation consumable candidates")
            allowed.setdefault(unit["item_id"], set()).update(
                require_uint64(row["item_id"]) for row in candidates
            )
        # Type 19 is the unit-trainable junction itself.  Pre-authorize every
        # selectable additional/default row beneath only its own unit root; commander
        # type-6 talent levels deliberately remain a separate namespace.
        if verified_unit_abilities is not None:
            for row in verified_unit_abilities["items"]:
                if row["mode"] not in {"additional", "default"}:
                    continue
                unit = eligible_units.get(row["unit"])
                if unit is None:
                    raise ValueError("Invalid native unit-ability source")
                allowed.setdefault(
                    require_uint64(unit["item_id"]), set(),
                ).add(require_uint64(row["item_id"]))
    elif unit_abilities is not None:
        raise ValueError(
            "native, equipment and consumables are required with unit abilities"
        )
    return {
        "allowed_items": [
            {"item_id": item, "items": sorted(children)}
            for item, children in sorted(allowed.items())
        ],
        "max_allowed_items": [],
    }


_TREE_COST_TYPES = {
    "arena_commanders",
    "arena_unit_trees",
    "arena_commander_abilities",
    "arena_commander_ability_levels",
}
_TREE_COST_KEYS = ("silver_cents", "gold_cents", "free_xp_cents", "unit_xp_cents")
# Preserve native unit-XP/free-XP research metadata and the LocalEconomy's
# prerequisite checks. Silver is deliberately free on the revival server for
# unit/equipment acquisition, and battle consumable loadout choices are free
# too. Keep the recovered source catalogue untouched and apply this policy
# only to the mapping view sent to the client.
_ZERO_SILVER_MAPPING_TYPES = frozenset({
    "arena_unit_trees",
    "arena_unit_equipment_trees",
    "arena_consumables",
})


def _visible_tree_costs(rows: list) -> list:
    # Preserve the zero-to-one cost adjustment used in the successful
    # offline hangar trial. Its necessity has not been isolated; this is
    # a local compatibility adjustment, not unmodified mapping metadata.
    out: list = []
    for row in rows:
        if row.get("type") not in _TREE_COST_TYPES:
            out.append(row)
            continue
        meta = row.get("metadata")
        if not isinstance(meta, dict):
            out.append(row)
            continue
        new_meta = dict(meta)
        changed = False
        for key in _TREE_COST_KEYS:
            if new_meta.get(key) == 0:
                new_meta[key] = 1
                changed = True
        if not changed:
            out.append(row)
            continue
        new_row = dict(row)
        new_row["metadata"] = new_meta
        out.append(new_row)
    return out


def _zero_silver_acquisition_cost(row: dict) -> dict:
    if row.get("type") not in _ZERO_SILVER_MAPPING_TYPES:
        return row
    metadata = row.get("metadata")
    if not isinstance(metadata, dict) or "silver_cents" not in metadata:
        return row
    result = dict(row)
    result["metadata"] = {**metadata, "silver_cents": 0}
    return result


def build_mappings(
    catalog: dict,
    extra: dict | None = None,
    official: dict | None = None,
) -> dict:
    # Native ID readers copy a JSON number's uint64 payload directly.
    # Python integers retain every bit; decimal strings are not decoded.
    _ = (catalog, extra)
    if official and official.get("item_mappings"):
        # BD68D0 also reads the separate purchase_option_children table.
        # Omit it here because this local catalogue does not implement all
        # of its referenced purchase options or their purchase semantics.
        rows = []
        for row in _visible_tree_costs(official["item_mappings"]):
            new_row = dict(row)
            if new_row.get("type") == "arena_unit_strength":
                # BFC160 has no arena_unit_strength branch: type 23 is
                # discarded by C4DB40. arena_unit_trees with the existing
                # _strength db_key resolves to native type 4 instead.
                # Keep the logical source type, IDs and metadata intact.
                new_row["type"] = "arena_unit_trees"
            new_row = _zero_silver_acquisition_cost(new_row)
            item_id = row.get("item_id")
            if item_id is None:
                rows.append(new_row)
                continue
            new_row["item_id"] = int(item_id)
            rows.append(new_row)
        return {"item_mappings": rows}
    return {"item_mappings": []}


def _trusted_talent_point_totals(
    totals: dict[str, int] | None, commander_keys: set[str],
) -> dict[str, int] | None:
    """Validate a complete server-derived override, never client input."""
    if totals is None:
        return None
    if (not isinstance(totals, dict) or set(totals) != commander_keys
            or any(type(key) is not str or type(value) is not int
                   or not 0 <= value <= 2**63 - 1
                   for key, value in totals.items())):
        raise ValueError("Invalid trusted commander talent-point totals")
    return dict(totals)


def build_catalogue(
    catalog: dict,
    extra: dict | None = None,
    official: dict | None = None,
    native: dict | None = None,
    *,
    talent_point_totals: dict[str, int] | None = None,
) -> dict:
    # Generated local options, not an original catalogue dump. BE8750
    # looks up purchase_<faction>_<unit>_<currency>; allow_from_client is
    # the availability flag used to include unowned faction-tree nodes.
    _ = (catalog, extra)
    native = native if native is not None else load_native_hangar()
    official = official or {}
    ids = numeric_ids_by_type_and_key(official)
    options = []
    for row in native_live_rows(native, "units"):
        metadata = row["metadata"]
        currency = "gold_cents" if row["is_premium"] else "unit_xp_cents"
        # The local premium policy is a uniform 1,000 Gold (cents on wire),
        # independent of stale or sentinel prices recovered from old DB rows.
        cost = (PREMIUM_UNIT_GOLD_COST
                if row["is_premium"] else metadata[currency])
        if type(cost) is not int or not 0 <= cost < 2**64:
            raise ValueError(f"Invalid cost: {row['key']} / {cost!r}")
        options.append({
            "id": f"purchase_{row['faction']}_{row['unit_key']}_{currency}",
            "currency_item_id": ids[("arena_currencies", currency)],
            "currency_quantity": cost,
            "receiving_item_id": require_uint64(row["item_id"]),
            "receiving_quantity": 1,
            "allow_from_client": True,
            "is_visible": True,
            "metadata": {},
        })

    talents = validate_native_commander_talents(
        load_native_commander_talents(), native,
    )
    talent_rows = talent_rows_by_commander(talents)

    # 10BFDB80 formats commander-tree purchases exactly as
    # ``unlock_ability_<ability-key>_<level>``. The executor has no rank-based
    # currency branch: it resolves both currency and amount from this PO. The
    # three base active rank-one rows are granted by commander-purchase child
    # options; every manual tree rank uses one point from its commander's
    # type-21 pool. They must not be published as the generic BFD030
    # ``purchase_<mapping>_<currency>`` tree option.
    live_commanders = {row["key"] for row in native_live_rows(native, "commanders")}
    talent_point_totals = _trusted_talent_point_totals(
        talent_point_totals, live_commanders,
    )
    for row in native.get("ability_levels", []):
        if not isinstance(row, dict) or row.get("commander") not in live_commanders:
            continue
        key = row.get("key")
        item_id = require_uint64(row.get("item_id"))
        metadata = row.get("metadata")
        if (not isinstance(key, str) or not key or not isinstance(metadata, dict)
                or type(metadata.get("free_xp_cents")) is not int
                or not 0 <= metadata["free_xp_cents"] < 2**64
                or ids.get(("arena_commander_ability_levels", key)) != item_id):
            raise ValueError(f"Invalid commander ability purchase row: {key!r}")
        ability_key = metadata.get("ability_key")
        level = metadata.get("ability_level")
        commander = row.get("commander")
        if (not isinstance(ability_key, str) or not ability_key
                or type(level) is not int or level < 1
                or commander not in talent_rows):
            raise ValueError(f"Invalid commander ability identity: {key!r}")
        options.append({
            "id": f"unlock_ability_{ability_key}_{level}",
            "currency_item_id": talent_rows[commander]["item_id"],
            "currency_quantity": 1,
            "receiving_item_id": item_id,
            "receiving_quantity": 1,
            "allow_from_client": True,
            "is_visible": True,
            "metadata": {},
        })
        options.append({
            "id": f"refund_ability_{ability_key}_{level}",
            "currency_item_id": item_id,
            "currency_quantity": 1,
            "receiving_item_id": talent_rows[commander]["item_id"],
            "receiving_quantity": 1,
            "allow_from_client": True,
            "is_visible": False,
            "metadata": {},
        })

    # 10BC5360 asks the catalogue for one of these options for every Tier up
    # to the commander's current Tier, then 10C51040 sums each receiving
    # quantity. The DB's ten values are per-Tier grants rather than cumulative
    # totals, so publish all 25 x 10 rows including the Tier-I zero grant.
    talent_track_id = ids[("arena_currencies", TALENT_TRACK_CURRENCY)]
    for commander, row in sorted(talent_rows.items()):
        grants = (row["tier_grants"] if talent_point_totals is None
                  else [0] * 9 + [talent_point_totals[commander]])
        for tier, grant in enumerate(grants, 1):
            options.append({
                "id": f"claim_tier_{tier}_{commander}_talent_points",
                "currency_item_id": talent_track_id,
                "currency_quantity": 0,
                "receiving_item_id": row["item_id"],
                "receiving_quantity": grant,
                "allow_from_client": False,
                "is_visible": False,
                "metadata": {},
            })

    # C45AD0 formats both equipment actions as
    # ``{equip|unequip}_<source-unit-key>_<equipment-key>``.  A live client
    # request confirmed both spellings for bar_mounted_warband; the junction
    # DB key is not part of the purchase-option ID.
    equipment = validate_native_unit_equipment(
        load_native_unit_equipment(), native,
    )
    silver_item_id = ids[("arena_currencies", "silver_cents")]
    for row in equipment["all_live_nonpremium"]:
        for action in ("equip", "unequip"):
            options.append({
                "id": f"{action}_{row['source_unit']}_{row['equipment_key']}",
                "currency_item_id": silver_item_id,
                "currency_quantity": 0,
                "receiving_item_id": require_uint64(row["equipment_item_id"]),
                "receiving_quantity": 1,
                "allow_from_client": True,
                "is_visible": True,
                "metadata": {},
            })

    # BC97B0/BFD720 concatenate the unit and ability DB keys without a
    # delimiter.  These zero-price options select the type-19 junction; they
    # are unrelated to commander ``unlock_ability_*`` talent purchases.
    unit_abilities = validate_native_unit_abilities(
        load_native_unit_abilities(), native,
    )
    for row in unit_abilities["items"]:
        if row["mode"] not in {"additional", "default"}:
            continue
        for action in ("equip", "unequip"):
            options.append({
                "id": f"{action}_ability_{row['db_key']}",
                "currency_item_id": silver_item_id,
                "currency_quantity": 0,
                "receiving_item_id": require_uint64(row["item_id"]),
                "receiving_quantity": 1,
                "allow_from_client": True,
                "is_visible": action == "equip",
                "metadata": {},
            })

    # Consumable picker lookup at game.dll BE83A0 concatenates the item key
    # and currency key without an extra separator.  Keep both protocol keys,
    # but publish only the zero-silver choice in the picker.  Exposing the
    # zero-gold compatibility key as a second visible offer duplicates every
    # consumable in the stock UI.
    consumables = validate_native_battle_consumables(
        load_native_battle_consumables(), native, official,
    )
    for row in tier_equivalent_service_definitions(native, 10, consumables):
        for currency in ("silver_cents", "gold_cents"):
            options.append({
                "id": f"purchase_consumable_{row['db_key']}{currency}",
                "currency_item_id": ids[("arena_currencies", currency)],
                "currency_quantity": 0,
                "receiving_item_id": require_uint64(row["item_id"]),
                "receiving_quantity": 1,
                "allow_from_client": True,
                "is_visible": currency == "silver_cents",
                "metadata": {},
            })
        # Type-11 removal does not reuse the purchase option.  game.dll
        # 10BFD52B -> 10BED6A0 formats this distinct option exactly as
        # ``refund_consumable_<key>silver_cents``.  The selected consumable is
        # the one-unit input and the account silver row is the zero-value
        # local refund destination.
        options.append({
            "id": f"refund_consumable_{row['db_key']}silver_cents",
            "currency_item_id": require_uint64(row["item_id"]),
            "currency_quantity": 1,
            "receiving_item_id": silver_item_id,
            "receiving_quantity": 0,
            "allow_from_client": True,
            "is_visible": False,
            "metadata": {},
        })
    options.sort(key=lambda row: row["id"])
    if len({row["id"] for row in options}) != len(options):
        raise ValueError("Canonical faction/unit/currency keys are not unique")
    return {"purchase_options": options, "po_package_map": []}


def native_full_strength(unit: dict) -> int:
    """Native replenishment quantity, separate from the model's troop count.

    The nine shipped war-elephant definitions require 100 at readiness RVA
    C484A0, although main_units.num_men is 4. Sending the crew count leaves
    them depleted. Other unit families use their native num_men unchanged.
    This affects the trusted initial profile, never battle damage/results.
    """
    num_men = unit["num_men"]
    if type(num_men) is not int or not 0 < num_men < 2**31:
        raise ValueError(f"Invalid initial troop strength: {unit['key']} / {num_men!r}")
    if unit.get("metadata", {}).get("squad_role_string") == "war_elephant":
        return 100
    return num_men


def build_profile(
    catalog: dict,
    official: dict | None = None,
    native: dict | None = None,
    active_key: str = "rom_germanicus",
    progression: dict | None = None,
    user_id: str | None = None,
    *,
    talent_point_bonuses: dict[str, int] | None = None,
    talent_point_totals: dict[str, int] | None = None,
) -> dict:
    """Build internal profile state with positive uint64 IDs, not wire output.

    SelectionState.respond serializes this state for HTTP, including the
    native signed-int64 representation of properties.active_commander.
    Do not send this builder's result directly for high-bit commander IDs.

    This creates an offline roster with server-owned commander progression,
    the DB-defined initial troop strength, and stable local instance IDs. It
    is not a battle snapshot, a replenishment API or a reconnect restore.
    """
    # HTTP BD7940 -> C4D9A0 expects numeric arrays:
    # [parent_instance_id, item_id, instance_id, quantity]. The local-cache
    # acquired_item_list / commanders objects are not this HTTP schema.
    _ = catalog
    native = native if native is not None else load_native_hangar()
    commanders = native_live_rows(native, "commanders")
    units = {row["key"]: row for row in native_live_rows(native, "units")}
    ability_items = {row["key"]: require_uint64(row["item_id"])
                     for row in native.get("abilities", [])
                     if row.get("commander") in {commander["key"] for commander in commanders}}
    ability_levels = list(native.get("ability_levels", []))
    commander_tiers = list(native.get("commander_tiers", []))
    commander_talents = validate_native_commander_talents(
        load_native_commander_talents(), native,
    )
    talent_rows = talent_rows_by_commander(commander_talents)
    ability_predecessors = ability_predecessors_by_commander(
        commander_talents, native,
    )
    unit_tree_links = list(native.get("unit_tree_links", []))
    by_commander = {row["key"]: row for row in commanders}
    talent_point_totals = _trusted_talent_point_totals(
        talent_point_totals, set(by_commander),
    )
    if talent_point_totals is not None and talent_point_bonuses is not None:
        raise ValueError("Trusted talent-point total and bonus overrides conflict")
    if active_key not in by_commander:
        raise ValueError(f"Unknown live commander: {active_key}")
    # The final commander root becomes the shown model during a complete
    # native profile rebuild.  Keep the catalogue order for every other card,
    # then publish the authoritative active commander last so the card
    # highlight, 3D model and active property agree.
    commanders = [row for row in commanders if row["key"] != active_key] + [
        by_commander[active_key]
    ]
    if progression is None:
        progression = {"schema_version": OFFLINE_PROGRESSION_SCHEMA_VERSION,
                       "commanders": {}}
    if (not isinstance(progression, dict)
            or set(progression) != {"schema_version", "commanders"}
            or type(progression.get("schema_version")) is not int
            or progression.get("schema_version") != OFFLINE_PROGRESSION_SCHEMA_VERSION
            or not isinstance(progression.get("commanders"), dict)):
        raise ValueError("Invalid offline progression schema")
    configured_progress = progression["commanders"]
    if any(not isinstance(key, str) or key not in by_commander for key in configured_progress):
        raise ValueError("Offline progression contains an unknown commander")
    if talent_point_bonuses is None:
        talent_point_bonuses = {}
    if (not isinstance(talent_point_bonuses, dict)
            or any(not isinstance(key, str) or key not in by_commander
                   or type(value) is not int or not 0 <= value <= 2**63 - 1
                   for key, value in talent_point_bonuses.items())):
        raise ValueError("Invalid trusted commander talent-point bonuses")
    portrait_rows = [row for row in (official or {}).get("item_mappings", [])
                     if row.get("type") == "arena_portraits"
                     and row.get("db_key") == OFFLINE_PORTRAIT_KEY]
    if len(portrait_rows) > 1:
        raise ValueError("Duplicate offline portrait mappings")
    portrait_id = require_uint64(portrait_rows[0]["item_id"]) if portrait_rows else None
    occupied = {require_uint64(row["item_id"]) for row in (official or {}).get("item_mappings", [])}
    occupied.update(require_uint64(row["item_id"]) for row in commanders)
    occupied.update(require_uint64(row["item_id"]) for row in units.values())
    occupied.update(require_uint64(row["item_id"])
                    for row in talent_rows.values())
    for rows in (native.get("abilities", []), ability_levels, commander_tiers):
        occupied.update(require_uint64(row["item_id"]) for row in rows)
    occupied.update(require_uint64(row["strength_item_id"]) for row in units.values())

    def stable_instance(label: str) -> int:
        value = int.from_bytes(hashlib.sha256(label.encode("utf-8")).digest()[:8], "little")
        while value == 0 or value in occupied:
            value = (value + 1) % 2**64
        occupied.add(value)
        return value
    records = [[0, require_uint64(row["item_id"]), require_uint64(row["item_id"]), 1]
               for row in commanders]
    if portrait_id is not None:
        if portrait_id in {row[2] for row in records}:
            raise ValueError("Offline portrait collides with commander ownership")
        records.append([0, portrait_id, portrait_id, 1])

    # arena_commander_tiers_unique_ids resolves to native profile type 12.
    # BEBA34 handles those records as roots and raises a commander's visible
    # tier to the highest owned row.  A type-6 ability-level record is instead
    # consumed only while BEB880 walks that commander's children.  The base
    # arena_commander_abilities item is type 8 and C4DB40 deliberately returns
    # no profile model for it, so it must never be emitted as ownership.
    #
    # The current DB has exactly one base battle ability at Tiers I, III and V
    # for every live commander. Tree modifier keys encode their position as
    # ``_<tier>-<column>_``; the three base keys do not. All unlocked base
    # abilities must be present even when an older progression state omitted
    # them, otherwise battle reconstruction exposes only the Tier-I button.
    # A trusted progression file can add modifier nodes and upgraded levels
    # using canonical string keys; client-supplied item IDs are never accepted.
    resolved_tiers = {}
    for commander in commanders:
        commander_key = commander["key"]
        tier_rows = {row.get("tier"): row for row in commander_tiers
                     if row.get("commander") == commander_key}
        if set(tier_rows) != set(range(1, 11)):
            raise ValueError(f"Expected ten commander progress rows: {commander_key}")

        level_index = {}
        base_levels = {}
        for level in ability_levels:
            metadata = level.get("metadata")
            if level.get("commander") != commander_key or not isinstance(metadata, dict):
                continue
            ability_key = metadata.get("ability_key")
            ability_level = metadata.get("ability_level")
            required_tier = metadata.get(commander_key)
            if (not isinstance(ability_key, str) or ability_key not in ability_items
                    or type(ability_level) is not int or ability_level < 1
                    or type(required_tier) is not int or not 1 <= required_tier <= 10):
                raise ValueError(f"Invalid commander ability metadata: {commander_key}")
            index_key = (ability_key, ability_level)
            if index_key in level_index:
                raise ValueError(f"Duplicate commander ability level: {commander_key} / {index_key}")
            level_index[index_key] = level
            if (ability_level == 1 and required_tier in (1, 3, 5)
                    and re.search(r"_\d+-\d+_", ability_key) is None):
                if required_tier in base_levels:
                    raise ValueError(
                        f"Duplicate base commander ability: {commander_key} / {required_tier}"
                    )
                base_levels[required_tier] = level
        if set(base_levels) != {1, 3, 5}:
            raise ValueError(f"Expected Tier-I/III/V commander abilities: {commander_key}")
        state = configured_progress.get(commander_key)
        if state is None:
            tier, requested = 1, {}
        else:
            required_state = {"tier", "abilities"}
            allowed_state = required_state | {
                "equipped_units", "unlocked_units", "talent_points",
            }
            if (not isinstance(state, dict) or not required_state <= set(state)
                    or not set(state) <= allowed_state):
                raise ValueError(f"Invalid commander progression: {commander_key}")
            tier, requested = state["tier"], state["abilities"]
            if type(tier) is not int or not 1 <= tier <= 10 or not isinstance(requested, dict):
                raise ValueError(f"Invalid commander progression: {commander_key}")
            if len(requested) > len(level_index):
                raise ValueError(f"Too many commander abilities: {commander_key}")
        resolved_tiers[commander_key] = tier

        selected = {
            base_levels[required_tier]["metadata"]["ability_key"]: 1
            for required_tier in (1, 3, 5)
            if required_tier <= tier
        }
        for ability_key, ability_level in requested.items():
            if not isinstance(ability_key, str) or type(ability_level) is not int or ability_level < 1:
                raise ValueError(f"Invalid commander ability selection: {commander_key}")
            selected[ability_key] = ability_level

        for ability_key in selected:
            parents = ability_predecessors.get((commander_key, ability_key))
            if parents is None:
                raise ValueError(
                    f"Unknown commander ability: {commander_key} / {ability_key}"
                )
            if parents and not any(selected.get(parent, 0) >= 1 for parent in parents):
                raise ValueError(
                    f"Commander ability prerequisite missing: "
                    f"{commander_key} / {ability_key}"
                )

        base_keys = {
            level["metadata"]["ability_key"] for level in base_levels.values()
        }
        spent_points = sum(
            max(level - 1, 0) if ability_key in base_keys else level
            for ability_key, level in selected.items()
        )
        total_points = (
            talent_point_totals[commander_key]
            if talent_point_totals is not None
            else (talent_rows[commander_key]["cumulative_points"][tier - 1]
                  + talent_point_bonuses.get(commander_key, 0))
        )
        if total_points > 2**63 - 1:
            raise ValueError("Invalid trusted commander talent-point bonuses")
        remaining_points = (
            max(total_points - spent_points, 0)
            if state is None or "talent_points" not in state
            else state["talent_points"]
        )
        if (type(remaining_points) is not int
                or not 0 <= remaining_points <= total_points
                or spent_points > total_points
                or remaining_points + spent_points != total_points):
            raise ValueError(
                f"Invalid commander talent balance: {commander_key}"
            )
        records.append([
            0,
            require_uint64(talent_rows[commander_key]["item_id"]),
            stable_instance(f"revival:commander-talents:{commander_key}"),
            remaining_points,
        ])

        for progress_tier in range(1, tier + 1):
            tier_item = require_uint64(tier_rows[progress_tier]["item_id"])
            records.append([0, tier_item, tier_item, 1])

        for ability_key in sorted(selected):
            # The type-8 base item is an integrity mapping only. Native type 8
            # has no profile object. 10C5B380 always sends a zero receiving
            # instance for the next rank and its prerequisite getter checks
            # ownership of the preceding rank item. Retain every type-6 rank
            # as its own row and instance rather than replacing the old rank.
            if ability_key not in ability_items:
                raise ValueError(
                    f"Unknown commander ability: {commander_key} / {ability_key}"
                )
            require_uint64(ability_items[ability_key])
            for rank in range(1, selected[ability_key] + 1):
                level = level_index.get((ability_key, rank))
                if level is None:
                    raise ValueError(
                        f"Unknown commander ability level: "
                        f"{commander_key} / {ability_key} / {rank}"
                    )
                required_tier = level["metadata"][commander_key]
                if required_tier > tier:
                    raise ValueError(
                        f"Commander ability exceeds tier: "
                        f"{commander_key} / {ability_key} / {rank}"
                    )
                records.append([
                    require_uint64(commander["item_id"]),
                    require_uint64(level["item_id"]),
                    stable_instance(
                        f"revival:commander-ability:{commander_key}:"
                        f"{ability_key}:{rank}"
                    ),
                    1,
                ])
    # Resolve each configured loadout through the real arena_unit_tree_links
    # graph.  If a progressed commander has no explicit three-unit loadout,
    # advance each starter branch to that commander Tier, preferring the same
    # squad role. Explicit additional unlocks are also closed over their real
    # prerequisite paths so the unit tree never shows an orphaned node.
    graph = {key: [] for key in units}
    seen_links = set()
    for link in unit_tree_links:
        if not isinstance(link, dict):
            raise ValueError("Invalid native unit tree link")
        parent, child = link.get("key_0"), link.get("key_1")
        if parent not in units or child not in units:
            continue
        if units[parent]["faction"] != units[child]["faction"]:
            raise ValueError(f"Cross-faction unit tree link: {parent} / {child}")
        pair = (parent, child)
        if pair in seen_links:
            raise ValueError(f"Duplicate unit tree link: {parent} / {child}")
        seen_links.add(pair)
        graph[parent].append((child, link.get("placement_0"), link.get("placement_1")))
    for edges in graph.values():
        edges.sort(key=lambda edge: (edge[2] != 2, edge[2] if type(edge[2]) is int else 99,
                                     edge[0]))

    def paths_from(start: str) -> dict[str, tuple[str, ...]]:
        paths = {start: (start,)}
        queue = [start]
        cursor = 0
        while cursor < len(queue):
            parent = queue[cursor]
            cursor += 1
            for child, _placement_0, _placement_1 in graph.get(parent, []):
                if child in paths or units[child].get("is_premium"):
                    continue
                paths[child] = paths[parent] + (child,)
                queue.append(child)
        return paths

    resolved_loadouts = {}
    resolved_unlocks = {}
    for commander in commanders:
        commander_key = commander["key"]
        tier = resolved_tiers[commander_key]
        state = configured_progress.get(commander_key) or {}
        starters = list(commander["starting_units"])
        if len(starters) != 3 or any(key not in units for key in starters):
            raise ValueError(f"Expected three DB-defined slots: {commander_key}")
        if any(units[key]["faction"] != commander["faction"] for key in starters):
            raise ValueError(f"Starter faction mismatch: {commander_key}")

        explicit = state.get("equipped_units")
        if explicit is not None:
            if (not isinstance(explicit, list) or len(explicit) != 3
                    or any(not isinstance(key, str) for key in explicit)):
                raise ValueError(f"Invalid equipped units: {commander_key}")
            equipped = list(explicit)
        else:
            equipped = []
            for start in starters:
                paths = paths_from(start)
                role = units[start]["metadata"].get("squad_role")
                candidates = [key for key, path in paths.items()
                              if units[key]["tier"] == tier and not units[key].get("is_premium")]
                if not candidates:
                    raise ValueError(f"No reachable Tier-{tier} unit: {commander_key} / {start}")
                equipped.append(min(candidates, key=lambda key: (
                    units[key]["metadata"].get("squad_role") != role,
                    len(paths[key]), key,
                )))

        extra = state.get("unlocked_units", [])
        if (not isinstance(extra, list) or len(extra) > len(units)
                or any(not isinstance(key, str) for key in extra)
                or len(extra) != len(set(extra))):
            raise ValueError(f"Invalid unlocked units: {commander_key}")

        unlocks = set()
        starts_by_key = {start: paths_from(start) for start in set(starters)}
        for key in equipped + extra:
            unit = units.get(key)
            if (unit is None or unit["faction"] != commander["faction"]
                    or type(unit.get("tier")) is not int or not 1 <= unit["tier"] <= tier):
                raise ValueError(f"Invalid progressed unit: {commander_key} / {key}")
            paths = [known[key] for known in starts_by_key.values() if key in known]
            if paths:
                unlocks.update(min(paths, key=lambda path: (len(path), path)))
            elif unit.get("is_premium") and key in state.get("unlocked_units", []):
                unlocks.add(key)
            else:
                # Revival's Tier-X sandbox deliberately exposes every live
                # same-faction unit, including branches outside a particular
                # commander's three shipped starter paths.  The validation
                # above still rejects unknown, cross-faction and over-tier
                # rows; represent a valid cross-branch unlock as its own root.
                unlocks.add(key)
        resolved_loadouts[commander_key] = equipped
        resolved_unlocks[commander_key] = unlocks

    owned_units = set()
    equipped_strengths = []
    for commander in commanders:
        commander_key = commander["key"]
        for key in sorted(resolved_unlocks[commander_key],
                          key=lambda unit_key: (units[unit_key]["tier"], unit_key)):
            unit = units[key]
            item_id = require_uint64(unit["item_id"])
            if item_id not in owned_units:
                records.append([0, item_id, item_id, 1])
                owned_units.add(item_id)
        for slot, key in enumerate(resolved_loadouts[commander_key]):
            unit = units[key]
            item_id = require_uint64(unit["item_id"])
            # Local instance identity, stable across row order and additions.
            # It is separate from the canonical item ID and cannot collide.
            instance_id = stable_instance(f"revival:starter:{commander['key']}:{slot}")
            records.append([require_uint64(commander["item_id"]), item_id, instance_id, 1])
            strength = native_full_strength(unit)
            equipped_strengths.append((instance_id, require_uint64(unit["strength_item_id"]), strength))
    # A strength record belongs to each equipped unit INSTANCE, not to its
    # shared root unlock or to the commander. Native child type 4 at BEC25A
    # passes its quantity to C5A230 (RVA) -> unit+108. C484A0 compares it
    # with the definition's required strength. Elephants use 100, not their
    # four crew members. Keep the native readiness check and model count intact.
    # Allocate these only after all starters to preserve their existing IDs.
    for unit_instance, strength_item, strength in equipped_strengths:
        instance_id = stable_instance(f"revival:starter-strength:{unit_instance}")
        records.append([unit_instance, strength_item, instance_id, strength])
    # The whole profile graph's identity.  ``user_id=None`` keeps the legacy
    # single-user lab value unless ``bind_identity`` resolved a real player.
    profile_user_id = active_native_user_id() if user_id is None else user_id
    return {
        "result": "out_of_sync",
        "profile": {
            "user_id": profile_user_id,
            "name": (active_display_name() if profile_user_id == active_native_user_id()
                     else profile_user_id),
            # BD7940 rejects older versions. Keep at least the successful
            # trial's version and advance with each server startup.
            "saved": max(time.time_ns() // 1_000_000, 1788186881000),
            "profile_records": records,
            # BD7D40 reads the key at index 0 and value at index 3.
            # The meanings of slots 1/2 remain unknown; tested zeros work.
            # Selection uses the commander instance ID. These root
            # instances deliberately share their canonical item IDs.
            "properties": (
                [["active_commander", 0, 0, require_uint64(by_commander[active_key]["item_id"])]]
                + ([['active_title', 0, 0, portrait_id]] if portrait_id is not None else [])
            ),
        },
    }


# Help text says "frontend"; the mode walker compares the stored token to "front_end".
# fake_auth_token / display_name_override are the built-in offline CA session.
# ``fake_auth_token`` must equal the ``+auth`` launch argument: both become the
# ``netease_token`` this server resolves back into a NativeIdentity.
_SCRIPT_TOKEN = re.compile(r"[\x20-\x21\x23-\x7e]{1,8192}")


def frontend_user_script(token: str = TOKEN, display_name: str | None = None) -> str:
    display_name = active_native_user_id() if display_name is None else display_name
    from companion.player_name import validate_display_name
    # Legacy transport identifiers can be 36 characters; real names are 1..32.
    if not isinstance(display_name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,36}', display_name):
        validate_display_name(display_name)
    if not _SCRIPT_TOKEN.fullmatch(token):
        raise ValueError("unquotable user script value")
    return (
        "game_startup_mode front_end;\n"
        f'fake_auth_token "{token}";\n'
        f'display_name_override "{display_name}";\n'
        "PERMANENTLY_SKIP_TUTORIAL true;\n"
        "disable_first_time_advice true;\n"
        "battle_advice_level 0;\n"
    )


FRONTEND_USER_SCRIPT = frontend_user_script(TOKEN, PLAYER)
