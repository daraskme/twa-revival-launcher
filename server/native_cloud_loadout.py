"""Revision-safe synchronization of the native type selection to the Worker."""
from __future__ import annotations

from dataclasses import dataclass

MAX_SAFE_INTEGER = (1 << 53) - 1
UINT64_MAX = (1 << 64) - 1


class CloudLoadoutError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CloudLoadout:
    revision: int
    commander_id: str
    item_ids: tuple[str, str, str]


def _view(value: object) -> CloudLoadout:
    if not isinstance(value, dict) or set(value) != {"revision", "loadout"}:
        raise CloudLoadoutError("invalid_loadout_response")
    revision, loadout = value["revision"], value["loadout"]
    if type(revision) is not int or not 0 <= revision <= MAX_SAFE_INTEGER or not isinstance(loadout, dict) \
            or set(loadout) != {"commanderId", "faction", "units", "maxTier"}:
        raise CloudLoadoutError("invalid_loadout_response")
    units = loadout.get("units")
    if (not isinstance(loadout.get("commanderId"), str)
            or not _uint64(loadout.get("commanderId"))
            or not isinstance(loadout.get("faction"), str)
            or loadout.get("maxTier") != 10 or type(loadout.get("maxTier")) is not int
            or not isinstance(units, list) or len(units) != 3):
        raise CloudLoadoutError("invalid_loadout_response")
    ids = []
    instances = set()
    for unit in units:
        if (not isinstance(unit, dict)
                or set(unit) != {"instanceId", "itemId", "key", "faction", "tier"}
                or any(not isinstance(unit.get(key), str) or not unit[key]
                       for key in ("instanceId", "key", "faction"))
                or not _uint64(unit.get("itemId"))
                or type(unit.get("tier")) is not int or unit["tier"] != 10
                or unit["faction"] != loadout["faction"]
                or unit["instanceId"] in instances):
            raise CloudLoadoutError("invalid_loadout_response")
        instances.add(unit["instanceId"])
        ids.append(unit["itemId"])
    return CloudLoadout(revision, loadout["commanderId"], tuple(ids))


def _uint64(value: object) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 20
            and value.isascii() and value.isdecimal() and value[0] != "0"
            and (len(value) < 20 or value <= str(UINT64_MAX)))


def sync_cloud_loadout(client: object, commander_id: str,
                       item_ids: list[str], *, api_errors: tuple[type, type, type]) -> CloudLoadout:
    """Publish one desired selection without ever blindly retrying a PUT."""
    if (not _uint64(commander_id)
            or not isinstance(item_ids, list) or len(item_ids) != 3
            or any(not _uint64(item) for item in item_ids)):
        raise CloudLoadoutError("invalid_native_loadout")
    api_error, conflict, network = api_errors

    def get() -> CloudLoadout:
        try:
            return _view(client.get_loadout())
        except (api_error, conflict) as error:
            raise CloudLoadoutError(str(getattr(error, "code", "loadout_error"))) from None
        except network:
            raise CloudLoadoutError("worker_unreachable") from None

    desired = (commander_id, tuple(item_ids))
    def select() -> None:
        try:
            client.select_commander(commander_id)
        except network:
            # PATCH may have committed; one GET resolves it without retrying.
            observed = get()
            if observed.commander_id != commander_id:
                raise CloudLoadoutError("commander_sync_uncertain") from None
        except (api_error, conflict) as error:
            raise CloudLoadoutError(str(getattr(error, "code", "commander_error"))) from None
    try:
        current = get()
    except CloudLoadoutError as error:
        if error.code != "commander_selection_required":
            raise
        select()
        current = get()
    if current.commander_id != commander_id:
        select()
        current = get()
    if current.commander_id != commander_id:
        raise CloudLoadoutError("commander_confirmation_mismatch")
    if (current.commander_id, current.item_ids) == desired:
        return current
    try:
        result = _view(client.put_loadout(commander_id, item_ids, current.revision))
    except network:
        # The write may have committed. Resolve by a read; never issue a
        # second PUT whose expected revision is now ambiguous.
        result = get()
        if result.revision != current.revision + 1:
            raise CloudLoadoutError("loadout_sync_uncertain") from None
    except conflict as error:
        if str(getattr(error, "code", "conflict")) != "loadout_revision_conflict":
            raise CloudLoadoutError(str(getattr(error, "code", "conflict"))) from None
        result = get()
        if result.revision != current.revision + 1:
            raise CloudLoadoutError("loadout_revision_conflict") from None
    except api_error as error:
        raise CloudLoadoutError(str(getattr(error, "code", "loadout_error"))) from None
    if (result.commander_id, result.item_ids) != desired:
        raise CloudLoadoutError("loadout_confirmation_mismatch")
    if result.revision != current.revision + 1:
        raise CloudLoadoutError("loadout_revision_mismatch")
    return result
