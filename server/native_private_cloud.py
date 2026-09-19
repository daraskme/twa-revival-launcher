"""Validated projection between Worker rooms and native custom-lobby routes."""
from __future__ import annotations

import copy
import hashlib
import json
import re
import threading
import time
from typing import Callable

from native_cloud_loadout import _uint64
from native_custom_lobby import NativeLobbyError, ca_envelope, decode_native_request
from native_battle_maps import (
    is_native_battle_map,
    native_battle_map_key,
    native_battle_maps_for_ruleset,
)
from native_matchmaking import ARBITRATION_FIELDS, NativeMatchmaking
from local_battle_state import BattleStateError
from native_private_cpu_notifications import CpuNotificationDeliveryUncertain, _loadout_json

UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
REWARD_POLICY = {"policyId": "private-zero-reward-v1", "authority": "server", "allRewardsZero": True}
ECONOMY_POLICY = {"policyId": "private-zero-economy-v1", "authority": "server", "roomCreationCost": 0,
                  "rewardMultiplier": 0, "battleCosts": {"commanders": 0, "units": 0, "abilities": 0,
                  "equipment": 0, "consumables": 0}}
ENTITLEMENT = {"policyId": "private-all-content-v1", "authority": "server",
               "scope": "private_battle_only", "allContentUnlocked": True, "persistToProfile": False}
MAX_NOTIFICATION_OUTBOX = 256
_NATIVE_RULESETS = ("annihilation", "territory")


def _native_map_keys() -> list[str]:
    """Return the complete audited lobby map list in manifest order."""
    return [row["key"] for ruleset in _NATIVE_RULESETS
            for row in native_battle_maps_for_ruleset(ruleset)]


def _native_map_for_ruleset(map_key: object, ruleset: object) -> bool:
    """Validate a selected map against its exact manifest ruleset."""
    return is_native_battle_map(map_key, ruleset)


def _legacy_map_for_ruleset(ruleset: object) -> str:
    """Resolve the historic map only for records that omit ``mapKey``."""
    return native_battle_map_key(ruleset)


class PrivateCloudError(Exception):
    pass


class PrivateBattleTransportError(Exception):
    def __init__(self, status: int | None, code: str, *, uncertain: bool):
        super().__init__(code)
        self.status = status
        self.code = code
        self.uncertain = uncertain


class PrivateBattleApi:
    """Narrow coordinator-facing wrapper over the real companion API client."""
    def __init__(self, api: object):
        self._api = api

    @staticmethod
    def _call(call, *, mutation: bool):
        try:
            return call()
        except Exception as error:
            status = getattr(error, "status", None)
            code = getattr(error, "code", None)
            if not isinstance(code, str):
                code = "worker_unreachable"
            uncertain = status is None or (mutation and type(status) is int and status >= 500)
            raise PrivateBattleTransportError(
                status if type(status) is int else None, code, uncertain=uncertain) from None

    def put_squad(self, battle_id: str, rows: object) -> dict:
        return self._call(lambda: self._api.put_squad(battle_id, rows), mutation=True)

    def get_roster(self, battle_id: str) -> dict:
        return self._call(lambda: self._api.get_roster(battle_id), mutation=False)

    def relay_ticket(self, battle_id: str) -> dict:
        return self._call(lambda: self._api.relay_ticket(battle_id), mutation=True)

    def report_result(self, battle_id: str, payload: dict) -> dict:
        """Submit one frozen result; an absent response is always uncertain."""
        return self._call(
            lambda: self._api.report_battle_result(battle_id, payload),
            mutation=True,
        )

    def get_battle(self, battle_id: str) -> dict:
        """Read the authenticated participant view used to resolve retries."""
        return self._call(lambda: self._api.get_battle(battle_id), mutation=False)


def _typed_equal(value, expected) -> bool:
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(value) == set(expected) and all(_typed_equal(value[key], item) for key, item in expected.items())
    return value == expected


def _room_config(value: object, error: str) -> dict:
    if (not isinstance(value, dict) or set(value) != {"title", "length"}
            or not isinstance(value.get("title"), str) or not 1 <= len(value["title"]) <= 80
            or value["title"] != value["title"].strip()
            or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value["title"])
            or type(value.get("length")) is not int or not 1 <= value["length"] <= 7200):
        raise PrivateCloudError(error)
    return copy.deepcopy(value)


def _loadout(value: object, native: dict) -> dict:
    commanders = {str(row["item_id"]): row for row in native["commanders"] if row.get("build_state") == "live"}
    units = {str(row["item_id"]): row for row in native["units"] if row.get("build_state", "live") == "live"}
    if not isinstance(value, dict) or set(value) != {"commanderId", "faction", "units", "maxTier"}:
        raise PrivateCloudError("invalid_private_loadout")
    commander_id = value.get("commanderId")
    commander = commanders.get(commander_id) if isinstance(commander_id, str) else None
    rows = value.get("units")
    if (commander is None or value.get("faction") != commander.get("faction")
            or type(value.get("maxTier")) is not int or value["maxTier"] != 10
            or not isinstance(rows, list) or len(rows) != 3):
        raise PrivateCloudError("invalid_private_loadout")
    instances = set()
    for row in rows:
        item_id = row.get("itemId") if isinstance(row, dict) else None
        unit = units.get(item_id) if isinstance(item_id, str) else None
        if (not isinstance(row, dict) or set(row) != {"instanceId", "itemId", "key", "faction", "tier"}
                or unit is None or not _uint64(item_id) or unit.get("faction") != commander.get("faction")
                or not isinstance(row.get("instanceId"), str) or not 1 <= len(row["instanceId"]) <= 128
                or row["instanceId"] in instances or row.get("key") != unit.get("key")
                or row.get("faction") != commander.get("faction")
                or type(row.get("tier")) is not int or row["tier"] != 10):
            raise PrivateCloudError("invalid_private_loadout")
        instances.add(row["instanceId"])
    return copy.deepcopy(value)


def _display_instance(value: str) -> int:
    """Derive a stable native display-only ID from an authoritative Worker ID."""
    return int.from_bytes(hashlib.sha256(value.encode("utf-8")).digest()[:8], "big") or 1


def _display_details(loadout: object, native: dict) -> dict:
    value = _loadout(loadout, native)
    commander_item = int(value["commanderId"])
    commander = next(row for row in native["commanders"]
                     if str(row.get("item_id")) == value["commanderId"])
    commander_instance = _display_instance("commander:" + value["commanderId"])
    records = [[0, commander_item, commander_instance, 1]]
    used = {commander_instance}
    for row in value["units"]:
        instance = _display_instance("unit:" + row["instanceId"])
        if instance in used:
            raise PrivateCloudError("invalid_private_loadout")
        used.add(instance)
        records.append([commander_instance, int(row["itemId"]), instance, 1])
    tiers = sorted((row for row in native.get("commander_tiers", [])
                    if isinstance(row, dict) and row.get("commander") == commander.get("key")),
                   key=lambda row: row.get("tier", 0))
    if ([row.get("tier") for row in tiers] != list(range(1, 11))
            or any(not _uint64(str(row.get("item_id"))) for row in tiers)):
        raise PrivateCloudError("invalid_private_commander_tiers")
    for row in tiers:
        instance = _display_instance("tier:" + value["commanderId"] + ":" + str(row["tier"]))
        if instance in used:
            raise PrivateCloudError("invalid_private_loadout")
        used.add(instance)
        records.append([0, int(row["item_id"]), instance, 1])
    return {"commander_tier": 10, "full_squad_setup": records,
            "new_player": False, "premium": False}


def validate_private_battle(view: object, native: dict) -> dict:
    if not isinstance(view, dict) or view.get("origin") != "private":
        raise PrivateCloudError("invalid_private_battle")
    if any(not isinstance(view.get(key), str) or UUID.fullmatch(view[key]) is None
           for key in ("roomId", "roomMatchId", "battleId")):
        raise PrivateCloudError("invalid_private_battle")
    _room_config(view.get("roomConfig"), "invalid_private_room_config")
    mode, ruleset = view.get("mode"), view.get("ruleset")
    if (mode not in ("pve", "pvp")
            or not _native_map_for_ruleset(view.get("mapKey"), ruleset)):
        raise PrivateCloudError("invalid_private_battle")
    if not all((_typed_equal(view.get("rewardPolicy"), REWARD_POLICY),
                _typed_equal(view.get("economyPolicy"), ECONOMY_POLICY),
                _typed_equal(view.get("battleEntitlement"), ENTITLEMENT))):
        raise PrivateCloudError("invalid_private_policy")
    cpu, rows = view.get("cpuRosterPolicy"), view.get("participants")
    if (not isinstance(cpu, dict) or set(cpu) != {"version", "seed", "aiOpponents", "aiTeam"}
            or type(cpu.get("version")) is not int or cpu["version"] != 1
            or cpu.get("seed") != "private-roster-v1:" + view["roomMatchId"]
            or type(cpu.get("aiOpponents")) is not int or type(cpu.get("aiTeam")) not in (int, type(None))):
        raise PrivateCloudError("invalid_private_cpu_policy")
    if not isinstance(rows, list) or not (1 if mode == "pve" else 2) <= len(rows) <= (10 if mode == "pve" else 20):
        raise PrivateCloudError("invalid_private_participants")
    seen, teams = set(), []
    for index, row in enumerate(rows):
        user_id = row.get("userId") if isinstance(row, dict) else None
        display_name = row.get("displayName") if isinstance(row, dict) else None
        if (not isinstance(row, dict) or type(row.get("seat")) is not int or row["seat"] != index
                or type(row.get("playerId")) is not int or row["playerId"] != index + 1
                or type(row.get("team")) is not int or row["team"] not in (0, 1)
                or not isinstance(user_id, str) or not 1 <= len(user_id) <= 128
                or any(ord(char) < 32 or ord(char) > 126 for char in user_id) or user_id in seen
                or not isinstance(display_name, str) or not 1 <= len(display_name) <= 32
                or any(ord(char) < 32 or 127 <= ord(char) <= 159
                       for char in display_name)):
            raise PrivateCloudError("invalid_private_participants")
        seen.add(user_id); teams.append(row["team"]); _loadout(row.get("loadout"), native)
    counts = [teams.count(0), teams.count(1)]
    valid_pve = mode == "pve" and set(teams) == {0} and 1 <= cpu["aiOpponents"] <= 10 and cpu["aiTeam"] == 1
    valid_pvp = mode == "pvp" and all(1 <= count <= 10 for count in counts) and cpu["aiOpponents"] == 0 and cpu["aiTeam"] is None
    if not (valid_pve or valid_pvp):
        raise PrivateCloudError("invalid_private_team_policy")
    result = copy.deepcopy(view)
    result["participants"] = [{key: copy.deepcopy(row[key]) for key in
                              ("userId", "displayName", "seat", "playerId",
                               "team", "loadout")} for row in rows]
    result["nativeTeams"] = [team + 1 for team in teams]
    result["expectedPlayers"] = len(rows)
    return result


class PrivateAdapterState:
    def __init__(self, native: dict):
        self.native = native
        self.state = "idle"
        self.battle = None

    def freeze_start(self, view):
        frozen = validate_private_battle(view, self.native)
        keys = ("origin", "roomId", "roomMatchId", "battleId", "mode", "ruleset", "mapKey", "roomConfig", "participants",
                "rewardPolicy", "economyPolicy", "battleEntitlement", "cpuRosterPolicy", "nativeTeams", "expectedPlayers")
        manifest = {key: frozen[key] for key in keys}
        if self.battle is not None:
            if self.battle != manifest:
                raise PrivateCloudError("private_battle_conflict")
            return copy.deepcopy(manifest)
        self.battle = manifest
        self.state = "awaiting_roster"
        return copy.deepcopy(manifest)

    def roster_ready(self):
        if self.state != "awaiting_roster":
            raise PrivateCloudError("private_adapter_state")
        self.state = "prepared"

    def returned(self, receipt, current_user):
        last = receipt.get("lastReturn") if isinstance(receipt, dict) else None
        members = receipt.get("members") if isinstance(receipt, dict) else None
        valid = (self.state == "prepared" and isinstance(current_user, str) and isinstance(receipt, dict)
                 and receipt.get("roomId") == self.battle["roomId"]
                 and receipt.get("ownerId") == current_user and receipt.get("status") == "open" and receipt.get("preparedMatch") is None
                 and isinstance(last, dict) and last.get("battleId") == self.battle["battleId"]
                 and last.get("matchId") == self.battle["roomMatchId"] and last.get("returnedBy") == current_user
                 and isinstance(members, list) and members and any(m.get("userId") == current_user for m in members if isinstance(m, dict))
                 and all(isinstance(member, dict) and member.get("ready") is False for member in members))
        if not valid:
            raise PrivateCloudError("invalid_private_return")
        self.state = "idle"
        self.battle = None


class CloudPrivateLobbyAdapter:
    """Synchronous, bounded lobby projection. Battle start is deliberately next-stage."""
    def __init__(self, api: object, native_user_id: str, *, mode: str, ai_opponents: int,
                 native_catalog: dict, sync_loadout: Callable[[], None],
                 cpu_players: Callable[[str, int], list[dict]] | None = None,
                 notifier: Callable[[int, str, str, object], int] | None = None,
                 native_game_source: Callable[[], dict | None] | None = None,
                 start_callback: Callable[[dict, dict], dict] | None = None,
                 return_callback: Callable[[dict, dict], dict] | None = None,
                 return_observed_callback: Callable[[dict], None] | None = None):
        """Project Room APIs into the native lobby protocol.

        Optional callbacks are reserved for the battle lifecycle block.  They
        receive immutable copies of the validated room and current profile;
        this lobby block never fabricates a successful start or return.
        """
        if (mode not in ("pve", "pvp")
                or type(ai_opponents) is not int
                or mode == "pve" and not 1 <= ai_opponents <= 10
                or mode == "pvp" and ai_opponents != 0):
            raise ValueError("invalid private creation defaults")
        self.api, self.user_id, self.mode = api, native_user_id, mode
        self.ai_opponents, self.sync_loadout, self.room_id = ai_opponents, sync_loadout, None
        self._native = native_catalog
        self._cpu_players = cpu_players
        self._notifier = notifier
        self._native_game_source = native_game_source
        self._notification_serial = 0
        self._outbox: list[tuple[int, str, str, object]] = []
        self._snapshot: dict | None = None
        self._lock = threading.RLock()
        self.start_callback, self.return_callback = start_callback, return_callback
        self.return_observed_callback = return_observed_callback
        self._battle = None
        self._restored_prepared_room = None
        self._length = 600

    def _flush_notifications(self) -> None:
        while self._outbox:
            serial, event, game_id, payload = self._outbox[0]
            if self._notifier is None:
                raise NativeLobbyError(503, "private_notifications_unavailable")
            try:
                recipients = self._notifier(serial, event, game_id, copy.deepcopy(payload))
            except CpuNotificationDeliveryUncertain:
                # The stanza may already have reached native. Consuming this
                # exact serial is safer than duplicating a roster mutation.
                self._outbox.pop(0)
                raise NativeLobbyError(503, "private_notification_uncertain") from None
            except Exception:
                # Definite failure: retain the exact serial/payload at head.
                raise NativeLobbyError(503, "private_notification_failed") from None
            if type(recipients) is not int or recipients <= 0:
                raise NativeLobbyError(503, "private_notification_failed")
            self._outbox.pop(0)

    def _queue_snapshot_diff(self, game: dict) -> None:
        previous = self._snapshot
        if previous is None:
            self._snapshot = copy.deepcopy(game)
            return
        before = {row["user_id"]: row for row in previous["players"] if not row["is_ai"]}
        after = {row["user_id"]: row for row in game["players"] if not row["is_ai"]}
        pending = []

        def queue(event: str, payload: object) -> None:
            pending.append((event, copy.deepcopy(payload)))

        for user_id in before.keys() - after.keys():
            queue("human_removed", user_id)
        for user_id in after.keys() - before.keys():
            queue("human_joined", after[user_id])
        for user_id in before.keys() & after.keys():
            old, new = before[user_id], after[user_id]
            if old["team_id"] != new["team_id"]:
                queue("human_removed", user_id)
                queue("human_joined", new)
                continue
            if old["profile_matchmaking_details"] != new["profile_matchmaking_details"]:
                queue("human_loadout", {"user_id": user_id,
                                         "profile_matchmaking_details": new["profile_matchmaking_details"]})
            if old["ready"] is not new["ready"]:
                queue("human_ready", {"user_id": user_id, "ready": new["ready"]})
        if previous["settings"] != game["settings"]:
            queue("settings_changed", game["settings"])
        if len(self._outbox) + len(pending) > MAX_NOTIFICATION_OUTBOX:
            raise NativeLobbyError(503, "private_notification_outbox_full")
        self._snapshot = copy.deepcopy(game)
        for event, payload in pending:
            self._notification_serial += 1
            self._outbox.append((self._notification_serial, event, game["game_id"], payload))

    def _call(self, action):
        try:
            return action()
        except Exception as error:
            status = getattr(error, "status", 503)
            code = str(getattr(error, "code", "worker_unreachable"))
            raise NativeLobbyError(status if type(status) is int else 503, code) from None

    @staticmethod
    def _uncertain_creation_room(error: Exception) -> str | None:
        expected = {(503, "room_creation_uncertain"), (409, "created_room_exists")}
        if (getattr(error, "status", None), getattr(error, "code", None)) not in expected:
            return None
        payload = getattr(error, "payload", None)
        room_id = payload.get("roomId") if isinstance(payload, dict) else None
        return room_id if isinstance(room_id, str) and UUID.fullmatch(room_id) else None

    def _resolved_create(self, create, expected: dict) -> tuple[dict, bool]:
        recovered_room_id = None
        existing_owned_room = False
        try:
            room = create()
        except Exception as error:
            room_id = self._uncertain_creation_room(error)
            if room_id is None:
                raise self._native_error(error) from None
            recovered_room_id = room_id
            existing_owned_room = (getattr(error, "status", None), getattr(error, "code", None)) == (409, "created_room_exists")
            room = self._call(lambda: self.api.get_room(room_id))
        room = self._room(room, recovered_room_id)
        if room.get("ownerId") != self.user_id:
            raise NativeLobbyError(409, "private_room_creation_conflict")
        if existing_owned_room:
            # A known ownership conflict identifies an existing room, not an
            # uncertain execution of this CREATE. Restore its actual settings.
            if room.get("mode") != self.mode or room.get("status") not in ("open", "awaiting_gameplay_adapter"):
                raise NativeLobbyError(409, "private_room_creation_conflict")
            return room, True
        actual = {key: room.get(key) for key in expected}
        if not _typed_equal(actual, expected):
            raise NativeLobbyError(409, "private_room_creation_conflict")
        return room, False

    def _leave(self, room_id: str) -> None:
        try:
            self.api.room_leave(room_id)
            return
        except Exception as error:
            status = getattr(error, "status", None)
            if status is not None and (type(status) is not int or status < 500):
                raise self._native_error(error) from None
            try:
                room = self.api.get_room(room_id)
            except Exception as resolved:
                absence = ((404, "room_not_found"),
                           (403, "room_membership_required"))
                if (getattr(resolved, "status", None),
                        getattr(resolved, "code", None)) in absence:
                    return
                raise self._native_error(error) from None
            if isinstance(room, dict) and room.get("roomId") == room_id:
                members = room.get("members")
                if (isinstance(members, list)
                        and any(isinstance(member, dict) and member.get("userId") == self.user_id
                                for member in members)):
                    raise NativeLobbyError(503, "private_leave_unresolved")
            raise NativeLobbyError(503, "invalid_private_leave_resolution")

    @staticmethod
    def _native_error(error: Exception) -> NativeLobbyError:
        status = getattr(error, "status", 503)
        code = getattr(error, "code", "worker_unreachable")
        return NativeLobbyError(status if type(status) is int else 503,
                                code if isinstance(code, str) else "worker_unreachable")

    def _request(self, raw, content_type, profile):
        request, headers, _form = decode_native_request(raw, content_type)
        identities = [request.get("user_id"), headers.get("user_id")]
        if isinstance(profile, dict) and "user_id" in profile:
            identities.append(profile.get("user_id"))
        if any(value is not None and value != self.user_id for value in identities):
            raise NativeLobbyError(403, "native_private_identity_mismatch")
        return request

    def _room(self, room: object, expected_id: str | None = None) -> dict:
        if not isinstance(room, dict):
            raise NativeLobbyError(503, "invalid_private_room")
        normalized = copy.deepcopy(room)
        ruleset = normalized.get("ruleset")
        if "mapKey" not in normalized:
            try:
                normalized["mapKey"] = _legacy_map_for_ruleset(ruleset)
            except ValueError:
                raise NativeLobbyError(503, "invalid_private_room") from None
        room_id, owner_id, members = normalized.get("roomId"), normalized.get("ownerId"), normalized.get("members")
        maximum = normalized.get("maxPlayers")
        mode = normalized.get("mode")
        config = normalized.get("roomConfig")
        if (not isinstance(room_id, str) or UUID.fullmatch(room_id) is None
                or expected_id is not None and room_id != expected_id
                or not isinstance(owner_id, str) or not owner_id
                or mode not in ("pve", "pvp")
                or type(maximum) is not int
                or not 1 <= maximum <= (10 if mode == "pve" else 20)
                or not _native_map_for_ruleset(normalized.get("mapKey"), ruleset)
                or normalized.get("visibility") not in ("listed", "unlisted")
                or not isinstance(config, dict) or set(config) != {"title", "length"}
                or not isinstance(config.get("title"), str) or not 1 <= len(config["title"]) <= 80
                or config["title"] != config["title"].strip()
                or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in config["title"])
                or type(config.get("length")) is not int or not 1 <= config["length"] <= 7200
                or not isinstance(members, list) or not 1 <= len(members) <= maximum):
            raise NativeLobbyError(503, "invalid_private_room")
        found = False
        member_ids = set()
        for member in members:
            if not isinstance(member, dict):
                raise NativeLobbyError(503, "invalid_private_room")
            user_id = member.get("userId")
            if not isinstance(user_id, str) or not user_id or user_id in member_ids:
                raise NativeLobbyError(503, "invalid_private_room")
            team = member.get("team")
            if (type(team) is not int or team not in (0, 1)
                    or mode == "pve" and team != 0):
                raise NativeLobbyError(503, "invalid_private_room")
            member_ids.add(user_id)
            if user_id == self.user_id:
                found = True
        if owner_id not in member_ids:
            raise NativeLobbyError(503, "invalid_private_room")
        if not found:
            raise NativeLobbyError(403, "native_private_membership_mismatch")
        ai_opponents = normalized.get("aiOpponents")
        if (type(ai_opponents) is not int
                or mode == "pve" and not 1 <= ai_opponents <= 10
                or mode == "pvp" and ai_opponents != 0):
            raise NativeLobbyError(503, "invalid_private_room")
        return normalized

    def _game(self, room: dict, *, recovering_prepared: bool = False) -> dict:
        room = self._room(room)
        room_id = room["roomId"]
        ruleset = room.get("ruleset")
        if not _native_map_for_ruleset(room.get("mapKey"), ruleset):
            raise NativeLobbyError(503, "invalid_private_room")
        players = []
        for member in room["members"]:
            try:
                details = _display_details(member.get("loadout"), self._native)
            except PrivateCloudError as error:
                raise NativeLobbyError(503, str(error)) from None
            team, ready = member.get("team"), member.get("ready")
            if (type(team) is not int or team not in (0, 1) or type(ready) is not bool
                    or not isinstance(member.get("userId"), str)
                    or not isinstance(member.get("displayName"), str)):
                raise NativeLobbyError(503, "invalid_private_room")
            # The immutable prior battle's readiness does not arm this fresh
            # frontend. Keep only this recovering client's local UI unready.
            if (member["userId"] == self.user_id and room.get("status") == "awaiting_gameplay_adapter"
                    and (recovering_prepared or self._restored_prepared_room == room_id)):
                ready = False
            players.append({"user_id": member["userId"], "display_name": member["displayName"],
                            "team_id": team + 1, "ready": ready, "online_status": "online",
                            "is_ai": False, "profile_matchmaking_details": details})
        ai_opponents = room.get("aiOpponents")
        if ai_opponents:
            if room["mode"] != "pve" or self._cpu_players is None:
                raise NativeLobbyError(503, "private_cpu_projection_unavailable")
            try:
                cpu_rows = self._cpu_players(room_id, ai_opponents)
            except Exception:
                raise NativeLobbyError(503, "invalid_private_cpu_projection") from None
            if (not isinstance(cpu_rows, list) or len(cpu_rows) != ai_opponents
                    or any(not isinstance(row, dict)
                           or set(row) != {"user_id", "display_name", "team_id", "ready",
                                          "online_status", "is_ai", "profile_matchmaking_details"}
                           or row.get("is_ai") is not True or row.get("ready") is not True
                           or row.get("online_status") != "online" or row.get("team_id") != 2
                           or not isinstance(row.get("user_id"), str) or not row["user_id"]
                           or not isinstance(row.get("display_name"), str) or not row["display_name"]
                           for row in cpu_rows)):
                raise NativeLobbyError(503, "invalid_private_cpu_projection")
            try:
                for row in cpu_rows:
                    _loadout_json(row["profile_matchmaking_details"])
            except ValueError:
                raise NativeLobbyError(503, "invalid_private_cpu_projection") from None
            identities = [row["user_id"] for row in players + cpu_rows]
            if len(identities) != len(set(identities)):
                raise NativeLobbyError(503, "invalid_private_cpu_projection")
            players.extend(copy.deepcopy(cpu_rows))
        return {"game_id": room_id, "owner_id": room["ownerId"],
                "settings": {"title": room["roomConfig"]["title"],
                             "map": room["mapKey"],
                             "length": room["roomConfig"]["length"],
                             "max_players": room["maxPlayers"] + ai_opponents,
                             "privacy": room.get("visibility") != "listed"},
                "battle_key": "", "maps": _native_map_keys(),
                "teams": [{"team_id": 1, "team_name": "Team 1"}, {"team_id": 2, "team_name": "Team 2"}],
                "players": players}

    @staticmethod
    def _summary_game(row: object) -> dict:
        if isinstance(row, dict):
            row = copy.deepcopy(row)
            ruleset = row.get("ruleset")
            if "mapKey" not in row:
                try:
                    row["mapKey"] = _legacy_map_for_ruleset(ruleset)
                except ValueError:
                    raise NativeLobbyError(503, "invalid_private_room_directory") from None
        if not isinstance(row, dict) or not isinstance(row.get("roomId"), str) \
                or UUID.fullmatch(row["roomId"]) is None \
                or not isinstance(row.get("ownerDisplayName"), str) \
                or not 1 <= len(row["ownerDisplayName"]) <= 32 \
                or row.get("mode") not in ("pve", "pvp") \
                or not _native_map_for_ruleset(row.get("mapKey"), row.get("ruleset")) \
                or type(row.get("members")) is not int or row["members"] < 1 \
                or type(row.get("maxPlayers")) is not int \
                or not 1 <= row["maxPlayers"] <= (10 if row["mode"] == "pve" else 20) \
                or row["members"] > row["maxPlayers"] \
                or type(row.get("aiOpponents")) is not int \
                or not 0 <= row["aiOpponents"] <= (10 if row["mode"] == "pve" else 0) \
                or type(row.get("expiresAt")) is not int or row["expiresAt"] <= 0:
            raise NativeLobbyError(503, "invalid_private_room_directory")
        config = row.get("roomConfig")
        if (not isinstance(config, dict) or set(config) != {"title", "length"}
                or not isinstance(config.get("title"), str) or not config["title"]
                or type(config.get("length")) is not int or not 1 <= config["length"] <= 7200):
            raise NativeLobbyError(503, "invalid_private_room_directory")
        return {"game_id": row["roomId"], "owner_id": "directory:" + row["roomId"],
                "settings": {"title": config["title"],
                             "map": row["mapKey"],
                             "length": config["length"],
                             "max_players": row["maxPlayers"] + row["aiOpponents"],
                             "privacy": False},
                "battle_key": "", "maps": _native_map_keys(),
                "players": [], "teams": [{"team_id": 1, "team_name": "Team 1"},
                                          {"team_id": 2, "team_name": "Team 2"}]}

    def refresh_notifications(self, profile: dict | None = None) -> int:
        """Bounded poll hook for a coordinator-owned background refresh tick.

        One invocation performs one authenticated Room GET, commits its
        validated snapshot diff, then drains the serial outbox in order.
        """
        with self._lock:
            self._flush_notifications()
            if self.room_id is None:
                return self._notification_serial
            room = self._room(self._call(lambda: self.api.get_room(self.room_id)), self.room_id)
            self._observe_completed_return(room)
            self._queue_snapshot_diff(self._game(room))
            self._flush_notifications()
            if (room.get("status") == "awaiting_gameplay_adapter" and isinstance(profile, dict)
                    and self._restored_prepared_room != room["roomId"]):
                try:
                    self._start(profile, room=room)
                except NativeLobbyError as error:
                    if error.code != "native_private_roster_pending":
                        raise
            return self._notification_serial

    def _observe_completed_return(self, room: dict) -> bool:
        """Clear a member's stale battle after the owner's validated return.

        Members never call the owner-only return mutation.  The exact
        ``lastReturn`` identity in an authenticated full Room snapshot is the
        only observation that clears their frozen battle locally.
        """
        if self._battle is None:
            return False
        last = room.get("lastReturn")
        if (isinstance(last, dict)
                and set(last) == {"battleId", "matchId", "returnedBy"}
                and last.get("battleId") == self._battle.get("battleId")
                and last.get("matchId") == self._battle.get("roomMatchId")
                and isinstance(last.get("returnedBy"), str)):
            self._notify_return_observed({
                "roomId": room["roomId"],
                "battleId": last["battleId"],
                "matchId": last["matchId"],
                "returnedBy": last["returnedBy"],
                "terminal": False,
            })
            self._battle = None
            return True
        return False

    def _notify_return_observed(self, receipt: dict) -> None:
        if self.return_observed_callback is None:
            return
        try:
            self.return_observed_callback(copy.deepcopy(receipt))
        except Exception:
            raise NativeLobbyError(503, "private_return_observation_failed") from None

    def is_current_return_owner(self, battle: dict) -> bool:
        """Authenticate current operational ownership from a live Room read.

        The dedicated Worker operation is state-preserving and covers both a
        live transferred owner and terminal cleanup after Room lease expiry.
        The immutable battle creator is never substituted for current owner.
        """
        with self._lock:
            if self._battle is None:
                return False
            try:
                candidate = validate_private_battle(battle, self._native)
            except PrivateCloudError:
                return False
            identity_keys = (
                "origin", "roomId", "roomMatchId", "battleId", "mode",
                "ruleset", "mapKey", "roomConfig", "participants",
                "rewardPolicy", "economyPolicy", "battleEntitlement",
                "cpuRosterPolicy",
            )
            if (candidate.get("roomId") != self.room_id
                    or any(not _typed_equal(candidate.get(key),
                                            self._battle.get(key))
                           for key in identity_keys)
                    or any(not _typed_equal(battle.get(key),
                                            self._battle.get(key))
                           for key in ("createdBy", "expiresAt"))):
                return False
            try:
                receipt = self._call(lambda: self.api.room_return_eligibility(
                    battle["roomId"], battle["battleId"]
                ))
            except NativeLobbyError:
                return False
            expected = {"roomId": battle["roomId"],
                        "battleId": battle["battleId"],
                        "matchId": battle["roomMatchId"],
                        "status": "returnable", "owner": True}
            return _typed_equal(receipt, expected)

    def _start(self, profile: dict, *, room: dict | None = None) -> dict:
        if self.room_id is not None and self._restored_prepared_room == self.room_id:
            raise NativeLobbyError(409, "native_private_resume_unavailable")
        if self.room_id is None or self.start_callback is None:
            raise NativeLobbyError(409, "native_private_cloud_start_pending")
        self.sync_loadout()
        if room is None:
            room = self._room(self._call(lambda: self.api.get_room(self.room_id)), self.room_id)
        if room.get("status") == "open":
            room = self._room(self._call(lambda: self.api.room_prepare(self.room_id)), self.room_id)
        if room.get("status") != "awaiting_gameplay_adapter":
            raise NativeLobbyError(409, "private_room_not_prepared")
        prepared = room.get("preparedMatch")
        if (not isinstance(prepared, dict)
                or prepared.get("roomConfig") != room.get("roomConfig")):
            raise NativeLobbyError(503, "invalid_private_prepared_match")
        view = self._call(lambda: self.api.room_start(self.room_id))
        try:
            battle = validate_private_battle(view, self._native)
        except PrivateCloudError as error:
            raise NativeLobbyError(503, str(error)) from None
        if (battle["roomId"] != self.room_id
                or battle["roomConfig"] != room["roomConfig"]
                or battle["roomMatchId"] != prepared.get("matchId")
                or battle["mode"] != room["mode"]
                or battle["ruleset"] != room["ruleset"]
                or battle["mapKey"] != room["mapKey"]):
            raise NativeLobbyError(409, "private_battle_manifest_mismatch")
        prepared_members = prepared.get("members")
        if not isinstance(prepared_members, list) or len(prepared_members) != len(battle["participants"]):
            raise NativeLobbyError(409, "private_battle_manifest_mismatch")
        for index, (member, participant) in enumerate(zip(prepared_members, battle["participants"])):
            if (not isinstance(member, dict)
                    or participant["seat"] != index
                    or participant["playerId"] != index + 1
                    or member.get("userId") != participant["userId"]
                    or type(member.get("team")) is not int
                    or member["team"] != participant["team"]
                    or not _typed_equal(member.get("loadout"), participant["loadout"])):
                raise NativeLobbyError(409, "private_battle_manifest_mismatch")
        try:
            result = self.start_callback(copy.deepcopy(battle), copy.deepcopy(profile))
        except PrivateBattleTransportError as error:
            raise NativeLobbyError(error.status or 503, error.code) from None
        except Exception:
            raise NativeLobbyError(503, "private_coordinator_failed") from None
        expected = {"status", "roomId", "roomMatchId", "battleId", "idempotent"}
        if (not isinstance(result, dict) or set(result) != expected
                or result.get("status") not in ("awaiting_roster", "prepared")
                or type(result.get("idempotent")) is not bool
                or result.get("roomId") != battle["roomId"]
                or result.get("roomMatchId") != battle["roomMatchId"]
                or result.get("battleId") != battle["battleId"]):
            raise NativeLobbyError(503, "invalid_private_coordinator_result")
        # Both statuses acknowledge this exact start and a confirmed local
        # squad upload. Roster completion and native starting notifications
        # remain asynchronous; a normal wait must not show Custom Battle Error.
        self._battle = copy.deepcopy(battle)
        return ca_envelope({"result": "ok"}, time.time_ns() // 1_000_000)

    def arbitrate_native(self, path: str, request: dict, headers: dict, state) -> dict | None:
        """Route one prepared private CASA request without entering a public queue.

        Only this adapter's frozen room is owned. A public request falls through;
        the owned private request never falls back on missing preparation/identity.
        All participants remain frozen roster metadata; enrollment is local only.
        """
        with self._lock:
            if (path not in ('/enroll', '/check') or self._battle is None
                    or request.get('battle_id') != self.room_id):
                return None
            if set(request) != ARBITRATION_FIELDS:
                raise NativeLobbyError(400, 'invalid_arbitration_fields')
            if (headers.get('user_id') != self.user_id
                    or request.get('user_id') != self.user_id):
                raise NativeLobbyError(403, 'native_user_mismatch')
            game = self._prepared_native_game()
            if request.get('battle_key') != game['battle_key']:
                raise NativeLobbyError(409, 'arbitration_key_mismatch')
            if state is None:
                raise NativeLobbyError(503, 'private_arbitration_unavailable')
            battle_id = self._battle['battleId']
            population = []
            by_user = {row['user_id']: row for row in game['players']}
            for participant in self._battle['participants']:
                row = by_user[participant['userId']]
                population.append({'user_id': participant['userId'],
                    'seat': participant['seat'], 'team': participant['team'],
                    'player_id': participant['playerId'],
                    'details': copy.deepcopy(row['profile_matchmaking_details'])})
            for row in game['players']:
                if row['is_ai']:
                    population.append({'user_id': row['user_id'], 'team': row['team_id'] - 1,
                        'is_ai': True, 'details': copy.deepcopy(row['profile_matchmaking_details'])})
            roster_digest = hashlib.sha256(json.dumps(
                population, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            expected_context = {
                'mode': 'private', 'private': True,
                'party_id': self.room_id, 'room_game_id': self.room_id,
                'room_match_id': self._battle['roomMatchId'],
                'cloud_battle_id': battle_id, 'battle_instance_id': battle_id,
                'created_by': self._battle['createdBy'], 'map': self._battle['mapKey'],
                'room_config': self._battle['roomConfig'],
                'cpu_roster_policy': self._battle['cpuRosterPolicy'],
                'relay_authenticated_humans': len(self._battle['participants']),
                'native_expected_players': len(population), 'roster_digest': roster_digest,
                'result_participants': [{'user_id': row['user_id'], 'party_id': '',
                    'is_ai': row.get('is_ai') is True} for row in population],
                'full_squad_setup': by_user[self.user_id]['profile_matchmaking_details']['full_squad_setup'],
                'reward_policy': 'none', 'reward_multiplier': 0,
            }
            try:
                if state.resolve_wire_battle_id(self.room_id) != battle_id:
                    raise BattleStateError('battle_alias_mismatch')
                snapshot = state.snapshot(battle_id)
                context = snapshot.get('context')
                if (snapshot.get('user_ids') != [self.user_id]
                        or snapshot.get('expected_players') != len(population)
                        or not isinstance(context, dict)
                        or any(not _typed_equal(context.get(key), value)
                               for key, value in expected_context.items())):
                    raise BattleStateError('battle_roster_mismatch')
                state.validate_relay_join(battle_id, request['battle_key'], self.user_id, len(population))
                snapshot, _ = state.enroll(battle_id, self.user_id)
                if snapshot.get('enrolled_user_ids') != [self.user_id]:
                    raise BattleStateError('battle_not_enrolled')
            except BattleStateError as error:
                raise NativeLobbyError(409, 'battle_state_' + error.code) from None
            payload = {'result': 'ok'} if path == '/enroll' else {'all_users_ready': True}
            return ca_envelope(payload, time.time_ns() // 1_000_000)

    def _prepared_native_game(self) -> dict:
        if self._battle is None or self._native_game_source is None:
            raise NativeLobbyError(409, "native_private_battle_not_prepared")
        try:
            game = self._native_game_source()
        except Exception:
            raise NativeLobbyError(503, "private_native_game_unavailable") from None
        if not isinstance(game, dict):
            raise NativeLobbyError(409, "native_private_battle_not_prepared")
        required = {"game_id", "owner_id", "settings", "battle_key", "relay_server",
                    "maps", "teams", "players"}
        if (set(game) != required or game.get("game_id") != self._battle["roomId"]
                or not isinstance(self._battle.get("createdBy"), str)
                or game.get("owner_id") != self._battle["createdBy"]):
            raise NativeLobbyError(503, "invalid_private_native_game")
        key = game.get("battle_key")
        if (not isinstance(key, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", key)
                or int(key) >= 1 << 64 or game.get("relay_server") != "127.0.0.1:19000"):
            raise NativeLobbyError(503, "invalid_private_native_game")
        config, cpu = self._battle["roomConfig"], self._battle["cpuRosterPolicy"]
        expected_settings = {"title": config["title"], "map": self._battle["mapKey"],
                             "length": config["length"],
                             "max_players": len(self._battle["participants"]) + cpu["aiOpponents"],
                             "privacy": True}
        if (not _typed_equal(game.get("settings"), expected_settings)
                or game.get("maps") != [self._battle["mapKey"]]
                or game.get("teams") != [{"team_id": 1, "team_name": "Team 1"},
                                          {"team_id": 2, "team_name": "Team 2"}]):
            raise NativeLobbyError(503, "invalid_private_native_game")
        players = game.get("players")
        if not isinstance(players, list) or len(players) != expected_settings["max_players"]:
            raise NativeLobbyError(503, "invalid_private_native_game")
        player_keys = {"user_id", "display_name", "online_status", "team_id", "ready",
                       "is_ai", "profile_matchmaking_details"}
        if any(not isinstance(row, dict) or set(row) != player_keys
               or not isinstance(row.get("user_id"), str) or not row["user_id"]
               or not isinstance(row.get("display_name"), str) or not row["display_name"]
               for row in players):
            raise NativeLobbyError(503, "invalid_private_native_game")
        humans = [row for row in players if isinstance(row, dict) and row.get("is_ai") is False]
        cpus = [row for row in players if isinstance(row, dict) and row.get("is_ai") is True]
        if len(humans) != len(self._battle["participants"]) or len(cpus) != cpu["aiOpponents"]:
            raise NativeLobbyError(503, "invalid_private_native_game")
        matchmaking = NativeMatchmaking(self._native)
        by_user = {row.get("user_id"): row for row in humans}
        if len(by_user) != len(humans):
            raise NativeLobbyError(503, "invalid_private_native_game")
        for participant in self._battle["participants"]:
            row = by_user.get(participant["userId"])
            try:
                details = row["profile_matchmaking_details"]
                matchmaking.pvp_opponent_details(details["full_squad_setup"])
                identity = matchmaking.pvp_rows_cloud_loadout(details["full_squad_setup"])
            except Exception:
                raise NativeLobbyError(503, "invalid_private_native_game") from None
            expected_identity = {"commander_id": participant["loadout"]["commanderId"],
                                 "item_ids": [unit["itemId"] for unit in participant["loadout"]["units"]]}
            if (row.get("team_id") != participant["team"] + 1
                    or row.get("online_status") != "online" or row.get("ready") is not True
                    or not _typed_equal(identity, expected_identity)):
                raise NativeLobbyError(503, "invalid_private_native_game")
        identities = [row["user_id"] for row in players]
        if len(identities) != len(set(identities)):
            raise NativeLobbyError(503, "invalid_private_native_game")
        for row in cpus:
            try:
                matchmaking.pvp_opponent_details(
                    row["profile_matchmaking_details"]["full_squad_setup"])
            except Exception:
                raise NativeLobbyError(503, "invalid_private_native_game") from None
            if (row.get("team_id") != cpu["aiTeam"] + 1
                    or row.get("online_status") != "online" or row.get("ready") is not True):
                raise NativeLobbyError(503, "invalid_private_native_game")
        return copy.deepcopy(game)

    def return_battle(self, battle_id: str, profile: dict) -> dict:
        """Authorize locally, POST exactly one Worker return, then clear/freeze state."""
        with self._lock:
            if (self.return_callback is None or self._battle is None
                    or battle_id != self._battle.get("battleId")):
                raise NativeLobbyError(409, "private_battle_return_not_authorized")
            try:
                authorization = self.return_callback(copy.deepcopy(self._battle),
                                                     copy.deepcopy(profile))
            except Exception as error:
                code = getattr(error, "code", None)
                if not isinstance(code, str):
                    code = "private_return_authorization_failed"
                pending = {
                    "private_worker_battle_not_returnable",
                    "private_worker_settlement_missing",
                    "private_result_not_delivered",
                    "private_local_settlement_missing",
                    "private_result_not_durable",
                    "private_return_owner_unconfirmed",
                }
                status = 409 if code in pending else 503
                raise NativeLobbyError(status, code) from None
            expected = {"battleId": battle_id,
                        "roomMatchId": self._battle["roomMatchId"],
                        "status": "return_authorized"}
            if not _typed_equal(authorization, expected):
                raise NativeLobbyError(503, "invalid_private_return_authorization")
            receipt = self._call(lambda: self.api.room_return(self._battle["roomId"], battle_id))
            terminal = {"roomId": self._battle["roomId"], "terminal": True,
                        "status": "expired", "battleId": battle_id,
                        "matchId": self._battle["roomMatchId"], "cleaned": True}
            if _typed_equal(receipt, terminal):
                self._notify_return_observed(copy.deepcopy(terminal))
                self.room_id = None
                self._snapshot = None
            else:
                room = self._room(receipt, self._battle["roomId"])
                last = room.get("lastReturn")
                if (room.get("status") != "open" or room.get("preparedMatch") is not None
                        or room.get("ownerId") != self.user_id
                        or not isinstance(last, dict)
                        or last.get("battleId") != battle_id
                        or last.get("matchId") != self._battle["roomMatchId"]
                        or last.get("returnedBy") != self.user_id
                        or any(member.get("ready") is not False for member in room["members"])):
                    raise NativeLobbyError(503, "invalid_private_return_receipt")
                self._notify_return_observed({
                    "roomId": room["roomId"], "battleId": battle_id,
                    "matchId": last["matchId"], "returnedBy": last["returnedBy"],
                    "terminal": False,
                })
                self._snapshot = copy.deepcopy(self._game(room))
            self._battle = None
            self._outbox.clear()
            return copy.deepcopy(receipt)

    def release_expired_battle(self, receipt: dict) -> dict:
        """Clear one locally expired lease after the relay closes successfully."""
        with self._lock:
            battle = self._battle
            def nonempty_string(value):
                return isinstance(value, str) and bool(value)

            expected = (isinstance(battle, dict)
                    and nonempty_string(self.room_id)
                    and nonempty_string(battle.get("roomId"))
                    and nonempty_string(battle.get("battleId"))
                    and nonempty_string(battle.get("roomMatchId"))
                    and self.room_id == battle.get("roomId")
                    and isinstance(receipt, dict)
                    and set(receipt) == {"roomId", "battleId", "roomMatchId", "status"}
                    and receipt.get("status") == "local_expired_release"
                    and all(nonempty_string(receipt.get(key)) for key in
                            ("roomId", "battleId", "roomMatchId"))
                    and receipt.get("roomId") == battle.get("roomId")
                    and receipt.get("battleId") == battle.get("battleId")
                    and receipt.get("roomMatchId") == battle.get("roomMatchId"))
            if not expected:
                raise NativeLobbyError(409, "private_expired_release_mismatch")
            if self.return_observed_callback is None:
                raise NativeLobbyError(503, "private_return_observation_unavailable")
            self._notify_return_observed({
                "roomId": battle["roomId"], "battleId": battle["battleId"],
                "matchId": battle["roomMatchId"], "terminal": True,
            })
            self.room_id = None
            self._snapshot = None
            self._battle = None
            self._outbox.clear()
            return copy.deepcopy(receipt)

    def handle_native(self, path, raw, content_type, profile, *, method="POST"):
        with self._lock:
            return self._handle_native(path, raw, content_type, profile, method=method)

    def _handle_native(self, path, raw, content_type, profile, *, method="POST"):
        if path not in {"/create", "/get_games", "/join", "/ready", "/unready", "/leave",
                        "/change_team", "/change_squad", "/change_game_settings", "/battle_check", "/start_game"}:
            return None
        if method != "POST":
            raise NativeLobbyError(405, "method_not_allowed")
        request = self._request(raw, content_type, profile)
        # Never let a later Worker mutation overtake a previously committed
        # native notification. Failed deliveries remain at the outbox head.
        self._flush_notifications()
        if path == "/get_games":
            rows, cursor, seen = [], None, set()
            for _page in range(100):
                listing = self._call(lambda cursor=cursor: self.api.list_rooms(limit=50, cursor=cursor))
                page = listing.get("rooms") if isinstance(listing, dict) else None
                next_cursor = listing.get("nextCursor") if isinstance(listing, dict) else None
                if not isinstance(page, list) or next_cursor is not None and not isinstance(next_cursor, str):
                    raise NativeLobbyError(503, "invalid_private_room_directory")
                rows.extend(page)
                if next_cursor is None:
                    break
                if not next_cursor or next_cursor in seen:
                    raise NativeLobbyError(503, "invalid_private_room_directory")
                seen.add(next_cursor)
                cursor = next_cursor
            else:
                raise NativeLobbyError(503, "private_room_directory_too_large")
            games = [self._summary_game(row) for row in rows]
            return ca_envelope({"result": games}, time.time_ns() // 1_000_000)
        if path == "/create":
            ruleset = next((candidate for candidate in _NATIVE_RULESETS
                            if _native_map_for_ruleset(request.get("map"), candidate)), None)
            private = request.get("private")
            maximum = request.get("max_players")
            if isinstance(maximum, str) and maximum.isascii() and maximum.isdecimal():
                maximum = int(maximum)
            valid_private = type(private) is bool or isinstance(private, str) and private in ("true", "false")
            if (ruleset is None or type(maximum) is not int or not 1 <= maximum <= 20
                    or not valid_private):
                raise NativeLobbyError(400, "invalid_private_create")
            human_capacity = maximum - self.ai_opponents if self.mode == "pve" else maximum
            if not 1 <= human_capacity <= (10 if self.mode == "pve" else 20):
                raise NativeLobbyError(400, "invalid_private_create")
            length = request.get("length", 600)
            if type(length) is not int or not 1 <= length <= 7200:
                raise NativeLobbyError(400, "invalid_private_create")
            visibility = "unlisted" if private is True or private == "true" else "listed"
            self.sync_loadout()
            title = request.get("title")
            if (not isinstance(title, str) or title != title.strip() or not 1 <= len(title) <= 80
                    or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in title)):
                raise NativeLobbyError(400, "invalid_private_create")
            room_config = {"title": title, "length": length}
            expected = {"mode": self.mode, "ruleset": ruleset,
                        "maxPlayers": human_capacity, "aiOpponents": self.ai_opponents,
                        "visibility": visibility, "mapKey": request["map"],
                        "roomConfig": room_config}
            room, restored = self._resolved_create(
                lambda: self.api.create_room(self.mode, ruleset, human_capacity,
                                             self.ai_opponents, visibility, room_config,
                                             request["map"]),
                expected)
            recovery_room = (room["roomId"] if restored
                and room.get("status") == "awaiting_gameplay_adapter" else None)
            game = self._game(room, recovering_prepared=recovery_room is not None)
            self.room_id = room["roomId"]
            self._restored_prepared_room = recovery_room
            self._length = room["roomConfig"]["length"]
            self._snapshot = copy.deepcopy(game)
            return ca_envelope({"result": game}, time.time_ns() // 1_000_000)
        room_id = request.get("game_id")
        if not isinstance(room_id, str) or UUID.fullmatch(room_id) is None:
            raise NativeLobbyError(400, "invalid_game_id")
        if path != "/join" and self.room_id != room_id:
            raise NativeLobbyError(404, "room_not_found")
        if path == "/start_game":
            return self._start(profile)
        if path == "/battle_check" and self._battle is not None:
            return ca_envelope(self._prepared_native_game(), time.time_ns() // 1_000_000)
        if path == "/join":
            self.sync_loadout()
            room = self._room(self._call(lambda: self.api.room_join(room_id)), room_id)
            self.room_id = room_id
        elif path == "/leave":
            self._leave(room_id)
            self.room_id = None
            self._restored_prepared_room = None
            self._snapshot = None
            self._outbox.clear()
            return ca_envelope({"result": "ok"}, time.time_ns() // 1_000_000)
        elif path in ("/ready", "/unready"):
            if self._restored_prepared_room == room_id:
                # Stock's Unready/Leave control first asks to cancel readiness.
                # Validate live membership, acknowledge local cancellation only;
                # the old prepared room/battle and peer stay immutable.
                room = self._room(self._call(lambda: self.api.get_room(room_id)), room_id)
                if path == "/ready" or room.get("status") != "awaiting_gameplay_adapter":
                    raise NativeLobbyError(409, "native_private_resume_unavailable")
            else:
                self.sync_loadout()
                room = self._call(lambda: self.api.room_ready(room_id, path == "/ready"))
        elif path == "/change_team":
            native_team = request.get("team_id", request.get("team"))
            if type(native_team) is not int or native_team not in (1, 2):
                raise NativeLobbyError(400, "invalid_team")
            room = self._call(lambda: self.api.room_team(room_id, native_team - 1))
        elif path == "/change_squad":
            self.sync_loadout()
            room = self._call(lambda: self.api.get_room(room_id))
        elif path == "/change_game_settings":
            settings = request.get("settings")
            if (not isinstance(settings, dict) or not settings
                    or set(settings) - {"title", "map", "length", "max_players", "privacy"}):
                raise NativeLobbyError(400, "invalid_lobby_settings")
            current = self._room(self._call(lambda: self.api.get_room(room_id)), room_id)
            if current["ownerId"] != self.user_id:
                raise NativeLobbyError(403, "room_owner_required")
            patch = {}
            if "map" in settings:
                ruleset = next((candidate for candidate in _NATIVE_RULESETS
                                if _native_map_for_ruleset(settings["map"], candidate)), None)
                if ruleset is None:
                    raise NativeLobbyError(400, "invalid_lobby_map")
                patch.update(mapKey=settings["map"], ruleset=ruleset)
            if "length" in settings:
                length = settings["length"]
                if type(length) is not int or not 1 <= length <= 7200:
                    raise NativeLobbyError(400, "invalid_lobby_length")
                patch["roomConfig"] = {**current["roomConfig"], "length": length}
            if "title" in settings:
                title = settings["title"]
                if (not isinstance(title, str) or title != title.strip() or not 1 <= len(title) <= 80
                        or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in title)):
                    raise NativeLobbyError(400, "invalid_lobby_title")
                patch["roomConfig"] = {**patch.get("roomConfig", current["roomConfig"]), "title": title}
            if "max_players" in settings:
                maximum = settings["max_players"]
                if type(maximum) is not int or not 2 <= maximum <= 20:
                    raise NativeLobbyError(400, "invalid_lobby_capacity")
                patch["maxPlayers"] = maximum - current["aiOpponents"]
            if "privacy" in settings:
                privacy = settings["privacy"]
                if type(privacy) is bool:
                    patch["visibility"] = "unlisted" if privacy else "listed"
                elif isinstance(privacy, str) and privacy in ("public", "private", "invite_only"):
                    patch["visibility"] = "listed" if privacy == "public" else "unlisted"
                else:
                    raise NativeLobbyError(400, "invalid_lobby_privacy")
            room = self._room(self._call(lambda: self.api.room_settings(room_id, patch)), room_id)
            if any(not _typed_equal(room.get(key), value) for key, value in patch.items()):
                raise NativeLobbyError(503, "private_room_settings_mismatch")
        else:
            room = self._call(lambda: self.api.get_room(room_id))
        room = self._room(room, room_id)
        game = self._game(room)
        self._queue_snapshot_diff(game)
        self._flush_notifications()
        if path in ("/ready", "/unready", "/change_team", "/change_squad", "/change_game_settings"):
            payload = {"result": "ok"}
        elif path == "/battle_check":
            payload = game
        else:
            payload = {"result": game}
        return ca_envelope(payload, time.time_ns() // 1_000_000)
