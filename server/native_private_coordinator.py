"""Fail-closed private Worker-to-native roster coordination core."""
from __future__ import annotations

import copy
import threading
from dataclasses import dataclass
from typing import Callable

from native_private_cloud import PrivateCloudError, validate_private_battle
from native_matchmaking import EFFECTIVE_UNIT_TIER
from native_pvp_coordinator import (
    RelayTicketSource, derive_relay_ws_url, validate_relay_ticket,
)


_MANIFEST_KEYS = (
    "origin", "roomId", "roomMatchId", "battleId", "mode", "ruleset",
    "mapKey", "roomConfig", "participants", "rewardPolicy", "economyPolicy",
    "battleEntitlement", "cpuRosterPolicy", "nativeTeams", "expectedPlayers",
    "expiresAt", "createdBy",
)


class PrivateCoordinatorError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class PreparedPrivateBattle:
    battle_id: str
    room_id: str
    room_match_id: str
    mode: str
    ruleset: str
    map_key: str
    seat: int
    team: int
    player_id: int
    user_ids: tuple[str, ...]
    cpu_seats_by_team: tuple[int, int]
    battle_key_hex: str
    relay_url: str
    reward_policy: dict
    economy_policy: dict
    battle_entitlement: dict
    room_config: dict
    cpu_roster_policy: dict
    expires_at: int | None
    local_commander_key: str
    local_commander_tier: int
    local_unit_tiers: tuple[int, int, int]
    created_by: str
    display_names: tuple[str, ...]


def _typed_equal(left: object, right: object) -> bool:
    """JSON equality that does not treat True as integer 1."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            _typed_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _typed_equal(a, b) for a, b in zip(left, right)
        )
    return left == right


class PrivateBattleCoordinator:
    """Upload one trusted local squad and validate the complete Worker roster.

    ``api`` supplies synchronous ``put_squad`` and ``get_roster`` methods.
    Errors are consumed through stable ``status`` and ``code`` attributes so
    both the existing PvP wrapper and the base companion API can be adapted.
    """

    def __init__(self, api, native_user_id: str, matchmaking, *,
                 api_base_url: str | None = None,
                 on_prepared: Callable[[PreparedPrivateBattle, RelayTicketSource,
                                        list[dict]], None] | None = None) -> None:
        if not isinstance(native_user_id, str) or not native_user_id:
            raise ValueError("native_user_id required")
        self.api = api
        self.user_id = native_user_id
        self.matchmaking = matchmaking
        self.api_base_url = api_base_url
        self.on_prepared = on_prepared
        self.state = "idle"
        self.manifest = None
        self.local_rows = None
        self.frozen_rows = None
        self.prepared = None
        self.ticket_source = None
        self._native_game = None
        self._lock = threading.RLock()

    def _result(self, idempotent: bool = False) -> dict:
        return {
            "status": self.state,
            "roomId": self.manifest["roomId"],
            "roomMatchId": self.manifest["roomMatchId"],
            "battleId": self.manifest["battleId"],
            "idempotent": idempotent,
        }

    @staticmethod
    def _identity(participant: dict) -> dict:
        return {
            "commander_id": participant["loadout"]["commanderId"],
            "item_ids": [row["itemId"] for row in participant["loadout"]["units"]],
        }

    @staticmethod
    def _room_config(value: object) -> dict:
        if (not isinstance(value, dict) or set(value) != {"title", "length"}
                or not isinstance(value.get("title"), str)
                or not 1 <= len(value["title"]) <= 80
                or value["title"] != value["title"].strip()
                or type(value.get("length")) is not int
                or not 1 <= value["length"] <= 7200):
            raise PrivateCoordinatorError("invalid_private_room_config")
        return copy.deepcopy(value)

    def start(self, battle: object, profile: dict) -> dict:
        with self._lock:
            try:
                validated = validate_private_battle(battle, self.matchmaking._native)
            except PrivateCloudError as error:
                raise PrivateCoordinatorError(str(error)) from None
            validated["roomConfig"] = self._room_config(
                battle.get("roomConfig") if isinstance(battle, dict) else None
            )
            expires_at = battle.get("expiresAt") if isinstance(battle, dict) else None
            if type(expires_at) is not int or expires_at <= 0:
                raise PrivateCoordinatorError("invalid_private_battle_expiry")
            validated["expiresAt"] = expires_at
            created_by = battle.get("createdBy")
            source_participants = battle.get("participants")
            if (not isinstance(created_by, str)
                    or created_by not in {row["userId"] for row in validated["participants"]}
                    or not isinstance(source_participants, list)
                    or len(source_participants) != len(validated["participants"])):
                raise PrivateCoordinatorError("invalid_private_display_metadata")
            for target, source in zip(validated["participants"], source_participants):
                name = source.get("displayName") if isinstance(source, dict) else None
                if (source.get("userId") != target["userId"]
                        or not isinstance(name, str) or not 1 <= len(name) <= 32):
                    raise PrivateCoordinatorError("invalid_private_display_metadata")
                target["displayName"] = name
            validated["createdBy"] = created_by
            manifest = {key: copy.deepcopy(validated[key]) for key in _MANIFEST_KEYS}
            if self.manifest is not None:
                if not _typed_equal(manifest, self.manifest):
                    raise PrivateCoordinatorError("private_battle_conflict")
                if self.state == "upload_pending":
                    return self._upload_frozen()
                return self._result(True)

            mine = next((row for row in manifest["participants"]
                         if row["userId"] == self.user_id), None)
            if mine is None:
                raise PrivateCoordinatorError("private_membership_mismatch")
            try:
                squad, _saved = self.matchmaking._trusted_battle_squad(
                    copy.deepcopy(profile)
                )
                rows = [list(row) for row in squad.records]
                actual = self.matchmaking.pvp_rows_cloud_loadout(rows)
            except Exception:
                raise PrivateCoordinatorError("invalid_private_local_squad") from None
            if not _typed_equal(actual, self._identity(mine)):
                raise PrivateCoordinatorError("private_local_squad_changed")

            # Freeze before the first remote mutation. A lost response may
            # still mean Worker committed these exact bytes; retries must never
            # rebuild from a newer profile and conflict with first-write-wins.
            self.manifest = manifest
            self.local_rows = rows
            self.state = "upload_pending"
            return self._upload_frozen()

    def _upload_frozen(self) -> dict:
            try:
                acknowledgement = self.api.put_squad(
                    self.manifest["battleId"], copy.deepcopy(self.local_rows)
                )
            except Exception:
                raise PrivateCoordinatorError("private_squad_upload_uncertain") from None
            missing = acknowledgement.get("missing") \
                if isinstance(acknowledgement, dict) else None
            participant_ids = {row["userId"] for row in self.manifest["participants"]}
            if not (
                isinstance(acknowledgement, dict)
                and set(acknowledgement) == {"ok", "ready", "missing"}
                and acknowledgement.get("ok") is True
                and type(acknowledgement.get("ready")) is bool
                and isinstance(missing, list)
                and all(isinstance(value, str) for value in missing)
                and len(missing) == len(set(missing))
                and acknowledgement["ready"] is (len(missing) == 0)
                and self.user_id not in missing
                and set(missing) <= participant_ids
            ):
                raise PrivateCoordinatorError("private_squad_upload_unconfirmed")
            self.state = "awaiting_roster"
            return self._result()

    def poll(self) -> dict:
        with self._lock:
            if self.state == "prepared":
                return self._result(True)
            if self.state != "awaiting_roster":
                raise PrivateCoordinatorError("private_coordinator_state")
            try:
                roster = self.api.get_roster(self.manifest["battleId"])
            except Exception as error:
                if (getattr(error, "status", None) == 409
                        and getattr(error, "code", None) == "roster_incomplete"):
                    return self._result()
                raise PrivateCoordinatorError(
                    str(getattr(error, "code", "private_roster_unavailable"))
                ) from None

            cpu = self.manifest["cpuRosterPolicy"]
            cpu_seats = ([0, cpu["aiOpponents"]]
                         if self.manifest["mode"] == "pve" else [0, 0])
            expected = {
                "battleId": self.manifest["battleId"], "origin": "private",
                "mode": self.manifest["mode"], "ruleset": self.manifest["ruleset"],
                "mapKey": self.manifest["mapKey"], "rosterPolicy": None,
                "cpuSeatsByTeam": cpu_seats, "roomId": self.manifest["roomId"],
                "roomMatchId": self.manifest["roomMatchId"],
                "roomConfig": self.manifest["roomConfig"],
                "economyPolicy": self.manifest["economyPolicy"],
                "battleEntitlement": self.manifest["battleEntitlement"],
                "cpuRosterPolicy": self.manifest["cpuRosterPolicy"],
            }
            if (not isinstance(roster, dict)
                    or any(not _typed_equal(roster.get(key), value)
                           for key, value in expected.items())):
                raise PrivateCoordinatorError("private_roster_mismatch")
            got, humans = roster.get("participants"), self.manifest["participants"]
            if not isinstance(got, list) or len(got) != len(humans):
                raise PrivateCoordinatorError("private_roster_mismatch")
            by_user = {row.get("userId"): row for row in got if isinstance(row, dict)}
            if (len(by_user) != len(got)
                    or set(by_user) != {row["userId"] for row in humans}):
                raise PrivateCoordinatorError("private_roster_mismatch")

            frozen = []
            for participant in humans:
                row = by_user[participant["userId"]]
                if any(type(row.get(key)) is not int or row[key] != participant[key]
                       for key in ("seat", "team", "playerId")):
                    raise PrivateCoordinatorError("private_roster_mismatch")
                rows = row.get("rows")
                try:
                    details = self.matchmaking.pvp_opponent_details(rows)
                    actual = self.matchmaking.pvp_rows_cloud_loadout(rows)
                except Exception:
                    raise PrivateCoordinatorError(
                        "private_roster_loadout_mismatch"
                    ) from None
                if (not _typed_equal(actual, self._identity(participant))
                        or participant["userId"] == self.user_id
                        and rows != self.local_rows):
                    raise PrivateCoordinatorError(
                        "private_roster_loadout_mismatch"
                    )
                frozen.append({
                    "user_id": participant["userId"], "seat": participant["seat"],
                    "team": participant["team"], "player_id": participant["playerId"],
                    "details": copy.deepcopy(details),
                })
            mine = next(row for row in frozen if row["user_id"] == self.user_id)
            try:
                ticket = validate_relay_ticket(
                    self.api.relay_ticket(self.manifest["battleId"]),
                    battle_id=self.manifest["battleId"], seat=mine,
                )
                prepared = PreparedPrivateBattle(
                    battle_id=self.manifest["battleId"],
                    room_id=self.manifest["roomId"],
                    room_match_id=self.manifest["roomMatchId"],
                    mode=self.manifest["mode"], ruleset=self.manifest["ruleset"],
                    map_key=self.manifest["mapKey"], seat=mine["seat"],
                    team=mine["team"], player_id=mine["player_id"],
                    user_ids=tuple(row["user_id"] for row in frozen),
                    cpu_seats_by_team=tuple(cpu_seats),
                    battle_key_hex=ticket["battle_key_hex"],
                    relay_url=derive_relay_ws_url(
                        self.api_base_url, ticket["relay_url"]),
                    reward_policy=copy.deepcopy(self.manifest["rewardPolicy"]),
                    economy_policy=copy.deepcopy(self.manifest["economyPolicy"]),
                    battle_entitlement=copy.deepcopy(
                        self.manifest["battleEntitlement"]),
                    room_config=copy.deepcopy(self.manifest["roomConfig"]),
                    cpu_roster_policy=copy.deepcopy(
                        self.manifest["cpuRosterPolicy"]),
                    expires_at=self.manifest["expiresAt"],
                    local_commander_key=next(
                        row["key"] for row in self.matchmaking._native["commanders"]
                        if str(row["item_id"]) == self._identity(
                            next(p for p in self.manifest["participants"]
                                 if p["userId"] == self.user_id))["commander_id"]),
                    local_commander_tier=mine["details"]["commander_tier"],
                    # Revival's trusted battle builder projects every deployed
                    # unit to the configured Tier-X combat contract; catalogue
                    # identity tiers remain progression/UI metadata only.
                    local_unit_tiers=(EFFECTIVE_UNIT_TIER,) * 3,
                    created_by=self.manifest["createdBy"],
                    display_names=tuple(
                        row["displayName"] for row in self.manifest["participants"]),
                )
                ticket_source = RelayTicketSource(
                    self.api, prepared.battle_id, mine, ticket)
                if self.on_prepared is None:
                    raise PrivateCoordinatorError("private_binding_unavailable")
                binding = self.on_prepared(
                    prepared, ticket_source, copy.deepcopy(frozen))
                if isinstance(binding, dict) and isinstance(
                        binding.get("nativeGame"), dict):
                    self._native_game = copy.deepcopy(binding["nativeGame"])
            except PrivateCoordinatorError:
                raise
            except Exception:
                raise PrivateCoordinatorError("private_binding_failed") from None
            self.frozen_rows = frozen
            self.prepared = prepared
            self.ticket_source = ticket_source
            self.state = "prepared"
            return self._result()

    def native_game(self) -> dict | None:
        with self._lock:
            if self.state != "prepared" or self._native_game is None:
                return None
            return copy.deepcopy(self._native_game)
