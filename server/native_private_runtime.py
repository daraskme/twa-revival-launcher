"""Bounded owner for one cloud-private native room-match lease."""
from __future__ import annotations

import copy
import hashlib
import threading
import time

from native_private_binding import NativePrivateBattleBinding
from native_private_cloud import CloudPrivateLobbyAdapter, PrivateBattleApi
from native_private_coordinator import PrivateBattleCoordinator
from native_private_results import PrivateResultAuthority, PrivateResultError
from native_custom_lobby import NativeLobbyError


class NativePrivateRuntime:
    """Compose lobby, roster, relay, SQLite, and result stages.

    ``step`` performs one bounded Room observation. It never sleeps, launches a
    process, or converts an incomplete stage into success.
    """

    def __init__(self, *, room_api, battle_api, state, matchmaking,
                 native_user_id, mode, ai_opponents, sync_loadout, notifier,
                 starting_notifier, relay_factory, api_base_url=None,
                 return_owner=None, clock_seconds=None):
        self.room_api = room_api
        self.battle_api = (battle_api if isinstance(battle_api, PrivateBattleApi)
                           else PrivateBattleApi(battle_api))
        self.state = state
        self.matchmaking = matchmaking
        self.user_id = native_user_id
        self.relay_factory = relay_factory
        self.api_base_url = api_base_url
        self.starting_notifier = starting_notifier
        self._lock = threading.RLock()
        self._reported = set()
        self._clock_seconds = clock_seconds or (lambda: int(time.time()))
        self._next_recovery_check = 0
        self._return_receipt = None
        self._closing_binding = None
        self.binding = self._new_binding()
        self.coordinator = self._new_coordinator()
        self.results = PrivateResultAuthority(
            self.battle_api, state, native_user_id, matchmaking._native,
            clock_seconds=clock_seconds, return_owner=return_owner)
        self.adapter = CloudPrivateLobbyAdapter(
            room_api, native_user_id, mode=mode, ai_opponents=ai_opponents,
            native_catalog=matchmaking._native, sync_loadout=sync_loadout,
            cpu_players=self._lobby_cpu_players, notifier=notifier,
            native_game_source=self.coordinator.native_game,
            start_callback=self.coordinator.start,
            return_callback=self.results.authorize_return,
            return_observed_callback=self._observe_return)
        # Adapter callbacks mutate this composition.  A single re-entrant
        # boundary avoids runtime->adapter versus adapter->runtime inversion.
        self.adapter._lock = self._lock
        if return_owner is None:
            self.results.return_owner = self.adapter.is_current_return_owner

    def _cpu_details(self):
        squad = self.matchmaking._trusted_pve_enemy_squad(10)
        return self.matchmaking._squad_details(
            squad.commander_tier, squad.records)

    def _lobby_cpu_players(self, room_id, count):
        details = self._cpu_details()
        return [{"user_id": "private-cpu-" + hashlib.sha256(
                    (room_id + ":" + str(index)).encode()).hexdigest()[:24],
                 "display_name": "CPU " + str(index + 1), "team_id": 2,
                 "ready": True, "online_status": "online", "is_ai": True,
                 "profile_matchmaking_details": copy.deepcopy(details)}
                for index in range(count)]

    def _binding_cpus(self, prepared):
        count = sum(prepared.cpu_seats_by_team)
        commanders = sorted(
            (row for row in self.matchmaking._native["commanders"]
             if row.get("build_state") == "live"), key=lambda row: row["key"])
        units_by_faction = {}
        for row in self.matchmaking._native["units"]:
            if row.get("build_state") == "live" and row.get("is_premium") is False:
                units_by_faction.setdefault(row["faction"], []).append(row["key"])
        result = []
        seed = prepared.cpu_roster_policy["seed"]
        for index in range(count):
            digest = hashlib.sha256((seed + ":" + str(index)).encode()).digest()
            commander = commanders[int.from_bytes(digest[:4], "little") % len(commanders)]
            pool = sorted(units_by_faction[commander["faction"]])
            unit_keys = tuple(pool[(int.from_bytes(digest[4 + slot * 4:8 + slot * 4],
                                                    "little") + slot) % len(pool)]
                              for slot in range(3))
            squad = self.matchmaking._trusted_pve_cpu_squad(
                unit_keys, 10, commander["key"])
            details = self.matchmaking._squad_details(
                squad.commander_tier, squad.records)
            result.append({"user_id": "private-cpu-" + digest.hex()[:24],
                           "team": 1, "is_ai": True, "details": details})
        return result

    def _new_binding(self):
        binding = NativePrivateBattleBinding(
            self.state, self.user_id, self._binding_cpus,
            lambda prepared, ticket: self.relay_factory(
                prepared, ticket, binding.on_relay_event),
            self.starting_notifier)
        return binding

    def _new_coordinator(self):
        return PrivateBattleCoordinator(
            self.battle_api, self.user_id, self.matchmaking,
            api_base_url=self.api_base_url,
            on_prepared=self.binding.bind)

    def step(self, profile):
        with self._lock:
            room_expired_observed = False
            try:
                serial = self.adapter.refresh_notifications(copy.deepcopy(profile))
            except NativeLobbyError as error:
                # A Room lease can expire while this exact frozen battle is
                # still locally prepared.  The Worker return-authority path
                # must still run; all other failures remain visible.
                if not self._is_expired_frozen_battle_error(error):
                    raise
                room_expired_observed = True
                serial = getattr(self.adapter, "_notification_serial", 0)
            if self.coordinator.state == "awaiting_roster":
                self.coordinator.poll()
            manifest = self.coordinator.manifest
            report = None
            returned = None
            if manifest is not None and self.coordinator.state == "prepared":
                battle_id = manifest["battleId"]
                snapshot = self.state.snapshot(battle_id)
                if (snapshot.get("phase") in {"settled", "delivered"}
                        and battle_id not in self._reported):
                    try:
                        report = self.results.report_local(copy.deepcopy(manifest))
                    except PrivateResultError as error:
                        if error.code not in {"private_local_settlement_missing",
                                              "private_result_not_durable",
                                              "battle_expired"}:
                            raise
                    else:
                        self._reported.add(battle_id)
                expired = (type(manifest.get("expiresAt")) is int
                           and self._clock_seconds() >= manifest["expiresAt"])
                recovery_due = self._clock_seconds() >= self._next_recovery_check
                if recovery_due:
                    self._next_recovery_check = self._clock_seconds() + 5
                if ((snapshot.get("phase") == "delivered" or expired or recovery_due)
                        and self.results.return_owner(
                            copy.deepcopy(manifest)) is True):
                    try:
                        returned = self.return_battle(profile)
                    except Exception as error:
                        if getattr(error, "code", "") not in {
                                "private_worker_battle_not_returnable",
                                "private_worker_settlement_missing",
                                "private_return_authorization_pending"}:
                            raise
                elif room_expired_observed and expired:
                    receipt = self.results.authorize_expired_local_release(
                        copy.deepcopy(manifest))
                    returned = self.adapter.release_expired_battle(receipt)
            return {"notificationSerial": serial,
                    "coordinatorState": self.coordinator.state,
                    "resultReport": copy.deepcopy(report),
                    "returnReceipt": copy.deepcopy(returned)}

    def _is_expired_frozen_battle_error(self, error: Exception) -> bool:
        manifest = getattr(self.coordinator, "manifest", None)
        room_id = getattr(self.adapter, "room_id", None)
        battle = getattr(self.adapter, "_battle", None)
        required_ids = ("roomId", "battleId", "roomMatchId")
        return (
            type(error) is NativeLobbyError
            and error.status == 410
            and error.code == "room_expired"
            and getattr(self.coordinator, "state", None) == "prepared"
            and isinstance(manifest, dict)
            and isinstance(battle, dict)
            and all(isinstance(manifest.get(key), str) and manifest[key]
                    for key in required_ids)
            and all(isinstance(battle.get(key), str) and battle[key]
                    for key in required_ids)
            and room_id == manifest["roomId"]
            and battle["roomId"] == manifest["roomId"]
            and battle["battleId"] == manifest["battleId"]
            and battle["roomMatchId"] == manifest["roomMatchId"]
        )

    def return_battle(self, profile):
        with self._lock:
            manifest = self.coordinator.manifest
            if manifest is None:
                raise RuntimeError("private_battle_not_started")
            return self.adapter.return_battle(
                manifest["battleId"], copy.deepcopy(profile))

    def _observe_return(self, receipt):
        """Close the exact old lease before adapter permits a new match."""
        with self._lock:
            manifest = self.coordinator.manifest
            if (not isinstance(receipt, dict) or manifest is None
                    or receipt.get("battleId") != manifest.get("battleId")
                    or receipt.get("matchId") != manifest.get("roomMatchId")):
                raise RuntimeError("stale_private_return_observation")
            self.binding.close()
            self.binding = self._new_binding()
            self.coordinator = self._new_coordinator()
            self.adapter.start_callback = self.coordinator.start
            self.adapter._native_game_source = self.coordinator.native_game

    def close(self):
        with self._lock:
            self.binding.close()
