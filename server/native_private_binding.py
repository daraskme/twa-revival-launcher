"""Durable binding of a validated private Worker roster to native custom play."""
from __future__ import annotations

import copy
import hashlib
import json
import threading

from local_battle_state import BattleStateError
from native_private_cpu_notifications import CpuNotificationDeliveryUncertain

_ENTITLEMENTS = {"scope": "battle_only", "persist_to_profile": False,
                 "all_units": True, "all_commander_abilities": True,
                 "all_equipment": True, "all_consumables": True}


class PrivateBindingError(Exception):
    pass


class NativePrivateBattleBinding:
    """Allocate first, then expose relay and the native starting notification.

    Remote humans are roster identities, never locally enrolled. Their relay
    handshakes establish their own process-local enrollment evidence.
    """

    def __init__(self, state, local_user_id, cpu_builder, relay_factory, notify):
        self.state = state
        self.local_user_id = local_user_id
        self.cpu_builder = cpu_builder
        self.relay_factory = relay_factory
        self.notify = notify
        self._receipt = None
        self._relay = None
        self._closed = False
        self._lock = threading.RLock()
        self._event_lock = threading.RLock()
        self._lease_active = False
        with self.state._transaction():
            self.state._connection.execute(
                """CREATE TABLE IF NOT EXISTS private_notification_intents_v1 (
                   battle_id TEXT PRIMARY KEY, roster_digest TEXT NOT NULL,
                   state TEXT NOT NULL CHECK(state IN ('intent','unknown','notified','failed'))
                )""")

    def _notice_state(self, battle_id, digest):
        row = self.state._connection.execute(
            "SELECT roster_digest,state FROM private_notification_intents_v1 WHERE battle_id=?",
            (battle_id,)).fetchone()
        if row is None:
            return None
        if row["roster_digest"] != digest:
            raise PrivateBindingError("private_binding_conflict")
        return row["state"]

    def _set_notice_state(self, battle_id, digest, value):
        with self.state._transaction():
            self.state._connection.execute(
                """INSERT INTO private_notification_intents_v1 VALUES (?,?,?)
                   ON CONFLICT(battle_id) DO UPDATE SET state=excluded.state
                   WHERE roster_digest=excluded.roster_digest""",
                (battle_id, digest, value))

    def bind(self, prepared, ticket_source, frozen_humans):
      with self._lock:
        if self._closed:
            raise PrivateBindingError("private_binding_closed")
        return self._bind(prepared, ticket_source, frozen_humans)

    def _bind(self, prepared, ticket_source, frozen_humans):
        humans = copy.deepcopy(frozen_humans)
        if self._receipt is not None:
            if (self._receipt["prepared"] != prepared
                    or self._receipt["humans"] != humans):
                raise PrivateBindingError("private_binding_conflict")
            if self._receipt["notified"]:
                return copy.deepcopy(self._receipt["result"])
            if self._receipt.get("notification_unknown"):
                raise PrivateBindingError("private_notification_uncertain")
        if ([row["user_id"] for row in humans] != list(prepared.user_ids)
                or self.local_user_id not in prepared.user_ids):
            raise PrivateBindingError("invalid_private_humans")
        cpus = (copy.deepcopy(self._receipt["cpus"])
                if self._receipt is not None
                else copy.deepcopy(self.cpu_builder(prepared)))
        if not isinstance(cpus, list) or len(cpus) != sum(prepared.cpu_seats_by_team):
            raise PrivateBindingError("invalid_private_cpu_roster")
        cpu_ids = []
        for row in cpus:
            if (not isinstance(row, dict) or row.get("is_ai") is not True
                    or not isinstance(row.get("user_id"), str)
                    or not isinstance(row.get("details"), dict)
                    or type(row.get("team")) is not int):
                raise PrivateBindingError("invalid_private_cpu_roster")
            cpu_ids.append(row["user_id"])
        if len(cpu_ids) != len(set(cpu_ids)) or set(cpu_ids) & set(prepared.user_ids):
            raise PrivateBindingError("invalid_private_cpu_roster")
        population = humans + cpus
        roster_digest = hashlib.sha256(json.dumps(
            population, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")).hexdigest()
        durable_notice = self._notice_state(prepared.battle_id, roster_digest)
        decimal_key = str(int(prepared.battle_key_hex, 16))
        context = {
            "mode": "private", "private": True,
            "lobby_visibility_private": True,
            "cloud_battle_id": prepared.battle_id,
            "battle_instance_id": prepared.battle_id,
            "room_game_id": prepared.room_id,
            "room_match_id": prepared.room_match_id,
            "created_by": prepared.created_by,
            "party_id": prepared.room_id, "result_party_id": "",
            "map": prepared.map_key,
            "room_config": copy.deepcopy(prepared.room_config),
            "cpu_roster_policy": copy.deepcopy(prepared.cpu_roster_policy),
            "relay_authenticated_humans": len(humans),
            "native_expected_players": len(population),
            "result_participants": [{"user_id": row["user_id"],
                                     "party_id": "", "is_ai": row in cpus}
                                    for row in population],
            "roster_digest": roster_digest,
            "reward_policy": "none", "reward_multiplier": 0,
            "room_creation_cost_silver_cents": 0,
            "battle_cost_silver_cents": 0,
            "commander_unlock_cost_silver_cents": 0,
            "unit_unlock_cost_silver_cents": 0,
            "ability_unlock_cost_silver_cents": 0,
            "equipment_unlock_cost_silver_cents": 0,
            "consumable_cost_silver_cents": 0,
            "display_name": prepared.display_names[
                prepared.user_ids.index(self.local_user_id)],
            "commander_key": prepared.local_commander_key,
            "commander_tier": prepared.local_commander_tier,
            "unit_tiers": list(prepared.local_unit_tiers),
            "battle_tier": max(prepared.local_unit_tiers),
            "pve_enemy_tier": max(prepared.local_unit_tiers),
            "full_squad_setup": copy.deepcopy(
                next(row["details"]["full_squad_setup"] for row in humans
                     if row["user_id"] == self.local_user_id)),
            "private_entitlements": copy.deepcopy(_ENTITLEMENTS),
        }
        game = {
            "game_id": prepared.room_id, "owner_id": prepared.created_by,
            "settings": {"title": prepared.room_config["title"],
                         "map": prepared.map_key,
                         "length": prepared.room_config["length"],
                         "max_players": len(population), "privacy": True},
            "battle_key": decimal_key, "relay_server": "127.0.0.1:19000",
            "maps": [prepared.map_key],
            "teams": [{"team_id": 1, "team_name": "Team 1"},
                      {"team_id": 2, "team_name": "Team 2"}],
            "players": [{"user_id": row["user_id"],
                         "display_name": (prepared.display_names[
                             prepared.user_ids.index(row["user_id"])]
                             if row in humans else row["user_id"]),
                         "online_status": "online",
                         "team_id": row["team"] + 1, "ready": True,
                         "is_ai": row in cpus,
                         "profile_matchmaking_details": copy.deepcopy(row["details"])}
                        for row in population],
        }
        try:
            # Each companion persists only its authenticated local authority.
            # Remote humans enroll in their own SQLite/relay process; they are
            # retained in result_participants and the frozen roster digest.
            self.state.allocate(prepared.battle_id, [self.local_user_id], context,
                                battle_key=decimal_key,
                                expected_players=len(population))
            self.state.bind_wire_battle_id(prepared.room_id, prepared.battle_id)
            self.state.enroll(prepared.battle_id, self.local_user_id)
        except BattleStateError as error:
            raise PrivateBindingError(str(error)) from None
        result = {"battleId": prepared.battle_id,
                  "roomMatchId": prepared.room_match_id,
                  "status": "bound", "nativeGame": game}
        if self._receipt is None:
            self._receipt = {"prepared": copy.deepcopy(prepared),
                             "humans": copy.deepcopy(humans),
                             "cpus": copy.deepcopy(cpus), "notified": False,
                             "notification_unknown": False, "result": result}
            self._receipt["roster_digest"] = roster_digest
        if self._relay is None:
            relay = self.relay_factory(prepared, ticket_source)
            self._relay = relay
            with self._event_lock:
                self._lease_active = True
            try:
                relay.start()
            except Exception:
                with self._event_lock:
                    self._lease_active = False
                try:
                    relay.stop()
                except Exception:
                    raise PrivateBindingError(
                        "private_relay_cleanup_unconfirmed") from None
                self._relay = None
                raise PrivateBindingError("private_relay_start_failed") from None
        durable_notice = self._notice_state(prepared.battle_id, roster_digest)
        if durable_notice in {"intent", "unknown"}:
            self._receipt["notification_unknown"] = True
            raise PrivateBindingError("private_notification_uncertain")
        if durable_notice == "notified":
            self._receipt["notified"] = True
            return copy.deepcopy(result)
        self._set_notice_state(prepared.battle_id, roster_digest, "intent")
        try:
            recipients = self.notify(prepared.room_id)
        except CpuNotificationDeliveryUncertain:
            with self._event_lock:
                if self._notice_state(prepared.battle_id, roster_digest) == "notified":
                    self._receipt["notified"] = True
                    self._receipt["notification_unknown"] = False
                    return copy.deepcopy(result)
                self._receipt["notification_unknown"] = True
                self._set_notice_state(prepared.battle_id, roster_digest, "unknown")
            raise PrivateBindingError("private_notification_uncertain") from None
        except Exception as error:
            with self._event_lock:
                if self._notice_state(prepared.battle_id, roster_digest) == "notified":
                    self._receipt["notified"] = True
                    self._receipt["notification_unknown"] = False
                    return copy.deepcopy(result)
                definite = getattr(error, "definite_no_write", False) is True
                if definite:
                    self._set_notice_state(prepared.battle_id, roster_digest, "failed")
                    self._lease_active = False
                else:
                    self._receipt["notification_unknown"] = True
                    self._set_notice_state(prepared.battle_id, roster_digest, "unknown")
            if definite:
                self._stop_relay(False)
                raise PrivateBindingError("private_notification_failed") from None
            raise PrivateBindingError("private_notification_uncertain") from None
        if type(recipients) is not int or recipients <= 0:
            with self._event_lock:
                if self._notice_state(prepared.battle_id, roster_digest) == "notified":
                    self._receipt["notified"] = True
                    self._receipt["notification_unknown"] = False
                    return copy.deepcopy(result)
                self._set_notice_state(prepared.battle_id, roster_digest, "failed")
                self._lease_active = False
            self._stop_relay(False)
            raise PrivateBindingError("private_notification_failed")
        try:
            self._set_notice_state(prepared.battle_id, roster_digest, "notified")
        except Exception:
            self._receipt["notification_unknown"] = True
            raise PrivateBindingError("private_notification_uncertain") from None
        self._receipt["notified"] = True
        return copy.deepcopy(result)

    def on_relay_event(self, payload):
        """Accept only the authenticated relay's frozen ticking barrier."""
        with self._event_lock:
            if self._closed or not self._lease_active:
                raise PrivateBindingError("private_binding_closed")
            if (not isinstance(payload, dict)
                    or set(payload) != {"event", "battleId", "phase", "tick"}
                    or payload.get("event") != "battle_phase"
                    or payload.get("phase") != "ticking"
                    or type(payload.get("tick")) is not int
                    or payload["tick"] != 0):
                raise PrivateBindingError("invalid_private_relay_event")
            if (self._receipt is None
                    or payload.get("battleId")
                    != self._receipt["prepared"].battle_id
                    or self._relay is None):
                raise PrivateBindingError("stale_private_battle_lease")
            try:
                before = self.state.snapshot(payload["battleId"])
                if before.get("phase") in {
                        "result_reported", "result_ready", "settled", "delivered"}:
                    if not self._receipt.get("notified"):
                        raise PrivateBindingError("stale_private_battle_lease")
                    return copy.deepcopy(before)
                if before.get("phase") not in {"enrolled", "ticking"}:
                    raise PrivateBindingError("stale_private_battle_lease")
                if not self._receipt.get("notified"):
                    # The authenticated all-seat relay barrier is stronger
                    # evidence than the uncertain XMPP send outcome. Commit
                    # delivery without replaying the notification.
                    self._set_notice_state(
                        payload["battleId"], self._receipt["roster_digest"],
                        "notified")
                    self._receipt["notified"] = True
                    self._receipt["notification_unknown"] = False
                snapshot = self.state.start_ticking(payload["battleId"])
            except BattleStateError as error:
                raise PrivateBindingError(str(error)) from None
            return copy.deepcopy(snapshot)

    def _stop_relay(self, permanent):
        with self._lock:
            if permanent:
                self._closed = True
            relay = self._relay
        with self._event_lock:
            self._lease_active = False
        if relay is None:
            return
        relay.stop()
        with self._lock:
            if self._relay is relay:
                self._relay = None

    def close(self):
        self._stop_relay(True)
