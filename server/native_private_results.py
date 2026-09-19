"""Durable private-battle result reporting and room-return authorization.

The native final event, zero settlement, and result delivery are authoritative
only after they have been persisted in ``LocalBattleState``.  This adapter
derives the Worker's report solely from that immutable evidence.  It never
accepts result fields from the room-return request and never writes profile
currency.
"""
from __future__ import annotations

import copy
import time

from battle_api import CloudSettlementAuthority, report_hash
from native_private_cloud import (
    REWARD_POLICY,
    PrivateBattleTransportError,
    PrivateCloudError,
    _typed_equal,
    validate_private_battle,
)


ZERO_BASE = {"silver": 0, "freeXp": 0, "commanderXp": 0, "unitXp": []}
ZERO_AWARDED = copy.deepcopy(ZERO_BASE)
RESULTS = {"victory", "draw", "defeat", "aborted"}
LOCAL_REWARDS = {
    "free_xp_cents": 0,
    "silver_cents": 0,
    "commander_xp_cents": 0,
    "unit_xp_cents": 0,
    "unit_xp_by_unit": {},
}
LOCAL_ENTITLEMENTS = {
    "scope": "battle_only",
    "persist_to_profile": False,
    "all_units": True,
    "all_commander_abilities": True,
    "all_equipment": True,
    "all_consumables": True,
}
LOCAL_COSTS = {
    "room_creation_cost_silver_cents", "battle_cost_silver_cents",
    "commander_unlock_cost_silver_cents", "unit_unlock_cost_silver_cents",
    "ability_unlock_cost_silver_cents", "equipment_unlock_cost_silver_cents",
    "consumable_cost_silver_cents",
}


class PrivateResultError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class PrivateResultAuthority:
    """Turn durable local completion into an idempotent Worker settlement."""

    def __init__(self, api, state, local_user_id: str, native_catalog: dict,
                 *, clock_seconds=None, return_owner=None) -> None:
        if not isinstance(local_user_id, str) or not local_user_id:
            raise ValueError("local_user_id required")
        self.api = api
        self.state = state
        self.local_user_id = local_user_id
        self.native_catalog = native_catalog
        self.clock_seconds = clock_seconds or (lambda: int(time.time()))
        # Battle ``createdBy`` is immutable, while Room ownership may transfer
        # after a bound participant leaves. Composition must therefore supply
        # an authenticated current-owner resolver; absence fails closed.
        self.return_owner = return_owner or (lambda _battle: False)

    @staticmethod
    def _local_settlement(value: object, battle_id: str) -> tuple[str, bool]:
        if not isinstance(value, dict):
            raise PrivateResultError("private_local_settlement_missing")
        outcome = value.get("outcome")
        verified = value.get("verified")
        rewards = value.get("rewards")
        expected_keys = {
            "match_id", "mode", "outcome", "verified", "reward_policy",
            "rewards", *LOCAL_COSTS, "private_entitlements",
            "profile_persisted",
        }
        if (
            set(value) != expected_keys
            or value.get("match_id") != battle_id
            or value.get("mode") != "private"
            or outcome not in RESULTS
            or type(verified) is not bool
            or value.get("reward_policy") != "none"
            or not _typed_equal(rewards, LOCAL_REWARDS)
            or any(type(value.get(key)) is not int or value[key] != 0
                   for key in LOCAL_COSTS)
            or not _typed_equal(value.get("private_entitlements"),
                                LOCAL_ENTITLEMENTS)
            or value.get("profile_persisted") is not False
        ):
            raise PrivateResultError("invalid_private_local_settlement")
        return outcome, verified

    def _identity(self, frozen_battle: object) -> tuple[dict, dict]:
        try:
            battle = validate_private_battle(frozen_battle, self.native_catalog)
        except PrivateCloudError as error:
            raise PrivateResultError(str(error)) from None
        snapshot = self.state.snapshot(battle["battleId"])
        context = snapshot.get("context")
        expected_context = {
            "mode": "private",
            "private": True,
            "cloud_battle_id": battle["battleId"],
            "battle_instance_id": battle["battleId"],
            "room_game_id": battle["roomId"],
            "room_match_id": battle["roomMatchId"],
        }
        if (
            not isinstance(context, dict)
            or any(not _typed_equal(context.get(key), value)
                   for key, value in expected_context.items())
            or snapshot.get("user_ids") != [self.local_user_id]
        ):
            raise PrivateResultError("private_return_identity_mismatch")
        if not any(row["userId"] == self.local_user_id
                   for row in battle["participants"]):
            raise PrivateResultError("private_return_identity_mismatch")
        participant_ids = {row["userId"] for row in battle["participants"]}
        if (not isinstance(frozen_battle.get("createdBy"), str)
                or frozen_battle["createdBy"] not in participant_ids
                or type(frozen_battle.get("expiresAt")) is not int
                or frozen_battle["expiresAt"] <= 0):
            raise PrivateResultError("invalid_private_frozen_manifest")
        return battle, snapshot

    def _payload(self, battle: dict) -> dict:
        settlement = self.state.settlement(battle["battleId"], self.local_user_id)
        outcome, verified = self._local_settlement(settlement, battle["battleId"])
        durable = self.state.final_event(battle["battleId"], self.local_user_id)
        rows = self.state.get_battle_results(battle["battleId"])
        if not isinstance(durable, dict) or not isinstance(rows, list):
            raise PrivateResultError("private_result_not_durable")
        payload = {
            "result": outcome,
            "wasAfk": not verified,
            "base": copy.deepcopy(ZERO_BASE),
            "resultRows": copy.deepcopy(rows),
            "reportHash": report_hash(durable),
        }
        return payload

    @staticmethod
    def _settlement(value: object, battle_id: str, user_id: str,
                    payload: dict) -> dict:
        if not isinstance(value, dict):
            raise PrivateResultError("invalid_private_worker_settlement")
        expected_reason = (
            "afk" if payload["wasAfk"]
            else "aborted" if payload["result"] == "aborted"
            else "private"
        )
        settlement = value.get("settlement")
        expected_settlement = {
            "policyId": "private-zero-reward-v1",
            "authority": "server",
            "appliedMultiplier": None,
            "zeroReason": expected_reason,
            "awarded": copy.deepcopy(ZERO_AWARDED),
        }
        if (
            set(value) != {"battleId", "userId", "result", "wasAfk", "base",
                           "settlement", "reportHash", "settledAt"}
            or value.get("battleId") != battle_id
            or value.get("userId") != user_id
            or value.get("result") != payload["result"]
            or value.get("wasAfk") is not payload["wasAfk"]
            or not _typed_equal(value.get("base"), payload["base"])
            or value.get("reportHash") != payload["reportHash"]
            or type(value.get("settledAt")) is not int
            or value["settledAt"] <= 0
            or not _typed_equal(settlement, expected_settlement)
        ):
            raise PrivateResultError("invalid_private_worker_settlement")
        # Share the common awarded-amount parser with public settlement.
        if any(CloudSettlementAuthority.applied_amounts(value).values()):
            raise PrivateResultError("invalid_private_worker_settlement")
        return copy.deepcopy(value)

    def _worker_view(self, value: object, frozen_source: dict, battle: dict,
                     payload: dict | None, *, settlement_required: bool,
                     returnable_required: bool = True) -> str:
        if not isinstance(value, dict) or set(value) != {"battle", "settlement"}:
            raise PrivateResultError("invalid_private_worker_battle")
        worker_battle = value.get("battle")
        try:
            validated = validate_private_battle(worker_battle, self.native_catalog)
        except PrivateCloudError as error:
            raise PrivateResultError("invalid_private_worker_battle") from error
        immutable = (
            "origin", "roomId", "roomMatchId", "battleId", "mode", "ruleset",
            "mapKey", "roomConfig", "participants", "rewardPolicy",
            "economyPolicy", "battleEntitlement", "cpuRosterPolicy",
        )
        if any(not _typed_equal(validated.get(key), battle.get(key))
               for key in immutable):
            raise PrivateResultError("private_worker_battle_mismatch")
        for key in ("createdBy", "expiresAt"):
            if not _typed_equal(worker_battle.get(key), frozen_source.get(key)):
                raise PrivateResultError("private_worker_battle_mismatch")
        status = worker_battle.get("status")
        expires_at = worker_battle.get("expiresAt")
        deadline = type(expires_at) is int and self.clock_seconds() >= expires_at
        if returnable_required and status != "settled" and status != "expired" and not (
                status == "disputed" and deadline):
            raise PrivateResultError("private_worker_battle_not_returnable")
        receipt = value.get("settlement")
        if receipt is None:
            if settlement_required or not (status == "expired" or deadline):
                raise PrivateResultError("private_worker_settlement_missing")
        else:
            if payload is None:
                raise PrivateResultError("invalid_private_worker_settlement")
            self._settlement(receipt, battle["battleId"], self.local_user_id, payload)
        return status

    def report_local(self, frozen_battle: dict) -> dict:
        """Report this participant's durable local result, regardless of owner."""
        battle, _snapshot = self._identity(frozen_battle)
        payload = self._payload(battle)
        try:
            receipt = self.api.report_result(battle["battleId"], payload)
            self._settlement(receipt, battle["battleId"], self.local_user_id, payload)
        except PrivateBattleTransportError as error:
            if not error.uncertain:
                raise PrivateResultError(error.code) from None
            try:
                view = self.api.get_battle(battle["battleId"])
            except PrivateBattleTransportError as read_error:
                raise PrivateResultError(read_error.code) from None
            self._worker_view(view, frozen_battle, battle, payload,
                              settlement_required=True,
                              returnable_required=False)
        return {"battleId": battle["battleId"], "userId": self.local_user_id,
                "status": "result_verified"}

    def authorize_return(self, frozen_battle: dict, _profile: dict) -> dict:
        """Return the exact callback receipt expected by the room adapter."""
        battle, snapshot = self._identity(frozen_battle)
        try:
            owner = self.return_owner(copy.deepcopy(frozen_battle))
        except Exception:
            raise PrivateResultError("private_return_owner_unconfirmed") from None
        if owner is not True:
            raise PrivateResultError("private_return_owner_unconfirmed")
        payload = None
        settlement_required = False
        try:
            payload = self._payload(battle)
        except PrivateResultError as error:
            # A disconnected owner may have no native final. Only the Worker's
            # independently frozen expiry deadline can authorize cleanup.
            if error.code not in {
                    "private_local_settlement_missing",
                    "private_result_not_durable"}:
                raise
            payload = None
        if payload is not None:
            try:
                self.report_local(frozen_battle)
                settlement_required = True
            except PrivateResultError as error:
                if error.code != "battle_expired":
                    raise
            if self.local_user_id not in snapshot.get("delivered_user_ids", ()):
                raise PrivateResultError("private_result_not_delivered")
        try:
            view = self.api.get_battle(battle["battleId"])
        except PrivateBattleTransportError as error:
            raise PrivateResultError(error.code) from None
        self._worker_view(view, frozen_battle, battle, payload,
                          settlement_required=settlement_required)
        return {
            "battleId": battle["battleId"],
            "roomMatchId": battle["roomMatchId"],
            "status": "return_authorized",
        }

    def authorize_expired_local_release(self, frozen_battle: dict) -> dict:
        """Authenticate a local lease release without mutating the Worker.

        This is deliberately distinct from ``authorize_return``: it never
        infers ownership and never authorizes a Room return mutation.
        """
        battle, snapshot = self._identity(frozen_battle)
        expires_at = frozen_battle.get("expiresAt")
        if type(expires_at) is not int or self.clock_seconds() < expires_at:
            raise PrivateResultError("private_battle_not_expired")
        settlement = self.state.settlement(battle["battleId"], self.local_user_id)
        delivered = self.local_user_id in snapshot.get("delivered_user_ids", ())
        if settlement is not None and not delivered:
            raise PrivateResultError("private_result_not_delivered")
        if settlement is None and self.state.final_event(
                battle["battleId"], self.local_user_id) is not None:
            raise PrivateResultError("private_local_settlement_missing")
        payload = self._payload(battle) if settlement is not None else None
        try:
            view = self.api.get_battle(battle["battleId"])
        except PrivateBattleTransportError as error:
            raise PrivateResultError(error.code) from None
        self._worker_view(view, frozen_battle, battle, payload,
                          settlement_required=False, returnable_required=True)
        return {"roomId": battle["roomId"],
                "battleId": battle["battleId"],
                "roomMatchId": battle["roomMatchId"],
                "status": "local_expired_release"}
