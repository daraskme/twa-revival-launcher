"""Strict host-side controller for the loopback specialization IPC.

The caller must supply the commander owning the visible native tree and an
authoritative raw server-profile ``saved`` value that the host paired with its
validated native commander and tree revision.  That pairing must come from the
same validated host snapshot; the commander must not be inferred from the
server's currently active commander.  The native wire ``saved`` value may be a
signed/floored adapter watermark and is not the raw server value.  Server GET
state is only a consistency check; it is never used as click authority.  An uncertain POST
keeps its operation ID and exact bytes pending so only an idempotent retry can
continue that logical click.
"""
from __future__ import annotations

import copy
import http.client
import json
import math
import re
import secrets
import threading
from dataclasses import dataclass
from typing import Callable


HOST = "127.0.0.1"
PORT = 18765
PATH = "/native-probe/specialization"
# A successful POST carries the complete native profile graph (currently well
# above a settlement-sized 256 KiB payload).  Keep a finite defensive ceiling
# while allowing the real in-memory service response.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
PRICE_FREE_XP_CENTS = 1_000_000  # Legacy receipt compatibility only.
PRICE_DISPLAY_FREE_XP = 10_000   # Legacy display compatibility only.
OPERATION_ID = re.compile(r"native-specialization-[0-9a-f]{32}\Z")
ACTIONS = frozenset(("respec_commander",))
DEFINITIVE_NO_WRITE_STATUS = {
    # Exact status mapping from ProbeHandler._economy_http_status.  Each listed
    # service path rejects before LocalEconomy publishes state.
    "economy_invalid_specialization_control_request": 400,
    "economy_invalid_specialization_action": 400,
    "economy_invalid_specialization_operation_id": 400,
    "economy_invalid_specialization_watermark": 400,
    "economy_specialization_commander_mismatch": 409,
    "economy_insufficient_free_xp": 409,
    "economy_commander_not_owned": 409,
    "economy_idempotency_conflict": 409,
    "economy_specializations_not_enabled": 503,
    "economy_specialization_action_unavailable": 503,
    "economy_specialization_state_changed": 503,
    "economy_specialization_change_pending_battle": 503,
    "economy_specialization_requires_tier_x": 503,
    "economy_specialization_route_required": 503,
    "economy_specialization_capacity_reached": 503,
    "economy_operation_capacity_reached": 503,
}


class SpecializationControlError(RuntimeError):
    def __init__(self, code: str, *, uncertain: bool = False,
                 definitive: bool = False):
        super().__init__(code)
        self.code = code
        self.uncertain = uncertain
        self.definitive = definitive


@dataclass(frozen=True)
class PendingClick:
    action: str
    commander_key: str
    expected_saved: int
    operation_id: str
    body: bytes
    status_before: dict


Transport = Callable[[str, bytes | None, float], tuple[int, bytes]]


def _strict_object(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or len(raw) > MAX_RESPONSE_BYTES:
        raise SpecializationControlError("specialization_response_too_large")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise SpecializationControlError("duplicate_specialization_response_key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(
                               SpecializationControlError(
                                   "invalid_specialization_response_number"
                               )))
    except SpecializationControlError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SpecializationControlError("invalid_specialization_response") from exc
    if not isinstance(value, dict):
        raise SpecializationControlError("invalid_specialization_response")
    return value


def _loopback_request(method: str, body: bytes | None,
                      timeout: float) -> tuple[int, bytes]:
    """Use a fixed numeric loopback peer; http.client has no proxy/redirect layer."""
    connection = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
    headers = ({"Content-Type": "application/json", "Accept": "application/json"}
               if body is not None else {"Accept": "application/json"})
    try:
        connection.request(method, PATH, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        return response.status, raw
    finally:
        connection.close()


def _uint64(value: object, code: str) -> int:
    if type(value) is not int or not 0 <= value < 2**64:
        raise SpecializationControlError(code)
    return value


def _nonnegative(value: object, code: str) -> int:
    if type(value) is not int or value < 0:
        raise SpecializationControlError(code)
    return value


def _validate_status(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != {
            "selected_route", "route_capacity", "entitled_total",
            "active_total", "banked", "spent", "remaining",
            "purchasable_capacity", "selected_routes", "route_spent",
            "fixed_talent_budget", "purchase_enabled", "migration_required",
            "policy_version"}:
        raise SpecializationControlError("invalid_specialization_status")
    selected = value["selected_route"]
    policy = value["policy_version"]
    if ((selected is not None and (not isinstance(selected, str) or not selected))
            or not isinstance(policy, str) or not policy
            or type(value["fixed_talent_budget"]) is not int
            or value["fixed_talent_budget"] != 30
            or type(value["purchase_enabled"]) is not bool
            or value["purchase_enabled"] is not False
            or type(value["migration_required"]) is not bool):
        raise SpecializationControlError("invalid_specialization_status")
    routes = value["selected_routes"]
    route_spent = value["route_spent"]
    if (not isinstance(routes, list)
            or any(not isinstance(item, str) or not item for item in routes)
            or len(set(routes)) != len(routes)
            or not isinstance(route_spent, dict)
            or not route_spent
            or any(not isinstance(key, str) or not key
                   or type(amount) is not int or amount < 0
                   for key, amount in route_spent.items())
            or set(routes) - set(route_spent)
            or selected != (routes[0] if len(routes) == 1 else None)):
        raise SpecializationControlError("invalid_specialization_status")
    fields = {key: _nonnegative(value[key], "invalid_specialization_status")
              for key in ("route_capacity", "entitled_total", "active_total",
                          "banked", "spent", "remaining", "purchasable_capacity")}
    if (fields["route_capacity"] != 30
            or fields["entitled_total"] != 30
            or fields["active_total"] != 30
            or fields["banked"] != 0
            or fields["purchasable_capacity"] != 0
            or fields["spent"] != sum(route_spent.values())
            or fields["active_total"] != min(fields["entitled_total"],
                                      fields["route_capacity"])
            or fields["banked"] != fields["entitled_total"] - fields["active_total"]
            or fields["remaining"] != fields["active_total"] - fields["spent"]
            or fields["purchasable_capacity"]
            != max(0, fields["route_capacity"] - fields["entitled_total"])):
        raise SpecializationControlError("invalid_specialization_status")
    return copy.deepcopy(value)


def _validate_get(value: dict) -> dict:
    if set(value) != {"result", "commander_key", "saved", "pending_battle",
                     "free_xp_cents", "status"} or value.get("result") != "ok":
        raise SpecializationControlError("invalid_specialization_status_response")
    commander = value["commander_key"]
    if (not isinstance(commander, str) or not commander
            or type(value["pending_battle"]) is not bool):
        raise SpecializationControlError("invalid_specialization_status_response")
    result = copy.deepcopy(value)
    result["saved"] = _uint64(value["saved"], "invalid_specialization_status_response")
    result["free_xp_cents"] = _nonnegative(
        value["free_xp_cents"], "invalid_specialization_status_response",
    )
    result["status"] = _validate_status(value["status"])
    return result


class SpecializationController:
    """Serialize native-tree clicks and preserve uncertain operation identity."""

    def __init__(self, *, transport: Transport = _loopback_request,
                 timeout: float = 2.0,
                 token_hex: Callable[[int], str] = secrets.token_hex):
        if (type(timeout) not in {int, float} or not math.isfinite(timeout)
                or not 0.1 <= timeout <= 5.0):
            raise ValueError("timeout must be between 0.1 and 5 seconds")
        self._transport = transport
        self._timeout = float(timeout)
        self._token_hex = token_hex
        self._gate = threading.Lock()
        self._state_lock = threading.Lock()
        self._pending: PendingClick | None = None
        self._uncertain_operation_ids: set[str] = set()

    def pending_click(self) -> PendingClick | None:
        with self._state_lock:
            return copy.deepcopy(self._pending)

    def _exchange(self, method: str, body: bytes | None) -> dict:
        try:
            status, raw = self._transport(method, body, self._timeout)
        except Exception as exc:
            raise SpecializationControlError(
                "specialization_transport_uncertain",
                uncertain=method == "POST",
            ) from exc
        if type(status) is not int or not 100 <= status <= 599:
            raise SpecializationControlError(
                "invalid_specialization_http_status", uncertain=method == "POST",
            )
        value = _strict_object(raw)
        if status != 200:
            # NativeLobbyError.as_envelope is a strict CA wrapper.  Do not
            # accept a flat/proxy/custom response containing a familiar code.
            response = value.get("response")
            error = (response.get("error")
                     if set(value) == {"timestamp", "response"}
                     and type(value.get("timestamp")) is int
                     and value["timestamp"] >= 0
                     and isinstance(response, dict)
                     and set(response) == {"error"} else None)
            suffix = error if isinstance(error, str) and error else str(status)
            definitive = (method == "POST" and isinstance(error, str)
                          and DEFINITIVE_NO_WRITE_STATUS.get(error) == status)
            raise SpecializationControlError(
                "specialization_server_rejected:" + suffix,
                uncertain=method == "POST" and not definitive,
                definitive=definitive,
            )
        return value

    def read_status(self) -> dict:
        return _validate_get(self._exchange("GET", None))

    @staticmethod
    def _caller_context(commander_key: object, expected_saved: object) -> tuple[str, int]:
        """Validate a host-paired native commander/revision and raw saved value."""
        if not isinstance(commander_key, str) or not commander_key:
            raise SpecializationControlError("invalid_native_tree_commander")
        return commander_key, _uint64(expected_saved, "invalid_native_tree_saved")

    @staticmethod
    def _preflight(action: str, commander: str, expected: int,
                   current: dict) -> None:
        if current["commander_key"] != commander:
            raise SpecializationControlError("native_tree_commander_mismatch")
        if current["saved"] != expected:
            raise SpecializationControlError("stale_native_tree_context")
        if current["pending_battle"]:
            raise SpecializationControlError("specialization_change_pending_battle")
        if current["status"]["migration_required"]:
            raise SpecializationControlError("specialization_migration_required")

    def purchase_talent_point(self, commander_key: str,
                              expected_raw_saved: int) -> dict:
        # The v2 fixed-budget policy has no purchasable points.  Refuse before
        # reading or posting so this client can never initiate a paid mutation.
        raise SpecializationControlError("specialization_purchase_disabled")

    def respec_commander(self, commander_key: str,
                         expected_raw_saved: int) -> dict:
        return self._begin("respec_commander", commander_key, expected_raw_saved)

    def _begin(self, action: str, commander_key: str, expected_saved: int) -> dict:
        if action not in ACTIONS:
            raise SpecializationControlError("invalid_specialization_action")
        commander, expected = self._caller_context(commander_key, expected_saved)
        if not self._gate.acquire(blocking=False):
            raise SpecializationControlError("specialization_click_in_progress")
        try:
            with self._state_lock:
                if self._pending is not None:
                    raise SpecializationControlError(
                        "specialization_retry_required", uncertain=True,
                    )
            current = self.read_status()
            self._preflight(action, commander, expected, current)
            operation_id = "native-specialization-" + self._token_hex(16)
            if OPERATION_ID.fullmatch(operation_id) is None:
                raise SpecializationControlError("invalid_generated_operation_id")
            payload = {"action": action, "commander_key": commander,
                       "operation_id": operation_id, "expected_saved": expected}
            body = json.dumps(payload, separators=(",", ":"),
                              sort_keys=True).encode("utf-8")
            pending = PendingClick(action, commander, expected, operation_id,
                                   body, current)
            with self._state_lock:
                self._pending = pending
            return self._post_pending(pending)
        finally:
            self._gate.release()

    def retry_pending(self, commander_key: str, expected_raw_saved: int) -> dict:
        commander, expected = self._caller_context(
            commander_key, expected_raw_saved,
        )
        if not self._gate.acquire(blocking=False):
            raise SpecializationControlError("specialization_click_in_progress")
        try:
            with self._state_lock:
                pending = self._pending
            if pending is None:
                raise SpecializationControlError("no_specialization_retry_pending")
            if (pending.commander_key != commander
                    or pending.expected_saved != expected):
                raise SpecializationControlError(
                    "specialization_retry_context_mismatch", uncertain=True,
                )
            if pending.action == "purchase_talent_point":
                raise SpecializationControlError("specialization_purchase_disabled")
            return self._post_pending(pending)
        finally:
            self._gate.release()

    def _post_pending(self, pending: PendingClick) -> dict:
        try:
            response = self._exchange("POST", pending.body)
            self._validate_result(response, pending)
        except SpecializationControlError as exc:
            with self._state_lock:
                was_uncertain = pending.operation_id in self._uncertain_operation_ids
            if exc.definitive and not was_uncertain:
                with self._state_lock:
                    if self._pending == pending:
                        self._pending = None
            else:
                exc.uncertain = True
                exc.definitive = False
                with self._state_lock:
                    self._uncertain_operation_ids.add(pending.operation_id)
            raise
        with self._state_lock:
            if self._pending != pending:
                raise SpecializationControlError(
                    "specialization_pending_identity_changed", uncertain=True,
                )
            self._pending = None
            self._uncertain_operation_ids.discard(pending.operation_id)
        return response

    @staticmethod
    def _validate_result(response: dict, pending: PendingClick) -> None:
        if set(response) != {"result", "action", "commander_key", "saved",
                            "receipt", "status", "profile"}:
            raise SpecializationControlError("invalid_specialization_result")
        if (response.get("result") != "ok"
                or response.get("action") != pending.action
                or response.get("commander_key") != pending.commander_key
                or not isinstance(response.get("profile"), dict)):
            raise SpecializationControlError("specialization_result_identity_mismatch")
        saved = _uint64(response.get("saved"), "invalid_specialization_result")
        status = _validate_status(response.get("status"))
        receipt = response.get("receipt")
        if not isinstance(receipt, dict):
            raise SpecializationControlError("invalid_specialization_receipt")
        common = {
            "operation_id": pending.operation_id, "kind": pending.action,
            "commander": pending.commander_key,
        }
        if any(receipt.get(key) != value for key, value in common.items()):
            raise SpecializationControlError("specialization_receipt_identity_mismatch")
        receipt_saved = _uint64(receipt.get("saved"),
                                "invalid_specialization_receipt")
        if not pending.expected_saved < receipt_saved <= saved:
            raise SpecializationControlError("invalid_specialization_receipt")
        if (set(receipt) != {"operation_id", "kind", "saved", "commander",
                            "policy_version", "entitled_total", "selected_routes"}
                or receipt.get("policy_version")
                != pending.status_before["status"]["policy_version"]
                or type(receipt.get("entitled_total")) is not int
                or receipt.get("entitled_total") != 30
                or receipt.get("selected_routes") != []):
            raise SpecializationControlError("invalid_specialization_receipt")
        if (saved == receipt_saved
                and (status["entitled_total"] != receipt["entitled_total"]
                     or status["selected_routes"] != []
                     or status["spent"] != 0)):
            raise SpecializationControlError("invalid_specialization_receipt")


__all__ = [
    "PRICE_DISPLAY_FREE_XP", "PRICE_FREE_XP_CENTS", "PendingClick",
    "SpecializationControlError", "SpecializationController",
]
