"""Bounded, read-only host reader for the native specialization UI DTO.

The default transport is deliberately narrower than a general HTTP client:
it opens a direct connection to ``127.0.0.1:18765`` and never follows a
redirect or consults proxy settings.  Tests may inject a transport that
returns ``(status, body)`` from an isolated loopback server.

This module validates presentation data only.  ``expected_commander`` and
``expected_raw_saved`` are mandatory caller context; a server response never
becomes authority for the visible commander or for purchase/respec actions.
No polling, native callback, or mutation is performed here.
"""
from __future__ import annotations

import copy
import http.client
import json
import math
import sys
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import quote

_SERVER = Path(__file__).resolve().parents[1] / "server"
if str(_SERVER) not in sys.path:
    sys.path.insert(0, str(_SERVER))

from commander_specialization_policy import POLICY_VERSION  # noqa: E402
from local_economy import NATIVE_SAVED_FLOOR  # noqa: E402
from specialization_ui_status import (  # noqa: E402
    ROUTE_NAME_KEY_PREFIX,
    UI_STATUS_VERSION,
)


HOST = "127.0.0.1"
PORT = 18765
PATH = "/native-probe/specialization-ui-status"
MAX_RESPONSE_BYTES = 128 * 1024
LANGUAGES = frozenset(("en", "ja", "ru"))
_ROOT_FIELDS = frozenset({
    "version", "language", "commander_key", "policy_version", "fixed_talent_budget",
    "balances", "selected_route", "routes", "purchase", "respec",
    "banked", "raw_saved", "saved", "selected_routes",
})
_BALANCE_FIELDS = frozenset({
    "route_capacity", "entitled_total", "active_total", "banked", "spent",
    "remaining", "purchasable_capacity",
})
_ROUTE_FIELDS = frozenset({
    "root", "name_localization_key", "capacity", "selected", "locked",
    "completed", "spent",
})
_PURCHASE_REASONS = frozenset({"fixed_budget"})
_RESPEC_REASONS = frozenset({"ready", "pending_battle"})


class NativeSpecializationUiStatusError(ValueError):
    """Stable validation/transport failure without exposing response data."""

    def __init__(self, code: str, *, status: int | None = None):
        super().__init__(code)
        self.code = code
        self.status = status


Transport = Callable[[str], tuple[int, bytes]]


def _duplicate_rejecting_object(pairs: list[tuple[object, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise NativeSpecializationUiStatusError("duplicate_json_key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise NativeSpecializationUiStatusError("nonfinite_json_number")


def _parse_json(body: bytes) -> dict:
    if not isinstance(body, bytes) or len(body) > MAX_RESPONSE_BYTES:
        raise NativeSpecializationUiStatusError("response_too_large")
    try:
        text = body.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_json_constant,
        )
    except NativeSpecializationUiStatusError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError):
        raise NativeSpecializationUiStatusError("invalid_json") from None
    if not isinstance(value, dict):
        raise NativeSpecializationUiStatusError("invalid_root_shape")
    return value


def _is_int(value: object) -> bool:
    return type(value) is int


def _require_fields(value: object, fields: frozenset[str], code: str) -> dict:
    if not isinstance(value, dict) or frozenset(value) != fields:
        raise NativeSpecializationUiStatusError(code)
    return value


def _require_text(value: object, code: str) -> str:
    if not isinstance(value, str) or not value:
        raise NativeSpecializationUiStatusError(code)
    return value


def _require_bool(value: object, code: str) -> bool:
    if type(value) is not bool:
        raise NativeSpecializationUiStatusError(code)
    return value


class NativeSpecializationUiStatusReader:
    """Read and validate one immutable copy of the UI presentation DTO."""

    def __init__(
        self,
        *,
        expected_commander: str,
        expected_raw_saved: int,
        known_roots: Iterable[str],
        transport: Transport | None = None,
        timeout_seconds: float = 2.0,
    ):
        if not isinstance(expected_commander, str) or not expected_commander:
            raise ValueError("expected_commander")
        if not _is_int(expected_raw_saved) or not 0 < expected_raw_saved < 2**64:
            raise ValueError("expected_raw_saved")
        roots = tuple(known_roots)
        if (len(roots) != 3
                or any(type(root) is not str or not root for root in roots)
                or len(set(roots)) != 3):
            raise ValueError("known_roots")
        if (not isinstance(timeout_seconds, (int, float))
                or isinstance(timeout_seconds, bool)
                or not math.isfinite(timeout_seconds)
                or not 0 < timeout_seconds <= 5):
            raise ValueError("timeout_seconds")
        self.expected_commander = expected_commander
        self.expected_raw_saved = expected_raw_saved
        self.known_roots = frozenset(roots)
        self._transport = transport
        self.timeout_seconds = float(timeout_seconds)

    def _http_transport(self, language: str) -> tuple[int, bytes]:
        connection = http.client.HTTPConnection(
            HOST, PORT, timeout=self.timeout_seconds,
        )
        try:
            # HTTPConnection does not consult environment proxy settings and
            # no redirect handler exists here.  The literal host/port are an
            # intentional loopback boundary, not configurable user input.
            connection.request(
                "GET", PATH + "?language=" + quote(language, safe=""),
                headers={"Accept": "application/json"},
            )
            response = connection.getresponse()
            body = response.read(MAX_RESPONSE_BYTES + 1)
            return response.status, body
        except (OSError, http.client.HTTPException, TimeoutError):
            raise NativeSpecializationUiStatusError("transport_failed") from None
        finally:
            connection.close()

    def _fetch(self, language: str) -> bytes:
        transport = self._transport or self._http_transport
        try:
            result = transport(language)
        except NativeSpecializationUiStatusError:
            raise
        except Exception:
            raise NativeSpecializationUiStatusError("transport_failed") from None
        if (not isinstance(result, tuple) or len(result) != 2
                or type(result[0]) is not int or not isinstance(result[1], bytes)):
            raise NativeSpecializationUiStatusError("invalid_transport_result")
        status, body = result
        if status != 200:
            raise NativeSpecializationUiStatusError("http_status", status=status)
        if len(body) > MAX_RESPONSE_BYTES:
            raise NativeSpecializationUiStatusError("response_too_large")
        return body

    def read(self, language: str) -> dict:
        """Return a validated deep copy for one supported language."""
        if type(language) is not str or language not in LANGUAGES:
            raise NativeSpecializationUiStatusError("unsupported_language")
        payload = _parse_json(self._fetch(language))
        self._validate(payload, language)
        return copy.deepcopy(payload)

    def _validate(self, payload: dict, language: str) -> None:
        if frozenset(payload) != _ROOT_FIELDS:
            raise NativeSpecializationUiStatusError("invalid_root_fields")
        if payload["version"] != UI_STATUS_VERSION:
            raise NativeSpecializationUiStatusError("invalid_version")
        if payload["language"] != language:
            raise NativeSpecializationUiStatusError("language_mismatch")
        if payload["commander_key"] != self.expected_commander:
            raise NativeSpecializationUiStatusError("commander_mismatch")
        if payload["policy_version"] != POLICY_VERSION:
            raise NativeSpecializationUiStatusError("invalid_policy_version")
        raw_saved, wire_saved = payload["raw_saved"], payload["saved"]
        if (not _is_int(raw_saved) or not 0 < raw_saved < 2**64
                or raw_saved != self.expected_raw_saved
                or not _is_int(wire_saved) or not 0 <= wire_saved < 2**64
                or wire_saved != max(raw_saved, NATIVE_SAVED_FLOOR)):
            raise NativeSpecializationUiStatusError("saved_mismatch")

        if type(payload["fixed_talent_budget"]) is not int or payload["fixed_talent_budget"] != 30:
            raise NativeSpecializationUiStatusError("invalid_fixed_budget")

        balances = _require_fields(
            payload["balances"], _BALANCE_FIELDS, "invalid_balances",
        )
        if any(not _is_int(value) or value < 0 for value in balances.values()):
            raise NativeSpecializationUiStatusError("invalid_balances")
        routes_value = payload["routes"]
        if not isinstance(routes_value, list) or len(routes_value) != 3:
            raise NativeSpecializationUiStatusError("invalid_routes")
        routes: dict[str, dict] = {}
        for row in routes_value:
            route = _require_fields(row, _ROUTE_FIELDS, "invalid_route")
            root = _require_text(route["root"], "invalid_route")
            if root in routes or root not in self.known_roots:
                raise NativeSpecializationUiStatusError("unknown_route_root")
            if route["name_localization_key"] != ROUTE_NAME_KEY_PREFIX + root:
                raise NativeSpecializationUiStatusError("invalid_route_name_key")
            if not _is_int(route["capacity"]) or route["capacity"] < 1:
                raise NativeSpecializationUiStatusError("invalid_route_capacity")
            # Native completion cost is presentation data, not a per-route
            # allocation cap under the v3 open-route policy.
            if not _is_int(route["spent"]) or route["spent"] < 0:
                raise NativeSpecializationUiStatusError("invalid_route_spent")
            for key in ("selected", "locked", "completed"):
                _require_bool(route[key], "invalid_route_flags")
            routes[root] = route
        if set(routes) != set(self.known_roots):
            raise NativeSpecializationUiStatusError("route_root_set_mismatch")

        selected = payload["selected_route"]
        selected_routes = payload["selected_routes"]
        if (not isinstance(selected_routes, list)
                or any(type(root) is not str or root not in routes for root in selected_routes)
                or len(set(selected_routes)) != len(selected_routes)
                or selected != (selected_routes[0] if len(selected_routes) == 1 else None)):
            raise NativeSpecializationUiStatusError("invalid_selected_route")
        if (selected is not None
                and (type(selected) is not str or selected not in routes)):
            raise NativeSpecializationUiStatusError("invalid_selected_route")
        for root, route in routes.items():
            if (route["selected"] is not (root in selected_routes)
                    or route["selected"] is not (route["spent"] > 0)
                    or route["locked"] is not False
                    or route["completed"] is not (
                        root in selected_routes and route["spent"] >= route["capacity"]
                    )):
                raise NativeSpecializationUiStatusError("inconsistent_route_flags")
        expected_capacity = 30
        if (balances["route_capacity"] != expected_capacity
                or balances["entitled_total"] != 30
                or balances["active_total"] != 30
                or balances["spent"] != sum(route["spent"] for route in routes.values())
                or balances["banked"] != balances["entitled_total"] - balances["active_total"]
                or balances["remaining"] != balances["active_total"] - balances["spent"]
                or balances["purchasable_capacity"] != max(
                    0, expected_capacity - balances["entitled_total"])
                or balances["spent"] > balances["active_total"]):
            raise NativeSpecializationUiStatusError("inconsistent_balances")

        purchase = _require_fields(
            payload["purchase"], frozenset({"enabled", "reason", "text"}),
            "invalid_purchase_status",
        )
        if (not isinstance(purchase["reason"], str)
                or purchase["reason"] not in _PURCHASE_REASONS
                or _require_bool(purchase["enabled"], "invalid_purchase_status")
                != (purchase["reason"] == "ready")
                or not isinstance(purchase["text"], str)):
            raise NativeSpecializationUiStatusError("invalid_purchase_status")
        respec = _require_fields(
            payload["respec"],
            frozenset({"enabled", "reason", "free", "outside_battle_only", "text"}),
            "invalid_respec_status",
        )
        if (not isinstance(respec["reason"], str)
                or respec["reason"] not in _RESPEC_REASONS
                or _require_bool(respec["enabled"], "invalid_respec_status")
                != (respec["reason"] == "ready")
                or respec["free"] is not True
                or respec["outside_battle_only"] is not True
                or not isinstance(respec["text"], str)):
            raise NativeSpecializationUiStatusError("invalid_respec_status")
        banked = _require_fields(
            payload["banked"], frozenset({"visible", "count", "text"}),
            "invalid_banked_status",
        )
        if (not _is_int(banked["count"]) or banked["count"] < 0
                or banked["count"] != balances["banked"]
                or banked["visible"] is not (banked["count"] > 0)
                or not isinstance(banked["text"], str)):
            raise NativeSpecializationUiStatusError("invalid_banked_status")


__all__ = [
    "HOST", "PORT", "PATH", "MAX_RESPONSE_BYTES",
    "NativeSpecializationUiStatusError", "NativeSpecializationUiStatusReader",
]
