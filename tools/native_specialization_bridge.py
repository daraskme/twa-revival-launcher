"""Single-session host worker for native specialization button actions."""
from __future__ import annotations

import queue
import http.client
import json
import re
import threading
import time
from urllib.parse import urlencode
from dataclasses import dataclass
from typing import Callable

try:
    from . import build_native_specialization_binding as binding
    from .native_specialization_control import (
        SpecializationControlError, SpecializationController,
    )
except ImportError:  # pragma: no cover
    import build_native_specialization_binding as binding
    from native_specialization_control import (
        SpecializationControlError, SpecializationController,
    )


NATIVE_SAVED_FLOOR = 1_788_186_881_000
MODES = frozenset(("off", "observe", "enabled"))
ACTION_NAMES = {
    "revival_purchase_talent_point": "purchase_talent_point",
    "revival_respec_commander": "respec_commander",
}
MAX_EVENT_AGE_MS = 2_000
MAX_FUTURE_MS = 250
DEBOUNCE_MS = 250
ACK_PATH = "/native-probe/specialization-refresh-ack"
REFRESH_SIGNALS = frozenset(("profile_refresh_armed", "profile_refresh_arm_rejected",
                             "profile_refresh_arm_failed", "profile_refresh_consumed",
                             "profile_refresh_not_consumed",
                             "profile_refresh_observe_failed"))


def confirm_specialization_refresh(operation_id: str, saved: int,
                                   timeout: float = 0.5) -> bool:
    """Read the exact loopback post-write ACK; redirects/proxies are absent."""
    if (not isinstance(operation_id, str)
            or re.fullmatch(r"native-specialization-[0-9a-f]{32}", operation_id) is None
            or type(saved) is not int or not 0 < saved < 2**64):
        return False
    connection = http.client.HTTPConnection("127.0.0.1", 18765, timeout=timeout)
    path = ACK_PATH + "?" + urlencode({"operation_id": operation_id,
                                       "saved": str(saved)})
    try:
        connection.request("GET", path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        raw = response.read(4097)
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()
    if response.status != 200 or len(raw) > 4096:
        return False
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_ack_key")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(
                               ValueError("invalid_ack_number")))
    except (UnicodeError, ValueError, json.JSONDecodeError):
        return False
    return (isinstance(value, dict) and set(value) == {
                "result", "operation_id", "saved", "status",
                "http_response_written"}
            and value.get("result") == "ok"
            and value.get("operation_id") == operation_id
            and type(value.get("saved")) is int and value["saved"] == saved
            and value.get("status") == "specialization_refresh_resynced"
            and value.get("http_response_written") is True)


class SpecializationRefresh:
    """Arm the stock flag and require a specialization-specific HTTP ACK."""

    def __init__(self, post: Callable[[dict], None], record: Callable[[dict], None],
                 confirm: Callable[[str, int], bool] | None = None,
                 timeout: float = 2.5) -> None:
        self._post, self._record = post, record
        self._confirm = confirm or (lambda _operation, _saved: False)
        self._timeout = timeout
        self._condition = threading.Condition()
        self._signals: dict[str, list[str]] = {}
        self._post_lock = threading.Lock()
        self._closed = False

    @staticmethod
    def token(operation_id: str, saved: int) -> str:
        return f"specialization|{operation_id}|{saved}"

    def deliver(self, payload: object) -> bool:
        if not isinstance(payload, dict) or payload.get("kind") not in REFRESH_SIGNALS:
            return False
        token = payload.get("token")
        if not isinstance(token, str) or not token.startswith("specialization|"):
            return False
        with self._condition:
            self._signals.setdefault(token, []).append(payload["kind"])
            self._condition.notify_all()
        return True

    def __call__(self, operation_id: str, saved: int) -> bool:
        token = self.token(operation_id, saved)
        deadline = time.monotonic() + self._timeout
        with self._post_lock:
            if self._closed:
                return False
            self._post({"type": "arm_profile_refresh", "payload": {"token": token}})
        required = ("profile_refresh_armed", "profile_refresh_consumed")
        for expected in required:
            with self._condition:
                while expected not in self._signals.get(token, []):
                    if self._closed:
                        self._signals.pop(token, None)
                        return False
                    rows = self._signals.get(token, [])
                    if any(value.endswith(("failed", "rejected", "not_consumed"))
                           for value in rows):
                        self._signals.pop(token, None)
                        return False
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._signals.pop(token, None)
                        return False
                    self._condition.wait(remaining)
        while time.monotonic() < deadline:
            if self._closed:
                return False
            try:
                confirmed = self._confirm(operation_id, saved)
            except Exception as error:
                self._record({"event": "specialization_http_ack_check_failed",
                              "operation_id": operation_id,
                              "error": type(error).__name__})
                confirmed = False
            if confirmed:
                with self._condition:
                    self._signals.pop(token, None)
                return True
            time.sleep(0.05)
        self._record({"event": "specialization_http_ack_unavailable",
                      "operation_id": operation_id, "saved": saved})
        with self._condition:
            self._signals.pop(token, None)
        return False

    def close(self) -> None:
        with self._post_lock:
            self._closed = True
        with self._condition:
            self._signals.clear()
            self._condition.notify_all()


@dataclass(frozen=True)
class Action:
    action: str
    commander: str
    instance_id: int
    raw_saved: int
    wire_saved: int
    owner_epoch: int
    emitted_at_ms: int


class SpecializationBridge:
    """Validate quickly on submit and perform HTTP only on one worker."""

    def __init__(self, *, mode: str, controller: SpecializationController,
                 record: Callable[[dict], None],
                 refresh: Callable[[str, int], bool] | None = None,
                 commanders: dict[int, str] | None = None,
                 now_ms: Callable[[], int] | None = None,
                 queue_limit: int = 8) -> None:
        if mode not in MODES or type(queue_limit) is not int or not 1 <= queue_limit <= 32:
            raise ValueError("invalid_specialization_bridge_policy")
        self.mode = mode
        self._controller = controller
        self._record = record
        self._refresh = refresh
        self._commanders = (binding.load_commander_item_ids()
                            if commanders is None else dict(commanders))
        self._now_ms = now_ms or (lambda: time.time_ns() // 1_000_000)
        self._queue: queue.Queue[Action | None] = queue.Queue(queue_limit)
        self._lock = threading.Lock()
        self._start_lock = threading.Lock()
        self._closed = False
        self._stopping = threading.Event()
        self._last: dict[tuple[int, str], int] = {}
        self._thread = threading.Thread(target=self._run,
                                        name="twa-specialization", daemon=True)
        self._thread.start()

    def submit(self, payload: object) -> bool:
        if self.mode == "off":
            return False
        try:
            action = self._decode(payload)
        except (KeyError, TypeError, ValueError, binding.BindingBuildError) as error:
            self._record({"event": "specialization_event_rejected",
                          "reason": str(error) or type(error).__name__})
            return False
        key = (action.owner_epoch, action.action)
        with self._lock:
            if self._closed:
                return False
            previous = self._last.get(key)
            if previous is not None and action.emitted_at_ms - previous < DEBOUNCE_MS:
                self._record({"event": "specialization_event_debounced",
                              "action": action.action,
                              "commander": action.commander})
                return False
            try:
                self._queue.put_nowait(action)
            except queue.Full:
                self._record({"event": "specialization_queue_full"})
                return False
            self._last[key] = action.emitted_at_ms
        return True

    def _decode(self, payload: object) -> Action:
        if not isinstance(payload, dict) or payload.get("kind") != "specialization_ui_action":
            raise ValueError("invalid_specialization_event")
        if set(payload) != {"kind", "actionName", "ownerEpoch", "identity",
                            "emittedAtMs"}:
            raise ValueError("invalid_specialization_event")
        action = ACTION_NAMES.get(payload["actionName"])
        epoch, emitted = payload["ownerEpoch"], payload["emittedAtMs"]
        now = self._now_ms()
        if (action is None or type(epoch) is not int or not 0 < epoch < 2**31
                or type(emitted) is not int
                or emitted < now - MAX_EVENT_AGE_MS or emitted > now + MAX_FUTURE_MS):
            raise ValueError("stale_or_invalid_specialization_event")
        commander, instance_id, wire_saved = binding.decode_action_identity(
            payload["identity"], self._commanders,
        )
        definition_id = next(item for item, key in self._commanders.items()
                             if key == commander)
        if instance_id != definition_id:
            raise ValueError("displayed_commander_instance_mismatch")
        # Server I/O belongs exclusively to the worker, never Frida's message
        # callback.  raw_saved is filled only after the worker revalidates.
        return Action(action, commander, instance_id, -1, wire_saved,
                      epoch, emitted)

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is None:
                    return
                try:
                    self._perform(item)
                except Exception as error:
                    try:
                        self._record({"event": "specialization_worker_error",
                                      "error": type(error).__name__,
                                      "user_action_required": True})
                    except Exception:
                        pass
            finally:
                self._queue.task_done()

    def _perform(self, item: Action) -> None:
        now = self._now_ms()
        if (self._stopping.is_set() or item.emitted_at_ms < now - MAX_EVENT_AGE_MS
                or item.emitted_at_ms > now + MAX_FUTURE_MS):
            self._record({"event": "specialization_queued_event_expired",
                          "action": item.action, "commander": item.commander})
            return
        try:
            status = self._controller.read_status()
        except SpecializationControlError as error:
            self._record({"event": "specialization_context_read_failed",
                          "action": item.action, "commander": item.commander,
                          "reason": error.code})
            return
        raw_saved = status["saved"]
        if (status["commander_key"] != item.commander
                or max(raw_saved, NATIVE_SAVED_FLOOR) != item.wire_saved):
            self._record({"event": "specialization_context_rejected",
                          "action": item.action, "commander": item.commander,
                          "reason": "native_server_context_mismatch"})
            return
        if self._stopping.is_set():
            self._record({"event": "specialization_queued_event_cancelled",
                          "action": item.action, "commander": item.commander})
            return
        if self.mode == "observe":
            self._record({"event": "specialization_action_observed",
                          "action": item.action, "commander": item.commander,
                          "raw_saved": raw_saved})
            return
        # Serialize the mutation-start boundary with close().  Once this tiny
        # section releases, the operation is explicitly in flight; shutdown
        # must wait for it and must not unload the shared script underneath it.
        with self._start_lock:
            if self._stopping.is_set():
                self._record({"event": "specialization_queued_event_cancelled",
                              "action": item.action,
                              "commander": item.commander})
                return
        try:
            pending_reader = getattr(self._controller, "pending_click", None)
            pending_before = pending_reader() if callable(pending_reader) else None
            if pending_before is not None:
                self._record({"event": "specialization_prior_retry_required",
                              "action": item.action, "commander": item.commander})
                return
            method = getattr(self._controller, item.action)
            response = method(item.commander, raw_saved)
        except SpecializationControlError as error:
            if error.uncertain:
                pending_after = pending_reader() if callable(pending_reader) else None
                if (pending_before is not None or pending_after is None
                        or pending_after.action != item.action
                        or pending_after.commander_key != item.commander
                        or pending_after.expected_saved != raw_saved):
                    self._record({"event": "specialization_action_uncertain",
                                  "action": item.action,
                                  "commander": item.commander,
                                  "reason": "pending_operation_identity_mismatch"})
                    return
                try:
                    response = self._controller.retry_pending(
                        item.commander, raw_saved,
                    )
                except SpecializationControlError as retry_error:
                    self._record({"event": "specialization_action_uncertain",
                                  "action": item.action,
                                  "commander": item.commander,
                                  "reason": retry_error.code})
                    return
            else:
                self._record({"event": "specialization_action_rejected",
                              "action": item.action, "commander": item.commander,
                              "reason": error.code})
                return
        receipt = response["receipt"]
        operation_id, saved = receipt["operation_id"], response["saved"]
        self._record({"event": "specialization_action_committed",
                      "action": item.action, "commander": item.commander,
                      "operation_id": operation_id, "saved": saved})
        if self._stopping.is_set():
            self._record({"event": "specialization_refresh_unconfirmed",
                          "operation_id": operation_id, "saved": saved,
                          "reason": "bridge_shutdown_after_commit",
                          "user_action_required": True})
            return
        try:
            refreshed = bool(self._refresh and self._refresh(operation_id, saved))
        except Exception as error:
            self._record({"event": "specialization_refresh_failed",
                          "operation_id": operation_id, "saved": saved,
                          "error": type(error).__name__,
                          "user_action_required": True})
            refreshed = False
        self._record({"event": ("specialization_refresh_confirmed" if refreshed
                                else "specialization_refresh_unconfirmed"),
                      "operation_id": operation_id, "saved": saved,
                      "user_action_required": not refreshed})

    def wait_idle(self, timeout: float = 2.0) -> bool:
        deadline = time.monotonic() + timeout
        while self._queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.005)
        return self._queue.unfinished_tasks == 0

    def close(self, timeout: float = 12.0) -> bool:
        already_closed = False
        with self._lock:
            if self._closed:
                already_closed = True
            else:
                self._closed = True
                with self._start_lock:
                    self._stopping.set()
        refresh_close = getattr(self._refresh, "close", None)
        if callable(refresh_close):
            try:
                refresh_close()
            except Exception:
                pass
        if not already_closed:
            while True:
                try:
                    queued = self._queue.get_nowait()
                except queue.Empty:
                    break
                else:
                    self._queue.task_done()
                    if queued is not None:
                        try:
                            self._record({"event": "specialization_queued_event_cancelled",
                                          "action": queued.action,
                                          "commander": queued.commander})
                        except Exception:
                            pass
            try:
                self._queue.put_nowait(None)
            except queue.Full:  # drain above makes this defensive only
                pass
        self._thread.join(timeout)
        if self._thread.is_alive():
            try:
                self._record({"event": "specialization_worker_stop_timeout",
                              "user_action_required": True})
            except Exception:
                pass
            return False
        return True


__all__ = ["Action", "MODES", "NATIVE_SAVED_FLOOR", "SpecializationBridge",
           "SpecializationRefresh", "confirm_specialization_refresh"]
