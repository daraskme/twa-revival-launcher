"""Bounded host transport for specialization presentation data.

This is the read-only middle step between the native setup observation and a
future reviewed renderer binding.  It validates the native displayed identity
against the existing server status, reads the strict UI DTO on a worker, and
returns that DTO to the same live native owner/epoch.  It never writes native
memory and never turns presentation data into click authority.
"""
from __future__ import annotations

import copy
from collections import OrderedDict
import queue
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

try:
    from . import build_native_specialization_binding as binding
    from .client_language import current_client_language
    from .native_specialization_ui_status import (
        NativeSpecializationUiStatusError,
        NativeSpecializationUiStatusReader,
    )
    from .native_specialization_bridge import NATIVE_SAVED_FLOOR
except ImportError:  # pragma: no cover
    import build_native_specialization_binding as binding
    from client_language import current_client_language
    from native_specialization_ui_status import (
        NativeSpecializationUiStatusError,
        NativeSpecializationUiStatusReader,
    )
    from native_specialization_bridge import NATIVE_SAVED_FLOOR


OWNER_RE = re.compile(r"0x[0-9a-f]{1,8}\Z")
MAX_SETUP_AGE_MS = 2_000
MAX_SETUP_FUTURE_MS = 250
MAX_QUEUE = 8
MAX_OWNER_TOMBSTONES = 256


def load_known_specialization_roots(root: Path) -> dict[str, tuple[str, ...]]:
    """Derive the reviewed three roots per commander from read-only catalogues."""
    try:
        from .commander_specialization_policy import derive_policies
        from .f2p_fake import load_native_hangar
        from .native_commander_talents import load_native_commander_talents
    except ImportError:  # pragma: no cover
        from commander_specialization_policy import derive_policies
        from f2p_fake import load_native_hangar
        from native_commander_talents import load_native_commander_talents
    native = load_native_hangar(root / "catalog" / "native_hangar.json")
    talents = load_native_commander_talents(
        root / "catalog" / "native_commander_talents.json",
    )
    return {key: tuple(policy.roots)
            for key, policy in derive_policies(native, talents).items()}


@dataclass(frozen=True)
class Setup:
    owner: str
    owner_epoch: int
    identity: dict
    commander: str
    wire_saved: int
    emitted_at_ms: int
    view_seq: int = 0


class SpecializationPresentation:
    """Consume setup events and return validated DTOs asynchronously."""

    def __init__(
        self,
        *,
        post: Callable[[dict], None],
        controller: object,
        record: Callable[[dict], None],
        client_root: Path,
        known_roots: dict[str, Iterable[str]],
        commanders: dict[int, str] | None = None,
        now_ms: Callable[[], int] | None = None,
        queue_limit: int = 4,
    ) -> None:
        if (not callable(post) or not callable(record)
                or not isinstance(client_root, Path)
                or type(queue_limit) is not int
                or not 1 <= queue_limit <= MAX_QUEUE):
            raise ValueError("invalid_specialization_presentation_policy")
        roots = {key: tuple(value) for key, value in known_roots.items()}
        if (not roots or any(
                len(value) != 3 or len(set(value)) != 3
                or any(type(root) is not str or not root for root in value)
                for value in roots.values())):
            raise ValueError("invalid_specialization_presentation_roots")
        self._post = post
        self._controller = controller
        self._record = record
        self._client_root = client_root
        self._known_roots = {key: tuple(value) for key, value in roots.items()}
        self._commanders = (binding.load_commander_item_ids()
                            if commanders is None else dict(commanders))
        self._now_ms = now_ms or (lambda: time.time_ns() // 1_000_000)
        self._queue: queue.Queue[Setup | None] = queue.Queue(queue_limit)
        self._lock = threading.Lock()
        self._closed = False
        # The address can be reused by a later native panel.  Retain only the
        # last destroyed epoch, so a new generation is not permanently
        # rejected and an old destructor cannot invalidate it.
        self._invalid_owners: OrderedDict[str, int] = OrderedDict()
        self._latest_epochs: dict[str, int] = {}
        self._latest_views: dict[str, tuple[int, int]] = {}
        self._next_view_seq = 1
        self._pending: dict[tuple[str, int], dict] = {}
        self._post_gate = threading.Lock()
        self._thread = threading.Thread(
            target=self._run, name="twa-specialization-presentation", daemon=True,
        )
        self._thread.start()

    def submit_setup(self, payload: object) -> bool:
        try:
            setup = self._decode_setup(payload)
            with self._lock:
                if (self._closed
                        or setup.owner_epoch < self._latest_epochs.get(
                            setup.owner, 0)
                        or setup.owner_epoch <= self._invalid_owners.get(
                            setup.owner, 0)):
                    return False
                # A later native generation proves this address was reused;
                # the old tombstone is no longer needed.
                self._invalid_owners.pop(setup.owner, None)
                view_seq = self._next_view_seq
                self._next_view_seq += 1
                setup = Setup(
                    setup.owner, setup.owner_epoch, setup.identity,
                    setup.commander, setup.wire_saved, setup.emitted_at_ms,
                    view_seq,
                )
                self._latest_epochs[setup.owner] = max(
                    setup.owner_epoch, self._latest_epochs.get(setup.owner, 0),
                )
                self._latest_views[setup.owner] = (setup.owner_epoch, view_seq)
                for key in tuple(self._pending):
                    if key[0] == setup.owner:
                        self._pending.pop(key, None)
                self._queue.put_nowait(setup)
        except (KeyError, TypeError, ValueError, binding.BindingBuildError,
                queue.Full) as error:
            self._record({
                "event": "specialization_ui_setup_dropped",
                "reason": str(error) or type(error).__name__,
            })
            return False
        return True

    def owner_destroyed(self, payload: object) -> bool:
        if (not isinstance(payload, dict)
                or set(payload) != {"kind", "owner", "ownerEpoch"}
                or payload.get("kind") != "specialization_ui_owner_destroyed"
                or not isinstance(payload["owner"], str)
                or OWNER_RE.fullmatch(payload["owner"]) is None
                or type(payload["ownerEpoch"]) is not int
                or not 0 < payload["ownerEpoch"] < 2**31):
            return False
        owner, epoch = payload["owner"], payload["ownerEpoch"]
        with self._lock:
            if epoch < self._latest_epochs.get(owner, epoch):
                return True
            self._latest_epochs[owner] = max(epoch, self._latest_epochs.get(owner, 0))
            self._invalid_owners.pop(owner, None)
            self._invalid_owners[owner] = epoch
            latest_view = self._latest_views.get(owner)
            if latest_view is not None and latest_view[0] <= epoch:
                self._latest_views.pop(owner, None)
            for key in tuple(self._pending):
                if key[0] == owner and key[1] <= epoch:
                    self._pending.pop(key, None)
            self._latest_epochs.pop(owner, None)
            while len(self._invalid_owners) > MAX_OWNER_TOMBSTONES:
                self._invalid_owners.popitem(last=False)
        return True

    def accept_receipt(self, payload: object) -> bool:
        if (not isinstance(payload, dict)
                or set(payload) != {"kind", "owner", "ownerEpoch", "identity", "status"}
                or payload.get("kind") != "specialization_ui_status_received"
                or not isinstance(payload.get("owner"), str)
                or OWNER_RE.fullmatch(payload["owner"]) is None
                or type(payload.get("ownerEpoch")) is not int
                or not isinstance(payload.get("identity"), dict)
                or not isinstance(payload.get("status"), dict)):
            return False
        key = (payload["owner"], payload["ownerEpoch"])
        with self._lock:
            expected = self._pending.get(key)
            if (expected is None
                    or payload["ownerEpoch"] <= self._invalid_owners.get(
                        payload["owner"], 0)):
                self._record({
                    "event": "specialization_ui_status_receipt_dropped",
                    "reason": "stale_owner_or_unrequested",
                })
                return False
        if (payload["identity"] != expected["identity"]
                or payload["status"] != expected["status"]):
            self._record({
                "event": "specialization_ui_status_receipt_dropped",
                "reason": ("identity_changed"
                           if payload["identity"] != expected["identity"]
                           else "status_changed"),
            })
            return False
        with self._lock:
            # Consume only after every receipt field has matched.  A stale or
            # modified receipt must not destroy a valid in-flight response.
            if self._pending.get(key) != expected:
                return False
            self._pending.pop(key, None)
        self._record({
            "event": "specialization_ui_status_received",
            "ownerEpoch": payload["ownerEpoch"],
            "language": payload["status"].get("language"),
            "version": payload["status"].get("version"),
            "runtime_verified": False,
        })
        return True

    def _decode_setup(self, payload: object) -> Setup:
        if (not isinstance(payload, dict)
                or set(payload) != {"kind", "owner", "ownerEpoch", "identity", "emittedAtMs"}
                or payload.get("kind") != "specialization_ui_setup"):
            raise ValueError("invalid_specialization_ui_setup")
        owner, epoch, emitted = payload["owner"], payload["ownerEpoch"], payload["emittedAtMs"]
        if (not isinstance(owner, str) or OWNER_RE.fullmatch(owner) is None
                or type(epoch) is not int or not 0 < epoch < 2**31
                or type(emitted) is not int):
            raise ValueError("invalid_specialization_ui_setup")
        commander, _instance_id, wire_saved = binding.decode_action_identity(
            payload["identity"], self._commanders,
        )
        identity = copy.deepcopy(payload["identity"])
        return Setup(owner, epoch, identity, commander, wire_saved, emitted)

    def _run(self) -> None:
        while True:
            setup = self._queue.get()
            try:
                if setup is None:
                    return
                try:
                    self._perform(setup)
                except Exception as error:
                    self._record({
                        "event": "specialization_ui_setup_failed",
                        "reason": type(error).__name__,
                    })
            finally:
                self._queue.task_done()

    def wait_idle(self, timeout: float = 2.0) -> bool:
        deadline = time.monotonic() + timeout
        while self._queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.005)
        return self._queue.unfinished_tasks == 0

    def _perform(self, setup: Setup) -> None:
        now = self._now_ms()
        if (setup.emitted_at_ms < now - MAX_SETUP_AGE_MS
                or setup.emitted_at_ms > now + MAX_SETUP_FUTURE_MS):
            self._record({"event": "specialization_ui_setup_dropped",
                          "reason": "stale_setup"})
            return
        try:
            current = self._controller.read_status()
        except Exception as error:
            self._record({"event": "specialization_ui_context_read_failed",
                          "reason": type(error).__name__})
            return
        raw_saved = current.get("saved") if isinstance(current, dict) else None
        if (not isinstance(current, dict)
                or current.get("commander_key") != setup.commander
                or type(raw_saved) is not int
                or not 0 < raw_saved < 2**64
                or max(raw_saved, NATIVE_SAVED_FLOOR) != setup.wire_saved):
            self._record({"event": "specialization_ui_setup_dropped",
                          "reason": "native_server_context_mismatch"})
            return
        roots = self._known_roots.get(setup.commander)
        if roots is None:
            self._record({"event": "specialization_ui_setup_dropped",
                          "reason": "unknown_commander_policy"})
            return
        try:
            language = current_client_language(self._client_root).lower()
            reader = NativeSpecializationUiStatusReader(
                expected_commander=setup.commander,
                expected_raw_saved=raw_saved,
                known_roots=roots,
            )
            status = reader.read(language)
        except (NativeSpecializationUiStatusError, OSError, ValueError) as error:
            self._record({"event": "specialization_ui_status_read_failed",
                          "reason": type(error).__name__})
            return
        raw_saved, wire_saved = status.get("raw_saved"), status.get("saved")
        if (type(raw_saved) is not int or not 0 < raw_saved < 2**64
                or type(wire_saved) is not int or not 0 <= wire_saved < 2**64):
            self._record({"event": "specialization_ui_status_read_failed",
                          "reason": "invalid_saved_generation"})
            return
        # Frida's JavaScript transport uses Number for ordinary JSON numbers.
        # Keep both uint64 generations exact across that boundary; the native
        # receipt path does not interpret or authorize these strings.
        native_status = copy.deepcopy(status)
        native_status["raw_saved"] = str(raw_saved)
        native_status["saved"] = str(wire_saved)
        key = (setup.owner, setup.owner_epoch)
        # Serialise the close transition with the start of post().  This
        # prevents a slow HTTP read from publishing after teardown begins.
        with self._post_gate:
            with self._lock:
                if (self._closed
                        or setup.owner_epoch <= self._invalid_owners.get(
                            setup.owner, 0)
                        or self._latest_views.get(setup.owner) != (
                            setup.owner_epoch, setup.view_seq)):
                    return
                self._pending[key] = {
                    "identity": copy.deepcopy(setup.identity),
                    "status": copy.deepcopy(native_status),
                    "view_seq": setup.view_seq,
                }
            try:
                self._post({
                    "type": "specialization_ui_status",
                    "payload": {
                        "owner": setup.owner,
                        "ownerEpoch": setup.owner_epoch,
                        "identity": setup.identity,
                        "status": native_status,
                    },
                })
            except Exception as error:
                with self._lock:
                    self._pending.pop(key, None)
                self._record({"event": "specialization_ui_status_post_failed",
                              "reason": type(error).__name__})

    def close(self, timeout: float = 2.0) -> bool:
        with self._post_gate:
            with self._lock:
                if self._closed:
                    return not self._thread.is_alive()
                self._closed = True
                self._invalid_owners.clear()
                self._latest_epochs.clear()
                self._latest_views.clear()
                self._pending.clear()
                while True:
                    try:
                        self._queue.get_nowait()
                    except queue.Empty:
                        break
                    else:
                        self._queue.task_done()
                self._queue.put_nowait(None)
        self._thread.join(timeout)
        return not self._thread.is_alive()


__all__ = ["Setup", "SpecializationPresentation",
           "load_known_specialization_roots"]
