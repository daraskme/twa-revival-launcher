#!/usr/bin/env python3
"""Persist native Arena unit drag/drop gestures through the local economy.

The stock retired client updates its unit-card selection locally but emits no
HTTP mutation.  This loopback companion combines the native unit-card identity
with a real Windows gesture (list press -> movement -> squad-slot release), then
asks the local server to apply its normal ownership/faction checks.  Requiring
the physical gesture prevents an ordinary card click from changing a squad.
"""

from __future__ import annotations

import argparse
import copy
import ctypes
import hashlib
import json
import os
import queue
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from ctypes import wintypes
from pathlib import Path
from typing import Callable


# Direct script execution places only ``tools`` on sys.path.  The reviewed
# specialization host imports ``companion.client_lock`` through
# ``client_language``; pin the repository containing this exact script before
# any optional host imports instead of relying on cwd or inherited PYTHONPATH.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SPECIALIZATION_PREFLIGHT_REFUSED_EXIT = 78


SOURCE = r"""
const game = Process.getModuleByName('game.dll');
const expectedGameDllPath = __EXPECTED_GAME_DLL_PATH__;

function normalizedWindowsPath(value) {
  return value.replaceAll('/', '\\').toLowerCase();
}
if (normalizedWindowsPath(game.path) !==
    normalizedWindowsPath(expectedGameDllPath)) {
  send({kind:'fatal_module_path_mismatch', actual:game.path,
        expected:expectedGameDllPath});
  throw new Error('loaded game.dll is not the reviewed Revival copy');
}

function bytesHex(address, length) {
  const values = new Uint8Array(address.readByteArray(length));
  return Array.from(values, value => value.toString(16).padStart(2, '0')).join('');
}

// Validate the exact current v30 bytes before installing any Interceptor.
// This rejects an already-hooked or otherwise modified in-memory module even
// when the on-disk file still has the approved hash.
const hookAnchors = [
  [0xdbd7e0, '558bec566a018bf1e8e3c30100ff7508'],
  [0xdb68c0, '558bec5de9b7d70b00cccccccccccccc'],
  [0xdc1138, 'e8d3b2d8ff8b45e8c683df02000001'],
];
for (const [rva, expected] of hookAnchors) {
  const actual = bytesHex(game.base.add(rva), expected.length / 2);
  if (actual !== expected) {
    send({kind:'fatal_hook_anchor_mismatch', rva, expected, actual});
    throw new Error('unit-drag hook anchor mismatch at RVA 0x' +
                    rva.toString(16));
  }
}

// The shipped client already has a deferred, main-thread profile refresh
// command.  Its console callback at RVA 0xc47df0 only sets this byte; the
// normal frame update at RVA 0xc5b4e0 consumes it and performs the request on
// the game's own thread.  The bridge mirrors that single-byte callback after
// a durable unit save.  It deliberately never creates a native-call wrapper
// and never interrupts an arbitrary game thread.
const PROFILE_REFRESH_FLAG_RVA = 0x1b04081;
const profileRefreshFlag = game.base.add(PROFILE_REFRESH_FLAG_RVA);

function observeProfileRefreshConsumption(token, attempts) {
  setTimeout(() => {
    try {
      const value = profileRefreshFlag.readU8();
      if (value === 0) {
        send({kind:'profile_refresh_consumed', token});
      } else if (attempts > 0) {
        observeProfileRefreshConsumption(token, attempts - 1);
      } else {
        send({kind:'profile_refresh_not_consumed', token, value});
      }
    } catch (error) {
      send({kind:'profile_refresh_observe_failed', token,
            error:String(error)});
    }
  }, 25);
}

function receiveProfileRefreshArm() {
  recv('arm_profile_refresh', message => {
    const payload = message && message.payload;
    const token = payload && payload.token;
    try {
      const before = profileRefreshFlag.readU8();
      if (before !== 0 && before !== 1) {
        send({kind:'profile_refresh_arm_rejected', token, before});
      } else {
        // A value of one means the stock frame consumer has not run yet.  A
        // second save can safely share that pending fetch because the fetch
        // reads the latest authoritative profile.
        if (before === 0) profileRefreshFlag.writeU8(1);
        send({kind:'profile_refresh_armed', token,
              coalesced:before === 1});
        observeProfileRefreshConsumption(token, 80);
      }
    } catch (error) {
      send({kind:'profile_refresh_arm_failed', token,
            error:String(error)});
    }
    receiveProfileRefreshArm();
  });
}

function u32(pointer, offset) {
  try { return pointer.add(offset).readU32(); } catch (_) { return null; }
}

function stdString(pointer) {
  try {
    const length = pointer.add(16).readU32();
    const capacity = pointer.add(20).readU32();
    if (length === 0 || length > 256) return null;
    const data = capacity >= 16 ? pointer.readPointer() : pointer;
    return data.readUtf8String(length);
  } catch (_) { return null; }
}

// DBD7E0 is entered by the real UnitCard drag gesture with ECX already set to
// its UnitModel (vtable RVA 0x146d068). Its exact item-id halves are
// +0x38/+0x3c. Capturing here binds identity to the user's held card and
// removes all timing ambiguity from the later UI selection animation.
Interceptor.attach(game.base.add(0xdbd7e0), {
  onEnter() {
    try {
      const model = this.context.ecx;
      const lo = u32(model, 0x38);
      const hi = u32(model, 0x3c);
      if (lo !== null && hi !== null) {
        send({kind:'unit_drag_source', lo:String(lo), hi:String(hi),
              emitted_at_ms:Date.now()});
      }
    } catch (_) {}
  }
});

// Some already-instantiated cards bypass DBD7E0 on later drags. DB68C0 is
// their common event dispatcher and is observed at mouse-down for both fresh
// and reused cards. Python only accepts this identity while the button is
// physically held from the source-list region, so hover/redraw dispatches
// cannot mutate a loadout.
Interceptor.attach(game.base.add(0xdb68c0), {
  onEnter() {
    const model = this.context.ecx;
    const lo = u32(model, 0x38);
    const hi = u32(model, 0x3c);
    if (lo !== null && hi !== null) {
      send({kind:'unit_drag_source', lo:String(lo), hi:String(hi),
            emitted_at_ms:Date.now()});
    }
  }
});

// DC0FA0 is the stock Army-panel drop handler. Immediately before this call
// it pushes: pointer-to-unit-key std::string, direction, zero. Reading that
// already-resolved key is both cheaper and more reliable than re-clicking the
// source card after mouse-up.
Interceptor.attach(game.base.add(0xdc1138), {
  onEnter() {
    try {
      const keyPointer = this.context.esp.readPointer();
      const key = stdString(keyPointer);
      if (key !== null) {
        send({kind:'unit_drop_key', key, emitted_at_ms:Date.now(),
              direction:u32(this.context.esp, 4),
              third:u32(this.context.esp, 8)});
      }
    } catch (_) {}
  }
});

receiveProfileRefreshArm();
send({kind:'hooks_ready'});
"""


LOADOUT_URL = "http://127.0.0.1:18765/native-probe/loadout/unit"
EXPECTED_GAME_DLL_SHA256S = frozenset({
    # Reviewed copied-client v30 baseline.
    "ce6b75a00898fa2da801b81d37943fa8c2fc879980f4600a1be502e5a50f2e3e",
    # Work-only native five-mode candidate; static/diff/relocation audit only.
    "0adc72669de2037b5c5087d049fb634740a82ebe6a0e507209a935dc86f06d19",
    # Above candidate plus reviewed three-byte commander-minimum-tier experiment.
    "e4753697feaaa62ce871af27b346a232d306d5d5a45ac4401194bd39a1d40750",
    # Reviewed combined commander-tier and six-additional-ability candidate.
    "be3c79e460fe797b69e3ff571fa7a89d3b4bbbe668149e27fc0b9297ba36179f",
    # Reviewed commander battle-tier comparison candidate derived from the
    # combined candidate above.
    "bbd407fbb910c02520afb160328ccb71f115a6861ca99132db488219eb0b9853",
    # Reviewed commander record-tier comparison candidate derived from bbd.
    "b41fe1b5ed2c055e7d2078254123d536a37186fa5c7aa9783c5b206cb50ebe9f",
    # Reviewed Recent Players fallback; existing hook anchors are unchanged.
    "4e622f6934e0ba552b93ef546bec5dacdb0d7ae47d28b0c823959b52fdd08f15",
    # Existing reviewed private-response DLL retained on the peer PC.
    '4fc11b6e734042ee0c7d0df54bc5c7f689f2d7842c450e4df541e22310804013',
    'f760ece7869a3e254376f927ee610675cab8112fafb502c6c18e90c30664fc0c',
    '884e30f841d6a1268b7cc918fa2d14b972f007ce593b957fd3d1ee93c75cbf0a',
    'b5d1547b720fd03f1e55e76e2d41b531d2d72e0b4a6270c73223018b8cd45e06',
})
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
ERROR_ALREADY_EXISTS = 183
BRIDGE_MUTEX_PREFIX = "Local\\TWARevivalUnitDragBridge-"
PROFILE_REFRESH_MAX_ATTEMPTS = 4
PROFILE_REFRESH_ARM_TIMEOUT_SECONDS = 1.0
PROFILE_REFRESH_OBSERVE_TIMEOUT_SECONDS = 2.5
PROFILE_REFRESH_SERVER_ACK_POLL_SECONDS = 0.05
# The server's receipt-correlated external gate lasts 10 seconds.  Stop before
# that authority can expire; a later blind arm could provoke an ordinary stale
# profile replacement instead of the reviewed correlated ok_resync path.
PROFILE_REFRESH_TOTAL_TIMEOUT_SECONDS = 8.0
PROFILE_REFRESH_BACKOFF_SECONDS = (0.15, 0.3, 0.6, 0.75)
NATIVE_DROP_GRACE_SECONDS = 0.05
OWNED_START_TIMEOUT_SECONDS = 15.0
NATIVE_READY_TIMEOUT_SECONDS = 30.0

_PROFILE_REFRESH_ARM_SIGNALS = {
    "profile_refresh_armed",
    "profile_refresh_arm_rejected",
    "profile_refresh_arm_failed",
}
_PROFILE_REFRESH_OBSERVE_SIGNALS = {
    "profile_refresh_consumed",
    "profile_refresh_not_consumed",
    "profile_refresh_observe_failed",
}
_PROFILE_REFRESH_SIGNALS = (
    _PROFILE_REFRESH_ARM_SIGNALS | _PROFILE_REFRESH_OBSERVE_SIGNALS
)


class ProfileRefreshCoordinator:
    """Drive one latest-wins stock profile refresh without blocking input.

    A unit write is already durable when this coordinator is called.  Frida's
    arm acknowledgement only proves that the stock byte was (or already was)
    one; it does not prove that the frame loop consumed it.  The coordinator
    therefore waits for both the separately tokened consumption observation
    and the server's exact operation/saved ``external_refresh_resynced``
    acknowledgement.  Neither signal is described as visual UI application;
    that remains a screenshot-based live acceptance check.  A newer saved
    watermark supersedes the older job before any further old-token post can
    be dispatched.
    """

    def __init__(
        self,
        post: Callable[[dict], None],
        confirm_server: Callable[[str, str], bool],
        record: Callable[[dict], None],
        *,
        max_attempts: int = PROFILE_REFRESH_MAX_ATTEMPTS,
        arm_timeout: float = PROFILE_REFRESH_ARM_TIMEOUT_SECONDS,
        observe_timeout: float = PROFILE_REFRESH_OBSERVE_TIMEOUT_SECONDS,
        server_ack_poll: float = PROFILE_REFRESH_SERVER_ACK_POLL_SECONDS,
        total_timeout: float = PROFILE_REFRESH_TOTAL_TIMEOUT_SECONDS,
        backoffs: tuple[float, ...] = PROFILE_REFRESH_BACKOFF_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if (type(max_attempts) is not int or max_attempts <= 0
                or arm_timeout <= 0 or observe_timeout <= 0
                or server_ack_poll <= 0
                or total_timeout <= 0 or not backoffs
                or any(value < 0 for value in backoffs)
                or not callable(confirm_server)):
            raise ValueError("invalid_profile_refresh_policy")
        self._post = post
        self._confirm_server = confirm_server
        self._record = record
        self._max_attempts = max_attempts
        self._arm_timeout = arm_timeout
        self._observe_timeout = observe_timeout
        self._server_ack_poll = server_ack_poll
        self._total_timeout = total_timeout
        self._backoffs = backoffs
        self._clock = clock
        self._condition = threading.Condition()
        # request() and the pre-post generation check share this lock.  Once a
        # newer request returns, an older worker can no longer post another arm.
        self._dispatch_lock = threading.Lock()
        self._token: str | None = None
        self._operation_id: str | None = None
        self._token_value = -1
        self._generation = 0
        self._deadline = 0.0
        self._signals: list[dict] = []
        self._outcomes: dict[str, str] = {}
        self._stopping = False
        self._thread = threading.Thread(
            target=self._run,
            name="twa-profile-refresh",
            daemon=True,
        )
        self._thread.start()

    def request(self, token: str, operation_id: str) -> bool:
        """Schedule a newer saved watermark; equal/older requests are ignored."""
        try:
            token_value = int(token)
        except (TypeError, ValueError):
            raise ValueError("invalid_profile_refresh_token") from None
        if (str(token_value) != token or not 0 < token_value < 2**64
                or not isinstance(operation_id, str)
                or not operation_id):
            raise ValueError("invalid_profile_refresh_token")
        superseded: str | None = None
        with self._dispatch_lock:
            with self._condition:
                if token_value <= self._token_value:
                    ignored = True
                else:
                    ignored = False
                    superseded = self._token
                    if superseded is not None:
                        self._set_outcome_locked(superseded, "superseded")
                    self._token = token
                    self._operation_id = operation_id
                    self._token_value = token_value
                    self._generation += 1
                    self._deadline = self._clock() + self._total_timeout
                    self._signals.clear()
                    self._condition.notify_all()
        if ignored:
            self._record({
                "event": "stale_profile_refresh_request_ignored",
                "token": token,
                "latest_token": str(self._token_value),
            })
            return False
        if superseded is not None:
            self._record({
                "event": "profile_refresh_superseded",
                "token": superseded,
                "newer_token": token,
            })
        self._record({
            "event": "profile_refresh_scheduled",
            "token": token,
            "operation_id": operation_id,
        })
        return True

    def deliver(self, payload: dict) -> bool:
        """Accept only a recognized signal for the currently newest token."""
        kind = payload.get("kind") if isinstance(payload, dict) else None
        token = payload.get("token") if isinstance(payload, dict) else None
        if kind not in _PROFILE_REFRESH_SIGNALS or not isinstance(token, str):
            return False
        with self._condition:
            if token != self._token:
                current = self._token
                accepted = False
            else:
                current = token
                accepted = True
                self._signals.append(dict(payload))
                # Bound duplicate messages from repeated observers.
                del self._signals[:-32]
                self._condition.notify_all()
        if not accepted:
            self._record({
                "event": "stale_profile_refresh_signal_ignored",
                "token": token,
                "current_token": current,
                "kind": kind,
            })
        return accepted

    def wait_terminal(self, token: str, timeout: float) -> str | None:
        """Wait for a test/operator-visible terminal outcome."""
        deadline = time.monotonic() + timeout
        with self._condition:
            while token not in self._outcomes:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._condition.wait(remaining)
            return self._outcomes[token]

    def close(self, timeout: float = 2.0) -> None:
        with self._condition:
            self._stopping = True
            self._condition.notify_all()
        self._thread.join(timeout)
        if self._thread.is_alive():
            self._record({
                "event": "profile_refresh_worker_stop_timeout",
                "user_action_required": True,
            })

    def _set_outcome_locked(self, token: str, outcome: str) -> None:
        self._outcomes[token] = outcome
        while len(self._outcomes) > 16:
            del self._outcomes[next(iter(self._outcomes))]
        self._condition.notify_all()

    def _is_current_locked(self, token: str, generation: int) -> bool:
        return (not self._stopping and self._token == token
                and self._generation == generation)

    def _wait_signal(
        self,
        token: str,
        generation: int,
        kinds: set[str],
        timeout: float,
    ) -> dict | None:
        deadline = min(self._deadline, self._clock() + timeout)
        with self._condition:
            while self._is_current_locked(token, generation):
                for index, signal in enumerate(self._signals):
                    if signal.get("kind") in kinds:
                        return self._signals.pop(index)
                remaining = deadline - self._clock()
                if remaining <= 0:
                    return None
                self._condition.wait(remaining)
        return None

    def _wait_backoff(
        self, token: str, generation: int, seconds: float,
    ) -> bool:
        deadline = min(self._deadline, self._clock() + seconds)
        with self._condition:
            while self._is_current_locked(token, generation):
                remaining = deadline - self._clock()
                if remaining <= 0:
                    return self._clock() < self._deadline
                self._condition.wait(remaining)
            return False

    def _dispatch(self, token: str, generation: int) -> bool:
        with self._dispatch_lock:
            with self._condition:
                if not self._is_current_locked(token, generation):
                    return False
            self._post({
                "type": "arm_profile_refresh",
                "payload": {"token": token},
            })
        return True

    def _finish(self, token: str, generation: int, outcome: str) -> bool:
        with self._condition:
            if not self._is_current_locked(token, generation):
                return False
            self._set_outcome_locked(token, outcome)
            self._token = None
            self._operation_id = None
            self._signals.clear()
            return True

    def _wait_server_resync(
        self,
        token: str,
        operation_id: str,
        generation: int,
    ) -> tuple[bool, str]:
        """Poll the loopback control until its exact server ack appears."""
        # Once the game's frame loop consumes the byte, never arm it again:
        # a slow first response could otherwise be overtaken by a duplicate
        # profile request. Spend the remainder of the one bounded job waiting
        # for this exact operation/saved HTTP-write acknowledgement.
        deadline = self._deadline
        last_reason = "server_profile_resync_unconfirmed"
        while True:
            with self._condition:
                if not self._is_current_locked(token, generation):
                    return False, "profile_refresh_superseded"
                if self._clock() >= deadline:
                    return False, last_reason
            try:
                confirmed = self._confirm_server(token, operation_id)
            except Exception as error:
                confirmed = False
                last_reason = (
                    "server_profile_status_failed:"
                    + type(error).__name__
                )
            if confirmed is True:
                return True, "external_refresh_resynced"
            if type(confirmed) is not bool:
                last_reason = "invalid_server_profile_status"
            wait_until = min(deadline, self._clock() + self._server_ack_poll)
            with self._condition:
                while self._is_current_locked(token, generation):
                    remaining = wait_until - self._clock()
                    if remaining <= 0:
                        break
                    self._condition.wait(remaining)

    def _confirm_consumed_request(
        self,
        token: str,
        operation_id: str,
        generation: int,
        attempt: int,
    ) -> tuple[bool, str]:
        self._record({
            "event": "profile_refresh_request_consumed",
            "token": token,
            "operation_id": operation_id,
            "attempt": attempt,
        })
        confirmed, reason = self._wait_server_resync(
            token, operation_id, generation,
        )
        if not confirmed:
            return False, reason
        if self._finish(token, generation, "server_resynced"):
            self._record({
                "event": "profile_refresh_server_resynced",
                "token": token,
                "operation_id": operation_id,
                "attempt": attempt,
                "http_response_written": True,
                "ui_apply_confirmed": False,
            })
        return True, reason

    def _run_job(
        self, token: str, operation_id: str, generation: int,
    ) -> None:
        last_reason = "profile_refresh_deadline_expired"
        attempts_run = 0
        request_consumed = False
        for attempt in range(1, self._max_attempts + 1):
            with self._condition:
                if not self._is_current_locked(token, generation):
                    return
                if self._clock() >= self._deadline:
                    break
            attempts_run = attempt
            try:
                if not self._dispatch(token, generation):
                    return
            except Exception as error:
                last_reason = "post_failed:" + type(error).__name__
            else:
                signal = self._wait_signal(
                    token,
                    generation,
                    _PROFILE_REFRESH_SIGNALS,
                    self._arm_timeout,
                )
                if signal is None:
                    with self._condition:
                        if not self._is_current_locked(token, generation):
                            return
                    last_reason = "profile_refresh_arm_timeout"
                elif signal["kind"] == "profile_refresh_consumed":
                    request_consumed = True
                    confirmed, last_reason = self._confirm_consumed_request(
                        token, operation_id, generation, attempt,
                    )
                    if confirmed:
                        return
                    break
                elif signal["kind"] != "profile_refresh_armed":
                    last_reason = signal["kind"]
                    if "before" in signal:
                        last_reason += ":before=" + str(signal.get("before"))
                    if signal.get("error"):
                        last_reason += ":" + str(signal["error"])
                else:
                    self._record({
                        "event": "profile_refresh_armed",
                        "token": token,
                        "attempt": attempt,
                        "coalesced": bool(signal.get("coalesced")),
                    })
                    observed = self._wait_signal(
                        token,
                        generation,
                        _PROFILE_REFRESH_OBSERVE_SIGNALS,
                        self._observe_timeout,
                    )
                    if observed is None:
                        with self._condition:
                            if not self._is_current_locked(token, generation):
                                return
                        last_reason = "profile_refresh_observe_timeout"
                    elif observed["kind"] == "profile_refresh_consumed":
                        request_consumed = True
                        confirmed, last_reason = (
                            self._confirm_consumed_request(
                                token, operation_id, generation, attempt,
                            )
                        )
                        if confirmed:
                            return
                        break
                    else:
                        last_reason = observed["kind"]
                        if observed.get("error"):
                            last_reason += ":" + str(observed["error"])
            if attempt < self._max_attempts:
                self._record({
                    "event": "profile_refresh_retry",
                    "token": token,
                    "attempt": attempt + 1,
                    "reason": last_reason,
                })
                backoff = self._backoffs[min(
                    attempt - 1, len(self._backoffs) - 1,
                )]
                if not self._wait_backoff(token, generation, backoff):
                    with self._condition:
                        if not self._is_current_locked(token, generation):
                            return
                    break

        if self._finish(token, generation, "failed"):
            message = (
                "Unit selection was saved, but the live Arena profile refresh "
                "could not be confirmed. The current hangar view may be stale; "
                "inspect the unit-drag log before making another change."
            )
            self._record({
                "event": "profile_refresh_terminal_failure",
                "token": token,
                "attempts": attempts_run,
                "reason": last_reason,
                "request_consumed": request_consumed,
                "server_profile_resynced": False,
                "ui_apply_confirmed": False,
                "user_action_required": True,
                "message": message,
            })
            print("TWA unit-drag warning: " + message, flush=True)

    def _run(self) -> None:
        while True:
            with self._condition:
                while self._token is None and not self._stopping:
                    self._condition.wait()
                if self._stopping:
                    return
                token = self._token
                operation_id = self._operation_id
                generation = self._generation
            assert token is not None
            assert operation_id is not None
            try:
                self._run_job(token, operation_id, generation)
            except Exception as error:
                # A coordinator bug must not terminate the supervisor loop.
                if self._finish(token, generation, "failed"):
                    self._record({
                        "event": "profile_refresh_worker_error",
                        "token": token,
                        "error": type(error).__name__,
                        "reason": str(error),
                        "user_action_required": True,
                    })


def build_agent_source(root: Path, specialization_mode: str = "off") -> str:
    """Bind the instrumentation source to this copy's loaded game.dll path."""
    marker = "__EXPECTED_GAME_DLL_PATH__"
    if SOURCE.count(marker) != 1:
        raise RuntimeError("invalid_agent_source_template")
    expected = str((root / "client" / "game.dll").resolve())
    source = SOURCE.replace(marker, json.dumps(expected))
    if specialization_mode == "off":
        return source
    if specialization_mode not in {"observe", "enabled"}:
        raise ValueError("invalid_specialization_mode")
    try:
        from . import build_native_specialization_binding as specialization_binding
    except ImportError:
        import build_native_specialization_binding as specialization_binding
    specialization_binding.validate_game(root / "client" / "game.dll")
    return (source + "\n" + specialization_binding.build_source(
        root / "client" / "game.dll",
    ) + "\nsend({kind:'specialization_host_ready'});\n")


def _load_specialization_host(root: Path):
    """Load all enabled-mode host dependencies without native interaction."""
    try:
        from .native_specialization_bridge import (
            SpecializationBridge, SpecializationRefresh,
            confirm_specialization_refresh,
        )
        from .native_specialization_control import SpecializationController
        from .native_specialization_presentation import (
            SpecializationPresentation, load_known_specialization_roots,
        )
    except ImportError:
        from native_specialization_bridge import (
            SpecializationBridge, SpecializationRefresh,
            confirm_specialization_refresh,
        )
        from native_specialization_control import SpecializationController
        from native_specialization_presentation import (
            SpecializationPresentation, load_known_specialization_roots,
        )
    roots = load_known_specialization_roots(root)
    # Build and validate the exact composed source before acquiring the native
    # instrumentation mutex or attaching.  A broken import/catalogue/anchor is
    # deterministic for this checkout and must not enter the retry loop.
    source = build_agent_source(root, "enabled")
    return {
        "SpecializationBridge": SpecializationBridge,
        "SpecializationRefresh": SpecializationRefresh,
        "confirm_specialization_refresh": confirm_specialization_refresh,
        "SpecializationController": SpecializationController,
        "SpecializationPresentation": SpecializationPresentation,
        "presentation_roots": roots,
        "agent_source": source,
    }


def _load_script_for_startup(
    script,
    on_message: Callable,
    hooks_ready: threading.Event,
    specialization_host_ready: threading.Event,
    script_failed: threading.Event,
    cleanup: Callable[[], None],
    refusal: Callable[[BaseException], None] | None = None,
    *,
    timeout: float = 5.0,
) -> None:
    """Load one composed script and require its complete initialization."""
    try:
        script.on("message", on_message)
        script.load()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if script_failed.is_set():
                raise RuntimeError("unit_drag_script_startup_error")
            if hooks_ready.is_set() and specialization_host_ready.is_set():
                return
            time.sleep(min(0.02, max(0.0, deadline - time.monotonic())))
        if script_failed.is_set():
            raise RuntimeError("unit_drag_script_startup_error")
        if not hooks_ready.is_set():
            raise RuntimeError("unit_drag_hooks_not_ready")
        raise RuntimeError("specialization_host_not_ready")
    except BaseException as error:
        try:
            if refusal is not None:
                refusal(error)
        finally:
            cleanup()
        raise


class _NoControlRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_loadout(request, timeout: float, control_capability: str | None):
    if control_capability is None:
        return urllib.request.urlopen(request, timeout=timeout)
    return urllib.request.build_opener(_NoControlRedirects()).open(
        request, timeout=timeout,
    )


def load_selection_context(timeout: float = 5, *,
                           control_capability: str | None = None) -> dict:
    headers = ({"X-TWA-Unit-Control": control_capability}
               if control_capability is not None else {})
    request = urllib.request.Request(LOADOUT_URL, headers=headers, method="GET")
    with _open_loadout(request, timeout, control_capability) as response:
        return json.loads(response.read().decode("utf-8"))


def post_selection(
    item_id: int,
    slot: int,
    commander_item_id: int,
    expected_saved: int,
    *,
    control_capability: str | None = None,
) -> dict:
    body = json.dumps({
        "item_id": str(item_id),
        "slot": slot,
        "commander_item_id": str(commander_item_id),
        "expected_saved": expected_saved,
    }).encode("utf-8")
    request = urllib.request.Request(
        LOADOUT_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            **({"X-TWA-Unit-Control": control_capability}
               if control_capability is not None else {}),
        },
        method="POST",
    )
    with _open_loadout(request, 5, control_capability) as response:
        return json.loads(response.read().decode("utf-8"))


def load_unit_item_ids(root: Path) -> dict[str, int]:
    return {
        row["key"]: item_id
        for item_id, row in load_unit_catalogue(root).items()
    }


def load_unit_catalogue(root: Path) -> dict[int, dict[str, str]]:
    source = root / "private-server" / "src" / "native-loadouts.json"
    if source.is_file():
        native = json.loads(source.read_text(encoding="utf-8"))
        units = native["units"]
    else:
        # The internal client bundle excludes Worker source. Use the same
        # reviewed live-unit catalogue as the bundled native stack.
        native = json.loads((root / "catalog" / "native_hangar.json").read_text(
            encoding="utf-8"))
        units = [{"id": row["item_id"], "key": row["key"], "faction": row["faction"]}
                 for row in native["units"] if row.get("build_state", "live") == "live"]
    result: dict[int, dict[str, str]] = {}
    for row in units:
        item_id = int(row["id"])
        key = row["key"]
        faction = row["faction"]
        if (not 0 < item_id < 2**64 or not isinstance(key, str) or not key
                or not isinstance(faction, str) or not faction
                or item_id in result):
            raise ValueError("invalid native unit catalogue")
        result[item_id] = {"key": key, "faction": faction}
    return result


class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


class RECT(ctypes.Structure):
    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


user32 = ctypes.WinDLL("user32") if hasattr(ctypes, "WinDLL") else None
if user32 is not None:
    user32.GetForegroundWindow.restype = wintypes.HWND

kernel32 = (
    ctypes.WinDLL("kernel32", use_last_error=True)
    if hasattr(ctypes, "WinDLL") else None
)
if kernel32 is not None:
    kernel32.OpenProcess.argtypes = [
        wintypes.DWORD, wintypes.BOOL, wintypes.DWORD,
    ]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.CreateMutexW.argtypes = [
        ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR,
    ]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL


def _normal_path(value: str | Path) -> str:
    return os.path.normcase(os.path.abspath(str(value)))


def _process_image_path(pid: int) -> str:
    if kernel32 is None or type(pid) is not int or pid <= 0:
        raise RuntimeError("unsupported_or_invalid_arena_pid")
    handle = kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, False, pid,
    )
    if not handle:
        raise RuntimeError("arena_process_unavailable")
    try:
        size = wintypes.DWORD(32768)
        image = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(
            handle, 0, image, ctypes.byref(size),
        ):
            raise RuntimeError("arena_process_path_unavailable")
        return image.value
    finally:
        kernel32.CloseHandle(handle)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_instrumentation_target(pid: int, root: Path) -> dict[str, str]:
    """Fail before attach unless this is the reviewed copied v30 client."""
    expected_exe = root / "client" / "Arena.exe"
    game_dll = root / "client" / "game.dll"
    if _normal_path(_process_image_path(pid)) != _normal_path(expected_exe):
        raise RuntimeError("untrusted_arena_process")
    if not game_dll.is_file():
        raise RuntimeError("reviewed_game_dll_missing")
    digest = _sha256_file(game_dll)
    if digest not in EXPECTED_GAME_DLL_SHA256S:
        raise RuntimeError("unreviewed_game_dll")
    return {"arena": str(expected_exe.resolve()), "game_sha256": digest}


def _acquire_bridge_mutex(pid: int) -> int:
    """Allow only one bridge process to instrument one Arena process."""
    if kernel32 is None:
        raise RuntimeError("bridge_mutex_unavailable")
    ctypes.set_last_error(0)
    handle = kernel32.CreateMutexW(
        None, False, f"{BRIDGE_MUTEX_PREFIX}{pid}",
    )
    if not handle:
        raise RuntimeError("bridge_mutex_failed")
    if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
        kernel32.CloseHandle(handle)
        raise RuntimeError("bridge_already_attached")
    return int(handle)


def _arena_window(pid: int) -> int:
    if user32 is None:
        return 0
    found: list[int] = []
    callback_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

    def visit(hwnd: int, _parameter: int) -> bool:
        if not user32.IsWindowVisible(hwnd):
            return True
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if int(owner.value) != pid:
            return True
        title = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, title, len(title))
        # Match the process first. The patched copy may append "Revival" to
        # the title, while older builds used the stock title. Reject only
        # untitled helper windows owned by Arena.exe.
        if title.value.strip():
            found.append(hwnd)
        return True

    user32.EnumWindows(callback_type(visit), 0)
    return found[0] if found else 0


def _wait_for_arena_window(pid: int, timeout: float) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        hwnd = _arena_window(pid)
        if hwnd:
            return hwnd
        time.sleep(0.05)
    raise RuntimeError("arena_window_not_found")


def _module_probe_source() -> str:
    return r"""
const probe = () => {
  try {
    const module = Process.getModuleByName('game.dll');
    clearInterval(timer);
    send({kind:'reviewed_module_found', path:module.path});
  } catch (_) {}
};
const timer = setInterval(probe, 50);
probe();
"""


def _wait_for_reviewed_module(session, expected: Path, timeout: float) -> None:
    """Wait through a temporary read-only Frida script, then always unload it."""
    found = threading.Event()
    result: dict[str, object] = {}
    probe = session.create_script(_module_probe_source())

    def on_message(message: dict, _data: object) -> None:
        payload = message.get("payload") if message.get("type") == "send" else None
        if (isinstance(payload, dict)
                and payload.get("kind") == "reviewed_module_found"
                and isinstance(payload.get("path"), str)):
            result["path"] = payload["path"]
        else:
            result["error"] = True
        found.set()

    try:
        probe.on("message", on_message)
        probe.load()
        if not found.wait(timeout):
            raise RuntimeError("loaded_game_dll_not_ready")
        if result.get("error"):
            raise RuntimeError("loaded_game_dll_probe_failed")
        if _normal_path(result.get("path", "")) != _normal_path(expected):
            raise RuntimeError("loaded_game_dll_path_mismatch")
    finally:
        try:
            probe.unload()
        except Exception:
            raise RuntimeError("loaded_game_dll_probe_cleanup_failed") from None


def _cursor_client(hwnd: int) -> tuple[int, int] | None:
    point = POINT()
    if not user32.GetCursorPos(ctypes.byref(point)):
        return None
    if not user32.ScreenToClient(hwnd, ctypes.byref(point)):
        return None
    client = RECT()
    if not user32.GetClientRect(hwnd, ctypes.byref(client)):
        return None
    width = client.right - client.left
    height = client.bottom - client.top
    if width <= 0 or height <= 0:
        return None
    # Keep this process DPI-unaware so real mouse input is reported in the
    # same legacy space as Arena, then normalize 1600x900 (150% desktop DPI)
    # to the fixed 2400x1350 Scaleform layout used by the hit boxes below.
    return round(point.x * 2400 / width), round(point.y * 1350 / height)


def _arena_is_foreground(hwnd: int) -> bool:
    return bool(user32 is not None and user32.GetForegroundWindow() == hwnd)


def _source_point(point: tuple[int, int] | None) -> bool:
    # Unit cards can occupy the centre army panel as well as the left list,
    # depending on resolution, filtering, and scroll position.  Native unit
    # identity is still validated before persistence; exclude only the bottom
    # equipped-slot strip from source selection.
    return point is not None and 0 <= point[0] <= 2400 and 120 <= point[1] < 1120


def _target_slot(point: tuple[int, int] | None) -> int | None:
    if point is None or not 1120 <= point[1] <= 1349:
        return None
    x = point[0]
    # The commander portrait occupies roughly x=727..885.  The three unit
    # cards begin to its right, with centres near 1016, 1280 and 1542 in the
    # fixed 2400x1350 Scaleform layout.  Save/reload screenshots compared with
    # the authoritative API show that the stock client renders the persisted
    # three-element array in reverse order: visual left/middle/right are
    # persisted slots 2/1/0.
    if 885 <= x <= 1148:
        return 2
    if 1149 <= x <= 1413:
        return 1
    if 1414 <= x <= 1675:
        return 0
    return None


def _is_drag(start: tuple[int, int] | None, end: tuple[int, int] | None) -> bool:
    if not _source_point(start) or _target_slot(end) is None:
        return False
    assert start is not None and end is not None
    return abs(end[0] - start[0]) + abs(end[1] - start[1]) >= 240


def _unique_unit_candidate(candidates: set[int]) -> int | None:
    return next(iter(candidates)) if len(candidates) == 1 else None


def _event_in_gesture(
    emitted_at_ms: int,
    last_button_up_ms: int | None,
    upper_ms: int,
) -> bool:
    """Bind native emission time, not asynchronous Python delivery time."""
    return bool(
        type(emitted_at_ms) is int and emitted_at_ms > 0
        and type(last_button_up_ms) is int
        and last_button_up_ms <= emitted_at_ms <= upper_ms
    )


def _resolve_drag_identity(
    source_ids: set[int],
    drop_keys: list[str],
    unit_item_ids: dict[str, int],
) -> tuple[int | None, str]:
    """Missing notifications may fall back; contradictory ones never do."""
    if source_ids - set(unit_item_ids.values()):
        return None, "unknown_unit_drag_source"
    if len(source_ids) > 1:
        return None, "ambiguous_unit_drag_source"
    if any(key not in unit_item_ids for key in drop_keys):
        return None, "unknown_native_drop_identity"
    drop_ids = {unit_item_ids[key] for key in drop_keys}
    if len(drop_ids) > 1:
        return None, "ambiguous_native_drop_identity"
    source_item = _unique_unit_candidate(source_ids)
    drop_item = _unique_unit_candidate(drop_ids)
    if (source_item is not None and drop_item is not None
            and source_item != drop_item):
        return None, "unit_drag_identity_mismatch"
    item_id = source_item if source_item is not None else drop_item
    return item_id, "resolved" if item_id is not None else "missing_drag_identity"


def _wait_native_drop_keys(
    events: queue.Queue[tuple[int, str, int | None]],
    *,
    timeout: float = NATIVE_DROP_GRACE_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> list[tuple[int, str, int | None]]:
    """Spend at most one grace budget, including duplicate notifications."""
    deadline = clock() + timeout
    found = []
    while True:
        remaining = deadline - clock()
        if remaining <= 0:
            break
        try:
            found.append(events.get(timeout=remaining))
        except queue.Empty:
            break
    return found


def _valid_refresh_operation_id(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and re.fullmatch(r"native-unit-drag-[0-9a-f]{32}", value)
    )


def _validated_context_envelope(context: object) -> dict:
    """Validate and normalize the server authority captured at mouse-down."""
    expected_fields = {
        "ok", "commander", "commander_item_id", "faction", "saved", "units",
        "refresh_pending", "refresh_operation_id", "refresh_ack",
    }
    if (not isinstance(context, dict)
            or set(context) != expected_fields
            or context.get("ok") is not True):
        raise ValueError("invalid_selection_context")
    commander = context.get("commander")
    commander_item = context.get("commander_item_id")
    faction = context.get("faction")
    saved = context.get("saved")
    units = context.get("units")
    refresh_pending = context.get("refresh_pending")
    refresh_operation_id = context.get("refresh_operation_id")
    refresh_ack = context.get("refresh_ack")
    valid_ack = (
        refresh_ack is None
        or isinstance(refresh_ack, dict)
        and set(refresh_ack) == {"operation_id", "saved", "status"}
        and _valid_refresh_operation_id(refresh_ack.get("operation_id"))
        and type(refresh_ack.get("saved")) is int
        and 0 < refresh_ack["saved"] < 2**64
        and refresh_ack.get("status") == "external_refresh_resynced"
    )
    if (not isinstance(commander, str) or not commander
            or not isinstance(commander_item, str)
            or not commander_item.isascii() or not commander_item.isdigit()
            or len(commander_item) > 20
            or not 0 < int(commander_item) < 2**64
            or not isinstance(faction, str) or not faction
            or type(saved) is not int or not 0 <= saved < 2**64
            or type(refresh_pending) is not bool
            or not valid_ack
            or (refresh_pending and not _valid_refresh_operation_id(
                refresh_operation_id
            ))
            or (not refresh_pending and refresh_operation_id is not None)
            or (refresh_pending and refresh_ack is not None)
            or not isinstance(units, list) or len(units) != 3
            or any(not isinstance(key, str) or not key for key in units)):
        raise ValueError("invalid_selection_context")
    return {
        "commander": commander,
        "commander_item_id": int(commander_item),
        "faction": faction,
        "saved": saved,
        "refresh_pending": refresh_pending,
        "refresh_operation_id": refresh_operation_id,
        "refresh_ack": None if refresh_ack is None else dict(refresh_ack),
        "units": list(units),
    }


def _startup_profile_refresh_request(
    context: object,
) -> tuple[str, str] | None:
    """Return an exact catch-up token/operation only for pending state."""
    if (not isinstance(context, dict)
            or context.get("refresh_pending") is not True):
        return None
    try:
        validated = _validated_context_envelope(context)
    except ValueError:
        return None
    operation_id = validated["refresh_operation_id"]
    if validated["saved"] <= 0 or not isinstance(operation_id, str):
        return None
    return str(validated["saved"]), operation_id


def _server_profile_resynced(token: str, operation_id: str, *,
                             control_capability: str | None = None) -> bool:
    """Match only the server's exact completed-HTTP-write acknowledgement.

    This does not claim that the socket response reached Arena or that
    Scaleform applied the graph; live screenshots remain the final UI proof.
    """
    context = _validated_context_envelope(
        load_selection_context(
            timeout=0.75, control_capability=control_capability,
        ),
    )
    ack = context["refresh_ack"]
    return bool(
        isinstance(ack, dict)
        and ack["operation_id"] == operation_id
        and str(ack["saved"]) == token
        and ack["status"] == "external_refresh_resynced"
    )


def _bind_context_unit(
    context: dict,
    item_id: int,
    catalogue: dict[int, dict[str, str]],
) -> dict:
    unit = catalogue.get(item_id)
    if unit is None:
        raise ValueError("unknown_unit_item")
    if unit["faction"] != context["faction"]:
        raise ValueError("unit_faction_mismatch")
    return {
        **context,
        "unit_key": unit["key"],
    }


def _validated_selection_context(
    context: object,
    item_id: int,
    catalogue: dict[int, dict[str, str]],
) -> dict:
    return _bind_context_unit(
        _validated_context_envelope(context), item_id, catalogue,
    )


def _validated_selection_response(
    response: object,
    *,
    item_id: int,
    slot: int,
    context: dict,
) -> tuple[int, bool, str | None, bool, str | None]:
    expected_fields = {
        "ok", "slot", "unit_item_id", "saved", "commander",
        "commander_item_id", "operation_id", "refresh_pending",
        "refresh_operation_id",
        "before_units", "after_units",
    }
    if (not isinstance(response, dict) or set(response) != expected_fields
            or response.get("ok") is not True
            or response.get("slot") != slot
            or response.get("unit_item_id") != str(item_id)
            or response.get("commander") != context["commander"]
            or response.get("commander_item_id") != str(
                context["commander_item_id"]
            )
            or response.get("before_units") != context["units"]):
        raise ValueError("unit_loadout_response_mismatch")
    saved = response.get("saved")
    operation_id = response.get("operation_id")
    refresh_pending = response.get("refresh_pending")
    refresh_operation_id = response.get("refresh_operation_id")
    after_units = response.get("after_units")
    if (type(saved) is not int or not 0 <= saved < 2**64
            or type(refresh_pending) is not bool
            or not isinstance(after_units, list) or len(after_units) != 3
            or any(not isinstance(key, str) or not key for key in after_units)):
        raise ValueError("unit_loadout_response_mismatch")
    expected_after = list(context["units"])
    expected_after[slot] = context["unit_key"]
    if after_units != expected_after:
        raise ValueError("unit_loadout_response_mismatch")
    changed = expected_after != context["units"]
    if ((changed and saved <= context["saved"])
            or (not changed and saved != context["saved"])
            or (changed and not _valid_refresh_operation_id(operation_id))
            or (not changed and operation_id is not None)
            or (refresh_pending and not _valid_refresh_operation_id(
                refresh_operation_id
            ))
            or (refresh_pending and refresh_operation_id != operation_id)
            or (not refresh_pending and refresh_operation_id is not None)
            or (not changed and refresh_pending)):
        raise ValueError("unit_loadout_response_mismatch")
    return (
        saved, changed, operation_id, refresh_pending,
        refresh_operation_id,
    )


def _helper_protocol(root: Path):
    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    from companion import native_helper_protocol
    return native_helper_protocol


def _read_owned_start(args, root: Path, stream=None) -> dict:
    protocol = _helper_protocol(root)
    source = sys.stdin.buffer if stream is None else stream
    result: queue.Queue = queue.Queue(maxsize=1)

    def read_one() -> None:
        try:
            result.put(source.readline(protocol.MAX_CONTROL_LINE + 1), block=False)
        except BaseException as error:
            result.put(error, block=False)

    threading.Thread(target=read_one, daemon=True,
                     name="owned-helper-start-reader").start()
    try:
        raw = result.get(timeout=OWNED_START_TIMEOUT_SECONDS)
    except queue.Empty:
        raise RuntimeError("owned_helper_start_timeout") from None
    if (isinstance(raw, BaseException) or not raw
            or len(raw) > protocol.MAX_CONTROL_LINE or not raw.endswith(b"\n")):
        raise RuntimeError("invalid_owned_helper_start")
    try:
        command = json.loads(raw)
    except (UnicodeError, ValueError):
        raise RuntimeError("invalid_owned_helper_start") from None
    expected_keys = {
        "protocol", "command", "nonce", "arena_pid", "specialization_mode",
        "arena_path", "game_path", "game_sha256", "unit_control_capability",
        "native_user_id", "session_sha256",
    }
    nonce = command.get("nonce") if isinstance(command, dict) else None
    expected_arena = (root / "client" / "Arena.exe").resolve()
    expected_game = (root / "client" / "game.dll").resolve()
    if (not isinstance(command, dict) or set(command) != expected_keys
            or command.get("protocol") != protocol.PROTOCOL
            or command.get("command") != "start"
            or not isinstance(nonce, str) or len(nonce) != 64
            or any(char not in "0123456789abcdef" for char in nonce)
            or command.get("arena_pid") != args.pid
            or command.get("specialization_mode") != args.specialization_mode
            or _normal_path(command.get("arena_path", "")) != _normal_path(expected_arena)
            or _normal_path(command.get("game_path", "")) != _normal_path(expected_game)
            or not isinstance(command.get("game_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", command["game_sha256"]) is None
            or not isinstance(command.get("unit_control_capability"), str)
            or re.fullmatch(r"[0-9a-f]{64}",
                            command["unit_control_capability"]) is None
            or not isinstance(command.get("native_user_id"), str)
            or re.fullmatch(r"[A-Za-z0-9_-]{1,36}",
                            command["native_user_id"]) is None
            or not isinstance(command.get("session_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}",
                            command["session_sha256"]) is None):
        raise RuntimeError("invalid_owned_helper_start")
    return command


def _write_owned_ready(command: dict, target: dict[str, str], *, stream=None) -> None:
    protocol = _helper_protocol(Path(__file__).resolve().parents[1])
    if (_normal_path(target.get("arena", ""))
            != _normal_path(command["arena_path"])
            or target.get("game_sha256") != command["game_sha256"]):
        raise RuntimeError("owned_helper_copy_binding_changed")
    payload = {
        "protocol": protocol.PROTOCOL,
        "event": "interactive_ready",
        "nonce": command["nonce"],
        "helper_pid": os.getpid(),
        "arena_pid": command["arena_pid"],
        "specialization_mode": command["specialization_mode"],
        "arena_path": command["arena_path"],
        "game_path": command["game_path"],
        "game_sha256": command["game_sha256"],
        "unit_control_capability_sha256": hashlib.sha256(
            command["unit_control_capability"].encode("ascii")
        ).hexdigest(),
        "native_user_id": command["native_user_id"],
        "session_sha256": command["session_sha256"],
    }
    payload["proof"] = protocol.ready_proof(command["nonce"], payload)
    encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":"))
               + "\n").encode("utf-8")
    if len(encoded) > protocol.MAX_CONTROL_LINE:
        raise RuntimeError("owned_helper_ready_too_large")
    destination = sys.stdout.buffer if stream is None else stream
    destination.write(encoded)
    destination.flush()


def _safe_party_mode_record(payload: dict) -> dict | None:
    """Allow only bounded mode diagnostics; never forward arbitrary fields."""
    modes = {"territory_pve", "annihilation_pve", "territory_pvp", "annihilation_pvp"}
    kind = payload.get("kind")
    if kind == "party_mode_sync_ready":
        return {"event": kind}
    if kind == "party_mode_replay_synchronized":
        mode, value = payload.get("mode"), payload.get("display_enum")
        if isinstance(mode, str) and mode in modes and type(value) is int and 1 <= value <= 4:
            return {"event": kind, "mode": mode, "display_enum": value}
        return None
    if kind != "party_mode_diagnostic":
        return None
    result = {"event": kind}
    choices = {
        "phase": {"enter", "leave"}, "call_kind": {"wire", "enum"},
        "reason": {"entered", "foreign_caller", "saved_not_pending", "unknown_wire",
                   "intent_cached", "read_error", "no_intent", "different_session",
                   "ordinary_selection", "stale_or_changed", "catalog_incomplete", "replayed"},
    }
    for name, allowed in choices.items():
        value = payload.get(name)
        if not isinstance(value, str) or value not in allowed:
            return None
        result[name] = value
    for name, maximum, nullable in (
            ("call_id", 48, False), ("elapsed_ms", 120000, False),
            ("caller_rva", 0x2000000, True), ("requested_enum", 4, True),
            ("effective_enum", 4, True), ("publish", 1, True),
            ("selected", 4, True), ("saved", 4, True), ("catalog_count", 4, True)):
        value = payload.get(name)
        if not (nullable and value is None) and not (type(value) is int and 0 <= value <= maximum):
            return None
        result[name] = value
    if result["call_id"] == 0:
        return None
    for name in ("requested_mode", "intent_mode"):
        value = payload.get(name)
        if value is not None and (not isinstance(value, str) or value not in modes):
            return None
        result[name] = value
    same = payload.get("intent_same_session")
    if same is not None and type(same) is not bool:
        return None
    result["intent_same_session"] = same
    ui_result = payload.get("ui_result")
    ui_results = {"no_witness", "newer_authority", "different_session", "different_thread",
                  "selection_changed", "catalog_changed", "mapping_mismatch", "no_client",
                  "no_party", "party_identity", "not_peer", "registration_count",
                  "registration_array", "ambiguous_selector", "selector_identity",
                  "reverse_registration", "no_selector", "cache_changed", "switch_missing",
                  "description_incomplete", "party_changed", "refreshed", "native_failed",
                  "ui_read_error"}
    if ui_result is not None and (not isinstance(ui_result, str) or ui_result not in ui_results):
        return None
    result["ui_result"] = ui_result
    catalog = payload.get("catalog")
    if not isinstance(catalog, list) or len(catalog) > 4:
        return None
    result["catalog"] = []
    for row in catalog:
        if not isinstance(row, dict):
            return None
        mode, value = row.get("mode"), row.get("display_enum")
        if mode is not None and (not isinstance(mode, str) or mode not in modes):
            return None
        if value is not None and not (type(value) is int and 0 <= value <= 4):
            return None
        result["catalog"].append({"mode": mode, "display_enum": value})
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=float, default=3600)
    parser.add_argument(
        "--specialization-mode", choices=("off", "observe", "enabled"),
        default="off",
    )
    parser.add_argument(
        "--restart-after-persist", action="store_true", help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--owned-control", action="store_true", help=argparse.SUPPRESS,
    )
    args = parser.parse_args()

    root = ROOT
    owned_start = _read_owned_start(args, root) if args.owned_control else None
    control_capability = (
        None if owned_start is None
        else owned_start["unit_control_capability"]
    )
    import frida

    bridge_mutex = None
    target = _verify_instrumentation_target(args.pid, root)
    hwnd = _wait_for_arena_window(args.pid, NATIVE_READY_TIMEOUT_SECONDS)
    unit_catalogue = load_unit_catalogue(root)
    unit_item_ids = {
        row["key"]: item_id for item_id, row in unit_catalogue.items()
    }
    source_events: queue.Queue[tuple[int, int]] = queue.Queue()
    drop_keys: queue.Queue[tuple[int, str, int | None]] = queue.Queue()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    handle = args.output.open("a", encoding="utf-8", buffering=1)
    record_lock = threading.Lock()
    refresh_coordinator: ProfileRefreshCoordinator | None = None
    specialization_bridge = None
    specialization_refresh = None
    specialization_presentation = None
    specialization_controller = None
    exit_status = 0
    hooks_ready = threading.Event()
    specialization_host_ready = threading.Event()
    script_failed = threading.Event()
    party_mode_log_count = 0
    if args.specialization_mode == "off":
        specialization_host_ready.set()

    def record(row: dict) -> None:
        with record_lock:
            handle.write(json.dumps({"time": time.time(), **row}) + "\n")

    record({
        "event": "instrumentation_target_verified",
        "pid": args.pid,
        "arena": target["arena"],
        "game_sha256": target["game_sha256"],
    })

    def on_message(message: dict, _data: object) -> None:
        nonlocal party_mode_log_count
        payload = message.get("payload") if message.get("type") == "send" else None
        if not isinstance(payload, dict):
            script_failed.set()
            record({
                "event": "frida_error",
                "message_type": message.get("type"),
                "description": message.get("description"),
                "stack": message.get("stack"),
            })
            return
        if payload.get("kind") in ("party_mode_sync_ready", "party_mode_replay_synchronized", "party_mode_diagnostic"):
            detail = _safe_party_mode_record(payload)
            if detail is not None and party_mode_log_count < 100:
                party_mode_log_count += 1
                record(detail)
            return
        if payload.get("kind") == "hooks_ready":
            hooks_ready.set()
            record({"event": "hooks_ready", "pid": args.pid})
            return
        if payload.get("kind") in {"native_preferences_ready", "native_preferences_routed"}:
            record({"event": payload["kind"]})
            return
        if payload.get("kind") in {
                "career_ui_ready", "career_ui_sort_controls_verified",
                "career_ui_row_adapted", "career_ui_average_sort_adapted",
                "career_ui_row_refused", "career_ui_headers_refused",
                "career_ui_sort_refused", "career_ui_sort_unsupported_row"}:
            detail = payload.get("detail")
            record({"event": payload.get("kind"),
                    "detail": detail if detail in {"commander", "unit"} else ""})
            return
        if payload.get("kind") in {"npl_auth_ready", "npl_auth_forwarded"}:
            module = payload.get("module")
            record({"event": payload["kind"], "module": (
                module if module in {"npl-base.dll", "npl-sdk.dll"} else None)})
            return
        if payload.get("kind") == "specialization_host_ready":
            specialization_host_ready.set()
            record({"event": "specialization_host_ready", "pid": args.pid})
            return
        if payload.get("kind") == "specialization_ui_setup":
            worker = specialization_presentation
            if worker is None or not worker.submit_setup(payload):
                if worker is None:
                    record({"event": "specialization_ui_setup_without_worker"})
            return
        if payload.get("kind") == "specialization_ui_owner_destroyed":
            if specialization_presentation is not None:
                specialization_presentation.owner_destroyed(payload)
            return
        if payload.get("kind") == "specialization_ui_status_received":
            if specialization_presentation is not None:
                specialization_presentation.accept_receipt(payload)
            return
        if payload.get("kind") in {
                "specialization_binding_ready", "specialization_binding_refused",
                "specialization_ui_action_refused",
                "specialization_ui_setup_refused",
                "specialization_ui_status_refused"}:
            record({"event": payload.get("kind"),
                    **{key: value for key, value in payload.items()
                       if key != "kind"}})
            return
        if payload.get("kind") == "specialization_ui_action":
            worker = specialization_bridge
            if worker is None or not worker.submit(payload):
                if worker is None:
                    record({"event": "specialization_event_without_worker"})
            return
        if payload.get("kind") in _PROFILE_REFRESH_SIGNALS:
            specialization = specialization_refresh
            if specialization is not None and specialization.deliver(payload):
                return
            coordinator = refresh_coordinator
            if coordinator is None or not coordinator.deliver(payload):
                if coordinator is None:
                    record({
                        "event": "stale_profile_refresh_signal_ignored",
                        "token": payload.get("token"),
                        "current_token": None,
                        "kind": payload.get("kind"),
                    })
            return
        if payload.get("kind") == "unit_drop_key":
            key = payload.get("key")
            direction = payload.get("direction")
            emitted_at_ms = payload.get("emitted_at_ms")
            if (isinstance(key, str) and type(emitted_at_ms) is int
                    and 0 < emitted_at_ms < 2**53):
                drop_keys.put((
                    emitted_at_ms, key,
                    direction if type(direction) is int else None,
                ))
            else:
                record({"event": "invalid_unit_drop_key"})
            return
        if payload.get("kind") == "unit_candidate":
            record({"event": "unbound_unit_candidate_ignored"})
            return
        if payload.get("kind") != "unit_drag_source":
            return
        try:
            lo = int(payload["lo"])
            hi = int(payload["hi"])
            emitted_at_ms = payload.get("emitted_at_ms")
            if not (0 <= lo < 2**32 and 0 <= hi < 2**32
                    and type(emitted_at_ms) is int
                    and 0 < emitted_at_ms < 2**53):
                raise ValueError
            item_id = lo | hi << 32
            # Keep unknown IDs until gesture resolution: a second unknown
            # source must invalidate the gesture, not disappear before a
            # different known source is accepted.
            source_events.put((emitted_at_ms, item_id))
            unit = unit_catalogue.get(item_id)
            if unit is None:
                record({
                    "event": "non_catalogue_drag_source_rejected",
                    "item_id": str(item_id),
                })
                return
            record({
                "event": "native_drag_source",
                "emitted_at_ms": emitted_at_ms,
                "item_id": str(item_id),
                "unit": unit["key"],
                "faction": unit["faction"],
            })
        except (KeyError, TypeError, ValueError):
            record({"event": "invalid_unit_candidate"})

    specialization_host = None
    try:
        if args.specialization_mode != "off":
            specialization_host = _load_specialization_host(root)
            agent_source = specialization_host["agent_source"]
        else:
            agent_source = build_agent_source(root, "off")
        if owned_start is not None:
            from tools.native_user_preferences import GAME_SHA256S as PREFERENCES_GAME_SHA256S, build_source as build_preferences
            if target["game_sha256"] in PREFERENCES_GAME_SHA256S:
                agent_source = build_preferences(root, owned_start["native_user_id"]) + "\n" + agent_source
            from tools.native_npl_auth import build_source as build_npl_auth
            # Validate both owned stubs before publishing helper readiness.
            agent_source = build_npl_auth(root) + "\n" + agent_source
            from tools.native_mode_availability import GAME_SHA256S as MODE_GAME_SHA256S, build_source as build_mode_availability
            if target["game_sha256"] in MODE_GAME_SHA256S:
                agent_source = build_mode_availability(root) + "\n" + agent_source
            from tools.native_career_ui import build_source as build_career_ui
            agent_source = build_career_ui(root) + "\n" + agent_source
    except BaseException as error:
        # Never persist exception text here: import errors can contain host
        # paths and future dependency errors may carry sensitive values.
        record({
            "event": "specialization_startup_refused",
            "phase": "host_preflight",
            "error_class": type(error).__name__,
            "reason": "specialization_host_preflight_failed",
        })
        handle.close()
        return SPECIALIZATION_PREFLIGHT_REFUSED_EXIT

    session = None
    script = None
    try:
        bridge_mutex = _acquire_bridge_mutex(args.pid)
        session = frida.attach(args.pid)
        # Close the narrow PID-reuse window between the first path check and
        # instrumentation attach. The named mutex remains held throughout.
        target = _verify_instrumentation_target(args.pid, root)
        _wait_for_reviewed_module(
            session, root / "client" / "game.dll",
            NATIVE_READY_TIMEOUT_SECONDS,
        )
        detached = threading.Event()
        session.on("detached", lambda *_args: detached.set())
        script = session.create_script(agent_source)
    except BaseException:
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        handle.close()
        if kernel32 is not None and bridge_mutex is not None:
            kernel32.CloseHandle(bridge_mutex)
        raise

    assert session is not None and script is not None

    def abort_startup() -> None:
        """Release pre-loop resources if setup or script load fails."""
        if specialization_presentation is not None:
            specialization_presentation.close()
        if specialization_bridge is not None:
            specialization_bridge.close()
        elif specialization_refresh is not None:
            specialization_refresh.close()
        try:
            script.unload()
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass
        handle.close()
        if kernel32 is not None and bridge_mutex is not None:
            kernel32.CloseHandle(bridge_mutex)

    try:
        if args.specialization_mode != "off":
            assert specialization_host is not None
            SpecializationController = specialization_host[
                "SpecializationController"
            ]
            SpecializationRefresh = specialization_host[
                "SpecializationRefresh"
            ]
            SpecializationPresentation = specialization_host[
                "SpecializationPresentation"
            ]
            SpecializationBridge = specialization_host[
                "SpecializationBridge"
            ]
            confirm_specialization_refresh = specialization_host[
                "confirm_specialization_refresh"
            ]
            presentation_roots = specialization_host["presentation_roots"]
            specialization_controller = SpecializationController()
            specialization_refresh = SpecializationRefresh(
                script.post, record, confirm_specialization_refresh,
            )
            specialization_presentation = SpecializationPresentation(
                post=script.post,
                controller=specialization_controller,
                record=record,
                client_root=root / "client",
                known_roots=presentation_roots,
            )
            specialization_bridge = SpecializationBridge(
                mode=args.specialization_mode,
                controller=specialization_controller,
                record=record,
                refresh=specialization_refresh,
            )
    except BaseException:
        abort_startup()
        raise
    # The normal bounded-loop ``finally`` starts below.  Require both the base
    # hooks marker and, for composed specialization mode, a marker appended
    # after the entire binding IIFE.  A top-level script error therefore
    # unloads/detaches and cannot fall through to interactive readiness.
    def record_script_startup_refusal(error: BaseException) -> None:
        record({
            "event": "specialization_startup_refused",
            "phase": "script_initialization",
            "error_class": type(error).__name__,
            "reason": "specialization_script_initialization_failed",
        })

    try:
        _load_script_for_startup(
            script, on_message, hooks_ready, specialization_host_ready,
            script_failed, abort_startup,
            record_script_startup_refusal,
        )
    except BaseException:
        if args.specialization_mode != "off":
            return SPECIALIZATION_PREFLIGHT_REFUSED_EXIT
        raise
    refresh_coordinator = ProfileRefreshCoordinator(
        script.post,
        lambda token, operation_id: _server_profile_resynced(
            token, operation_id, control_capability=control_capability,
        ),
        record,
    )
    try:
        if owned_start is not None:
            startup_context = _validated_context_envelope(
                load_selection_context(
                    control_capability=control_capability,
                ),
            )
            startup_request = _startup_profile_refresh_request(startup_context)
        else:
            try:
                startup_request = _startup_profile_refresh_request(
                    load_selection_context(
                        control_capability=control_capability,
                    ),
                )
            except (OSError, urllib.error.HTTPError,
                    json.JSONDecodeError) as error:
                startup_request = None
                record({
                    "event": "profile_refresh_startup_probe_failed",
                    "error": type(error).__name__,
                    "reason": str(error),
                })
        if startup_request is not None:
            startup_token, startup_operation_id = startup_request
            if refresh_coordinator.request(startup_token, startup_operation_id):
                record({
                    "event": "profile_refresh_startup_catchup_scheduled",
                    "token": startup_token,
                    "operation_id": startup_operation_id,
                })
            else:
                record({
                    "event": "profile_refresh_startup_catchup_rejected",
                    "token": startup_token,
                    "operation_id": startup_operation_id,
                })
        was_down = False
        drag_start: tuple[int, int] | None = None
        last_button_up_sample_ms: int | None = None
        gesture_lower_ms: int | None = None
        drag_candidates: set[int] = set()
        gesture_foreground = False
        gesture_context: dict | None = None
        press_point: tuple[int, int] | None = None
        pending_click: tuple[int, dict, float] | None = None

        if _arena_window(args.pid) != hwnd:
            raise RuntimeError("arena_window_changed_during_startup")
        record({"event": "ready", "pid": args.pid})
        if owned_start is not None:
            _write_owned_ready(owned_start, target)

        def clear_queue(target: queue.Queue) -> None:
            while True:
                try:
                    target.get_nowait()
                except queue.Empty:
                    return

        def collect_drag_sources(upper_ms: int | None = None) -> None:
            while True:
                try:
                    emitted_at_ms, item_id = source_events.get_nowait()
                except queue.Empty:
                    return
                if (drag_start is not None and gesture_foreground
                        and _event_in_gesture(
                            emitted_at_ms, gesture_lower_ms,
                            upper_ms if upper_ms is not None
                            else time.time_ns() // 1_000_000,
                        )):
                    drag_candidates.add(item_id)
                else:
                    record({
                        "event": "out_of_gesture_drag_source_ignored",
                        "item_id": str(item_id),
                        "emitted_at_ms": emitted_at_ms,
                    })

        def native_drop_candidates(upper_ms: int) -> list[str]:
            candidates = []
            for emitted_at_ms, key, direction in _wait_native_drop_keys(drop_keys):
                if not _event_in_gesture(
                    emitted_at_ms, gesture_lower_ms, upper_ms,
                ):
                    record({
                        "event": "out_of_gesture_drop_key_ignored",
                        "key": key, "emitted_at_ms": emitted_at_ms,
                    })
                    continue
                item_id = unit_item_ids.get(key)
                record({
                    "event": "native_unit_drop_key", "key": key,
                    "direction": direction,
                    "emitted_at_ms": emitted_at_ms,
                    "item_id": str(item_id) if item_id is not None else None,
                })
                candidates.append(key)
            return candidates

        def persist(
            item_id: int,
            end: tuple[int, int] | None,
            captured_context: dict,
        ) -> None:
            slot = _target_slot(end)
            if slot is None:
                return
            try:
                context = _bind_context_unit(
                    captured_context, item_id, unit_catalogue,
                )
                response = post_selection(
                    item_id, slot, context["commander_item_id"],
                    context["saved"],
                    control_capability=control_capability,
                )
                (saved, changed, operation_id, refresh_pending,
                 refresh_operation_id) = _validated_selection_response(
                    response, item_id=item_id, slot=slot, context=context,
                )
                record({
                    "event": ("unit_drag_persisted" if changed
                              else "unit_drag_unchanged"), "slot": slot,
                    "item_id": str(item_id), "unit": context["unit_key"],
                    "commander": context["commander"], "saved": saved,
                    "operation_id": operation_id,
                    "refresh_pending": refresh_pending,
                    "refresh_operation_id": refresh_operation_id,
                    "before_units": context["units"],
                    "after_units": response["after_units"],
                })
                if not changed:
                    return
                # ``--restart-after-persist`` is accepted only so an older
                # already-running supervisor cannot restart the game while it
                # is being upgraded.  A unit swap must remain in this Arena
                # process.
                record({"event": "unit_drag_saved_restartless", "pid": args.pid})
                token = str(saved)
                if not refresh_pending:
                    message = (
                        "Unit selection was saved, but live profile refresh "
                        "could not be armed. The current hangar view may be "
                        "stale; inspect the unit-drag log."
                    )
                    record({
                        "event": "profile_refresh_unavailable",
                        "token": token,
                        "request_consumed": False,
                        "server_profile_resynced": False,
                        "ui_apply_confirmed": False,
                        "user_action_required": True,
                        "message": message,
                    })
                    print("TWA unit-drag warning: " + message, flush=True)
                    return
                assert refresh_operation_id is not None
                if not refresh_coordinator.request(
                    token, refresh_operation_id,
                ):
                    record({
                        "event": "profile_refresh_schedule_rejected",
                        "token": token,
                        "operation_id": refresh_operation_id,
                        "reason": "saved_watermark_not_newer",
                    })
            except (OSError, ValueError, urllib.error.HTTPError,
                    json.JSONDecodeError) as error:
                record({
                    "event": "unit_drag_rejected", "slot": slot,
                    "item_id": str(item_id), "error": type(error).__name__,
                    "reason": str(error),
                })

        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline and not detached.is_set():
            # Use the actual input sample time even if context loading or
            # persistence blocks this loop before the next iteration.
            sampled_at_ms = time.time_ns() // 1_000_000
            down = bool(user32.GetAsyncKeyState(0x01) & 0x8000)
            point = _cursor_client(hwnd)
            foreground = _arena_is_foreground(hwnd)
            if down and not was_down:
                gesture_lower_ms = last_button_up_sample_ms
                press_point = point if foreground else None
                drag_start = (
                    point if foreground and _source_point(point)
                    and gesture_lower_ms is not None else None
                )
                drag_candidates = set()
                gesture_foreground = drag_start is not None
                gesture_context = None
                clear_queue(drop_keys)
                if gesture_foreground:
                    try:
                        # Bind commander + profile watermark before the held
                        # card can trigger any UI/profile transition.  Loading
                        # this only after mouse-up allowed a same-faction
                        # commander switch during the drag to target the new
                        # commander with a fresh, incorrectly accepted token.
                        gesture_context = _validated_context_envelope(
                            load_selection_context(
                                control_capability=control_capability,
                            ),
                        )
                    except (OSError, ValueError, urllib.error.HTTPError,
                            json.JSONDecodeError) as error:
                        gesture_foreground = False
                        drag_start = None
                        record({
                            "event": "gesture_context_rejected",
                            "error": type(error).__name__,
                            "reason": str(error),
                        })
                record({
                    "event": "gesture_start",
                    "point": list(point) if point else None,
                    "arena_foreground": foreground,
                    "eligible_source": drag_start is not None,
                    "sampled_at_ms": sampled_at_ms,
                    "native_window_start_ms": gesture_lower_ms,
                })
            if down and was_down and not foreground:
                gesture_foreground = False
            if down:
                collect_drag_sources()
            if not down and was_down:
                released_at_ms = sampled_at_ms
                native_window_end_ms = released_at_ms + round(
                    NATIVE_DROP_GRACE_SECONDS * 1000,
                )
                valid_drag = (
                    gesture_foreground and foreground
                    and _is_drag(drag_start, point)
                    and gesture_lower_ms is not None
                    and released_at_ms >= gesture_lower_ms
                )
                record({
                    "event": "gesture_release",
                    "released_at_ms": released_at_ms,
                    "end": list(point) if point else None,
                    "valid_drag": valid_drag,
                })
                # The stock drop hook runs synchronously with mouse-up. Give
                # its Frida message 50 ms to cross into Python,
                # then fall back to the already unique source-card identity.
                # Waiting 350 ms here delayed every valid swap before the HTTP
                # save even started and pushed visible refresh past one second.
                native_keys = (
                    native_drop_candidates(native_window_end_ms)
                    if valid_drag else []
                )
                collect_drag_sources(native_window_end_ms)
                drag_item, identity_reason = _resolve_drag_identity(
                    drag_candidates, native_keys, unit_item_ids,
                )
                record({
                    "event": "gesture_end",
                    "released_at_ms": released_at_ms,
                    "start": list(drag_start) if drag_start else None,
                    "end": list(point) if point else None,
                    "has_candidate": drag_item is not None,
                    "valid_drag": valid_drag,
                    "arena_foreground": foreground,
                    "identity_matches": identity_reason == "resolved",
                    "identity_reason": identity_reason,
                })
                if (drag_item is not None and valid_drag
                        and gesture_context is not None):
                    persist(drag_item, point, gesture_context)
                    pending_click = None
                elif (drag_item is not None and gesture_context is not None
                      and foreground and _source_point(press_point)
                      and point is not None and press_point is not None
                      and abs(point[0] - press_point[0])
                      + abs(point[1] - press_point[1]) < 80):
                    pending_click = (
                        drag_item, copy.deepcopy(gesture_context),
                        time.monotonic() + 8.0,
                    )
                    record({
                        "event": "unit_click_selected",
                        "item_id": str(drag_item),
                        "unit": unit_catalogue[drag_item]["key"],
                    })
                elif (pending_click is not None and foreground
                      and _target_slot(press_point) is not None
                      and _target_slot(point) == _target_slot(press_point)):
                    pending_item, pending_context, expires = pending_click
                    pending_click = None
                    if time.monotonic() <= expires:
                        persist(pending_item, point, pending_context)
                    else:
                        record({"event": "unit_click_selection_expired"})
                elif valid_drag:
                    record({"event": identity_reason})
                drag_start = None
                drag_candidates = set()
                gesture_foreground = False
                gesture_context = None
                gesture_lower_ms = None
                press_point = None
            was_down = down
            if not down:
                last_button_up_sample_ms = sampled_at_ms
                clear_queue(source_events)
                clear_queue(drop_keys)
            time.sleep(0.01)
    finally:
        specialization_stopped = True
        if specialization_presentation is not None:
            specialization_stopped = specialization_presentation.close() and specialization_stopped
        if specialization_bridge is not None:
            specialization_stopped = specialization_bridge.close() and specialization_stopped
        refresh_coordinator.close()
        if specialization_stopped:
            try:
                script.unload()
            except Exception:
                pass
            try:
                session.detach()
            except Exception:
                pass
        else:
            record({"event": "specialization_worker_abandoned_after_script_gate_closed",
                    "user_action_required": True})
            exit_status = 4
            try:
                script.unload()
            except Exception:
                pass
            try:
                session.detach()
            except Exception:
                pass
        handle.close()
        if kernel32 is not None and bridge_mutex is not None:
            kernel32.CloseHandle(bridge_mutex)
    return exit_status


if __name__ == "__main__":
    raise SystemExit(main())
