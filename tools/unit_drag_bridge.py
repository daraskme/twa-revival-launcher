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
import itertools
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

from tools.player_native_payload import GAME_HASH

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
  [0xc5b4e0, '558bec83ec0c568bf18b4e1485c97405'],
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

// BC1670 can return success without sending the supplied profile request:
// while +0x138 or +0x150 is nonzero it only sets +0x148. This occurs during
// old-unit ability cleanup (live Iberian cavalry reproduction). Wait for the
// queue on its owning frame thread before raising the existing stock byte.
// No profile, queue field, return value, or instruction is modified.
let pendingProfileRefresh = null;
Interceptor.attach(game.base.add(0xc5b4e0), {
  onEnter() {
    const job = pendingProfileRefresh;
    if (!job) return;
    if (Date.now() >= job.deadline) {
      pendingProfileRefresh = null;
      send({kind:'profile_refresh_not_consumed', token:job.token,
            reason:'native_queue_timeout'});
      return;
    }
    try {
      const owner = this.context.ecx.add(0x18).readPointer();
      if (owner.isNull() || owner.add(0x121).readU8() !== 0 ||
          owner.add(0x138).readU32() !== 0 ||
          owner.add(0x150).readU32() !== 0 ||
          !owner.add(0x1b8).readPointer().equals(owner.add(0x1bc))) return;
      const before = profileRefreshFlag.readU8();
      pendingProfileRefresh = null;
      if (before !== 0 && before !== 1) {
        send({kind:'profile_refresh_arm_rejected', token:job.token, before});
        return;
      }
      if (before === 0) profileRefreshFlag.writeU8(1);
      observeProfileRefreshConsumption(job.token, 80);
    } catch (error) {
      pendingProfileRefresh = null;
      send({kind:'profile_refresh_arm_failed', token:job.token,
            error:String(error)});
    }
  }
});

function receiveProfileRefreshArm() {
  recv('arm_profile_refresh', message => {
    const payload = message && message.payload;
    const token = payload && payload.token;
    const budget = payload && payload.max_wait_ms;
    if (typeof token !== 'string' || !Number.isInteger(budget) ||
        budget <= 0 || budget > 8000) {
      send({kind:'profile_refresh_arm_rejected', token,
            reason:'invalid_refresh_deadline'});
    } else {
      const coalesced = pendingProfileRefresh !== null;
      const job = {token, deadline:Date.now() + budget};
      pendingProfileRefresh = job;
      // Armed means queued for a safe frame; it does not prove a byte write,
      // a dispatched HTTP request, or visual application.
      send({kind:'profile_refresh_armed', token, coalesced});
      setTimeout(() => {
        if (pendingProfileRefresh === job) {
          pendingProfileRefresh = null;
          send({kind:'profile_refresh_not_consumed', token,
                reason:'native_queue_timeout'});
        }
      }, budget);
    }
    receiveProfileRefreshArm();
  });
}

function u32(pointer, offset) {
  try { return pointer.add(offset).readU32(); } catch (_) { return null; }
}

// One counter for unit_drag_source and unit_drop_target.  Frida runs hook
// callbacks one at a time and delivers send() in order, so a larger seq was
// emitted later in the game's own processing order.  The host uses it to keep
// a late target of an earlier drop from resolving the current drag.
let unitDragSeq = 0;
function nextUnitDragSeq() {
  unitDragSeq += 1;
  return unitDragSeq;
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
        send({kind:'unit_drag_source', source_hook:'drag_begin', lo:String(lo), hi:String(hi),
              emitted_at_ms:Date.now(), seq:nextUnitDragSeq()});
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
      send({kind:'unit_drag_source', source_hook:'dispatcher', lo:String(lo), hi:String(hi),
            emitted_at_ms:Date.now(), seq:nextUnitDragSeq()});
    }
  }
});

// The deployment bar can be reordered in-game (bar card onto bar card).  That
// swaps only the on-screen cards, so the release position cannot name the
// saved slot; the game's own replaced-unit object can.  Static proof on the
// release DLL, byte-identical at every anchor below in each accepted build on
// disk:
//   roster UnitCard drag-end DB5A30 -> D68CB0 (squad_slots hit-test)
//   -> call D21410 @D68D9C (ret D68DA1) -> occupied slot: call C55F10 @D21518
//   (ret D2151D) -> loop: call C4BC60 @C55FBA (ret C55FBF), once per replaced
//   unit and before any purchase/child logic, with or without consumables.
// arg0 of that C4BC60 call is the deployed item being replaced.  Its u64
// instance id at +8/+0xc is the refund parent_id and the server's slot
// instance id.  Bar reorders run DB5A90 -> D69000 -> D94AF0 -> C5A7C0 ->
// BFC770, never reach C55F10 and leave item+8 unchanged.  Both hooks are
// optional: an anchor mismatch or a failed attach installs nothing, reports
// *_unavailable, never stops this script, and the host keeps its screen-slot
// rules.
// Anchors, in order: the hooked prologue; C55F10's frame and arguments; its
// loop (ESI is the element, the call returns to C55FBF); D21410's frame;
// D21410 writing [ebp-8] (owned item) and [ebp-0xc] (map node); D21410
// calling C55F10 (ret D2151D); the roster drag-end calling D21410 (ret
// D68DA1).
const DROP_TARGET_ANCHORS = [
  [0xc4bc60, '558bec81ecbc000000538b5d088bc15657538b48'],
  [0xc55f10, '558bec81eccc0000008b450c5356578b780c'],
  [0xc55fab, '8b46088bcb8945fc8d45e050ff760ce8a15cffff'],
  [0xd21410, '558bec83ec4053578b7d108bcf'],
  [0xd21488, '8b55f08d4b6c8b42108945f88b45088945f48d45f4508d45dc50e80940baff8d5370f30f7e008b40088945f48945cc'],
  [0xd214fb, '8b45f48d4dd083c008508d45c050e86248dfffff75f88d45d08bcf5053e8f349f3ff'],
  [0xd68d90, '8b75fc8b5df8538d46405057e86f86fbff83c40c'],
];
// C5A7C0 is hooked whole; D94C3D is the bar drop's call to it (ret D94C4C).
const REORDER_ANCHORS = [
  [0xc5a7c0, '558bec8b4914e8c5e4f8ff85c074088bc85de9991ffaff5dc20c00'],
  [0xd94c3d, '8b4df457ff75fcff75e8e8745becff'],
];

function anchorsMatch(list, kind) {
  for (const [rva, expected] of list) {
    let actual = null;
    try {
      actual = bytesHex(game.base.add(rva), expected.length / 2);
    } catch (_) {}
    if (actual !== expected) {
      send({kind, reason:'anchor_mismatch', rva, expected, actual});
      return false;
    }
  }
  return true;
}

let dropTargetHook = 'unavailable';
if (anchorsMatch(DROP_TARGET_ANCHORS, 'unit_drop_target_unavailable')) {
  const RET_C55F10_LOOP = game.base.add(0xc55fbf);
  const RET_D21410_TO_C55F10 = game.base.add(0xd2151d);
  const RET_D68CB0_TO_D21410 = game.base.add(0xd68da1);
  try {
    Interceptor.attach(game.base.add(0xc4bc60), {
      onEnter(args) {
        // Recursion (C4BCF1) and every other caller are ignored.
        if (!this.returnAddress.equals(RET_C55F10_LOOP)) return;
        const emitted_at_ms = Date.now();
        const seq = nextUnitDragSeq();
        try {
          const target = args[0];            // [esp+4]: deployed item replaced
          const element = this.context.esi;  // loop element: +8 key, +0xc item
          const f1 = this.context.ebp;       // C55F10 frame; no prologue ran yet
          const ret1 = f1.add(4).readPointer();
          const incoming = f1.add(0x10).readPointer();  // arg3: dropped unit
          const key = element.add(8).readS32();
          let path = 'other';
          let checks = element.add(0xc).readPointer().equals(target);
          if (ret1.equals(RET_D21410_TO_C55F10)) {
            const f2 = f1.readPointer();     // saved ebp: D21410 frame
            const node = f2.sub(0xc).readPointer();
            checks = checks && f2.add(8).readS32() === key
                     && node.add(8).readS32() === key
                     && node.add(0xc).readPointer().equals(target)
                     && f2.sub(8).readPointer().equals(incoming);
            // D63FFF is the tech-tree hotkey; only D68DA1 is a roster drag.
            path = f2.add(4).readPointer().equals(RET_D68CB0_TO_D21410)
              ? 'roster_drag' : 'd21410_other';
          }
          if (!checks) {
            send({kind:'unit_drop_target_unreadable', reason:'frame_mismatch',
                  path, emitted_at_ms, seq});
            return;
          }
          send({kind:'unit_drop_target', path, key,
                lo:String(target.add(8).readU32()),
                hi:String(target.add(0xc).readU32()),
                incoming_lo:String(incoming.add(8).readU32()),
                incoming_hi:String(incoming.add(0xc).readU32()),
                emitted_at_ms, seq});
        } catch (_) {
          send({kind:'unit_drop_target_unreadable', reason:'read_failed',
                emitted_at_ms, seq});
        }
      }
    });
    dropTargetHook = 'installed';
  } catch (_) {
    // Optional: a failed attach leaves the screen-slot rules in charge.
    send({kind:'unit_drop_target_unavailable', reason:'attach_failed',
          rva:0xc4bc60});
  }
}

// Log-only: a bar-to-bar drag swaps two commander-map entries here.  The host
// uses it only to stop trusting screen positions for this game process.
let reorderObserver = 'unavailable';
if (anchorsMatch(REORDER_ANCHORS, 'deployment_bar_reorder_unavailable')) {
  const RET_BAR_DROP = game.base.add(0xd94c4c);
  try {
    Interceptor.attach(game.base.add(0xc5a7c0), {
      onEnter(args) {
        try {
          send({kind:'deployment_bar_reorder',
                path:(this.returnAddress.equals(RET_BAR_DROP)
                  ? 'bar_drag' : 'other'),
                src:args[1].toInt32(), dst:args[2].toInt32(),
                emitted_at_ms:Date.now()});
        } catch (_) {}
      }
    });
    reorderObserver = 'installed';
  } catch (_) {
    send({kind:'deployment_bar_reorder_unavailable', reason:'attach_failed',
          rva:0xc5a7c0});
  }
}

receiveProfileRefreshArm();
send({kind:'hooks_ready', drop_target_hook:dropTargetHook,
      reorder_observer:reorderObserver});
"""


LOADOUT_URL = "http://127.0.0.1:18765/native-probe/loadout/unit"
# A save includes the cloud profile write (15-second network timeout) and
# native graph validation. The old five-second limit could abandon a save
# that subsequently committed, leaving its live refresh unacknowledged.
UNIT_SELECTION_SAVE_TIMEOUT_SECONDS = 30.0
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
    # Reviewed native 0.2.4 far-terrain address-space fix; drag anchors unchanged.
    GAME_HASH,
})
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
ERROR_ALREADY_EXISTS = 183
BRIDGE_MUTEX_PREFIX = "Local\\TWARevivalUnitDragBridge-"
PROFILE_REFRESH_MAX_ATTEMPTS = 4
PROFILE_REFRESH_ARM_TIMEOUT_SECONDS = 1.0
PROFILE_REFRESH_OBSERVE_TIMEOUT_SECONDS = 8.0
PROFILE_REFRESH_SERVER_ACK_POLL_SECONDS = 0.05
# The server's receipt-correlated external gate lasts 10 seconds.  Stop before
# that authority can expire; a later blind arm could provoke an ordinary stale
# profile replacement instead of the reviewed correlated ok_resync path.
PROFILE_REFRESH_TOTAL_TIMEOUT_SECONDS = 8.0
PROFILE_REFRESH_BACKOFF_SECONDS = (0.15, 0.3, 0.6, 0.75)
# The drop-target hook reports the replaced unit while Arena processes the
# mouse-up.  Every wait ends as soon as this gesture's target arrives or the
# button goes down again; the bounds only cover a late message.
# Ordering dependency: for an occupied slot the game also posts its own
# refund /event for the old unit's consumables (logged 225-373 ms after
# release), and the server accepts that batch only as the cleanup of an
# already saved swap.  While no reorder is latched the screen slot is still a
# safe fallback, so the wait is capped well before that /event and the
# fallback POST wins the race, as in 0.2.26.
NATIVE_TARGET_FALLBACK_WAIT_SECONDS = 0.12
# With a latched reorder nothing may be saved without the game's own target,
# so wait longer (a save after the /event beats no save at all).
NATIVE_TARGET_LATCHED_WAIT_SECONDS = 0.5
# Wait slice: how often the button is re-checked while waiting.
NATIVE_TARGET_POLL_SECONDS = 0.01
# A target belongs to a release only if the game emitted it at or after the
# last loop sample that still saw the button down, minus this slack (a press
# that blocked the loop, e.g. in its context GET, may cover the whole drag).
# JS Date.now() and Python time.time_ns() read the same Windows system clock
# in epoch milliseconds (field logs: Python receipt minus JS emission
# 0.0-8.8 ms, median 0.7 ms, n=859); the slack only absorbs its tick
# granularity (up to 15.6 ms per tick).
NATIVE_TARGET_CLOCK_SLACK_MS = 30
# Native-message budget for a screen drag without the hook, and the emission
# bound for drag-source notifications after release (the 0.2.26 grace).
NATIVE_EVENT_GRACE_SECONDS = 0.05
# With the hook, a held source-region press that moved this far is a drag;
# shorter gestures stay clicks (click-to-assign).
NATIVE_DRAG_MIN_MOVEMENT = 80
# Screen geometry may name a slot only until a deployment-bar reorder is seen
# in this game process.  False refuses every screen-slot save.
SCREEN_SLOT_FALLBACK = True
REORDER_LATCH_EVENT = "deployment_bar_reorder_observed"
REORDER_LATCH_SCAN_BYTES = 16 * 1024 * 1024
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
    arm acknowledgement only proves that a safe-frame job was queued; it
    does not prove that the stock byte was written or consumed.  The coordinator
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
                "payload": {
                    "token": token,
                    "max_wait_ms": max(1, min(8000, int(
                        (self._deadline - self._clock()) * 1000,
                    ))),
                },
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


def _compose_arcani_slot_fix(
    root: Path, agent_source: str, mode: str, game_sha256: str,
):
    """Preflight and compose the pinned Arcani hook before any native attach."""
    if mode == "off":
        return agent_source, None
    if mode not in {"observe", "enabled"}:
        raise ValueError("invalid_arcani_slot_fix_mode")
    from tools import native_arcani_slot_fix
    if game_sha256 != native_arcani_slot_fix.GAME_SHA256:
        raise RuntimeError("arcani_slot_fix_unreviewed_game")
    return (agent_source + "\n" + native_arcani_slot_fix.build_source(
        str(root / "client" / "game.dll"), apply=mode == "enabled",
    ), native_arcani_slot_fix)


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
    arcani_slot_fix_ready: threading.Event | None = None,
) -> None:
    """Load one composed script and require its complete initialization."""
    try:
        script.on("message", on_message)
        script.load()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if script_failed.is_set():
                raise RuntimeError("unit_drag_script_startup_error")
            if (hooks_ready.is_set() and specialization_host_ready.is_set()
                    and (arcani_slot_fix_ready is None
                         or arcani_slot_fix_ready.is_set())):
                return
            time.sleep(min(0.02, max(0.0, deadline - time.monotonic())))
        if script_failed.is_set():
            raise RuntimeError("unit_drag_script_startup_error")
        if not hooks_ready.is_set():
            raise RuntimeError("unit_drag_hooks_not_ready")
        if (arcani_slot_fix_ready is not None
                and not arcani_slot_fix_ready.is_set()):
            raise RuntimeError("arcani_slot_fix_not_ready")
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
    target_instance_id: int | None,
    control_capability: str | None = None,
) -> dict:
    """POST one save; ``target_instance_id`` is the game-reported slot item.

    ``None`` means the slot came from screen geometry.  The key is always
    sent, so the server refuses a helper that predates native targets.
    """
    if target_instance_id is not None and (
            type(target_instance_id) is not int
            or not 0 < target_instance_id < 2**64):
        raise ValueError("invalid_target_instance_id")
    body = json.dumps({
        "item_id": str(item_id),
        "slot": slot,
        "commander_item_id": str(commander_item_id),
        "expected_saved": expected_saved,
        "target_instance_id": (None if target_instance_id is None
                               else str(target_instance_id)),
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
    with _open_loadout(request, UNIT_SELECTION_SAVE_TIMEOUT_SECONDS, control_capability) as response:
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


def _left_button_down() -> bool:
    """Re-check the physical button while waiting for a native target."""
    return bool(user32.GetAsyncKeyState(0x01) & 0x8000)


def _button_held_at_arrival() -> bool:
    """The physical button as a drag source reaches the host.

    Read on the Frida message thread, so a press made while the loop is
    blocked (a POST) and never sampled still leaves a trace.  A failed read
    is "not held": the source is then treated like a hover redraw.
    """
    try:
        return _left_button_down()
    except Exception:
        return False


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


def _is_native_drag(
    start: tuple[int, int] | None, end: tuple[int, int] | None,
) -> bool:
    """A held source-region press that moved; the game names any target."""
    if not _source_point(start) or end is None:
        return False
    assert start is not None
    return (abs(end[0] - start[0]) + abs(end[1] - start[1])
            >= NATIVE_DRAG_MIN_MOVEMENT)


def _bar_reorder_gesture(
    press: tuple[int, int] | None, end: tuple[int, int] | None,
) -> bool:
    """Press on one deployment-bar card and release on another one.

    Like a native drag, the pointer must have moved at least
    ``NATIVE_DRAG_MIN_MOVEMENT``: a click that straddles a card boundary by
    a pixel is no reorder.  The host uses this only without the C5A7C0
    observer; with it, the game's own report is authoritative.
    """
    first, second = _target_slot(press), _target_slot(end)
    if first is None or second is None or first == second:
        return False
    assert press is not None and end is not None
    return (abs(end[0] - press[0]) + abs(end[1] - press[1])
            >= NATIVE_DRAG_MIN_MOVEMENT)


def _unique_unit_candidate(candidates: set[int]) -> int | None:
    return next(iter(candidates)) if len(candidates) == 1 else None


def _recover_proven_drag_source(
    sources: list[tuple[int, int, int, bool, str | None]],
    *,
    source_overflow: bool,
    invalid_source_seen: bool,
    arrived: list[dict],
    targets: list[dict],
    wait_end: str,
    press_sampled_at_ms: int | None,
    released_at_ms: int,
    target_wait_upper_ms: int,
    lower_ms: int,
    upper_ms: int,
    slot_instance_ids: list[int],
    catalogue_ids,
) -> tuple[int, tuple[int, int, str], int] | None:
    """Resolve one later genuine drag start against one exact native target.

    Dispatcher reports can name a card traversed while a drag begins.  Their
    disagreement is ignored only when every conflicting report strictly
    predates a single held DBD7E0 drag-begin report.  The native target must
    independently name that same known unit and one owned slot.  No label,
    source, or slot may be inferred from the screen.
    """
    if (source_overflow or invalid_source_seen or wait_end != "target"
            or type(press_sampled_at_ms) is not int
            or type(released_at_ms) is not int
            or press_sampled_at_ms <= 0
            or released_at_ms < press_sampled_at_ms
            or type(target_wait_upper_ms) is not int
            or target_wait_upper_ms < released_at_ms
            or len(arrived) != 1 or len(targets) != 1
            or arrived[0] is not targets[0] or not sources
            or len({event[2] for event in sources}) != len(sources)):
        return None
    genuine = [event for event in sources if event[4] == "drag_begin"]
    if len(genuine) != 1:
        return None
    proof_ms, item_id, proof_seq, held, _hook = genuine[0]
    if (not held or proof_ms < press_sampled_at_ms
            or proof_ms > released_at_ms
            or item_id not in catalogue_ids):
        return None
    for emitted_ms, source_id, seq, _held, hook in sources:
        if (source_id not in catalogue_ids
                or emitted_ms < press_sampled_at_ms
                or hook not in {"drag_begin", "dispatcher"}):
            return None
        if source_id != item_id and not (
                hook == "dispatcher" and seq < proof_seq
                and emitted_ms < proof_ms):
            return None
    target = targets[0]
    if (target["unreadable"] or target["path"] != "roster_drag"
            or target["incoming_id"] != item_id
            or target["seq"] <= max(event[2] for event in sources)
            or target["emitted_at_ms"] <= proof_ms
            or target["emitted_at_ms"] < released_at_ms
            or target["emitted_at_ms"] > target_wait_upper_ms):
        return None
    native = _resolve_native_slot(
        targets, lower_ms=lower_ms, upper_ms=upper_ms,
        slot_instance_ids=slot_instance_ids, source_item=item_id,
        catalogue_ids=catalogue_ids, ordered=False,
    )
    if native[2] != "resolved" or native[0] is None or native[1] is None:
        return None
    return item_id, native, proof_seq


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


_DROP_TARGET_PATHS = ("roster_drag", "d21410_other", "other")
_DROP_TARGET_UNREADABLE_REASONS = ("frame_mismatch", "read_failed")
_HOOK_UNAVAILABLE_REASONS = ("anchor_mismatch", "attach_failed")
# POST outcomes that stored the gesture's slot decision on the server.
_SAVED_OUTCOMES = frozenset({"persisted", "unchanged"})
# Only a gesture without any native event may use the screen slot (and only
# while no reorder is latched).  Native evidence that is unreadable,
# ambiguous, unordered or contradicting refuses the save: the game did
# report this drop, so the screen position is no longer the safe guess.
_SCREEN_FALLBACK_NATIVE_REASONS = frozenset({"native_target_missing"})


def _u32_text(value: object) -> int | None:
    if (not isinstance(value, str) or not value.isascii()
            or not value.isdigit() or len(value) > 10):
        return None
    number = int(value)
    return number if number < 2**32 else None


def _uint64_text(value: object) -> bool:
    return bool(
        isinstance(value, str) and value.isascii() and value.isdigit()
        and len(value) <= 20 and str(int(value)) == value
        and 0 < int(value) < 2**64
    )


def _event_seq(value: object) -> int | None:
    """The agent's shared unit-drag event counter, strictly positive."""
    return value if type(value) is int and 0 < value < 2**53 else None


def _hook_state(value: object) -> str:
    return value if value in ("installed", "unavailable") else "invalid"


def _anchor_report(payload: dict) -> dict:
    """Bounded fields of an unavailable optional hook (mismatch or attach)."""
    rva = payload.get("rva")
    reason = payload.get("reason")
    report: dict = {
        "reason": reason if reason in _HOOK_UNAVAILABLE_REASONS else None,
        "rva": rva if type(rva) is int and 0 <= rva < 2**32 else None,
    }
    for name in ("expected", "actual"):
        value = payload.get(name)
        report[name] = (
            value if isinstance(value, str)
            and re.fullmatch(r"[0-9a-f]{2,256}", value) else None
        )
    return report


def _parse_drop_target(payload: object) -> dict | None:
    """Strictly parse one C4BC60 drop-target (or unreadable) message."""
    if not isinstance(payload, dict):
        return None
    kind = payload.get("kind")
    path = payload.get("path")
    emitted_at_ms = payload.get("emitted_at_ms")
    seq = _event_seq(payload.get("seq"))
    if (type(emitted_at_ms) is not int or not 0 < emitted_at_ms < 2**53
            or seq is None):
        return None
    if kind == "unit_drop_target_unreadable":
        reason = payload.get("reason")
        if (reason not in _DROP_TARGET_UNREADABLE_REASONS
                or (path is not None and path not in _DROP_TARGET_PATHS)):
            return None
        return {"unreadable": True, "reason": reason, "path": path,
                "emitted_at_ms": emitted_at_ms, "seq": seq}
    parts = [_u32_text(payload.get(name))
             for name in ("lo", "hi", "incoming_lo", "incoming_hi")]
    key = payload.get("key")
    if (kind != "unit_drop_target" or path not in _DROP_TARGET_PATHS
            or None in parts or type(key) is not int
            or not -2**31 <= key < 2**31):
        return None
    lo, hi, incoming_lo, incoming_hi = parts
    instance_id = lo | hi << 32
    if instance_id == 0:
        return None
    return {"unreadable": False, "path": path, "key": key,
            "instance_id": instance_id,
            "incoming_id": incoming_lo | incoming_hi << 32,
            "emitted_at_ms": emitted_at_ms, "seq": seq}


def _roster_drop_target(target: dict) -> bool:
    """Evidence about a roster drag; a failed read may not know its path."""
    return (target["path"] == "roster_drag"
            or (target["unreadable"] and target["path"] is None))


def _native_target_wait(
    *, native_drag: bool, valid_drag: bool, reorder_latched: bool,
    screen_fallback: bool = True,
) -> float:
    """How long one release may wait for its native target."""
    if native_drag:
        if not screen_fallback:
            # Software-rendered clients can report the native drop after the
            # former 120ms screen fallback. Wait for its exact instance;
            # timeout is a refusal, never permission to guess a slot.
            return 1.0
        # Bar or not: the game's target is authoritative wherever the
        # release landed.  Only an unlatched wait has a screen fallback.
        return (NATIVE_TARGET_LATCHED_WAIT_SECONDS if reorder_latched
                else NATIVE_TARGET_FALLBACK_WAIT_SECONDS)
    return NATIVE_EVENT_GRACE_SECONDS if valid_drag else 0.0


def _wait_native_targets(
    events: queue.Queue,
    *,
    timeout: Callable[[], float] | float,
    accept: Callable[[dict], bool],
    stop: Callable[[], bool] | None = None,
    poll: float = NATIVE_TARGET_POLL_SECONDS,
    # Not time.monotonic: on Python 3.11 for Windows it ticks every 15.6 ms,
    # a large share of a 120 ms bound.
    clock: Callable[[], float] = time.perf_counter,
) -> tuple[list[dict], str]:
    """Collect the native targets of one release.

    Messages that already arrived are always taken.  The wait ends as soon as
    ``accept`` names one of them this release's target (anything already
    queued behind it is drained without waiting), when ``stop`` reports the
    button down again, or ``timeout`` seconds after it started.  A callable
    ``timeout`` is re-read every ``poll`` seconds, so a reorder latched during
    the wait extends it.  Returns ``(targets, end)``; ``end`` is ``"target"``,
    ``"button_down"`` or ``"timeout"``.
    """
    started = clock()
    found: list[dict] = []
    while True:
        try:
            target = events.get_nowait()
        except queue.Empty:
            limit = timeout() if callable(timeout) else timeout
            remaining = started + limit - clock()
            if remaining <= 0:
                return found, "timeout"
            if stop is not None and stop():
                return found, "button_down"
            try:
                target = events.get(timeout=min(remaining, poll))
            except queue.Empty:
                continue
        found.append(target)
        if accept(target):
            while True:
                try:
                    found.append(events.get_nowait())
                except queue.Empty:
                    return found, "target"


def _release_target(
    target: dict,
    *,
    lower_ms: int,
    last_down_arrival: int | None,
    source_seq: int | None,
) -> bool:
    """Could Arena have emitted ``target`` for the release being handled?

    Never when it reached the host before a loop sample that still saw the
    button down (``arrival`` order; the game reports a drop only after its
    mouse-up), when it was emitted before that last down sample minus the
    clock slack (``lower_ms``), or when the game emitted it before this
    gesture's own drag source (``seq``).  Such targets belong to an earlier
    gesture and only the late-target rules see them.  Without a held drag
    source (``source_seq`` None) nothing orders an earlier drop's target
    before this one: ``_resolve_native_slot`` then accepts only a target
    that names the dragged unit.
    """
    return (
        (last_down_arrival is None
         or target["arrival"] > last_down_arrival)
        and target["emitted_at_ms"] >= lower_ms
        and (source_seq is None or target["seq"] > source_seq)
    )


def _late_target_owner(
    entry: dict | None, target: dict, *, next_source_seq: int | None = None,
    catalogue_ids=frozenset(),
) -> bool:
    """Is ``entry``, the last native-drag release, the gesture of ``target``?

    Its window opens at that release's last down sample minus the clock
    slack, after its own drag source (``seq``), and closes at the next
    press: at the press sample (or at the drag source of a press the loop
    never sampled) and, in the game's own order, before the next gesture's
    first drag source (``next_source_seq``, or the entry's own
    ``next_source_seq`` for an unsampled press).  Without a held source of
    its own, a target that names another catalogue unit is not the entry's.
    A target outside the window is only logged: no earlier gesture is kept
    to compare it with.
    """
    if entry is None:
        return False
    emitted_at_ms, seq = target["emitted_at_ms"], target["seq"]
    if (emitted_at_ms < entry["lower_ms"]
            or (entry["source_seq"] is not None
                and seq <= entry["source_seq"])):
        return False
    item_id = entry.get("item_id")
    if (entry["source_seq"] is None and item_id is not None
            and not target["unreadable"]
            and target["incoming_id"] in catalogue_ids
            and target["incoming_id"] != item_id):
        return False
    if entry["closed_at_ms"] is None:
        return True
    limits = [value for value in (next_source_seq,
                                  entry.get("next_source_seq"))
              if value is not None]
    return (emitted_at_ms <= entry["closed_at_ms"]
            and (not limits or seq < min(limits)))


def _resolve_native_slot(
    targets: list[dict],
    *,
    lower_ms: int | None,
    upper_ms: int,
    slot_instance_ids: list[int],
    source_item: int | None,
    catalogue_ids,
    ordered: bool = True,
) -> tuple[int | None, int | None, str]:
    """Map the game's replaced-unit id to its saved slot; never guess.

    ``ordered`` means a drag source held before the release orders this
    release's targets after every earlier drop's (``_release_target``).
    The dropped item's +8 is inferred to be its catalogue id and never names
    the unit.  It first filters out targets of another catalogue unit (an
    earlier drop's).  Without a held source it must name the dragged unit
    itself: an earlier drop of an unverifiable unit could otherwise pass for
    this one.  Any native evidence that then does not name exactly one slot
    refuses the save (``native_target_missing`` alone may fall back).
    """
    relevant = [
        target for target in targets
        if _roster_drop_target(target)
        and _event_in_gesture(target["emitted_at_ms"], lower_ms, upper_ms)
    ]
    unreadable = [target for target in relevant if target["unreadable"]]
    drops = [target for target in relevant if not target["unreadable"]]
    if unreadable and not drops:
        return None, None, "native_target_unreadable"
    if not drops:
        return None, None, "native_target_missing"

    def this_unit(target: dict) -> bool:
        incoming = target["incoming_id"]
        if source_item is None:
            return ordered
        if incoming == source_item:
            return True
        return ordered and incoming not in catalogue_ids

    candidates = [target for target in drops if this_unit(target)]
    if unreadable:
        return None, None, "native_target_ambiguous"
    if not candidates:
        if source_item is not None and any(
                target["incoming_id"] in catalogue_ids for target in drops):
            return None, None, "native_incoming_unit_mismatch"
        return None, None, "native_incoming_unit_unverified"
    instance_ids = {target["instance_id"] for target in candidates}
    if len(instance_ids) != 1:
        return None, None, "native_target_ambiguous"
    instance_id = next(iter(instance_ids))
    if instance_id not in slot_instance_ids:
        return None, None, "native_target_not_in_context_commander"
    return slot_instance_ids.index(instance_id), instance_id, "resolved"


def _drop_slot_decision(
    native: tuple[int | None, int | None, str] | None,
    *,
    screen_slot: int | None,
    screen_eligible: bool,
    reorder_latched: bool,
    screen_fallback: bool = SCREEN_SLOT_FALLBACK,
) -> tuple[int | None, int | None, str | None, str]:
    """Return ``(slot, target_instance_id, slot_source, reason)``.

    ``native`` is the ``_resolve_native_slot`` result, or ``None`` without a
    drop-target hook and for click-to-assign (the game has no target object
    for a click).  A resolved native target always wins.  Screen geometry is
    used only when no native event for the gesture arrived
    (``native_target_missing``) and while no deployment-bar reorder has been
    seen in this game process: a reorder swaps the on-screen cards but not
    the saved slots.  Unreadable, ambiguous, unverified or contradicting
    native evidence refuses.  A ``None`` slot means refuse (no POST).
    """
    if native is not None:
        slot, instance_id, reason = native
        if reason == "resolved":
            return slot, instance_id, "native", reason
        if reason not in _SCREEN_FALLBACK_NATIVE_REASONS:
            return None, None, None, reason
    if screen_slot is None:
        return None, None, None, "no_screen_slot"
    if not screen_eligible:
        return None, None, None, "not_a_screen_drag"
    if reorder_latched:
        return None, None, None, "reorder_observed"
    if not screen_fallback:
        return None, None, None, "screen_slot_fallback_disabled"
    return screen_slot, None, "screen", "screen_slot"


def _drop_target_record(
    target: dict,
    *,
    released_at_ms: int | None,
    slot_instance_ids: list[int] | None = None,
    source_item: int | None = None,
) -> dict:
    """Bounded log fields for one native target, including its delay."""
    row = {
        "path": target["path"],
        "emitted_at_ms": target["emitted_at_ms"],
        "seq": target.get("seq"),
        "delay_ms": (None if released_at_ms is None
                     else target["emitted_at_ms"] - released_at_ms),
        "unreadable": target["unreadable"],
    }
    if target["unreadable"]:
        row["reason"] = target["reason"]
        return row
    instance_id = target["instance_id"]
    row.update({
        "key": target["key"],
        "instance_id": str(instance_id),
        "incoming_id": str(target["incoming_id"]),
        "slot": (slot_instance_ids.index(instance_id)
                 if slot_instance_ids and instance_id in slot_instance_ids
                 else None),
        "incoming_matches_source": (
            None if source_item is None
            else target["incoming_id"] == source_item
        ),
    })
    return row


def _prior_reorder_latch(
    path: Path, pid: int, max_bytes: int = REORDER_LATCH_SCAN_BYTES,
) -> bool:
    """A restarted helper inherits a reorder already seen by this game PID."""
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - max_bytes))
            data = stream.read()
    except OSError:
        return False
    for line in data.splitlines():
        try:
            row = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if (isinstance(row, dict)
                and row.get("event") == REORDER_LATCH_EVENT
                and type(row.get("pid")) is int and row["pid"] == pid):
            return True
    return False


def _http_error_code(error: BaseException) -> str | None:
    """The loopback server's bounded refusal code, e.g. a target mismatch."""
    if not isinstance(error, urllib.error.HTTPError):
        return None
    try:
        body = json.loads(error.read(4096))
    except Exception:
        return None
    if isinstance(body, dict) and isinstance(body.get("response"), dict):
        body = body["response"]
    code = body.get("error") if isinstance(body, dict) else None
    return (code if isinstance(code, str)
            and re.fullmatch(r"[a-z0-9_]{1,80}", code) else None)


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
        "slot_instance_ids",
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
    slot_instance_ids = context.get("slot_instance_ids")
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
            or any(not isinstance(key, str) or not key for key in units)
            or not isinstance(slot_instance_ids, list)
            or len(slot_instance_ids) != 3
            or not all(_uint64_text(value) for value in slot_instance_ids)
            or len(set(slot_instance_ids)) != 3):
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
        "slot_instance_ids": [int(value) for value in slot_instance_ids],
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
        "arcani_slot_fix_mode",
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
            or command.get("arcani_slot_fix_mode") != args.arcani_slot_fix
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
        "arcani_slot_fix_mode": command["arcani_slot_fix_mode"],
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
    parser.add_argument("--public-pvp-only", action="store_true")
    parser.add_argument(
        "--specialization-mode", choices=("off", "observe", "enabled"),
        default="off",
    )
    parser.add_argument(
        "--arcani-slot-fix", choices=("off", "observe", "enabled"),
        default="off",
    )
    parser.add_argument(
        "--restart-after-persist", action="store_true", help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--owned-control", action="store_true", help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--local-lab-preferences", action="store_true",
        help="route only the local development player's native UI preference object",
    )
    args = parser.parse_args()

    if args.arcani_slot_fix != "off" and args.specialization_mode != "off":
        parser.error("Arcani slot fix and specialization bridge cannot be combined")
    if args.local_lab_preferences and (args.owned_control or args.specialization_mode != "off"):
        raise RuntimeError("local_lab_preferences_requires_plain_development_bridge")

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
    # (emitted_at_ms, item_id, seq, button held when it reached the host)
    source_events: queue.Queue[tuple[int, int, int, bool, str | None]] = queue.Queue()
    drop_targets: queue.Queue[dict] = queue.Queue()
    # One order for target arrivals and the loop's button samples (a clock
    # would tie: Python 3.11's monotonic clock ticks every 15.6 ms here).
    arrival_order = itertools.count(1)
    # Once a deployment-bar reorder is seen in this game process, screen
    # geometry can no longer name a saved slot.  The latch never clears; a
    # restarted helper inherits it from this PID's earlier log rows.
    reorder_latched = threading.Event()
    if _prior_reorder_latch(args.output, args.pid):
        reorder_latched.set()
    drop_target_hook: str | None = None
    reorder_observer: str | None = None
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
    arcani_slot_fix_ready = threading.Event()
    script_failed = threading.Event()
    party_mode_log_count = 0
    source_provenance_count = 0
    invalid_source_count = 0
    invalid_target_count = 0
    if args.specialization_mode == "off":
        specialization_host_ready.set()
    if args.arcani_slot_fix == "off":
        arcani_slot_fix_ready.set()
    arcani_slot_fix_host = None

    def record(row: dict) -> None:
        with record_lock:
            handle.write(json.dumps({"time": time.time(), **row}) + "\n")

    record({
        "event": "instrumentation_target_verified",
        "pid": args.pid,
        "arena": target["arena"],
        "game_sha256": target["game_sha256"],
    })
    if reorder_latched.is_set():
        record({"event": "reorder_latch_inherited", "pid": args.pid})

    def latch_reorder(source: str, **detail) -> None:
        reorder_latched.set()
        record({"event": REORDER_LATCH_EVENT, "pid": args.pid,
                "source": source, **detail})

    def on_message(message: dict, _data: object) -> None:
        nonlocal party_mode_log_count, source_provenance_count, invalid_source_count, invalid_target_count, drop_target_hook, reorder_observer
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
            drop_target_hook = _hook_state(payload.get("drop_target_hook"))
            reorder_observer = _hook_state(payload.get("reorder_observer"))
            hooks_ready.set()
            record({"event": "hooks_ready", "pid": args.pid,
                    "drop_target_hook": drop_target_hook,
                    "reorder_observer": reorder_observer})
            return
        kind = payload.get("kind")
        if isinstance(kind, str) and kind.startswith(("slot_mapper_", "slot_trial_")):
            if arcani_slot_fix_host is not None:
                detail = arcani_slot_fix_host.safe_record(payload)
                if detail is not None:
                    if detail["event"] == "slot_mapper_ready":
                        arcani_slot_fix_ready.set()
                    record(detail)
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
        if payload.get("kind") in {
                "unit_drop_target", "unit_drop_target_unreadable"}:
            drop_target = _parse_drop_target(payload)
            if drop_target is None:
                invalid_target_count += 1
                record({"event": "invalid_unit_drop_target"})
            else:
                # Host arrival order, compared with the loop's button samples.
                drop_target["arrival"] = next(arrival_order)
                drop_targets.put(drop_target)
            return
        if payload.get("kind") in {
                "unit_drop_target_unavailable",
                "deployment_bar_reorder_unavailable"}:
            record({"event": payload["kind"], **_anchor_report(payload)})
            return
        if payload.get("kind") == "deployment_bar_reorder":
            path = payload.get("path")
            source, destination = payload.get("src"), payload.get("dst")
            emitted_at_ms = payload.get("emitted_at_ms")
            valid = (path in ("bar_drag", "other")
                     and type(source) is int and type(destination) is int
                     and type(emitted_at_ms) is int
                     and 0 < emitted_at_ms < 2**53)
            if valid and source == destination:
                record({"event": "deployment_bar_reorder_noop",
                        "path": path, "src": source,
                        "emitted_at_ms": emitted_at_ms})
                return
            # Fail closed: even a malformed report stops screen-slot saves.
            latch_reorder(
                "native", path=path if valid else None,
                src=source if valid else None,
                dst=destination if valid else None,
                emitted_at_ms=emitted_at_ms if valid else None,
            )
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
            seq = _event_seq(payload.get("seq"))
            if not (0 <= lo < 2**32 and 0 <= hi < 2**32
                    and type(emitted_at_ms) is int
                    and 0 < emitted_at_ms < 2**53 and seq is not None):
                raise ValueError
            item_id = lo | hi << 32
            # Keep unknown IDs until gesture resolution: a second unknown
            # source must invalidate the gesture, not disappear before a
            # different known source is accepted.  The button state at
            # arrival reveals a press the blocked loop never sampled.
            arrival_at_ms = time.time_ns() // 1_000_000
            arrival_held = _button_held_at_arrival()
            source_hook = payload.get("source_hook")
            source_hook = (source_hook if source_hook in
                           ("drag_begin", "dispatcher") else None)
            source_events.put((emitted_at_ms, item_id, seq,
                               arrival_held, source_hook))
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
                "seq": seq,
                "item_id": str(item_id),
                "unit": unit["key"],
                "faction": unit["faction"],
            })
            if source_provenance_count < 128:
                source_provenance_count += 1
                record({
                    "event": "unit_drag_source_provenance",
                    "seq": seq,
                    "item_id": str(item_id),
                    "source_hook": source_hook,
                    "native_emitted_at_ms": emitted_at_ms,
                    "host_arrival_at_ms": arrival_at_ms,
                    "arrival_held": arrival_held,
                })
        except (KeyError, TypeError, ValueError):
            invalid_source_count += 1
            record({"event": "invalid_unit_candidate"})

    specialization_host = None
    try:
        if args.specialization_mode != "off":
            specialization_host = _load_specialization_host(root)
            agent_source = specialization_host["agent_source"]
        else:
            agent_source = build_agent_source(root, "off")
        if owned_start is not None or args.local_lab_preferences:
            from tools.native_user_preferences import GAME_SHA256S as PREFERENCES_GAME_SHA256S, build_source as build_preferences
            if target["game_sha256"] in PREFERENCES_GAME_SHA256S:
                user_id = (owned_start["native_user_id"] if owned_start is not None
                           else "player")
                agent_source = build_preferences(
                    root, user_id, local_lab=args.local_lab_preferences,
                ) + "\n" + agent_source
            elif args.local_lab_preferences:
                raise RuntimeError("local_lab_preferences_unreviewed_game")
        if owned_start is not None:
            from tools.native_npl_auth import build_source as build_npl_auth
            # Validate both owned stubs before publishing helper readiness.
            agent_source = build_npl_auth(root) + "\n" + agent_source
            from tools.native_mode_availability import GAME_SHA256S as MODE_GAME_SHA256S, build_source as build_mode_availability
            if target["game_sha256"] in MODE_GAME_SHA256S:
                agent_source = build_mode_availability(
                    root, public_pvp_only=args.public_pvp_only,
                ) + "\n" + agent_source
            from tools.native_career_ui import build_source as build_career_ui
            agent_source = build_career_ui(root) + "\n" + agent_source
        agent_source, arcani_slot_fix_host = _compose_arcani_slot_fix(
            root, agent_source, args.arcani_slot_fix, target["game_sha256"],
        )
    except BaseException as error:
        # Never persist exception text here: import errors can contain host
        # paths and future dependency errors may carry sensitive values.
        if args.arcani_slot_fix != "off":
            record({
                "event": "arcani_slot_fix_startup_refused",
                "phase": "host_preflight",
                "error_class": type(error).__name__,
                "reason": "arcani_slot_fix_host_preflight_failed",
            })
        else:
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
        if args.arcani_slot_fix != "off":
            record({
                "event": "arcani_slot_fix_startup_refused",
                "phase": "script_initialization",
                "error_class": type(error).__name__,
                "reason": "arcani_slot_fix_script_initialization_failed",
            })
        else:
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
            arcani_slot_fix_ready=arcani_slot_fix_ready,
        )
    except BaseException:
        if args.specialization_mode != "off" or args.arcani_slot_fix != "off":
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
        last_released_at_ms: int | None = None
        # Arrival order of the last loop sample that saw the button down: a
        # target that reached the host before it cannot name the next release.
        last_down_arrival: int | None = None
        # Epoch ms of that sample: the earliest a release's target can be
        # emitted (minus the clock slack), even when the press blocked the
        # loop in its context GET for the whole drag.
        last_down_sample_ms: int | None = None
        # The last native-drag release, bar or not: its release sample, screen
        # slot, slot ids and what was saved.  Late targets are compared only
        # with it, inside its window (``_late_target_owner``).
        gesture_entry: dict | None = None
        # The first drag source of a press the loop never sampled (it was
        # blocked in a POST), until the next sampled press.
        unobserved_press: dict | None = None
        gesture_lower_ms: int | None = None
        gesture_press_sample_ms: int | None = None
        drag_candidates: set[int] = set()
        gesture_sources: list[tuple[int, int, int, bool, str | None]] = []
        gesture_sources_overflow = False
        source_invalid_at_press = 0
        target_invalid_at_press = 0
        # Smallest ``seq`` among this gesture's accepted drag sources.
        gesture_source_seq: int | None = None
        gesture_foreground = False
        gesture_context: dict | None = None
        press_point: tuple[int, int] | None = None
        pending_click: tuple[int, dict, float] | None = None
        # Only the exact reviewed hook may name slots; any other state keeps
        # the screen rules under the reorder latch.
        native_mode = drop_target_hook == "installed"
        # With the C5A7C0 observer the game reports every bar reorder itself;
        # the physical press/release geometry is only a stand-in without it.
        gesture_reorder_latch = reorder_observer != "installed"
        drop_warning_printed = False
        # Last wait poll that saw the button up (epoch ms).
        wait_last_up_ms: int | None = None

        if _arena_window(args.pid) != hwnd:
            raise RuntimeError("arena_window_changed_during_startup")
        record({"event": "ready", "pid": args.pid,
                "native_drop_target": native_mode,
                "reorder_latched": reorder_latched.is_set(),
                "gesture_reorder_latch": gesture_reorder_latch})
        if owned_start is not None:
            _write_owned_ready(owned_start, target)

        def collect_drag_sources(
            upper_ms: int | None = None, *, keep_later: bool = False,
            released_at_ms: int | None = None,
        ) -> None:
            nonlocal gesture_source_seq, gesture_sources_overflow
            later = []
            while True:
                try:
                    event = source_events.get_nowait()
                except queue.Empty:
                    break
                emitted_at_ms, item_id, seq, _held, _hook = event
                if (keep_later and upper_ms is not None
                        and emitted_at_ms > upper_ms):
                    # After this release's grace: a press that began while
                    # the release waited owns it (or the idle clear drops it).
                    later.append(event)
                    continue
                if (drag_start is not None and gesture_foreground
                        and _event_in_gesture(
                            emitted_at_ms, gesture_lower_ms,
                            upper_ms if upper_ms is not None
                            else time.time_ns() // 1_000_000,
                        )):
                    drag_candidates.add(item_id)
                    if len(gesture_sources) < 32:
                        gesture_sources.append(event)
                    else:
                        gesture_sources_overflow = True
                    # Only a source emitted while the button was held orders
                    # this gesture's targets; a later redraw may follow them.
                    if ((released_at_ms is None
                         or emitted_at_ms <= released_at_ms)
                            and (gesture_source_seq is None
                                 or seq < gesture_source_seq)):
                        gesture_source_seq = seq
                else:
                    record({
                        "event": "out_of_gesture_drag_source_ignored",
                        "item_id": str(item_id),
                        "emitted_at_ms": emitted_at_ms,
                    })
            for event in later:
                source_events.put(event)

        def route_late_target(drop_target: dict, phase: str) -> None:
            # Late, held, hotkey and replace-dialog targets are never saved.
            # One is compared only with the gesture whose window contains its
            # emission; its delay after that release is logged to tune the
            # waits.
            entry = gesture_entry
            # Once closed, the entry precedes the gesture now in progress.
            owned = _late_target_owner(entry, drop_target,
                                       next_source_seq=gesture_source_seq,
                                       catalogue_ids=unit_catalogue)
            row = _drop_target_record(
                drop_target,
                released_at_ms=(entry["released_at_ms"] if owned
                                else last_released_at_ms),
                slot_instance_ids=(entry["slot_instance_ids"] if owned
                                   else None),
                source_item=entry["item_id"] if owned else None,
            )
            record({"event": "native_drop_target_unmatched", "phase": phase,
                    "gesture_released_at_ms": (entry["released_at_ms"]
                                               if owned else None),
                    **row})
            if not _roster_drop_target(drop_target):
                return
            if not owned:
                report_unobserved_drag(drop_target, entry)
                return
            assert entry is not None
            if entry["outcome"] not in _SAVED_OUTCOMES:
                # Arena replaced a unit for a drag that was not saved.
                if not entry["late_reported"]:
                    entry["late_reported"] = True
                    not_saved("late_native_target", item_id=entry["item_id"],
                              screen_slot=entry["screen_slot"],
                              native_reason=entry["native_reason"],
                              input_kind="drag", native_slot=row.get("slot"),
                              outcome=entry["outcome"],
                              released_at_ms=entry["released_at_ms"])
                return
            if (row.get("slot") is None or row["slot"] == entry["slot"]
                    or entry["contradicted"]):
                return
            # The game replaced another slot than this gesture's accepted
            # save.  After a screen save: a reorder the helper did not see.
            # After a native save: the target used was not this drag's (an
            # earlier drop's, taken without a held source to order them).
            # Only the player can repair the loadout now.
            entry["contradicted"] = True
            latch_reorder("late_native_slot_mismatch", slot=row["slot"],
                          screen_slot=entry["screen_slot"],
                          slot_source=entry["slot_source"],
                          released_at_ms=entry["released_at_ms"])
            persisted = entry["outcome"] == "persisted"
            if entry["slot_source"] == "screen":
                event = "unit_drag_screen_save_contradicted"
                message = (
                    "A unit change was saved to the wrong deployment slot "
                    "because the game reported it too late. Restart Arena "
                    "and check the loadout before the next battle."
                ) if persisted else (
                    "A unit change was matched to the wrong deployment slot "
                    "because the game reported it too late; the slot the "
                    "game changed was not saved. Restart Arena and check "
                    "the loadout before the next battle."
                )
            else:
                event = "unit_drag_native_save_contradicted"
                message = (
                    "A unit change was saved to the wrong deployment slot: "
                    "after the save the game reported another slot for the "
                    "same drag. Restart Arena and check the loadout before "
                    "the next battle."
                ) if persisted else (
                    "A unit change was matched to the wrong deployment "
                    "slot: after the check the game reported another slot "
                    "for the same drag, and that slot was not saved. "
                    "Restart Arena and check the loadout before the next "
                    "battle."
                )
            warn(message, event=event,
                 slot=row["slot"], screen_slot=entry["screen_slot"],
                 saved_slot=entry["slot"], slot_source=entry["slot_source"],
                 outcome=entry["outcome"],
                 item_id=(None if entry["item_id"] is None
                          else str(entry["item_id"])),
                 released_at_ms=entry["released_at_ms"])

        def report_unobserved_drag(drop_target: dict,
                                   entry: dict | None) -> None:
            # Arena replaced a unit for a press the loop never sampled (it
            # was blocked in a POST): nothing saved it.
            press = unobserved_press
            if (press is None or press["reported"]
                    or drop_target["seq"] <= press["seq"]):
                return
            press["reported"] = True
            row = _drop_target_record(
                drop_target, released_at_ms=None,
                slot_instance_ids=(None if entry is None
                                   else entry["slot_instance_ids"]),
            )
            not_saved(
                "unobserved_drag", item_id=press["item_id"],
                screen_slot=None, native_reason=None, input_kind="drag",
                native_slot=row.get("slot"),
                source_emitted_at_ms=press["emitted_at_ms"],
                message=(
                    "A deployment-bar unit change made while the previous "
                    "change was being saved was not saved "
                    "(unobserved_drag). Restart Arena before the next "
                    "battle so the hangar shows the saved loadout, then "
                    "make the change again."
                ),
            )

        def drop_idle_sources() -> None:
            # No sampled press claims these sources.  One that reached the
            # host while the button was held comes from a press made while
            # the loop was blocked (a POST): the last release's window
            # closes at it, so that drag's own target is not judged as the
            # last release's.  Sources that arrived with the button up are
            # hover or redraw reports and change nothing.
            nonlocal unobserved_press
            while True:
                try:
                    emitted_at_ms, item_id, seq, held, _hook = (
                        source_events.get_nowait())
                except queue.Empty:
                    return
                if not held:
                    continue
                entry = gesture_entry
                closes = (entry is not None
                          and emitted_at_ms >= entry["released_at_ms"]
                          and (entry["source_seq"] is None
                               or seq > entry["source_seq"]))
                if closes:
                    assert entry is not None
                    if (entry["closed_at_ms"] is None
                            or emitted_at_ms < entry["closed_at_ms"]):
                        entry["closed_at_ms"] = emitted_at_ms
                    if (entry["next_source_seq"] is None
                            or seq < entry["next_source_seq"]):
                        entry["next_source_seq"] = seq
                if unobserved_press is None or seq < unobserved_press["seq"]:
                    unobserved_press = {"seq": seq,
                                        "emitted_at_ms": emitted_at_ms,
                                        "item_id": item_id,
                                        "reported": False}
                record({"event": "unobserved_press_drag_source",
                        "item_id": str(item_id),
                        "emitted_at_ms": emitted_at_ms, "seq": seq,
                        "closes_released_at_ms": (
                            entry["released_at_ms"] if closes else None)})

        def discard_drop_targets(phase: str) -> None:
            while True:
                try:
                    drop_target = drop_targets.get_nowait()
                except queue.Empty:
                    return
                route_late_target(drop_target, phase)

        def button_down_again() -> bool:
            # Polled while waiting for a native target: a new press ends the
            # wait, so input sampling never stalls behind it.
            nonlocal wait_last_up_ms
            now_ms = time.time_ns() // 1_000_000
            if _left_button_down():
                return True
            wait_last_up_ms = now_ms
            return False

        def warn(message: str, *, event: str, **detail) -> None:
            nonlocal drop_warning_printed
            record({"event": event, **detail, "user_action_required": True,
                    "message": message})
            # The owned helper's stdout is a control pipe that is not read
            # after readiness; one line per process cannot fill it.
            if not drop_warning_printed:
                drop_warning_printed = True
                print("TWA unit-drag warning: " + message, flush=True)

        def not_saved(
            reason: str,
            *,
            item_id: int | None,
            screen_slot: int | None,
            native_reason: str | None,
            input_kind: str,
            message: str | None = None,
            **detail,
        ) -> None:
            warn(
                message or (
                    "A deployment-bar unit change was not saved because its "
                    "saved slot could not be confirmed (" + reason + "). "
                    "Restart Arena before the next battle so the hangar "
                    "shows the saved loadout, then make the change again."
                ),
                event="unit_drag_not_saved", reason=reason,
                native_reason=native_reason, input=input_kind,
                item_id=None if item_id is None else str(item_id),
                screen_slot=screen_slot,
                reorder_latched=reorder_latched.is_set(),
                **detail,
            )

        def persist(
            item_id: int,
            slot: int,
            target_instance_id: int | None,
            captured_context: dict,
            *,
            slot_source: str,
            screen_slot: int | None,
        ) -> str:
            """POST one save; return "persisted", "unchanged" or "rejected"."""
            target_text = (None if target_instance_id is None
                           else str(target_instance_id))
            outcome = "rejected"
            try:
                context = _bind_context_unit(
                    captured_context, item_id, unit_catalogue,
                )
                response = post_selection(
                    item_id, slot, context["commander_item_id"],
                    context["saved"],
                    target_instance_id=target_instance_id,
                    control_capability=control_capability,
                )
                (saved, changed, operation_id, refresh_pending,
                 refresh_operation_id) = _validated_selection_response(
                    response, item_id=item_id, slot=slot, context=context,
                )
                record({
                    "event": ("unit_drag_persisted" if changed
                              else "unit_drag_unchanged"), "slot": slot,
                    "slot_source": slot_source, "screen_slot": screen_slot,
                    "target_instance_id": target_text,
                    "item_id": str(item_id), "unit": context["unit_key"],
                    "commander": context["commander"], "saved": saved,
                    "operation_id": operation_id,
                    "refresh_pending": refresh_pending,
                    "refresh_operation_id": refresh_operation_id,
                    "before_units": context["units"],
                    "after_units": response["after_units"],
                })
                outcome = "persisted" if changed else "unchanged"
                if not changed:
                    return outcome
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
                    return outcome
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
                    "slot_source": slot_source, "screen_slot": screen_slot,
                    "target_instance_id": target_text,
                    "item_id": str(item_id), "error": type(error).__name__,
                    "reason": str(error),
                    "server_error": _http_error_code(error),
                })
            return outcome

        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline and not detached.is_set():
            # Use the actual input sample time even if context loading or
            # persistence blocks this loop before the next iteration.
            sampled_at_ms = time.time_ns() // 1_000_000
            down = bool(user32.GetAsyncKeyState(0x01) & 0x8000)
            # A target that arrived before this point reached the host while
            # the button was in the state just sampled.
            observed_arrival = next(arrival_order)
            if down:
                last_down_arrival = observed_arrival
                last_down_sample_ms = sampled_at_ms
            resume_press = False
            point = _cursor_client(hwnd)
            foreground = _arena_is_foreground(hwnd)
            if down and not was_down:
                gesture_press_sample_ms = sampled_at_ms
                gesture_lower_ms = last_button_up_sample_ms
                press_point = point if foreground else None
                drag_start = (
                    point if foreground and _source_point(point)
                    and gesture_lower_ms is not None else None
                )
                drag_candidates = set()
                gesture_sources = []
                gesture_sources_overflow = False
                source_invalid_at_press = invalid_source_count
                target_invalid_at_press = invalid_target_count
                gesture_source_seq = None
                gesture_foreground = drag_start is not None
                gesture_context = None
                # The last release's late-target window closes at this press.
                if (gesture_entry is not None
                        and gesture_entry["closed_at_ms"] is None):
                    gesture_entry["closed_at_ms"] = sampled_at_ms
                discard_drop_targets("press")
                unobserved_press = None
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
                last_released_at_ms = released_at_ms
                screen_slot = _target_slot(point)
                in_gesture = (gesture_lower_ms is not None
                              and released_at_ms >= gesture_lower_ms)
                valid_drag = (
                    gesture_foreground and foreground
                    and _is_drag(drag_start, point)
                    and in_gesture
                )
                native_drag = (
                    native_mode and gesture_foreground and foreground
                    and _is_native_drag(drag_start, point)
                    and in_gesture
                )
                if foreground and _bar_reorder_gesture(press_point, point):
                    assert press_point is not None and point is not None
                    if gesture_reorder_latch:
                        latch_reorder("gesture", press=list(press_point),
                                      end=list(point))
                    else:
                        # The observer reports a reorder the game made.
                        record({"event": "bar_reorder_gesture_seen",
                                "press": list(press_point),
                                "end": list(point)})
                record({
                    "event": "gesture_release",
                    "released_at_ms": released_at_ms,
                    "last_down_sample_ms": last_down_sample_ms,
                    "end": list(point) if point else None,
                    "valid_drag": valid_drag,
                    "native_drag": native_drag,
                    "screen_slot": screen_slot,
                    "reorder_latched": reorder_latched.is_set(),
                })
                tracked = native_drag or valid_drag
                grace_upper_ms = released_at_ms + round(
                    NATIVE_EVENT_GRACE_SECONDS * 1000,
                )
                # The mouse-up happened after the last sample that saw the
                # button down.  When the press blocked the loop (its context
                # GET), that is the press sample itself, and the whole drag
                # may lie between it and this release sample; the arrival
                # and seq checks keep an earlier drop's target out.
                target_lower_ms = (min(released_at_ms,
                                       last_down_sample_ms
                                       if last_down_sample_ms is not None
                                       else released_at_ms)
                                   - NATIVE_TARGET_CLOCK_SLACK_MS)
                # The drag source seen while the button was held is known
                # before the wait, so an earlier drop's target cannot end it.
                collect_drag_sources(grace_upper_ms, keep_later=True,
                                     released_at_ms=released_at_ms)

                def this_release(drop_target: dict) -> bool:
                    return tracked and _release_target(
                        drop_target, lower_ms=target_lower_ms,
                        last_down_arrival=last_down_arrival,
                        source_seq=gesture_source_seq,
                    )

                def ends_wait(drop_target: dict) -> bool:
                    # Without a drag source nothing can be saved: keep
                    # waiting for one (and for the target after it).
                    # Without a source held before the release nothing
                    # orders an earlier drop's target before this one's:
                    # collect every target until the bound, so a later one
                    # can still show the first to be ambiguous.
                    collect_drag_sources(grace_upper_ms, keep_later=True,
                                         released_at_ms=released_at_ms)
                    return (bool(drag_candidates)
                            and gesture_source_seq is not None
                            and _roster_drop_target(drop_target)
                            and this_release(drop_target))

                def wait_bound() -> float:
                    # Re-read every poll: a reorder latched meanwhile
                    # removes the screen fallback and extends the wait.
                    return _native_target_wait(
                        native_drag=native_drag, valid_drag=valid_drag,
                        reorder_latched=reorder_latched.is_set(),
                        screen_fallback=not args.public_pvp_only,
                    )

                # Arena reports the replaced unit while it processes this
                # mouse-up.  Every native drag, bar or not, waits for it; the
                # wait ends at this gesture's target or a new press.  A screen
                # drag without the hook keeps the whole 0.2.26 source grace.
                wait_last_up_ms = released_at_ms
                wait_started = time.perf_counter()
                arrived, wait_end = _wait_native_targets(
                    drop_targets, timeout=wait_bound, accept=ends_wait,
                    stop=button_down_again if native_drag else None,
                )
                target_seen_perf = time.perf_counter()
                wait_ms = round((time.perf_counter() - wait_started) * 1000)
                resume_press = wait_end == "button_down"
                collect_drag_sources(grace_upper_ms, keep_later=True,
                                     released_at_ms=released_at_ms)
                drag_item, identity_reason = _resolve_drag_identity(
                    drag_candidates, [], unit_item_ids,
                )
                targets = []
                for drop_target in arrived:
                    if this_release(drop_target):
                        targets.append(drop_target)
                    else:
                        # Held, stale or untracked: judged against the
                        # previous gesture (its window closed at this press).
                        route_late_target(drop_target, (
                            "held" if last_down_arrival is not None
                            and drop_target["arrival"] <= last_down_arrival
                            else "stale" if tracked else "release"
                        ))
                native_wait_seconds = wait_bound()
                native_wait_deadline = wait_started + native_wait_seconds
                native_wait_upper_ms = released_at_ms + round(
                    native_wait_seconds * 1000)
                # A real roster target may arrive after release+50 ms. For
                # ambiguous provenance only, drain competing evidence for at
                # most 50 ms after that target arrived, capped by the same
                # native-target wait deadline. This keeps the equip POST ahead
                # of Arena's later native unequip cleanup on a valid drag.
                if (native_drag and identity_reason == "ambiguous_unit_drag_source"
                        and wait_end == "target" and len(arrived) == 1
                        and len(targets) == 1
                        and any(event[4] == "drag_begin"
                                for event in gesture_sources)):
                    recovery_upper_ms = min(
                        native_wait_upper_ms,
                        targets[0]["emitted_at_ms"]
                        + round(NATIVE_EVENT_GRACE_SECONDS * 1000),
                    )
                    remaining = max(0.0, min(
                        native_wait_deadline - time.perf_counter(),
                        target_seen_perf + NATIVE_EVENT_GRACE_SECONDS
                        - time.perf_counter(),
                    ))
                    if remaining:
                        additional, extra_end = _wait_native_targets(
                            drop_targets, timeout=remaining,
                            accept=lambda _target: False,
                            stop=button_down_again,
                        )
                        if extra_end == "button_down":
                            resume_press = True
                        for drop_target in additional:
                            arrived.append(drop_target)
                            if this_release(drop_target):
                                targets.append(drop_target)
                            else:
                                route_late_target(drop_target, "recovery_grace")
                    collect_drag_sources(recovery_upper_ms, keep_later=True,
                                         released_at_ms=released_at_ms)
                native = None
                slot_instance_ids = None
                if native_drag and gesture_context is not None:
                    slot_instance_ids = gesture_context["slot_instance_ids"]
                    # Only a unique held drag-begin, preceding dispatcher
                    # conflicts, and one exact later native roster target
                    # can recover an otherwise ambiguous source set.
                    if (identity_reason == "ambiguous_unit_drag_source"
                            and not resume_press
                            and invalid_target_count == target_invalid_at_press):
                        proven = _recover_proven_drag_source(
                            gesture_sources,
                            source_overflow=gesture_sources_overflow,
                            invalid_source_seen=(invalid_source_count
                                                 != source_invalid_at_press),
                            arrived=arrived, targets=targets,
                            wait_end=wait_end,
                            press_sampled_at_ms=gesture_press_sample_ms,
                            released_at_ms=released_at_ms,
                            target_wait_upper_ms=native_wait_upper_ms,
                            lower_ms=target_lower_ms,
                            upper_ms=(time.time_ns() // 1_000_000
                                      + NATIVE_TARGET_CLOCK_SLACK_MS),
                            slot_instance_ids=slot_instance_ids,
                            catalogue_ids=unit_catalogue,
                        )
                        if proven is not None:
                            drag_item, native, proof_seq = proven
                            identity_reason = "resolved"
                            record({"event": "unit_drag_provenance_recovered",
                                    "item_id": str(drag_item),
                                    "proof_seq": proof_seq,
                                    "target_seq": targets[0]["seq"],
                                    "native_slot": native[0]})
                    if native is None:
                        native = _resolve_native_slot(
                            targets, lower_ms=target_lower_ms,
                            upper_ms=(time.time_ns() // 1_000_000
                                      + NATIVE_TARGET_CLOCK_SLACK_MS),
                            slot_instance_ids=slot_instance_ids,
                            source_item=drag_item, catalogue_ids=unit_catalogue,
                            ordered=gesture_source_seq is not None,
                        )
                for drop_target in targets:
                    record({
                        "event": "native_drop_target",
                        **_drop_target_record(
                            drop_target, released_at_ms=released_at_ms,
                            slot_instance_ids=slot_instance_ids,
                            source_item=drag_item,
                        ),
                        "released_at_ms": released_at_ms,
                        "screen_slot": screen_slot,
                        "native_drag": native_drag,
                    })
                native_reason = None if native is None else native[2]
                native_evidence = (
                    native is not None
                    and native_reason != "native_target_missing"
                )
                if (native is not None and native_reason == "resolved"
                        and screen_slot is not None
                        and native[0] != screen_slot):
                    latch_reorder("native_slot_mismatch", slot=native[0],
                                  screen_slot=screen_slot)
                record({
                    "event": "gesture_end",
                    "released_at_ms": released_at_ms,
                    "start": list(drag_start) if drag_start else None,
                    "end": list(point) if point else None,
                    "has_candidate": drag_item is not None,
                    "valid_drag": valid_drag,
                    "native_drag": native_drag,
                    "screen_slot": screen_slot,
                    "native_reason": native_reason,
                    "wait_end": wait_end,
                    "wait_ms": wait_ms,
                    "source_seq": gesture_source_seq,
                    "arena_foreground": foreground,
                    "identity_matches": identity_reason == "resolved",
                    "identity_reason": identity_reason,
                })
                bar_drop = valid_drag or (native_drag and (
                    screen_slot is not None or native_evidence))
                outcome = "not_attempted"
                saved_slot = saved_source = None
                if (drag_item is not None and bar_drop
                        and gesture_context is not None):
                    slot, target_instance_id, slot_source, reason = (
                        _drop_slot_decision(
                            native, screen_slot=screen_slot,
                            screen_eligible=valid_drag,
                            reorder_latched=reorder_latched.is_set(),
                            screen_fallback=(SCREEN_SLOT_FALLBACK
                                             and not args.public_pvp_only),
                        )
                    )
                    if slot is None:
                        outcome = "refused"
                        not_saved(reason, item_id=drag_item,
                                  screen_slot=screen_slot,
                                  native_reason=native_reason,
                                  input_kind="drag")
                    else:
                        outcome = persist(
                            drag_item, slot, target_instance_id,
                            gesture_context, slot_source=slot_source,
                            screen_slot=screen_slot,
                        )
                        saved_slot, saved_source = slot, slot_source
                    pending_click = None
                elif (drag_item is not None and gesture_context is not None
                      and not args.public_pvp_only
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
                        # A click has no native target object. Public mode
                        # therefore cannot infer an equip from inspecting a
                        # roster card followed by selecting a deployed unit.
                        # Legacy screen assignment uses the drag policy.
                        slot, _target, slot_source, reason = (
                            _drop_slot_decision(
                                None, screen_slot=screen_slot,
                                screen_eligible=True,
                                reorder_latched=reorder_latched.is_set(),
                                screen_fallback=(SCREEN_SLOT_FALLBACK
                                                 and not args.public_pvp_only),
                            )
                        )
                        if slot is None:
                            not_saved(reason, item_id=pending_item,
                                      screen_slot=screen_slot,
                                      native_reason=None, input_kind="click")
                        else:
                            persist(pending_item, slot, None,
                                    pending_context, slot_source=slot_source,
                                    screen_slot=screen_slot)
                    else:
                        record({"event": "unit_click_selection_expired"})
                elif bar_drop:
                    record({"event": identity_reason})
                    if native_evidence:
                        # Arena did replace a unit, but the held card was
                        # not identified; nothing can be saved.
                        outcome = "refused"
                        not_saved(identity_reason, item_id=None,
                                  screen_slot=screen_slot,
                                  native_reason=native_reason,
                                  input_kind="drag")
                # Every native-drag release gets its own entry, bar or not,
                # so a late target is never judged against an older drop.
                saved = outcome in _SAVED_OUTCOMES
                gesture_entry = {
                    "released_at_ms": released_at_ms,
                    "lower_ms": target_lower_ms,
                    "closed_at_ms": None,
                    # Set when a press the loop never sampled closes it.
                    "next_source_seq": None,
                    "source_seq": gesture_source_seq,
                    "screen_slot": screen_slot,
                    "slot_instance_ids": (
                        None if gesture_context is None
                        else gesture_context["slot_instance_ids"]),
                    "item_id": drag_item,
                    "native_reason": native_reason,
                    "outcome": outcome,
                    "slot": saved_slot if saved else None,
                    "slot_source": saved_source if saved else None,
                    "late_reported": False,
                    "contradicted": False,
                } if tracked else None
                drag_start = None
                drag_candidates = set()
                gesture_foreground = False
                gesture_context = None
                gesture_lower_ms = None
                press_point = None
                # A stale held-source seq would make this entry's own late
                # target look newer than the next gesture and go unjudged.
                gesture_source_seq = None
            was_down = down
            if not down and resume_press:
                # The next press began during the wait: keep its drag sources
                # and targets for that press, bounded by the last up poll.
                last_button_up_sample_ms = wait_last_up_ms
            elif not down:
                last_button_up_sample_ms = sampled_at_ms
                # Sources first: a press made during a blocking POST closes
                # the last release's window before its targets are judged.
                drop_idle_sources()
                discard_drop_targets("idle")
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
