"""Bounded local matchmaking announce supervision shared by probe entry points."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from native_matchmaking import QUEUE_SECONDS
ANNOUNCE_POLL_SECONDS = 0.5
# Public collection is capped at 300s; roster admission has a bounded grace.
ANNOUNCE_DEADLINE_SECONDS = float(QUEUE_SECONDS - 30)


@dataclass
class AnnounceResult:
    announced: bool = False
    attempts: int = 0
    clients: int = 0
    last_error: str | None = None


class AutoAnnouncer:
    """Announce one accepted queue only after its response and XMPP are ready."""

    def __init__(self, matchmaking, xmpp_hub, *, trace=None,
                 profile_source=None, queue_response_ready=None,
                 queue_response_consumed=None,
                 allowed_modes=None,
                 fence_generation: bool = False,
                 poll_seconds: float = ANNOUNCE_POLL_SECONDS,
                 deadline_seconds: float = ANNOUNCE_DEADLINE_SECONDS,
                 clock=time.monotonic, sleep=time.sleep) -> None:
        self._matchmaking = matchmaking
        self._xmpp = xmpp_hub
        self._trace = trace
        self._profile_source = profile_source
        self._queue_response_ready = queue_response_ready or (lambda _generation: True)
        self._queue_response_consumed = (queue_response_consumed
                                         or (lambda _generation: None))
        self._allowed_modes = (None if allowed_modes is None
                               else frozenset(allowed_modes))
        self._fence_generation = fence_generation
        self._poll = poll_seconds
        self._deadline = deadline_seconds
        self._clock = clock
        self._sleep = sleep
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.result = AnnounceResult()

    def notification_ready(self) -> bool:
        count = getattr(self._xmpp, "notification_client_count", None)
        return type(count) is int and count > 0

    def poll_once(self) -> str:
        state = self._matchmaking.lab_state
        queue_state = state.get("queue_state")
        if queue_state == "matching":
            return "matching"
        if queue_state != "queued":
            return "idle" if queue_state in (None, "idle") else "settled"
        if (self._allowed_modes is not None
                and state.get("game_mode") not in self._allowed_modes):
            return "matching"
        generation = state.get("party_id") if self._fence_generation else None
        if self._fence_generation and not isinstance(generation, str):
            return "waiting_for_queue_response"
        if not self._queue_response_ready(generation):
            return "waiting_for_queue_response"
        if not self.notification_ready():
            return "waiting_for_notification_stream"
        self.result.attempts += 1
        try:
            if self._profile_source is None:
                raise RuntimeError("profile_source_unavailable")
            profile = self._profile_source()
            if self._fence_generation:
                clients = self._matchmaking.announce(
                    profile, expected_party_id=generation)
            else:
                clients = self._matchmaking.announce(profile)
        except Exception as error:
            self.result.last_error = getattr(error, "code", type(error).__name__)
            self._emit("companion_announce_failed", reason=self.result.last_error)
            return "failed"
        self.result.announced = True
        self.result.clients = clients
        if self._fence_generation:
            self._queue_response_consumed(generation)
        self._emit("companion_announce_sent", clients=clients,
                   attempts=self.result.attempts)
        return "announced"

    def run_until_announced(self) -> AnnounceResult:
        started = self._clock()
        while not self._stop.is_set():
            outcome = self.poll_once()
            if outcome in {"announced", "settled"}:
                return self.result
            if self._clock() - started >= self._deadline:
                self._emit("companion_announce_deadline", attempts=self.result.attempts)
                return self.result
            self._sleep(self._poll)
        return self.result

    def _loop(self) -> None:
        while not self._stop.is_set():
            if self._matchmaking.lab_state.get("queue_state") == "queued":
                self.result = AnnounceResult()
                self.run_until_announced()
            self._stop.wait(self._poll)

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("announcer_already_started")
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="native-pve-announcer")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    def _emit(self, event: str, **fields) -> None:
        if self._trace is not None:
            try:
                self._trace({"event": event, **fields})
            except Exception:
                pass
