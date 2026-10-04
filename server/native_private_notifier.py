"""Idempotent private-lobby human notifications over NativeXmppProbe."""
from __future__ import annotations

import copy
import hashlib
import json
import threading

from native_private_cpu_notifications import CpuNotificationDeliveryUncertain


class PrivateNotifierError(ValueError):
    pass


class NativePrivateXmppNotifier:
    """Callable four-argument notifier consumed by CloudPrivateLobbyAdapter.

    A serial whose socket write became uncertain is terminally uncertain and
    is never transmitted again. A confirmed delivery is memoized and replayed
    as its original recipient count without duplicating the stanza. Zero
    recipients is a definite no-write and remains retryable with the same
    serial after the notification resource binds.
    """

    def __init__(self, probe) -> None:
        self.probe = probe
        self._lock = threading.RLock()
        self._records: dict[int, tuple[str, str, int | None]] = {}
        self._highest_serial = 0

    def _remember(self, serial: int, value: tuple[str, str, int | None]) -> None:
        self._records[serial] = value
        self._highest_serial = serial
        while len(self._records) > 256:
            del self._records[min(self._records)]

    @staticmethod
    def _digest(event: object, game_id: object, payload: object) -> str:
        try:
            raw = json.dumps([event, game_id, payload], sort_keys=True,
                             separators=(",", ":"), ensure_ascii=False,
                             allow_nan=False).encode("utf-8")
        except (TypeError, ValueError):
            raise PrivateNotifierError("invalid_private_notification") from None
        return hashlib.sha256(raw).hexdigest()

    def __call__(self, serial: int, event: str, game_id: str,
                 payload: object) -> int:
        if type(serial) is not int or serial <= 0:
            raise PrivateNotifierError("invalid_private_notification_serial")
        digest = self._digest(event, game_id, payload)
        with self._lock:
            prior = self._records.get(serial)
            if prior is not None:
                prior_digest, state, recipients = prior
                if prior_digest != digest:
                    raise PrivateNotifierError("private_notification_serial_conflict")
                if state == "uncertain":
                    raise CpuNotificationDeliveryUncertain()
                return recipients or 0
            if serial <= self._highest_serial:
                raise PrivateNotifierError("stale_private_notification_serial")
            try:
                recipients = self._send(event, game_id, copy.deepcopy(payload))
            except CpuNotificationDeliveryUncertain:
                self._remember(serial, (digest, "uncertain", None))
                raise
            if type(recipients) is not int or recipients < 0:
                raise PrivateNotifierError("invalid_private_notification_result")
            if recipients > 0:
                self._remember(serial, (digest, "delivered", recipients))
            return recipients

    def _send(self, event: str, game_id: str, payload: object) -> int:
        if event == 'chat_room' and payload is None:
            return self.probe.send_private_chat_room(game_id)
        if event == "human_joined":
            return self.probe.send_private_human_joined(game_id, payload)
        if event == "human_removed":
            return self.probe.send_private_human_removed(game_id, payload)
        if event == "human_loadout" and isinstance(payload, dict):
            return self.probe.send_private_human_loadout(
                game_id, payload.get("user_id"),
                payload.get("profile_matchmaking_details"))
        if event == "human_ready" and isinstance(payload, dict):
            return self.probe.send_private_human_ready(
                game_id, payload.get("user_id"), payload.get("ready"))
        if event == "settings_changed":
            return self.probe.send_private_settings_changed(game_id, payload)
        raise PrivateNotifierError("unsupported_private_notification")
