"""Validate and persist only the selected owned offline commander."""
from __future__ import annotations

import copy
import json
import os
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path


def _wire_properties(properties: list) -> list:
    """Encode native selected-model properties as signed int64 values.

    BD81E9 (active_commander) and BD8292 (active_title, which selects the
    portrait model) require the signed-int64 JSON flag, then use the raw bits.
    Item records, requests, internal state and persistence keep uint64 IDs.
    """
    result = copy.deepcopy(properties)
    for row in result:
        if row[0] in ("active_commander", "active_title"):
            active = row[3]
            if type(active) is not int or not 0 <= active < 2**64:
                raise ValueError(f"Internal {row[0]} must be uint64")
            row[3] = active if active < 2**63 else active - 2**64
    return result


class SelectionState:
    def __init__(
        self,
        profile: dict,
        mappings: dict,
        path: Path | None = None,
        trace: Callable[[dict], None] | None = None,
    ):
        self._lock = threading.RLock()
        self._profile = copy.deepcopy(profile)
        self.path = path
        self._trace = trace
        commander_items = {row["item_id"] for row in mappings["item_mappings"]
                           if row["type"] == "arena_commanders"}
        self._owned = {row[2] for row in self._profile["profile"]["profile_records"]
                       if row[0] == 0 and row[1] in commander_items and row[3] > 0}
        before = self._selection_version()
        load_status = "initial_default"
        if path is not None and path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                active = data.get("active_commander") if isinstance(data, dict) else None
                if type(active) is int and active in self._owned:
                    self._update(active)
                    load_status = "initial_restored"
                else:
                    load_status = "initial_invalid_ignored"
            except (OSError, UnicodeError, json.JSONDecodeError):
                load_status = "initial_read_error"
        self._emit_trace(load_status, before)

    def _selection_version(self) -> tuple[int | None, int]:
        inner = self._profile["profile"]
        active = next((row[3] for row in inner["properties"] if row[0] == "active_commander"), None)
        return active, inner["saved"]

    def _emit_trace(self, status: str, before: tuple, body: object = None) -> None:
        if self._trace is None:
            return
        # Log only whitelisted numeric IDs/times. Never echo auth headers,
        # raw bodies, arbitrary strings, file paths, or exception contents.
        body = body if isinstance(body, dict) else {}
        request = body.get("request")
        request = request if isinstance(request, dict) else {}
        headers = body.get("headers")
        headers = headers if isinstance(headers, dict) else {}

        def number(value: object) -> int | None:
            return value if type(value) is int and 0 <= value < 2**64 else None

        after = self._selection_version()
        self._trace({
            "status": status,
            "requested_active": number(request.get("active_commander")),
            "client_profile_timestamp": number(request.get("profile_timestamp")),
            "client_read_timestamp": number(request.get("timestamp")),
            "client_request_timestamp": number(headers.get("timestamp")),
            "active_before": number(before[0]),
            "active_after": number(after[0]),
            "profile_saved_before": number(before[1]),
            "profile_saved_after": number(after[1]),
        })

    def _update(self, active: int) -> bool:
        inner = self._profile["profile"]
        for row in inner["properties"]:
            if row[0] == "active_commander":
                if row[3] == active:
                    return False
                row[3] = active
                inner["saved"] = max(time.time_ns() // 1_000_000, inner["saved"] + 1)
                return True
        raise ValueError("Native profile has no active_commander property")

    def _persist(self, active: int) -> None:
        if self.path is None:
            return
        # Never persist caller-supplied records, balances, or timestamps.
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.path.parent,
                                             prefix=self.path.name + ".", suffix=".tmp", delete=False) as handle:
                temporary = Path(handle.name)
                json.dump({"active_commander": active}, handle)
                handle.write("\n")
            os.replace(temporary, self.path)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()

    def respond(self, raw: bytes = b"", accept_selection: bool = False) -> tuple[dict, str]:
        """Return a selection acknowledgement or a complete profile snapshot.

        POST /profile/ selection has request.active_commander (instance ID).
        Profile reads also use POST, but contain request.timestamp instead.
        A successful selection uses the native `ok` delta schema so existing
        commander/unit models are not destroyed by full profile resync.
        """
        with self._lock:
            status = "unchanged"
            before = self._selection_version()
            body = None
            if raw and (accept_selection or self._trace is not None):
                try:
                    body = json.loads(raw)
                except (UnicodeError, json.JSONDecodeError):
                    body = None
            if accept_selection:
                request = body.get("request") if isinstance(body, dict) else None
                fields = set(request) if isinstance(request, dict) else set()
                if fields in ({"timestamp"}, {"profile_timestamp"}):
                    field = next(iter(fields))
                    timestamp = request[field]
                    current = self._profile["profile"]["saved"]
                    if type(timestamp) is int and 0 <= timestamp < 2**64:
                        if timestamp == current:
                            self._emit_trace("unchanged", before, body)
                            return {
                                "result": "ok",
                                "saved": current,
                                "events": [],
                                "properties": [],
                            }, "unchanged"
                        status = "stale" if timestamp < current else "rejected"
                    else:
                        status = "rejected"
                elif isinstance(request, dict) and "active_commander" in request:
                    active = request["active_commander"]
                    if type(active) is int and active in self._owned:
                        timestamp = request.get("profile_timestamp")
                        current_active, current_saved = self._selection_version()
                        if (type(timestamp) is not int
                                or not 0 <= timestamp < 2**64
                                or timestamp > current_saved
                                or timestamp != current_saved
                                and active != current_active):
                            status = "rejected"
                        else:
                            changed = self._update(active)
                            status = "accepted"
                            if changed:
                                try:
                                    self._persist(active)
                                except OSError:
                                    status = "accepted_not_persisted"
                    else:
                        status = "rejected"
            self._emit_trace(status, before, body)
            if status in ("accepted", "accepted_not_persisted"):
                inner = self._profile["profile"]
                # BFE350 reads these fields directly in response, not inside
                # profile. Empty events are valid; they grant/delete nothing.
                return {
                    "result": "ok",
                    "saved": inner["saved"],
                    "events": [],
                    "properties": _wire_properties(inner["properties"]),
                }, status
            response = copy.deepcopy(self._profile)
            response["profile"]["properties"] = _wire_properties(response["profile"]["properties"])
            return response, status
