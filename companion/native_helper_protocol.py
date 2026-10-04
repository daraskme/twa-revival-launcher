"""Private authenticated control records for an owned native UI helper."""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

PROTOCOL = "twa-native-helper-v1"
MAX_CONTROL_LINE = 16 * 1024


def canonical_ready_payload(payload: dict[str, Any]) -> bytes:
    fields = {
        "protocol": payload.get("protocol"),
        "event": payload.get("event"),
        "nonce": payload.get("nonce"),
        "helper_pid": payload.get("helper_pid"),
        "arena_pid": payload.get("arena_pid"),
        "specialization_mode": payload.get("specialization_mode"),
        "arcani_slot_fix_mode": payload.get("arcani_slot_fix_mode"),
        "arena_path": payload.get("arena_path"),
        "game_path": payload.get("game_path"),
        "game_sha256": payload.get("game_sha256"),
        "unit_control_capability_sha256": payload.get(
            "unit_control_capability_sha256"),
        "native_user_id": payload.get("native_user_id"),
        "session_sha256": payload.get("session_sha256"),
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def ready_proof(nonce: str, payload: dict[str, Any]) -> str:
    try:
        key = bytes.fromhex(nonce)
    except (TypeError, ValueError):
        return ""
    if len(key) != 32:
        return ""
    return hmac.new(key, canonical_ready_payload(payload),
                    hashlib.sha256).hexdigest()


def proof_matches(nonce: str, payload: dict[str, Any], proof: object) -> bool:
    expected = ready_proof(nonce, payload)
    return bool(expected and isinstance(proof, str)
                and hmac.compare_digest(expected, proof))
