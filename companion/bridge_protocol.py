"""Private parent/bridge-child control protocol.

The bearer token never crosses this channel.  Both processes independently
read the configured private session file and use its token digest to
authenticate a bounded, nonce-scoped readiness record.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any

PROTOCOL = "twa-companion-bridge-v1"
MAX_CONTROL_LINE = 64 * 1024
UNIT_CONTROL_HEADER = "X-TWA-Unit-Control"
_HEX_256_RE = re.compile(r"[0-9a-f]{64}")
_NATIVE_USER_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,36}")
_CLIENT_VERSION_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


@dataclass(frozen=True)
class UnitControlBinding:
    """One launch's private unit-control capability and identity fence."""

    capability: str = field(repr=False)
    capability_sha256: str
    native_user_id: str
    session_sha256: str

    def __post_init__(self) -> None:
        if (_HEX_256_RE.fullmatch(self.capability) is None
                or _HEX_256_RE.fullmatch(self.capability_sha256) is None
                or _HEX_256_RE.fullmatch(self.session_sha256) is None
                or _NATIVE_USER_ID_RE.fullmatch(self.native_user_id) is None
                or not hmac.compare_digest(
                    hashlib.sha256(self.capability.encode("ascii")).hexdigest(),
                    self.capability_sha256,
                )):
            raise ValueError("invalid unit-control binding")

    @classmethod
    def generate(cls, native_user_id: str,
                 session_sha256: str) -> "UnitControlBinding":
        return cls.from_capability(
            secrets.token_hex(32), native_user_id, session_sha256,
        )

    @classmethod
    def from_capability(cls, capability: str, native_user_id: str,
                        session_sha256: str) -> "UnitControlBinding":
        if not isinstance(capability, str):
            raise ValueError("invalid unit-control binding")
        return cls(
            capability=capability,
            capability_sha256=hashlib.sha256(
                capability.encode("ascii", errors="strict")
            ).hexdigest(),
            native_user_id=native_user_id,
            session_sha256=session_sha256,
        )


def valid_client_version(value: object) -> bool:
    if not isinstance(value, str) or len(value) > 128:
        return False
    match = _CLIENT_VERSION_RE.fullmatch(value)
    if match is None:
        return False
    prerelease = match.group(4)
    return prerelease is None or all(
        not (identifier.isdigit() and len(identifier) > 1
             and identifier.startswith("0"))
        for identifier in prerelease.split(".")
    )


def canonical_ready_payload(payload: dict[str, Any]) -> bytes:
    fields = {
        "protocol": payload.get("protocol"),
        "event": payload.get("event"),
        "nonce": payload.get("nonce"),
        "pid": payload.get("pid"),
        "mode": payload.get("mode"),
        "ruleset": payload.get("ruleset"),
        "private_mode": payload.get("private_mode"),
        "private_ai_opponents": payload.get("private_ai_opponents"),
        "puid": payload.get("puid"),
        "native_user_id": payload.get("native_user_id"),
        "display_name": payload.get("display_name"),
        "api_base_url": payload.get("api_base_url"),
        "client_version": payload.get("client_version"),
        "unit_control_capability_sha256": payload.get(
            "unit_control_capability_sha256"),
        "surfaces": payload.get("surfaces"),
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def ready_proof(token: str, payload: dict[str, Any]) -> str:
    key = hashlib.sha256(token.encode("utf-8")).digest()
    return hmac.new(key, canonical_ready_payload(payload), hashlib.sha256).hexdigest()


def constant_time_proof_matches(token: str, payload: dict[str, Any], proof: object) -> bool:
    return isinstance(proof, str) and hmac.compare_digest(ready_proof(token, payload), proof)
