"""EOS-to-Worker exchange without persisting the short-lived EOS token."""
from __future__ import annotations

import re
import time
from typing import Any

from .api_client import ApiClient, ApiError

_SESSION_TOKEN = re.compile(r"^[a-f0-9]{64}$")


class WorkerLoginResponseError(ApiError):
    def __init__(self, code: str) -> None:
        super().__init__(502, code)


def exchange_connect_token(
    api: ApiClient,
    connect_token: str,
    expected_puid: str,
    *,
    display_name: str | None = None,
    invite_code: str | None = None,
    eos_expires_at: int | None = None,
) -> dict[str, Any]:
    """Exchange in memory and return a validated persistable Worker session."""
    result = api.auth_eos(connect_token, display_name=display_name, invite_code=invite_code)
    if not isinstance(result, dict):
        raise WorkerLoginResponseError("invalid_login_response")
    token = result.get("token")
    expires_at = result.get("expiresAt")
    user = result.get("user")
    puid = user.get("id") if isinstance(user, dict) else None
    if not isinstance(token, str) or not _SESSION_TOKEN.fullmatch(token):
        raise WorkerLoginResponseError("invalid_session_token_response")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at <= int(time.time()):
        raise WorkerLoginResponseError("invalid_session_expiry_response")
    if eos_expires_at is not None and expires_at > min(eos_expires_at, int(time.time()) + 3605):
        raise WorkerLoginResponseError("invalid_session_expiry_response")
    if not isinstance(puid, str) or not puid or puid != expected_puid:
        raise WorkerLoginResponseError("worker_identity_mismatch")
    api.session_token = token
    return {"token": token, "puid": puid, "expiresAt": expires_at}
