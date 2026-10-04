"""EOS-to-Worker exchange without persisting the short-lived EOS token."""
from __future__ import annotations

import re
import time
from typing import Any

from .api_client import ApiClient, ApiError, ResponseClock

_SESSION_TOKEN = re.compile(r"^[a-f0-9]{64}$")


class WorkerLoginResponseError(ApiError):
    def __init__(self, code: str) -> None:
        super().__init__(502, code)


def session_expiry(api, expiry, proof_expiry, *, now, previous=None):
    """Validate origin-time bounds, then store a conservative local deadline.

    Date is received on the existing TLS-validated, nonredirecting API request.
    No server authorization is extended, and the Epic proof remains a hard cap.
    The original server expiry is retained only to validate later renewals.
    """
    path = '/v1/auth/eos/refresh' if previous is not None else '/v1/auth/eos'
    clock = getattr(api, 'response_clock', None)
    if not isinstance(clock, ResponseClock) or clock.path != path:
        clock = None
    reference = clock.server_time if clock is not None else now
    old_server = previous.get('serverExpiresAt', previous['expiresAt']) if previous else 0
    if type(old_server) is not int or old_server < 0:
        raise WorkerLoginResponseError('invalid_session_expiry_response')
    if proof_expiry is not None and (type(proof_expiry) is not int or proof_expiry <= reference):
        raise WorkerLoginResponseError('invalid_session_expiry_response')
    ceiling = min(proof_expiry, reference + 3605) if proof_expiry is not None else reference + 3605
    if (type(expiry) is not int or expiry <= reference
            or expiry > max(old_server, ceiling) or expiry < old_server):
        raise WorkerLoginResponseError('invalid_session_expiry_response')
    # Starting from the request's local start subtracts all network/processing
    # delay; translating from response receipt would extend the real lifetime.
    local_expiry = int(clock.local_started) + expiry - reference if clock is not None else expiry
    if previous and expiry == old_server:
        local_expiry = min(local_expiry, previous['expiresAt'])
    if local_expiry <= now:
        raise WorkerLoginResponseError('invalid_session_expiry_response')
    return {'expiresAt': local_expiry, 'serverExpiresAt': expiry}


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
    lifetime = session_expiry(api, expires_at, eos_expires_at, now=int(time.time()))
    if not isinstance(puid, str) or not puid or puid != expected_puid:
        raise WorkerLoginResponseError("worker_identity_mismatch")
    api.session_token = token
    return {"token": token, "puid": puid, **lifetime}
