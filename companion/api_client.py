"""urllib-based client for the Cloudflare Worker private-server/ API.

Stdlib only (``urllib.request``). Field names and paths were checked against
the real, now-implemented private-server/ source while writing this module
(private-server/src/index.ts, http.ts, control.ts, profiles.ts, battles.ts,
updates.ts -- that thread built this concurrently with this one; see
docs/companion_updater_20260902.md's "companion/eos との統合"-adjacent notes
for what was cross-checked and what still needs a live wrangler-dev
integration pass). Every request carries ``X-TWA-Client-Version`` (the game)
and ``X-TWA-Launcher-Version`` (the installed companion) and (when
there is a body, or always for consistency -- see _headers())
``Content-Type: application/json``, and never sets ``Origin`` (index.ts
rejects any request that has one: this client is a native companion, not a
browser). Bearer auth uses whichever token is passed -- the saved Worker
session token, except for auth_eos() which takes the caller-supplied EOS
Connect ID token instead.

Error mapping (private-server/src/http.ts's ``json({error: code, ...detail},
status)`` convention -- `detail` fields are merged into the top-level body,
which is why ConflictError below just keeps the whole parsed body):

  503 with body {"error": "maintenance", ...}                -> MaintenanceError
  426 with body {"error": "update_required", "minClientVersion",
                 "manifestUrl"} (see control.ts's enforceClientVersion)  -> UpdateRequiredError
  401                                                          -> AuthError
  409                                                          -> ConflictError(full body)
  anything else non-2xx                                       -> ApiError(status, code)

Retries with capped exponential backoff apply only to idempotent GET
requests, and only for network-level failures (timeouts, connection resets)
-- never for a well-formed non-2xx HTTP response (a 503 maintenance reply is
not a transient glitch to retry through; the caller should surface it).
"""
from __future__ import annotations

from dataclasses import dataclass
from email.utils import parsedate_to_datetime
import hashlib
import ipaddress
import json
import math
import os
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import quote, urlsplit

from .manifest import ManifestError, semver_tuple

MAX_JSON_BYTES = 4 * 1024 * 1024  # 4 MiB cap on parsed JSON responses
DEFAULT_TIMEOUT = 15.0
_RETRYABLE_NETWORK_ERRORS = (urllib.error.URLError, socket.timeout, ConnectionError, TimeoutError)
def _validated_launcher_version(value: object) -> str:
    """Use an unambiguous SemVer header; malformed installations report old."""
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        return "0.0.0"
    try:
        semver_tuple(value)
    except (ManifestError, TypeError, ValueError):
        return "0.0.0"
    return value


def _installed_launcher_version() -> str:
    try:
        value = (Path(__file__).parent / "VERSION").read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return "0.0.0"
    return _validated_launcher_version(value)


class ApiError(Exception):
    """Any non-2xx response not covered by a more specific subclass below."""

    def __init__(self, status: int, code: str, message: str | None = None,
                 payload: dict[str, Any] | None = None) -> None:
        super().__init__(f"{status} {code}")
        self.status = status
        self.code = code
        self.message = message if message is not None else code
        self.payload = dict(payload) if isinstance(payload, dict) else {}


class MaintenanceError(ApiError):
    def __init__(self, message: str, ends_at: int | None) -> None:
        super().__init__(503, "maintenance", message)
        self.ends_at = ends_at


class UpdateRequiredError(ApiError):
    def __init__(self, min_version: str, manifest_url: str | None) -> None:
        super().__init__(426, "update_required", f"client update required: >= {min_version}")
        self.min_version = min_version
        self.manifest_url = manifest_url


class LauncherUpdateRequiredError(ApiError):
    def __init__(self, min_launcher_version: str, manifest_url: str | None) -> None:
        super().__init__(426, "launcher_update_required",
                         f"launcher update required: >= {min_launcher_version}")
        self.min_launcher_version = min_launcher_version
        self.manifest_url = manifest_url


class AuthError(ApiError):
    pass


class ConflictError(ApiError):
    def __init__(self, payload: dict[str, Any]) -> None:
        super().__init__(409, str(payload.get("error", "conflict")), payload=payload)


class NetworkError(Exception):
    """A connection-level failure (timeout, refused, DNS, ...), not an HTTP response."""


_BODY_NETWORK_ERRORS = _RETRYABLE_NETWORK_ERRORS + (NetworkError,)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def normalize_api_base_url(value: str) -> str:
    if not isinstance(value, str) or not value or any(ord(ch) < 0x21 for ch in value) or "\\" in value:
        raise ValueError("API base URL must be a clean origin URL")
    parsed = urlsplit(value)
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise ValueError("API base URL must not contain credentials, query, or fragment")
    if parsed.path not in ("", "/") or not parsed.hostname:
        raise ValueError("API base URL must be an origin without a path")
    scheme = parsed.scheme.lower()
    host = parsed.hostname.rstrip(".").lower()
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("API base URL has an invalid port") from exc
    if scheme == "http":
        is_loopback = host == "localhost"
        if not is_loopback:
            try:
                is_loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                pass
        if not is_loopback:
            raise ValueError("API base URL must use HTTPS (HTTP is allowed only for an explicit loopback host)")
    elif scheme != "https":
        raise ValueError("API base URL must use HTTPS (HTTP is allowed only for an explicit loopback host)")
    rendered_host = f"[{host}]" if ":" in host else host
    default_port = (scheme == "https" and port in (None, 443)) or (scheme == "http" and port in (None, 80))
    return f"{scheme}://{rendered_host}" + ("" if default_port else f":{port}")


def _raise_for_status(status: int, body: Any) -> NoReturn:
    obj = body if isinstance(body, dict) else {}
    code = str(obj.get("error", "unknown"))
    if status == 503 and code == "maintenance":
        raise MaintenanceError(str(obj.get("message", "")), obj.get("endsAt"))
    if status == 426 and code == "launcher_update_required":
        raise LauncherUpdateRequiredError(
            str(obj.get("minLauncherVersion", "")),
            obj.get("manifestUrl") if isinstance(obj.get("manifestUrl"), str) else None,
        )
    if status == 426:
        # Field names confirmed against the real private-server/src/control.ts
        # (enforceClientVersion): {error:"update_required", minClientVersion, manifestUrl}.
        raise UpdateRequiredError(str(obj.get("minClientVersion", "")), obj.get("manifestUrl"))
    if status == 401:
        raise AuthError(status, code)
    if status == 409:
        raise ConflictError(obj)
    raise ApiError(status, code, payload=obj)


def _parse_json_bytes(raw: bytes) -> Any:
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}


@dataclass(frozen=True)
class ResponseClock:
    """Time of one successful origin response, used only for session deadlines."""
    path: str
    server_time: int
    local_started: float

    @classmethod
    def read(cls, response, path, started, elapsed):
        try:
            headers = response.headers
            values = headers.get_all('Date') if hasattr(headers, 'get_all') else [headers.get('Date')]
            if not isinstance(values, list) or len(values) != 1:
                return None
            value = values[0]
            if not isinstance(value, str) or len(value) > 128:
                return None
            date = parsedate_to_datetime(value)
            if date.tzinfo is None or date.utcoffset().total_seconds() != 0:
                return None
            server_time = int(date.timestamp())
            # A changed OS clock during the request cannot define a reliable
            # local deadline. Missing/malformed Date falls back to strict checks.
            if (server_time <= 0 or not 0 <= elapsed <= 600
                    or abs((time.time() - started) - elapsed) > 2):
                return None
            return cls(path, server_time, started)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None


class ApiClient:
    def __init__(
        self,
        base_url: str,
        client_version: str,
        session_token: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        *,
        strict_download_transport: bool = False,
        total_timeout: float | None = None,
        launcher_version: str | None = None,
    ) -> None:
        self.base_url = normalize_api_base_url(base_url)
        self.client_version = client_version
        self.launcher_version = (_installed_launcher_version() if launcher_version is None
                                 else _validated_launcher_version(launcher_version))
        self.session_token = session_token
        self.response_clock: ResponseClock | None = None
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite positive number")
        if total_timeout is not None and (
            not math.isfinite(total_timeout) or total_timeout <= 0
        ):
            raise ValueError("total_timeout must be a finite positive number")
        self.timeout = timeout
        self.strict_download_transport = strict_download_transport
        self._deadline = (
            time.monotonic() + total_timeout if total_timeout is not None else None
        )
        self._opener = urllib.request.build_opener(_NoRedirectHandler())

    def _operation_timeout(self) -> float:
        """Return a per-I/O timeout without exceeding an optional total budget."""
        if self._deadline is None:
            return self.timeout
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise NetworkError("network operation deadline exceeded")
        return min(self.timeout, remaining)

    def _retry_sleep(self, delay: float) -> None:
        if self._deadline is None:
            time.sleep(delay)
            return
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise NetworkError("network operation deadline exceeded")
        time.sleep(min(delay, remaining))

    def _read_bounded(self, response: Any, max_bytes: int, chunk_size: int = 64 * 1024) -> bytes:
        """Read incrementally, checking the total deadline between socket reads.

        ``read1`` performs at most one buffered/raw read on HTTPResponse, rather
        than waiting to fill a multi-megabyte request while a peer trickles
        bytes. A single socket read may still overrun the total deadline by up
        to the configured per-I/O timeout; it cannot extend it indefinitely.
        """
        parts: list[bytes] = []
        total = 0
        read_once = getattr(response, "read1", response.read)
        while True:
            self._operation_timeout()
            chunk = read_once(min(chunk_size, max_bytes + 1 - total))
            if not chunk:
                return b"".join(parts)
            parts.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                return b"".join(parts)

    # -- low-level request plumbing -----------------------------------

    def _headers(self, auth_token: str | None, extra: dict[str, str] | None) -> dict[str, str]:
        headers = {
            "User-Agent": f"TWA-Revival-Companion/{self.client_version}",
            "X-TWA-Client-Version": self.client_version,
            "X-TWA-Launcher-Version": self.launcher_version,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        token = auth_token if auth_token is not None else self.session_token
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if extra:
            headers.update(extra)
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        auth_token: str | None = None,
        extra_headers: dict[str, str] | None = None,
        max_bytes: int = MAX_JSON_BYTES,
    ) -> Any:
        self.response_clock = None
        idempotent = method == "GET"
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        attempts = 4 if idempotent else 1
        delay = 0.25
        last_exc: Exception | None = None
        for attempt in range(attempts):
            req = urllib.request.Request(
                url, data=data, method=method, headers=self._headers(auth_token, extra_headers)
            )
            try:
                started, tick = time.time(), time.monotonic()
                with self._opener.open(req, timeout=self._operation_timeout()) as resp:
                    raw = self._read_bounded(resp, max_bytes)
                    if len(raw) > max_bytes:
                        raise ApiError(resp.status, "response_too_large")
                    self.response_clock = ResponseClock.read(resp, path, started, time.monotonic() - tick)
                    return _parse_json_bytes(raw)
            except urllib.error.HTTPError as exc:
                try:
                    raw = self._read_bounded(exc, max_bytes)
                except _BODY_NETWORK_ERRORS as body_error:
                    raise NetworkError(str(body_error)) from body_error
                finally:
                    exc.close()
                _raise_for_status(exc.code, _parse_json_bytes(raw))
            except _RETRYABLE_NETWORK_ERRORS as exc:
                last_exc = exc
                if idempotent and attempt + 1 < attempts:
                    self._retry_sleep(delay)
                    delay = min(delay * 2, 4.0)
                    continue
                raise NetworkError(str(exc)) from exc
        raise NetworkError(str(last_exc) if last_exc else "request failed")

    # -- account / session ----------------------------------------------

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/health")

    def auth_eos(
        self, connect_id_token: str, display_name: str | None = None, invite_code: str | None = None
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if display_name is not None:
            body["displayName"] = display_name
        if invite_code is not None:
            body["inviteCode"] = invite_code
        result = self._request("POST", "/v1/auth/eos", body=body, auth_token=connect_id_token)
        return result

    def me(self) -> dict[str, Any]:
        return self._request("GET", "/v1/me")

    def update_display_name(self, display_name: str) -> dict[str, Any]:
        return self._request("PATCH", "/v1/me/display-name", body={"displayName": display_name})

    def get_career(self) -> dict[str, Any]:
        """Read the signed-in account's career using the saved session token."""
        return self._request("GET", "/v1/career")

    def select_commander(self, commander_id: str) -> dict[str, Any]:
        """PATCH /v1/me/commander. POST /v1/battles pins the battle loadout to
        the account's selected commander, so this must run first whenever the
        native active commander changes."""
        return self._request("PATCH", "/v1/me/commander", body={"commanderId": commander_id})

    def get_loadout(self) -> dict[str, Any]:
        return self._request("GET", "/v1/me/loadout")

    def put_loadout(self, commander_id: str, item_ids: list[str],
                    expected_revision: int) -> dict[str, Any]:
        return self._request(
            "PUT", "/v1/me/loadout",
            body={"commanderId": commander_id, "itemIds": item_ids,
                  "expectedRevision": expected_revision})

    # -- standard matchmaking (PvP) -------------------------------------

    def renew_session(self, connect_id_token: str) -> dict[str, Any]:
        return self._request("POST", "/v1/auth/eos/refresh", body={"connectIdToken": connect_id_token})

    def matchmaking_join(self, mode: str, ruleset: str) -> dict[str, Any]:
        return self._request("POST", "/v1/matchmaking/join", body={"mode": mode, "ruleset": ruleset})

    def matchmaking_status(self) -> dict[str, Any]:
        return self._request("GET", "/v1/matchmaking")

    def matchmaking_cancel(self) -> dict[str, Any]:
        return self._request("POST", "/v1/matchmaking/cancel", body={})

    def create_room(self, mode: str, ruleset: str, max_players: int,
                    ai_opponents: int, visibility: str | None = None,
                    room_config: dict[str, Any] | None = None,
                    map_key: str | None = None) -> dict[str, Any]:
        body={"mode": mode,
            "ruleset": ruleset, "maxPlayers": max_players,
            "aiOpponents": ai_opponents}
        if visibility is not None:
            body["visibility"] = visibility
        if room_config is not None:
            body["roomConfig"] = room_config
        if map_key is not None:
            body["mapKey"] = map_key
        return self._request("POST", "/v1/rooms", body=body)

    def list_rooms(self, *, limit: int = 50, cursor: str | None = None) -> dict[str, Any]:
        path = f"/v1/rooms?limit={limit}"
        if cursor is not None:
            path += "&cursor=" + quote(cursor, safe="")
        return self._request("GET", path)

    def get_room(self, room_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/rooms/{room_id}")

    def room_join(self, room_id: str) -> dict[str, Any]:
        return self._request("POST", f"/v1/rooms/{room_id}/join", body={})

    def room_leave(self, room_id: str) -> dict[str, Any]:
        return self._request("POST", f"/v1/rooms/{room_id}/leave", body={})

    def room_ready(self, room_id: str, ready: bool) -> dict[str, Any]:
        return self._request("POST", f"/v1/rooms/{room_id}/ready",
                             body={"ready": ready})

    def room_team(self, room_id: str, team: int) -> dict[str, Any]:
        return self._request("POST", f"/v1/rooms/{room_id}/team", body={"team": team})

    def room_settings(self, room_id: str, settings: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", f"/v1/rooms/{room_id}/settings", body=settings)

    def room_prepare(self, room_id: str) -> dict[str, Any]:
        return self._request("POST", f"/v1/rooms/{room_id}/prepare", body={})

    def room_start(self, room_id: str) -> dict[str, Any]:
        return self._request("POST", f"/v1/rooms/{room_id}/start", body={})

    def room_return(self, room_id: str, battle_id: str) -> dict[str, Any]:
        return self._request("POST", f"/v1/rooms/{room_id}/return",
                             body={"battleId": battle_id})

    def room_return_eligibility(self, room_id: str,
                                battle_id: str) -> dict[str, Any]:
        """Read current owner/returnability without clearing Room state."""
        return self._request(
            "POST", f"/v1/rooms/{room_id}/return-eligibility",
            body={"battleId": battle_id},
        )

    def create_battle_from_assignment(self, assignment_id: str) -> dict[str, Any]:
        return self._request("POST", "/v1/battles/from-assignment", body={"assignmentId": assignment_id})

    def relay_ticket(self, battle_id: str) -> dict[str, Any]:
        """Returns {ticket, relayUrl, expiresAt, battleId, battleKeyHex, seat, playerId, team}."""
        return self._request("POST", f"/v1/battles/{battle_id}/relay-ticket", body={})

    def put_squad(self, battle_id: str, rows: Any) -> dict[str, Any]:
        """Upload this participant's trusted native full_squad_setup rows (opaque to the Worker).

        The rows travel as a JSON *string* (`rowsJson`): native uint64 ids exceed
        2^53 and would be rounded if the Worker parsed and re-serialized them.
        """
        rows_json = json.dumps(rows, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        return self._request("PUT", f"/v1/battles/{battle_id}/squad", body={"rowsJson": rows_json})

    def get_roster(self, battle_id: str) -> dict[str, Any]:
        """All participants' squads once every seat has uploaded; 409 roster_incomplete before that.

        Each participant's `rowsJson` string is parsed here (Python keeps big ints
        exact) and exposed as `rows`, so callers see the native row arrays.
        """
        roster = self._request("GET", f"/v1/battles/{battle_id}/roster")
        for seat in roster.get("participants", []) if isinstance(roster, dict) else []:
            if isinstance(seat, dict) and "rows" not in seat and isinstance(seat.get("rowsJson"), str):
                seat["rows"] = json.loads(seat["rowsJson"])
        return roster

    def logout(self) -> dict[str, Any]:
        result = self._request("POST", "/v1/logout", body={})
        self.session_token = None
        return result

    # -- profile blob -----------------------------------------------------

    def get_profile(self) -> dict[str, Any] | None:
        """Returns {schemaVersion, saved, blob}, or None if no profile exists yet (404)."""
        try:
            return self._request("GET", "/v1/profile")
        except ApiError as exc:
            if exc.status == 404:
                return None
            raise

    def put_profile(self, schema_version: int, saved: int, blob: Any, expected_saved: int) -> dict[str, Any]:
        """Optimistic-concurrency write: If-Match must equal the server's current `saved`.

        Raises ConflictError (409) if the server's watermark has moved on.
        """
        # Quoted, HTTP ETag-style: private-server/src/profiles.ts's
        # expectedSaved() only accepts /^"(\d{1,15})"$/ -- a bare digit
        # string is rejected as invalid_if_match. An absent header means
        # "create only", so expected_saved == 0 (no profile yet) sends none.
        headers = {"If-Match": f'"{expected_saved}"'} if expected_saved else {}
        return self._request(
            "PUT",
            "/v1/profile",
            body={"schemaVersion": schema_version, "saved": saved, "blob": blob},
            extra_headers=headers,
        )

    # -- battles ------------------------------------------------------

    def create_battle(self, mode: str, ruleset: str, loadout: Any,
                      map_key: str | None = None) -> dict[str, Any]:
        """Create a PvE battle, optionally pinning the allocator's map.

        ``map_key`` is only supplied by a local allocation which already
        froze its authoritative map choice.  Omitting it preserves the
        Worker-owned random selection path and the legacy request shape.
        """
        body = {"mode": mode, "ruleset": ruleset, "loadout": loadout}
        if map_key is not None:
            body["mapKey"] = map_key
        return self._request("POST", "/v1/battles", body=body)

    def report_battle_result(self, battle_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", f"/v1/battles/{battle_id}/result", body=payload)

    def get_battle(self, battle_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/battles/{battle_id}")

    def get_battle_with_admission(self, battle_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/battles/{battle_id}?admission=1")

    def get_active_battle(self) -> dict[str, Any]:
        return self._request("GET", "/v1/battles/active")

    # -- ops: announcements / update manifest ------------------------

    def announcements(self) -> dict[str, Any]:
        return self._request("GET", "/v1/announcements")

    def update_manifest(self, channel: str) -> dict[str, Any]:
        from .trusted_keys import PUBLIC_DOWNLOAD_ORIGIN
        if self.base_url == PUBLIC_DOWNLOAD_ORIGIN:
            if channel not in ('stable', 'beta'):
                raise ApiError(0, 'invalid_channel')
            return self._request('GET', f'/manifests/{channel}.json', auth_token='')
        # /v1/update/manifest is one of the few routes the Worker exempts
        # from its blanket "no query strings" rule (see private-server/src/
        # index.ts's queryRoutes) specifically so channel selection can be
        # ?channel=<channel> (defaulting server-side to "stable" if omitted).
        return self._request("GET", f"/v1/update/manifest?channel={quote(channel, safe='')}")

    def launcher_update_manifest(self, channel: str) -> dict[str, Any]:
        from .trusted_keys import PUBLIC_DOWNLOAD_ORIGIN
        if self.base_url == PUBLIC_DOWNLOAD_ORIGIN:
            if channel not in ('stable', 'beta'):
                raise ApiError(0, 'invalid_channel')
            # R2 serves channel files directly; query strings cannot select an
            # object. Never attach the account API's session to the public CDN.
            return self._request('GET', f'/launcher-manifests/{channel}.json', auth_token='')
        return self._request("GET", f"/v1/update/launcher-manifest?channel={quote(channel, safe='')}")

    # -- object download (update payloads) -----------------------------

    @staticmethod
    def _validate_release_payload_url(url: str) -> None:
        """Reject payload transports that are unsafe for a release update."""
        if (
            not isinstance(url, str)
            or not url
            or "\\" in url
            or any(ord(char) < 0x21 for char in url)
        ):
            raise ApiError(0, "unsafe_update_url", "update URL is malformed")
        parsed = urlsplit(url)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ApiError(0, "unsafe_update_url", "update URL has an invalid port") from exc
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ApiError(
                0,
                "unsafe_update_url",
                "release update objects require an HTTPS URL without credentials or fragment",
            )
        host = parsed.hostname.rstrip(".").lower()
        is_loopback = host == "localhost"
        if not is_loopback:
            try:
                is_loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                pass
        if is_loopback:
            raise ApiError(0, "unsafe_update_url", "release update objects cannot use loopback")
        # Accessing parsed.port above validates it. Keep this assignment so
        # linters do not mistake the validation for dead code.
        _ = port

    def download_object(
        self,
        url: str,
        dest_path: Path,
        expected_sha256: str,
        expected_size: int,
        chunk_size: int = 1 << 20,
    ) -> None:
        """Stream url to dest_path, verifying size and sha256 before the final rename.

        On any mismatch the partial download is removed and an ApiError is
        raised; dest_path is left untouched (the caller sees no update to
        the destination unless verification fully succeeds).
        """
        full_url = url if "://" in url else f"{self.base_url}{url if url.startswith('/') else '/' + url}"
        if self.strict_download_transport:
            self._validate_release_payload_url(full_url)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = dest_path.with_name(dest_path.name + ".part")
        req = urllib.request.Request(full_url, headers={"X-TWA-Client-Version": self.client_version,
            "X-TWA-Launcher-Version": self.launcher_version,
            "User-Agent": f"TWA-Revival-Companion/{self.client_version}"})
        hasher = hashlib.sha256()
        total = 0
        try:
            # The release updater uses the no-redirect opener. This is stricter
            # than merely rejecting HTTPS -> HTTP redirects: a manifest must
            # contain the final HTTPS object URL, making every fetched origin
            # visible in the signed data. Development callers retain the
            # historical urllib behavior unless they explicitly opt in.
            opener = self._opener.open if self.strict_download_transport else urllib.request.urlopen
            with opener(req, timeout=self._operation_timeout()) as resp:
                with tmp_path.open("wb") as fh:
                    while True:
                        self._operation_timeout()
                        read_once = getattr(resp, "read1", resp.read)
                        chunk = read_once(min(chunk_size, 64 * 1024))
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > expected_size:
                            raise ApiError(0, "download_too_large", f"{url}: exceeded expected size {expected_size}")
                        hasher.update(chunk)
                        fh.write(chunk)
        except urllib.error.HTTPError as exc:
            try:
                raw = self._read_bounded(exc, MAX_JSON_BYTES)
            except _BODY_NETWORK_ERRORS as body_error:
                raise NetworkError(str(body_error)) from body_error
            finally:
                exc.close()
                tmp_path.unlink(missing_ok=True)
            _raise_for_status(exc.code, _parse_json_bytes(raw))
        except _RETRYABLE_NETWORK_ERRORS as exc:
            tmp_path.unlink(missing_ok=True)
            raise NetworkError(str(exc)) from exc
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise
        if total != expected_size:
            tmp_path.unlink(missing_ok=True)
            raise ApiError(0, "size_mismatch", f"{url}: got {total} bytes, expected {expected_size}")
        digest = hasher.hexdigest()
        if digest != expected_sha256.lower():
            tmp_path.unlink(missing_ok=True)
            raise ApiError(0, "hash_mismatch", f"{url}: sha256 {digest} != expected {expected_sha256}")
        os.replace(tmp_path, dest_path)
