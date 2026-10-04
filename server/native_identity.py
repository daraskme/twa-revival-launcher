"""Per-user identity for the loopback native stack.

The game presents exactly one secret to the local stack: the ``+auth <token>``
launch argument (mirrored by the ``fake_auth_token`` preference).  It reaches
this server as ``request.netease_token`` of ``POST /netease/login_netease``;
every later identity field the client sends (``headers.user_id``, the CASAG
``backend_user_id``/``backend_access_token`` of ``/auth/twa/verify``, the XMPP
JID localpart and the 37 byte GAME_JOIN identity slot) is a value this server
handed the client first.  Therefore the token is the only trustworthy root and
everything else is verified *against* the resolved identity, never used as one.

``native_user_id`` is derived from the Worker/EOS PUID and must satisfy the
native wire constraints: at most 36 bytes so it still fits the NUL terminated
37 byte GAME_JOIN slot (``native_relay_probe.game_join_metadata``), printable
ASCII only, and no character outside the economy identifier alphabet.

Raw session tokens are never stored: only their SHA-256 digest, which is the
same digest the Cloudflare Worker keys ``sessions.token_hash`` by
(``private-server/src/accounts.ts`` ``hash()``).
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Protocol, runtime_checkable

# The GAME_JOIN identity slot is 37 bytes including its NUL terminator.
NATIVE_USER_ID_MAX = 36
# An EOS ProductUserId is 32 lowercase hex characters, so it always passes
# through verbatim.  That is required, not merely convenient: the Worker's
# relay ticket (private-server/src/battles.ts ``issueRelayTicket``) and the
# BattleRelay Durable Object both carry ``actor.id`` (= the PUID) as the seat
# ``userId``, and that value must equal the client's GAME_JOIN identity slot
# byte for byte.  Any transformation here would break PvP seat matching.
_PASSTHROUGH_MAX = NATIVE_USER_ID_MAX
_PASSTHROUGH = re.compile(r"[A-Za-z0-9_-]{1,%d}" % _PASSTHROUGH_MAX)
_NATIVE_USER_ID = re.compile(r"[A-Za-z0-9_-]{1,%d}" % NATIVE_USER_ID_MAX)
_HEX_256 = re.compile(r"[0-9a-f]{64}")
_DERIVATION_DOMAIN = b"twa-revival:native-user-id:v1\x00"

# The historical single-user lab identity.  ``f2p_fake.PLAYER`` / ``TOKEN``
# keep these exact values so every existing test and trace stays valid.
DEFAULT_NATIVE_USER_ID = "player"
LEGACY_SESSION_TOKEN = "revival-token"
MAX_TOKEN_CHARS = 8192


class IdentityError(ValueError):
    """A fail-closed identity error with a stable, value-free code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def hash_session_token(token: object) -> str:
    """SHA-256 of the presented session token, matching the Worker's digest."""
    if not isinstance(token, str) or not 1 <= len(token) <= MAX_TOKEN_CHARS:
        raise IdentityError("invalid_session_token")
    if any(ord(char) < 32 or ord(char) == 127 for char in token):
        raise IdentityError("invalid_session_token")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def derive_native_user_id(puid: object) -> str:
    """Deterministically map a PUID onto a native-wire safe identifier.

    A PUID that already fits the wire (at most 36 characters of
    ``[A-Za-z0-9_-]``) is used **verbatim**.  An EOS ProductUserId is 32
    lowercase hex characters, so this is the only branch real accounts take,
    and the value stays byte-identical to the Worker's ``actor.id`` used as the
    relay-ticket seat ``userId``.

    The shortened form exists only for inputs the wire cannot represent -- an
    over-long or non-identifier PUID -- which no EOS deployment produces today.
    It is therefore unreachable for anything the passthrough branch accepts.
    """
    if not isinstance(puid, str) or not 1 <= len(puid) <= 256:
        raise IdentityError("invalid_puid")
    if any(ord(char) < 32 or ord(char) > 126 for char in puid):
        raise IdentityError("invalid_puid")
    if _PASSTHROUGH.fullmatch(puid):
        return puid
    digest = hashlib.sha256(_DERIVATION_DOMAIN + puid.encode("utf-8")).hexdigest()
    return "u" + digest[: NATIVE_USER_ID_MAX - 1]


@dataclass(frozen=True)
class NativeIdentity:
    """One resolved player: wire identity, cloud identity, session digest."""

    native_user_id: str
    puid: str
    session_token_hash: str
    display_name: str | None = None

    def __post_init__(self) -> None:
        if self.display_name is not None:
            from companion.player_name import validate_display_name
            validate_display_name(self.display_name)
        if (not isinstance(self.native_user_id, str)
                or not _NATIVE_USER_ID.fullmatch(self.native_user_id)):
            raise IdentityError("invalid_native_user_id")
        if len(self.native_user_id.encode("ascii")) > NATIVE_USER_ID_MAX:
            raise IdentityError("invalid_native_user_id")
        if not isinstance(self.puid, str) or not 1 <= len(self.puid) <= 256:
            raise IdentityError("invalid_puid")
        if (not isinstance(self.session_token_hash, str)
                or not _HEX_256.fullmatch(self.session_token_hash)):
            raise IdentityError("invalid_session_token_hash")


@runtime_checkable
class IdentityResolverProtocol(Protocol):
    """The surface every native handler needs from a resolver."""

    @property
    def native_user_id(self) -> str: ...

    def resolve_session_token(self, token: object) -> NativeIdentity: ...

    def resolve_native_user_id(self, value: object) -> NativeIdentity: ...

    def matches(self, value: object) -> bool: ...


class IdentityResolver:
    """Resolve the ``+auth`` session token presented by the running game.

    Phase 1 of the companion is one process per player, so the registry
    normally holds exactly one identity.  The dict shape is kept so a later
    multi-tenant host can register several without changing call sites.
    """

    def __init__(self, sessions: Iterable[tuple[str, str]] = ()) -> None:
        self._by_hash: dict[str, NativeIdentity] = {}
        self._by_native: dict[str, NativeIdentity] = {}
        for token, puid in sessions:
            self.register(token, puid)

    # -- registration ---------------------------------------------------

    def register(self, session_token: str, puid: str, *,
                 display_name: str | None = None) -> NativeIdentity:
        """Bind one live session token to its PUID-derived native identity."""
        identity = NativeIdentity(
            native_user_id=derive_native_user_id(puid),
            puid=puid,
            session_token_hash=hash_session_token(session_token),
            display_name=display_name,
        )
        return self._insert(identity)

    def _insert(self, identity: NativeIdentity) -> NativeIdentity:
        existing = self._by_native.get(identity.native_user_id)
        if existing is not None and existing.puid != identity.puid:
            raise IdentityError("native_user_id_collision")
        self._by_hash[identity.session_token_hash] = identity
        self._by_native[identity.native_user_id] = identity
        return identity

    def forget(self, session_token: str) -> None:
        identity = self._by_hash.pop(hash_session_token(session_token), None)
        if identity is not None and not any(
                entry.native_user_id == identity.native_user_id
                for entry in self._by_hash.values()):
            self._by_native.pop(identity.native_user_id, None)

    # -- resolution -----------------------------------------------------

    def resolve_session_token(self, token: object) -> NativeIdentity:
        """Return the identity for a presented ``+auth`` token.

        An unknown session is rejected: this server never invents an account
        for a token it did not issue or was not told about.
        """
        try:
            digest = hash_session_token(token)
        except IdentityError:
            raise IdentityError("unknown_session") from None
        identity = self._by_hash.get(digest)
        if identity is None:
            raise IdentityError("unknown_session")
        return identity

    def resolve_native_user_id(self, value: object) -> NativeIdentity:
        """Verify a client-echoed native user id against the registry."""
        if not isinstance(value, str):
            raise IdentityError("native_user_mismatch")
        identity = self._by_native.get(value)
        if identity is None:
            raise IdentityError("native_user_mismatch")
        return identity

    def matches(self, value: object) -> bool:
        """True when ``value`` is a native user id this resolver knows."""
        return isinstance(value, str) and value in self._by_native

    # -- single-user convenience ----------------------------------------

    @property
    def identity(self) -> NativeIdentity:
        if len(self._by_native) != 1:
            raise IdentityError("ambiguous_identity")
        return next(iter(self._by_native.values()))

    @property
    def native_user_id(self) -> str:
        """The one bound wire identity (phase 1: one process, one player)."""
        return self.identity.native_user_id

    @property
    def identities(self) -> tuple[NativeIdentity, ...]:
        return tuple(self._by_native.values())


class StaticIdentityResolver(IdentityResolver):
    """The legacy single-user lab identity: ``player`` / ``revival-token``.

    ``native_user_id`` is fixed rather than derived so existing traces, SQLite
    rows and tests keep the exact historical value.
    """

    def __init__(
        self,
        native_user_id: str = DEFAULT_NATIVE_USER_ID,
        session_token: str = LEGACY_SESSION_TOKEN,
        puid: str | None = None,
    ) -> None:
        super().__init__()
        if (not isinstance(native_user_id, str)
                or not _NATIVE_USER_ID.fullmatch(native_user_id)):
            raise IdentityError("invalid_native_user_id")
        self._insert(NativeIdentity(
            native_user_id=native_user_id,
            puid=native_user_id if puid is None else puid,
            session_token_hash=hash_session_token(session_token),
        ))


def read_session_token_file(
    path: str | Path, *, expected_api_base_url: str | None = None,
) -> tuple[str, str]:
    """Read ``{token, puid}`` (or a Worker login reply) from a JSON file.

    Accepted shapes, in order:
      ``{"token": "...", "puid": "..."}``
      ``{"token": "...", "user": {"id": "..."}}``  (the ``POST /v1/auth/eos``
      reply produced by ``companion.api_client.ApiClient.auth_eos``)

    The token is returned to the caller and never written to a trace.
    """
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        raise IdentityError("session_token_file_unreadable") from error
    except UnicodeError:
        raise IdentityError("invalid_session_token_file") from None
    try:
        body = json.loads(raw)
    except (ValueError, UnicodeError):
        raise IdentityError("invalid_session_token_file") from None
    if not isinstance(body, dict):
        raise IdentityError("invalid_session_token_file")
    token = body.get("token")
    puid = body.get("puid")
    if puid is None:
        user = body.get("user")
        puid = user.get("id") if isinstance(user, dict) else None
    if not isinstance(token, str) or not isinstance(puid, str):
        raise IdentityError("invalid_session_token_file")
    if expected_api_base_url is not None:
        try:
            from companion.api_client import normalize_api_base_url
        except ImportError:
            raise IdentityError("companion_package_unavailable") from None
        api_base_url = body.get("apiBaseUrl")
        expires_at = body.get("expiresAt")
        if (not _HEX_256.fullmatch(token)
                or not isinstance(api_base_url, str)
                or not isinstance(expires_at, int) or isinstance(expires_at, bool)):
            raise IdentityError("invalid_bound_session_file")
        try:
            expected = normalize_api_base_url(expected_api_base_url)
        except (TypeError, ValueError):
            raise IdentityError("invalid_expected_api_base_url") from None
        try:
            actual = normalize_api_base_url(api_base_url)
        except (TypeError, ValueError):
            raise IdentityError("invalid_bound_session_file") from None
        if actual != expected:
            raise IdentityError("session_api_base_url_mismatch")
        if expires_at <= int(time.time()):
            raise IdentityError("session_expired")
    # Validate both halves before returning so a malformed file fails at read
    # time rather than at the first game request.
    hash_session_token(token)
    derive_native_user_id(puid)
    return token, puid


__all__ = [
    "DEFAULT_NATIVE_USER_ID",
    "IdentityError",
    "IdentityResolver",
    "IdentityResolverProtocol",
    "LEGACY_SESSION_TOKEN",
    "NATIVE_USER_ID_MAX",
    "NativeIdentity",
    "StaticIdentityResolver",
    "derive_native_user_id",
    "hash_session_token",
    "read_session_token_file",
]
