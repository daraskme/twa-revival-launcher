"""High-level EOS login session: Auth login -> Connect login -> Connect ID token.

Two backends implement the same small surface:

  EosSession       -- drives the real EOSSDK-Win64-Shipping.dll via
                       bindings.py on one caller-owned thread.
  FakeEosBackend    -- no DLL, no network. Returns a structurally valid
                       (3-segment, base64url, JSON payload) but unsigned
                       fake token. For unit tests and ``--fake`` CLI runs
                       only -- it will NEVER pass the Worker's real
                       verification (private-server/src/eos.ts requires
                       an RS256 signature from Epic's JWKS), by design.

Both expose the same public shape so callers (the CLI, and eventually the
companion's Worker client) do not need to know which one they hold:

  backend.login(method, **kwargs) -> ConnectIdToken
  backend.logout() -> None
  backend.shutdown() -> None
  backend.on_auth_expiring(callback) -> None   (best-effort; see notes)

ConnectIdToken.token is exactly the string to send as
``Authorization: Bearer <token>`` to the Worker's ``POST /v1/auth/eos``.
"""
from __future__ import annotations

import base64
import json
import logging
import threading
import time
import uuid
from ctypes import POINTER, byref, c_void_p, pointer
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Protocol, Union

from . import bindings as b

logger = logging.getLogger("companion.eos.session")

LOGIN_METHODS = ("account_portal", "persistent", "dev_auth", "exchange_code")

# Connect access tokens are documented as valid for "現在は1時間" (currently
# one hour) -- see the Connect interface reference page cited in
# docs/eos_companion_20260902.md. EOS_Connect_AddNotifyAuthExpiration fires
# "approximately 1 minute prior to expiration"; DEFAULT_EXPIRY_MARGIN_S
# is this module's own conservative default for is_expiring_soon(), used
# when there is no live AddNotify callback (e.g. FakeEosBackend, or a
# caller just polling ConnectIdToken.expires_at).
DEFAULT_EXPIRY_MARGIN_S = 90


class EosLoginError(RuntimeError):
    """An EOS-level login failure (as opposed to a ctypes/DLL problem,
    which raises bindings.EosBindingError instead).
    """

    def __init__(self, message, *, operation=None, result_code=None):
        super().__init__(message)
        # Only a fixed operation identifier and native integer may cross the UI
        # boundary. Exception text and authentication payloads remain private.
        self.operation = operation
        self.result_code = result_code


class EosTimeoutError(EosLoginError):
    """An async EOS call never completed within the caller's timeout."""


@dataclass(frozen=True)
class ConnectIdToken:
    token: str = field(repr=False)  # raw bearer credential: never log or persist it
    expires_at: int  # unix seconds, from the token's own "exp" claim (unverified locally -- see _decode_jwt_payload)
    puid: str  # Product User ID, from the token's own "sub" claim

    def is_expiring_soon(self, margin_s: int = DEFAULT_EXPIRY_MARGIN_S, now: Optional[int] = None) -> bool:
        now = int(time.time()) if now is None else now
        return self.expires_at - now <= margin_s


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _decode_jwt_payload(token: str) -> dict:
    """Decode (NOT verify) a JWT's payload segment.

    This is purely a local convenience for populating ConnectIdToken.puid
    / .expires_at for display and expiry-polling. It performs no signature
    check and must never be treated as authentication -- the Worker
    (private-server/src/eos.ts, verifyConnectIdToken) is the only party
    that verifies the token, against Epic's JWKS
    (https://api.epicgames.dev/auth/v1/oauth/jwks).
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise EosLoginError("Connect ID token is not a 3-segment JWT (header.payload.signature)")
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as exc:  # noqa: BLE001 - surface as a domain error
        raise EosLoginError(f"Connect ID token payload is not decodable JSON: {exc}") from exc
    if not isinstance(payload, dict) or "sub" not in payload or "exp" not in payload:
        raise EosLoginError("Connect ID token payload is missing required claims (sub, exp)")
    return payload


class EosBackend(Protocol):
    def login(self, method: str, **kwargs) -> ConnectIdToken: ...
    def logout(self) -> None: ...
    def shutdown(self) -> None: ...
    def on_auth_expiring(self, callback: Callable[[], None]) -> None: ...


# ---------------------------------------------------------------------------
# Real backend
# ---------------------------------------------------------------------------


class _PendingCall:
    """One in-flight async EOS call: holds the result once the SDK's Tick
    thread invokes our ctypes callback, and blocks the calling thread
    until then (or until timeout).
    """

    def __init__(self):
        self._event = threading.Event()
        self._value = None

    def resolve(self, value) -> None:
        self._value = value
        self._event.set()

class EosSession:
    """Drives a real EOSSDK-Win64-Shipping.dll.

    Lifecycle: construct -> start() -> login(...) [-> ... more logins ...]
    -> logout() -> shutdown(). Also usable as a context manager, which
    calls start()/shutdown() for you.
    """

    def __init__(
        self,
        dll_path: Union[str, Path],
        product_id: str,
        sandbox_id: str,
        deployment_id: str,
        client_id: str,
        client_secret: Optional[str] = None,
        product_name: str = "twa-revival-companion",
        product_version: str = "0.0.1",
        tick_interval_s: float = 0.05,
        call_timeout_s: float = 30.0,
    ):
        self._sdk = b.EosSdk(dll_path)
        self._product_id = product_id
        self._sandbox_id = sandbox_id
        self._deployment_id = deployment_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._product_name = product_name
        self._product_version = product_version
        self._tick_interval_s = tick_interval_s
        self._call_timeout_s = call_timeout_s

        self._platform: Optional[c_void_p] = None
        self._auth_handle: Optional[c_void_p] = None
        self._connect_handle: Optional[c_void_p] = None

        self._owner_thread_id: Optional[int] = None

        self._epic_account_id = None  # SelectedAccountId from the last Auth_Login
        self._auth_local_user_id = None  # LocalUserId used by EOS_Auth_Logout
        self._product_user_id = None  # PUID handle from the last Connect_Login/CreateUser

        self._expiring_callback: Optional[Callable[[], None]] = None
        self._expiration_notification_id: Optional[int] = None
        # ctypes callback objects MUST be kept alive for as long as the SDK
        # might invoke them (registered notifications live for the whole
        # session) -- storing them on self prevents GC from collecting the
        # CFUNCTYPE trampoline out from under a live registration.
        self._live_callbacks: list = []

        self._started = False
        self._initialized = False

    # -- lifecycle -----------------------------------------------------

    def __enter__(self) -> "EosSession":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.shutdown()

    def start(self) -> None:
        if self._started:
            return
        init_options = b.EOS_InitializeOptions(
            ApiVersion=b._ApiVersion.INITIALIZE,
            AllocateMemoryFunction=None,
            ReallocateMemoryFunction=None,
            ReleaseMemoryFunction=None,
            ProductName=self._product_name.encode("utf-8"),
            ProductVersion=self._product_version.encode("utf-8"),
            Reserved=None,
            SystemInitializeOptions=None,
            OverrideThreadAffinity=None,
        )
        result = self._sdk.EOS_Initialize(byref(init_options))
        if self._describe_result(result) != b.EOS_RESULT_SUCCESS:
            raise EosLoginError(f"EOS_Initialize failed: {self._describe_result(result)}")
        self._initialized = True

        platform_options = b.EOS_Platform_Options(
            ApiVersion=b._ApiVersion.PLATFORM_OPTIONS,
            Reserved=None,
            ProductId=self._product_id.encode("utf-8"),
            SandboxId=self._sandbox_id.encode("utf-8"),
            ClientCredentials=b.EOS_Platform_ClientCredentials(
                ClientId=self._client_id.encode("utf-8"),
                ClientSecret=self._client_secret.encode("utf-8") if self._client_secret else None,
            ),
            bIsServer=b.EOS_FALSE,
            EncryptionKey=None,
            OverrideCountryCode=None,
            OverrideLocaleCode=None,
            DeploymentId=self._deployment_id.encode("utf-8"),
            Flags=0,
            CacheDirectory=None,
            TickBudgetInMilliseconds=0,  # 0 = "perform all available work" per docs
            RTCOptions=None,
            IntegratedPlatformOptionsContainerHandle=None,
            SystemSpecificOptions=None,
            TaskNetworkTimeoutSeconds=None,
        )
        self._platform = self._sdk.EOS_Platform_Create(byref(platform_options))
        if not self._platform:
            self._sdk.EOS_Shutdown()
            self._initialized = False
            raise EosLoginError("EOS_Platform_Create returned NULL")

        self._auth_handle = self._sdk.EOS_Platform_GetAuthInterface(self._platform)
        self._connect_handle = self._sdk.EOS_Platform_GetConnectInterface(self._platform)
        if not self._auth_handle or not self._connect_handle:
            self._sdk.EOS_Platform_Release(self._platform)
            self._platform = None
            self._sdk.EOS_Shutdown()
            self._initialized = False
            raise EosLoginError("EOS platform did not provide Auth and Connect interfaces")
        self._owner_thread_id = threading.get_ident()
        self._started = True

    def _require_owner_thread(self) -> None:
        if self._owner_thread_id is not None and threading.get_ident() != self._owner_thread_id:
            raise EosLoginError("EOS session methods must run on the thread that called start()")

    def tick(self) -> None:
        """Pump notifications on the start() thread (needed for expiry callbacks)."""
        self._require_owner_thread()
        if self._started and self._platform:
            self._sdk.EOS_Platform_Tick(self._platform)

    def _wait_call(self, call: _PendingCall):
        deadline = time.monotonic() + self._call_timeout_s
        while not call._event.is_set():
            if time.monotonic() >= deadline:
                raise EosTimeoutError(f"EOS async call did not complete within {self._call_timeout_s}s")
            self._sdk.EOS_Platform_Tick(self._platform)
            call._event.wait(min(self._tick_interval_s, max(0.0, deadline - time.monotonic())))
        return call._value

    def shutdown(self) -> None:
        if not self._started and not self._initialized:
            return
        self._require_owner_thread()
        if self._connect_handle and self._expiration_notification_id is not None:
            try:
                self._sdk.EOS_Connect_RemoveNotifyAuthExpiration(
                    self._connect_handle, self._expiration_notification_id
                )
            except Exception:  # noqa: BLE001 - best effort during teardown
                logger.exception("EOS_Connect_RemoveNotifyAuthExpiration failed during shutdown")
        if self._platform:
            self._sdk.EOS_Platform_Release(self._platform)
            self._platform = None
        if self._initialized:
            self._sdk.EOS_Shutdown()
            self._initialized = False
        self._started = False
        self._auth_handle = None
        self._connect_handle = None
        self._expiration_notification_id = None
        self._live_callbacks.clear()
        self._owner_thread_id = None

    # -- result decoding -------------------------------------------------

    def _describe_result(self, code: int) -> str:
        raw = self._sdk.EOS_EResult_ToString(code)
        if raw is None:
            return str(code)
        return raw.decode("utf-8", "replace")

    # -- login -----------------------------------------------------------

    def login(self, method: str, *, dev_auth: Optional[str] = None, dev_name: Optional[str] = None,
              exchange_code: Optional[str] = None, allow_create_connect: bool = True) -> ConnectIdToken:
        if method not in LOGIN_METHODS:
            raise ValueError(f"Unknown login method {method!r}; choose one of {LOGIN_METHODS}")
        if type(allow_create_connect) is not bool:
            raise ValueError("allow_create_connect must be boolean")
        if not self._started:
            raise EosLoginError("EosSession.start() must be called before login()")
        self._require_owner_thread()

        credentials = b.EOS_Auth_Credentials(
            ApiVersion=b._ApiVersion.AUTH_CREDENTIALS,
            Id=None,
            Token=None,
            Type=b.EOS_LCT_AccountPortal,
            SystemAuthCredentialsOptions=None,
            ExternalType=0,
        )
        if method == "account_portal":
            credentials.Type = b.EOS_LCT_AccountPortal
        elif method == "persistent":
            credentials.Type = b.EOS_LCT_PersistentAuth
        elif method == "dev_auth":
            if not dev_auth or not dev_name:
                raise ValueError("dev_auth login needs both dev_auth='host:port' and dev_name")
            credentials.Type = b.EOS_LCT_Developer
            credentials.Id = dev_auth.encode("utf-8")
            credentials.Token = dev_name.encode("utf-8")
        elif method == "exchange_code":
            if not exchange_code:
                raise ValueError("exchange_code login needs exchange_code")
            credentials.Type = b.EOS_LCT_ExchangeCode
            credentials.Token = exchange_code.encode("utf-8")

        login_options = b.EOS_Auth_LoginOptions(
            ApiVersion=b._ApiVersion.AUTH_LOGIN,
            Credentials=pointer(credentials),
            ScopeFlags=b.EOS_AS_BasicProfile,
            LoginFlags=b.EOS_LF_NO_USER_INTERFACE if method == "persistent" else 0,
        )

        auth_call = _PendingCall()

        @b.EOS_Auth_OnLoginCallback
        def _on_auth_login(data_ptr):
            data = data_ptr.contents
            if not self._sdk.EOS_EResult_IsOperationComplete(data.ResultCode):
                if data.PinGrantInfo:
                    logger.info("EOS Auth login requires the user to complete a PIN grant")
                return
            if data.PinGrantInfo:
                logger.info("EOS Auth login requires the user to complete a PIN grant")
            auth_call.resolve(
                {
                    "result": self._describe_result(data.ResultCode),
                    "result_code": data.ResultCode,
                    "selected_account_id": data.SelectedAccountId,
                    "local_account_id": data.LocalUserId,
                }
            )

        self._live_callbacks.append(_on_auth_login)
        self._sdk.EOS_Auth_Login(self._auth_handle, byref(login_options), None, _on_auth_login)
        auth_result = self._wait_call(auth_call)

        if auth_result["result"] != b.EOS_RESULT_SUCCESS:
            raise EosLoginError(f"EOS_Auth_Login failed: {auth_result['result']}",
                                operation='auth_login', result_code=auth_result['result_code'])

        self._epic_account_id = auth_result["selected_account_id"] or auth_result["local_account_id"]
        self._auth_local_user_id = auth_result["local_account_id"]

        # Auth ID token -> Connect login.
        auth_jwt = self._copy_auth_id_token(self._epic_account_id)
        puid = self._connect_login_with_epic_id_token(auth_jwt, allow_create=allow_create_connect)
        self._product_user_id = puid

        connect_jwt = self._copy_connect_id_token(puid)
        self._register_expiration_notification()
        payload = _decode_jwt_payload(connect_jwt)
        return ConnectIdToken(token=connect_jwt, expires_at=int(payload["exp"]), puid=str(payload["sub"]))

    def _copy_auth_id_token(self, account_id) -> str:
        options = b.EOS_Auth_CopyIdTokenOptions(ApiVersion=b._ApiVersion.AUTH_COPY_ID_TOKEN, AccountId=account_id)
        out_ptr = POINTER(b.EOS_Auth_IdToken)()
        result = self._sdk.EOS_Auth_CopyIdToken(self._auth_handle, byref(options), byref(out_ptr))
        if self._describe_result(result) != b.EOS_RESULT_SUCCESS:
            raise EosLoginError(f"EOS_Auth_CopyIdToken failed: {self._describe_result(result)}",
                                operation='auth_token', result_code=result)
        try:
            jwt = out_ptr.contents.JsonWebToken
            if not jwt:
                raise EosLoginError("EOS_Auth_CopyIdToken succeeded but JsonWebToken was NULL")
            return jwt.decode("utf-8")
        finally:
            self._sdk.EOS_Auth_IdToken_Release(out_ptr)

    def refresh_connect(self) -> ConnectIdToken:
        """Refresh the existing Connect user from the SDK's current Auth proof.

        The caller must keep ticking this session on its owner thread. An
        account change or missing association requires explicit login instead.
        """
        self._require_owner_thread()
        if not self._started or not self._epic_account_id or not self._product_user_id:
            raise EosLoginError("Existing Epic login is required for refresh")
        before = _decode_jwt_payload(self._copy_connect_id_token(self._product_user_id))["sub"]
        puid = self._connect_login_with_epic_id_token(
            self._copy_auth_id_token(self._epic_account_id), allow_create=False)
        token = self._copy_connect_id_token(puid)
        payload = _decode_jwt_payload(token)
        if payload["sub"] != before:
            raise EosLoginError("Epic account changed during refresh")
        self._product_user_id = puid
        return ConnectIdToken(token=token, expires_at=int(payload["exp"]), puid=str(payload["sub"]))

    def _connect_login_with_epic_id_token(self, auth_jwt: str, *, allow_create: bool = True):
        credentials = b.EOS_Connect_Credentials(
            ApiVersion=b._ApiVersion.CONNECT_CREDENTIALS,
            Token=auth_jwt.encode("utf-8"),
            Type=b.EOS_ECT_EPIC_ID_TOKEN,
        )
        options = b.EOS_Connect_LoginOptions(
            ApiVersion=b._ApiVersion.CONNECT_LOGIN, Credentials=pointer(credentials), UserLoginInfo=None
        )

        call = _PendingCall()

        @b.EOS_Connect_OnLoginCallback
        def _on_connect_login(data_ptr):
            data = data_ptr.contents
            call.resolve(
                {
                    "result": self._describe_result(data.ResultCode),
                    "result_code": data.ResultCode,
                    "local_user_id": data.LocalUserId,
                    "continuance_token": data.ContinuanceToken,
                }
            )

        self._live_callbacks.append(_on_connect_login)
        self._sdk.EOS_Connect_Login(self._connect_handle, byref(options), None, _on_connect_login)
        result = self._wait_call(call)

        if result["result"] == b.EOS_RESULT_SUCCESS:
            return result["local_user_id"]

        if allow_create and result["result"] == b.EOS_RESULT_INVALID_USER and result["continuance_token"]:
            return self._connect_create_user(result["continuance_token"])

        raise EosLoginError(f"EOS_Connect_Login failed: {result['result']}",
                            operation='connect_login', result_code=result['result_code'])

    def _connect_create_user(self, continuance_token):
        options = b.EOS_Connect_CreateUserOptions(
            ApiVersion=b._ApiVersion.CONNECT_CREATE_USER, ContinuanceToken=continuance_token
        )
        call = _PendingCall()

        @b.EOS_Connect_OnCreateUserCallback
        def _on_create_user(data_ptr):
            data = data_ptr.contents
            call.resolve({"result": self._describe_result(data.ResultCode),
                          "result_code": data.ResultCode, "local_user_id": data.LocalUserId})

        self._live_callbacks.append(_on_create_user)
        self._sdk.EOS_Connect_CreateUser(self._connect_handle, byref(options), None, _on_create_user)
        result = self._wait_call(call)
        if result["result"] != b.EOS_RESULT_SUCCESS:
            raise EosLoginError(f"EOS_Connect_CreateUser failed: {result['result']}",
                                operation='connect_create', result_code=result['result_code'])
        return result["local_user_id"]

    def _copy_connect_id_token(self, puid) -> str:
        options = b.EOS_Connect_CopyIdTokenOptions(ApiVersion=b._ApiVersion.CONNECT_COPY_ID_TOKEN, LocalUserId=puid)
        out_ptr = POINTER(b.EOS_Connect_IdToken)()
        result = self._sdk.EOS_Connect_CopyIdToken(self._connect_handle, byref(options), byref(out_ptr))
        if self._describe_result(result) != b.EOS_RESULT_SUCCESS:
            raise EosLoginError(f"EOS_Connect_CopyIdToken failed: {self._describe_result(result)}",
                                operation='connect_token', result_code=result)
        try:
            jwt = out_ptr.contents.JsonWebToken
            if not jwt:
                raise EosLoginError("EOS_Connect_CopyIdToken succeeded but JsonWebToken was NULL")
            return jwt.decode("utf-8")
        finally:
            self._sdk.EOS_Connect_IdToken_Release(out_ptr)

    def _register_expiration_notification(self) -> None:
        if self._expiration_notification_id is not None:
            return  # already registered from a previous login() call in this session

        @b.EOS_Connect_OnAuthExpirationCallback
        def _on_expiring(_data_ptr):
            logger.info("EOS Connect auth expiring in ~1 minute; caller should re-login")
            if self._expiring_callback:
                try:
                    self._expiring_callback()
                except Exception:  # noqa: BLE001 - never let a caller's hook break the EOS pump
                    logger.exception("on_auth_expiring callback raised")

        self._live_callbacks.append(_on_expiring)
        options = b.EOS_Connect_AddNotifyAuthExpirationOptions(
            ApiVersion=b._ApiVersion.CONNECT_ADD_NOTIFY_AUTH_EXPIRATION
        )
        self._expiration_notification_id = self._sdk.EOS_Connect_AddNotifyAuthExpiration(
            self._connect_handle, byref(options), None, _on_expiring
        )
        if not self._expiration_notification_id:
            self._expiration_notification_id = None
            raise EosLoginError("EOS_Connect_AddNotifyAuthExpiration returned an invalid notification ID")

    def on_auth_expiring(self, callback: Callable[[], None]) -> None:
        self._expiring_callback = callback

    def logout(self) -> None:
        self._require_owner_thread()
        if not self._auth_handle or not self._auth_local_user_id:
            return
        options = b.EOS_Auth_LogoutOptions(
            ApiVersion=b._ApiVersion.AUTH_LOGOUT, LocalUserId=self._auth_local_user_id
        )
        call = _PendingCall()

        @b.EOS_Auth_OnLogoutCallback
        def _on_logout(data_ptr):
            call.resolve(self._describe_result(data_ptr.contents.ResultCode))

        self._live_callbacks.append(_on_logout)
        self._sdk.EOS_Auth_Logout(self._auth_handle, byref(options), None, _on_logout)
        result = self._wait_call(call)
        if result != b.EOS_RESULT_SUCCESS:
            logger.warning("EOS_Auth_Logout returned %s", result)
        self._epic_account_id = None
        self._auth_local_user_id = None
        self._product_user_id = None


# ---------------------------------------------------------------------------
# Fake backend -- no DLL, no network
# ---------------------------------------------------------------------------


class FakeEosBackend:
    """A structurally-realistic stand-in for EosSession.

    Produces a 3-segment base64url token whose payload carries the same
    claim names the Worker's verifier requires (aud, sub, pfpid, pfsid,
    pfdid, act.eat, iat, exp -- see private-server/src/eos.ts), so code
    that only inspects claims (this module's own _decode_jwt_payload, or
    a future companion Worker-client's logging) exercises the same shape
    it will see for real. It is UNSIGNED ("alg":"none"-shaped, no real
    signature bytes) and will be rejected by the Worker's RS256/JWKS
    check -- it is a stand-in for the EOS SDK, not for Epic's identity
    servers.
    """

    def __init__(
        self,
        *,
        puid: Optional[str] = None,
        product_id: str = "fake-product",
        sandbox_id: str = "fake-sandbox",
        deployment_id: str = "fake-deployment",
        client_id: str = "fake-client",
        ttl_s: int = 3600,
        external_type: str = "epicgames",
    ):
        self._puid = puid or f"fake-puid-{uuid.uuid4().hex[:16]}"
        self._product_id = product_id
        self._sandbox_id = sandbox_id
        self._deployment_id = deployment_id
        self._client_id = client_id
        self._ttl_s = ttl_s
        self._external_type = external_type
        self._expiring_callback: Optional[Callable[[], None]] = None
        self._logged_in = False

    def start(self) -> None:  # symmetry with EosSession; no-op
        pass

    def login(self, method: str, **_kwargs) -> ConnectIdToken:
        if method not in LOGIN_METHODS:
            raise ValueError(f"Unknown login method {method!r}; choose one of {LOGIN_METHODS}")
        now = int(time.time())
        header = {"alg": "none", "typ": "JWT"}
        payload = {
            "iss": "https://api.epicgames.dev/auth/v1",
            "aud": self._client_id,
            "sub": self._puid,
            "pfpid": self._product_id,
            "pfsid": self._sandbox_id,
            "pfdid": self._deployment_id,
            "act": {"eat": self._external_type},
            "iat": now,
            "exp": now + self._ttl_s,
        }

        def seg(obj) -> str:
            return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode("utf-8")).rstrip(b"=").decode(
                "ascii"
            )

        token = f"{seg(header)}.{seg(payload)}.{seg({'fake': True})}"
        self._logged_in = True
        return ConnectIdToken(token=token, expires_at=payload["exp"], puid=self._puid)

    def on_auth_expiring(self, callback: Callable[[], None]) -> None:
        self._expiring_callback = callback

    def fire_expiring(self) -> None:
        """Test helper: simulate the ~1-minute-before-expiry notification."""
        if self._expiring_callback:
            self._expiring_callback()

    def logout(self) -> None:
        self._logged_in = False

    def shutdown(self) -> None:
        self._logged_in = False
