"""ctypes bindings for a minimal subset of the EOS SDK.

Covers only what a launcher-style companion needs to turn an Epic Games
account login into a **Connect ID token**: EOS_Initialize, the Platform
interface, the Auth interface (login + ID token), and the Connect
interface (login + create-user + ID token + expiry notification).

--------------------------------------------------------------------------
VERIFICATION STATUS

The declarations below are matched to the supplied EOS SDK 1.19.1.2 C
headers (``SDK/Include``), which use ``#pragma pack(push, 8)``. The binding
intentionally covers only the Auth-to-Connect token flow described above.

The headers define ``EOS_CALL`` as ``__stdcall`` on 32-bit Windows and as
the platform default on Win64. This binding uses ``ctypes.CDLL``: on 64-bit Windows there is
only one calling convention (the Microsoft x64 ABI -- register-based,
caller/callee cleanup rules fixed by the ABI, not by a per-function
keyword), so the cdecl/stdcall distinction that matters on 32-bit x86 is
moot here, and ctypes' CDLL and WinDLL wrappers invoke functions
identically on x64; the only behavioural difference (WinDLL clearing
GetLastError / stdcall name-decoration checks) does not apply to a cdecl
export table like this one. Source: Microsoft's x64 calling convention
docs (learn.microsoft.com/cpp/build/x64-calling-convention) describe a
single fixed convention for x64; the CDLL vs WinDLL distinction in
ctypes is documented at docs.python.org/3/library/ctypes.html. This is
about Windows x64 and ctypes in general, not an EOS-specific claim.

String encoding: all ``const char*`` fields are UTF-8 per Epic's own
struct docs (e.g. ProductId/SandboxId/DeploymentId charset notes,
JsonWebToken as a JWT string). ctypes.c_char_p happily round-trips
UTF-8 bytes; this module handles the str<->bytes conversion at the
Python call boundary so callers of session.py never touch ctypes types.

Threading: EOS callbacks are dispatched while the application pumps
EOS_Platform_Tick. session.py keeps initialization, API calls, Tick, and
shutdown on one caller-owned thread.
"""
from __future__ import annotations

import ctypes
from ctypes import (
    CFUNCTYPE,
    POINTER,
    Structure,
    c_char_p,
    c_double,
    c_int32,
    c_uint32,
    c_uint64,
    c_void_p,
)
from pathlib import Path
from typing import Union

# EOS SDK eos_auth_types.h: desktop persistent authentication must not open UI.
EOS_LF_NO_USER_INTERFACE = 0x00001

# ---------------------------------------------------------------------------
# API versions from EOS SDK 1.19.1.2 headers
# ---------------------------------------------------------------------------


class _ApiVersion:
    INITIALIZE = 5
    PLATFORM_OPTIONS = 15
    AUTH_LOGIN = 3
    AUTH_CREDENTIALS = 4
    AUTH_COPY_ID_TOKEN = 1  # eos_auth_types.h: EOS_AUTH_COPYIDTOKEN_API_LATEST
    AUTH_ID_TOKEN = 1  # eos_auth_types.h: EOS_AUTH_IDTOKEN_API_LATEST
    AUTH_LOGOUT = 1  # eos_auth_types.h: EOS_AUTH_LOGOUT_API_LATEST
    CONNECT_LOGIN = 2
    CONNECT_CREDENTIALS = 1  # eos_connect_types.h: EOS_CONNECT_CREDENTIALS_API_LATEST
    CONNECT_CREATE_USER = 1  # eos_connect_types.h: EOS_CONNECT_CREATEUSER_API_LATEST
    CONNECT_COPY_ID_TOKEN = 1  # eos_connect_types.h: EOS_CONNECT_COPYIDTOKEN_API_LATEST
    CONNECT_ID_TOKEN = 1  # eos_connect_types.h: EOS_CONNECT_IDTOKEN_API_LATEST
    CONNECT_ADD_NOTIFY_AUTH_EXPIRATION = 1  # EOS_CONNECT_ADDNOTIFYAUTHEXPIRATION_API_LATEST


# ---------------------------------------------------------------------------
# Scalar/opaque typedefs
#   EOS_EpicAccountId, EOS_ProductUserId, EOS_ContinuanceToken and the
#   *Interface handles (EOS_HPlatform/EOS_HAuth/EOS_HConnect) are all
#   opaque pointers per every EOS API reference page that mentions them
#   ("An opaque handle to ..."). c_void_p is the correct ctypes mapping
#   for an opaque C pointer type. EOS_EResult and the various EOS_E*
#   enums are documented as plain C enums, which the SDK's public headers
#   are known (from every third-party EOS binding, e.g. the C# interop
#   and the sample above using bare int/EOS_EResult interchangeably) to
#   back with a 4-byte signed int -- so c_int32.
# ---------------------------------------------------------------------------

EOS_HPlatform = c_void_p
EOS_HAuth = c_void_p
EOS_HConnect = c_void_p
EOS_EpicAccountId = c_void_p
EOS_ProductUserId = c_void_p
EOS_ContinuanceToken = c_void_p
EOS_NotificationId = c_uint64

EOS_EResult = c_int32
EOS_Success = 0
EOS_InvalidUser = 3
EOS_InvalidParameters = 10
EOS_NotFound = 18
EOS_TimedOut = 27
EOS_Bool = c_int32
EOS_TRUE = 1
EOS_FALSE = 0

EOS_ELoginCredentialType = c_int32
EOS_LCT_Password = 0  # restricted to Epic internal use; do not use (per docs)
EOS_LCT_ExchangeCode = 1
EOS_LCT_PersistentAuth = 2
EOS_LCT_DeviceCode = 3  # not supported (superseded by ExternalAuth), kept for enum completeness
EOS_LCT_Developer = 4
EOS_LCT_RefreshToken = 5
EOS_LCT_AccountPortal = 6
EOS_LCT_ExternalAuth = 7
EOS_EExternalCredentialType = c_int32
EOS_ECT_EPIC = 0
EOS_ECT_EPIC_ID_TOKEN = 16

EOS_EAuthScopeFlags = c_int32  # bitwise-or flags per docs
EOS_AS_NoFlags = 0x0
EOS_AS_BasicProfile = 0x1
EOS_AS_FriendsList = 0x2
EOS_AS_Presence = 0x4
EOS_AS_FriendsManagement = 0x8  # Epic first-party only
EOS_AS_Email = 0x10  # Epic first-party only
EOS_AS_Country = 0x20

# EOS_ECT_EPIC is the legacy Epic access-token credential. Auth ID tokens
# returned by EOS_Auth_CopyIdToken require EOS_ECT_EPIC_ID_TOKEN.


# ---------------------------------------------------------------------------
# Structs -- EOS_Initialize
# ---------------------------------------------------------------------------


class EOS_InitializeOptions(Structure):
    """https://dev.epicgames.com/docs/api-ref/structs/eos-initialize-options"""

    _fields_ = [
        ("ApiVersion", c_int32),
        ("AllocateMemoryFunction", c_void_p),  # EOS_AllocateMemoryFunc*, NULL = use SDK default
        ("ReallocateMemoryFunction", c_void_p),
        ("ReleaseMemoryFunction", c_void_p),
        ("ProductName", c_char_p),
        ("ProductVersion", c_char_p),
        ("Reserved", c_void_p),
        ("SystemInitializeOptions", c_void_p),
        ("OverrideThreadAffinity", c_void_p),  # EOS_Initialize_ThreadAffinity*, NULL = default
    ]


# ---------------------------------------------------------------------------
# Structs -- Platform
# ---------------------------------------------------------------------------


class EOS_Platform_ClientCredentials(Structure):
    """https://dev.epicgames.com/docs/api-ref/structs/eos-platform-client-credentials

    No ApiVersion field of its own -- it is a plain value type embedded by
    value inside EOS_Platform_Options, not passed by pointer.
    """

    _fields_ = [
        ("ClientId", c_char_p),
        ("ClientSecret", c_char_p),
    ]


class EOS_Platform_Options(Structure):
    """https://dev.epicgames.com/docs/api-ref/structs/eos-platform-options

    Full field list is declared (even though this prototype only sets a
    handful) because C struct layout is offset-based: omitting a
    documented field would silently shift every field after it.
    """

    _fields_ = [
        ("ApiVersion", c_int32),
        ("Reserved", c_void_p),
        ("ProductId", c_char_p),
        ("SandboxId", c_char_p),
        ("ClientCredentials", EOS_Platform_ClientCredentials),
        ("bIsServer", EOS_Bool),
        ("EncryptionKey", c_char_p),  # NULL if unused (Player Data Storage / Title Storage only)
        ("OverrideCountryCode", c_char_p),
        ("OverrideLocaleCode", c_char_p),
        ("DeploymentId", c_char_p),
        ("Flags", c_uint64),
        ("CacheDirectory", c_char_p),
        ("TickBudgetInMilliseconds", c_uint32),
        ("RTCOptions", c_void_p),  # const EOS_Platform_RTCOptions*, NULL disables RTC/voice
        ("IntegratedPlatformOptionsContainerHandle", c_void_p),
        ("SystemSpecificOptions", c_void_p),
        ("TaskNetworkTimeoutSeconds", POINTER(c_double)),  # NULL = SDK default
    ]


# ---------------------------------------------------------------------------
# Structs -- Auth interface
# ---------------------------------------------------------------------------


class EOS_Auth_Credentials(Structure):
    """https://dev.epicgames.com/docs/api-ref/structs/eos-auth-credentials

    Per-credential-type Id/Token conventions (from the same page):
      EOS_LCT_AccountPortal  Id=NULL, Token=NULL
      EOS_LCT_PersistentAuth Id=NULL, Token=NULL on desktop (console: refresh token)
      EOS_LCT_Developer      Id="host:port" of the Dev Auth Tool, Token=credential name
      EOS_LCT_ExchangeCode   Id=NULL, Token=the exchange code
    """

    _fields_ = [
        ("ApiVersion", c_int32),
        ("Id", c_char_p),
        ("Token", c_char_p),
        ("Type", EOS_ELoginCredentialType),
        ("SystemAuthCredentialsOptions", c_void_p),
        ("ExternalType", EOS_EExternalCredentialType),
    ]


class EOS_Auth_LoginOptions(Structure):
    """https://dev.epicgames.com/docs/api-ref/structs/eos-auth-login-options"""

    _fields_ = [
        ("ApiVersion", c_int32),
        ("Credentials", POINTER(EOS_Auth_Credentials)),
        ("ScopeFlags", EOS_EAuthScopeFlags),
        ("LoginFlags", c_uint64),  # e.g. EOS_LF_NO_USER_INTERFACE; 0 = default
    ]


class EOS_Auth_LoginCallbackInfo(Structure):
    """https://dev.epicgames.com/docs/api-ref/structs/eos-auth-login-callback-info

    Use SelectedAccountId (not LocalUserId) to fetch the ID token per
    Epic's own field note: it is the ID meant for game-scoped backend
    calls and can differ from LocalUserId after an account merge.
    """

    _fields_ = [
        ("ResultCode", EOS_EResult),
        ("ClientData", c_void_p),
        ("LocalUserId", EOS_EpicAccountId),
        ("PinGrantInfo", c_void_p),  # const EOS_Auth_PinGrantInfo*, only used for the pin-grant flow (unsupported here)
        ("ContinuanceToken", EOS_ContinuanceToken),
        ("AccountFeatureRestrictedInfo_DEPRECATED", c_void_p),
        ("SelectedAccountId", EOS_EpicAccountId),
    ]


class EOS_Auth_CopyIdTokenOptions(Structure):
    """https://dev.epicgames.com/docs/api-ref/structs/eos-auth-copy-id-token-options"""

    _fields_ = [
        ("ApiVersion", c_int32),
        ("AccountId", EOS_EpicAccountId),
    ]


class EOS_Auth_IdToken(Structure):
    """https://dev.epicgames.com/docs/api-ref/structs/eos-auth-id-token

    Must be released with EOS_Auth_IdToken_Release when done.
    """

    _fields_ = [
        ("ApiVersion", c_int32),
        ("AccountId", EOS_EpicAccountId),
        ("JsonWebToken", c_char_p),
    ]


class EOS_Auth_LogoutOptions(Structure):

    _fields_ = [
        ("ApiVersion", c_int32),
        ("LocalUserId", EOS_EpicAccountId),
    ]


class EOS_Auth_LogoutCallbackInfo(Structure):

    _fields_ = [
        ("ResultCode", EOS_EResult),
        ("ClientData", c_void_p),
        ("LocalUserId", EOS_EpicAccountId),
    ]


# ---------------------------------------------------------------------------
# Structs -- Connect interface
# ---------------------------------------------------------------------------


class EOS_Connect_Credentials(Structure):
    """https://dev.epicgames.com/docs/api-ref/structs/eos-connect-credentials"""

    _fields_ = [
        ("ApiVersion", c_int32),
        ("Token", c_char_p),
        ("Type", EOS_EExternalCredentialType),
    ]


class EOS_Connect_LoginOptions(Structure):
    """https://dev.epicgames.com/docs/api-ref/structs/eos-connect-login-options

    UserLoginInfo (const EOS_Connect_UserLoginInfo*) is required only for
    Amazon/Apple/Google/Nintendo/Oculus/Device-ID credential types (or on
    Nintendo Switch generally); for EOS_ECT_EPIC it must be NULL per the
    docs, so it is typed as a bare c_void_p here rather than a modeled
    struct -- this prototype never sets it.
    """

    _fields_ = [
        ("ApiVersion", c_int32),
        ("Credentials", POINTER(EOS_Connect_Credentials)),
        ("UserLoginInfo", c_void_p),
    ]


class EOS_Connect_LoginCallbackInfo(Structure):
    """https://dev.epicgames.com/docs/api-ref/structs/eos-connect-login-callback-info

    ContinuanceToken is non-NULL exactly when ResultCode is
    EOS_InvalidUser -- that is the "no PUID yet, call
    EOS_Connect_CreateUser" signal.
    """

    _fields_ = [
        ("ResultCode", EOS_EResult),
        ("ClientData", c_void_p),
        ("LocalUserId", EOS_ProductUserId),
        ("ContinuanceToken", EOS_ContinuanceToken),
    ]


class EOS_Connect_CreateUserOptions(Structure):
    """https://dev.epicgames.com/docs/api-ref/structs/eos-connect-create-user-options"""

    _fields_ = [
        ("ApiVersion", c_int32),
        ("ContinuanceToken", EOS_ContinuanceToken),
    ]


class EOS_Connect_CreateUserCallbackInfo(Structure):
    """https://dev.epicgames.com/docs/api-ref/structs/eos-connect-create-user-callback-info"""

    _fields_ = [
        ("ResultCode", EOS_EResult),
        ("ClientData", c_void_p),
        ("LocalUserId", EOS_ProductUserId),
    ]


class EOS_Connect_CopyIdTokenOptions(Structure):
    """https://dev.epicgames.com/docs/api-ref/structs/eos-connect-copy-id-token-options"""

    _fields_ = [
        ("ApiVersion", c_int32),
        ("LocalUserId", EOS_ProductUserId),
    ]


class EOS_Connect_IdToken(Structure):
    """https://dev.epicgames.com/docs/api-ref/structs/eos-connect-id-token

    JsonWebToken here is the **Connect ID token** -- this is the exact
    string the companion must send as
    ``Authorization: Bearer <token>`` to the Worker's
    ``POST /v1/auth/eos`` (private-server/src/eos.ts verifies it against
    Epic's JWKS, checking aud/sub/pfpid/pfsid/pfdid/act.eat/exp). Must be
    released with EOS_Connect_IdToken_Release when done -- copy the
    Python string out first.
    """

    _fields_ = [
        ("ApiVersion", c_int32),
        ("ProductUserId", EOS_ProductUserId),
        ("JsonWebToken", c_char_p),
    ]


class EOS_Connect_AddNotifyAuthExpirationOptions(Structure):
    """https://dev.epicgames.com/docs/api-ref/functions/eos-connect-add-notify-auth-expiration
    lists only "structure containing the API version of the callback to
    use" -- i.e. just ApiVersion, matching every other zero-argument
    *AddNotify*Options struct pattern in the SDK.
    """

    _fields_ = [("ApiVersion", c_int32)]


class EOS_Connect_AuthExpirationCallbackInfo(Structure):

    _fields_ = [
        ("ClientData", c_void_p),
        ("LocalUserId", EOS_ProductUserId),
    ]


# ---------------------------------------------------------------------------
# Callback prototypes
#   All EOS async callbacks share the shape "void (*)(const InfoStruct*)"
#   per every "Callback Function Information" section fetched. CFUNCTYPE
#   is used rather than WINFUNCTYPE -- see the calling-convention note in
#   the module docstring for why that distinction does not matter on x64.
# ---------------------------------------------------------------------------

EOS_Auth_OnLoginCallback = CFUNCTYPE(None, POINTER(EOS_Auth_LoginCallbackInfo))
EOS_Auth_OnLogoutCallback = CFUNCTYPE(None, POINTER(EOS_Auth_LogoutCallbackInfo))
EOS_Connect_OnLoginCallback = CFUNCTYPE(None, POINTER(EOS_Connect_LoginCallbackInfo))
EOS_Connect_OnCreateUserCallback = CFUNCTYPE(None, POINTER(EOS_Connect_CreateUserCallbackInfo))
EOS_Connect_OnAuthExpirationCallback = CFUNCTYPE(None, POINTER(EOS_Connect_AuthExpirationCallbackInfo))


# ---------------------------------------------------------------------------
# Result-code handling
#   This binding resolves arbitrary result codes through
#   EOS_EResult_ToString(code) -- confirmed to exist and behave exactly
#   this way by the real sample program (it calls
#   ``EOS_EResult_ToString(Result)`` and prints the C string) -- and
#   compares the returned name.
# ---------------------------------------------------------------------------

EOS_RESULT_SUCCESS = "EOS_Success"
EOS_RESULT_INVALID_USER = "EOS_InvalidUser"
EOS_RESULT_NOT_FOUND = "EOS_NotFound"


class EosBindingError(RuntimeError):
    """Raised for DLL-loading or ctypes signature problems, as opposed to
    an EOS-level login failure (see session.EosLoginError for that).
    """

    def __init__(self, message: str, *, code: str = "runtime_invalid"):
        super().__init__(message)
        self.code = code


def _is_compatible_sdk_version(value: str) -> bool:
    return value == "1.19.1.2" or value.startswith("1.19.1.2-")


class EosSdk:
    """Loads EOSSDK-Win64-Shipping.dll and exposes typed ctypes function
    objects. Never downloads or locates a DLL on its own -- the path is
    always supplied explicitly by the caller (session.py / the CLI),
    per the HARD RULE against auto-fetching an SDK.
    """

    def __init__(self, dll_path: Union[str, Path]):
        if ctypes.sizeof(c_void_p) != 8:
            raise EosBindingError("EOSSDK-Win64-Shipping.dll requires a 64-bit Python process")
        dll_path = Path(dll_path)
        if not dll_path.is_file():
            raise EosBindingError(f"EOS SDK DLL not found: {dll_path}")
        try:
            # CDLL, not WinDLL -- see module docstring's calling-convention note.
            self.dll = ctypes.CDLL(str(dll_path))
        except OSError as exc:
            raise EosBindingError(
                f"Failed to load {dll_path} (wrong architecture? this process is "
                f"{ctypes.sizeof(ctypes.c_void_p) * 8}-bit): {exc}",
                # ctypes in Python 3.11 rewrites Windows error 126 as a
                # FileNotFoundError without retaining its winerror attribute.
                # The SDK itself was checked above, so this means a dependency.
                code=("runtime_dependency_missing" if (getattr(exc, "winerror", None) == 126
                                                       or isinstance(exc, FileNotFoundError))
                      else "runtime_invalid"),
            ) from exc
        self._bind()
        version = self.EOS_GetVersion()
        actual = version.decode("ascii", "replace") if version else "<null>"
        if not _is_compatible_sdk_version(actual):
            raise EosBindingError(f"EOS SDK version mismatch: expected 1.19.1.2, got {actual}")

    def _fn(self, name: str, restype, argtypes):
        try:
            fn = getattr(self.dll, name)
        except AttributeError as exc:
            raise EosBindingError(
                f"{name} not found in DLL -- wrong EOS SDK version, or this "
                f"binding's function name is stale."
            ) from exc
        fn.restype = restype
        fn.argtypes = argtypes
        return fn

    def _bind(self) -> None:
        self.EOS_GetVersion = self._fn("EOS_GetVersion", c_char_p, [])
        self.EOS_EResult_IsOperationComplete = self._fn(
            "EOS_EResult_IsOperationComplete", EOS_Bool, [EOS_EResult]
        )
        self.EOS_Initialize = self._fn("EOS_Initialize", EOS_EResult, [POINTER(EOS_InitializeOptions)])
        self.EOS_Shutdown = self._fn("EOS_Shutdown", EOS_EResult, [])
        self.EOS_Platform_Create = self._fn("EOS_Platform_Create", EOS_HPlatform, [POINTER(EOS_Platform_Options)])
        self.EOS_Platform_Release = self._fn("EOS_Platform_Release", None, [EOS_HPlatform])
        self.EOS_Platform_Tick = self._fn("EOS_Platform_Tick", None, [EOS_HPlatform])
        self.EOS_Platform_GetAuthInterface = self._fn("EOS_Platform_GetAuthInterface", EOS_HAuth, [EOS_HPlatform])
        self.EOS_Platform_GetConnectInterface = self._fn(
            "EOS_Platform_GetConnectInterface", EOS_HConnect, [EOS_HPlatform]
        )

        self.EOS_Auth_Login = self._fn(
            "EOS_Auth_Login",
            None,
            [EOS_HAuth, POINTER(EOS_Auth_LoginOptions), c_void_p, EOS_Auth_OnLoginCallback],
        )
        self.EOS_Auth_Logout = self._fn(
            "EOS_Auth_Logout",
            None,
            [EOS_HAuth, POINTER(EOS_Auth_LogoutOptions), c_void_p, EOS_Auth_OnLogoutCallback],
        )
        self.EOS_Auth_CopyIdToken = self._fn(
            "EOS_Auth_CopyIdToken",
            EOS_EResult,
            [EOS_HAuth, POINTER(EOS_Auth_CopyIdTokenOptions), POINTER(POINTER(EOS_Auth_IdToken))],
        )
        self.EOS_Auth_IdToken_Release = self._fn("EOS_Auth_IdToken_Release", None, [POINTER(EOS_Auth_IdToken)])

        self.EOS_Connect_Login = self._fn(
            "EOS_Connect_Login",
            None,
            [EOS_HConnect, POINTER(EOS_Connect_LoginOptions), c_void_p, EOS_Connect_OnLoginCallback],
        )
        self.EOS_Connect_CreateUser = self._fn(
            "EOS_Connect_CreateUser",
            None,
            [EOS_HConnect, POINTER(EOS_Connect_CreateUserOptions), c_void_p, EOS_Connect_OnCreateUserCallback],
        )
        self.EOS_Connect_CopyIdToken = self._fn(
            "EOS_Connect_CopyIdToken",
            EOS_EResult,
            [EOS_HConnect, POINTER(EOS_Connect_CopyIdTokenOptions), POINTER(POINTER(EOS_Connect_IdToken))],
        )
        self.EOS_Connect_IdToken_Release = self._fn(
            "EOS_Connect_IdToken_Release", None, [POINTER(EOS_Connect_IdToken)]
        )
        self.EOS_Connect_AddNotifyAuthExpiration = self._fn(
            "EOS_Connect_AddNotifyAuthExpiration",
            EOS_NotificationId,
            [
                EOS_HConnect,
                POINTER(EOS_Connect_AddNotifyAuthExpirationOptions),
                c_void_p,
                EOS_Connect_OnAuthExpirationCallback,
            ],
        )
        self.EOS_Connect_RemoveNotifyAuthExpiration = self._fn(
            "EOS_Connect_RemoveNotifyAuthExpiration", None, [EOS_HConnect, EOS_NotificationId]
        )

        self.EOS_EResult_ToString = self._fn("EOS_EResult_ToString", c_char_p, [EOS_EResult])


def result_to_string(code: int) -> str:
    """Best-effort EOS_EResult -> name, without a loaded DLL.

    Used by tests and by session.py error messages when the code is
    already known to be a simple case we can name ourselves; falls back
    to the numeric value. Real symbolic lookups for arbitrary codes go
    through EosSdk.EOS_EResult_ToString once a DLL is loaded (see
    session.EosSession._describe_result).
    """
    names = {0: EOS_RESULT_SUCCESS}
    return names.get(code, str(code))
