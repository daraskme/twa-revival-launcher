"""Player-facing entry to the existing verified login/update/native lifecycle.

Public configuration is deliberately separate from internal-test.env. No value
here can enable fake login, select internal PvP, or replace update trust roots.
"""
from __future__ import annotations

import ipaddress
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .api_client import ApiClient, ApiError, normalize_api_base_url
from .auth import exchange_connect_token
from .config import Config, _read_original_dir, load_session, save_session
from .manifest import ManifestError, semver_tuple
from .player_language import player_state_dir

# The pinned native payload contains game release 0.2.0. Launcher VERSION is
# independent: changing Python/UI code must not advance the game's update floor.
# Successfully installed game updates can raise this baseline via updater state.
BUNDLED_GAME_VERSION = "0.2.0"

# The original public launcher ZIP shipped the private Dev environment. Resolve
# that exact release to the reviewed public Live deployment after a signed code
# update. Keep the installed client credential and all user/config files intact.
PUBLIC_RELEASE_ORIGIN = 'https://staging-api.darask.me'
PUBLIC_RELEASE_IDENTITY = ('f40462cc7fd747babdaf1e1de82ada5f', 'xyza7891FqCrz4CmiPl3NT9yiBBIiq4T')
LEGACY_DEV_ENVIRONMENT = ('p-8brnre23av7jyhu6c9lg3vhwvyfuf8', 'a214a80febce4f589eea8538b51ce0e9')
PUBLIC_LIVE_ENVIRONMENT = ('252a53b783ed49be9458db10758443f1', 'c32881ddd9c74cceb8eb562fa23bdf79')


def effective_player_eos(origin, eos):
    result = dict(eos)
    if (origin == PUBLIC_RELEASE_ORIGIN
            and (eos['productId'], eos['clientId']) == PUBLIC_RELEASE_IDENTITY
            and (eos['sandboxId'], eos['deploymentId']) == LEGACY_DEV_ENVIRONMENT):
        result['sandboxId'], result['deploymentId'] = PUBLIC_LIVE_ENVIRONMENT
    return result


class PlayerReleaseError(RuntimeError):
    pass


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PlayerReleaseError("invalid_release_configuration")
        result[key] = value
    return result


@dataclass(frozen=True)
class PlayerRelease:
    config: Config
    eos: dict[str, str] = field(repr=False)


def load_player_release(root: Path, *, state_dir: Path | None = None) -> PlayerRelease:
    """Read operator-supplied settings; never inherit developer credentials."""
    path = root / "player-release.json"
    try:
        if path.stat().st_size > 16384:
            raise PlayerReleaseError("invalid_release_configuration")
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
        if (not isinstance(value, dict) or set(value) != {"schemaVersion", "apiBaseUrl", "eos"}
                or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1):
            raise PlayerReleaseError("invalid_release_configuration")
        origin = normalize_api_base_url(value["apiBaseUrl"])
        host = urlsplit(origin).hostname
        if not origin.startswith("https://") or host == "localhost":
            raise PlayerReleaseError("invalid_release_origin")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise PlayerReleaseError("invalid_release_origin")
        eos = value["eos"]
        if not isinstance(eos, dict) or set(eos) != {
                "productId", "sandboxId", "deploymentId", "clientId", "clientSecret"}:
            raise PlayerReleaseError("invalid_release_configuration")
        if any(not isinstance(eos[k], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", eos[k])
               for k in ("productId", "sandboxId", "deploymentId", "clientId")):
            raise PlayerReleaseError("invalid_release_configuration")
        secret = eos["clientSecret"]
        if not isinstance(secret, str) or not 1 <= len(secret) <= 512 or any(ord(c) < 33 for c in secret):
            raise PlayerReleaseError("invalid_release_configuration")
        version = (root / "companion" / "VERSION").read_text(encoding="utf-8").strip()
        semver_tuple(version)
    except (OSError, UnicodeError, TypeError, ValueError, ManifestError):
        raise PlayerReleaseError("invalid_release_configuration") from None
    if state_dir is None:
        try:
            state_dir = player_state_dir()
        except OSError:
            raise PlayerReleaseError("local_state_unavailable") from None
    config = Config(
        repo_root=root, client_dir=root / "client",
        original_dir=_read_original_dir(root / "config" / "paths.ini"),
        api_base_url=origin, client_version=BUNDLED_GAME_VERSION, state_dir=state_dir,
    )
    from .updater import _effective_current_version
    # Retain both the client-local and legacy game floors, including for API
    # version headers. Never infer a game update from the launcher version.
    # Configuration is also validated before any game has been installed.
    # The actual update/launch path always checks the full original boundary.
    if config.original_dir is not None and config.client_dir.exists():
        config.client_version = _effective_current_version(config)[0]
    return PlayerRelease(config, effective_player_eos(origin, eos))


def _name(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    from .player_name import validate_display_name
    try:
        return validate_display_name(value).strip()
    except ValueError:
        raise PlayerReleaseError("invalid_display_name") from None


class PlayerService:
    def __init__(self, release: PlayerRelease):
        self.release = release
        self.config = release.config

    def _session(self):
        from .native_launch import NativeLaunchError, session_snapshot
        session = load_session(self.config)
        if not isinstance(session, dict):
            raise PlayerReleaseError("login_required")
        try:
            return session_snapshot(self.config, session)
        except NativeLaunchError:
            raise PlayerReleaseError("login_required") from None

    def _api(self):
        return ApiClient(self.config.api_base_url, self.config.client_version,
                         session_token=self._ensure_session().token)

    def _remembered_binding(self):
        """Expired data is an identity constraint only, never authentication."""
        session = load_session(self.config)
        if (not isinstance(session, dict)
                or session.get("apiBaseUrl") != self.config.api_base_url
                or not isinstance(session.get("token"), str)
                or re.fullmatch(r"[a-f0-9]{64}", session["token"]) is None
                or not isinstance(session.get("puid"), str)
                or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", session["puid"]) is None
                or type(session.get("expiresAt")) is not int or session["expiresAt"] <= 0):
            return None
        return session

    def begin_account_switch(self):
        from .config import _write_json_private
        # Cancelling/failing a deliberate switch must not silently resume the
        # previous account on the next expiry. Manual verified login re-enables it.
        _write_json_private(self.config.state_dir / "persistent-resume-blocked.json",
                            {"schemaVersion": 1, "blocked": True})

    def _resume_blocked(self):
        return (self.config.state_dir / "persistent-resume-blocked.json").exists()

    def _verified_name(self, result, puid):
        user = result.get("user") if isinstance(result, dict) else None
        if (not isinstance(user, dict) or user.get("id") != puid
                or not isinstance(user.get("displayName"), str)):
            raise PlayerReleaseError("invalid_account_response")
        _name(user["displayName"])
        return user["displayName"]

    def _cache_name(self, session, name):
        from .config import _write_json_private
        try:
            _write_json_private(self.config.state_dir / "account-cache.json", {
                "schemaVersion": 1, "apiBaseUrl": session["apiBaseUrl"],
                "sessionHash": hashlib.sha256(session["token"].encode('ascii')).hexdigest(),
                "displayName": name,
            })
        except OSError:
            pass  # A display-cache failure cannot invalidate a verified login.

    def _ensure_session(self):
        try:
            return self._session()
        except PlayerReleaseError:
            previous = self._remembered_binding()
            if (previous is None or previous["expiresAt"] > int(time.time())
                    or self._resume_blocked()):
                raise PlayerReleaseError("login_required") from None
        from .eos.session import EosSession, EosLoginError, EosTimeoutError
        from .config import SessionChangedError
        eos = self.release.eos
        with EosSession(self.config.repo_root / "runtime" / "EOSSDK-Win64-Shipping.dll",
                eos["productId"], eos["sandboxId"], eos["deploymentId"],
                eos["clientId"], eos["clientSecret"], call_timeout_s=30.0) as backend:
            try:
                token = backend.login("persistent", allow_create_connect=False)
            except EosTimeoutError:
                raise
            except EosLoginError:
                # No UI/portal fallback: the user must explicitly sign in.
                raise PlayerReleaseError("login_required") from None
            if token.puid != previous["puid"]:
                raise PlayerReleaseError("login_required")
            api = ApiClient(self.config.api_base_url, self.config.client_version)
            session = exchange_connect_token(api, token.token, previous["puid"],
                display_name=None, eos_expires_at=token.expires_at)
            verified = self._verified_name(api.me(), previous["puid"])
            session.update(apiBaseUrl=self.config.api_base_url, createdAt=int(time.time()))
            if self._resume_blocked():
                raise PlayerReleaseError("login_required")
            try:
                save_session(self.config, session, expected_session=previous)
            except SessionChangedError:
                raise PlayerReleaseError("login_required") from None
        self._cache_name(session, verified)
        return self._session()

    def sign_in(self, name: str | None, *, method: str = "account_portal"):
        if method not in ("account_portal", "persistent"):
            raise PlayerReleaseError("unsupported_login_method")
        name = _name(name)
        previous = load_session(self.config)
        from .eos.session import EosSession
        from .config import SessionChangedError
        eos = self.release.eos
        with EosSession(
            self.config.repo_root / "runtime" / "EOSSDK-Win64-Shipping.dll",
            eos["productId"], eos["sandboxId"], eos["deploymentId"],
            eos["clientId"], eos["clientSecret"], call_timeout_s=180.0,
        ) as backend:
            token = backend.login(method)
            api = ApiClient(self.config.api_base_url, self.config.client_version)
            try:
                session = exchange_connect_token(api, token.token, token.puid,
                    display_name=name, eos_expires_at=token.expires_at)
            except ApiError as error:
                # Epic authentication alone does not create a game account.
                # An existing account may omit its name; a new one may not.
                if error.code == "invalid_display_name" and name is None:
                    raise PlayerReleaseError("player_name_required") from None
                raise
            session["apiBaseUrl"] = self.config.api_base_url
            session["createdAt"] = int(time.time())
            verified = self._verified_name(api.me(), token.puid)
            try:
                save_session(self.config, session, expected_session=previous)
            except SessionChangedError:
                raise PlayerReleaseError("login_required") from None
        self._cache_name(session, verified)
        try:
            (self.config.state_dir / "persistent-resume-blocked.json").unlink(missing_ok=True)
        except OSError:
            pass  # Retain the fail-closed block, but do not undo a verified login.
        return {"displayName": verified}

    def account(self, name: str | None = None):
        snapshot = self._ensure_session()
        api = ApiClient(self.config.api_base_url, self.config.client_version,
                        session_token=snapshot.token)
        result = api.me() if name is None else api.update_display_name(_name(name))
        current = self._session()
        if current != snapshot:
            raise PlayerReleaseError("login_required")
        verified = self._verified_name(result, snapshot.puid)
        # Display-only metadata must never rewrite the session being renewed
        # by the running game's supervisor. Bind it to this exact login.
        self._cache_name({"token": snapshot.token, "apiBaseUrl": snapshot.api_base_url}, verified)
        return {"displayName": verified}

    def saved_account(self):
        """Restore the last verified name only while its saved login is valid.

        This makes no authentication request, extends no expiry, and grants no
        server access. The normal account check still verifies revocation.
        """
        try:
            self._session()
        except PlayerReleaseError:
            return None
        return self.remembered_account()

    def remembered_account(self):
        """Last verified name for display, including expiry; grants no access."""
        try:
            session = self._remembered_binding()
            if session is None:
                return None
            path = self.config.state_dir / "account-cache.json"
            with path.open('rb') as stream:
                raw = stream.read(2049)
            if len(raw) > 2048:
                return None
            value = json.loads(raw)
            if (not isinstance(value, dict)
                    or set(value) != {"schemaVersion", "apiBaseUrl", "sessionHash", "displayName"}
                    or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
                    or value["apiBaseUrl"] != session["apiBaseUrl"]
                    or value["sessionHash"] != hashlib.sha256(session["token"].encode('ascii')).hexdigest()
                    or not isinstance(value["displayName"], str) or not _name(value["displayName"])):
                return None
            return {"displayName": value["displayName"]}
        except (OSError, ValueError, TypeError, PlayerReleaseError):
            return None

    def launcher_update(self):
        from .self_updater import stage
        from .trusted_keys import PUBLIC_DOWNLOAD_ORIGIN
        return stage(self.config.repo_root, PUBLIC_DOWNLOAD_ORIGIN, self.config.channel)

    def update(self):
        launcher = self.launcher_update()
        if launcher['restartRequired']:
            return launcher
        from .startup_gate import check_startup
        result = check_startup(self.config, "release", public_native=True)
        if not result.allow_launch:
            raise PlayerReleaseError(result.code.value)
        return {"version": result.version}

    def launch(self, locale: str):
        if locale not in ("JA", "EN", "RU"):
            raise PlayerReleaseError("invalid_language")
        launcher = self.launcher_update()
        if launcher['restartRequired']:
            return launcher
        # Arena resolves revival-*.localhost itself; unresolvable names end in native 0xf003.
        from tools.loopback_certificate import unresolved_loopback_hosts
        if unresolved_loopback_hosts():
            raise PlayerReleaseError("loopback_dns_missing")
        from .native_launch import run_authenticated_launch
        from .player_session import maintain_player_session
        # Run until the owned Arena exits. The desktop must not apply a five
        # minute subprocess timeout to this lifecycle.
        self._ensure_session()
        with maintain_player_session(self.release) as keeper:
            code = run_authenticated_launch(self.config, self._session(), locale=locale,
                battle_mode="pvp", public_native=True, on_tick=keeper.poll)
        if code != 0:
            raise PlayerReleaseError("game_exited_with_error")
        return {"finished": True}
