"""Companion configuration and local state (session token, update state).

Private session/staging/backup state lives under
``%LOCALAPPDATA%\\TWARevival\\`` by default (override with
the ``TWA_COMPANION_STATE_DIR`` environment variable -- tests always do this
so they never touch a real machine's LocalAppData). The signed-update floor is
instead tied to the copied client itself so changing the private state override
cannot make an older signed manifest look like an upgrade:

``session.json``
    Holds the companion's own bearer session token (the Worker's
    ``/v1/auth/eos`` response `token`, NOT the EOS Connect ID token, which is
    never persisted). Treat this file like a password: it is a bearer
    secret -- anyone who reads it can act as the logged-in player against
    the Worker API until the session expires or is revoked. It is written
    with owner-only permissions on a best-effort basis (POSIX chmod 600;
    Windows ACLs are not narrowed here, since NTFS permissions are already
    scoped to the owning user account under LocalAppData).

``client/.twa-revival-update-state.json``
    Records the last successfully applied client update (version, when, and
    which files) -- see companion/updater.py.

``state_dir/update_state.json`` is the legacy location. The updater reads it as
a migration floor, but new versions never write it.
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.original_paths import read_original_path

REPO_ROOT = Path(__file__).resolve().parents[1]
_VERSION_FILE = Path(__file__).resolve().parent / "VERSION"
_PATHS_INI = REPO_ROOT / "config" / "paths.ini"
CLIENT_UPDATE_STATE_FILENAME = ".twa-revival-update-state.json"


def _read_client_version() -> str:
    try:
        text = _VERSION_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return "0.0.0"
    return text or "0.0.0"


def _read_original_dir(paths_ini: Path) -> Path | None:
    """Parse config/paths.ini's ``original=<path>`` line.

    The file has no section header (see config/paths.ini), so this is a
    small manual key=value parse rather than configparser.
    """
    try:
        return read_original_path(paths_ini)
    except (OSError, UnicodeError, ValueError):
        return None


def default_state_dir() -> Path:
    override = os.environ.get("TWA_COMPANION_STATE_DIR")
    if override:
        return Path(override)
    local_app_data = os.environ.get("LOCALAPPDATA")
    base = Path(local_app_data) if local_app_data else Path.home() / "AppData" / "Local"
    return base / "TWARevival"


@dataclass
class Config:
    repo_root: Path = field(default_factory=lambda: REPO_ROOT)
    client_dir: Path = field(default_factory=lambda: REPO_ROOT / "client")
    original_dir: Path | None = field(default_factory=lambda: _read_original_dir(_PATHS_INI))
    api_base_url: str = field(
        default_factory=lambda: os.environ.get("TWA_API_BASE_URL", "http://127.0.0.1:8787")
    )  # wrangler dev default, production supplied by environment
    channel: str = "stable"
    client_version: str = field(default_factory=_read_client_version)
    state_dir: Path = field(default_factory=default_state_dir)

    @property
    def session_path(self) -> Path:
        return self.state_dir / "session.json"

    @property
    def update_state_path(self) -> Path:
        return self.client_dir / CLIENT_UPDATE_STATE_FILENAME

    @property
    def legacy_update_state_path(self) -> Path:
        return self.state_dir / "update_state.json"

    @property
    def staging_dir(self) -> Path:
        return self.state_dir / "staging"

    @property
    def backup_dir(self) -> Path:
        return self.state_dir / "backup"

    def ensure_state_dir(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)


def _write_json_private(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_tmp = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    tmp = Path(raw_tmp)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass  # best-effort; e.g. Windows has no POSIX mode bits to narrow


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def load_session(config: Config) -> dict[str, Any] | None:
    """Load the saved session, or None if absent/corrupt.

    The returned dict's ``token`` field is a bearer secret -- never log or
    print it.
    """
    return _load_json(config.session_path)


class SessionChangedError(ValueError):
    """Another login/logout replaced the session being renewed."""


_NO_SESSION_COMPARISON = object()


def save_session(config: Config, session: dict[str, Any], *,
                 expected_session: dict[str, Any] | None | object = _NO_SESSION_COMPARISON) -> None:
    """Persist the companion's Worker session. NEVER pass the EOS token here."""
    from .client_lock import client_operation_lock
    # A separate identity from the copied-client lock held during gameplay.
    with client_operation_lock(config.session_path, timeout_seconds=1.0):
        if expected_session is not _NO_SESSION_COMPARISON and load_session(config) != expected_session:
            raise SessionChangedError("session_changed")
        _write_json_private(config.session_path, session)


def clear_session(config: Config) -> None:
    from .client_lock import client_operation_lock
    with client_operation_lock(config.session_path, timeout_seconds=1.0):
        try:
            config.session_path.unlink()
        except FileNotFoundError:
            pass


def load_update_state(config: Config) -> dict[str, Any] | None:
    return _load_json(config.update_state_path)


def save_update_state(config: Config, state: dict[str, Any]) -> None:
    _write_json_private(config.update_state_path, state)
