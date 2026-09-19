"""Loopback-only TWAS / CASAG / stack_config stand-in for native Arena."""
from __future__ import annotations

import argparse
import ctypes
import json
import ntpath
import os
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import winreg
from ctypes import wintypes
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "server"))
from companion.client_lock import ClientOperationLockError, client_operation_lock
from tools.install_native_battle_modes import (
    DEFAULT_INSTALL_MANIFEST as NATIVE_MODE_INSTALL_MANIFEST,
    InstallError as NativeModeInstallError,
    classify_selector_installation,
    verify_installed_manifest,
)
from f2p_fake import FRONTEND_USER_SCRIPT
from f2p_fake import LOCAL_STACK_FILE
from f2p_fake import LOGIN
from f2p_fake import LOGIN_NETEASE
from f2p_fake import SERVER_LIST
from f2p_fake import active_native_user_id
from f2p_fake import bind_identity
from f2p_fake import frontend_user_script
from f2p_fake import login_netease_response
from f2p_fake import login_response
from f2p_fake import verify_response
from f2p_fake import STACK
from f2p_fake import STATUS
from f2p_fake import TOKEN
from f2p_fake import VERIFY
from f2p_fake import ca_envelope
from f2p_fake import augment_native_mappings
from f2p_fake import build_catalogue
from f2p_fake import build_defaults
from f2p_fake import build_mappings
from f2p_fake import build_profile
from f2p_fake import build_validation
from f2p_fake import build_versions
from f2p_fake import ca_json
from f2p_fake import load_catalog
from f2p_fake import load_item_ids
from f2p_fake import load_official_mappings
from f2p_fake import load_native_hangar
from f2p_fake import load_offline_progression
from native_consumables import load_native_battle_consumables
from native_equipment import load_native_unit_equipment
from native_unit_abilities import (
    load_native_unit_abilities,
    validate_deployed_unit_ability_wad,
)
from native_user_storage import (
    NativeUserStorage,
    NativeUserStorageError,
    read_bounded_body,
)
from profile_selection import SelectionState
from native_region_ping import NativeRegionPing, local_server_list
from xmpp_stub import start as start_xmpp
from pin_primary_monitor import apply as pin_primary_monitor
from pin_primary_monitor import preferences_path
from pin_primary_monitor import read_pref_text
from pin_primary_monitor import set_pref_string
from pin_primary_monitor import write_pref_text

LOG = ROOT / "server" / "request_log.jsonl"
PORT = 18765
LOOPBACK_HOSTS = ("127.0.0.1", "::1")
CLIENT = ROOT / "client"
CATALOG = ROOT / "catalog" / "catalog.json"
ITEM_IDS = ROOT / "catalog" / "f2p_item_ids.json"
OFFICIAL_MAPPINGS = ROOT / "catalog" / "official_mappings.json"
NATIVE_HANGAR = ROOT / "catalog" / "native_hangar.json"
OFFLINE_PROGRESSION = ROOT / "server" / "offline_progression.json"
BATTLES = ROOT / "battles"


def log_profile_selection(event: dict) -> None:
    print("profile_selection " + json.dumps(event, separators=(",", ":")), flush=True)


_CATALOG = load_catalog(CATALOG)
_ITEM_IDS = load_item_ids(ITEM_IDS)
_NATIVE = load_native_hangar(NATIVE_HANGAR)
_NATIVE_EQUIPMENT = load_native_unit_equipment()
_NATIVE_CONSUMABLES = load_native_battle_consumables()
_NATIVE_UNIT_ABILITIES = load_native_unit_abilities()
_OFFICIAL = augment_native_mappings(
    load_official_mappings(OFFICIAL_MAPPINGS),
    _NATIVE,
    _NATIVE_EQUIPMENT,
    _NATIVE_CONSUMABLES,
    unit_abilities=_NATIVE_UNIT_ABILITIES,
)
_PROGRESSION = load_offline_progression(OFFLINE_PROGRESSION)
_SELECTION_PATH = ROOT / "server" / "offline_selection.json"


def _restored_active_commander_key() -> str:
    """Resolve the legacy selection before ordering the full profile graph.

    Every owned commander keeps its three deployed type-3 rows so unit swaps
    remain available.  The active subtree is published last; resolving a
    persisted selection before construction keeps that order aligned with the
    active property instead of letting another faction overwrite the hangar.
    """
    default = "rom_germanicus"
    try:
        document = json.loads(_SELECTION_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return default
    active = document.get("active_commander") if isinstance(document, dict) else None
    matches = [row.get("key") for row in _NATIVE.get("commanders", [])
               if isinstance(row, dict) and row.get("build_state", "live") == "live"
               and row.get("item_id") == active]
    return matches[0] if len(matches) == 1 else default


PROFILE = build_profile(
    _CATALOG, _OFFICIAL, _NATIVE,
    active_key=_restored_active_commander_key(), progression=_PROGRESSION,
)
PROFILE_STATE = SelectionState(
    PROFILE, _OFFICIAL, _SELECTION_PATH, trace=log_profile_selection
)
VERSIONS = build_versions()
MAPPINGS = build_mappings(_CATALOG, _ITEM_IDS, _OFFICIAL)
CATALOGUE = build_catalogue(_CATALOG, _ITEM_IDS, _OFFICIAL, _NATIVE)
# Use the restored selection and its existing owned squad. An arbitrary first
# purchase option could grant a unit during native default-profile processing.
DEFAULTS = build_defaults(CATALOGUE, PROFILE_STATE.respond()[0], _NATIVE)
# Validation describes canonical item relationships, not mutable quantities.
# Pre-authorize only the verified loadout candidates so a native /event delta
# can replace type-9/type-11 records before its next full profile snapshot.
VALIDATION = build_validation(
    PROFILE_STATE.respond()[0],
    native=_NATIVE,
    equipment=_NATIVE_EQUIPMENT,
    consumables=_NATIVE_CONSUMABLES,
    unit_abilities=_NATIVE_UNIT_ABILITIES,
)

# Resolves the ``+auth <token>`` the client presents as
# ``request.netease_token``.  ``None`` keeps the historical lab behaviour:
# every token is accepted and every body describes ``f2p_fake.PLAYER``.
IDENTITY_RESOLVER = None


def bind_identity_resolver(resolver) -> None:
    """Serve one resolved player and reject sessions the resolver does not know."""
    global IDENTITY_RESOLVER
    previous = active_native_user_id()
    IDENTITY_RESOLVER = resolver
    bind_identity(None if resolver is None else resolver.identity)
    if active_native_user_id() != previous:
        rebind_native_identity()


def rebind_native_identity() -> None:
    """Rebuild the import-time profile views for the currently bound identity.

    ``--pve-battle-probe`` replaces these from the economy service on every
    request, but the plain stack and the pre-economy bootstrap read them
    directly, so they must not keep a stale ``user_id``.
    """
    global PROFILE, PROFILE_STATE, DEFAULTS, VALIDATION
    PROFILE = build_profile(
        _CATALOG, _OFFICIAL, _NATIVE,
        active_key=_restored_active_commander_key(), progression=_PROGRESSION,
    )
    PROFILE_STATE = SelectionState(
        PROFILE, _OFFICIAL, _SELECTION_PATH,
        trace=log_profile_selection,
    )
    DEFAULTS = build_defaults(CATALOGUE, PROFILE_STATE.respond()[0], _NATIVE)
    VALIDATION = build_validation(
        PROFILE_STATE.respond()[0],
        native=_NATIVE,
        equipment=_NATIVE_EQUIPMENT,
        consumables=_NATIVE_CONSUMABLES,
        unit_abilities=_NATIVE_UNIT_ABILITIES,
    )


def resolve_presented_token(raw: bytes, content_type: str = "application/json"):
    """Resolve ``netease_token`` from a ``/netease/login_netease`` body.

    Returns the resolved identity, or ``None`` when no resolver is bound.
    Raises ``ValueError`` for a session the resolver does not know: this
    server never invents an account for an unknown ``+auth`` token.
    """
    resolver = IDENTITY_RESOLVER
    if resolver is None:
        return None
    from native_custom_lobby import decode_native_request, NativeLobbyError
    try:
        request, _headers, _form = decode_native_request(raw, content_type)
    except NativeLobbyError as error:
        raise ValueError(error.code) from None
    token = request.get("netease_token")
    if token is None:
        raise ValueError("native_auth_token_missing")
    try:
        return resolver.resolve_session_token(token)
    except Exception:
        if token == "revival-token":
            raise ValueError("native_auth_legacy_token") from None
        raise ValueError("unknown_session") from None


class Handler(BaseHTTPRequestHandler):
    # ProbeHandler installs a per-run store.  The plain stack remains a
    # compatibility server when no run-scoped store is configured.
    native_user_storage: NativeUserStorage | None = None

    def log_message(self, fmt: str, *args) -> None:
        safe_path = urlparse(self.path).path
        line = f"{self.command} {safe_path} {fmt % args}\n"
        print(line, end="")

    def _send(self, code: int, body: bytes, content_type: str = "application/json",
              headers: dict[str, str] | None = None) -> None:
        self._last_write_succeeded = False
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        content_length = (headers or {}).get("Content-Length", str(len(body)))
        self.send_header("Content-Length", content_length)
        for key, value in (headers or {}).items():
            if key.lower() != "content-length":
                self.send_header(key, value)
        safe_path = urlparse(self.path).path
        print(
            f"{self.command} {safe_path} host={self.headers.get('Host')} -> {code}",
            flush=True,
        )
        self.end_headers()
        written = (len(body) if getattr(self, "_head_only", False)
                   else self.wfile.write(body))
        self._last_write_succeeded = written == len(body)
        try:
            LOG.parent.mkdir(parents=True, exist_ok=True)
            with LOG.open("a", encoding="utf-8") as f:
                f.write(
                    json.dumps(
                        {
                            "method": self.command,
                            "path": safe_path,
                            "host": self.headers.get("Host"),
                            "code": code,
                        }
                    )
                    + "\n"
                )
        except OSError:
            pass

    def do_OPTIONS(self) -> None:
        self._head_only = False
        self._body = b""
        self._send(405, b'{"error":"method_not_allowed"}')

    def do_GET(self) -> None:
        self._head_only = False
        self._body = b""
        self._handle()

    def do_HEAD(self) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        storage = self.native_user_storage
        if storage is None or not storage.is_blob_path(path):
            # Do not route HEAD through profile/queue handlers: several POST
            # endpoints have side effects or acknowledgements.
            self._head_only = False
            self.send_error(501, "Unsupported method ('HEAD')")
            return
        self._head_only = True
        self._body = b""
        self._handle()

    def do_POST(self) -> None:
        self._head_only = False
        storage = self.native_user_storage
        path = urlparse(self.path).path.rstrip("/") or "/"
        if storage is not None and storage.is_blob_path(path):
            self.close_connection = True
            try:
                response = storage.handle(self.command, path, b"")
            except NativeUserStorageError as error:
                self._send(error.status, json.dumps({"error": error.code}).encode())
                return
            self._send(response.status, response.body, response.content_type,
                       response.headers)
            return
        length = int(self.headers.get("Content-Length") or 0)
        self._body = self.rfile.read(length) if length else b""
        self._handle()

    def do_PUT(self) -> None:
        self._head_only = False
        storage = self.native_user_storage
        path = urlparse(self.path).path.rstrip("/") or "/"
        if storage is not None and storage.is_blob_path(path):
            try:
                self._body = read_bounded_body(
                    self.headers, self.rfile, timeout_socket=self.connection)
            except NativeUserStorageError as error:
                self.close_connection = True
                self._send(error.status, json.dumps({"error": error.code}).encode())
                return
        else:
            length = int(self.headers.get("Content-Length") or 0)
            self._body = self.rfile.read(length) if length else b""
        self._handle()

    def _handle(self) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        low = path.lower()
        storage = self.native_user_storage
        if storage is not None and storage.is_blob_path(path):
            try:
                response = storage.handle(self.command, path, getattr(self, "_body", b""))
            except NativeUserStorageError as error:
                self._send(error.status, json.dumps({"error": error.code}).encode())
                return
            if response is not None:
                self._send(response.status, response.body, response.content_type,
                           response.headers)
                return
            self._send(404, b'{"error":"object_not_found"}')
            return
        if (
            low.endswith("stack_config")
            or low.endswith("stack_config.json")
            or low == "/public/stack_config"
            or low.endswith("/public/revival.json")
        ):
            self._send(200, ca_json(STACK).encode("utf-8"))
            return
        if "gameid_registry" in low:
            self._send(200, ca_json(STACK).encode("utf-8"))
            return
        if "get_upload_link" in low:
            self._send(200, b'{"ok":true,"url":"http://127.0.0.1:18765/upload"}')
            return
        if "twa-game-data" in low or low.endswith("versions.json"):
            self._send(200, game_data_bytes(low))
            return
        if "user-storage" in low or low.endswith("/blob") or low.endswith("/upload"):
            self._send(200, b'{"ok":true}')
            return
        if low.endswith("/status.json") or low.endswith("/status") or low.endswith("/check"):
            self._send(200, json.dumps(STATUS).encode("utf-8"))
            return
        if "news" in low:
            self._send(
                200,
                b'{"news":[{"id":"maint-1","heading":"maintenance_critical","text":"maintenance"}],'
                b'"dont_show_news_ids":[],"heading":"maintenance_critical"}',
            )
            return
        if "server_list" in low:
            self._send(200, json.dumps(SERVER_LIST).encode("utf-8"))
            return
        if "login_netease" in low:
            # The only request that carries the client's ``+auth`` secret.
            try:
                identity = resolve_presented_token(
                    getattr(self, "_body", b""), self.headers.get("Content-Type", ""))
            except ValueError as error:
                trace = getattr(self, "_trace", None)
                if callable(trace):
                    trace({"event": "native_auth_rejected", "reason": str(error)})
                self._send(403, b'{"error":"unknown_session"}')
                return
            body = (LOGIN_NETEASE if identity is None
                    else login_netease_response(identity.native_user_id))
            self._send(200, json.dumps(body).encode("utf-8"))
            return
        if any(name in low for name in ("verify", "refresh")):
            self._send(200, json.dumps(
                VERIFY if IDENTITY_RESOLVER is None
                else verify_response(active_native_user_id())).encode("utf-8"))
            return
        if any(name in low for name in ("login", "/auth", "netease", "steam")):
            self._send(200, json.dumps(
                LOGIN if IDENTITY_RESOLVER is None
                else login_response(active_native_user_id())).encode("utf-8"))
            return
        if "send_profile_details" in low or "metrics" in low:
            self._send(200, json.dumps(ca_envelope({})).encode("utf-8"))
            return
        if low == "/v3/missions":
            mission_responder = getattr(
                PROFILE_STATE, "respond_daily_missions", None,
            )
            if callable(mission_responder):
                self._send(
                    200,
                    json.dumps(ca_envelope(mission_responder())).encode("utf-8"),
                )
            else:
                self._send(503, b'{"error":"mission_service_unavailable"}')
            return
        if "profile" in low or "tutorial-progress" in low:
            raw = getattr(self, "_body", b"")
            canonical = low.rstrip("/") or "/"
            tutorial_responder = getattr(
                PROFILE_STATE, "respond_tutorial_progress", None,
            )
            profile_responder = getattr(
                PROFILE_STATE, "respond_profile_message", None,
            )
            if (self.command == "POST" and canonical == "/tutorial-progress"
                    and callable(tutorial_responder)):
                profile, profile_status = tutorial_responder(raw)
            elif (self.command == "POST" and canonical == "/profile"
                  and callable(profile_responder)):
                profile, profile_status = profile_responder(
                    raw, accept_current_selection_noop=True,
                )
            else:
                profile, profile_status = PROFILE_STATE.respond(
                    raw,
                    accept_selection=(
                        self.command == "POST" and canonical == "/profile"
                    ),
                )
            self._send(200, json.dumps(ca_envelope(profile)).encode("utf-8"))
            if (self.command == "POST" and canonical == "/profile"
                    and getattr(self, "_last_write_succeeded", False) is True):
                graph_confirmer = getattr(
                    PROFILE_STATE, "confirm_profile_graph_http", None,
                )
                if callable(graph_confirmer):
                    # Bind confirmation to the exact in-memory response, not
                    # merely a saved watermark shared by concurrent replies.
                    graph_confirmer(profile)
            if (self.command == "POST" and canonical == "/profile"
                    and profile_status == "external_refresh_resynced"):
                confirmer = getattr(
                    PROFILE_STATE,
                    "confirm_external_profile_refresh_http",
                    None,
                )
                if (callable(confirmer)
                        and getattr(
                            self, "_last_write_succeeded", False,
                        ) is True):
                    # ``_send`` has returned after writing the complete body.
                    # This still does not prove that Arena parsed/applied it.
                    self._external_profile_refresh_http_confirmed = bool(
                        confirmer(profile.get("saved"))
                    )
            if (self.command == "POST" and canonical == "/profile"
                    and profile_status == "specialization_refresh_resynced"):
                confirmer = getattr(
                    PROFILE_STATE,
                    "confirm_specialization_profile_refresh_http",
                    None,
                )
                if (callable(confirmer)
                        and getattr(self, "_last_write_succeeded", False) is True):
                    self._specialization_profile_refresh_http_confirmed = bool(
                        confirmer(profile)
                    )
            return
        if low.endswith("/public") or "/public/" in low:
            self._send(200, json.dumps(ca_envelope({})).encode("utf-8"))
            return
        if "custom" in low or "lobby" in low:
            self._send(200, b'{"ok":true,"lobby_id":"solo-1","players":[]}')
            return
        if (low in {"/", "/hangar", "/api/catalog", "/api/launch-hangar",
                    "/api/launch-battle"}
                or low.startswith("/hangar/")):
            # The browser/Godot frontend is retired. In particular, never
            # expose a network route that can stop or launch Arena.exe.
            self._send(404, b'{"error":"native_frontend_only"}')
            return
        self._send(200, b'{"ok":true}')


def game_data_bytes(path: str) -> bytes:
    name = path.rsplit("/", 1)[-1]
    if "versions" in name:
        return json.dumps(VERSIONS).encode("utf-8")
    if "catalogue" in name:
        return json.dumps(CATALOGUE).encode("utf-8")
    if "defaults" in name:
        return json.dumps(DEFAULTS).encode("utf-8")
    if "mappings" in name:
        return json.dumps(MAPPINGS).encode("utf-8")
    if name == VERSIONS["validation"]:
        # BD8540 expects this raw object, without a CA response envelope.
        return json.dumps(VALIDATION).encode("utf-8")
    if name == VERSIONS["rules_engine_stable"]:
        # BD8AD0/C2A970 expects a raw array, not a CA response envelope. Empty
        # rules initialize readiness without inventing achievement rewards.
        return b"[]"
    return b"{}"


def scripts_dir() -> Path:
    path = Path(os.environ["APPDATA"]) / "The Creative Assembly" / "Arena" / "scripts"
    path.mkdir(parents=True, exist_ok=True)
    return path


def arena_exe() -> Path:
    return CLIENT / "Arena.exe"


class LaunchBoundaryError(RuntimeError):
    """The copied client cannot be proven disjoint from the owned original."""


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError as exc:
        raise LaunchBoundaryError(f"cannot inspect launch path {path}: {exc}") from exc
    return path.is_symlink() or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _require_real_directory_ancestors(path: Path, label: str) -> Path:
    """Reject a missing/file/reparse component anywhere in an existing path."""
    try:
        raw = Path(os.path.abspath(path))
    except (OSError, TypeError, ValueError) as exc:
        raise LaunchBoundaryError(f"cannot identify {label}: {exc}") from exc
    if not os.path.lexists(raw):
        raise LaunchBoundaryError(f"{label} must be an existing real directory: {raw}")

    current = raw
    while True:
        try:
            is_directory = current.is_dir()
        except OSError as exc:
            raise LaunchBoundaryError(f"cannot inspect {label} ancestor {current}: {exc}") from exc
        if not is_directory or _is_reparse_point(current):
            raise LaunchBoundaryError(
                f"{label} must contain only real directories, not files or reparse points: "
                f"{current}"
            )
        if current.parent == current:
            break
        current = current.parent
    return raw


def _configured_original_directory() -> Path:
    paths_ini = ROOT / "config" / "paths.ini"
    try:
        lines = paths_ini.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise LaunchBoundaryError(
            f"cannot verify the owned original because {paths_ini} is unreadable: {exc}"
        ) from exc

    values: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        key, separator, value = stripped.partition("=")
        if separator and key.strip().casefold() == "original":
            values.append(value.strip())
    if len(values) != 1 or not values[0]:
        raise LaunchBoundaryError(
            "config/paths.ini must contain exactly one non-empty original directory"
        )
    original = Path(values[0])
    if not original.is_absolute():
        raise LaunchBoundaryError("configured original directory must be an absolute path")
    return original


def _same_or_beneath(candidate: Path, root: Path) -> bool:
    candidate_text = ntpath.normcase(ntpath.abspath(os.fspath(candidate)))
    root_text = ntpath.normcase(ntpath.abspath(os.fspath(root)))
    try:
        return ntpath.commonpath((candidate_text, root_text)) == root_text
    except ValueError:
        return False


def _require_safe_launch_boundaries() -> None:
    """Fail closed before any copied-client mutation or process cleanup."""
    raw_client = _require_real_directory_ancestors(CLIENT, "copied client directory")
    raw_original = _require_real_directory_ancestors(
        _configured_original_directory(), "owned original directory"
    )
    try:
        resolved_client = raw_client.resolve(strict=True)
        resolved_original = raw_original.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise LaunchBoundaryError(f"cannot resolve client/original launch boundary: {exc}") from exc

    raw_overlap = (
        _same_or_beneath(raw_client, raw_original)
        or _same_or_beneath(raw_original, raw_client)
    )
    resolved_overlap = (
        _same_or_beneath(resolved_client, resolved_original)
        or _same_or_beneath(resolved_original, resolved_client)
    )
    if raw_overlap or resolved_overlap:
        raise LaunchBoundaryError(
            "copied client and owned original directories must be disjoint: "
            f"client={raw_client}, original={raw_original}"
        )


_CLIENT_LAUNCH_LEAVES = (
    "Arena.exe",
    "stack_config.json",
    "game.dll",
    "game.dll.bak-hangar",
    "npl-base.dll",
    "npl-sdk.dll",
    "npl-base.original.dll",
    "npl-sdk.original.dll",
)
_CLIENT_LAUNCH_LEAF_NAMES = {name.casefold() for name in _CLIENT_LAUNCH_LEAVES}
_CLIENT_WRITABLE_LEAF_NAMES = {
    name.casefold() for name in (
        "stack_config.json",
        "game.dll",
        "game.dll.bak-hangar",
        "npl-base.dll",
        "npl-sdk.dll",
    )
}


def _require_safe_client_leaf(
    path: Path, label: str, *, check_boundary: bool = True,
) -> Path:
    """Allow only an unshared regular top-level client file (or no leaf)."""
    if check_boundary:
        _require_safe_launch_boundaries()
    root = Path(os.path.abspath(CLIENT))
    target = Path(os.path.abspath(path))
    if (
        ntpath.normcase(os.fspath(target.parent))
        != ntpath.normcase(os.fspath(root))
        or target.name.casefold() not in _CLIENT_LAUNCH_LEAF_NAMES
    ):
        raise LaunchBoundaryError(
            f"{label} is outside the copied-client mutation allow-list: {target}"
        )
    if not os.path.lexists(target):
        return target
    try:
        metadata = target.lstat()
        is_file = target.is_file()
    except OSError as exc:
        raise LaunchBoundaryError(f"cannot inspect {label} {target}: {exc}") from exc
    if not is_file or _is_reparse_point(target):
        raise LaunchBoundaryError(
            f"{label} must be a regular file or a new leaf, not a directory/reparse point: "
            f"{target}"
        )
    if metadata.st_nlink != 1:
        raise LaunchBoundaryError(
            f"{label} must not be a hard link shared with another path: {target}"
        )
    return target


def _require_safe_client_log_directory(*, check_boundary: bool = True) -> Path:
    if check_boundary:
        _require_safe_launch_boundaries()
    path = Path(os.path.abspath(CLIENT / "log"))
    root = Path(os.path.abspath(CLIENT))
    if ntpath.normcase(os.fspath(path.parent)) != ntpath.normcase(os.fspath(root)):
        raise LaunchBoundaryError(f"client log directory escaped the copied client: {path}")
    if not os.path.lexists(path):
        return path
    try:
        is_directory = path.is_dir()
    except OSError as exc:
        raise LaunchBoundaryError(f"cannot inspect client log directory {path}: {exc}") from exc
    if not is_directory or _is_reparse_point(path):
        raise LaunchBoundaryError(
            f"client log must be a real directory, not a file/reparse point: {path}"
        )
    return path


def _require_safe_client_launch_targets() -> None:
    _require_safe_launch_boundaries()
    for name in _CLIENT_LAUNCH_LEAVES:
        _require_safe_client_leaf(
            CLIENT / name, f"launch-critical client leaf {name}", check_boundary=False,
        )
    _require_safe_client_log_directory(check_boundary=False)


def _atomic_replace_client_bytes(target: Path, data: bytes, label: str) -> None:
    """Publish bytes without ever opening an existing client leaf for writing."""
    target = _require_safe_client_leaf(target, label)
    if target.name.casefold() not in _CLIENT_WRITABLE_LEAF_NAMES:
        raise LaunchBoundaryError(f"{label} is not an authorized writable client leaf: {target}")
    if target.is_file() and target.read_bytes() == data:
        return
    descriptor, raw_temporary = tempfile.mkstemp(
        prefix=f".{target.name}.launch-", suffix=".tmp", dir=target.parent,
    )
    temporary = Path(raw_temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        # Recheck the client/original directory boundary and deterministic leaf
        # after staging, immediately before the only namespace replacement.
        target = _require_safe_client_leaf(target, label)
        os.replace(temporary, target)
        _require_safe_client_leaf(target, label)
    finally:
        temporary.unlink(missing_ok=True)


TH32CS_SNAPPROCESS = 0x00000002
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
WAIT_OBJECT_0 = 0
ERROR_NO_MORE_FILES = 18
ERROR_INVALID_PARAMETER = 87
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


@dataclass(frozen=True)
class _ArenaProcessIdentity:
    pid: int
    start_time_ticks: int
    image_path: str


_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
_kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
_kernel32.Process32FirstW.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W),
]
_kernel32.Process32FirstW.restype = wintypes.BOOL
_kernel32.Process32NextW.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W),
]
_kernel32.Process32NextW.restype = wintypes.BOOL
_kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_kernel32.OpenProcess.restype = wintypes.HANDLE
_kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
]
_kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
_kernel32.GetProcessTimes.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME),
]
_kernel32.GetProcessTimes.restype = wintypes.BOOL
_kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
_kernel32.TerminateProcess.restype = wintypes.BOOL
_kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
_kernel32.WaitForSingleObject.restype = wintypes.DWORD
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.CloseHandle.restype = wintypes.BOOL


def _normal_process_path(path: str | Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _same_process_identity(
    left: _ArenaProcessIdentity, right: _ArenaProcessIdentity,
) -> bool:
    return (
        left.pid == right.pid
        and left.start_time_ticks == right.start_time_ticks
        and _normal_process_path(left.image_path)
        == _normal_process_path(right.image_path)
    )


def _identity_from_handle(
    handle: int, pid: int,
) -> _ArenaProcessIdentity | None:
    size = wintypes.DWORD(32768)
    image = ctypes.create_unicode_buffer(size.value)
    creation = wintypes.FILETIME()
    exit_time = wintypes.FILETIME()
    kernel = wintypes.FILETIME()
    user = wintypes.FILETIME()
    if (not _kernel32.QueryFullProcessImageNameW(
            handle, 0, image, ctypes.byref(size))
            or not _kernel32.GetProcessTimes(
                handle, ctypes.byref(creation), ctypes.byref(exit_time),
                ctypes.byref(kernel), ctypes.byref(user),
            )):
        if _kernel32.WaitForSingleObject(handle, 0) == WAIT_OBJECT_0:
            return None
        raise OSError(ctypes.get_last_error(), "cannot identify Arena process")
    ticks = (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
    return _ArenaProcessIdentity(pid=pid, start_time_ticks=ticks, image_path=image.value)


def _require_process_snapshot_exhausted(error: int) -> None:
    """Accept only the documented end-of-enumeration result."""
    if error != ERROR_NO_MORE_FILES:
        raise OSError(error, "Arena process enumeration was incomplete")


def _snapshot_arena_processes() -> list[_ArenaProcessIdentity]:
    snapshot = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        raise OSError(ctypes.get_last_error(), "cannot enumerate Arena processes")
    identities: list[_ArenaProcessIdentity] = []
    try:
        row = _PROCESSENTRY32W()
        row.dwSize = ctypes.sizeof(row)
        ctypes.set_last_error(0)
        ok = _kernel32.Process32FirstW(snapshot, ctypes.byref(row))
        if not ok:
            _require_process_snapshot_exhausted(ctypes.get_last_error())
            return identities
        while ok:
            if row.szExeFile.casefold() == "arena.exe":
                pid = int(row.th32ProcessID)
                handle = _kernel32.OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid,
                )
                if not handle:
                    if ctypes.get_last_error() != ERROR_INVALID_PARAMETER:
                        raise OSError(
                            ctypes.get_last_error(),
                            f"cannot inspect Arena process {pid}",
                        )
                else:
                    try:
                        identity = _identity_from_handle(handle, pid)
                        if identity is not None:
                            identities.append(identity)
                    finally:
                        _kernel32.CloseHandle(handle)
            ctypes.set_last_error(0)
            ok = _kernel32.Process32NextW(snapshot, ctypes.byref(row))
        _require_process_snapshot_exhausted(ctypes.get_last_error())
    finally:
        _kernel32.CloseHandle(snapshot)
    return identities


def _terminate_same_process(expected: _ArenaProcessIdentity) -> bool:
    """Terminate only the exact PID/start-time/image identity first observed."""
    handle = _kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE,
        False,
        expected.pid,
    )
    if not handle:
        return ctypes.get_last_error() == ERROR_INVALID_PARAMETER
    try:
        actual = _identity_from_handle(handle, expected.pid)
        if actual is None:
            return True
        if not _same_process_identity(expected, actual):
            return False
        if not _kernel32.TerminateProcess(handle, 1):
            return _kernel32.WaitForSingleObject(handle, 0) == WAIT_OBJECT_0
        return _kernel32.WaitForSingleObject(handle, 5000) == WAIT_OBJECT_0
    finally:
        _kernel32.CloseHandle(handle)


def stop_revival_arena(*, snapshotter=None, terminator=None) -> None:
    """Quit only a verified leftover Revival Arena before replacing DLLs.

    A PID alone is never termination authority. The initial PID, creation time,
    and exact executable path are re-read through one live process handle just
    before ``TerminateProcess``. PID reuse or a newly launched copy causes this
    function to fail closed, leaving that process untouched.
    """
    take_snapshot = snapshotter or _snapshot_arena_processes
    terminate = terminator or _terminate_same_process
    verified_executable = _require_safe_client_leaf(
        arena_exe(), "Arena executable before cleanup",
    )
    target = _normal_process_path(verified_executable.resolve())
    candidates = [
        identity for identity in take_snapshot()
        if _normal_process_path(identity.image_path) == target
    ]
    for identity in candidates:
        if terminate(identity):
            continue
        # A process that exited between snapshot and open needs no cleanup. A
        # still-live exact identity is unsafe to patch and must abort launch.
        if any(_same_process_identity(identity, live) for live in take_snapshot()):
            raise RuntimeError(
                f"could not stop verified Revival Arena process {identity.pid}"
            )
    remaining = [
        identity for identity in take_snapshot()
        if _normal_process_path(identity.image_path) == target
    ]
    if remaining:
        # Do not kill a new process generation that appeared after the initial
        # snapshot. Abort instead of applying patches beneath a running Arena.
        raise RuntimeError("Revival Arena changed or restarted during cleanup")


def _replace_dll(src: Path, dest: Path) -> None:
    data = src.read_bytes()
    _atomic_replace_client_bytes(dest, data, f"client DLL {dest.name}")


def use_original_npl() -> bool:
    for name in ("npl-base.dll", "npl-sdk.dll"):
        original = CLIENT / name.replace(".dll", ".original.dll")
        if not original.is_file():
            return False
        try:
            _replace_dll(original, CLIENT / name)
        except OSError:
            return False
    return True


def build_npl_stub() -> bool:
    bat = ROOT / "npl_stub" / "build.bat"
    if not bat.is_file():
        return False
    result = subprocess.run(["cmd", "/c", str(bat)], cwd=str(bat.parent))
    return result.returncode == 0 and all(
        (ROOT / "npl_stub" / name).is_file()
        for name in ("npl-base.dll", "npl-sdk.dll")
    )


def use_stub_npl() -> bool:
    stub_dir = ROOT / "npl_stub"
    if not (stub_dir / "npl-base.dll").is_file() or not (stub_dir / "npl-sdk.dll").is_file():
        if not build_npl_stub():
            return False
    for name in ("npl-base.dll", "npl-sdk.dll"):
        src = stub_dir / name
        dest = CLIENT / name
        try:
            _replace_dll(src, dest)
        except OSError:
            return False
    log_directory = _require_safe_client_log_directory()
    log_directory.mkdir(exist_ok=True)
    _require_safe_client_log_directory()
    return True


def set_online_platform(name: str) -> None:
    path = preferences_path()
    if not path.is_file():
        return
    write_pref_text(path, set_pref_string(read_pref_text(path), "ONLINE_PLATFORM", name))


def write_stack_config() -> None:
    _atomic_replace_client_bytes(
        CLIENT / "stack_config.json",
        ca_json(LOCAL_STACK_FILE).encode("utf-8"),
        "client stack configuration",
    )


def ensure_machine_fingerprint() -> str:
    """Skip GetAdaptersInfo shutdown by seeding the registry fingerprint."""
    generated = f"{uuid.getnode():012x}"
    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\The Creative Assembly\Arena")
    try:
        try:
            existing, _typ = winreg.QueryValueEx(key, "machine_fingerprint")
            if existing:
                return str(existing)
        except FileNotFoundError:
            pass
        winreg.SetValueEx(key, "machine_fingerprint", 0, winreg.REG_SZ, generated)
        return generated
    finally:
        winreg.CloseKey(key)


def apply_hangar_patches() -> bool:
    """Rebuild client\\game.dll from the hangar backup + Revival patches."""
    script = ROOT / "tools" / "_preview" / "patch_hangar.py"
    if not script.is_file():
        return False
    _require_safe_client_launch_targets()
    result = subprocess.run([sys.executable, str(script)], cwd=str(script.parent))
    _require_safe_client_launch_targets()
    if result.returncode != 0:
        print("hangar patch failed", result.returncode, flush=True)
        return False
    return True


def launch_mode(mode: str, battle_xml: Path | None = None) -> dict:
    if mode not in {"frontend", "battle"} or (
            mode == "battle" and battle_xml is None):
        return {"ok": False, "error": "bad mode"}
    try:
        # Validate before deriving the lock identity, then repeat while holding
        # the lock so a path change can never turn an updater-safe client into
        # an original-tree target before the first write/patch/process stop.
        _require_safe_client_launch_targets()
        # This is the currently used local launcher and it mutates game.dll,
        # NPL, scripts and client settings before process creation. Hold the
        # same canonical-client lock as Companion's updater across that whole
        # sequence, not merely around the final Popen/WMI call.
        with client_operation_lock(CLIENT):
            _require_safe_client_launch_targets()
            selector_installation = classify_selector_installation(repo_root=ROOT)
            return _launch_mode_locked(
                mode, battle_xml, selector_installation=selector_installation,
            )
    except LaunchBoundaryError as exc:
        return {
            "ok": False,
            "error": f"unsafe copied-client boundary: {exc}",
        }
    except ClientOperationLockError as exc:
        return {
            "ok": False,
            "error": f"cannot launch Arena while a client update is active: {exc}",
        }
    except NativeModeInstallError as exc:
        return {
            "ok": False,
            "error": f"native five-mode installation is unsafe: {exc}",
        }


def _launch_mode_locked(
    mode: str,
    battle_xml: Path | None = None,
    *,
    selector_installation: str = "legacy",
) -> dict:
    if selector_installation not in {"legacy", "verified"}:
        return {"ok": False, "error": "invalid native selector installation state"}
    try:
        validate_deployed_unit_ability_wad(_NATIVE_UNIT_ABILITIES)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    scripts = scripts_dir()
    write_stack_config()
    if mode == "frontend":
        # ``display_name_override`` follows the bound identity: the native
        # final report's ``player_name`` is matched against the resolved native
        # user id before any settlement is accepted.  With no resolver bound
        # this is byte for byte the historical script.
        (scripts / "User.script.txt").write_text(
            frontend_user_script(), encoding="utf-16")
    elif mode == "battle" and battle_xml is not None:
        (scripts / "User.script.txt").write_text(
            f'game_startup_mode battle "{battle_xml}";\n', encoding="ascii"
        )
    exe = _require_safe_client_leaf(arena_exe(), "Arena executable before cleanup")
    if not exe.is_file():
        return {"ok": False, "error": f"missing {exe}"}
    stop_revival_arena()
    # Battle keeps original NPL. Lobby is solo/offline: built-in fake platform
    # plus fake_auth_token, not a live NetEase session.
    if mode == "frontend":
        if selector_installation == "legacy" and not apply_hangar_patches():
            return {"ok": False, "error": "hangar patch failed"}
        if not use_stub_npl():
            return {"ok": False, "error": "npl stub build failed"}
        platform = "fake"
    else:
        if not use_original_npl():
            return {"ok": False, "error": "original npl restore failed"}
        platform = "fake"
    pin_primary_monitor()
    set_online_platform(platform)
    fingerprint = ensure_machine_fingerprint()
    env = os.environ.copy()
    env["ONLINE_PLATFORM"] = platform
    env.pop("BOLTREND_NPL_ENV", None)
    env.pop("BOLTREND_NPL_APPID", None)
    env.pop("BOLTREND_NPL_LAUNCHEID", None)
    exe = _require_safe_client_leaf(arena_exe(), "Arena executable before launch")
    if not exe.is_file():
        return {"ok": False, "error": f"missing {exe}"}
    argv = [str(exe), "+auth", TOKEN]
    # Break away from Cursor/agent job objects so Arena is not killed
    # when the launcher process exits. Sandboxed jobs reject BREAKAWAY
    # (WinError 5); fall back to a detached process in that case.
    flag_sets = [0]
    if os.name == "nt":
        detached = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
        flag_sets = [detached | 0x01000000, detached, subprocess.CREATE_NEW_PROCESS_GROUP, 0]
    started = None
    last_error: OSError | None = None
    if os.name == "nt":
        # Agent jobs kill children. Win32_Process.Create is outside the job.
        ps = (
            "$exe = $env:ARENA_EXE; $cwd = $env:ARENA_CWD; "
            "$p = ([wmiclass]'Win32_Process').Create(\"$exe +auth revival-token\", $cwd); "
            "Write-Output $p.ReturnValue; Write-Output $p.ProcessId"
        )
        if selector_installation == "verified":
            verify_installed_manifest(
                ROOT / NATIVE_MODE_INSTALL_MANIFEST, repo_root=ROOT,
            )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            cwd=str(CLIENT),
            env={**env, "ARENA_EXE": str(exe), "ARENA_CWD": str(CLIENT)},
            capture_output=True,
            text=True,
        )
        print("wmi launch", result.stdout.strip(), result.stderr.strip(), flush=True)
        if result.returncode == 0 and result.stdout.strip().splitlines()[:1] == ["0"]:
            started = True
        else:
            last_error = OSError(f"wmi create failed {result.returncode} {result.stdout} {result.stderr}")
    if started is None:
        for creationflags in flag_sets:
            try:
                if selector_installation == "verified":
                    verify_installed_manifest(
                        ROOT / NATIVE_MODE_INSTALL_MANIFEST, repo_root=ROOT,
                    )
                started = subprocess.Popen(
                    argv,
                    cwd=str(CLIENT),
                    env=env,
                    close_fds=True,
                    creationflags=creationflags,
                )
                break
            except OSError as exc:
                last_error = exc
                continue
    if started is None:
        raise last_error if last_error is not None else OSError("failed to start Arena.exe")
    return {
        "ok": True,
        "mode": mode,
        "exe": str(exe),
        "fingerprint": fingerprint,
        "platform": platform,
    }


# Official battle.xml ability keys from the owned parent battle.xml + twa unit rows.
UNIT_BATTLE_ABS = {
    "rom_legionaries": ["unit_stab", "unit_light_pila_6", "unit_formation_attack"],
    "gre_foot_companions": ["unit_spear_heavy_thrust", "unit_hoplite_phalanx", "unit_melee_aoe"],
    "rom_velites": ["unit_focus_fire_javelins_rom_6", "unit_dash", "unit_hurl"],
    "rom_pedites": ["unit_stab", "unit_light_pila_6", "unit_formation_attack"],
}
COMMANDER_BATTLE_ABS = {
    "rom_germanicus": ["Germanicus_1", "Germanicus_3", "Germanicus_4"],
    "gre_alexander": ["Alexander_1", "Alexander_2", "Alexander_3"],
    "gre_miltiades": ["Miltiades_1", "Miltiades_2", "Miltiades_4"],
    "rom_caesar": ["Caesar_2", "Caesar_3", "Caesar_4"],
}


def battle_ability_xml(commander: str, unit: str) -> str:
    keys = list(UNIT_BATTLE_ABS.get(unit, [])) + list(COMMANDER_BATTLE_ABS.get(commander, []))
    if not keys:
        return ""
    lines = ["\t\t\t\t<unit_capabilities>"]
    for key in keys:
        lines.append(f"\t\t\t\t\t<special_ability>{key}</special_ability>")
    lines.append("\t\t\t\t</unit_capabilities>")
    return "\n" + "\n".join(lines)


MAX_ARMIES_PER_SIDE = 10
TERRITORY_BATTLE_SUFFIX = "_territory"


def army_xml(side_name: str, commander: str, unit: str, commander_name: str,
             extra_units: int = 2) -> str:
    caps = battle_ability_xml(commander, unit)
    extra = "".join(
        f"\t\t\t<unit>\n\t\t\t\t<unit_type type=\"{unit}\"/>{caps}\n\t\t\t</unit>\n"
        for _ in range(max(0, extra_units))
    )
    return f"""\t\t<army>
\t\t\t<faction>rom_rome</faction>
\t\t\t<unit script_name="{side_name}">
\t\t\t\t<general>
\t\t\t\t\t<commander_record_key>{commander}</commander_record_key>
\t\t\t\t\t<name>{commander_name}</name>
\t\t\t\t</general>
\t\t\t\t<unit_type type="{unit}"/>{caps}
\t\t\t</unit>
{extra}\t\t</army>
"""


def normalize_armies(side: dict, default_commander: str, default_unit: str,
                     default_name: str) -> list[dict]:
    """Accept either {armies:[...]} (new, up to 10) or {commander,unit,name} (old)."""
    armies = side.get("armies")
    if not isinstance(armies, list) or not armies:
        armies = [{
            "commander": side.get("commander"),
            "unit": side.get("unit"),
            "name": side.get("name"),
        }]
    out: list[dict] = []
    for army in armies[:MAX_ARMIES_PER_SIDE]:
        army = army or {}
        out.append({
            "commander": army.get("commander") or default_commander,
            "unit": army.get("unit") or default_unit,
            "name": army.get("name") or default_name,
            "extra_units": int(army.get("extra_units", 2)),
        })
    return out or [{"commander": default_commander, "unit": default_unit,
                    "name": default_name, "extra_units": 2}]


def armies_xml(alliance: int, armies: list[dict]) -> str:
    blocks = []
    for i, army in enumerate(armies, start=1):
        script_name = f"Army_{alliance}{i:02d}"
        blocks.append(army_xml(script_name, army["commander"], army["unit"],
                               army["name"], army.get("extra_units", 2)))
    return "".join(blocks)


def battle_map_fields(spec: dict) -> tuple[str, str, bool]:
    """Resolve the logical DB record separately from physical terrain.

    Existing callers pass ``map`` only, so classic battles continue to use
    one value for both fields. Territory DB records add ``_territory`` while
    retaining the base terrain directory. Explicit fields also support DB
    records whose physical map cannot be derived from that suffix.
    """
    map_id = str(spec.get("map") or "mycale").strip() or "mycale"
    battle_record = str(spec.get("battle_record") or map_id).strip() or map_id
    explicit_terrain = spec.get("terrain")
    terrain = str(explicit_terrain or map_id).strip() or map_id
    territory = battle_record.endswith(TERRITORY_BATTLE_SUFFIX)
    if explicit_terrain is None and terrain == battle_record and territory:
        terrain = battle_record[:-len(TERRITORY_BATTLE_SUFFIX)]
    return battle_record, terrain, territory


def victory_conditions_xml(territory: bool) -> str:
    tags = (("capture_enemy_location", "capture_tickets") if territory
            else ("capture_enemy_location", "kill_or_rout_enemy"))
    return "".join(
        f"\t\t<victory_condition>\n"
        f"\t\t\t<{tag}></{tag}>\n"
        f"\t\t</victory_condition>\n"
        for tag in tags
    )


def write_battle_xml(spec: dict) -> Path:
    BATTLES.mkdir(parents=True, exist_ok=True)
    battle_record, terrain, territory = battle_map_fields(spec)
    duration = int(spec.get("duration") or 600)
    script = spec.get("script")
    if script is None:
        script = "TestData/MapTesting/MB_Camera_Sweep.lua"
    script_xml = ""
    if str(script).strip():
        script_xml = f'\t\t<battle_script prepare_for_fade_in="false">{script}</battle_script>\n'
    player = spec.get("player") or {}
    enemy = spec.get("enemy") or {}
    player_armies = normalize_armies(player, "rom_germanicus", "rom_legionaries", "Player")
    enemy_armies = normalize_armies(enemy, "gre_alexander", "gre_foot_companions", "CPU")
    victory_xml = victory_conditions_xml(territory)
    # Both classic annihilation and territory battles are Arena sessions.
    # The shipped Arena battle fixtures always set this type; omitting it
    # selects the legacy classic postbattle layout, whose component tree does
    # not match the Arena postbattle controller and crashes while building the
    # earnings panel.
    battle_type_xml = "\t\t<type>battle_arena</type>\n"
    # The native battle-description default is -1 when this element is absent.
    # Leave classic battles on that engine-selected timeout result so the
    # surviving-soldier comparison is used instead of awarding one fixed side.
    # Keep the established territory fixture override unchanged.
    timeout_winner_xml = (
        "\t\t<timeout_winning_alliance_index>1</timeout_winning_alliance_index>\n"
        if territory else ""
    )
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<battle xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="battle.xsd">
	<alliance id="0">
{armies_xml(0, player_armies)}
{victory_xml}
		<rout_position x="-768" y="900"></rout_position>
	</alliance>
	<alliance id="1">
{armies_xml(1, enemy_armies)}
{victory_xml}
		<rout_position x="768" y="-900"></rout_position>
	</alliance>
	<battle_description>
{script_xml}		<battle_db_record>{battle_record}</battle_db_record>
		<time_of_day>day</time_of_day>
		<season>Summer</season>
		<precipitation_type>wet</precipitation_type>
{battle_type_xml}
{timeout_winner_xml}		<duration>{duration}</duration>
		<enable_ai/>
	</battle_description>
	<weather>
		<environment_key>terrain\\tiles\\battle\\battlefields\\{terrain}</environment_key>
		<prevailing_wind x="0" y="1"/>
	</weather>
	<battle_map_definition>
		<name>terrain\\tiles\\battle\\battlefields\\{terrain}</name>
	</battle_map_definition>
	<playable_area dimension="1940"></playable_area>
</battle>
"""
    dest = BATTLES / "current_battle.xml"
    dest.write_text(xml, encoding="utf-8")
    scripts = scripts_dir()
    copied = scripts / "battle.xml"
    copied.write_text(xml, encoding="utf-8")
    return copied


def launch_battle(spec: dict) -> dict:
    path = write_battle_xml(spec)
    result = launch_mode("battle", path)
    result["battle_xml"] = str(path)
    return result


class DualProtocolServer(ThreadingHTTPServer):
    """Accept HTTP and TLS on the same port. Arena may fetch stack_config over HTTPS."""

    def __init__(self, addr: tuple[str, int], handler: type[BaseHTTPRequestHandler]) -> None:
        super().__init__(addr, handler)
        self.ssl_context: ssl.SSLContext | None = None
        cert = ROOT / "server" / "certs" / "cert.pem"
        key = ROOT / "server" / "certs" / "key.pem"
        if cert.is_file() and key.is_file():
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            except ValueError:
                pass
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            ctx.load_cert_chain(str(cert), str(key))
            self.ssl_context = ctx

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        sock, addr = self.socket.accept()
        if self.ssl_context is None:
            return sock, addr
        try:
            peek = sock.recv(1, socket.MSG_PEEK)
        except OSError as exc:
            print(f"peek fail {addr}: {exc}", flush=True)
            return sock, addr
        if peek == b"\x16":
            try:
                sock = self.ssl_context.wrap_socket(sock, server_side=True)
            except ssl.SSLError as exc:
                print(f"tls fail {addr}: {exc}", flush=True)
                raise
        return sock, addr


class DualProtocolServer6(DualProtocolServer):
    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


def main(argv: list[str] | None = None) -> None:
    global SERVER_LIST
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--loopback", action="store_true",
        help="Compatibility flag; this native stack is always loopback-only",
    )
    parser.add_argument(
        "--local-region", action="store_true",
        help=("Enable local region discovery and four-byte UDP echo on "
              "127.0.0.1:55563 (no battles or TCP relay)"),
    )
    args = parser.parse_args(argv)
    # Pure module imports remain usable in CI, but a live service must never
    # publish type-19 catalogue rows for a different deployed client WAD.
    validate_deployed_unit_ability_wad(_NATIVE_UNIT_ABILITIES)
    host4, host6 = LOOPBACK_HOSTS
    region_ping = None
    previous_server_list = SERVER_LIST
    try:
        if args.local_region:
            region_ping = NativeRegionPing()
            # Bind synchronously before other listeners; failures are fatal.
            region_ping.start()
            SERVER_LIST = local_server_list()
            print("Local region discovery on 127.0.0.1:55563 UDP (no battle relay)")
        start_xmpp(hosts=(host4, host6))
        ipv4 = DualProtocolServer((host4, PORT), Handler)
        print(f"Revival stack listening on {host4}:{PORT} (http+https)")
        try:
            ipv6 = DualProtocolServer6((host6, PORT), Handler)
            threading.Thread(target=ipv6.serve_forever, daemon=True).start()
            print(f"Revival stack listening on [{host6}]:{PORT} (http+https)")
        except OSError as exc:
            print(f"IPv6 listen skipped: {exc}")
        for extra in (443, 80):
            try:
                extra_srv = DualProtocolServer((host4, extra), Handler)
                threading.Thread(target=extra_srv.serve_forever, daemon=True).start()
                print(f"Revival stack listening on {host4}:{extra} (http+https)")
            except OSError as exc:
                print(f"port {extra} skipped: {exc}")
            try:
                extra_srv6 = DualProtocolServer6((host6, extra), Handler)
                threading.Thread(target=extra_srv6.serve_forever, daemon=True).start()
                print(f"Revival stack listening on [{host6}]:{extra} (http+https)")
            except OSError as exc:
                print(f"IPv6 port {extra} skipped: {exc}")
        ipv4.serve_forever()
    finally:
        if region_ping is not None:
            region_ping.stop()
            SERVER_LIST = previous_server_list


if __name__ == "__main__":
    main()
