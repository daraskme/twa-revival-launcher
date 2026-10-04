"""Bounded local diagnostics. Never persist messages, request data or locals."""
from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import stat
import sys
import threading
from datetime import datetime, timezone
import uuid

RUN_ENV = "TWA_DIAGNOSTIC_RUN_ID"
MAX_LOG_BYTES = 256 * 1024
LOG_BACKUPS = 3
MAX_RUNS = 8
MAX_RECORD_BYTES = 12 * 1024
COMPONENTS = frozenset(("launcher", "worker", "native", "bridge", "companion"))
OPERATIONS = frozenset(("login", "account", "rename", "update", "launch", "language",
    "restart", "startup", "install", "worker_process", "unhandled", "thread_unhandled", "ui_callback",
    "prepare", "bridge_start", "arena_start", "helper_start", "supervise", "teardown",
    "arena_exit", "battle_bind", "open_logs", "repair_hosts"))
EVENTS = frozenset(("operation_failed", "process_failed", "python_unhandled",
    "native_exit", "launch_started", "launch_failed", "battle_bound", "logging_unavailable",
    "renderer_profile"))
# No arbitrary server/API error text is accepted as a diagnostic code.
ERROR_CODES = frozenset(("invalid_login_response", "invalid_session_token_response",
    "invalid_session_expiry_response", "worker_identity_mismatch", "failed", "offline", "configuration", "login_required", "auth_unavailable",
    "maintenance", "launcher_update_failed", "game_launch_failed", "game_exited_with_error",
    "language_failed", "invalid_display_name", "player_name_required", "registration_closed",
    "invitation_required", "account_disabled", "runtime_dependency_missing", "runtime_invalid",
    "install_failed", "install_space", "install_permission", "install_busy",
    "install_destination", "install_files", "install_download", "install_launcher",
    "eos_auth_login", "eos_auth_token", "eos_connect_login", "eos_connect_create", "eos_connect_token",
    "loopback_dns_missing", "loopback_bind_failed", "loopback_repair_failed", "loopback_repair_cancelled", "loopback_repair_unresolved",
    "loopback_repair_unsupported", "loopback_tls_failed", "loopback_repair_permission", "loopback_repair_timeout"))
VERSION = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:[-+][A-Za-z0-9.-]{1,32})?\Z")
EXCEPTION_CLASSES = frozenset(("WorkerLoginResponseError", "Exception", "RuntimeError", "ValueError", "TypeError", "OSError",
    "PermissionError", "FileNotFoundError", "TimeoutError", "ConnectionError", "MemoryError",
    "AssertionError", "KeyError", "IndexError", "AttributeError", "ZeroDivisionError",
    "ApiError", "NetworkError", "NativeLaunchError", "BridgeError", "BridgeStartError",
    "PlayerReleaseError", "PlayerSessionError", "ClientLanguageError", "LauncherUpdateError",
    "PlayerInstallError", "StageError", "NativePayloadError", "PackageError", "DownloadError",
    "ClientOperationLockBusy", "ClientOperationLockError", "EosLoginError", "EosTimeoutError", "EosBindingError", "UpdaterError", "ChildProtocolError"))
INSTALLER_PHASES = frozenset(("prepare", "launcher_check", "base_download", "native_download",
    "checking", "copying", "applying", "verifying", "complete"))
CODE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,79}\Z")
PUBLIC_PATH = re.compile(r"(?:companion|server|tools)/(?:[A-Za-z0-9_]+/)*[A-Za-z0-9_]+\.py\Z")

def _uuid(value):
    try:
        return str(uuid.UUID(value)) if isinstance(value, str) else None
    except (ValueError, AttributeError):
        return None

def run_id():
    """An opaque correlation ID; never derived from account/session material."""
    value = _uuid(os.environ.get(RUN_ENV))
    if value is None:
        value = str(uuid.uuid4())
        os.environ[RUN_ENV] = value
    return value

def _timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

def _version(value):
    return value if isinstance(value, str) and VERSION.fullmatch(value) else "unknown"

def _regular(path):
    info = path.lstat()
    return (stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and not getattr(info, "st_file_attributes", 0) & 0x400)

def _safe_directory(path):
    path = Path(path).absolute()
    # Do not follow existing symlinks/reparse points into release/original paths.
    for current in [*reversed(path.parents), path]:
        if current.exists() or current.is_symlink():
            info = current.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise OSError("diagnostic directory is not regular")
        else:
            current.mkdir()
            try:
                current.chmod(0o700)
            except OSError:
                pass
    return path

def _prune(root, active):
    # Only UUID directories belonging to this facility are eligible; never
    # recursively follow links or remove unrelated user files/directories.
    runs = []
    for path in root.iterdir():
        if _uuid(path.name) != path.name or path.name == active:
            continue
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400:
            runs.append((info.st_mtime_ns, path))
    for _, path in sorted(runs, reverse=True)[MAX_RUNS-1:]:
        files = list(path.iterdir())
        allowed = re.compile(r"(?:launcher|worker|native|bridge|companion)\.jsonl(?:\.[1-3])?|(?:launcher|worker|native|bridge|companion)-crash-summary\.txt|battle-context\.json|(?:launcher|worker|native|bridge|companion)-battle-context\.tmp\Z")
        if all(allowed.fullmatch(p.name) and _regular(p) for p in files):
            for file in files:
                file.unlink()
            path.rmdir()
    remaining = [p for p in root.iterdir() if _uuid(p.name) == p.name and p.name != active]
    if len(remaining) > MAX_RUNS-1:
        # Locked/unsafe old leaves must not be followed/deleted. Refuse a new
        # run rather than allow repeated failures to grow the facility forever.
        raise OSError("diagnostic retention could not be maintained")

class _QuietRotatingHandler(RotatingFileHandler):
    def handleError(self, record):
        # A disk/rotation failure must neither break play nor emit path/raw data
        # through logging's normal diagnostic stderr traceback.
        pass

class DiagnosticLog:
    def __init__(self, component, *, state_dir=None, repo_root=None, correlation=None):
        self.component = component if component in COMPONENTS else "companion"
        self.run = _uuid(correlation) or run_id()
        self.repo = Path(repo_root or Path(__file__).resolve().parents[1]).resolve()
        self.available = False
        self.handler = None
        self.directory = None
        self.launcher_version = "unknown"
        self.game_version = "unknown"
        self._lock = threading.RLock()
        try:
            from .player_language import player_state_dir
            root = _safe_directory(Path(state_dir if state_dir is not None else player_state_dir()) / "diagnostics")
            _prune(root, self.run)
            self.directory = _safe_directory(root / self.run)
            for existing in self.directory.iterdir():
                if not _regular(existing):
                    raise OSError("diagnostic leaf is not regular")
            self.handler = _QuietRotatingHandler(self.directory / (self.component + ".jsonl"),
                maxBytes=MAX_LOG_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8", errors="strict")
            self.handler.setFormatter(logging.Formatter("%(message)s"))
            self.available = True
            self.refresh_versions()
        except Exception:
            self.available = False

    def refresh_versions(self, *, client_version=None):
        if client_version is not None:
            self.game_version = _version(client_version)
        try:
            self.launcher_version = _version((self.repo / "companion/VERSION").read_text(encoding="ascii").strip())
        except Exception:
            pass
        try:
            if client_version is None:
                receipt = self.repo / "client/.twa-revival-update-state.json"
                if receipt.is_file() and receipt.stat().st_size <= 65536:
                    value = json.loads(receipt.read_text(encoding="utf-8"))
                    self.game_version = _version(value.get("version"))
        except Exception:
            pass

    def _frames(self, error):
        frames = []
        tb = error.__traceback__ if isinstance(error, BaseException) else None
        while tb is not None and len(frames) < 24:
            code = tb.tb_frame.f_code
            filename, function = "<external>", "<external>"
            try:
                relative = Path(code.co_filename).resolve().relative_to(self.repo).as_posix()
                if PUBLIC_PATH.fullmatch(relative):
                    filename = relative
                    function = code.co_name if CODE_NAME.fullmatch(code.co_name) else "<function>"
            except (OSError, ValueError):
                pass
            frames.append({"filename": filename, "function": function, "line": tb.tb_lineno})
            tb = tb.tb_next
        return frames

    def _battle(self):
        try:
            path = self.directory / "battle-context.json"
            if _regular(path) and path.stat().st_size <= 512:
                value = json.loads(path.read_text(encoding="utf-8"))
                if value.get("runId") == self.run:
                    return _uuid(value.get("battleId"))
        except Exception:
            pass
        return None

    def bind_battle(self, battle):
        battle = _uuid(battle)
        if battle is None or not self.available:
            return
        try:
            with self._lock:
                destination = self.directory / "battle-context.json"
                if destination.exists() and not _regular(destination):
                    return
                # This small record holds only the last known battle UUID; no
                # bearer token, room/ticket, identity or raw API payload.
                temporary = self.directory / (self.component + "-battle-context.tmp")
                with temporary.open("x", encoding="utf-8") as stream:
                    json.dump({"runId": self.run, "battleId": battle}, stream)
                os.replace(temporary, destination)
            self.event("battle_bound", "battle_bind")
        except Exception:
            pass

    def event(self, event, operation, *, error=None, code=None, exit_code=None, eos_result=None, crash=False,
              installer_phase=None, repair_stage=None, windows_error=None, helper_exit=None,
              renderer_mode=None, bind_family=None, bind_port=None, bind_transport=None):
        if not self.available:
            return
        try:
            with self._lock:
                value = {"schemaVersion": 1, "timestampUtc": _timestamp(), "runId": self.run,
                    "correlationId": self.run, "component": self.component,
                    "operation": operation if operation in OPERATIONS else "unhandled",
                    "event": event if event in EVENTS else "operation_failed",
                    "launcherVersion": self.launcher_version, "gameVersion": self.game_version}
                if operation == "install" and installer_phase in INSTALLER_PHASES:
                    value["installerPhase"] = installer_phase
                if event == "renderer_profile" and renderer_mode in (
                    "software", "hardware", "unknown", "preserved-software"):
                    value["rendererMode"] = renderer_mode
                if operation in ('bridge_start', 'launch') and code == 'loopback_bind_failed':
                    if bind_transport in ('tcp', 'udp'):
                        value['bindTransport'] = bind_transport
                    if bind_family in ('ipv4', 'ipv6') and type(bind_port) is int and 1 <= bind_port <= 65535:
                        value['bindFamily'] = bind_family
                        value['bindPort'] = bind_port
                    if type(windows_error) is int and 0 <= windows_error <= 0xffffffff:
                        value['windowsErrorCode'] = windows_error
                if operation == 'repair_hosts':
                    if repair_stage in ('start', 'process_handle', 'wait', 'helper_exit'):
                        value['repairStage'] = repair_stage
                    for name, number in (('windowsErrorCode', windows_error), ('helperExitCode', helper_exit)):
                        if type(number) is int and 0 <= number <= 0xffffffff:
                            value[name] = number
                battle = self._battle()
                if battle is not None:
                    value["battleId"] = battle
                if code is not None:
                    value["errorCode"] = code if code in ERROR_CODES else "failed"
                if isinstance(error, BaseException):
                    name = type(error).__name__
                    value["exceptionClass"] = name if name in EXCEPTION_CLASSES else "Exception"
                    value["frames"] = self._frames(error)
                if type(exit_code) is int:
                    unsigned = exit_code & 0xffffffff
                    value["exitCodeHex"] = f"0x{unsigned:08X}"
                    value["nativeFailure"] = ("heap_corruption" if unsigned == 0xc0000374 else
                        "access_violation" if unsigned == 0xc0000005 else
                        "stack_buffer_overrun" if unsigned == 0xc0000409 else
                        "normal" if unsigned == 0 else "abnormal_exit")
                if type(eos_result) is int and 0 <= eos_result <= 2147483647:
                    value["eosResult"] = eos_result
                text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
                if len(text.encode("utf-8")) > MAX_RECORD_BYTES:
                    value.pop("frames", None)
                    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
                self.handler.handle(logging.LogRecord("twa.local", logging.ERROR if crash else logging.INFO,
                    "", 0, text, (), None))
                if crash:
                    self._summary(value)
        except Exception:
            pass

    def _summary(self, value):
        path = self.directory / (self.component + "-crash-summary.txt")
        if path.exists() and not _regular(path):
            return
        rows = ["TWA local crash/error summary (sanitized; no raw memory)",
            *[f"{key}: {value[key]}" for key in ("timestampUtc", "component", "operation", "launcherVersion",
                "gameVersion", "runId", "correlationId", "battleId", "errorCode", "exitCodeHex", "nativeFailure",
                "exceptionClass", "installerPhase") if key in value]]
        rows.extend(f"  {frame['filename']}:{frame['line']} ({frame['function']})" for frame in value.get("frames", []))
        text = "\n".join(rows) + "\n"
        with path.open("w", encoding="utf-8") as stream:
            stream.write(text[:8192])

    def install_exception_hooks(self):
        # Default traceback printing may contain raw exception messages. Replace
        # it at these dedicated app entry points with sanitized local records.
        def system_hook(kind, value, traceback):
            if isinstance(value, KeyboardInterrupt):
                return
            self.event("python_unhandled", "unhandled", error=value, crash=True)
        def thread_hook(args):
            if isinstance(args.exc_value, (KeyboardInterrupt, SystemExit)):
                return
            self.event("python_unhandled", "thread_unhandled", error=args.exc_value, crash=True)
        sys.excepthook = system_hook
        threading.excepthook = thread_hook

    def close(self):
        self.available = False
        try:
            if self.handler is not None:
                self.handler.close()
        except Exception:
            pass

def open_log_folder(*, state_dir=None):
    """Called only from an explicit player click; opens a folder, uploads nothing."""
    try:
        from .player_language import player_state_dir
        path = _safe_directory(Path(state_dir if state_dir is not None else player_state_dir()) / "diagnostics")
        if os.name != "nt":
            return False
        os.startfile(str(path))
        return True
    except Exception:
        return False
