"""Build (and, only when explicitly confirmed, execute) an Arena.exe launch plan.

This module deliberately does *not* reproduce anything
server/local_stack.py's launch_mode() does today: writing
client\\stack_config.json, swapping the NPL stub, writing
%APPDATA%\\The Creative Assembly\\Arena\\scripts\\User.script.txt, setting the
ONLINE_PLATFORM preference, seeding the machine_fingerprint registry value,
or pinning the primary monitor. build_launch_plan() only describes what a
frontend launch needs; LaunchPlan.preferences_note says so explicitly so a
caller cannot mistake "plan built" for "environment prepared".

The `+auth <session_token>` argument and User.script ``fake_auth_token`` are
the same companion Worker session token. ``display_name_override`` is built
from the authenticated account name. Login and GAME_JOIN retain the PUID;
battle results validate the display name frozen by the bridge at launch.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
import json
import math
import os
import queue
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from .bridge_protocol import (
    MAX_CONTROL_LINE, PROTOCOL, constant_time_proof_matches,
    UnitControlBinding, valid_client_version,
)
from .client_lock import ClientOperationLockError, client_operation_lock
from .config import Config
from .player_name import validate_display_name

_SUPPORTED_MODES = ("frontend",)
_BRIDGE_SURFACES = {
    "http": [18765, 80, 443], "xmpp": [5222, 5223],
    "region_udp": 19063, "relay_tcp": 19000,
}


def _bridge_child_command(config: Config) -> list[str]:
    # The bundled Python uses an isolated ._pth and does not search cwd.
    # Pass the verified installation root as an argv value, never shell text.
    bootstrap = ("import runpy,sys;sys.path.insert(0,sys.argv.pop(1));"
                 "runpy.run_module('companion.bridge_child',run_name='__main__')")
    return [sys.executable, "-B", "-u", "-c", bootstrap, str(config.repo_root)]


def _canonical_path(path: Path) -> Path:
    try:
        return Path(os.path.realpath(os.path.abspath(path)))
    except (OSError, TypeError, ValueError) as error:
        raise BridgeStartError("bridge path cannot be resolved safely") from error


def _path_contains(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class LaunchPlan:
    argv: tuple[str, ...] = field(repr=False)
    cwd: str
    user_script_text: str = field(repr=False)
    preferences_note: str
    native_user_id: str | None = None
    display_name: str | None = None


def _frontend_user_script(repo_root: Path, session_token: str, native_user_id: str) -> str:
    """Build the script from the same validated helper as the local stack.

    Done lazily (inside this function, not at module import time) so
    commands that never build a launch plan (status/update/login) do not pay
    for it. Importing local_stack.py loads catalog/progression JSON
    read-only and builds an in-memory SelectionState -- it performs no
    filesystem writes and never calls main(), so it is safe to import
    outside of an actual launch.
    """
    server_dir = str(repo_root / "server")
    if server_dir not in sys.path:
        sys.path.insert(0, server_dir)
    from f2p_fake import frontend_user_script  # type: ignore

    return frontend_user_script(session_token, native_user_id)


def build_launch_plan(
    config: Config, session_token: str, native_user_id: str, mode: str = "frontend",
    *, display_name: str | None = None,
) -> LaunchPlan:
    if mode not in _SUPPORTED_MODES:
        raise ValueError(f"unsupported launch mode: {mode!r} (supported: {_SUPPORTED_MODES})")
    if not session_token:
        raise ValueError("session_token is required to build a launch plan")
    if not native_user_id:
        raise ValueError("native_user_id is required to build a launch plan")
    if display_name is not None:
        validate_display_name(display_name)
    exe = config.client_dir / "Arena.exe"
    argv = (str(exe), "+auth", session_token)
    user_script_text = _frontend_user_script(
        config.repo_root, session_token,
        native_user_id if display_name is None else display_name,
    )
    preferences_note = (
        "This immutable plan describes argv/cwd/user_script_text only. Normal "
        "CLI launch passes it to companion.launch_preparation for guarded "
        "copied-client, User.script, preferences, and fingerprint setup, then "
        "companion.native_launch owns bridge/process supervision and rollback. "
        "Building or printing this plan performs none of those operations."
    )
    return LaunchPlan(
        argv=argv,
        cwd=str(config.client_dir),
        user_script_text=user_script_text,
        preferences_note=preferences_note,
        native_user_id=native_user_id,
        display_name=display_name,
    )


def redacted_argv(plan: LaunchPlan) -> list[str]:
    """Return display-safe argv without exposing the bearer session token."""
    argv = list(plan.argv)
    try:
        index = argv.index("+auth")
    except ValueError:
        return argv
    if index + 1 < len(argv):
        argv[index + 1] = "<redacted>"
    return argv


def redacted_user_script(plan: LaunchPlan) -> str:
    """Return display-safe script text without its embedded session token."""
    try:
        index = plan.argv.index("+auth")
        token = plan.argv[index + 1]
    except (ValueError, IndexError):
        return plan.user_script_text
    return plan.user_script_text.replace(token, "<redacted>") if token else plan.user_script_text


class BridgeStartError(RuntimeError):
    """The owned bridge did not reach its authenticated ready boundary."""


class _WindowsJob:
    """Kill-on-close Job object assigned before the child receives start."""

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class BASIC_LIMIT(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class EXTENDED_LIMIT(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BASIC_LIMIT),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        class BASIC_ACCOUNTING(ctypes.Structure):
            _fields_ = [
                ("TotalUserTime", ctypes.c_longlong),
                ("TotalKernelTime", ctypes.c_longlong),
                ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                ("TotalPageFaultCount", wintypes.DWORD),
                ("TotalProcesses", wintypes.DWORD),
                ("ActiveProcesses", wintypes.DWORD),
                ("TotalTerminatedProcesses", wintypes.DWORD),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        terminate = kernel32.TerminateJobObject
        terminate.argtypes = (wintypes.HANDLE, wintypes.UINT)
        terminate.restype = wintypes.BOOL
        query = kernel32.QueryInformationJobObject
        query.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                          wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))
        query.restype = wintypes.BOOL
        create = kernel32.CreateJobObjectW
        create.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        create.restype = wintypes.HANDLE
        handle = create(None, None)
        if not handle:
            raise BridgeStartError("cannot create bridge lifetime job")
        info = EXTENDED_LIMIT()
        info.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE
        set_info = kernel32.SetInformationJobObject
        set_info.argtypes = (wintypes.HANDLE, ctypes.c_int,
                             ctypes.c_void_p, wintypes.DWORD)
        set_info.restype = wintypes.BOOL
        if not set_info(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            error = ctypes.get_last_error()
            close_handle(handle)
            raise BridgeStartError(f"cannot configure bridge lifetime job ({error})")
        self._ctypes = ctypes
        self._kernel32 = kernel32
        self._close_handle = close_handle
        self._terminate = terminate
        self._query = query
        self._accounting_type = BASIC_ACCOUNTING
        self._handle = handle

    def assign(self, process: subprocess.Popen) -> None:
        from ctypes import wintypes
        assign = self._kernel32.AssignProcessToJobObject
        assign.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        assign.restype = wintypes.BOOL
        if not assign(self._handle, wintypes.HANDLE(int(process._handle))):
            raise BridgeStartError(
                f"cannot contain bridge child ({self._ctypes.get_last_error()})")

    def terminate(self) -> None:
        if self._handle:
            if not self._terminate(self._handle, 1):
                raise BridgeStartError(
                    f"cannot terminate bridge lifetime job ({self._ctypes.get_last_error()})")

    def close(self) -> None:
        if self._handle:
            # KILL_ON_JOB_CLOSE is the crash fence.  An explicit termination
            # first also makes normal close deterministic when the bridge
            # parent exited while a descendant remained.
            error = None
            try:
                self.terminate()
                deadline = time.monotonic() + 5.0
                while True:
                    accounting = self._accounting_type()
                    if not self._query(self._handle, 1,
                                       self._ctypes.byref(accounting),
                                       self._ctypes.sizeof(accounting), None):
                        raise BridgeStartError(
                            "cannot verify bridge lifetime job shutdown")
                    if accounting.ActiveProcesses == 0:
                        break
                    if time.monotonic() >= deadline:
                        raise BridgeStartError(
                            "bridge lifetime job descendants did not stop")
                    time.sleep(0.02)
            except BridgeStartError as caught:
                error = caught
            handle, self._handle = self._handle, None
            if not self._close_handle(handle) and error is None:
                error = BridgeStartError(
                    f"cannot close bridge lifetime job ({self._ctypes.get_last_error()})")
            if error is not None:
                raise error


class _ProcessOwner:
    def __init__(self, process: subprocess.Popen, windows_job=None) -> None:
        self.process = process
        self.windows_job = windows_job

    def force_stop(self, timeout: float = 5.0) -> None:
        process = self.process
        if self.windows_job is not None:
            if process.poll() is not None:
                return
            self.windows_job.terminate()
            try:
                process.wait(timeout=timeout)
                return
            except subprocess.TimeoutExpired:
                self.windows_job.terminate()
                try:
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired as exc:
                    raise BridgeStartError(
                        "owned bridge process group did not stop") from exc
            return
        raise BridgeStartError("bridge process has no Windows Job ownership")

    def close(self) -> None:
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream is not None and not stream.closed:
                try:
                    stream.close()
                except OSError:
                    pass
        if self.windows_job is not None:
            self.windows_job.close()


class BridgeHandle:
    """One authenticated bridge child and all descendants it owns."""

    def __init__(self, owner: _ProcessOwner, control: BinaryIO, output: BinaryIO,
                 nonce: str, run_dir: Path) -> None:
        self._owner = owner
        self._control = control
        self._output = output
        self._nonce = nonce
        self.run_dir = run_dir
        self.pid = owner.process.pid
        self._lock = threading.Lock()
        self._closed = False

    @property
    def running(self) -> bool:
        return not self._closed and self._owner.process.poll() is None

    def stop(self, *, timeout: float = 20.0) -> None:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) \
                or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite positive number")
        with self._lock:
            if self._closed:
                return
            process = self._owner.process
            failure = None
            try:
                if process.poll() is None:
                    try:
                        record = {"protocol": PROTOCOL, "command": "stop",
                                  "nonce": self._nonce}
                        self._control.write((json.dumps(record, separators=(",", ":"))
                                             + "\n").encode("utf-8"))
                        self._control.flush()
                    except (BrokenPipeError, OSError, ValueError):
                        pass
                    try:
                        process.wait(timeout=float(timeout))
                    except subprocess.TimeoutExpired:
                        self._owner.force_stop()
                    else:
                        # A defective child must not be able to report a clean
                        # exit while retaining a descendant in its owned POSIX
                        # process group.  On Windows closing the Job below is
                        # the equivalent final descendant fence.
                        self._owner.force_stop()
                else:
                    # The leader may have exited while an owned descendant is
                    # still live; process-group/Job ownership remains authoritative.
                    self._owner.force_stop()
            except BaseException as error:
                failure = error
            for closer in (self._control.close, self._output.close,
                           self._owner.close):
                try:
                    closer()
                except BaseException as error:
                    if failure is None:
                        failure = error
            self._closed = True
            if failure is not None:
                raise failure

    close = stop

    def __enter__(self) -> "BridgeHandle":
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.stop()


def _read_control_record(stream: BinaryIO, process: subprocess.Popen,
                         timeout: float) -> dict:
    result: queue.Queue = queue.Queue(maxsize=1)

    def read_one() -> None:
        try:
            raw = stream.readline(MAX_CONTROL_LINE + 1)
            result.put(raw, block=False)
        except BaseException as error:
            result.put(error, block=False)

    threading.Thread(target=read_one, daemon=True,
                     name="bridge-control-reader").start()
    try:
        raw = result.get(timeout=timeout)
    except queue.Empty:
        if process.poll() is not None:
            raise BridgeStartError("bridge child exited before readiness") from None
        raise BridgeStartError("bridge readiness timed out") from None
    if isinstance(raw, BaseException):
        raise BridgeStartError("bridge control channel failed") from raw
    if not raw or len(raw) > MAX_CONTROL_LINE or not raw.endswith(b"\n"):
        raise BridgeStartError("bridge child closed its control channel")
    try:
        record = json.loads(raw)
    except (UnicodeError, ValueError):
        raise BridgeStartError("invalid bridge control record") from None
    if not isinstance(record, dict):
        raise BridgeStartError("invalid bridge control record")
    return record


def _confirm_child_stable(process: subprocess.Popen, seconds: float = 0.1) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise BridgeStartError("bridge child exited at readiness")
        time.sleep(min(0.01, deadline - time.monotonic()))
    if process.poll() is not None:
        raise BridgeStartError("bridge child exited at readiness")


def start_bridge(config: Config, *, mode: str = "pve",
                 ruleset: str = "territory", timeout: float = 45.0,
                 relay_timeout: float = 15.0,
                 private_ai_opponents: int | None = None,
                 expected_session_sha256: str | None = None,
                 expected_puid: str | None = None,
                 expected_display_name: str | None = None,
                 unit_control_binding: UnitControlBinding | None = None,
                 internal_pvp_test: bool = False,
                 ) -> BridgeHandle:
    """Start and authenticate the exact bridge child for this saved session.

    The session token is read from ``config.session_path`` independently by
    parent and child.  It is never placed in argv, the environment, the
    control protocol, an exception, or a trace.
    """
    if os.name != "nt":
        raise BridgeStartError(
            "owned bridge lifecycle is supported only on Windows")
    if mode not in ("pve", "pvp"):
        raise ValueError("mode must be 'pve' or 'pvp'")
    if ruleset not in ("territory", "annihilation"):
        raise ValueError("unsupported ruleset")
    if type(internal_pvp_test) is not bool:
        raise ValueError("internal_pvp_test must be a boolean")
    if not valid_client_version(config.client_version):
        raise ValueError("config.client_version must be valid SemVer")
    if private_ai_opponents is None:
        private_ai_opponents = 0 if mode == "pvp" else 1
    if (type(private_ai_opponents) is not int
            or (mode == "pvp" and private_ai_opponents != 0)
            or (mode == "pve" and not 1 <= private_ai_opponents <= 10)):
        raise ValueError("private_ai_opponents must be 0 for pvp or 1..10 for pve")
    if expected_session_sha256 is not None and (
            not isinstance(expected_session_sha256, str)
            or len(expected_session_sha256) != 64
            or any(char not in "0123456789abcdef"
                   for char in expected_session_sha256)):
        raise ValueError("expected_session_sha256 must be lowercase SHA-256 hex")
    if expected_display_name is not None:
        validate_display_name(expected_display_name)
    if expected_puid is not None and not isinstance(expected_puid, str):
        raise ValueError("expected_puid must be a string")
    if not isinstance(unit_control_binding, UnitControlBinding):
        raise ValueError("unit_control_binding must be a UnitControlBinding")
    for name, value, upper in (("timeout", timeout, 300.0),
                               ("relay_timeout", relay_timeout, 120.0)):
        if isinstance(value, bool) or not isinstance(value, (int, float)) \
                or not math.isfinite(value) or not 0.1 <= float(value) <= upper:
            raise ValueError(f"{name} must be a finite number in [0.1, {upper}]")

    server_dir = str(config.repo_root / "server")
    if server_dir not in sys.path:
        sys.path.insert(0, server_dir)
    from companion.api_client import normalize_api_base_url
    from native_identity import derive_native_user_id, read_session_token_file

    try:
        api_base_url = normalize_api_base_url(config.api_base_url)
        token, puid = read_session_token_file(
            config.session_path, expected_api_base_url=api_base_url)
        native_user_id = derive_native_user_id(puid)
    except (OSError, TypeError, ValueError) as error:
        raise BridgeStartError("saved companion session is not usable") from error
    session_sha256 = hashlib.sha256(token.encode("ascii")).hexdigest()
    if (expected_session_sha256 is not None and not secrets.compare_digest(
            session_sha256,
            expected_session_sha256)) or (
            expected_puid is not None and not secrets.compare_digest(
                puid.encode("utf-8"), expected_puid.encode("utf-8"))):
        raise BridgeStartError("saved companion session changed before bridge startup")
    if (not secrets.compare_digest(
                unit_control_binding.session_sha256, session_sha256)
            or not secrets.compare_digest(
                unit_control_binding.native_user_id.encode("ascii"),
                native_user_id.encode("ascii"))):
        raise BridgeStartError("unit-control binding identity mismatch")

    state_root = _canonical_path(config.state_dir)
    client_root = _canonical_path(config.client_dir)
    original_root = (_canonical_path(config.original_dir)
                     if config.original_dir is not None else None)
    if (_path_contains(state_root, client_root) or _path_contains(client_root, state_root)
            or (original_root is not None and (
                _path_contains(state_root, original_root)
                or _path_contains(original_root, state_root)
                or _path_contains(client_root, original_root)
                or _path_contains(original_root, client_root)))):
        raise BridgeStartError("bridge state/client/original paths overlap")

    nonce = secrets.token_hex(32)
    runs_root = state_root / "bridge-runs"
    try:
        runs_root.mkdir(parents=True, exist_ok=True)
        resolved_runs_root = _canonical_path(runs_root)
        if (resolved_runs_root != runs_root
                or not _path_contains(state_root, resolved_runs_root)
                or _path_contains(resolved_runs_root, client_root)
                or (original_root is not None and (
                    _path_contains(resolved_runs_root, original_root)
                    or _path_contains(original_root, resolved_runs_root)))):
            raise BridgeStartError("bridge run directory escapes private state")
        run_dir = resolved_runs_root / nonce
        run_dir.mkdir(parents=True, exist_ok=False)
        try:
            os.chmod(run_dir, 0o700)
        except OSError:
            pass
    except BridgeStartError:
        raise
    except OSError as error:
        raise BridgeStartError("cannot create private bridge state directory") from error

    command = _bridge_child_command(config)
    from .launch_preparation import sanitized_launch_environment
    child_environment = sanitized_launch_environment(os.environ)
    from .diagnostics import RUN_ENV, run_id
    child_environment[RUN_ENV] = run_id()
    if any(token in key or token in value
           for key, value in child_environment.items()):
        raise BridgeStartError(
            "bridge child environment contains session material")
    popen_kwargs = {
        "cwd": str(config.repo_root),
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "bufsize": 0,
        "env": child_environment,
    }
    windows_job = None
    if os.name == "nt":
        popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        windows_job = _WindowsJob()

    owner = None
    try:
        with client_operation_lock(config.client_dir):
            process = subprocess.Popen(command, **popen_kwargs)
            owner = _ProcessOwner(process, windows_job)
            if windows_job is not None:
                # The private child blocks on stdin until assignment succeeds;
                # no relay descendant can exist outside this Job.
                try:
                    windows_job.assign(process)
                except BaseException:
                    process.terminate()
                    try:
                        process.wait(timeout=5.0)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5.0)
                    raise
            if process.stdin is None or process.stdout is None:
                raise BridgeStartError("bridge control pipes unavailable")
            start = {
                "protocol": PROTOCOL, "command": "start", "nonce": nonce,
                "mode": mode, "ruleset": ruleset,
                "private_mode": mode,
                "private_ai_opponents": private_ai_opponents,
                "internal_pvp_test": internal_pvp_test,
                "api_base_url": api_base_url,
                "client_version": config.client_version,
                "session_path": str(config.session_path.resolve()),
                "run_dir": str(run_dir.resolve()),
                "relay_timeout": float(relay_timeout),
                "unit_control_capability": unit_control_binding.capability,
            }
            encoded = (json.dumps(start, sort_keys=True, separators=(",", ":"))
                       + "\n").encode("utf-8")
            process.stdin.write(encoded)
            process.stdin.flush()
            ready = _read_control_record(process.stdout, process, float(timeout))
            expected_surfaces = _BRIDGE_SURFACES
            if ready.get("event") == "error":
                raise BridgeStartError("bridge child rejected startup")
            if (ready.get("protocol") != PROTOCOL
                    or ready.get("event") != "ready"
                    or ready.get("nonce") != nonce
                    or ready.get("pid") != process.pid
                    or ready.get("mode") != mode
                    or ready.get("ruleset") != ruleset
                    or ready.get("private_mode") != mode
                    or ready.get("private_ai_opponents") != private_ai_opponents
                    or ready.get("internal_pvp_test") is not internal_pvp_test
                    or ready.get("puid") != puid
                    or ready.get("native_user_id") != native_user_id
                    or (expected_display_name is not None
                        and ready.get("display_name") != expected_display_name)
                    or ready.get("api_base_url") != api_base_url
                    or ready.get("client_version") != config.client_version
                    or ready.get("unit_control_capability_sha256")
                    != unit_control_binding.capability_sha256
                    or ready.get("surfaces") != expected_surfaces
                    or not constant_time_proof_matches(token, ready,
                                                       ready.get("proof"))):
                raise BridgeStartError("bridge readiness authentication failed")
            _confirm_child_stable(process)
            return BridgeHandle(owner, process.stdin, process.stdout, nonce, run_dir)
    except BaseException:
        if owner is not None:
            try:
                owner.force_stop()
            finally:
                owner.close()
        elif windows_job is not None:
            windows_job.close()
        raise


def spawn(plan: LaunchPlan, *, confirm: bool = False) -> subprocess.Popen:
    """Start Arena.exe from plan.argv/plan.cwd. Never called by tests.

    confirm=True is a deliberate, explicit guard: nothing in this module
    calls spawn() on its own, and no test/import path should ever be able to
    trigger a real Arena.exe launch by accident.
    """
    if not confirm:
        raise RuntimeError("spawn() requires confirm=True")
    # The updater holds the same canonical-client lock from its final process
    # check through every backup/publish and the durable version write. Process
    # creation is complete before Popen returns, so after this short critical
    # section a later updater must observe Arena in its fail-closed snapshot.
    try:
        with client_operation_lock(Path(plan.cwd)):
            return subprocess.Popen(plan.argv, cwd=plan.cwd)
    except ClientOperationLockError as exc:
        raise RuntimeError(f"cannot launch Arena safely: {exc}") from exc
