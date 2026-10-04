"""Fail-closed authenticated Arena launch orchestration.

This module owns process lifetime and ordering only. Copied-client mutation is
delegated to the preparation and renderer compatibility helpers. The bridge remains owned by
``launcher.start_bridge``.  Importing this module cannot start either one.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import subprocess
import time
from contextlib import AbstractContextManager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from tools.loopback_certificate import LoopbackCertificateError

from .api_client import normalize_api_base_url
from .client_lock import client_operation_lock
from .config import Config, load_session
from .diagnostics import DiagnosticLog
from .launcher import LaunchPlan, _WindowsJob, build_launch_plan, start_bridge
from .bridge_protocol import UnitControlBinding
from .native_helper_protocol import (
    MAX_CONTROL_LINE as HELPER_CONTROL_LIMIT,
    PROTOCOL as HELPER_PROTOCOL,
    proof_matches as helper_proof_matches,
)
from .startup_gate import StartupCode, StartupResult, check_startup

_TOKEN_RE = re.compile(r"^[a-f0-9]{64}$")
_PUID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class NativeLaunchError(RuntimeError):
    """A launch boundary failed without exposing authentication material."""


@dataclass(frozen=True)
class SessionSnapshot:
    token: str = field(repr=False)
    token_sha256: str
    puid: str
    native_user_id: str
    api_base_url: str
    expires_at: int


class PreparedClient(Protocol):
    argv: tuple[str, ...]
    cwd: Path
    env: Mapping[str, str]

    def close(self) -> None: ...
    def rollback(self) -> None: ...


class ArenaProcess(Protocol):
    @property
    def pid(self) -> int: ...
    def poll(self) -> int | None: ...
    def wait_input_idle(self, timeout: float) -> None: ...
    def start_helper(self, argv: tuple[str, ...], *, cwd: Path,
                     env: Mapping[str, str], readiness: Mapping[str, object],
                     control_binding: UnitControlBinding,
                     timeout: float = 45.0) -> None: ...
    def helper_failed(self) -> bool: ...
    def stop(self, timeout: float = 10.0) -> None: ...
    def safe_to_restore(self) -> bool: ...


@dataclass(frozen=True)
class LaunchDependencies:
    preflight: Callable[[], None]
    startup: Callable[[Config], StartupResult]
    prepare: Callable[[Config, LaunchPlan], PreparedClient]
    bridge: Callable[..., Any]
    arena: Callable[[PreparedClient], ArenaProcess]
    lock: Callable[[Path], AbstractContextManager]
    sleep: Callable[[float], None] = time.sleep
    display_name: Callable[[Config, SessionSnapshot], str] | None = None


def _derive_native_user_id(config: Config, puid: str) -> str:
    server_dir = str(config.repo_root / "server")
    if server_dir not in __import__("sys").path:
        __import__("sys").path.insert(0, server_dir)
    from native_identity import derive_native_user_id
    return derive_native_user_id(puid)


def session_snapshot(config: Config, session: Mapping[str, Any], *,
                     now: int | None = None) -> SessionSnapshot:
    """Validate one saved Worker session without logging its bearer token."""
    current = int(time.time()) if now is None else now
    if isinstance(current, bool) or not isinstance(current, int):
        raise NativeLaunchError("invalid launch clock")
    try:
        api_base_url = normalize_api_base_url(config.api_base_url)
        saved_url = normalize_api_base_url(session.get("apiBaseUrl", ""))
    except (TypeError, ValueError) as error:
        raise NativeLaunchError("saved session is not bound to this service") from error
    token, puid, expires_at = (session.get("token"), session.get("puid"),
                               session.get("expiresAt"))
    if (api_base_url != saved_url or not isinstance(token, str)
            or _TOKEN_RE.fullmatch(token) is None
            or not isinstance(puid, str) or _PUID_RE.fullmatch(puid) is None
            or isinstance(expires_at, bool) or not isinstance(expires_at, int)
            or expires_at <= current):
        raise NativeLaunchError("saved session is not usable for launch")
    try:
        native_user_id = _derive_native_user_id(config, puid)
    except (OSError, TypeError, ValueError) as error:
        raise NativeLaunchError("saved session identity is not usable") from error
    return SessionSnapshot(
        token=token,
        token_sha256=hashlib.sha256(token.encode("ascii")).hexdigest(),
        puid=puid,
        native_user_id=native_user_id,
        api_base_url=api_base_url,
        expires_at=expires_at,
    )


def revalidate_session(config: Config, snapshot: SessionSnapshot, *,
                       now: int | None = None) -> None:
    """Require the on-disk session to remain the exact original snapshot."""
    current = int(time.time()) if now is None else now
    raw = load_session(config)
    if not isinstance(raw, dict) or snapshot.expires_at <= current:
        raise NativeLaunchError("saved session expired or changed during launch")
    try:
        saved_url = normalize_api_base_url(raw.get("apiBaseUrl", ""))
    except (TypeError, ValueError):
        raise NativeLaunchError("saved session expired or changed during launch") from None
    token, puid, expires_at = raw.get("token"), raw.get("puid"), raw.get("expiresAt")
    if (not isinstance(token, str) or not isinstance(puid, str)
            or not isinstance(expires_at, int) or isinstance(expires_at, bool)
            or not secrets.compare_digest(
                hashlib.sha256(token.encode("utf-8")).hexdigest(),
                snapshot.token_sha256)
            or not secrets.compare_digest(puid.encode(), snapshot.puid.encode())
            or saved_url != snapshot.api_base_url
            or expires_at != snapshot.expires_at):
        raise NativeLaunchError("saved session expired or changed during launch")


class _OwnedArena:
    def __init__(self, process: "_Win32Process", job: _WindowsJob) -> None:
        self._process = process
        self._job = job
        self._helpers: list[_Win32Process] = []
        self._closed = False
        self._stopped_safely = False
        self.pid = process.pid

    def poll(self) -> int | None:
        return self._process.poll()

    def wait_input_idle(self, timeout: float) -> None:
        self._process.wait_input_idle(timeout)

    def start_helper(self, argv: tuple[str, ...], *, cwd: Path,
                     env: Mapping[str, str],
                     readiness: Mapping[str, object] | None = None,
                     control_binding: UnitControlBinding | None = None,
                     timeout: float = 45.0) -> None:
        process: _Win32Process | None = None
        try:
            command = (argv + ("--owned-control",)
                       if readiness is not None else argv)
            process = _create_suspended(
                command, cwd=cwd, env=env, hidden=True,
                control=readiness is not None,
            )
            self._job.assign(process)
            process.resume()
            self._helpers.append(process)
            if readiness is not None:
                if not isinstance(control_binding, UnitControlBinding):
                    raise NativeLaunchError(
                        "owned helper requires a unit-control binding")
                self._await_helper_ready(
                    process, readiness, control_binding, timeout,
                )
        except BaseException as error:
            if process is not None:
                try:
                    process.terminate()
                    process.wait(timeout=5.0)
                except BaseException:
                    pass
                if process not in self._helpers:
                    process.close()
            raise NativeLaunchError("cannot start owned Arena helper") from None

    def _await_helper_ready(self, process: "_Win32Process",
                            readiness: Mapping[str, object],
                            control_binding: UnitControlBinding,
                            timeout: float) -> None:
        control_in, control_out = process.control_streams()
        nonce = secrets.token_hex(32)
        binding = dict(readiness)
        if set(binding) != {
                "arena_pid", "specialization_mode", "arcani_slot_fix_mode",
                "arena_path", "game_path",
                "game_sha256"}:
            raise NativeLaunchError("invalid owned helper readiness binding")
        start = {
            "protocol": HELPER_PROTOCOL, "command": "start", "nonce": nonce,
            "unit_control_capability": control_binding.capability,
            "native_user_id": control_binding.native_user_id,
            "session_sha256": control_binding.session_sha256,
            **binding,
        }
        if set(start) != {
                "protocol", "command", "nonce", "arena_pid",
                "specialization_mode", "arcani_slot_fix_mode",
                "arena_path", "game_path",
                "game_sha256", "unit_control_capability", "native_user_id",
                "session_sha256"}:
            raise NativeLaunchError("invalid owned helper readiness binding")
        encoded = (json.dumps(start, sort_keys=True, separators=(",", ":"))
                   + "\n").encode("utf-8")
        if len(encoded) > HELPER_CONTROL_LIMIT:
            raise NativeLaunchError("owned helper start record is too large")
        control_in.write(encoded)
        control_in.flush()
        ready = _read_helper_record(control_out, process, timeout)
        expected = {
            "protocol": HELPER_PROTOCOL,
            "event": "interactive_ready",
            "nonce": nonce,
            "helper_pid": process.pid,
            "unit_control_capability_sha256": (
                control_binding.capability_sha256
            ),
            "native_user_id": control_binding.native_user_id,
            "session_sha256": control_binding.session_sha256,
            **binding,
        }
        if (set(ready) != set(expected) | {"proof"}
                or any(ready.get(key) != value for key, value in expected.items())
                or not helper_proof_matches(nonce, ready, ready.get("proof"))):
            raise NativeLaunchError("owned helper readiness authentication failed")

    def helper_failed(self) -> bool:
        return any(process.poll() is not None for process in self._helpers)

    def stop(self, timeout: float = 10.0) -> None:
        if self._closed:
            return
        failure: BaseException | None = None
        try:
            self._job.close()
        except BaseException as error:
            failure = error
        deadline = time.monotonic() + timeout
        for process in (self._process, *self._helpers):
            try:
                process.wait(timeout=max(0.0, deadline - time.monotonic()))
            except BaseException as error:
                if failure is None:
                    failure = error
        stopped = self.safe_to_restore()
        if stopped:
            self._stopped_safely = True
            self._closed = True
            self._process.close()
            for helper in self._helpers:
                helper.close()
        elif failure is None:
            failure = NativeLaunchError("owned Arena process tree is still running")
        if failure is not None:
            raise NativeLaunchError("owned Arena process tree did not stop") from None

    def safe_to_restore(self) -> bool:
        if self._stopped_safely:
            return True
        try:
            return (self._process.poll() is not None
                    and all(helper.poll() is not None for helper in self._helpers))
        except BaseException:
            return False


class _Win32Process:
    """Minimal retained-handle process used only for suspended Job startup."""

    def __init__(self, process_handle: int, thread_handle: int, pid: int, *,
                 control_in=None, control_out=None) -> None:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._ctypes = ctypes
        self._wintypes = wintypes
        self._kernel32 = kernel32
        self._handle = process_handle
        self._thread_handle = thread_handle
        self.pid = pid
        self._exit_code: int | None = None
        self._control_in = control_in
        self._control_out = control_out
        kernel32.ResumeThread.argtypes = (wintypes.HANDLE,)
        kernel32.ResumeThread.restype = wintypes.DWORD
        kernel32.GetExitCodeProcess.argtypes = (
            wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
        kernel32.TerminateProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL

    def wait_input_idle(self, timeout: float) -> None:
        user32 = self._ctypes.WinDLL("user32", use_last_error=True)
        wait = user32.WaitForInputIdle
        wait.argtypes = (self._wintypes.HANDLE, self._wintypes.DWORD)
        wait.restype = self._wintypes.DWORD
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise NativeLaunchError("Arena UI initialization timed out")
            result = wait(self._handle, min(max(int(remaining * 1000), 1), 100))
            if result == 0:
                return
            if result != 0x00000102:
                raise NativeLaunchError("Arena UI initialization failed")
            if self.poll() is not None:
                raise NativeLaunchError("Arena exited during UI initialization")

    def resume(self) -> None:
        if not self._thread_handle:
            raise NativeLaunchError("owned launch process has no suspended thread")
        handle, self._thread_handle = self._thread_handle, 0
        try:
            if self._kernel32.ResumeThread(handle) == 0xFFFFFFFF:
                raise NativeLaunchError("cannot resume owned launch process")
        finally:
            self._kernel32.CloseHandle(handle)

    def poll(self) -> int | None:
        if self._exit_code is not None:
            return self._exit_code
        state = self._kernel32.WaitForSingleObject(self._handle, 0)
        if state == 0x00000102:
            return None
        if state != 0x00000000:
            raise NativeLaunchError("cannot inspect owned launch process")
        code = self._wintypes.DWORD()
        if not self._kernel32.GetExitCodeProcess(
                self._handle, self._ctypes.byref(code)):
            raise NativeLaunchError("cannot inspect owned launch process")
        self._exit_code = int(code.value)
        return self._exit_code

    def wait(self, timeout: float | None = None) -> int:
        milliseconds = (0xFFFFFFFF if timeout is None else
                        min(max(int(timeout * 1000), 0), 0xFFFFFFFE))
        result = self._kernel32.WaitForSingleObject(self._handle, milliseconds)
        if result == 0x00000102:
            raise subprocess.TimeoutExpired("<owned process>", timeout)
        if result != 0x00000000:
            raise NativeLaunchError("cannot wait for owned launch process")
        code = self.poll()
        if code is None:
            raise NativeLaunchError("owned launch process wait was inconclusive")
        return code

    def terminate(self) -> None:
        if self.poll() is None and not self._kernel32.TerminateProcess(
                self._handle, 1):
            raise NativeLaunchError("cannot terminate owned launch process")

    def control_streams(self):
        if self._control_in is None or self._control_out is None:
            raise NativeLaunchError("owned helper control pipes unavailable")
        return self._control_in, self._control_out

    def close(self) -> None:
        for stream_name in ("_control_in", "_control_out"):
            stream = getattr(self, stream_name)
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
                setattr(self, stream_name, None)
        if self._thread_handle:
            self._kernel32.CloseHandle(self._thread_handle)
            self._thread_handle = 0
        if self._handle:
            self._kernel32.CloseHandle(self._handle)
            self._handle = 0


def _create_suspended(argv: tuple[str, ...], *, cwd: Path,
                      env: Mapping[str, str], hidden: bool,
                      control: bool = False) -> _Win32Process:
    if os.name != "nt" or not argv:
        raise NativeLaunchError("suspended process creation requires Windows")
    import ctypes
    from ctypes import wintypes

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
            ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
        ]

    class STARTUPINFOEXW(ctypes.Structure):
        _fields_ = [
            ("StartupInfo", STARTUPINFOW),
            ("lpAttributeList", ctypes.c_void_p),
        ]

    if any(not isinstance(value, str) or "\0" in value for value in argv):
        raise NativeLaunchError("owned launch command is invalid")
    environment = dict(env)
    if any(not isinstance(key, str) or not isinstance(value, str)
           or not key or "=" in key or "\0" in key or "\0" in value
           for key, value in environment.items()):
        raise NativeLaunchError("owned launch environment is invalid")
    block = "\0".join(
        f"{key}={value}" for key, value in sorted(
            environment.items(), key=lambda item: item[0].upper())) + "\0\0"
    command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
    environment_block = ctypes.create_unicode_buffer(block)
    startup = STARTUPINFOW(cb=ctypes.sizeof(STARTUPINFOW))
    info = PROCESS_INFORMATION()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel32.CreateProcessW
    create.argtypes = (
        wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
        wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
        ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION),
    )
    create.restype = wintypes.BOOL
    terminate_created = kernel32.TerminateProcess
    terminate_created.argtypes = (wintypes.HANDLE, wintypes.UINT)
    terminate_created.restype = wintypes.BOOL
    wait_created = kernel32.WaitForSingleObject
    wait_created.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    wait_created.restype = wintypes.DWORD
    close_created = kernel32.CloseHandle
    close_created.argtypes = (wintypes.HANDLE,)
    close_created.restype = wintypes.BOOL
    flags = 0x00000004 | 0x00000400  # CREATE_SUSPENDED | UNICODE_ENVIRONMENT
    if hidden:
        flags |= 0x08000000  # CREATE_NO_WINDOW
    child_fds: list[int] = []
    parent_fds: list[int] = []
    attribute_buffer = None
    delete_attributes = None
    attributes_initialized = False
    startup_pointer = ctypes.byref(startup)
    opened_streams: list[Any] = []
    process_created = False
    ownership_transferred = False
    try:
        if control:
            import msvcrt
            input_read, input_write = os.pipe()
            child_fds.append(input_read)
            parent_fds.append(input_write)
            output_read, output_write = os.pipe()
            parent_fds.append(output_read)
            child_fds.append(output_write)
            null_write = os.open(os.devnull, os.O_WRONLY)
            child_fds.append(null_write)
            for fd in child_fds:
                os.set_inheritable(fd, True)
            for fd in parent_fds:
                os.set_inheritable(fd, False)
            startup.dwFlags |= 0x00000100  # STARTF_USESTDHANDLES
            startup.hStdInput = msvcrt.get_osfhandle(input_read)
            startup.hStdOutput = msvcrt.get_osfhandle(output_write)
            startup.hStdError = msvcrt.get_osfhandle(null_write)
            initialize = kernel32.InitializeProcThreadAttributeList
            initialize.argtypes = (ctypes.c_void_p, wintypes.DWORD,
                                   wintypes.DWORD,
                                   ctypes.POINTER(ctypes.c_size_t))
            initialize.restype = wintypes.BOOL
            update = kernel32.UpdateProcThreadAttribute
            update.argtypes = (
                ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t,
                ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_size_t),
            )
            update.restype = wintypes.BOOL
            delete_attributes = kernel32.DeleteProcThreadAttributeList
            delete_attributes.argtypes = (ctypes.c_void_p,)
            delete_attributes.restype = None
            attribute_size = ctypes.c_size_t()
            initialize(None, 1, 0, ctypes.byref(attribute_size))
            if not attribute_size.value:
                raise NativeLaunchError("cannot size owned helper handle list")
            attribute_buffer = ctypes.create_string_buffer(attribute_size.value)
            attribute_list = ctypes.cast(attribute_buffer, ctypes.c_void_p)
            if not initialize(attribute_list, 1, 0,
                              ctypes.byref(attribute_size)):
                raise NativeLaunchError("cannot initialize owned helper handle list")
            attributes_initialized = True
            inherited_handles = (wintypes.HANDLE * len(child_fds))(
                *(msvcrt.get_osfhandle(fd) for fd in child_fds))
            if not update(
                    attribute_list, 0, 0x00020002,
                    ctypes.cast(inherited_handles, ctypes.c_void_p),
                    ctypes.sizeof(inherited_handles), None, None):
                raise NativeLaunchError("cannot restrict owned helper handles")
            startup_ex = STARTUPINFOEXW()
            startup_ex.StartupInfo = startup
            startup_ex.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
            startup_ex.lpAttributeList = attribute_list
            startup_pointer = ctypes.cast(
                ctypes.byref(startup_ex), ctypes.POINTER(STARTUPINFOW))
            flags |= 0x00080000  # EXTENDED_STARTUPINFO_PRESENT
        if not create(
                argv[0], command_line, None, None, bool(control), flags,
                ctypes.cast(environment_block, ctypes.c_void_p), str(cwd),
                startup_pointer, ctypes.byref(info)):
            raise NativeLaunchError("cannot create owned launch process")
        process_created = True
        for fd in tuple(child_fds):
            try:
                os.close(fd)
            finally:
                child_fds.remove(fd)
        control_in = control_out = None
        if control:
            control_in = os.fdopen(parent_fds[0], "wb", buffering=0)
            parent_fds.pop(0)
            opened_streams.append(control_in)
            control_out = os.fdopen(parent_fds[0], "rb", buffering=0)
            parent_fds.pop(0)
            opened_streams.append(control_out)
        result = _Win32Process(
            int(info.hProcess), int(info.hThread), int(info.dwProcessId),
            control_in=control_in, control_out=control_out,
        )
        ownership_transferred = True
        opened_streams.clear()
        return result
    except BaseException:
        for stream in opened_streams:
            try:
                stream.close()
            except OSError:
                pass
        if process_created and not ownership_transferred:
            if info.hProcess:
                terminate_created(info.hProcess, 1)
                wait_created(info.hProcess, 5000)
            if info.hThread:
                close_created(info.hThread)
                info.hThread = None
            if info.hProcess:
                close_created(info.hProcess)
                info.hProcess = None
        raise
    finally:
        if (attribute_buffer is not None and delete_attributes is not None
                and attributes_initialized):
            delete_attributes(ctypes.cast(attribute_buffer, ctypes.c_void_p))
        for fd in child_fds + parent_fds:
            try:
                os.close(fd)
            except OSError:
                pass


def _spawn_owned_arena(prepared: PreparedClient) -> _OwnedArena:
    """Create Arena suspended, contain it in a Job, then allow execution."""
    if os.name != "nt":
        raise NativeLaunchError("owned Arena launch is supported only on Windows")
    if not prepared.argv:
        raise NativeLaunchError("prepared Arena command is empty")
    job = _WindowsJob()
    process: _Win32Process | None = None
    try:
        process = _create_suspended(
            prepared.argv, cwd=prepared.cwd, env=prepared.env, hidden=False)
        job.assign(process)
        owned = _OwnedArena(process, job)
        process.resume()
        return owned
    except BaseException as error:
        if process is not None:
            try:
                process.terminate()
                process.wait(timeout=5.0)
            except BaseException:
                pass
            process.close()
        try:
            job.close()
        except BaseException:
            pass
        if isinstance(error, NativeLaunchError):
            raise
        raise NativeLaunchError("cannot create owned Arena process") from None


def _read_helper_record(stream, process: _Win32Process, timeout: float) -> dict:
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0.1 <= timeout <= 120.0):
        raise NativeLaunchError("invalid owned helper readiness timeout")
    result: __import__("queue").Queue = __import__("queue").Queue(maxsize=1)

    def read_one() -> None:
        try:
            result.put(stream.readline(HELPER_CONTROL_LIMIT + 1), block=False)
        except BaseException as error:
            result.put(error, block=False)

    __import__("threading").Thread(
        target=read_one, daemon=True, name="native-helper-control-reader",
    ).start()
    try:
        raw = result.get(timeout=float(timeout))
    except __import__("queue").Empty:
        if process.poll() is not None:
            raise NativeLaunchError("owned helper exited before readiness") from None
        raise NativeLaunchError("owned helper readiness timed out") from None
    if isinstance(raw, BaseException):
        raise NativeLaunchError("owned helper control channel failed") from None
    if not raw or len(raw) > HELPER_CONTROL_LIMIT or not raw.endswith(b"\n"):
        raise NativeLaunchError("owned helper closed its control channel")
    try:
        record = json.loads(raw)
    except (UnicodeError, ValueError):
        raise NativeLaunchError("owned helper sent an invalid control record") from None
    if not isinstance(record, dict):
        raise NativeLaunchError("owned helper sent an invalid control record")
    return record


def _account_name(config: Config, snapshot: SessionSnapshot) -> str:
    from .api_client import ApiClient
    from .player_name import account_display_name
    return account_display_name(
        ApiClient(config.api_base_url, config.client_version, snapshot.token),
        snapshot.puid)


def _default_dependencies(
    *, locale: str, internal_pvp_test: bool = False,
    public_native: bool = False,
) -> LaunchDependencies:
    from .launch_preparation import prepare_authenticated_client
    from .player_language import apply_launch_language

    def prepare(config, plan):
        # The lifecycle already owns the client lock. Apply after the startup
        # updater and before Arena reads either selector or the text overlay.
        from tools.loopback_certificate import ensure_certificate
        ensure_certificate(config.repo_root / 'server' / 'certs')
        apply_launch_language(config, locale)
        if public_native:
            from .renderer_probe import probe_renderer
            from .texture_memory_compat import reconcile
            try:
                decision = probe_renderer().decision
            except Exception:
                decision = "unknown"
            outcome = reconcile(config, decision)
            profile_log = DiagnosticLog("companion", state_dir=config.state_dir,
                                        repo_root=config.repo_root)
            try:
                profile_log.event("renderer_profile", "prepare",
                                  renderer_mode=outcome["mode"])
            finally:
                profile_log.close()
        return prepare_authenticated_client(config, plan)

    return LaunchDependencies(
        preflight=_require_frida,
        startup=lambda config: check_startup(
            config, "release", locale=locale,
            expected_native_battles=internal_pvp_test,
            public_native=public_native,
        ),
        prepare=prepare,
        bridge=start_bridge,
        arena=_spawn_owned_arena,
        lock=lambda path: client_operation_lock(path),
        display_name=_account_name,
    )


def _require_frida() -> None:
    """Prove the launch interpreter can import the exact helper dependency."""
    try:
        __import__("frida")
    except (ImportError, OSError):
        raise NativeLaunchError(
            "this Python interpreter cannot import the required Frida runtime") from None


def _validate_prepared(config: Config, plan: LaunchPlan,
                       prepared: PreparedClient, snapshot: SessionSnapshot) -> None:
    try:
        client = config.client_dir.resolve(strict=True)
        cwd = Path(prepared.cwd).resolve(strict=True)
        executable = Path(prepared.argv[0]).resolve(strict=True)
    except (AttributeError, IndexError, OSError, RuntimeError, TypeError, ValueError) as error:
        raise NativeLaunchError("prepared Arena launch paths are invalid") from None
    if cwd != client or executable != (client / "Arena.exe").resolve(strict=True):
        raise NativeLaunchError("prepared Arena launch escaped the copied client")
    if tuple(prepared.argv) != plan.argv:
        raise NativeLaunchError("prepared Arena command changed after authentication")
    if len(plan.argv) != 3 or plan.argv[1] != "+auth" or not secrets.compare_digest(
            plan.argv[2].encode(), snapshot.token.encode()):
        raise NativeLaunchError("prepared Arena authentication command is invalid")
    if plan.native_user_id != snapshot.native_user_id:
        raise NativeLaunchError("prepared Arena identity changed")
    try:
        env = dict(prepared.env)
    except (TypeError, ValueError) as error:
        raise NativeLaunchError("prepared Arena environment is invalid") from None
    if any(not isinstance(key, str) or not isinstance(value, str)
           for key, value in env.items()):
        raise NativeLaunchError("prepared Arena environment is invalid")
    if any(snapshot.token in key or snapshot.token in value
           for key, value in env.items()):
        raise NativeLaunchError("prepared Arena environment contains session material")


def _validate_supported_roots(config: Config) -> None:
    try:
        repo = config.repo_root.resolve(strict=True)
        client = config.client_dir.resolve(strict=True)
        supported = (repo / "client").resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise NativeLaunchError("launch roots cannot be resolved safely") from error
    if client != supported:
        raise NativeLaunchError(
            "native helper supports only the copied client under this repository")


def _unit_drag_command(config: Config, arena_pid: int, output: Path, *,
                       public_pvp_only: bool = False) -> tuple[str, ...]:
    if type(arena_pid) is not int or arena_pid <= 0:
        raise NativeLaunchError("owned Arena PID is invalid")
    return (
        __import__("sys").executable, "-u",
        str(config.repo_root / "tools" / "unit_drag_bridge.py"),
        "--pid", str(arena_pid), "--output", str(output),
        "--seconds", "31536000", "--specialization-mode", "off",
        "--arcani-slot-fix", "enabled",
    ) + (("--public-pvp-only",) if public_pvp_only else ())


def _unit_drag_readiness(config: Config, arena_pid: int) -> dict[str, object]:
    try:
        arena = (config.client_dir / "Arena.exe").resolve(strict=True)
        game = (config.client_dir / "game.dll").resolve(strict=True)
        digest_state = hashlib.sha256()
        with game.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest_state.update(chunk)
        digest = digest_state.hexdigest()
    except OSError as error:
        raise NativeLaunchError("native helper copy binding is unavailable") from None
    return {
        "arena_pid": arena_pid,
        "specialization_mode": "off",
        "arcani_slot_fix_mode": "enabled",
        "arena_path": str(arena),
        "game_path": str(game),
        "game_sha256": digest,
    }


def _poll_shutdown_exit(arena, sleep):
    """Allow a detached child to precede its owned Arena process by one second."""
    exit_code = arena.poll()
    for _ in range(20):
        if exit_code is not None:
            return exit_code
        sleep(0.05)
        exit_code = arena.poll()
    return exit_code


def run_authenticated_launch(
    config: Config,
    snapshot: SessionSnapshot,
    *,
    battle_mode: str = "pve",
    ruleset: str = "territory",
    private_ai_opponents: int | None = None,
    locale: str = "EN",
    internal_pvp_test: bool = False,
    public_native: bool = False,
    on_tick: Callable[[], None] | None = None,
    poll_seconds: float = 0.1,
    dependencies: LaunchDependencies | None = None,
) -> int:
    """Run gate, preparation, bridge, Arena, and teardown as one transaction."""
    if locale not in ("JA", "EN", "RU"):
        raise NativeLaunchError("unsupported native game language")
    _validate_supported_roots(config)
    if dependencies is None and os.name != "nt":
        raise NativeLaunchError("authenticated native launch is supported only on Windows")
    if battle_mode not in ("pve", "pvp") or ruleset not in (
            "territory", "annihilation"):
        raise NativeLaunchError("unsupported native battle launch mode")
    if type(internal_pvp_test) is not bool:
        raise NativeLaunchError("invalid internal PvP test flag")
    if type(public_native) is not bool or public_native and internal_pvp_test:
        raise NativeLaunchError("invalid public native launch channel")
    if private_ai_opponents is None:
        private_ai_opponents = 0 if battle_mode == "pvp" else 1
    if (type(private_ai_opponents) is not int
            or (battle_mode == "pvp" and private_ai_opponents != 0)
            or (battle_mode == "pve" and not 1 <= private_ai_opponents <= 10)):
        raise NativeLaunchError("invalid private AI opponent count")
    if (isinstance(poll_seconds, bool) or not isinstance(poll_seconds, (int, float))
            or not math.isfinite(poll_seconds) or not 0.01 <= poll_seconds <= 1.0):
        raise NativeLaunchError("invalid launch supervision interval")
    diagnostic = DiagnosticLog("native", state_dir=config.state_dir, repo_root=config.repo_root)
    diagnostic.refresh_versions(client_version=config.client_version)
    diagnostic.event("launch_started", "launch")
    operation = "startup"
    deps = dependencies or _default_dependencies(
        locale=locale, internal_pvp_test=internal_pvp_test,
        public_native=public_native,
    )
    prepared: PreparedClient | None = None
    bridge = None
    arena: ArenaProcess | None = None
    arena_started = False
    primary: BaseException | None = None
    exit_code: int | None = None
    try:
        with deps.lock(config.client_dir):
            try:
                revalidate_session(config, snapshot)
                deps.preflight()
                gate = deps.startup(config)
                if not isinstance(gate, StartupResult) or not gate.allow_launch \
                        or not gate.version:
                    code = (gate.code.value if isinstance(gate, StartupResult)
                            else "invalid")
                    detail = (
                        f": {gate.message}"
                        if isinstance(gate, StartupResult)
                        and gate.code == StartupCode.INCOMPATIBLE_GAME_NATIVE else ""
                    )
                    raise NativeLaunchError(f"startup gate blocked launch ({code}){detail}")
                launch_config = replace(config, client_version=gate.version)
                diagnostic.refresh_versions(client_version=gate.version)
                revalidate_session(launch_config, snapshot)
                display_name = (deps.display_name(launch_config, snapshot)
                                if deps.display_name is not None else None)
                revalidate_session(launch_config, snapshot)
                plan = build_launch_plan(
                    launch_config, snapshot.token, snapshot.native_user_id,
                    mode="frontend", display_name=display_name,
                )
                operation = "prepare"
                prepared = deps.prepare(launch_config, plan)
                _validate_prepared(launch_config, plan, prepared, snapshot)
                revalidate_session(launch_config, snapshot)
                control_binding = UnitControlBinding.generate(
                    snapshot.native_user_id, snapshot.token_sha256,
                )
                operation = "bridge_start"
                bridge = deps.bridge(
                    launch_config, mode=battle_mode, ruleset=ruleset,
                    private_ai_opponents=private_ai_opponents,
                    internal_pvp_test=internal_pvp_test,
                    expected_session_sha256=snapshot.token_sha256,
                    expected_puid=snapshot.puid,
                    expected_display_name=display_name,
                    unit_control_binding=control_binding,
                )
                revalidate_session(launch_config, snapshot)
                operation = "arena_start"
                arena = deps.arena(prepared)
                arena_started = True
                revalidate_session(launch_config, snapshot)
                arena.wait_input_idle(30.0)
                revalidate_session(launch_config, snapshot)
                if not bridge.running:
                    raise NativeLaunchError(
                        "authenticated bridge stopped during Arena startup")
                helper_output = Path(bridge.run_dir) / "unit-drag.jsonl"
                operation = "helper_start"
                arena.start_helper(
                    _unit_drag_command(launch_config, arena.pid, helper_output,
                                       public_pvp_only=public_native),
                    cwd=launch_config.repo_root, env=prepared.env,
                    readiness=_unit_drag_readiness(launch_config, arena.pid),
                    control_binding=control_binding,
                )
                revalidate_session(launch_config, snapshot)
                operation = "supervise"
                while True:
                    exit_code = arena.poll()
                    if exit_code is not None:
                        break
                    if not bridge.running:
                        exit_code = _poll_shutdown_exit(arena, deps.sleep)
                        if exit_code is not None:
                            break
                        raise NativeLaunchError(
                            "authenticated bridge stopped while Arena was running")
                    if arena.helper_failed():
                        exit_code = _poll_shutdown_exit(arena, deps.sleep)
                        if exit_code is not None:
                            break
                        raise NativeLaunchError(
                            "owned Arena helper stopped while Arena was running")
                    if on_tick is not None:
                        on_tick()
                    deps.sleep(float(poll_seconds))
            except BaseException as error:
                primary = error
            finally:
                if exit_code is None and arena is not None:
                    try:
                        exit_code = arena.poll()
                    except Exception:
                        pass
                # Record a naturally observed exit before teardown can replace
                # it with an owned shutdown status. Zero is a normal exit.
                if exit_code is not None:
                    diagnostic.event("native_exit", "arena_exit", exit_code=exit_code,
                        crash=(exit_code & 0xffffffff) != 0)
                if primary is None:
                    operation = "teardown"
                arena_safe = arena is None
                closers = [
                    (lambda: arena.stop()) if arena is not None else None,
                    (lambda: bridge.stop()) if bridge is not None else None,
                ]
                for closer in closers:
                    if closer is None:
                        continue
                    try:
                        closer()
                    except BaseException as error:
                        if primary is None:
                            primary = error
                if arena is not None:
                    arena_safe = arena.safe_to_restore()
                if prepared is not None:
                    if not arena_started:
                        prepared_closer = prepared.rollback
                    elif arena_safe:
                        prepared_closer = prepared.close
                    else:
                        prepared_closer = None
                        if primary is None:
                            primary = NativeLaunchError(
                                "startup files retained because Arena may still be running")
                    if prepared_closer is not None:
                        try:
                            prepared_closer()
                        except BaseException as error:
                            if primary is None:
                                primary = error
    except BaseException as error:
        if primary is None:
            primary = error
    if primary is not None:
        if not isinstance(primary, (KeyboardInterrupt, SystemExit)):
            diagnostic.event("launch_failed", operation, error=primary,
                code=(primary.code if isinstance(primary, LoopbackCertificateError) else "game_launch_failed"),
                exit_code=exit_code, crash=True)
        diagnostic.close()
        if isinstance(primary, (NativeLaunchError, LoopbackCertificateError, KeyboardInterrupt, SystemExit)):
            raise primary
        raise NativeLaunchError("authenticated launch failed") from None
    if exit_code is None:
        diagnostic.event("launch_failed", "arena_exit", code="game_launch_failed", crash=True)
        diagnostic.close()
        raise NativeLaunchError("Arena exited without a status")
    diagnostic.close()
    return int(exit_code)


__all__ = [
    "LaunchDependencies", "NativeLaunchError", "SessionSnapshot",
    "revalidate_session", "run_authenticated_launch", "session_snapshot",
]
