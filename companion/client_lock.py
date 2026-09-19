"""Cross-process exclusion for copied-client update and launch operations.

The lock identity is derived from the canonical copied-client directory, so
two Companion processes using the same client but different state-directory
overrides still serialize.  Windows uses a named mutex (the production
platform); POSIX uses ``flock`` on a per-user temporary file for CI/tests.
"""
from __future__ import annotations

import contextlib
import hashlib
import math
import ntpath
import os
import tempfile
import time
from pathlib import Path
from typing import Iterator


class ClientOperationLockError(RuntimeError):
    """The update/launch exclusion boundary could not be established."""


class ClientOperationLockBusy(ClientOperationLockError):
    """Another process currently owns the copied-client operation lock."""


def _client_lock_digest(client_dir: Path) -> str:
    try:
        absolute = Path(os.path.abspath(client_dir))
        canonical = absolute.resolve(strict=False)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ClientOperationLockError(
            f"cannot identify copied client for locking: {exc}"
        ) from exc
    # The real client is Windows-only.  Keep its case-insensitive identity even
    # when the same behavior is exercised by tests on another platform.
    identity = ntpath.normcase(ntpath.normpath(os.fspath(canonical)))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


@contextlib.contextmanager
def _windows_mutex(digest: str, timeout_seconds: float) -> Iterator[None]:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_mutex = kernel32.CreateMutexW
    create_mutex.argtypes = (ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR)
    create_mutex.restype = wintypes.HANDLE
    wait = kernel32.WaitForSingleObject
    wait.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    wait.restype = wintypes.DWORD
    release = kernel32.ReleaseMutex
    release.argtypes = (wintypes.HANDLE,)
    release.restype = wintypes.BOOL
    close = kernel32.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL

    handle = create_mutex(None, False, f"Local\\TWARevival.ClientOperation.{digest}")
    if not handle:
        raise ClientOperationLockError(
            f"cannot create copied-client operation mutex (winerror={ctypes.get_last_error()})"
        )
    acquired = False
    try:
        timeout_ms = min(int(timeout_seconds * 1000), 0xFFFFFFFE)
        result = wait(handle, timeout_ms)
        if result == 0x00000102:  # WAIT_TIMEOUT
            raise ClientOperationLockBusy(
                "copied-client operation lock is already held by another update or launch"
            )
        if result not in (0x00000000, 0x00000080):  # OBJECT_0 / ABANDONED
            raise ClientOperationLockError(
                f"cannot acquire copied-client operation mutex (result={result:#x}, "
                f"winerror={ctypes.get_last_error()})"
            )
        acquired = True
        yield
    finally:
        if acquired:
            release(handle)
        close(handle)


@contextlib.contextmanager
def _posix_file_lock(digest: str, timeout_seconds: float) -> Iterator[None]:
    import fcntl

    uid = getattr(os, "getuid", lambda: 0)()
    root = Path(tempfile.gettempdir()) / f"twa-revival-client-locks-{uid}"
    try:
        root.mkdir(mode=0o700, parents=False, exist_ok=True)
        if root.is_symlink() or not root.is_dir():
            raise ClientOperationLockError(
                f"copied-client lock root is not a real directory: {root}"
            )
        os.chmod(root, 0o700)
        handle = (root / f"{digest}.lock").open("a+b")
        os.chmod(handle.name, 0o600)
    except ClientOperationLockError:
        raise
    except OSError as exc:
        raise ClientOperationLockError(
            f"cannot open copied-client operation lock: {exc}"
        ) from exc

    acquired = False
    deadline = time.monotonic() + timeout_seconds
    try:
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ClientOperationLockBusy(
                        "copied-client operation lock is already held by another update or launch"
                    ) from None
                time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
            except OSError as exc:
                raise ClientOperationLockError(
                    f"cannot acquire copied-client operation lock: {exc}"
                ) from exc
        yield
    finally:
        if acquired:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        handle.close()


@contextlib.contextmanager
def client_operation_lock(
    client_dir: Path, *, timeout_seconds: float = 0.0,
) -> Iterator[None]:
    """Exclude another updater/Companion launch for one copied client.

    Acquisition is fail-fast by default.  This avoids an older updater waiting
    invisibly behind a newer one; a later explicit retry will re-read the
    durable installed-version floor before it can publish anything.
    """
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise ClientOperationLockError("lock timeout must be a non-negative number")
    if not math.isfinite(timeout_seconds) or timeout_seconds < 0:
        raise ClientOperationLockError("lock timeout must be a non-negative number")
    digest = _client_lock_digest(Path(client_dir))
    manager = (
        _windows_mutex(digest, float(timeout_seconds))
        if os.name == "nt"
        else _posix_file_lock(digest, float(timeout_seconds))
    )
    with manager:
        yield
