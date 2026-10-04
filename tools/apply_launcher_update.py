"""Retained recovery runner, launched from a verified transaction directory."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import os

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from companion import self_updater as updater
from companion.client_lock import client_operation_lock


def open_parent(pid):
    if os.name != 'nt' or pid <= 0 or pid == os.getpid():
        raise updater.LauncherUpdateError('invalid launcher parent')
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x00100000, False, pid)  # retained synchronization handle
    if not handle:
        raise updater.LauncherUpdateError('cannot retain launcher parent')
    return kernel, handle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--transaction', required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--wait-pid', type=int)
    group.add_argument('--recover', action='store_true')
    args = parser.parse_args()
    root = updater.installation(args.root)
    folder, _ = updater.load_plan(root, args.transaction)
    if Path(__file__).resolve() != folder / 'runner/tools/apply_launcher_update.py':
        raise updater.LauncherUpdateError('use the retained recovery runner')
    with client_operation_lock(root / '.launcher-update-worker'):
        if args.recover:
            updater.recover(root, args.transaction)
            return 0
        kernel, handle = open_parent(args.wait_pid)
        try:
            print(f'TWA_UPDATE_READY {args.transaction}', flush=True)
            if kernel.WaitForSingleObject(handle, 120000) != 0:
                raise updater.LauncherUpdateError('launcher did not exit')
        finally:
            kernel.CloseHandle(handle)
        outcome = 'updated'
        try:
            updater.apply(root, args.transaction)
        except Exception:
            if (root / updater.ACTIVE).exists():
                # An incomplete recovery is retained for the bootstrap; never
                # open a GUI over a mixture of old and new launcher code.
                return 1
            outcome = 'restored'
        # Bootstrap is deliberately outside the update allow-list.
        subprocess.Popen([sys.executable, '-B', str(root / 'tools/player_bootstrap.py'),
            '--update-result', outcome], cwd=root, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        raise SystemExit(1) from None
