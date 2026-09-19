"""Build a clean, hash-locked player core from an explicit reviewed file set.

This is the launcher/bridge/runtime component, not an installable game release.
It deliberately cannot collect operator settings, player state, or game copies.
Native assets, the installer, release credentials, and live acceptance must be
completed before this component can become a public player distribution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SPEC = ROOT / 'config/player-package-files.json'
MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_FILES = 12000
_SEGMENT = re.compile(r'[A-Za-z0-9_+., ()@-]+\Z')
_DEVICE = re.compile(r'(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\..*)?\Z', re.I)
RUNTIME_TOP = frozenset(('python.exe', 'pythonw.exe', 'python3.dll', 'python311.dll',
    'vcruntime140.dll', 'vcruntime140_1.dll', 'EOSSDK-Win64-Shipping.dll'))
FRIDA_FILES = frozenset(('__init__.py', 'aio.py', '_frida.pyd', '_frida.pyi', 'py.typed'))
# The isolated Python layout cannot borrow Tk from another local installation.
GUI_RUNTIME = frozenset(('Lib/tkinter/__init__.py', 'Lib/tkinter/ttk.py',
    'DLLs/_tkinter.pyd', 'DLLs/tcl86t.dll', 'DLLs/tk86t.dll',
    'tcl/tcl8.6/init.tcl', 'tcl/tk8.6/tk.tcl', 'tcl/tk8.6/ttk/ttk.tcl'))
ISOLATED_PYTHON = b'Lib\nDLLs\nLib/site-packages\n.\nimport site\n'


class PackageError(RuntimeError):
    pass


def _relative(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 240:
        raise PackageError('invalid package path')
    parts = value.split('/')
    if any(not _SEGMENT.fullmatch(p) or p in ('.', '..') or p.endswith(('.', ' '))
           or _DEVICE.fullmatch(p) for p in parts):
        raise PackageError('invalid package path')
    return parts


def _regular(root, relative):
    parts = _relative(relative)
    path = root.joinpath(*parts)
    for current in [root, *[root.joinpath(*parts[:i]) for i in range(1, len(parts)+1)]]:
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise PackageError('package sources cannot contain links')
        if current != path and not stat.S_ISDIR(info.st_mode):
            raise PackageError('package parent is not a directory')
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE:
        raise PackageError('invalid package source file')
    return path


def _digest(path, limit=MAX_FILE):
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024*1024), b''):
            size += len(block)
            if size > limit:
                raise PackageError('package source is too large')
            digest.update(block)
    return {'sha256': digest.hexdigest(), 'size': size}


def source_path(value):
    parts = _relative(value)
    return (value in ('Launch TWA.cmd', 'NOTICE.txt', 'companion/VERSION', 'config/preferences.template.txt')
        or (parts[0] in ('companion', 'server', 'tools') and value.endswith('.py')
            and not any(p in ('tests', '__pycache__') or p.startswith('test_') for p in parts))
        or (len(parts) == 2 and parts[0] == 'catalog' and value.endswith('.json')))


def source_paths(root):
    paths = json.loads(_regular(root, 'config/player-package-files.json').read_text(encoding='utf-8'))
    if not isinstance(paths, list) or not 1 <= len(paths) <= 512:
        raise PackageError('invalid reviewed source list')
    seen = set()
    for value in paths:
        allowed = source_path(value)
        if not allowed or value.casefold() in seen:
            raise PackageError('unreviewed or duplicate player source')
        seen.add(value.casefold())
    if 'NOTICE.txt' not in paths:
        raise PackageError('player runtime notices are missing from the reviewed source list')
    return paths


def runtime_path(value):
    parts = _relative(value)
    if len(parts) == 1:
        return value in RUNTIME_TOP
    if any(p in ('__pycache__', 'test', 'tests', 'ensurepip', 'idlelib', 'turtledemo') for p in parts):
        return False
    if parts[0] == 'DLLs':
        return len(parts) == 2 and Path(value).suffix in ('.dll', '.pyd')
    if parts[:2] == ['Lib', 'site-packages']:
        return len(parts) == 4 and parts[2] == 'frida' and parts[3] in FRIDA_FILES
    if parts[0] == 'Lib':
        return (Path(value).suffix in ('.py', '.pickle', '.cfg')
                and parts[-1] not in ('sitecustomize.py', 'usercustomize.py'))
    return parts[0] == 'tcl' and Path(value).suffix not in ('.py', '.pyc', '.pth', '.exe')


def inventory(root, runtime):
    """Snapshot exact bytes; no game directory or credential file is enumerated."""
    root, runtime = Path(root).resolve(strict=True), Path(runtime).resolve(strict=True)
    rows = [{'path': rel, 'source': 'code', **_digest(_regular(root, rel))}
            for rel in source_paths(root)]
    for current, directories, files in os.walk(runtime, followlinks=False):
        base = Path(current)
        # Never enter unrelated third-party libraries or native/runtime caches.
        if base == runtime:
            directories[:] = [p for p in directories if p in ('DLLs', 'Lib', 'tcl')]
        else:
            directories[:] = [p for p in directories if p not in (
                '__pycache__', 'test', 'tests', 'ensurepip', 'idlelib', 'turtledemo')]
        if base == runtime/'Lib/site-packages':
            directories[:] = [p for p in directories if p == 'frida']
        for name in files:
            rel = (base/name).relative_to(runtime).as_posix()
            if runtime_path(rel):
                rows.append({'path': 'runtime/'+rel, 'source': 'runtime',
                             **_digest(_regular(runtime, rel))})
    expected = {'runtime/'+p for p in RUNTIME_TOP | GUI_RUNTIME} | {
        'runtime/Lib/site-packages/frida/'+p for p in FRIDA_FILES}
    if not expected <= {row['path'] for row in rows}:
        raise PackageError('required player runtime is missing')
    if len(rows) > MAX_FILES or sum(row['size'] for row in rows) > MAX_TOTAL:
        raise PackageError('player core exceeds package limits')
    if len({row['path'].casefold() for row in rows}) != len(rows):
        raise PackageError('case-insensitive package path collision')
    rows.append({'path': 'runtime/python311._pth', 'source': 'generated',
                 'size': len(ISOLATED_PYTHON),
                 'sha256': hashlib.sha256(ISOLATED_PYTHON).hexdigest()})
    return {'schemaVersion': 1, 'kind': 'player-core-candidate', 'publicReady': False,
            'files': sorted(rows, key=lambda row: row['path'])}


def build(root, runtime, plan, output):
    """Publish a new ZIP only after every planned byte matches its source."""
    root, runtime, output = Path(root), Path(runtime), Path(output).absolute()
    if plan != inventory(root, runtime):
        raise PackageError('package sources changed after inventory')
    if output.exists() or not output.parent.is_dir():
        raise PackageError('package output must be new in an existing directory')
    descriptor, temporary = tempfile.mkstemp(prefix='.player-core-', suffix='.zip', dir=output.parent)
    os.close(descriptor)
    try:
        with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for row in plan['files']:
                if row['source'] == 'generated':
                    archive.writestr(row['path'], ISOLATED_PYTHON)
                    continue
                source = (_regular(root, row['path']) if row['source'] == 'code'
                          else _regular(runtime, row['path'][len('runtime/'):]))
                digest = hashlib.sha256()
                size = 0
                info = zipfile.ZipInfo(row['path'], (2026, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                with source.open('rb') as stream, archive.open(info, 'w', force_zip64=True) as target:
                    for block in iter(lambda: stream.read(1024*1024), b''):
                        size += len(block)
                        if size > row['size']:
                            raise PackageError('package source changed during copy')
                        target.write(block)
                        digest.update(block)
                if size != row['size'] or digest.hexdigest() != row['sha256']:
                    raise PackageError('package source changed during copy')
            archive.writestr('player-core-manifest.json', json.dumps(plan, indent=2))
        # Windows rename refuses an existing destination; elsewhere use a new
        # exclusive output file so a concurrent artifact is never replaced.
        with open(temporary, 'rb') as source, output.open('xb') as target:
            import shutil
            shutil.copyfileobj(source, target)
        return {'fileCount': len(plan['files']), 'bytes': output.stat().st_size,
                'sha256': _digest(output, MAX_TOTAL)['sha256'], 'publicReady': False}
    finally:
        Path(temporary).unlink(missing_ok=True)


def build_installer(root, runtime, plan, native_root, output):
    """Package the verified core and exact native payload, never machine state."""
    from tools import player_native_payload as native
    entries = native.rows(Path(native_root).resolve(strict=True))
    output = Path(output)
    if output.exists() or not output.parent.is_dir():
        raise PackageError('installer output must be new')
    with tempfile.TemporaryDirectory(prefix='.player-installer-',dir=output.parent) as directory:
        intermediate = Path(directory)/'core.zip'
        build(root,runtime,plan,intermediate)
        with zipfile.ZipFile(intermediate,'a',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
            seen = {name.casefold() for name in archive.namelist()}
            for source,target,expected in entries:
                if target.casefold() in seen:
                    raise PackageError('native/core path collision')
                seen.add(target.casefold())
                path = native.checked(Path(native_root),source,expected)
                digest = hashlib.sha256()
                with path.open('rb') as stream, archive.open(target,'w',force_zip64=True) as destination:
                    for chunk in iter(lambda:stream.read(1024*1024),b''):
                        destination.write(chunk)
                        digest.update(chunk)
                if digest.hexdigest() != expected:
                    raise PackageError('native payload changed during packaging')
        with intermediate.open('rb') as source, output.open('xb') as destination:
            import shutil
            shutil.copyfileobj(source,destination)
    return {'coreFiles':len(plan['files']),'nativeFiles':len(entries),
            'bytes':output.stat().st_size,'sha256':_digest(output,MAX_TOTAL)['sha256'],'publicReady':False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('inventory', 'build', 'installer'))
    parser.add_argument('--runtime-root', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--native-root', type=Path)
    args = parser.parse_args()
    if args.command == 'inventory':
        plan = inventory(ROOT, args.runtime_root)
        with args.plan.open('x', encoding='utf-8') as target:
            json.dump(plan, target, indent=2)
        print(json.dumps({'fileCount': len(plan['files']), 'publicReady': False}))
    else:
        if args.output is None:
            parser.error('build requires --output')
        plan = json.loads(args.plan.read_text(encoding='utf-8'))
        if args.command == 'installer':
            if args.native_root is None:
                parser.error('installer requires --native-root')
            print(json.dumps(build_installer(ROOT,args.runtime_root,plan,args.native_root,args.output)))
        else:
            print(json.dumps(build(ROOT, args.runtime_root, plan, args.output)))


if __name__ == '__main__':
    main()
