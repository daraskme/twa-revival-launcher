"""Signed launcher updates with a retained old-code recovery runner.

This module deliberately imports only stdlib and small retained support modules
in the recovery path. Those files are copied before installation is modified.
Runtime Python/EOS DLLs, credentials, game data and the bootstrap are not targets.
"""
from __future__ import annotations

import ast
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from .client_lock import client_operation_lock
from . import _ed25519
from .trusted_keys import RELEASE_TRUSTED_KEYS, TRUSTED_KEYS
from tools.original_paths import read_original_path

MAX_MANIFEST = 2 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
ACTIVE = '.twa-launcher-update-active.json'
FLOOR = '.twa-launcher-update-state.json'
RUNNER_FILES = ('companion/self_updater.py', 'companion/client_lock.py',
                'companion/_ed25519.py', 'companion/trusted_keys.py',
                'tools/apply_launcher_update.py', 'tools/player_bootstrap.py',
                'tools/original_paths.py')
_HEX = re.compile(r'[0-9a-f]{64}\Z')
_TX = re.compile(r'[0-9a-f]{32}\Z')
_SEGMENT = re.compile(r'[A-Za-z0-9_.-]+\Z')
_RESERVED = re.compile(r'(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?\Z', re.I)


class LauncherUpdateError(RuntimeError):
    pass


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LauncherUpdateError('duplicate update field')
        result[key] = value
    return result


def version_key(value):
    # Launcher release versions are numeric. Channels carry beta selection.
    if not isinstance(value, str) or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value):
        raise LauncherUpdateError('invalid launcher version')
    return tuple(int(part) for part in value.split('.'))


def allowed_path(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 160:
        raise LauncherUpdateError('invalid launcher update path')
    parts = value.split('/')
    if any(not _SEGMENT.fullmatch(p) or p in ('.', '..') or p.endswith('.') or _RESERVED.fullmatch(p) for p in parts):
        raise LauncherUpdateError('invalid launcher update path')
    if (value == 'companion/VERSION' or value == 'NOTICE.txt'
            or (len(parts) >= 2 and parts[0] in ('companion', 'server', 'tools')
                and value.endswith('.py') and not any(p.casefold() in ('tests', '__pycache__') for p in parts)
                and value.casefold() != 'tools/player_bootstrap.py')
            or (len(parts) == 2 and parts[0] == 'catalog' and value.endswith('.json'))):
        return value
    raise LauncherUpdateError('path is outside the launcher update set')


def _safe(path: Path, *, directory=False, missing=False) -> Path:
    path = Path(os.path.abspath(path))
    for ancestor in reversed((path, *path.parents)):
        try:
            info = ancestor.lstat()
        except FileNotFoundError:
            if missing:
                continue
            raise LauncherUpdateError('required update path is missing') from None
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise LauncherUpdateError('update paths cannot use links or junctions')
        if ancestor != path or directory:
            if not stat.S_ISDIR(info.st_mode):
                raise LauncherUpdateError('update parent is not a directory')
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise LauncherUpdateError('update target must be an unshared regular file')
    return path


def _mkdir(path: Path) -> Path:
    _safe(path, directory=True, missing=True)
    path.mkdir(parents=True, exist_ok=True)
    return _safe(path, directory=True)


def _read_json(path: Path):
    _safe(path)
    with path.open('rb') as stream:
        raw = stream.read(MAX_MANIFEST + 1)
    if len(raw) > MAX_MANIFEST:
        raise LauncherUpdateError('update record too large')
    return json.loads(raw, object_pairs_hook=_unique)


def _write(path: Path, data: bytes):
    _safe(path, missing=True)
    _mkdir(path.parent)
    fd, raw = tempfile.mkstemp(prefix='.launcher-', dir=path.parent)
    temporary = Path(raw)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _safe(path, missing=True)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _json(path, value):
    _write(path, canonical(value))


def file_record(path: Path):
    _safe(path, missing=True)
    if not path.exists():
        return None
    hasher = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            size += len(chunk)
            if size > MAX_FILE:
                raise LauncherUpdateError('launcher file too large')
            hasher.update(chunk)
    return {'sha256': hasher.hexdigest(), 'size': size}


def _copy(source, target, expected):
    if file_record(source) != expected:
        raise LauncherUpdateError('launcher file changed')
    # Bounded above; use an atomic replacement so no interpreter sees half a file.
    old_mtime = int(target.stat().st_mtime) if target.exists() else None
    _write(target, source.read_bytes())
    # Timestamp-based Python caches may otherwise reuse equal-size old code
    # when two versions are installed within one second. Keep caches invalid.
    if target.suffix == '.py' and old_mtime is not None and int(target.stat().st_mtime) == old_mtime:
        os.utime(target, (time.time(), old_mtime + 1))
    if file_record(target) != expected:
        raise LauncherUpdateError('launcher copy verification failed')


def installation(root: Path) -> Path:
    root = _safe(root, directory=True)
    _safe(root / 'companion', directory=True)
    _safe(root / 'tools', directory=True)
    config = root / 'config/paths.ini'
    if config.exists():
        _safe(config)
        if config.stat().st_size > 16384:
            raise LauncherUpdateError('invalid installation paths')
        try:
            configured = read_original_path(config)
        except (OSError, UnicodeError, ValueError):
            raise LauncherUpdateError('invalid installation paths') from None
        if not configured.is_absolute():
            raise LauncherUpdateError('original game path must be absolute')
        original = _safe(configured, directory=True, missing=True)
        a, b = str(root).casefold(), str(original).casefold()
        if a == b or a.startswith(b + os.sep) or b.startswith(a + os.sep):
            raise LauncherUpdateError('launcher and original game must be separate')
    return root


def installed_version(root):
    root = installation(root)
    path = _safe(root / 'companion/VERSION')
    if path.stat().st_size > 64:
        raise LauncherUpdateError('invalid installed version')
    version = path.read_text(encoding='ascii').strip()
    version_key(version)
    floor = _safe(root / FLOOR, missing=True)
    if floor.exists():
        saved = _read_json(floor)
        if (not isinstance(saved, dict) or set(saved) != {'version', 'manifestSha256'}
                or not isinstance(saved['manifestSha256'], str) or not _HEX.fullmatch(saved['manifestSha256'])):
            raise LauncherUpdateError('invalid launcher version floor')
        if version_key(saved['version']) > version_key(version):
            version = saved['version']
    return version


def validate_manifest(value, origin: str, channel: str):
    expected = {'schemaVersion', 'kind', 'channel', 'version', 'createdAt', 'files', 'publicKeyId', 'signature'}
    if (not isinstance(value, dict) or set(value) != expected or type(value['schemaVersion']) is not int
            or value['schemaVersion'] != 1 or value['kind'] != 'launcher' or channel not in ('stable', 'beta')
            or value['channel'] != channel or type(value['createdAt']) is not int or value['createdAt'] <= 0):
        raise LauncherUpdateError('invalid launcher manifest')
    if (not isinstance(value['publicKeyId'], str) or not re.fullmatch('[A-Za-z0-9._-]{1,64}', value['publicKeyId'])
            or not isinstance(value['signature'], str) or len(value['signature']) > 128
            or len(canonical(value)) > MAX_MANIFEST):
        raise LauncherUpdateError('invalid launcher signature fields')
    version_key(value['version'])
    from urllib.parse import urlsplit
    parsed = urlsplit(origin)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment or '\\' in origin
            or any(ord(c) <= 32 for c in origin)):
        raise LauncherUpdateError('invalid launcher update origin')
    files = value['files']
    if not isinstance(files, list) or not 1 <= len(files) <= 2048:
        raise LauncherUpdateError('invalid launcher files')
    seen, total = set(), 0
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {'path', 'sha256', 'size', 'url'}:
            raise LauncherUpdateError('invalid launcher file')
        path = allowed_path(entry['path'])
        if path.casefold() in seen:
            raise LauncherUpdateError('duplicate launcher path')
        seen.add(path.casefold())
        if (not isinstance(entry['sha256'], str) or not _HEX.fullmatch(entry['sha256'])
                or type(entry['size']) is not int or not 0 <= entry['size'] <= MAX_FILE
                or entry['url'] != f"{origin}/v1/update/object/launcher/{value['version']}/{path}"):
            raise LauncherUpdateError('invalid launcher payload')
        total += entry['size']
    if 'companion/version' not in seen or total > MAX_TOTAL:
        raise LauncherUpdateError('launcher version file missing or bundle too large')
    return value


def verify_manifest(value, origin: str, channel: str, *, trusted_keys=None):
    validate_manifest(value, origin, channel)
    keys = RELEASE_TRUSTED_KEYS if trusted_keys is None else trusted_keys
    if (not isinstance(keys, dict) or not keys
            or any(not isinstance(key, str) or not re.fullmatch('[0-9A-Fa-f]{64}', key) for key in keys.values())
            or any(key.lower() in TRUSTED_KEYS.values() for key in keys.values())):
        raise LauncherUpdateError('release signing keys not configured')
    try:
        public_key = bytes.fromhex(keys[value['publicKeyId']])
        signature = base64.b64decode(value['signature'], validate=True)
        unsigned = {key: item for key, item in value.items() if key != 'signature'}
        if not _ed25519.verify(public_key, canonical(unsigned), signature):
            raise ValueError('invalid signature')
    except (ValueError, KeyError, TypeError):
        raise LauncherUpdateError('launcher signature verification failed') from None
    return value


def transaction_dir(root, transaction):
    if not isinstance(transaction, str) or not _TX.fullmatch(transaction):
        raise LauncherUpdateError('invalid update transaction')
    return _safe(root / '.launcher-updates' / transaction, directory=True)


@contextmanager
def launcher_lock(root):
    with client_operation_lock(Path(root) / '.launcher-instance'):
        yield


def stage(root, origin, channel='stable', *, api=None, trusted_keys=None):
    root = installation(root)
    if (root / ACTIVE).exists():
        raise LauncherUpdateError('an interrupted launcher update needs recovery')
    current = installed_version(root)
    if api is None:
        from .api_client import ApiClient
        api = ApiClient(origin, current, strict_download_transport=True, total_timeout=1200)
    manifest = verify_manifest(api.launcher_update_manifest(channel), origin, channel, trusted_keys=trusted_keys)
    if version_key(manifest['version']) < version_key(current):
        raise LauncherUpdateError('launcher downgrade refused')
    records = []
    for entry in manifest['files']:
        before = file_record(root / entry['path'])
        after = {key: entry[key] for key in ('sha256', 'size')}
        records.append({'path': entry['path'], 'before': before, 'after': after})
    # Equal-version local edits are never silently replaced by a self-update.
    if version_key(manifest['version']) == version_key(current):
        if any(row['before'] != row['after'] for row in records):
            raise LauncherUpdateError('same-version launcher contents differ')
        return {'version': current, 'restartRequired': False}
    transaction = uuid.uuid4().hex
    folder = _mkdir(root / '.launcher-updates' / transaction)
    for entry, row in zip(manifest['files'], records):
        target = folder / 'payload' / entry['path']
        _mkdir(target.parent)
        if row['before'] == row['after']:
            _copy(root / entry['path'], target, row['after'])
        else:
            api.download_object(entry['url'], target, entry['sha256'], entry['size'])
        if file_record(target) != row['after']:
            raise LauncherUpdateError('staged launcher payload mismatch')
        if target.suffix == '.py':
            ast.parse(target.read_bytes(), filename=entry['path'])
    if (folder / 'payload/companion/VERSION').read_text(encoding='ascii').strip() != manifest['version']:
        raise LauncherUpdateError('launcher version payload mismatch')
    runner = {}
    for name in RUNNER_FILES:
        fingerprint = file_record(root / name)
        if fingerprint is None:
            raise LauncherUpdateError('recovery runner is not installed')
        _copy(root / name, folder / 'runner' / name, fingerprint)
        runner[name] = fingerprint
    _write(folder / 'runner/companion/__init__.py', b'')
    _json(folder / 'plan.json', {'schemaVersion': 1, 'root': str(root), 'origin': origin, 'channel': channel,
        'baseVersion': current, 'manifest': manifest, 'records': records, 'runner': runner})
    return {'version': manifest['version'], 'restartRequired': True, 'transaction': transaction}


def load_plan(root, transaction, *, trusted_keys=None):
    root = installation(root)
    folder = transaction_dir(root, transaction)
    plan = _read_json(folder / 'plan.json')
    if (not isinstance(plan, dict) or set(plan) != {'schemaVersion', 'root', 'origin', 'channel',
            'baseVersion', 'manifest', 'records', 'runner'} or type(plan['schemaVersion']) is not int
            or plan['schemaVersion'] != 1 or plan['root'] != str(root)):
        raise LauncherUpdateError('invalid launcher update plan')
    manifest = verify_manifest(plan['manifest'], plan['origin'], plan['channel'], trusted_keys=trusted_keys)
    version_key(plan['baseVersion'])
    if not isinstance(plan['records'], list) or len(plan['records']) != len(manifest['files']):
        raise LauncherUpdateError('invalid launcher snapshot')
    for entry, row in zip(manifest['files'], plan['records']):
        if (not isinstance(row, dict) or set(row) != {'path', 'before', 'after'} or row['path'] != entry['path']
                or row['after'] != {key: entry[key] for key in ('sha256', 'size')}):
            raise LauncherUpdateError('launcher plan differs from signed manifest')
        before = row['before']
        if before is not None and (not isinstance(before, dict) or set(before) != {'sha256', 'size'}
                or not isinstance(before['sha256'], str) or not _HEX.fullmatch(before['sha256'])
                or type(before['size']) is not int or not 0 <= before['size'] <= MAX_FILE):
            raise LauncherUpdateError('invalid launcher backup metadata')
    if not isinstance(plan['runner'], dict) or set(plan['runner']) != set(RUNNER_FILES):
        raise LauncherUpdateError('invalid recovery runner')
    for name, fingerprint in plan['runner'].items():
        if file_record(folder / 'runner' / name) != fingerprint:
            raise LauncherUpdateError('recovery runner changed')
    return folder, plan


def arena_running():
    import csv
    result = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'], capture_output=True,
        text=True, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    rows = list(csv.reader(result.stdout.splitlines()))
    if (result.returncode or result.stderr.strip() or not rows
            or any(len(row) != 5 or not row[1].strip().isdigit() for row in rows)):
        raise LauncherUpdateError('cannot confirm that Arena has stopped')
    return any(row[0].casefold() == 'arena.exe' for row in rows)


def _require_stopped():
    if arena_running():
        raise LauncherUpdateError('close Arena before updating the launcher')


def _clear_active(root, transaction):
    path = _safe(root / ACTIVE)
    if _read_json(path) != {'transaction': transaction}:
        raise LauncherUpdateError('active update changed')
    path.unlink()


def _journal(folder, plan):
    value = _read_json(folder / 'journal.json')
    if (not isinstance(value, dict) or set(value) != {'phase', 'rows'}
            or value['phase'] not in ('applying', 'complete', 'restored')
            or not isinstance(value['rows'], list) or len(value['rows']) != len(plan['records']) + 1
            or value['rows'][:-1] != plan['records']):
        raise LauncherUpdateError('invalid recovery journal')
    row = value['rows'][-1]
    expected_floor = canonical({'version': plan['manifest']['version'],
        'manifestSha256': hashlib.sha256(canonical(plan['manifest'])).hexdigest()})
    if (not isinstance(row, dict) or set(row) != {'path', 'before', 'after'} or row['path'] != FLOOR
            or row['after'] != {'size': len(expected_floor), 'sha256': hashlib.sha256(expected_floor).hexdigest()}):
        raise LauncherUpdateError('invalid recovery version floor')
    if row['before'] is not None:
        before = row['before']
        if (not isinstance(before, dict) or set(before) != {'size', 'sha256'}
                or type(before['size']) is not int or not 0 < before['size'] <= MAX_MANIFEST
                or not isinstance(before['sha256'], str) or not _HEX.fullmatch(before['sha256'])):
            raise LauncherUpdateError('invalid previous version floor')
    return value


def _recover_locked(root, transaction, folder, plan):
    journal = _journal(folder, plan)
    if journal['phase'] == 'complete':
        for row in journal['rows']:
            if file_record(root / row['path']) != row['after']:
                raise LauncherUpdateError('completed update was modified')
        _clear_active(root, transaction)
        return 'updated'
    # Check every backup and live target before restoring any. Never overwrite
    # a later manual edit, nor trust a backup merely because it exists.
    for row in journal['rows']:
        if row['before'] is not None and file_record(folder / 'backup' / row['path']) != row['before']:
            raise LauncherUpdateError('launcher backup changed')
        if file_record(root / row['path']) not in (row['before'], row['after']):
            raise LauncherUpdateError('launcher changed outside the update')
    for row in reversed(journal['rows']):
        target = root / row['path']
        if file_record(target) == row['before']:
            continue
        if row['before'] is None:
            _safe(target).unlink()
        else:
            _copy(folder / 'backup' / row['path'], target, row['before'])
    _json(folder / 'journal.json', {**journal, 'phase': 'restored'})
    _clear_active(root, transaction)
    return 'restored'


def recover(root, transaction, *, trusted_keys=None):
    root = installation(root)
    folder, plan = load_plan(root, transaction, trusted_keys=trusted_keys)
    with launcher_lock(root), client_operation_lock(root / 'client'):
        _require_stopped()
        if _read_json(root / ACTIVE) != {'transaction': transaction}:
            raise LauncherUpdateError('unexpected pending update')
        return _recover_locked(root, transaction, folder, plan)


def apply(root, transaction, *, trusted_keys=None, probe=None):
    """Reverify, back up all files, publish, check GUI startup, then commit.

    SystemExit/power loss intentionally leave the active journal for bootstrap
    recovery. Ordinary exceptions restore before returning to the old launcher.
    """
    root = installation(root)
    folder, plan = load_plan(root, transaction, trusted_keys=trusted_keys)
    probe = probe or probe_launcher
    with launcher_lock(root), client_operation_lock(root / 'client'):
        _require_stopped()
        if (root / ACTIVE).exists():
            raise LauncherUpdateError('pending update must be recovered first')
        if installed_version(root) != plan['baseVersion']:
            raise LauncherUpdateError('installation advanced while downloading')
        if version_key(plan['manifest']['version']) <= version_key(plan['baseVersion']):
            raise LauncherUpdateError('launcher update is not newer')
        floor = canonical({'version': plan['manifest']['version'],
            'manifestSha256': hashlib.sha256(canonical(plan['manifest'])).hexdigest()})
        _write(folder / 'payload' / FLOOR, floor)
        rows = plan['records'] + [{'path': FLOOR, 'before': file_record(root / FLOOR),
            'after': {'sha256': hashlib.sha256(floor).hexdigest(), 'size': len(floor)}}]
        for row in rows:
            if file_record(root / row['path']) != row['before']:
                raise LauncherUpdateError('launcher changed while downloading')
            if file_record(folder / 'payload' / row['path']) != row['after']:
                raise LauncherUpdateError('staged update changed before installation')
        # Backup completes before the durable write-ahead journal or any target.
        for row in rows:
            if row['before'] is not None:
                _copy(root / row['path'], folder / 'backup' / row['path'], row['before'])
        journal = {'phase': 'applying', 'rows': rows}
        _json(folder / 'journal.json', journal)
        _json(root / ACTIVE, {'transaction': transaction})
        try:
            for row in rows:
                if file_record(root / row['path']) != row['before']:
                    raise LauncherUpdateError('launcher target changed during installation')
                _copy(folder / 'payload' / row['path'], root / row['path'], row['after'])
            probe(root)
            for row in rows:
                if file_record(root / row['path']) != row['after']:
                    raise LauncherUpdateError('installed launcher verification failed')
            _json(folder / 'journal.json', {**journal, 'phase': 'complete'})
            _clear_active(root, transaction)
        except Exception:
            outcome = _recover_locked(root, transaction, folder, plan)
            if outcome != 'updated':
                raise LauncherUpdateError('launcher update failed and was restored') from None
    return {'version': plan['manifest']['version'], 'updated': True}


def probe_launcher(root):
    result = subprocess.run([sys.executable, '-B', str(root / 'tools/player_launcher.py'), '--startup-probe'],
        cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=45, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode != 0 or result.stdout.strip() != b'TWA_PLAYER_READY':
        raise LauncherUpdateError('updated launcher could not initialize')


def schedule_restart(root, transaction):
    """Do not close the GUI until its retained old-code helper acknowledges it."""
    import queue
    import threading
    root = installation(root)
    folder, _ = load_plan(root, transaction)
    command = [sys.executable, '-B', str(folder / 'runner/tools/apply_launcher_update.py'),
               '--root', str(root), '--transaction', transaction, '--wait-pid', str(os.getpid())]
    child = subprocess.Popen(command, cwd=folder / 'runner', stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    received = queue.Queue()
    def read():
        try:
            received.put(child.stdout.readline(256))
        except OSError:
            received.put(b'')
    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    try:
        line = received.get(timeout=45)
        if line.removesuffix(b'\n').removesuffix(b'\r') != f'TWA_UPDATE_READY {transaction}'.encode():
            raise LauncherUpdateError('update helper did not accept the handoff')
    except Exception:
        child.terminate()
        child.wait(timeout=10)
        raise LauncherUpdateError('could not start the update helper') from None
    finally:
        if not reader.is_alive():
            child.stdout.close()
    return child
