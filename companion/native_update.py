"""Recoverable migration of the signed public native payload.

The game updater alone owns client/data/wad.pack. This transaction changes
the reviewed work payload, its UI pack and both NPL DLL copies while Arena is closed.
The old native manifest remains recoverable until every new file is verified.
If signed game delivery is unavailable afterward, startup rejects the old
game WAD and the next update attempt resumes from the verified native state.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

from .client_lock import client_operation_lock
from .self_updater import _mkdir, _safe, _write
from .updater import (
    ArenaRunningError, _is_same_or_beneath, _require_safe_update_boundaries,
    is_arena_running,
)
from tools.player_native_payload import DOWNLOAD_HASHES


class NativeUpdateError(RuntimeError):
    """A native migration cannot be proved safe or completed."""


# SHA-256 values from the signed production native-payload 0.2.1 manifest.
# These are an exact migration floor, not an alternate trust root.
OLD_HASHES = {
    'work/native-battle-mode-install.json': 'c97c9cc1d71d275a167e727ddb30a73fb40c3ad6c897658872fd41fdc933c433',
    'work/private-response-key-20260911/game.dll': 'b5d1547b720fd03f1e55e76e2d41b531d2d72e0b4a6270c73223018b8cd45e06',
    'work/recent-native-fallback-20260911/receipt.json': 'e02ee57bd3bef4105fe73b06eca14c57232c9a7142fa358729eeb9caaaabcb2d',
    'work/native_ui_toolchain/fixed20_20260907_04/dui5.fixed20-ja-candidate.pack': '896693d11cd1b79f99df919856f446c95ef85888ee325c698361bae0e76c64c9',
    'work/native_ui_toolchain/fixed20_20260907_04/receipt-ja.json': '2b99058381762bc10e7da70e0dd60a6847e6b176a96392079b079f4bade36069',
    'work/local_en.native-five-mode-candidate_20260905.pack': 'f1727e367b02231532a61e875de9c6783c4c516e930d768cdc4b7abc0feb5d55',
    'work/local_en.native-five-mode-candidate_20260905.json': 'c1b53466228a3bf7a9ba8f6163c597c739182acf2d57cbf6b65a40ab7c2c5d41',
    'work/local_ja.native-five-mode-candidate_20260905.pack': '57c00e6db4266ae5c96a33c4fddd27e6cb166ecf98072163c029b78a48625104',
    'work/local_ja.native-five-mode-candidate_20260905.json': 'b52564e69ef7943d7c1c17198d8aef297a52aad525b14c90795d85fa59ae9fcc',
    'work/local_ru.native-five-mode-candidate_20260905.pack': 'bcc4159e3232c35131b356adc89c79762a30606e4643dc9da7ee0cd8ef945062',
    'work/local_ru.native-five-mode-candidate_20260905.json': 'dda5cc7ae46a4a38722c48a408040072e76f54c57c40c349c14c0e7e1c7ee492',
    'work/player-native/wad.pack': 'b03f4e48a0e4fbf87d3f936945293241ed871a27f8d467cf174a1e4a5cf39efb',
    'npl_stub/npl-base.dll': '57e21f4bb30309799ff00ce386b82ec2f5fbf6507f381803f5ae56877c5335f8',
    'npl_stub/npl-sdk.dll': 'e27de46954077a979f4b56568fa13a2f49cd5061026c5868f6262fb68aba3e45',
}
OLD_DUI5 = OLD_HASHES['work/native_ui_toolchain/fixed20_20260907_04/dui5.fixed20-ja-candidate.pack']
NEW_DUI5 = DOWNLOAD_HASHES['work/native_ui_toolchain/fixed30_20260907_01/dui5.fixed30-ja-candidate.pack']
NEW_DUI5_SOURCE = 'work/native_ui_toolchain/fixed30_20260907_01/dui5.fixed30-ja-candidate.pack'
CLIENT_DUI5 = 'client/data/dui5.pack'
LEGACY_TRANSACTION = '.twa-native-update-v1'
TRANSACTION = '.twa-native-update-024-from021'
PREVIOUS_TRANSACTION = '.twa-native-update-024-from022'
FROM_023_TRANSACTION = '.twa-native-update-024-from023'
HISTORICAL_023_FROM_021 = '.twa-native-update-023-from021'
HISTORICAL_023_FROM_022 = '.twa-native-update-023-from022'
GAME_REPAIR_TRANSACTION = '.twa-native-update-024-game-repair-'
HISTORICAL_023_GAME_REPAIR = '.twa-native-update-023-game-repair-'
# Exact signed native-payload 0.2.2 hashes, frozen for legacy recovery.
PREVIOUS_HASHES = {
    'work/native-battle-mode-install.json': '73399535ac1b444aa39da7986bf25125015043f1d0be2be584de9319ec779e52',
    'work/private-response-key-20260911/game.dll': 'b5d1547b720fd03f1e55e76e2d41b531d2d72e0b4a6270c73223018b8cd45e06',
    'work/recent-native-fallback-20260911/receipt.json': 'e02ee57bd3bef4105fe73b06eca14c57232c9a7142fa358729eeb9caaaabcb2d',
    'work/native_ui_toolchain/fixed30_20260907_01/dui5.fixed30-ja-candidate.pack': '3a7916541268a328ba8b4a8f843197883ea0d727dfc07add58513f7ee4c0ca2b',
    'work/native_ui_toolchain/fixed30_20260907_01/receipt-ja.json': 'b21d5e4c209f75b95ea62011f6813afdbb4beba82fe80f1dbbd46a7e83a17025',
    'work/local_en.native-five-mode-candidate_20260905.pack': 'f1727e367b02231532a61e875de9c6783c4c516e930d768cdc4b7abc0feb5d55',
    'work/local_en.native-five-mode-candidate_20260905.json': 'c1b53466228a3bf7a9ba8f6163c597c739182acf2d57cbf6b65a40ab7c2c5d41',
    'work/local_ja.native-five-mode-candidate_20260905.pack': '57c00e6db4266ae5c96a33c4fddd27e6cb166ecf98072163c029b78a48625104',
    'work/local_ja.native-five-mode-candidate_20260905.json': 'b52564e69ef7943d7c1c17198d8aef297a52aad525b14c90795d85fa59ae9fcc',
    'work/local_ru.native-five-mode-candidate_20260905.pack': 'bcc4159e3232c35131b356adc89c79762a30606e4643dc9da7ee0cd8ef945062',
    'work/local_ru.native-five-mode-candidate_20260905.json': 'dda5cc7ae46a4a38722c48a408040072e76f54c57c40c349c14c0e7e1c7ee492',
    'work/player-native/wad.pack': 'c959ade88fa034cd1978449e1765c3ef92077aecaa796ecb6060abb21e0e19f8',
    'npl_stub/npl-base.dll': '57e21f4bb30309799ff00ce386b82ec2f5fbf6507f381803f5ae56877c5335f8',
    'npl_stub/npl-sdk.dll': 'e27de46954077a979f4b56568fa13a2f49cd5061026c5868f6262fb68aba3e45',
}
# Exact signed native-payload 0.2.3 hashes. Keep this predecessor independent
# of the current payload so an interrupted 0.2.3 transaction can be recovered
# and an intact 0.2.3 install can migrate to the reviewed 0.2.4 candidate.
NATIVE023_HASHES = {
    'work/native-battle-mode-install.json': '73399535ac1b444aa39da7986bf25125015043f1d0be2be584de9319ec779e52',
    'work/private-response-key-20260911/game.dll': 'b5d1547b720fd03f1e55e76e2d41b531d2d72e0b4a6270c73223018b8cd45e06',
    'work/recent-native-fallback-20260911/receipt.json': 'e02ee57bd3bef4105fe73b06eca14c57232c9a7142fa358729eeb9caaaabcb2d',
    'work/native_ui_toolchain/fixed30_20260907_01/dui5.fixed30-ja-candidate.pack': '3a7916541268a328ba8b4a8f843197883ea0d727dfc07add58513f7ee4c0ca2b',
    'work/native_ui_toolchain/fixed30_20260907_01/receipt-ja.json': 'b21d5e4c209f75b95ea62011f6813afdbb4beba82fe80f1dbbd46a7e83a17025',
    'work/local_en.native-five-mode-candidate_20260905.pack': 'f1727e367b02231532a61e875de9c6783c4c516e930d768cdc4b7abc0feb5d55',
    'work/local_en.native-five-mode-candidate_20260905.json': 'c1b53466228a3bf7a9ba8f6163c597c739182acf2d57cbf6b65a40ab7c2c5d41',
    'work/local_ja.native-five-mode-candidate_20260905.pack': '57c00e6db4266ae5c96a33c4fddd27e6cb166ecf98072163c029b78a48625104',
    'work/local_ja.native-five-mode-candidate_20260905.json': 'b52564e69ef7943d7c1c17198d8aef297a52aad525b14c90795d85fa59ae9fcc',
    'work/local_ru.native-five-mode-candidate_20260905.pack': 'bcc4159e3232c35131b356adc89c79762a30606e4643dc9da7ee0cd8ef945062',
    'work/local_ru.native-five-mode-candidate_20260905.json': 'dda5cc7ae46a4a38722c48a408040072e76f54c57c40c349c14c0e7e1c7ee492',
    'work/player-native/wad.pack': 'c959ade88fa034cd1978449e1765c3ef92077aecaa796ecb6060abb21e0e19f8',
    'npl_stub/npl-base.dll': '9ab3d54d9d5f28d1ad1802a621d8e68f6f9f37f10808f8b3586d5949f32c424d',
    'npl_stub/npl-sdk.dll': '65122308d752e5a39e749737900222e5f5518b48a4a2381f10c1eff2dcc66591',
}
PREVIOUS_DUI5 = '3a7916541268a328ba8b4a8f843197883ea0d727dfc07add58513f7ee4c0ca2b'
SCHEMA = 1


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _hash_or_none(path: Path) -> str | None:
    _safe(path, missing=True)
    return _digest(path) if path.exists() else None


def _checked(path: Path, expected: str) -> Path:
    if _hash_or_none(path) != expected:
        raise NativeUpdateError('native file integrity mismatch')
    return path


def _atomic_copy(source: Path, target: Path, expected: str) -> None:
    _checked(source, expected)
    _mkdir(target.parent)
    _safe(target, missing=True)
    fd, raw = tempfile.mkstemp(prefix='.native-', suffix='.tmp', dir=target.parent)
    temporary = Path(raw)
    try:
        with source.open('rb') as inp, os.fdopen(fd, 'wb') as out:
            shutil.copyfileobj(inp, out, 1024 * 1024)
            out.flush()
            os.fsync(out.fileno())
        _checked(temporary, expected)
        _safe(target, missing=True)
        os.replace(temporary, target)
        _checked(target, expected)
    finally:
        temporary.unlink(missing_ok=True)


def _expanded(hashes: dict[str, str], client_ui: str) -> dict[str, str]:
    result = {**hashes, CLIENT_DUI5: client_ui}
    for name in ('npl-base.dll', 'npl-sdk.dll'):
        source = 'npl_stub/' + name
        if source in hashes:
            result['client/' + name] = hashes[source]
    return result


def _owned_temporary(path: Path, *, journal: bool = False) -> bool:
    pattern = r'\.launcher-[a-z0-9_]{8}' if journal else r'\.native-[a-z0-9_]{8}\.tmp'
    return re.fullmatch(pattern, path.name) is not None


class _Transition:
    """One exact predecessor and target, with a version-specific journal."""

    def __init__(self, directory: str, old: dict[str, str], new: dict[str, str],
                 old_ui: str, new_ui: str, *, client_npl_old=None,
                 candidate: bool = True):
        self.directory = directory
        self.candidate = candidate
        self.old = _expanded(old, old_ui)
        if client_npl_old is not None:
            self.old.update(client_npl_old)
        self.new = _expanded(new, new_ui)
        changed = [name for name, value in self.new.items() if self.old.get(name) != value]
        self.changed = tuple(sorted(name for name in changed if not name.startswith('client/'))
                             + sorted(name for name in changed if name.startswith('client/')))

    def old_state(self, paths) -> bool:
        return (self.matches(paths, self.old)
                and all(_hash_or_none(paths[name]) is None
                        for name in self.new.keys() - self.old.keys()))

    @staticmethod
    def matches(paths, expected) -> bool:
        return all(_hash_or_none(paths[name]) == value for name, value in expected.items())

    def journal(self, root):
        return root / self.directory / 'journal.json'

    def record(self, root, phase):
        _write(self.journal(root), json.dumps({'schemaVersion': SCHEMA, 'phase': phase},
               sort_keys=True, separators=(',', ':')).encode('ascii'))

    def read_record(self, root):
        journal = _safe(self.journal(root), missing=True)
        if not journal.exists():
            return None
        raw = journal.read_bytes()
        if len(raw) > 256:
            raise NativeUpdateError('native update journal is invalid')
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError):
            raise NativeUpdateError('native update journal is invalid') from None
        if (not isinstance(value, dict) or set(value) != {'schemaVersion', 'phase'}
                or type(value['schemaVersion']) is not int or value['schemaVersion'] != SCHEMA
                or value['phase'] not in ('preparing', 'ready', 'committed', 'rolled_back')):
            raise NativeUpdateError('native update journal is invalid')
        return value['phase']

    def backup(self, root, name):
        return root / self.directory / 'backup' / name

    def cleanup(self, root):
        directory = _safe(root / self.directory, directory=True)
        backup_dir = directory / 'backup'
        for name in self.changed:
            path = _safe(self.backup(root, name), missing=True)
            if path.exists():
                path.unlink()
        if backup_dir.exists():
            for child in sorted(backup_dir.rglob('*'), key=lambda p: len(p.parts), reverse=True):
                _safe(child, directory=child.is_dir())
                if child.is_dir():
                    child.rmdir()
                elif _owned_temporary(child):
                    child.unlink()
                else:
                    raise NativeUpdateError('native backup contains an unknown file')
            backup_dir.rmdir()
        for child in directory.iterdir():
            if child.name != 'journal.json':
                if not _owned_temporary(child, journal=True):
                    raise NativeUpdateError('native transaction contains an unknown file')
                _safe(child).unlink()
        (directory / 'journal.json').unlink()
        directory.rmdir()

    def recover(self, root, paths):
        directory = _safe(root / self.directory, directory=True, missing=True)
        if not directory.exists():
            return
        phase = self.read_record(root)
        if phase is None:
            entries = list(directory.iterdir())
            if entries and self.old_state(paths) and all(_owned_temporary(p, journal=True) for p in entries):
                for path in entries:
                    _safe(path).unlink()
                entries = []
            if not entries:
                directory.rmdir()
                return
            raise NativeUpdateError('native update journal is missing')
        if phase == 'preparing':
            if not self.old_state(paths):
                raise NativeUpdateError('incomplete native preparation changed live files')
        elif phase == 'ready':
            # Verify every rollback source before modifying any live target.
            for name, expected in self.old.items():
                if name not in self.changed and _hash_or_none(paths[name]) != expected:
                    raise NativeUpdateError('native recovery found an unknown unchanged file')
            for name in self.changed:
                old = self.old.get(name)
                if _hash_or_none(paths[name]) not in (old, self.new[name]):
                    raise NativeUpdateError('native recovery found an unknown live file')
                if old is not None:
                    _checked(self.backup(root, name), old)
            for name in self.changed:
                old = self.old.get(name)
                if old is None:
                    target = _safe(paths[name], missing=True)
                    if target.exists():
                        target.unlink()
                else:
                    _atomic_copy(self.backup(root, name), paths[name], old)
            if not self.old_state(paths):
                raise NativeUpdateError('native rollback verification failed')
            self.record(root, 'rolled_back')
        elif phase == 'committed':
            if not self.matches(paths, self.new):
                raise NativeUpdateError('committed native update was modified')
        elif not self.old_state(paths):
            raise NativeUpdateError('rolled back native update was modified')
        self.cleanup(root)

    def apply(self, root, paths, cache):
        self.record(root, 'preparing')
        _mkdir(root / self.directory / 'backup')
        for name in self.changed:
            if name in self.old:
                _atomic_copy(paths[name], self.backup(root, name), self.old[name])
        self.record(root, 'ready')
        try:
            manifest = 'work/native-battle-mode-install.json'
            names = [name for name in self.changed if name != manifest]
            if manifest in self.changed:
                names.append(manifest)
            for name in names:
                if name == CLIENT_DUI5:
                    source = cache / NEW_DUI5_SOURCE
                elif name.startswith('client/npl-'):
                    source = cache / 'npl_stub' / Path(name).name
                else:
                    source = cache / name
                _atomic_copy(source, paths[name], self.new[name])
            if not self.matches(paths, self.new):
                raise NativeUpdateError('native migration verification failed')
            self.record(root, 'committed')
        except Exception:
            self.recover(root, paths)
            raise
        self.cleanup(root)


def _transitions():
    # Historical transactions remain recoverable after a launcher update. Only
    # transitions whose target is the current signed payload can start anew.
    result = (
        _Transition(LEGACY_TRANSACTION, OLD_HASHES, PREVIOUS_HASHES, OLD_DUI5,
                    PREVIOUS_DUI5, candidate=False),
        _Transition(TRANSACTION, OLD_HASHES, DOWNLOAD_HASHES, OLD_DUI5, NEW_DUI5),
        _Transition(PREVIOUS_TRANSACTION, PREVIOUS_HASHES, DOWNLOAD_HASHES, PREVIOUS_DUI5, NEW_DUI5),
        _Transition(FROM_023_TRANSACTION, NATIVE023_HASHES, DOWNLOAD_HASHES, NEW_DUI5, NEW_DUI5),
        _Transition(HISTORICAL_023_FROM_021, OLD_HASHES, NATIVE023_HASHES,
                    OLD_DUI5, NEW_DUI5, candidate=False),
        _Transition(HISTORICAL_023_FROM_022, PREVIOUS_HASHES, NATIVE023_HASHES,
                    PREVIOUS_DUI5, NEW_DUI5, candidate=False),
    )
    # Launcher 0.2.35 migrated the native payload before the signed game
    # 0.2.2 updater restored the old client DLLs. Accept only that exact
    # state (including either partially restored pair), never arbitrary
    # user files. All work files and the client UI must already be current.
    names = ('npl-base.dll', 'npl-sdk.dll')
    if all('npl_stub/' + name in DOWNLOAD_HASHES
           and 'npl_stub/' + name in PREVIOUS_HASHES
           and DOWNLOAD_HASHES['npl_stub/' + name] != PREVIOUS_HASHES['npl_stub/' + name]
           for name in names):
        for mask in (1, 2, 3):
            client_old = {
                'client/' + name: PREVIOUS_HASHES['npl_stub/' + name]
                for index, name in enumerate(names) if mask & (1 << index)
            }
            result += (_Transition(
                HISTORICAL_023_GAME_REPAIR + str(mask), NATIVE023_HASHES, NATIVE023_HASHES,
                NEW_DUI5, NEW_DUI5, client_npl_old=client_old,
                candidate=False),)
            result += (_Transition(
                GAME_REPAIR_TRANSACTION + str(mask), DOWNLOAD_HASHES, DOWNLOAD_HASHES,
                NEW_DUI5, NEW_DUI5, client_npl_old=client_old),)
    return result


def _targets(config) -> dict[str, Path]:
    _require_safe_update_boundaries(config)
    root = _safe(config.repo_root, directory=True)
    original = _safe(config.original_dir, directory=True)
    if (_is_same_or_beneath(root, original) or _is_same_or_beneath(original, root)
            or Path(os.path.abspath(config.client_dir)) != root / 'client'):
        raise NativeUpdateError('native update boundary is invalid')
    names = set()
    for transition in _transitions():
        names.update(transition.old)
        names.update(transition.new)
    paths = {name: root / name for name in names}
    for path in paths.values():
        _safe(path, missing=True)
    return paths


def _recover(root, paths):
    transitions = _transitions()
    active = []
    for transition in transitions:
        directory = _safe(root / transition.directory, directory=True, missing=True)
        if directory.exists():
            active.append(transition)
    if len(active) > 1:
        raise NativeUpdateError('multiple native update transactions')
    if active:
        active[0].recover(root, paths)


def _record(root, phase):
    _transitions()[1].record(root, phase)


def _read_record(root):
    return _transitions()[1].read_record(root)


def _predecessor(paths):
    matches = [transition for transition in _transitions()
               if transition.candidate and transition.old_state(paths)]
    if len(matches) != 1:
        raise NativeUpdateError('unreviewed installed native payload')
    return matches[0]


def migrate_native(config, *, downloader=None, process_lister=None) -> str:
    """Migrate a reviewed predecessor or repair the exact 0.2.35 game reset."""
    paths = _targets(config)
    root = Path(os.path.abspath(config.repo_root))
    current = _expanded(DOWNLOAD_HASHES, NEW_DUI5)
    with client_operation_lock(config.client_dir):
        if is_arena_running(process_lister):
            raise ArenaRunningError('Arena.exe must close before native migration')
        _recover(root, paths)
        if _Transition.matches(paths, current):
            return 'current'
        predecessor = _predecessor(paths)
    if downloader is None:
        from .base_download import download_native
        downloader = download_native
    cache = _safe(Path(downloader(config.state_dir / 'native-downloads',
                                  channel=config.channel)), directory=True)
    for name, expected in DOWNLOAD_HASHES.items():
        _checked(cache / name, expected)
    _checked(cache / NEW_DUI5_SOURCE, NEW_DUI5)
    with client_operation_lock(config.client_dir):
        if is_arena_running(process_lister):
            raise ArenaRunningError('Arena.exe must close before native migration')
        _recover(root, paths)
        if _Transition.matches(paths, current):
            return 'current'
        transition = _predecessor(paths)
        if transition.directory != predecessor.directory:
            raise NativeUpdateError('installed native payload changed while downloading')
        transition.apply(root, paths, cache)
        return 'updated'
