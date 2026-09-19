"""Install a player candidate into a NEW directory, publishing only after checks.

The selected base game is read-only. No sessions, developer settings, TLS keys,
logs, registry settings or junctions are imported from the package/source PC.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from companion.client_lock import client_operation_lock
from tools import player_package as package
from tools import player_native_payload as native
from tools import stage_client as stage
from tools.client_language import normalize_language, set_client_language
from tools.loopback_certificate import create as create_certificate


class PlayerInstallError(RuntimeError):
    pass


def core_rows(root, *, launcher_manifest=None):
    manifest = package._regular(root, 'player-core-manifest.json')
    if manifest.stat().st_size > 4 * 1024 * 1024:
        raise PlayerInstallError('invalid core manifest')
    value = json.loads(manifest.read_text(encoding='utf-8'))
    if (not isinstance(value, dict) or type(value.get('schemaVersion')) is not int
            or value.get('schemaVersion') != 1 or value.get('kind') != 'player-core-candidate'
            or value.get('publicReady') is not False):
        raise PlayerInstallError('invalid core manifest')
    rows = value.get('files')
    if not isinstance(rows, list) or not 1 <= len(rows) <= package.MAX_FILES:
        raise PlayerInstallError('invalid core file list')
    if launcher_manifest is not None:
        from companion import self_updater as update
        from companion.trusted_keys import PUBLIC_DOWNLOAD_ORIGIN
        signed = update.verify_manifest(launcher_manifest, PUBLIC_DOWNLOAD_ORIGIN, 'stable')
        if (signed['version'] != update.installed_version(root)
                or signed['version'] != (root/'companion/VERSION').read_text(encoding='ascii').strip()):
            raise PlayerInstallError('launcher must update before installation')
        retained = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != {'path','source','size','sha256'}:
                raise PlayerInstallError('invalid core file')
            try:
                update.allowed_path(row['path'])
            except update.LauncherUpdateError:
                retained.append(row)
            else:
                if row['source'] != 'code':
                    raise PlayerInstallError('invalid mutable core source')
        # The authenticated full code catalog replaces obsolete code rows.
        # Bootstrap/runtime remain checked against the original package lock.
        rows = retained + [{'path': item['path'], 'source': 'code',
                            'size': item['size'], 'sha256': item['sha256']}
                           for item in signed['files']]
    seen, total = set(), 0
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {'path', 'source', 'size', 'sha256'}
                or type(row['size']) is not int or row['size'] < 0):
            raise PlayerInstallError('invalid core file')
        name = row['path']
        package._relative(name)
        source = row['source']
        allowed = ((source == 'runtime' and name.startswith('runtime/') and package.runtime_path(name[8:]))
                   or (source == 'generated' and name == 'runtime/python311._pth')
                   or (source == 'code' and package.source_path(name)))
        if not allowed or name.casefold() in seen:
            raise PlayerInstallError('unreviewed core path')
        seen.add(name.casefold())
        actual = package._digest(package._regular(root, name))
        if actual != {'size': row['size'], 'sha256': row['sha256']}:
            raise PlayerInstallError('core integrity mismatch: ' + name)
        if source == 'generated' and (root/name).read_bytes() != package.ISOLATED_PYTHON:
            raise PlayerInstallError('invalid Python isolation')
        total += actual['size']
    required = {'runtime/'+name for name in package.RUNTIME_TOP | package.GUI_RUNTIME} | {
        'runtime/python311._pth', 'NOTICE.txt', 'Launch TWA.cmd', 'tools/player_bootstrap.py',
        'tools/player_launcher.py', 'companion/VERSION', 'catalog/native_unit_abilities.json'}
    required |= {'runtime/Lib/site-packages/frida/'+p for p in package.FRIDA_FILES}
    if not {name.casefold() for name in required} <= seen or total > package.MAX_TOTAL:
        raise PlayerInstallError('incomplete or excessive player core')
    return rows


def _write_paths(root, original):
    (root/'config').mkdir(exist_ok=True)
    (root/'config/paths.ini').write_text(f'original={original}\n', encoding='utf-8')


def verify(root):
    from companion.config import Config
    from companion.launch_preparation import _ProductionOperations
    from tools.original_paths import read_original_path
    original = read_original_path(root/'config/paths.ini')
    config = Config(repo_root=root, client_dir=root/'client', original_dir=original)
    native.rows(root)
    native.checked(root/'client', 'Arena.exe', native.ARENA_HASH)
    native.verify_game(root/'client/game.dll')
    for name, expected in native.NPL.items():
        native.checked(root/'client', name, expected)
    operations = _ProductionOperations()
    operations.verify_native_install(config)
    operations.validate_wad_catalogue(config, root/'client/data/wad.pack')
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root/'server/certs/cert.pem', root/'server/certs/key.pem')
    return {'nativeVerified': True, 'wadVerified': True, 'tlsVerified': True}


def install(source, original, destination, language='EN', *, progress=lambda message: None,
            native_source=None, launcher_manifest=None):
    progress('checking')
    source = Path(source).resolve(strict=True)
    original = Path(original).resolve(strict=True)
    native_source = source if native_source is None else Path(native_source).resolve(strict=True)
    destination = Path(os.path.abspath(destination))
    language = normalize_language(language)
    # Validate every ancestor without hiding junctions in the destination.
    for ancestor in (destination, *destination.parents):
        if os.path.lexists(ancestor) and (stage._is_reparse_point(ancestor) or not ancestor.is_dir()):
            raise PlayerInstallError('unsafe installation destination')
    if os.path.lexists(destination):
        raise PlayerInstallError('installation destination must be new')
    stage._require_disjoint_trees(original, destination)
    stage._require_disjoint_trees(native_source, destination)
    files = core_rows(source) if launcher_manifest is None else core_rows(source, launcher_manifest=launcher_manifest)
    payload = native.rows(native_source)
    required = stage._required_bytes(original)
    required += sum(row['size'] for row in files)
    # Payload is retained for launch verification and copied to the game.
    required += 2 * sum((native_source/name).stat().st_size for name, _, _ in payload)
    stage._check_free_space(destination, required + 512*1024*1024)
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True)
    staging = parent / f'.{destination.name}.install-{uuid.uuid4().hex}'
    with client_operation_lock(destination/'client'):
        if os.path.lexists(destination):
            raise PlayerInstallError('installation destination must be new')
        staging.mkdir()
        try:
            progress('copying')
            for row in files:
                target = staging/row['path']
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(package._regular(source, row['path']), target)
                if package._digest(target) != {key: row[key] for key in ('size', 'sha256')}:
                    raise PlayerInstallError('core changed during installation')
            native.copy_payload(native_source, staging)
            _write_paths(staging, original)
            # Deliberately no reference junction to the original in a player install.
            stage.stage_client(original, staging/'client', reference_creator=lambda *_: None, language='EN')
            progress('applying')
            # stage_client generated this overlay from the BASE English pack.
            # The release replaces that pack, so re-create this owned temporary
            # overlay from the new pack rather than treating it as user data.
            overlay_name = 'client/data/zz_twa_active_locale.pack'
            overlay = package._regular(staging, overlay_name)
            staged_overlay_hash = native.digest(overlay)
            native.apply_payload(staging)
            native.checked(staging, overlay_name, staged_overlay_hash).unlink()
            set_client_language(staging/'client', language, repo_root=staging, original=original)
            create_certificate(staging/'server/certs')
            # Only the explicit player release configuration may cross this boundary.
            if (source/'player-release.json').exists():
                from companion.player_release import load_player_release
                load_player_release(source, state_dir=staging/'unused-validation-state')
                shutil.copyfile(package._regular(source, 'player-release.json'), staging/'player-release.json')
            progress('verifying')
            result = verify(staging)
            receipt = {'schemaVersion': 1, 'language': language, 'publicReady': False,
                       'baseGame': str(original), **result}
            (staging/'player-install.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
            # On Windows rename refuses an existing destination, including a race.
            # Neither a partial install nor settings appear at the final path.
            os.rename(staging, destination)
            progress('complete')
            return receipt
        finally:
            # This UUID directory was created by this invocation beneath the
            # checked parent. Never delete a supplied destination or follow links.
            if staging.exists():
                if staging.parent != parent or stage._is_reparse_point(staging):
                    raise PlayerInstallError('unsafe staging cleanup')
                stage._remove_staging_tree(staging)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-game', type=Path, default=ROOT/'base-game')
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--language', choices=('JA', 'EN', 'RU'), default='EN')
    args = parser.parse_args()
    result = install(ROOT, args.base_game, args.destination, args.language,
                     progress=lambda phase: print('TWA_INSTALL ' + phase, flush=True))
    print(json.dumps(result))


if __name__ == '__main__':
    main()
