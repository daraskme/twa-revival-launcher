"""Verify the published source subset of TWA Revival launcher 0.2.43.

Usage (Python 3.8+, standard library only, no network access):

    python -I verify_release.py
    python -I verify_release.py --zip path\\to\\TWA-Launcher-0.2.43.zip

This script is self-contained: it never imports or runs code from this repository
(-I keeps Python from importing anything from this folder).
It checks that
  * the files here are the release's published code subset, with no extra files;
  * explicitly excluded game-data catalogs and four source files are absent;
  * the original stable manifest has a valid Ed25519 signature from the pinned
    release key and accounts for both published and excluded update files;
  * with --zip: the ZIP's SHA-256 equals the published value, it has no duplicate
    entries, every file in it matches the published SHA-256 list, and the
    non-secret fields of player-release.json have the published values.

It is a consistency check between this repository and the download. It is not a
proof that the code is harmless; read the code and README.md for that.
"""
import argparse
import base64
import hashlib
import json
import os
import sys
import zipfile
from pathlib import Path

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
VERSION = '0.2.43'
ORIGIN = 'https://downloads.darask.me'
RELEASE_KEY_ID = '2751aa46b0af141c'
RELEASE_PUBLIC_KEY = bytes.fromhex('b6f75c29cdefdb770c0379d1195694e2696c20421ce305b0400e9193dabda4a5')
ZIP_SHA256 = 'ff9dd3e96efbd2fbfd0ebf3536d1274c5eac93fd598d61659f4ce35a0ad7622a'
# Non-secret fields of player-release.json in the published ZIP. The EOS client
# secret is required by Epic's SDK; it is checked for presence only, never shown.
PLAYER_RELEASE = {
    'schemaVersion': 1,
    'apiBaseUrl': 'https://staging-api.darask.me',
    'eos': {
        'productId': 'f40462cc7fd747babdaf1e1de82ada5f',
        'sandboxId': 'p-8brnre23av7jyhu6c9lg3vhwvyfuf8',
        'deploymentId': 'a214a80febce4f589eea8538b51ce0e9',
        'clientId': 'xyza7891FqCrz4CmiPl3NT9yiBBIiq4T',
    },
}
REPO_EXTRAS = {'README.md', 'PUBLISHING.md', 'verify_release.py', '.gitattributes', '.gitignore',
               'manifests/launcher-stable.json', 'manifests/player-core-manifest.json'}
EXCLUDED_RELEASE_FILES = {
    'catalog/catalog.json', 'catalog/f2p_item_ids.json',
    'catalog/native_battle_consumables.json', 'catalog/native_battle_maps.json',
    'catalog/native_commander_talents.json', 'catalog/native_hangar.json',
    'catalog/native_matchmaking.json', 'catalog/native_postbattle_map_aliases.json',
    'catalog/native_unit_abilities.json', 'catalog/native_unit_equipment.json',
    'catalog/official_mappings.json',
    # Source files embedding original instruction sequences or catalog mappings.
    'tools/build_native_specialization_binding.py', 'tools/native_fixed_family_mapper.py',
    'server/local_stack.py', 'server/native_postbattle_maps.py',
}
BOOTSTRAP_FILES = {'Launch TWA.cmd', 'tools/player_bootstrap.py', 'config/preferences.template.txt'}

# --- Ed25519 verification (RFC 8032, section 6 reference algorithm) ---------------
_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    e1, e2 = (y1 - x1) * (y2 - x2) % _P, (y1 + x1) * (y2 + x2) % _P
    e3, e4 = 2 * t1 * t2 * _D % _P, 2 * z1 * z2 % _P
    e, f, g, h = e2 - e1, e4 - e3, e4 + e3, e2 + e1
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(scalar, point):
    result = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    return _P - x if (x & 1) != sign else x


def _decode(data):
    y = int.from_bytes(data, 'little')
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


_GY = 4 * _inv(5) % _P
_G = (_recover_x(_GY, 0), _GY, 1, _recover_x(_GY, 0) * _GY % _P)


def ed25519_verify(public_key, message, signature):
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a, r = _decode(public_key), _decode(signature[:32])
    s = int.from_bytes(signature[32:], 'little')
    if a is None or r is None or s >= _Q:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), 'little') % _Q
    return _equal(_mul(s, _G), _add(r, _mul(h, a)))
# -----------------------------------------------------------------------------------


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def check_manifest(name, channel, code_rows, problems):
    """Signature, identity and file list of one launcher update manifest."""
    manifest = json.loads((HERE / 'manifests' / name).read_bytes())
    try:
        signature = base64.b64decode(manifest['signature'], validate=True)
        unsigned = {key: value for key, value in manifest.items() if key != 'signature'}
        payload = json.dumps(unsigned, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        ok = manifest['publicKeyId'] == RELEASE_KEY_ID and ed25519_verify(RELEASE_PUBLIC_KEY, payload, signature)
    except (KeyError, ValueError, TypeError):
        ok = False
    if not ok:
        problems.append(f'{name}: signature is not valid for release key {RELEASE_KEY_ID}')
        return
    if (manifest.get('kind'), manifest.get('channel'), manifest.get('version')) != ('launcher', channel, VERSION):
        problems.append(f'{name}: not the {channel} launcher manifest for {VERSION}')
    by_path = {row['path']: row for row in code_rows}
    signed_paths = [row['path'] for row in manifest['files']]
    if len(signed_paths) != len(set(signed_paths)):
        problems.append(f'{name}: duplicate file paths')
    if set(signed_paths) != set(by_path) - BOOTSTRAP_FILES:
        problems.append(f'{name}: signed file set differs from the full release update set')
    for row in manifest['files']:
        code = by_path.get(row['path'])
        if code is None or (code['sha256'], code['size']) != (row['sha256'], row['size']):
            problems.append(f'{name}: {row["path"]} differs from the release file list')
        if row.get('url') != f'{ORIGIN}/v1/update/object/launcher/{VERSION}/{row["path"]}':
            problems.append(f'{name}: unexpected download URL for {row["path"]}')
    print(f'Signature OK: {name} ({channel}, {len(manifest["files"])} files) is signed by release key {RELEASE_KEY_ID}.')


def check_repository(problems):
    core = json.loads((HERE / 'manifests/player-core-manifest.json').read_bytes())
    paths = [row['path'] for row in core['files']]
    if len(paths) != len(set(paths)) or len(paths) != len({p.casefold() for p in paths}):
        raise ValueError('duplicate paths in the release file list')
    for path in paths:
        if not isinstance(path, str) or '\\' in path or ':' in path or path.startswith('/') or any(
                part in ('', '.', '..') for part in path.split('/')):
            raise ValueError('unsafe path in the release file list')
    code_rows = [row for row in core['files'] if row.get('source') == 'code']
    code_paths = {row['path'] for row in code_rows}
    if not EXCLUDED_RELEASE_FILES <= code_paths or not BOOTSTRAP_FILES <= code_paths:
        problems.append('release list does not contain the expected data/bootstrap files')
    published = [row for row in code_rows if row['path'] not in EXCLUDED_RELEASE_FILES]
    for row in published:
        if Path(row['path']).suffix not in ('.py', '.cmd', '.txt') and row['path'] != 'companion/VERSION':
            problems.append(f'non-source file in the published subset: {row["path"]}')
    expected = {row['path'] for row in published} | REPO_EXTRAS
    present = set()
    for folder, dirs, files in os.walk(HERE):
        dirs[:] = [d for d in dirs if d not in ('.git', '__pycache__')]
        for name in dirs + files:
            if (Path(folder) / name).is_symlink():
                problems.append(f'symlink in repository: {(Path(folder) / name).relative_to(HERE)}')
        for name in files:
            present.add((Path(folder) / name).relative_to(HERE).as_posix())
    for path in sorted(present - expected):
        problems.append(f'unexpected file in this repository: {path}')
    for path in sorted(expected - present):
        problems.append(f'missing from this repository: {path}')
    for row in published:
        path = HERE / row['path']
        if path.is_file():
            data = path.read_bytes()
            if (len(data), sha256(data)) != (row['size'], row['sha256']):
                problems.append(f'differs from the release: {row["path"]}')
    print(f'{len(published)} published code files compared with the release file list; '
          f'{len(present - expected)} unexpected file(s).')
    print(f'{len(EXCLUDED_RELEASE_FILES)} release files intentionally excluded (11 catalogs and 4 source files); their hashes remain in the original manifests.')
    check_manifest('launcher-stable.json', 'stable', code_rows, problems)
    return core


def check_zip(archive_path, core, problems):
    raw = archive_path.read_bytes()
    digest = sha256(raw)
    print(f'ZIP SHA-256: {digest}')
    if digest != ZIP_SHA256:
        problems.append(f'ZIP SHA-256 is not the published {VERSION} value {ZIP_SHA256}')
    with zipfile.ZipFile(archive_path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or len(names) != len({n.casefold() for n in names}):
            problems.append('ZIP contains duplicate entries')
        expected = {row['path'] for row in core['files']} | {'player-core-manifest.json', 'player-release.json'}
        for name in sorted(set(names) - expected):
            problems.append(f'unexpected file in ZIP: {name}')
        if archive.read('player-core-manifest.json') != (HERE / 'manifests/player-core-manifest.json').read_bytes():
            problems.append('player-core-manifest.json in the ZIP differs from manifests/')
        for row in core['files']:
            if row['path'] not in names:
                problems.append(f'missing in ZIP: {row["path"]}')
                continue
            data = archive.read(row['path'])
            if (len(data), sha256(data)) != (row['size'], row['sha256']):
                problems.append(f'ZIP file differs from the release list: {row["path"]}')
        release = json.loads(archive.read('player-release.json'))
        eos = release.get('eos') if isinstance(release, dict) else None
        shown = {key: value for key, value in release.items() if key != 'eos'} if isinstance(release, dict) else None
        if (not isinstance(eos, dict) or set(release) != {'schemaVersion', 'apiBaseUrl', 'eos'}
                or set(eos) != set(PLAYER_RELEASE['eos']) | {'clientSecret'}
                or not isinstance(eos.get('clientSecret'), str) or not eos['clientSecret']
                or dict(shown, eos={k: v for k, v in eos.items() if k != 'clientSecret'}) != PLAYER_RELEASE):
            problems.append('player-release.json does not have the published API address and EOS identifiers')
    print(f'{len(core["files"])} ZIP files compared with the release file list; player-release.json checked '
          '(its EOS client secret is not displayed).')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--zip', type=Path, help='downloaded TWA-Launcher-0.2.43.zip to check as well')
    args = parser.parse_args()
    problems = []
    try:
        core = check_repository(problems)
        if args.zip:
            check_zip(args.zip, core, problems)
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        problems.append(f'invalid or unreadable verification input ({type(exc).__name__})')
    if problems:
        print('FAILED:')
        for problem in problems:
            print('  -', problem)
        return 1
    print('All checks passed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
