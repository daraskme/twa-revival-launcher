"""Check that this repository and a downloaded ZIP are exactly TWA Revival launcher 0.2.25.

Usage (Python 3.8+, standard library only, no network access):

    python -I verify_release.py
    python -I verify_release.py --zip path\\to\\TWA-Launcher-0.2.25.zip

This script is self-contained: it never imports or runs code from this repository
(-I keeps Python from importing anything from this folder).
It checks that
  * the files here are exactly the release's code files, with no extra files;
  * the two update manifests carry valid Ed25519 signatures from the pinned release
    key (the same key as companion/trusted_keys.py), and list exactly those files;
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
VERSION = '0.2.25'
ORIGIN = 'https://downloads.darask.me'
RELEASE_KEY_ID = '2751aa46b0af141c'
RELEASE_PUBLIC_KEY = bytes.fromhex('b6f75c29cdefdb770c0379d1195694e2696c20421ce305b0400e9193dabda4a5')
ZIP_SHA256 = 'f06432b45e4321d15cb3f7356ab02c7dcf8525c9052a6b80ba85f669d50b252a'
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
REPO_EXTRAS = {'README.md', 'verify_release.py', '.gitattributes', 'manifests/launcher-stable.json',
               'manifests/launcher-beta.json', 'manifests/player-core-manifest.json',
               # Linux/Proton support added after the release; not part of the ZIP.
               'linux/README.md', 'linux/sitecustomize.py', 'linux/twa-proton.sh'}

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
    for row in manifest['files']:
        code = by_path.get(row['path'])
        if code is None or (code['sha256'], code['size']) != (row['sha256'], row['size']):
            problems.append(f'{name}: {row["path"]} differs from the files here')
        if row.get('url') != f'{ORIGIN}/v1/update/object/launcher/{VERSION}/{row["path"]}':
            problems.append(f'{name}: unexpected download URL for {row["path"]}')
    print(f'Signature OK: {name} ({channel}, {len(manifest["files"])} files) is signed by release key {RELEASE_KEY_ID}.')


def check_repository(problems):
    core = json.loads((HERE / 'manifests/player-core-manifest.json').read_bytes())
    code_rows = [row for row in core['files'] if row.get('source') == 'code']
    expected = {row['path'] for row in code_rows} | REPO_EXTRAS
    present = set()
    for folder, dirs, files in os.walk(HERE):
        dirs[:] = [d for d in dirs if d not in ('.git', '__pycache__')]
        for name in files:
            present.add((Path(folder) / name).relative_to(HERE).as_posix())
    for path in sorted(present - expected):
        problems.append(f'unexpected file in this repository: {path}')
    for path in sorted(expected - present):
        problems.append(f'missing from this repository: {path}')
    for row in code_rows:
        path = HERE / row['path']
        if path.is_file():
            data = path.read_bytes()
            if (len(data), sha256(data)) != (row['size'], row['sha256']):
                problems.append(f'differs from the release: {row["path"]}')
    print(f'{len(code_rows)} code files here compared with the release file list; '
          f'{len(present - expected)} unexpected file(s).')
    check_manifest('launcher-stable.json', 'stable', code_rows, problems)
    check_manifest('launcher-beta.json', 'beta', code_rows, problems)
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
    parser.add_argument('--zip', type=Path, help='downloaded TWA-Launcher-0.2.25.zip to check as well')
    args = parser.parse_args()
    problems = []
    core = check_repository(problems)
    if args.zip:
        check_zip(args.zip, core, problems)
    if problems:
        print('FAILED:')
        for problem in problems:
            print('  -', problem)
        return 1
    print('All checks passed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
