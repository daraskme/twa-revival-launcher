"""Pinned native assets for the September player candidate (no credentials).

The historical manifest is retained byte-for-byte for launch preflight. This
module adds a release-side hash boundary; local review receipts are not signatures.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil

from tools.player_package import _regular, _relative

MANIFEST = 'work/native-battle-mode-install.json'
MANIFEST_HASH = 'c97c9cc1d71d275a167e727ddb30a73fb40c3ad6c897658872fd41fdc933c433'
GAME_HASH = 'b5d1547b720fd03f1e55e76e2d41b531d2d72e0b4a6270c73223018b8cd45e06'
ARENA_HASH = 'f45d6bab7d1ed62451556970ad4f6eb5040d7ea6606f5afd212c81b487e12dc2'
WAD_HASH = 'b03f4e48a0e4fbf87d3f936945293241ed871a27f8d467cf174a1e4a5cf39efb'
WAD = 'work/player-native/wad.pack'
NPL = {
    'npl-base.dll': '57e21f4bb30309799ff00ce386b82ec2f5fbf6507f381803f5ae56877c5335f8',
    'npl-sdk.dll': 'e27de46954077a979f4b56568fa13a2f49cd5061026c5868f6262fb68aba3e45',
}
# Exact allowed remote files. Executable launcher code never comes from this
# content channel; these hashes match the existing reviewed native receipts.
DOWNLOAD_HASHES = {
    MANIFEST: MANIFEST_HASH,
    'work/private-response-key-20260911/game.dll': GAME_HASH,
    'work/recent-native-fallback-20260911/receipt.json': 'e02ee57bd3bef4105fe73b06eca14c57232c9a7142fa358729eeb9caaaabcb2d',
    'work/native_ui_toolchain/fixed20_20260907_04/dui5.fixed20-ja-candidate.pack': '896693d11cd1b79f99df919856f446c95ef85888ee325c698361bae0e76c64c9',
    'work/native_ui_toolchain/fixed20_20260907_04/receipt-ja.json': '2b99058381762bc10e7da70e0dd60a6847e6b176a96392079b079f4bade36069',
    'work/local_en.native-five-mode-candidate_20260905.pack': 'f1727e367b02231532a61e875de9c6783c4c516e930d768cdc4b7abc0feb5d55',
    'work/local_en.native-five-mode-candidate_20260905.json': 'c1b53466228a3bf7a9ba8f6163c597c739182acf2d57cbf6b65a40ab7c2c5d41',
    'work/local_ja.native-five-mode-candidate_20260905.pack': '57c00e6db4266ae5c96a33c4fddd27e6cb166ecf98072163c029b78a48625104',
    'work/local_ja.native-five-mode-candidate_20260905.json': 'b52564e69ef7943d7c1c17198d8aef297a52aad525b14c90795d85fa59ae9fcc',
    'work/local_ru.native-five-mode-candidate_20260905.pack': 'bcc4159e3232c35131b356adc89c79762a30606e4643dc9da7ee0cd8ef945062',
    'work/local_ru.native-five-mode-candidate_20260905.json': 'dda5cc7ae46a4a38722c48a408040072e76f54c57c40c349c14c0e7e1c7ee492',
    WAD: WAD_HASH,
    **{'npl_stub/' + name: expected for name, expected in NPL.items()},
}
# Invariants shared by the current DLL and the older reviewed drag bridge.
DRAG_ANCHORS = {
    0xDBD7E0: '558bec566a018bf1e8e3c30100ff7508',
    0xDB68C0: '558bec5de9b7d70b00cccccccccccccc',
    0xDC1138: 'e8d3b2d8ff8b45e8c683df02000001',
    0xC5B4E0: ('558bec83ec0c568bf18b4e1485c97405e89b32faff803d8140b011007424'
                 '6a008d4df4c6058140b01100e8617863ff8b4e18506a01e8d647f9ff8d4d'
                 'f4e87e8f'),
}


class NativePayloadError(RuntimeError):
    pass


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def checked(root, relative, expected):
    path = _regular(root, relative)
    if digest(path) != expected:
        raise NativePayloadError('native asset integrity mismatch: ' + relative)
    return path


def validate_drag_anchors(data):
    # All reviewed anchors live in the same original PE section (RVA - 0xc00).
    # A release hash is also mandatory in verify_game; anchors alone never trust a DLL.
    for rva, hex_bytes in DRAG_ANCHORS.items():
        expected = bytes.fromhex(hex_bytes)
        if data[rva - 0xC00:rva - 0xC00 + len(expected)] != expected:
            raise NativePayloadError(f'drag anchor mismatch: {rva:#x}')


def verify_game(path):
    if digest(path) != GAME_HASH:
        raise NativePayloadError('unreviewed release game DLL')
    validate_drag_anchors(Path(path).read_bytes())


def rows(root, *, live_source=False):
    root = Path(root).resolve(strict=True)
    manifest = checked(root, MANIFEST, MANIFEST_HASH)
    value = json.loads(manifest.read_text(encoding='utf-8'))
    result = [(MANIFEST, MANIFEST, MANIFEST_HASH)]
    for item in value['files']:
        source = item['source'].replace('\\', '/')
        _relative(source)
        result.append((source, source, item['sha256']))
        receipt = value['receipts'][item['destination']]
        name = receipt['path'].replace('\\', '/')
        result.append((name, name, receipt['sha256']))
    result.append(('client/data/wad.pack' if live_source else WAD, WAD, WAD_HASH))
    result.extend(('npl_stub/' + name, 'npl_stub/' + name, expected)
                  for name, expected in NPL.items())
    for source, target, expected in result:
        checked(root, source, expected)
    game = next(item for item in value['files'] if item['destination'] == 'game.dll')
    verify_game(root / game['source'])
    return result


def copy_payload(source, destination, *, live_source=False):
    entries = rows(source, live_source=live_source)
    for relative, target, expected in entries:
        path = Path(destination) / target
        if path.exists():
            raise NativePayloadError('native payload destination already exists')
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(checked(source, relative, expected), path)
        checked(destination, target, expected)
    return len(entries)


def apply_payload(root):
    rows(root)
    manifest = json.loads((root / MANIFEST).read_text(encoding='utf-8'))
    files = [(item['source'], item['destination'], item['sha256']) for item in manifest['files']]
    files.append((WAD, 'data/wad.pack', WAD_HASH))
    files.extend(('npl_stub/' + name, name, expected) for name, expected in NPL.items())
    for source, target, expected in files:
        destination = root / 'client' / target
        shutil.copyfile(checked(root, source.replace('\\', '/'), expected), destination)
        checked(root / 'client', target, expected)
    checked(root / 'client', 'Arena.exe', ARENA_HASH)
    verify_game(root / 'client/game.dll')
