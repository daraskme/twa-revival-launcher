"""Pinned native assets for the reviewed 0.2.4 QA candidate (no credentials).

This module adds a release-side hash boundary for the install manifest and
reviewed native files; local review receipts are not signatures.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil

from tools.player_package import _regular, _relative

MANIFEST = 'work/native-battle-mode-install.json'
MANIFEST_HASH = '747f3c9bf44fe25dcf916d975c7cf9c452c8d1a89ee577a4972282d6fb8be627'
GAME_HASH = 'b565fe965b33e5aa4e3197bb8710fccac17f83e3c4462cf911043aa7f6c33d01'
ARENA_HASH = 'f45d6bab7d1ed62451556970ad4f6eb5040d7ea6606f5afd212c81b487e12dc2'
WAD_HASH = 'c959ade88fa034cd1978449e1765c3ef92077aecaa796ecb6060abb21e0e19f8'
WAD = 'work/player-native/wad.pack'
NPL = {
    'npl-base.dll': '9ab3d54d9d5f28d1ad1802a621d8e68f6f9f37f10808f8b3586d5949f32c424d',
    'npl-sdk.dll': '65122308d752e5a39e749737900222e5f5518b48a4a2381f10c1eff2dcc66591',
}
# Exact allowed remote files. Executable launcher code never comes from this
# content channel; the game row points to the reviewed far terrain trial receipt.
DOWNLOAD_HASHES = {
    MANIFEST: MANIFEST_HASH,
    'work/qa041-far4096-20261002/game.dll': GAME_HASH,
    'work/qa041-far4096-20261002/receipt.json': '79119f5eaa0db95a19b2958c543ed73f60997c9b3dd4d97bbaa48590508b31c8',
    'work/native_ui_toolchain/fixed30_20260907_01/dui5.fixed30-ja-candidate.pack': '3a7916541268a328ba8b4a8f843197883ea0d727dfc07add58513f7ee4c0ca2b',
    'work/native_ui_toolchain/fixed30_20260907_01/receipt-ja.json': 'b21d5e4c209f75b95ea62011f6813afdbb4beba82fe80f1dbbd46a7e83a17025',
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
# C4BC60..D94C3D are the drop-target and bar-reorder hook anchors; the bridge
# rechecks them in memory and installs those two hooks only on an exact match.
DRAG_ANCHORS = {
    0xDBD7E0: '558bec566a018bf1e8e3c30100ff7508',
    0xDB68C0: '558bec5de9b7d70b00cccccccccccccc',
    0xC5B4E0: ('558bec83ec0c568bf18b4e1485c97405e89b32faff803d8140b011007424'
                 '6a008d4df4c6058140b01100e8617863ff8b4e18506a01e8d647f9ff8d4d'
                 'f4e87e8f'),
    0xC4BC60: '558bec81ecbc000000538b5d088bc15657538b48',
    0xC55F10: '558bec81eccc0000008b450c5356578b780c',
    0xC55FAB: '8b46088bcb8945fc8d45e050ff760ce8a15cffff',
    0xD21410: '558bec83ec4053578b7d108bcf',
    0xD21488: ('8b55f08d4b6c8b42108945f88b45088945f48d45f4508d45dc50e80940ba'
                 'ff8d5370f30f7e008b40088945f48945cc'),
    0xD214FB: ('8b45f48d4dd083c008508d45c050e86248dfffff75f88d45d08bcf5053e8'
                 'f349f3ff'),
    0xD68D90: '8b75fc8b5df8538d46405057e86f86fbff83c40c',
    0xC5A7C0: '558bec8b4914e8c5e4f8ff85c074088bc85de9991ffaff5dc20c00',
    0xD94C3D: '8b4df457ff75fcff75e8e8745becff',
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
