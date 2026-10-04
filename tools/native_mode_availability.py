"""Remove retired ranked-season UI requirements from the five-mode selector.

Territory PvP occupies the old ranked display slot. The native server-list
availability check succeeds, but DE1F70 then replaces its state with disabled
when no ranked season exists. Its two Play-button checks repeat that test.
The three season UI callers are adapted. The stock squad tier-spread limit is
raised from 1 to 9 for the owned sandbox launch: all selectable tiers I-X are
combat-normalized to X by the authenticated server. Native ownership, squad
size, tier bounds, authentication and battle-result validation remain intact.
The change is process-local and requires exact DLL/UI hashes, comparison
anchors, relocated operands and the original DWORD before any mutation.
The reviewed DLL/UI files are never modified on disk.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from tools.player_native_payload import GAME_HASH

GAME_SHA256 = '541d91ecfd137cb8e325d906cf193846a6b07cf4b0c9cffafcf444794f9bf641'
PRIVATE_RESPONSE_GAME_SHA256 = '4fc11b6e734042ee0c7d0df54bc5c7f689f2d7842c450e4df541e22310804013'
RECENT_FALLBACK_GAME_SHA256 = '4e622f6934e0ba552b93ef546bec5dacdb0d7ae47d28b0c823959b52fdd08f15'
GAME_SHA256S = frozenset({GAME_SHA256, PRIVATE_RESPONSE_GAME_SHA256, RECENT_FALLBACK_GAME_SHA256, 'f760ece7869a3e254376f927ee610675cab8112fafb502c6c18e90c30664fc0c', '884e30f841d6a1268b7cc918fa2d14b972f007ce593b957fd3d1ee93c75cbf0a', 'b5d1547b720fd03f1e55e76e2d41b531d2d72e0b4a6270c73223018b8cd45e06', GAME_HASH})
UI_SHA256 = '3a7916541268a328ba8b4a8f843197883ea0d727dfc07add58513f7ee4c0ca2b'

# The stock 55563 UDP port can be reserved by Windows even with no listener.
# Only the owned, hash-verified process changes; disk images and OS reservations
# remain intact. The bridge and its authenticated readiness proof use 19063.
REGION_PING_SOURCE = r'''
(() => {
  if (Process.arch !== 'ia32') throw Error('region_ping_arch');
  const game = Process.getModuleByName('game.dll');
  const normalize = value => value.replaceAll('/', '\\').toLowerCase();
  if (normalize(game.path) !== normalize(__GAME_PATH__)) throw Error('region_ping_path');
  // mov dword ptr [ebp-0xc], 55563; call the native endpoint constructor.
  const site = game.base.add(0xbe442f);
  const original = 'c745f40bd90000e8e500ffff';
  const installed = 'c745f4774a0000e8e500ffff';
  const read = () => Array.from(new Uint8Array(site.readByteArray(12)),
    byte => byte.toString(16).padStart(2, '0')).join('');
  if (read() !== original) throw Error('region_ping_anchor');
  try {
    Memory.patchCode(site.add(3), 4, writable => writable.writeByteArray([0x77, 0x4a, 0, 0]));
    if (read() !== installed) throw Error('region_ping_write');
  } catch (error) {
    Memory.patchCode(site.add(3), 4, writable => writable.writeByteArray([0x0b, 0xd9, 0, 0]));
    throw error;
  }
  send({kind:'native_region_ping_ready', port:19063});
})();
'''

SOURCE = r'''
(() => {
  if (Process.arch !== 'ia32') throw Error('mode_availability_arch_mismatch');
  const game = Process.getModuleByName('game.dll');
  const normalize = s => s.replaceAll('/', '\\').toLowerCase();
  if (normalize(game.path) !== normalize(__GAME_PATH__))
    throw Error('mode_availability_path_mismatch');
  const anchors = [
    [0xc4fa10, '568bf18b4e1485c9'],
    [0xde1fa9, 'e862dae6ff84c0741b'],
    [0xdf7bfa, 'e8117ee5ff84c0750a'],
    [0xdf88fc, 'e80f71e5ff84c07509'],
    // The normal mode-list check runs immediately before the row override.
    [0xde1f88, 'e8f36ef8ff'],
  ];
  for (const [rva, expected] of anchors) {
    const bytes = new Uint8Array(game.base.add(rva).readByteArray(expected.length / 2));
    const actual = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
    if (actual !== expected) throw Error('mode_availability_anchor_mismatch');
  }
  // All seven absolute references to the stock tier-spread constant are
  // read-only UI comparisons/selection checks in this exact PE. Validate
  // relocated operands separately: ASLR changes their absolute addresses.
  const tierSpread = game.base.add(0x16044f8);
  const tierReferences = [
    [0xd08157, '8b0d'], [0xd0820c, '3b05'], [0xd08223, '8b0d'],
    [0xdf7c1f, '3b05'], [0xdf8724, '3b0d'], [0xdf8733, '3b35'],
    [0xdf8b37, '3b05'],
  ];
  for (const [rva, opcode] of tierReferences) {
    const instruction = game.base.add(rva);
    const actual = Array.from(new Uint8Array(instruction.readByteArray(2)),
      b => b.toString(16).padStart(2, '0')).join('');
    if (actual !== opcode || !instruction.add(2).readPointer().equals(tierSpread))
      throw Error('mode_tier_spread_anchor_mismatch');
  }
  if (tierSpread.readU32() !== 1)
    throw Error('mode_tier_spread_original_mismatch');
  const tierRegion = Process.findRangeByAddress(tierSpread);
  if (tierRegion === null || !tierRegion.protection.includes('w'))
    throw Error('mode_tier_spread_not_writable');
  // Valid original unit tiers are 1..10; the largest allowed spread is 9.
  tierSpread.writeU32(9);
  if (tierSpread.readU32() !== 9) throw Error('mode_tier_spread_write_failed');
  const callers = new Set([0xde1fae, 0xdf7bff, 0xdf8901]);
  const reported = new Set();
  Interceptor.attach(game.base.add(0xc4fa10), {
    onEnter() { this.caller = this.returnAddress.sub(game.base).toUInt32(); },
    onLeave(value) {
      if (!callers.has(this.caller)) return;
      // This returns "season requirement satisfied" only to the selector's
      // legacy UI checks. It never makes an unadvertised mode available:
      // DE1FAE preserves the state already produced by D68E80 in that case.
      value.replace(1);
      if (!reported.has(this.caller)) {
        reported.add(this.caller);
        send({kind:'mode_season_ui_adapted', caller_rva:this.caller});
      }
    }
  });
  send({kind:'mode_availability_ready'});
})();
'''

# The retired first-battle tutorial also resets the saved mode whenever a
# fresh profile has tutorial_progress=0 (D69AC0 -> D69D06). The native profile
# update then rebuilds the selector from that zero, including after a match.
# Retire only that two-byte write; ordinary preference access and user choices
# keep their storage. No per-frame callbacks or instruction relocation are
# needed. The surrounding calls, stack restoration and return stay intact.
TUTORIAL_MODE_SOURCE = r'''
(() => {
  if (Process.arch !== 'ia32') throw Error('tutorial_mode_arch');
  const game = Process.getModuleByName('game.dll');
  const normalize = value => value.replaceAll('/', '\\').toLowerCase();
  if (normalize(game.path) !== normalize(__GAME_PATH__))
    throw Error('tutorial_mode_path');
  const anchors = [
    [0x17a120, '558bec8b450883f871770e'],
    [0xd69ced, '85db7517e8faedf6ff6a61'],
    [0xd69d03, 'ff500c89185f5e5b8be55dc3'],
  ];
  for (const [rva, expected] of anchors) {
    const bytes = new Uint8Array(game.base.add(rva).readByteArray(expected.length / 2));
    if (Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('') !== expected)
      throw Error('tutorial_mode_anchor');
  }
  const reset = game.base.add(0xd69d06);
  Memory.patchCode(reset, 2, writable => writable.writeByteArray([0x90, 0x90]));
  const installed = new Uint8Array(reset.readByteArray(2));
  if (installed[0] !== 0x90 || installed[1] !== 0x90)
    throw Error('tutorial_mode_write_failed');
})();
'''


PUBLIC_PVP_PREFERENCE_SOURCE = r'''
(() => {
  if (Process.arch !== 'ia32') throw Error('public_pvp_preference_arch');
  const game = Process.getModuleByName('game.dll');
  const normalize = value => value.replaceAll('/', '\\').toLowerCase();
  if (normalize(game.path) !== normalize(__GAME_PATH__)) throw Error('public_pvp_preference_path');
  const getter = game.base.add(0x17a120);
  const anchor = '558bec8b450883f871770e';
  const actual = Array.from(new Uint8Array(getter.readByteArray(anchor.length / 2)),
    byte => byte.toString(16).padStart(2, '0')).join('');
  if (actual !== anchor) throw Error('public_pvp_preference_anchor');
  // Option 0x61 is a logical UI index. Both its reader and writer use this
  // accessor, which returns the address of its value, not the value itself.
  // Convert retired public PvE preferences before any stock view restores
  // them. Private (3), Territory PvP (2), Annihilation PvP (4) remain intact.
  Interceptor.attach(getter, {
    onEnter(args) { this.isMode = args[0].toUInt32() === 0x61; },
    onLeave(value) {
      if (!this.isMode || value.isNull()) return;
      const range = Process.findRangeByAddress(value);
      if (range === null || !range.protection.includes('w')) return;
      const saved = value.readU32();
      if (saved === 0 || saved === 1) value.writeU32(saved === 0 ? 2 : 4);
    }
  });
})();
'''


def build_source(root: Path, *, public_pvp_only: bool = False) -> str:
    if type(public_pvp_only) is not bool:
        raise ValueError('invalid_public_pvp_only')
    game_digest = None
    for relative, digest in (('game.dll', GAME_SHA256), ('data/dui5.pack', UI_SHA256)):
        path = root / 'client' / relative
        if not path.is_file() or path.is_symlink():
            raise RuntimeError('mode_availability_file_missing')
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual not in (GAME_SHA256S if relative == 'game.dll' else {digest}):
            raise RuntimeError('mode_availability_file_mismatch')
        if relative == 'game.dll':
            game_digest = actual
    source = (REGION_PING_SOURCE + SOURCE).replace(
        '__GAME_PATH__', json.dumps(str((root/'client/game.dll').resolve())))
    try:
        from . import native_party_mode_sync
    except ImportError:
        import native_party_mode_sync
    if game_digest == native_party_mode_sync.GAME_SHA256:
        source += '\n' + native_party_mode_sync.build_source(root)
        source += '\n' + TUTORIAL_MODE_SOURCE.replace(
            '__GAME_PATH__', json.dumps(str((root/'client/game.dll').resolve())))
        if public_pvp_only:
            source += '\n' + PUBLIC_PVP_PREFERENCE_SOURCE.replace(
                '__GAME_PATH__', json.dumps(str((root/'client/game.dll').resolve())))
        try:
            from . import native_retreat_destination
        except ImportError:
            import native_retreat_destination
        source += '\n' + native_retreat_destination.build_source(root)
    return source
