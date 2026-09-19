"""Guarded, process-only native profile averages; no DLL or pack writes.

Reviewed ia32 Arena profile rows store their display aggregate at +0x30.
The original maximum-points / maximum-kills columns are relabeled and rendered
as kills / battles. Only their own career comparator uses the same ratio.
Unattributed unit FreeXP is displayed as an em dash; backend totals stay intact.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

GAME_SHA256S = frozenset({
    '541d91ecfd137cb8e325d906cf193846a6b07cf4b0c9cffafcf444794f9bf641',
    '4fc11b6e734042ee0c7d0df54bc5c7f689f2d7842c450e4df541e22310804013',
    '4e622f6934e0ba552b93ef546bec5dacdb0d7ae47d28b0c823959b52fdd08f15',
    'f760ece7869a3e254376f927ee610675cab8112fafb502c6c18e90c30664fc0c',
    '884e30f841d6a1268b7cc918fa2d14b972f007ce593b957fd3d1ee93c75cbf0a',
    'b5d1547b720fd03f1e55e76e2d41b531d2d72e0b4a6270c73223018b8cd45e06',
})
UI_SHA256 = '896693d11cd1b79f99df919856f446c95ef85888ee325c698361bae0e76c64c9'

# Integer arithmetic avoids loss of precision in signed-64 native counts and
# keeps sorting exact even when displayed two-decimal means happen to match.
MATH_SOURCE = r'''
const careerAverageText = (kills, battles) => {
  if (kills < 0n || battles < 0n) throw Error('career_ui_negative_stat');
  if (battles === 0n) return '0';
  const cents = (kills * 200n + battles) / (battles * 2n);
  const whole = cents / 100n, fraction = cents % 100n;
  if (fraction === 0n) return whole.toString();
  return whole.toString() + '.' + fraction.toString().padStart(2, '0').replace(/0$/, '');
};
const careerAverageBefore = (ak, ab, bk, bb, descending) => {
  if ([ak, ab, bk, bb].some(n => n < 0n)) throw Error('career_ui_negative_stat');
  if (ab === 0n) { ak = 0n; ab = 1n; }
  if (bb === 0n) { bk = 0n; bb = 1n; }
  const left = ak * bb, right = bk * ab;
  return descending ? left > right : left < right;
};
const careerRowBefore = (a, b, descending) => {
  // One strict weak ordering for the whole target column. Unsupported rows
  // are always after measured rows, ordered by stable component identity.
  if (a.valid !== b.valid) return a.valid;
  if (!a.valid) return a.identity < b.identity;
  return careerAverageBefore(a.kills, a.battles, b.kills, b.battles, descending);
};
'''

SOURCE = r'''
(() => {
  if (Process.arch !== 'ia32') throw Error('career_ui_arch_mismatch');
  const game = Process.getModuleByName('game.dll');
  const normalize = s => s.replaceAll('/', '\\').toLowerCase();
  if (normalize(game.path) !== normalize(__GAME_PATH__)) throw Error('career_ui_path_mismatch');
  const anchors = __ANCHORS__;
  for (const [rva, expected] of anchors) {
    const actual = Array.from(new Uint8Array(game.base.add(rva).readByteArray(expected.length / 2)),
      b => b.toString(16).padStart(2, '0')).join('');
    if (actual !== expected) throw Error('career_ui_anchor_mismatch');
  }
  // These relocated vtable slots prove the class/init and callback associations.
  for (const [slot, target] of [[0x1464784,0xda7210],[0x1464888,0xda8460],
      [0x1464b9c,0xda7380],[0x1479438,0xdfb310]]) {
    if (!game.base.add(slot).readPointer().equals(game.base.add(target)))
      throw Error('career_ui_vtable_mismatch');
  }
  __MATH__
  const at = rva => game.base.add(rva);
  const wideCtor = new NativeFunction(at(0x2934e0), 'pointer', ['pointer','pointer'], 'thiscall');
  const wideDtor = new NativeFunction(at(0x294910), 'void', ['pointer'], 'thiscall');
  const narrowCtor = new NativeFunction(at(0x292d20), 'pointer', ['pointer','pointer'], 'thiscall');
  const narrowDtor = new NativeFunction(at(0x2944a0), 'void', ['pointer'], 'thiscall');
  const setText = new NativeFunction(at(0x92f1a0), 'void', ['pointer','pointer','int'], 'thiscall');
  // Frida names the ia32 Windows caller-cleanup ABI `mscdecl`, not `cdecl`.
  const find = new NativeFunction(at(0x8ff720), 'pointer', ['pointer','pointer','int'], 'mscdecl');
  const reported = new Set();
  const note = (reason, detail) => {
    const key = reason + ':' + (detail || '');
    if (reported.has(key)) return;
    reported.add(key);
    send({kind: reason, detail: detail || ''});
  };
  function text(component, value, allStates = false) {
    if (component.isNull() || component.add(0xcc).readPointer().isNull())
      throw Error('career_ui_text_component_missing');
    const object = Memory.alloc(12), chars = Memory.allocUtf16String(value);
    wideCtor(object, chars);
    try { setText(component, object, allStates ? 1 : 0); }
    finally { wideDtor(object); }
  }
  function child(parent, name) {
    if (parent.isNull()) throw Error('career_ui_parent_missing');
    const object = Memory.alloc(12), chars = Memory.allocUtf8String(name);
    narrowCtor(object, chars);
    try {
      const found = find(parent, object, 1);
      if (found.isNull()) throw Error('career_ui_child_missing');
      return found;
    } finally { narrowDtor(object); }
  }
  const rowClass = row => {
    const vtable = row.readPointer();
    if (vtable.equals(at(0x1464780))) return 'commander';
    if (vtable.equals(at(0x1464884))) return 'unit';
    return '';
  };
  function counts(row) {
    return [BigInt(row.add(0x50).readS64().toString()),
      BigInt(row.add(0x68).readS64().toString())];
  }
  function renderRow(row, expectedClass) {
    if (rowClass(row) !== expectedClass) throw Error('career_ui_row_class_mismatch');
    const [kills, battles] = counts(row);
    const value = row.add(expectedClass === 'commander' ? 0xc8 : 0xd0).readPointer();
    // The actual visible label is the nested `text` child beneath each value,
    // proven in ftp_profile at 0x106d4 / 0x14183. Sorting controls are arrows.
    const caption = child(value, 'text');
    text(caption, __AVERAGE_LABEL__, true);
    text(value, careerAverageText(kills, battles));
    // Legacy rewards have no proven per-unit FreeXP allocation. Do not present
    // a numeric zero as measured attribution. Whole-profile/commander XP stays.
    if (expectedClass === 'unit') text(row.add(0xd4).readPointer(), '\u2014');
    note('career_ui_row_adapted', expectedClass);
  }
  function headers(panel) {
    if (!panel.readPointer().equals(at(0x1464b98))) throw Error('career_ui_panel_class_mismatch');
    const commander = child(panel.add(0x194).readPointer(), 'max_points');
    const unit = child(panel.add(0x198).readPointer(), 'max_kills');
    // These are narrow arrow controls, not text headers. Their labels are in
    // each row's `text` child above. Preserve all native arrow button states.
    note('career_ui_sort_controls_verified');
  }
  for (const [rva, kind] of [[0xd873b0,'commander'],[0xd87ed0,'unit']]) {
    Interceptor.attach(at(rva), {
      onEnter() { this.careerRow = this.context.ecx; },
      onLeave() {
        try { renderRow(this.careerRow, kind); }
        catch (_) { note('career_ui_row_refused', kind); }
      }
    });
  }
  // Init/refresh verify the two dedicated native sort controls exist.
  for (const rva of [0xda7380, 0xdccdd0]) {
    Interceptor.attach(at(rva), {
      onEnter() { this.careerPanel = this.context.ecx; },
      onLeave() {
        try { headers(this.careerPanel); }
        catch (_) { note('career_ui_headers_refused'); }
      }
    });
  }
  Interceptor.attach(at(0xd5e7b0), {
    onEnter(args) {
      this.careerOrder = null;
      try {
        // Dedicated profile lambda supplies pointers to enum and direction.
        if (this.returnAddress.sub(game.base).toUInt32() !== 0xdfb325) return;
        const closure = this.context.ecx;
        const column = closure.readPointer().readU32();
        if (column !== 14 && column !== 11) return;
        const expected = column === 14 ? 'commander' : 'unit';
        const descending = closure.add(4).readPointer().readU8() !== 0;
        const rows = [args[0],args[1]].map(component => {
          const result = {valid:false, identity:component.toUInt32()};
          try {
            // Native d5e7ba only requires count > 0 and uses its first script.
            if (component.add(0x1d8).readU32() === 0) return result;
            const row = component.add(0x1dc).readPointer().readPointer();
            if (row.isNull() || rowClass(row) !== expected) return result;
            const [kills, battles] = counts(row);
            if (kills < 0n || battles < 0n) return result;
            return {...result,valid:true,kills,battles};
          } catch (_) { return result; }
        });
        this.careerOrder = careerRowBefore(rows[0], rows[1], descending) ? 1 : 0;
        if (rows.some(row => !row.valid)) note('career_ui_sort_unsupported_row');
      } catch (_) { note('career_ui_sort_refused'); }
    },
    onLeave(value) {
      if (this.careerOrder !== null) {
        value.replace(this.careerOrder);
        note('career_ui_average_sort_adapted');
      }
    }
  });
  send({kind:'career_ui_ready'});
})();
'''

# ASLR-free instruction anchors populated from the reviewed image. Absolute
# vtable values are checked as relocated pointers by SOURCE above.
ANCHORS: tuple[tuple[int, str], ...] = (
    (0x2934e0, '558bec568b75088bc6578bf9'),
    (0x294910, '568b7108'),
    (0x292d20, '558bec8b55088bc256578bf1'),
    (0x2944a0, '568b7108'),
    (0x92f1a0, '558bec83ec48807d0c008bc15356'),
    (0x8ff720, '558bec51'),
    (0xd873b0, '558bec83ec48538b5d08568bf1c745fc'),
    (0xd87ed0, '558bec83ec64538b5d08568bf1c745ec'),
    (0xda7380, '558bec83ec2056578bf1c745'),
    (0xdccdd0, '558bec83ec185356578bf9e8904afcff8bcfe8'),
    (0xd5e7b0, '558bec518b4508894dfc83b8d801'),
    (0xd5e7cf, '8b015356578b008d1cc530000000'),
    (0xd5e803, '8b45fc8b40048038007415'),
    (0xdfb310, '558bec8b450c83c104ff308b4508ff30e88b34f6ff5dc2'),
)


def build_source(root: Path) -> str:
    root = Path(root)
    from tools.client_language import current_client_language
    labels = {'EN': 'Avg. kills', 'JA': '\u5e73\u5747\u6483\u7834\u6570', 'RU': '\u0423\u0431\u0438\u0439\u0441\u0442\u0432 \u0437\u0430 \u0431\u043e\u0439'}
    for relative, accepted in (('game.dll', GAME_SHA256S), ('data/dui5.pack', {UI_SHA256})):
        path = root / 'client' / relative
        if not path.is_file() or path.is_symlink():
            raise RuntimeError('career_ui_file_missing')
        if hashlib.sha256(path.read_bytes()).hexdigest() not in accepted:
            raise RuntimeError('career_ui_file_mismatch')
    if not ANCHORS:
        raise RuntimeError('career_ui_anchors_missing')
    average_label = labels[current_client_language(root / 'client')]
    return (SOURCE.replace('__GAME_PATH__', json.dumps(str((root/'client/game.dll').resolve())))
            .replace('__ANCHORS__', json.dumps(ANCHORS))
            .replace('__MATH__', MATH_SOURCE)
            .replace('__AVERAGE_LABEL__', json.dumps(average_label)))
