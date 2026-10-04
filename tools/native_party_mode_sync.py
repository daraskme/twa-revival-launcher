"""Preserve authenticated party mode through the native startup catalog replay.

The stock wire setter can run after server discovery creates catalog rows but
before game config gives those rows display enums. Its successful match then
selects zero; the later deferred saved-mode replay publishes the old mode back
to the party. Retain only that intervening authoritative wire value, and feed
its completed catalog enum to the stock deferred replay. Ordinary user mode
selection, completed startup and other session objects are left unchanged.
After that replay, a still-registered peer selector can refresh its native view
on its initialization thread, without changing the saved solo preference.

This is process-local and composed with the existing owned helper. No DLL,
catalog row, UI file, server setting or saved preference is edited on disk.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from tools.player_native_payload import GAME_HASH as GAME_SHA256


SOURCE = r'''
(() => {
  if (Process.arch !== 'ia32') throw Error('party_mode_sync_arch');
  const game = Process.getModuleByName('game.dll');
  const normalize = value => value.replaceAll('/', '\\').toLowerCase();
  if (normalize(game.path) !== normalize(__GAME_PATH__))
    throw Error('party_mode_sync_path');
  const anchors = [
    [0xbfad50, '558bec518bc1538945fc568b98740200'],
    [0xbfade0, '558bec568bf1578bbe7402000083bf7c'],
    [0xbe28c0, '568bf18b86a801000085c074186a01508d8ef0feffffe805850100c786a8010000000000005ec20400'],
    [0xb6e3c5, 'e886c90800'],
    [0xb6d8a1, 'e8aad40800'],
    [0xb6e745, 'e806c60800'],
    [0xdd8130, '558bec568b7508578bf989b7a0000000'],
    [0xdd8161, '807d0c007451'],
    [0x1c36420, '33c083fe040f8502000000b00383fe04e91b1d1aff'],
    [0x1c364c0, '33d283f8040f850b00000050e82ffdffffe9341d1aff83f804e9191d1aff'],
  ];
  for (const [rva, expected] of anchors) {
    const bytes = new Uint8Array(game.base.add(rva).readByteArray(expected.length / 2));
    if (Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('') !== expected)
      throw Error('party_mode_sync_anchor');
  }
  const modes = new Set(['territory_pve', 'annihilation_pve', 'territory_pvp', 'annihilation_pvp']);
  const partyCallers = new Set([0xb6e3ca, 0xb6d8a6, 0xb6e74a]);
  let pending = null;
  let startupUi = null, refreshingUi = false;
  const diagnosticsEnabled = false;
  const diagnosticStart = Date.now();
  let diagnosticCalls = 0;

  function wire(text) {
    const size = text.readU32();
    if (size < 1 || size > 32) return null;
    const data = text.add(8).readPointer();
    if (data.isNull()) return null;
    const value = data.readUtf8String(size);
    return modes.has(value) ? value : null;
  }

  function completedEnum(session, wanted) {
    const manager = session.add(0x274).readPointer();
    if (manager.isNull()) return null;
    const count = manager.add(0x27c).readU32();
    if (count !== 2 && count !== 4) return null;
    const rows = manager.add(0x280).readPointer();
    if (rows.isNull()) return null;
    const names = new Set(), enums = new Set();
    let result = null;
    for (let index = 0; index < count; index++) {
      const row = rows.add(index * 0x38), name = wire(row), value = row.add(0xc).readU32();
      if (name === null || names.has(name) || value < 1 || value > 4 || enums.has(value))
        return null;
      if (count === 2 && !['territory_pvp', 'annihilation_pvp'].includes(name)) return null;
      names.add(name); enums.add(value);
      if (name === wanted) result = value;
    }
    return result;
  }

  const logicalModes = {territory_pve:0, annihilation_pve:1,
    territory_pvp:2, annihilation_pvp:4};
  const displayEnums = [1, 2, 4, 0, 3];
  function sameVtable(object, rva) {
    return !object.isNull() && object.readPointer().equals(game.base.add(rva));
  }
  function vectorContains(vector, countOffset, arrayOffset, wanted) {
    const count = vector.add(countOffset).readU32();
    if (count < 1 || count > 64) return false;
    const array = vector.add(arrayOffset).readPointer();
    if (array.isNull()) return false;
    let matches = 0;
    for (let index = 0; index < count; index++)
      if (array.add(index * 4).readPointer().equals(wanted)) matches++;
    return matches === 1;
  }
  function rememberStartupUi(invocation) {
    try {
      const selector = invocation.context.edi, session = invocation.context.ecx;
      if (!sameVtable(selector, 0x14637f4) ||
          !selector.add(0xc4).readPointer().equals(session)) return null;
      const logical = selector.add(0xa0).readU32();
      if (![0, 1, 2, 4].includes(logical)) return null;
      return {selector, session, logical, thread:Process.getCurrentThreadId()};
    } catch (_) { return null; }
  }
  function privatePartyId(party) {
    // B6E327/B6E6AD restore this 12-byte CAString; BFEC00 sends the same ID.
    // Compare only in memory. It must never appear in diagnostics or errors.
    const text = party.add(0x190), size = text.readU32();
    if (size < 1 || size > 128) return null;
    const data = text.add(8).readPointer();
    if (data.isNull()) return null;
    const value = data.readUtf8String(size);
    return value.length === size && /^[A-Za-z0-9_-]{1,128}$/.test(value) ? value : null;
  }
  function partyIdentity(session) {
    try {
      const client = session.add(0x29c).readPointer();
      if (client.isNull()) return null;
      const party = client.add(0xd37fc).readPointer();
      if (party.isNull() || !party.add(0x188).readPointer().equals(client)) return null;
      const id = privatePartyId(party);
      return id === null ? null : {client, party, id};
    } catch (_) { return null; }
  }
  function peerSelector(session, witness, identity) {
    const blocked = reason => ({selector:null, reason});
    const client = session.add(0x29c).readPointer();
    if (client.isNull()) return blocked('no_client');
    const party = client.add(0xd37fc).readPointer();
    if (party.isNull()) return blocked('no_party');
    if (identity === null || !client.equals(identity.client) || !party.equals(identity.party))
      return blocked('party_changed');
    if (privatePartyId(party) !== identity.id) return blocked('party_changed');
    if (!party.add(0x188).readPointer().equals(client)) return blocked('party_identity');
    if (party.add(0x18c).readU32() !== 4) return blocked('not_peer');
    const event = party.add(0x158), count = event.add(4).readU32();
    if (count < 1 || count > 64) return blocked('registration_count');
    const array = event.add(8).readPointer();
    if (array.isNull()) return blocked('registration_array');
    let selector = null;
    for (let index = 0; index < count; index++) {
      const listener = array.add(index * 4).readPointer();
      if (!sameVtable(listener, 0x1463918)) continue;
      const candidate = listener.sub(ptr(0x80));
      if (selector !== null) return blocked('ambiguous_selector');
      if (!sameVtable(candidate, 0x14637f4) ||
          !candidate.equals(witness.selector) ||
          !candidate.add(0xc4).readPointer().equals(session)) return blocked('selector_identity');
      if (!vectorContains(listener, 8, 12, event)) return blocked('reverse_registration');
      selector = candidate;
    }
    if (selector === null) return blocked('no_selector');
    if (selector.add(0xa0).readU32() !== witness.logical) return blocked('cache_changed');
    const widget = selector.add(0xb4).readPointer();
    if (widget.isNull() || widget.readPointer().isNull()) return blocked('switch_missing');
    // DD8130 permits an absent description widget, but assumes its controller
    // exists if the widget is present. Refuse the unsafe half-created state.
    const description = selector.add(0xc0).readPointer();
    if (!description.isNull()) {
      if (description.add(0x1d8).readU32() !== 1) return blocked('description_incomplete');
      const controllers = description.add(0x1dc).readPointer();
      if (controllers.isNull() || !sameVtable(controllers.readPointer(), 0x1459010))
        return blocked('description_incomplete');
    }
    if (!session.add(0x29c).readPointer().equals(client) ||
        !client.add(0xd37fc).readPointer().equals(party) ||
        !party.add(0x188).readPointer().equals(client) || party.add(0x18c).readU32() !== 4 ||
        privatePartyId(party) !== identity.id)
      return blocked('party_changed');
    return {selector, reason:null};
  }
  function refreshPeerUi(replay) {
    if (replay === null || refreshingUi) return null;
    const witness = startupUi;
    startupUi = null; // Consume before the native method reenters BFADE0.
    let nativeStarted = false;
    try {
      if (witness === null) return 'no_witness';
      if (pending !== null) return 'newer_authority';
      if (!witness.session.equals(replay.session)) return 'different_session';
      if (Process.getCurrentThreadId() !== witness.thread) return 'different_thread';
      if (replay.session.add(0x2bc).readU32() !== replay.value) return 'selection_changed';
      if (completedEnum(replay.session, replay.mode) !== replay.value) return 'catalog_changed';
      const logical = logicalModes[replay.mode];
      if (displayEnums[logical] !== replay.value) return 'mapping_mismatch';
      // Read current bidirectional registration, not a cached native lifetime.
      // D617E0/D5B270 replace the listener vtable and unregister on destruction.
      const target = peerSelector(replay.session, witness, replay.partyIdentity);
      if (target.selector === null) return target.reason;
      const selectView = new NativeFunction(game.base.add(0xdd8130), 'void',
        ['pointer', 'int', 'int'], 'thiscall');
      refreshingUi = true;
      // Stock party refresh uses persist=false. The peer role gate makes its
      // internal publisher a no-op; no preference, API or broad event rewrite.
      nativeStarted = true;
      selectView(target.selector, logical, 0);
      return 'refreshed';
    } catch (_) {
      // A native exception may follow partial UI work. Never label it a no-op
      // or retry it; keep raw errors out of the diagnostic record.
      return nativeStarted ? 'native_failed' : 'ui_read_error';
    }
    finally { refreshingUi = false; }
  }

  // Diagnostics share the two existing hooks: an independent observer on
  // these addresses would invalidate the startup anchors. Never emit a native
  // pointer, arbitrary string, row bytes or an uninitialized enum as a number.
  function smallEnum(value) { return value >= 0 && value <= 4 ? value : null; }
  function diagnosticState(session) {
    const result = {selected:null, saved:null, catalog_count:null, catalog:[],
      intent_mode:pending === null ? null : pending.mode,
      intent_same_session:pending === null ? null : pending.session.equals(session)};
    try {
      result.selected = smallEnum(session.add(0x2bc).readU32());
      result.saved = smallEnum(session.add(0x2b8).readU32());
      const manager = session.add(0x274).readPointer();
      if (manager.isNull()) return result;
      const count = manager.add(0x27c).readU32();
      result.catalog_count = smallEnum(count);
      if (count > 4) return result;
      const rows = manager.add(0x280).readPointer();
      if (rows.isNull()) return result;
      for (let index = 0; index < count; index++) {
        const row = rows.add(index * 0x38);
        result.catalog.push({mode:wire(row), display_enum:smallEnum(row.add(0xc).readU32())});
      }
    } catch (_) { /* Partial bounded state is useful; never serialize errors. */ }
    return result;
  }
  function diagnosticEmit(call, phase, reason) {
    if (call === null) return;
    try {
      const elapsed = Date.now() - diagnosticStart;
      if (elapsed < 0 || elapsed > 120000) return;
      send({kind:'party_mode_diagnostic', call_id:call.id, phase, call_kind:call.kind,
        elapsed_ms:elapsed, caller_rva:call.caller, requested_mode:call.mode,
        requested_enum:call.requested, effective_enum:call.effective, publish:call.publish,
        reason, ui_result:call.uiResult ?? null, ...diagnosticState(call.session)});
    } catch (_) { /* Observation must not change mode behavior. */ }
  }
  function diagnosticBegin(kind, invocation, args) {
    if (!diagnosticsEnabled || diagnosticCalls >= 48) return null;
    try {
      const elapsed = Date.now() - diagnosticStart;
      if (elapsed < 0 || elapsed > 120000) return null;
      const caller = invocation.returnAddress.sub(game.base).toUInt32();
      const call = {id:++diagnosticCalls, kind, session:invocation.context.ecx,
        caller:caller < game.size ? caller : null, mode:null, requested:null,
        effective:null, publish:null};
      if (kind === 'wire') {
        try { call.mode = wire(invocation.context.esp.add(4)); } catch (_) {}
      } else {
        call.requested = smallEnum(args[0].toUInt32());
        call.effective = call.requested;
        const publish = args[1].toUInt32();
        call.publish = publish <= 1 ? publish : null;
      }
      diagnosticEmit(call, 'enter', 'entered');
      return call;
    } catch (_) { return null; }
  }

  Interceptor.attach(game.base.add(0xbfad50), {
    onEnter() {
      this.intent = null;
      this.modeDiagnostic = diagnosticBegin('wire', this, null);
      this.modeReason = 'foreign_caller';
      const caller = this.returnAddress.sub(game.base).toUInt32();
      if (!partyCallers.has(caller)) return;
      pending = null; // A newer authoritative event invalidates an older one.
      try {
        const session = this.context.ecx, saved = session.add(0x2b8).readU32();
        // Zero means the stock deferred replay has already been consumed.
        // The uninitialized value can be arbitrary before the first setter.
        if (saved < 1 || saved > 4) { this.modeReason = 'saved_not_pending'; return; }
        const mode = wire(this.context.esp.add(4));
        if (mode === null) { pending = null; this.modeReason = 'unknown_wire'; return; }
        this.intent = { session, saved, mode, at: Date.now(), partyIdentity:partyIdentity(session) };
        this.modeReason = 'intent_cached';
      } catch (_) { pending = null; this.modeReason = 'read_error'; }
    },
    onLeave() {
      if (this.intent !== null) pending = this.intent;
      diagnosticEmit(this.modeDiagnostic, 'leave', this.modeReason);
    }
  });

  Interceptor.attach(game.base.add(0xbfade0), {
    onEnter(args) {
      this.uiReplay = null;
      this.modeDiagnostic = diagnosticBegin('enum', this, args);
      this.modeReason = 'no_intent';
      if (refreshingUi) return;
      const caller = this.returnAddress.sub(game.base).toUInt32();
      if (caller === 0xda40b2) startupUi = rememberStartupUi(this);
      else if (caller !== 0xbe28db && startupUi !== null &&
               startupUi.session.equals(this.context.ecx)) startupUi = null;
      if (pending === null) return;
      if (!pending.session.equals(this.context.ecx)) { this.modeReason = 'different_session'; return; }
      const intent = pending;
      pending = null; // One replay only; a later normal selection always wins.
      this.modeReason = 'ordinary_selection';
      if (caller !== 0xbe28db) return;
      try {
        const age = Date.now() - intent.at;
        this.modeReason = 'stale_or_changed';
        if (age < 0 || age > 30000 || args[0].toUInt32() !== intent.saved ||
            this.context.ecx.add(0x2b8).readU32() !== intent.saved) return;
        const value = completedEnum(this.context.ecx, intent.mode);
        this.modeReason = 'catalog_incomplete';
        if (value === null) return;
        // Keep the stock publisher flag and completion callback. That path
        // updates selection and naturally clears +2B8 after this call.
        args[0] = ptr(value);
        this.uiReplay = {session:this.context.ecx, mode:intent.mode, value,
          partyIdentity:intent.partyIdentity};
        this.modeReason = 'replayed';
        if (this.modeDiagnostic !== null) this.modeDiagnostic.effective = value;
        send({kind:'party_mode_replay_synchronized', mode:intent.mode, display_enum:value});
      } catch (_) {
        // Unknown/mutated native state never receives a guessed selection.
        this.modeReason = 'read_error';
      }
    },
    onLeave() {
      const uiResult = refreshPeerUi(this.uiReplay);
      if (this.modeDiagnostic !== null) this.modeDiagnostic.uiResult = uiResult;
      diagnosticEmit(this.modeDiagnostic, 'leave', this.modeReason);
    }
  });
  send({kind:'party_mode_sync_ready'});
})();
'''


def build_source(root: Path, *, diagnostics: bool = False) -> str:
    if type(diagnostics) is not bool:
        raise ValueError('party_mode_diagnostics_flag')
    game = root / 'client' / 'game.dll'
    if not game.is_file() or game.is_symlink():
        raise RuntimeError('party_mode_sync_file_missing')
    if hashlib.sha256(game.read_bytes()).hexdigest() != GAME_SHA256:
        raise RuntimeError('party_mode_sync_file_mismatch')
    source = SOURCE.replace('__GAME_PATH__', json.dumps(str(game.resolve())))
    if diagnostics:
        source = source.replace('const diagnosticsEnabled = false;', 'const diagnosticsEnabled = true;', 1)
    return source
