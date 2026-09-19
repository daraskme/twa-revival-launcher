#!/usr/bin/env python3
"""Build the guarded Frida source for the native specialization buttons.

This is deliberately a source builder, not a second process agent.  The
returned fragment is intended to be composed into ``unit_drag_bridge`` so the
existing one-session/mutex boundary remains authoritative.  It binds the two
new DUI widgets to the *existing* ``ArenaTechTreePanel`` callback object and
only emits an action-name observation.  It cannot purchase or respec by
itself: the host must first bind the displayed tree to an authoritative
commander key and raw profile watermark.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GAME = ROOT / "client" / "game.dll"
EXPECTED_SHA256 = (
    "b41fe1b5ed2c055e7d2078254123d536a37186fa5c7aa9783c5b206cb50ebe9f"
)
IMAGE_FILE_DELTA = 0xC00
SETUP_RVA = 0xDAB970
LOOKUP_RVA = 0x8FF720
STRING_CTOR_RVA = 0x292D20
STRING_DTOR_RVA = 0x2944A0
REGISTER_RVA = 0xBC0F10
EVENT_RVA = 0xE0EB10
OWNER_DTOR_RVA = 0xD61F00
UPDATE_RVA = 0xDBF000
STOCK_SOURCE_BIND_RVA = 0xDAC185
ATTACHMENT_SCAN_RVA = 0x8FFA40
EVENT_SOURCE_RVA = 0xE0EB21
CALLBACK_NOTIFICATION_RVA = 0xCD8350
DISPLAYED_COMMANDER_RESOLVER_RVA = 0xD74AD0
OWNER_VTABLE_RVA = 0x146576C
EMBEDDED_CALLBACK_VTABLE_RVA = 0x1465870
BSS_RVA = 0x1B4A100
MANAGER_INNER_PROFILE_OFFSET = 0x14C
INNER_INSTANCE_MAP_OFFSET = 0x68
INNER_SAVED_OFFSET = 0x278
PROFILE_PAYLOAD_IID_OFFSET = 0x08
PROFILE_PAYLOAD_DEFINITION_OFFSET = 0x18
CA_STRING_COMPARE_RVA = 0x295290
NAMES = ("revival_purchase_talent_point", "revival_respec_commander")

# Full on-disk proof anchors.  Some intentionally include preferred-base
# absolute operands; RUNTIME_ANCHORS truncates before each relocated operand.
ANCHORS = {
    SETUP_RVA: bytes.fromhex(
        "558bec83ec1853568bd98d4df4685cac4611e899734eff6a018d45f450ff7304"
        "e88b3db5ff83c40c8983c4000000"
    ),
    LOOKUP_RVA: bytes.fromhex("558bec518b0d78a8a1115356578b71048bd98b7d0c"),
    STRING_CTOR_RVA: bytes.fromhex("558bec8b55088bc256578bf18d7801908a084084c975f9"),
    STRING_DTOR_RVA: bytes.fromhex("568b710881fe56c77711742585f67421"),
    # Full body through RET: [container+8] data, [container+4] count, compare
    # existing entries with callback, otherwise append then call callback+8.
    REGISTER_RVA: bytes.fromhex(
        "558bec568bf18b46088b56048d14903bc274128b4d083908740783c0043bc275f5"
        "3bc275148d45088bce50e8500587ff8b4d08568b01ff50085e5dc20400"
    ),
    EVENT_RVA: bytes.fromhex("558bec83ec64538b5d08565768384c3e118b3b8bf1"),
    # The callback receives the listener container, dereferences its source
    # pointer, and compares the source component's CA name at +0x94.
    EVENT_SOURCE_RVA: bytes.fromhex(
        "8b3b8bf181c79400000057e85f6748ff83c40884c0"
    ),
    # Embedded callback vtable slot +8 is called synchronously when a listener
    # is newly appended.  It records the listener container in the callback's
    # reciprocal list; the generic callback destructor removes both sides.
    CALLBACK_NOTIFICATION_RVA: bytes.fromhex(
        "558bec8b410c8b5108578d79048d14908b410c3bc274148b4d08"
        "8d9b000000003908740783c0043bc275f58b5708568b77048d14b2"
        "5e3bc2750b8d45088bcf50e8fb9075ff5f5dc20400"
    ),
    OWNER_DTOR_RVA: bytes.fromhex("558bec568bf1e845a6fffff64508017409"),
    UPDATE_RVA: bytes.fromhex("558bec83ec2c"),
    # Stock unlock-link binding: the lookup-returned UI component owns an
    # attachment-record vector at +1D8/+1DC.  Record zero's first pointer is
    # an attached controller; controller+0x74 is the listener container.
    STOCK_SOURCE_BIND_RVA: bytes.fromhex(
        "85f6742183bed80100000076188b86dc0100008b0885c9740c"
        "8d437083c17450e8664de1ff"
    ),
    # The same component vector is iterated as 0x28-byte records, not as a
    # pointer array or a recursive UI-child tree.
    ATTACHMENT_SCAN_RVA: bytes.fromhex(
        "558bec51538bd95657895dfc8b83d80100008d14808b83dc010000"
        "8bf08d3cd03bf7741e8b5d088d46045350e8df5799ff83c40884c0"
        "750783c6283bf775e8"
    ),
    DISPLAYED_COMMANDER_RESOLVER_RVA: bytes.fromhex(
        "558bec83ec18568bf15783becc00000000745c"
    ),
    # Resolver body: pass owner+0xCC into the two canonical-key builders,
    # compare their bounded outputs, and return the matched node payload at
    # +0x10.  This is the provenance used by displayedIdentity below.
    DISPLAYED_COMMANDER_RESOLVER_RVA + 0x30: bytes.fromhex(
        "9ceb edff8bf885ff7435ffb6cc0000008d45f48bcf50e885dde5ff"
        "8d45e88bcf50e83a22e5ff508d4df4e8c1d85aff84c0740c"
        "8b45fc5f5e8b40108be55dc3"
    ),
    # The stock reset helper first invokes the same resolver with its owner.
    0xDD3660: bytes.fromhex("56e86a14faff"),
    # Comparator reads data=[arg+8], length=[arg], computes data+length, then
    # compares that bounded range; the absolute byte at the entry is only a
    # case-sensitivity flag.
    CA_STRING_COMPARE_RVA: bytes.fromhex(
        "558bec8b4d08538a1d50c77711568b41088b318b4d0c03f03bc6"
    ),
}
# In-memory absolute operands are relocated.  Runtime guards stop immediately
# before the first such operand while the offline guards above retain the full
# reviewed on-disk bytes.
RUNTIME_ANCHORS = {
    SETUP_RVA: ANCHORS[SETUP_RVA][:13],
    LOOKUP_RVA: ANCHORS[LOOKUP_RVA][:6],
    STRING_CTOR_RVA: ANCHORS[STRING_CTOR_RVA],
    STRING_DTOR_RVA: ANCHORS[STRING_DTOR_RVA][:6],
    REGISTER_RVA: ANCHORS[REGISTER_RVA],
    EVENT_RVA: ANCHORS[EVENT_RVA][:11],
    EVENT_SOURCE_RVA: ANCHORS[EVENT_SOURCE_RVA],
    CALLBACK_NOTIFICATION_RVA: ANCHORS[CALLBACK_NOTIFICATION_RVA],
    OWNER_DTOR_RVA: ANCHORS[OWNER_DTOR_RVA],
    UPDATE_RVA: ANCHORS[UPDATE_RVA],
    STOCK_SOURCE_BIND_RVA: ANCHORS[STOCK_SOURCE_BIND_RVA],
    ATTACHMENT_SCAN_RVA: ANCHORS[ATTACHMENT_SCAN_RVA],
    DISPLAYED_COMMANDER_RESOLVER_RVA:
        ANCHORS[DISPLAYED_COMMANDER_RESOLVER_RVA],
    DISPLAYED_COMMANDER_RESOLVER_RVA + 0x30:
        ANCHORS[DISPLAYED_COMMANDER_RESOLVER_RVA + 0x30],
    0xDD3660: ANCHORS[0xDD3660],
    CA_STRING_COMPARE_RVA: ANCHORS[CA_STRING_COMPARE_RVA][:9],
}


class BindingBuildError(RuntimeError):
    """The reviewed copied-client contract did not hold."""


def validate_game(path: Path = GAME) -> None:
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA256:
        raise BindingBuildError("unreviewed_game_dll")
    for rva, expected in ANCHORS.items():
        offset = rva - IMAGE_FILE_DELTA
        if offset < 0 or data[offset:offset + len(expected)] != expected:
            raise BindingBuildError(f"native_binding_anchor_mismatch:{rva:#x}")


def build_source(game_path: Path = GAME) -> str:
    """Return a self-contained fragment for the shared unit-drag session."""
    config = {
        "path": str(game_path.resolve()),
        "sha256": EXPECTED_SHA256,
        "setup": SETUP_RVA,
        "lookup": LOOKUP_RVA,
        "ctor": STRING_CTOR_RVA,
        "dtor": STRING_DTOR_RVA,
        "register": REGISTER_RVA,
        "event": EVENT_RVA,
        "ownerDtor": OWNER_DTOR_RVA,
        "update": UPDATE_RVA,
        "displayedResolver": DISPLAYED_COMMANDER_RESOLVER_RVA,
        "ownerVtable": OWNER_VTABLE_RVA,
        "embeddedCallbackVtable": EMBEDDED_CALLBACK_VTABLE_RVA,
        "callbackNotification": CALLBACK_NOTIFICATION_RVA,
        "bss": BSS_RVA,
        "managerInner": MANAGER_INNER_PROFILE_OFFSET,
        "instanceMap": INNER_INSTANCE_MAP_OFFSET,
        "saved": INNER_SAVED_OFFSET,
        "payloadIid": PROFILE_PAYLOAD_IID_OFFSET,
        "payloadDefinition": PROFILE_PAYLOAD_DEFINITION_OFFSET,
        "names": NAMES,
        "nameLens": [len(value.encode("ascii")) for value in NAMES],
        "maxAttachments": 32,
        "maxListeners": 64,
        "anchors": [[rva, value.hex()]
                    for rva, value in RUNTIME_ANCHORS.items()],
    }
    return r"""// guarded native specialization button binding
const specializationBindingConfig = %s;
(function installSpecializationBinding(C) {
  const game = Process.getModuleByName('game.dll');
  const norm = value => value.replaceAll('/', '\\').toLowerCase();
  if (Process.arch !== 'ia32' || Process.pointerSize !== 4)
    throw new Error('specialization_binding_abi_mismatch');
  if (norm(game.path) !== norm(C.path))
    throw new Error('specialization_binding_module_path_mismatch');
  function bytesHex(address, length) {
    const values = new Uint8Array(address.readByteArray(length));
    return Array.from(values, value => value.toString(16).padStart(2, '0')).join('');
  }
  for (const [rva, expected] of C.anchors) {
    if (bytesHex(game.base.add(rva), expected.length / 2) !== expected)
      throw new Error('specialization_binding_anchor_mismatch_' + rva.toString(16));
  }
  if (!game.base.add(C.ownerVtable).add(8).readPointer().equals(
        game.base.add(C.update)))
    throw new Error('specialization_binding_update_vtable_mismatch');
  if (!game.base.add(C.embeddedCallbackVtable).add(8).readPointer().equals(
        game.base.add(C.callbackNotification)))
    throw new Error('specialization_binding_callback_notification_mismatch');

  const lookup = new NativeFunction(game.base.add(C.lookup), 'pointer',
                                    ['pointer', 'pointer', 'int'], 'mscdecl');
  const stringCtor = new NativeFunction(game.base.add(C.ctor), 'void',
                                        ['pointer', 'pointer'], 'thiscall');
  const stringDtor = new NativeFunction(game.base.add(C.dtor), 'void',
                                        ['pointer'], 'thiscall');
  const registerListener = new NativeFunction(game.base.add(C.register), 'void',
                                              ['pointer', 'pointer'], 'thiscall');
  const displayedCommander = new NativeFunction(
      game.base.add(C.displayedResolver), 'pointer', ['pointer'], 'thiscall');
  const liveOwners = new Map();
  const ownerStates = new Map();
  const ownerLifetimes = new Map();
  let nextOwnerEpoch = 1;

  // E0EB10 passes a pointer-to-source in its event argument.  Its stock
  // comparison at E0EB25 supplies source+0x94 to 295290. Full register-flow
  // disassembly proves CA string length at +0 and data pointer at +8.  This
  // is not an MSVC SSO std::string and must not use +0x10/+0x14.
  function caStringEquals(value, expected, expectedLength) {
    try {
      const length = value.readU32();
      if (length !== expectedLength || length === 0) return false;
      const data = value.add(8).readPointer();
      if (data.isNull()) return false;
      const actual = new Uint8Array(data.readByteArray(length));
      for (let i = 0; i < expectedLength; i++)
        if (actual[i] !== expected.charCodeAt(i)) return false;
      return true;
    } catch (_) { return false; }
  }
  function listenerContainer(owner, name) {
    if (!listenerContainer.failureReasons)
      listenerContainer.failureReasons = Object.create(null);
    if (C.names.includes(name)) listenerContainer.failureReasons[name] = null;
    const refuse = reason => {
      if (C.names.includes(name)) listenerContainer.failureReasons[name] = reason;
      return false;
    };
    const temporary = Memory.alloc(24);
    temporary.writeByteArray(new Uint8Array(24));
    const utf8 = Memory.allocUtf8String(name);
    let constructed = false;
    try {
      stringCtor(temporary, utf8); constructed = true;
      const root = owner.add(4).readPointer();
      if (root.isNull()) return refuse('root_null');
      const component = lookup(root, temporary, 1);
      if (component.isNull()) return refuse('lookup_null');
      if (!caStringEquals(component.add(0x94), name, name.length))
        return refuse('component_name_mismatch');
      const attachmentCount = component.add(0x1d8).readU32();
      if (attachmentCount < 1 || attachmentCount > C.maxAttachments)
        return refuse('attachment_count');
      const attachmentRecords = component.add(0x1dc).readPointer();
      if (attachmentRecords.isNull()) return refuse('attachment_records_null');
      // 8FFA40 proves 0x28-byte attachment records.  DAC185 can use record
      // zero for the stock reset widget, but the copied generic-button
      // instances may have other controllers before their Button publisher.
      // Scan the complete bounded vector and retain only a controller whose
      // +0x74 listener container names this exact lookup result as its source.
      // Duplicate records for the same controller do not create ambiguity;
      // two distinct matching publishers do, because there is no proven rule
      // for selecting between them.
      const matches = new Map();
      try {
        for (let i = 0; i < attachmentCount; i++) {
          const controller = attachmentRecords.add(i * 0x28).readPointer();
          if (controller.isNull()) continue;
          const controllerVtable = controller.readPointer();
          const container = controller.add(0x74);
          if (!container.readPointer().equals(component)) continue;
          if (controllerVtable.isNull())
            return refuse('matching_controller_invalid');
          const listenerCount = container.add(4).readU32();
          if (listenerCount > C.maxListeners ||
              (listenerCount > 0 &&
               container.add(8).readPointer().isNull()))
            return refuse('matching_controller_invalid');
          matches.set(controller.toString(), {container, source:component,
                                               controller});
        }
      } catch (_) {
        // Do not accept a result from a partial scan: an unreadable later
        // record could hide a second matching publisher.
        return refuse('attachment_scan_unreadable');
      }
      if (matches.size === 0) return refuse('matching_controller_not_found');
      if (matches.size !== 1) return refuse('matching_controller_ambiguous');
      return matches.values().next().value;
    } finally {
      if (constructed) stringDtor(temporary);
    }
  }
  function u64Parts(value) {
    return {lo:String(value.readU32()), hi:String(value.add(4).readU32())};
  }
  function sameU64(left, right) {
    return left.readU32() === right.readU32() &&
           left.add(4).readU32() === right.add(4).readU32();
  }
  function displayedIdentity(owner) {
    // D74AD0 is the stock panel resolver used by the reset path. It translates
    // owner+0xCC's browsed definition record into a live profile payload.
    const payload = displayedCommander(owner);
    if (payload.isNull()) return null;
    const iidAt = payload.add(C.payloadIid);
    const definitionAt = payload.add(C.payloadDefinition);
    const manager = game.base.add(C.bss).readPointer();
    if (manager.isNull()) return null;
    const inner = manager.add(C.managerInner).readPointer();
    if (inner.isNull()) return null;
    const savedAt = inner.add(C.saved);
    const savedBefore = u64Parts(savedAt);
    const map = inner.add(C.instanceMap);
    const bucketCount = map.add(8).readU32();
    if (bucketCount < 1 || bucketCount > 65536) return null;
    const buckets = map.add(0xc).readPointer();
    if (buckets.isNull()) return null;
    // Modulo a 64-bit IID by a bounded 32-bit bucket count without lossy JS
    // Number conversion.
    const lo = iidAt.readU32(), hi = iidAt.add(4).readU32();
    const bucketIndex = ((hi %% bucketCount) * (4294967296 %% bucketCount) +
                         (lo %% bucketCount)) %% bucketCount;
    const bucket = buckets.add(bucketIndex * 12), sentinel = bucket.add(4);
    let node = bucket.readPointer();
    const seen = new Set();
    let exact = false;
    for (let count = 0; count < 16 && !node.isNull() && !node.equals(sentinel);
         count++) {
      const key = node.toString();
      if (seen.has(key)) return null;
      seen.add(key);
      if (sameU64(node.add(8), iidAt)) {
        exact = node.add(0x10).readPointer().equals(payload); break;
      }
      node = node.add(4).readPointer();
    }
    const savedAfter = u64Parts(savedAt);
    if (!exact || savedBefore.lo !== savedAfter.lo ||
        savedBefore.hi !== savedAfter.hi ||
        !manager.equals(game.base.add(C.bss).readPointer()) ||
        !inner.equals(manager.add(C.managerInner).readPointer())) return null;
    return {instanceId:u64Parts(iidAt),
            definitionId:u64Parts(definitionAt), saved:savedBefore};
  }

  function sameIdentity(left, right) {
    if (!left || !right) return false;
    for (const field of ['instanceId', 'definitionId', 'saved']) {
      if (!left[field] || !right[field] ||
          left[field].lo !== right[field].lo ||
          left[field].hi !== right[field].hi) return false;
    }
    return true;
  }

  const pendingUiStatus = new Map();
  function deliverPendingUiStatus(ownerKey, epoch, current) {
    const pending = pendingUiStatus.get(ownerKey);
    if (!pending || pending.ownerEpoch !== epoch) return false;
    pendingUiStatus.delete(ownerKey);
    if (!sameIdentity(current, pending.identity)) {
      send({kind:'specialization_ui_status_refused', owner:ownerKey,
            ownerEpoch:epoch, reason:'specialization_ui_identity_changed'});
      return false;
    }
    // Receipt is emitted only from a native setup/action interceptor after
    // that interceptor has resolved the current identity on the native path.
    send({kind:'specialization_ui_status_received', owner:ownerKey,
          ownerEpoch:epoch, identity:current, status:pending.status});
    return true;
  }

  // Presentation transport only: the host may return validated status data
  // to the same live owner, but this fragment deliberately has no native
  // writer or widget-state mutation.  Re-arm recv after every message so a
  // stale/late response cannot consume the next request.
  function receiveSpecializationUiStatus() {
    recv('specialization_ui_status', message => {
      try {
        const payload = message && message.payload;
        if (!payload || Object.keys(payload).sort().join(',') !==
            'identity,owner,ownerEpoch,status')
          throw new Error('invalid_specialization_ui_status_message');
        const ownerKey = payload.owner;
        if (typeof ownerKey !== 'string' ||
            !/^0x[0-9a-f]+$/.test(ownerKey))
          throw new Error('invalid_specialization_ui_owner');
        const epoch = payload.ownerEpoch;
        if (!Number.isInteger(epoch) || epoch < 1 || epoch >= 0x80000000 ||
            liveOwners.get(ownerKey) !== epoch)
          throw new Error('stale_specialization_ui_owner');
        if (!payload.status || typeof payload.status !== 'object')
          throw new Error('invalid_specialization_ui_status_payload');
        // Do not call displayedIdentity from this recv callback: it may run
        // on Frida's script thread rather than the native UI thread.  The
        // next native setup/action interceptor re-resolves and delivers it.
        pendingUiStatus.set(ownerKey, {
          ownerEpoch:epoch, identity:payload.identity, status:payload.status,
        });
        send({kind:'specialization_ui_status_queued', owner:ownerKey,
              ownerEpoch:epoch});
      } catch (error) {
        send({kind:'specialization_ui_status_refused',
              reason:String(error)});
      }
      receiveSpecializationUiStatus();
    });
  }
  receiveSpecializationUiStatus();

  function nativeOwnerContext(owner) {
    try {
      if (owner.isNull() || !owner.readPointer().equals(
            game.base.add(C.ownerVtable)) ||
          !owner.add(0x70).readPointer().equals(
            game.base.add(C.embeddedCallbackVtable))) return null;
      const root = owner.add(4).readPointer();
      if (root.isNull()) return null;
      return {owner, key:owner.toString(), root,
              rootKey:root.toString(), threadId:Process.getCurrentThreadId()};
    } catch (_) { return null; }
  }
  function sourceBindingStillCurrent(owner, binding, name, expectedLength) {
    try {
      const current = listenerContainer(owner, name);
      return current !== false &&
             current.source.equals(binding.source) &&
             current.controller.equals(binding.controller) &&
             current.container.equals(binding.container) &&
             !binding.container.isNull() && !binding.source.isNull() &&
             binding.container.readPointer().equals(binding.source) &&
             caStringEquals(binding.source.add(0x94), name, expectedLength);
    } catch (_) { return false; }
  }
  function boundedPointerListContains(base, countOffset, dataOffset, target,
                                      maximum) {
    try {
      const count = base.add(countOffset).readU32();
      if (count > maximum) return null;
      const data = base.add(dataOffset).readPointer();
      if (count > 0 && data.isNull()) return null;
      for (let i = 0; i < count; i++)
        if (data.add(i * Process.pointerSize).readPointer().equals(target))
          return true;
      return false;
    } catch (_) { return null; }
  }
  function bindingRelationship(binding, callback) {
    const forward = boundedPointerListContains(
      binding.container, 4, 8, callback, C.maxListeners);
    const reverse = boundedPointerListContains(
      callback, 8, 12, binding.container, C.maxListeners);
    if (forward === null || reverse === null || forward !== reverse)
      return 'ambiguous';
    return forward ? 'present' : 'absent';
  }
  function stateStillCurrent(state) {
    const current = nativeOwnerContext(state.owner);
    return current !== null && current.key === state.key &&
           current.rootKey === state.rootKey &&
           current.threadId === state.threadId &&
           ownerStates.get(state.key) === state;
  }
  function invalidateGeneration(state) {
    state.active = false;
    liveOwners.delete(state.key);
    pendingUiStatus.delete(state.key);
  }
  function newGeneration(context) {
    let lifetime = ownerLifetimes.get(context.key);
    if (!lifetime) {
      lifetime = {sourceRegistrations:new Map(), quarantined:false};
      ownerLifetimes.set(context.key, lifetime);
    } else if (!lifetime.quarantined) lifetime.sourceRegistrations.clear();
    const state = {owner:context.owner, key:context.key,
      rootKey:context.rootKey, threadId:context.threadId,
      epoch:nextOwnerEpoch++, registration:'unattempted',
      registeredSources:0, sources:[], bindings:[], lastUpdateMs:null,
      identityKey:null, active:true, busy:false, lifetime};
    ownerStates.set(context.key, state);
    return state;
  }
  function advanceIdentityEpoch(state, identityKey) {
    pendingUiStatus.delete(state.key);
    liveOwners.delete(state.key);
    state.epoch = nextOwnerEpoch++;
    state.identityKey = identityKey;
    if (state.registration === 'ready')
      liveOwners.set(state.key, state.epoch);
  }
  function resetBindingRegistration(state) {
    pendingUiStatus.delete(state.key);
    liveOwners.delete(state.key);
    state.epoch = nextOwnerEpoch++;
    state.identityKey = null;
    state.registration = 'unattempted';
    state.registeredSources = 0;
    state.sources = [];
    state.bindings = [];
    state.lifetime.sourceRegistrations.clear();
  }
  function observeNativeOwner(owner, origin) {
    const context = nativeOwnerContext(owner);
    if (context === null) return;
    let state = ownerStates.get(context.key);
    if (state && (state.rootKey !== context.rootKey ||
                  state.threadId !== context.threadId)) {
      invalidateGeneration(state);
      state = null;
    }
    if (!state) state = newGeneration(context);
    if (origin === 'update') {
      const now = Date.now();
      if (state.lastUpdateMs !== null && now - state.lastUpdateMs < 250)
        return;
      state.lastUpdateMs = now;
    }
    if (state.lifetime.quarantined) {
      state.registration = 'quarantined';
      return;
    }
    if (state.busy || state.registration === 'quarantined') return;
    state.busy = true;
    try {
      let newlyReady = false;
      if (state.registration === 'ready') {
        const current = C.names.map(name => listenerContainer(owner, name));
        if (!current.every(Boolean)) {
          resetBindingRegistration(state);
          return;
        }
        const callback = owner.add(0x70);
        const relationships = current.map(value =>
          bindingRelationship(value, callback));
        if (relationships.some(value => value === 'ambiguous')) {
          state.registration = 'quarantined';
          state.lifetime.quarantined = true;
          invalidateGeneration(state);
          send({kind:'specialization_binding_refused', owner:state.key,
                ownerEpoch:state.epoch,
                reason:'asymmetric_native_registration'});
          return;
        }
        const changed = current.some((value, index) =>
          !state.bindings[index] ||
          !value.source.equals(state.bindings[index].source) ||
          !value.controller.equals(state.bindings[index].controller) ||
          !value.container.equals(state.bindings[index].container));
        if (changed || relationships.some(value => value === 'absent')) {
          resetBindingRegistration(state);
          // Native reciprocal teardown proves symmetric absence is safe to
          // re-register, even when an allocator reused the same addresses.
        }
      }
      if (state.registration === 'unattempted') {
        // Resolve both sources before the first registration attempt.
        const resolved = C.names.map(name => listenerContainer(owner, name));
        if (!resolved.every(Boolean)) {
          send({kind:'specialization_binding_refused', owner:state.key,
                ownerEpoch:state.epoch, reason:'widget_not_found',
                resolved:resolved.map(value => value !== false),
                lookupFailures:C.names.map(name =>
                  (listenerContainer.failureReasons || {})[name] || null)});
          return;
        }
        if (!stateStillCurrent(state)) {
          invalidateGeneration(state);
          return;
        }
        for (let i = 0; i < resolved.length; i++) {
          if (!sourceBindingStillCurrent(
                owner, resolved[i], C.names[i], C.nameLens[i])) {
            state.registration = 'quarantined';
            state.lifetime.quarantined = true;
            liveOwners.delete(state.key);
            pendingUiStatus.delete(state.key);
            send({kind:'specialization_binding_refused', owner:state.key,
                  ownerEpoch:state.epoch,
                  reason:'source_binding_changed_before_registration',
                  registeredSources:state.registeredSources});
            return;
          }
          const sourceKey = resolved[i].source.toString();
          const relationship = bindingRelationship(
            resolved[i], owner.add(0x70));
          if (relationship === 'ambiguous') {
            state.registration = 'quarantined';
            state.lifetime.quarantined = true;
            invalidateGeneration(state);
            send({kind:'specialization_binding_refused', owner:state.key,
                  ownerEpoch:state.epoch,
                  reason:'asymmetric_native_registration'});
            return;
          }
          const prior = state.lifetime.sourceRegistrations.get(sourceKey);
          if (relationship === 'present') {
            state.lifetime.sourceRegistrations.set(sourceKey, 'registered');
            state.registeredSources++;
            continue;
          }
          if (prior !== undefined && prior !== 'registered') {
            state.registration = 'quarantined';
            state.lifetime.quarantined = true;
            return;
          }
          state.lifetime.sourceRegistrations.set(sourceKey, 'attempting');
          try {
            registerListener(resolved[i].container, owner.add(0x70));
            if (bindingRelationship(resolved[i], owner.add(0x70)) !==
                'present') throw new Error('registration_not_reciprocal');
            state.lifetime.sourceRegistrations.set(sourceKey, 'registered');
            state.registeredSources++;
            if (!sourceBindingStillCurrent(
                  owner, resolved[i], C.names[i], C.nameLens[i])) {
              state.registration = 'quarantined';
              state.lifetime.quarantined = true;
              liveOwners.delete(state.key);
              pendingUiStatus.delete(state.key);
              send({kind:'specialization_binding_refused', owner:state.key,
                    ownerEpoch:state.epoch,
                    reason:'source_binding_changed_during_registration',
                    registeredSources:state.registeredSources});
              return;
            }
          } catch (_) {
            // Native duplicate suppression is proven, but a thrown call does
            // not prove whether append/reciprocal callback publication ran.
            // With no reviewed unregister, quarantine this owner lifetime.
            state.registration = 'quarantined';
            state.lifetime.sourceRegistrations.set(sourceKey, 'ambiguous');
            state.lifetime.quarantined = true;
            liveOwners.delete(state.key);
            pendingUiStatus.delete(state.key);
            send({kind:'specialization_binding_refused', owner:state.key,
                  ownerEpoch:state.epoch,
                  reason:'partial_registration_ambiguous',
                  registeredSources:state.registeredSources});
            return;
          }
        }
        if (!stateStillCurrent(state)) {
          state.registration = 'quarantined';
          state.lifetime.quarantined = true;
          send({kind:'specialization_binding_refused', owner:state.key,
                ownerEpoch:state.epoch,
                reason:'owner_context_changed_during_registration',
                registeredSources:state.registeredSources});
          return;
        }
        state.sources = resolved.map(value => value.source.toString());
        state.bindings = resolved;
        state.registration = 'ready';
        liveOwners.set(state.key, state.epoch);
        newlyReady = true;
        send({kind:'specialization_binding_ready', owner:state.key,
              ownerEpoch:state.epoch, root:state.rootKey,
              registeredSources:state.registeredSources, origin});
      }
      if (state.registration !== 'ready' || !stateStillCurrent(state)) return;
      const identity = displayedIdentity(owner);
      if (!stateStillCurrent(state)) return;
      if (identity === null) {
        send({kind:'specialization_ui_setup_refused', owner:state.key,
              ownerEpoch:state.epoch,
              reason:'displayed_commander_identity_unproven'});
        return;
      }
      const identityKey = JSON.stringify(identity);
      const identityChanged = state.identityKey !== null &&
                              state.identityKey !== identityKey;
      if (identityChanged) advanceIdentityEpoch(state, identityKey);
      else state.identityKey = identityKey;
      deliverPendingUiStatus(state.key, state.epoch, identity);
      if (newlyReady || origin === 'setup' || identityChanged)
        send({kind:'specialization_ui_setup', owner:state.key,
              ownerEpoch:state.epoch, identity, emittedAtMs:Date.now()});
    } catch (error) {
      send({kind:'specialization_binding_refused', owner:state.key,
            ownerEpoch:state.epoch, reason:String(error)});
    } finally { state.busy = false; }
  }

  Interceptor.attach(game.base.add(C.setup), {
    onEnter() {
      this.owner = this.context.ecx;
      this.threadId = Process.getCurrentThreadId();
    },
    onLeave() {
      if (this.threadId === Process.getCurrentThreadId())
        observeNativeOwner(this.owner, 'setup');
    }
  });
  Interceptor.attach(game.base.add(C.update), {
    onEnter() { observeNativeOwner(this.context.ecx, 'update'); }
  });
  Interceptor.attach(game.base.add(C.ownerDtor), {
    onEnter() {
      const owner = this.context.ecx.toString();
      const state = ownerStates.get(owner);
      const ownerEpoch = state && state.epoch;
      if (state) invalidateGeneration(state);
      ownerStates.delete(owner);
      ownerLifetimes.delete(owner);
      liveOwners.delete(owner);
      pendingUiStatus.delete(owner);
      // A destructor for a registered owner carries the generation it
      // invalidated.  Unregistered teardown has no live generation and is
      // reported without an epoch so the host cannot invalidate a future
      // address-reused panel.
      if (ownerEpoch === undefined)
        send({kind:'specialization_ui_owner_destroyed', owner});
      else
        send({kind:'specialization_ui_owner_destroyed', owner, ownerEpoch});
    }
  });
  Interceptor.attach(game.base.add(C.event), {
    onEnter(args) {
      try {
        const callbackOwner = this.context.ecx.sub(0x70);
        const ownerKey = callbackOwner.toString();
        const state = ownerStates.get(ownerKey);
        const epoch = liveOwners.get(ownerKey);
        if (!state || state.registration !== 'ready' ||
            epoch !== state.epoch || !stateStillCurrent(state) ||
            !this.context.ecx.readPointer().equals(
              game.base.add(C.embeddedCallbackVtable)))
          return;
        const eventArgument = args[0];
        if (eventArgument.isNull()) return;
        const source = eventArgument.readPointer();
        if (source.isNull()) return;
        let actionIndex = -1;
        for (let i = 0; i < C.names.length; i++)
          if (source.toString() === state.sources[i] &&
              caStringEquals(source.add(0x94), C.names[i], C.nameLens[i])) {
            actionIndex = i; break;
          }
        if (actionIndex < 0) return;
        const currentBinding = listenerContainer(
          callbackOwner, C.names[actionIndex]);
        const currentRelationship = currentBinding ? bindingRelationship(
          currentBinding, callbackOwner.add(0x70)) : 'absent';
        if (!currentBinding ||
            !currentBinding.source.equals(source) ||
            !eventArgument.equals(currentBinding.container) ||
            !state.bindings[actionIndex] ||
            !currentBinding.controller.equals(
              state.bindings[actionIndex].controller) ||
            !currentBinding.container.equals(
              state.bindings[actionIndex].container) ||
            currentRelationship !== 'present') {
          if (currentRelationship === 'ambiguous') {
            state.registration = 'quarantined';
            state.lifetime.quarantined = true;
          } else {
            resetBindingRegistration(state);
          }
          if (currentRelationship === 'ambiguous')
            advanceIdentityEpoch(state, null);
          send({kind:'specialization_ui_action_refused', owner:ownerKey,
                ownerEpoch:state.epoch,
                reason:'stale_specialization_ui_source'});
          return;
        }
        const identity = displayedIdentity(callbackOwner);
        if (identity === null || !stateStillCurrent(state)) {
          send({kind:'specialization_ui_action_refused',
                reason:'displayed_commander_identity_unproven', ownerEpoch:epoch});
          return;
        }
        const identityKey = JSON.stringify(identity);
        if (state.identityKey !== null && state.identityKey !== identityKey) {
          advanceIdentityEpoch(state, identityKey);
          send({kind:'specialization_ui_action_refused', owner:ownerKey,
                ownerEpoch:state.epoch,
                reason:'displayed_commander_identity_changed'});
          send({kind:'specialization_ui_setup', owner:ownerKey,
                ownerEpoch:state.epoch, identity, emittedAtMs:Date.now()});
          return;
        }
        state.identityKey = identityKey;
        deliverPendingUiStatus(ownerKey, epoch, identity);
        send({kind:'specialization_ui_action', actionName:C.names[actionIndex],
              ownerEpoch:epoch, identity, emittedAtMs:Date.now()});
      } catch (_) {}
    }
  });
})(specializationBindingConfig);
""" % json.dumps(config, separators=(",", ":"))


def load_commander_item_ids(path: Path = ROOT / "catalog" / "native_hangar.json") -> dict[int, str]:
    value = json.loads(path.read_text(encoding="utf-8"))
    result: dict[int, str] = {}
    for row in value.get("commanders", []):
        if row.get("build_state") != "live":
            continue
        item_id, key = row.get("item_id"), row.get("key")
        if (type(item_id) is not int or not 0 < item_id < 2**64
                or not isinstance(key, str) or not key or item_id in result):
            raise BindingBuildError("invalid_commander_identity_catalogue")
        result[item_id] = key
    if not result:
        raise BindingBuildError("empty_commander_identity_catalogue")
    return result


def _parts(value: object, label: str) -> int:
    if (not isinstance(value, dict) or set(value) != {"lo", "hi"}
            or any(not isinstance(value.get(k), str)
                   or not value[k].isascii() or not value[k].isdigit()
                   for k in ("lo", "hi"))):
        raise BindingBuildError(f"invalid_{label}")
    lo, hi = int(value["lo"]), int(value["hi"])
    if not 0 <= lo < 2**32 or not 0 <= hi < 2**32:
        raise BindingBuildError(f"invalid_{label}")
    return lo | hi << 32


def decode_action_identity(payload: object,
                           commanders: dict[int, str]) -> tuple[str, int, int]:
    """Convert one exact-pointer-verified agent identity to host authority."""
    if not isinstance(payload, dict) or set(payload) != {
            "instanceId", "definitionId", "saved"}:
        raise BindingBuildError("invalid_displayed_identity")
    instance_id = _parts(payload["instanceId"], "displayed_instance_id")
    definition_id = _parts(payload["definitionId"], "displayed_definition_id")
    saved = _parts(payload["saved"], "displayed_saved")
    if instance_id == 0 or saved == 0 or definition_id not in commanders:
        raise BindingBuildError("unrecognized_displayed_commander")
    return commanders[definition_id], instance_id, saved


def main() -> int:
    validate_game()
    source = build_source()
    print(json.dumps({
        "mode": "offline-source-only",
        "game_dll_sha256": EXPECTED_SHA256,
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "actions": list(NAMES),
        "mutation_enabled": False,
        "missing_prerequisite": "shared_session_integration_and_runtime_acceptance",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
