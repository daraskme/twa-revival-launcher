"""Pinned Arcani slot correction source for the owned native bridge."""
from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from tools.player_native_payload import GAME_HASH as GAME_SHA256

CATALOG_SHA256 = "e9913a5ec02aab020b13ca4de2620a7d8cd0c54ca6cfa876fc8876d91e2c29ff"
HANGAR_SHA256 = "70bf185dddde41f567df185e4d7c10f32d19bd2bff1fd32ad30788274c2b689e"
MAX_TELEMETRY_EVENTS = 64
MAX_ROWS = 15
RENDER_CALLER = 0xD83BFC
CLICK_CALLER = 0xE00974
PICKER_CALLERS = (0xD98334, 0xDD0A94)
AUTO_RESELECT_CALLER = 0xDD3009


@lru_cache(maxsize=1)
def _keys() -> tuple[tuple[str, ...], tuple[str, ...], dict[str, str], str]:
    path = Path(__file__).resolve().parents[1] / "catalog/native_unit_abilities.json"
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != CATALOG_SHA256:
        raise ValueError("slot_mapper_catalogue_hash_mismatch")
    rows = json.loads(raw)["items"]
    if len(rows) != 3376:
        raise ValueError("slot_mapper_catalogue_count_mismatch")
    public = {row["ability"] for row in rows}
    irreplaceable = {row["ability"] for row in rows if row["mode"] == "irreplaceable"}
    mutable = {row["ability"] for row in rows if row["mode"] in {"default", "additional"}} - irreplaceable
    if (len(public) != 244 or len(mutable) != 241 or
            any(not key or len(key) > 52 or
                any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_" for c in key)
                for key in public)):
        raise ValueError("slot_mapper_catalogue_keys_invalid")
    arcani = {row["ability"]: str(row["item_id"]) for row in rows
              if row["unit"] == "rom_arcani" and row["mode"] in {"default", "additional"}}
    if len(arcani) != 10 or set(arcani) - mutable:
        raise ValueError("slot_mapper_arcani_abilities_invalid")
    hangar = path.with_name("native_hangar.json")
    hangar_raw = hangar.read_bytes()
    if hashlib.sha256(hangar_raw).hexdigest() != HANGAR_SHA256:
        raise ValueError("slot_mapper_hangar_hash_mismatch")
    unit = [row for row in json.loads(hangar_raw)["units"] if row["key"] == "rom_arcani"]
    if len(unit) != 1 or unit[0]["item_id"] != 3679783939900596058:
        raise ValueError("slot_mapper_arcani_unit_invalid")
    return tuple(sorted(public)), tuple(sorted(mutable)), arcani, str(unit[0]["item_id"])


_SOURCE = r"""
(() => {
  const game = Process.getModuleByName('game.dll');
  const expectedPath = __EXPECTED_PATH__;
  if (game.path.replaceAll('/', '\\').toLowerCase() !==
      expectedPath.replaceAll('/', '\\').toLowerCase())
    throw new Error('slot_mapper_module_path_mismatch');
  const publicKeys = new Set(__PUBLIC_KEYS__);
  const mutableKeys = new Set(__MUTABLE_KEYS__);
  const APPLY = __APPLY__;
  const arcaniItemByKey = __ARCANI_IDS__;
  const arcaniKeyByItem = new Map(Object.entries(arcaniItemByKey).map(([key, id]) => [id, key]));
  const arcaniUnitId = '__ARCANI_UNIT_ID__';
  const anchors = [
    [0xd83620, '558bec81ecc0000000538bd956895ddc'],
    [0xe6de80, '558bec83ec688b450c568bf1c745fc00'],
    [0xd84100, '558bec83ec0c568bf1837e60000f84b5'],
    [0xd83bf7, 'e884a20e00'],
    [0xe0096f, 'e88c37f8ff'],
    [0xdcb880, '558bec83ec5053568bf1578975e88b46'],
    [0xd9832f, 'e84c350300'],
    [0xdd0a8f, 'e8ecadffff'],
    [0xdd3004, 'e8f710fbff'],
  ];
  for (const [rva, expected] of anchors) {
    const raw = new Uint8Array(game.base.add(rva).readByteArray(expected.length / 2));
    const actual = Array.from(raw, x => x.toString(16).padStart(2, '0')).join('');
    if (actual !== expected) throw new Error('slot_mapper_anchor_mismatch');
  }
  const rendered = new Map();
  const emitted = new Set();
  let eventCount = 0;
  let generation = 0;
  let selection = null;
  function slot(value) { return Number.isInteger(value) && value >= -1 && value <= 15; }
  function publicKey(row) {
    try {
      const length = row.readU32();
      if (length < 1 || length > 52) return null;
      const data = row.add(8).readPointer();
      if (data.isNull()) return null;
      let key = '';
      for (let i = 0; i < length; i++) {
        const ch = data.add(i).readU8();
        if (!((ch >= 97 && ch <= 122) || (ch >= 48 && ch <= 57) || ch === 95)) return null;
        key += String.fromCharCode(ch);
      }
      return publicKeys.has(key) ? key : null;
    } catch (_) { return null; }
  }
  function flags(row) {
    const mode = row.add(0x34).readU32();
    return {draw: row.add(0x28).readU8() !== 0,
            skip: row.add(0x30).readU8(),
            mode,
            field38: !row.add(0x38).readPointer().isNull()};
  }
  function nativeUnitState(unit, model, selectedKey) {
    // Internal definition/instance IDs are checked but never emitted.
    if (unit.add(0x18).readU64().toString() !== arcaniUnitId) return null;
    const capOwner = unit.add(0x60).readPointer();
    if (capOwner.isNull()) return null;
    const capRecord = capOwner.add(8).readPointer();
    if (capRecord.isNull() || capRecord.add(0x118).readU32() !== 3) return null;
    if (!model.readPointer().equals(capRecord)) return null;
    const iid = unit.add(8).readU64().toString();
    const definitions = new Set();
    const slots = new Set();
    let count = 0;
    let selectedOwnedSlot = null;
    for (const [countOff, arrayOff] of [[0xb8,0xbc],[0xc4,0xc8]]) {
      const n = unit.add(countOff).readU32();
      if (n > 15 || count + n > 15) return null;
      const array = unit.add(arrayOff).readPointer();
      if (n && array.isNull()) return null;
      for (let i = 0; i < n; i++) {
        const item = array.add(i * 4).readPointer();
        if (item.isNull() || !item.readPointer().equals(game.base.add(0x144da60)) ||
            item.add(0x10).readU64().toString() !== iid) return null;
        const definition = item.add(0x18).readU64().toString();
        const ownedKey = arcaniKeyByItem.get(definition);
        const ownedSlot = item.add(0x68).readU32() | 0;
        if (!ownedKey || definitions.has(definition) || !slot(ownedSlot)) return null;
        if (ownedSlot >= 0 && slots.has(ownedSlot)) return null;
        definitions.add(definition);
        if (ownedSlot >= 0) slots.add(ownedSlot);
        if (ownedKey === selectedKey) selectedOwnedSlot = ownedSlot;
        count++;
      }
    }
    return {owned_count:count, selected_owned_slot:selectedOwnedSlot};
  }
  function emit(record) {
    // Bound diagnostics, never gameplay behavior: the correction remains
    // active for the entire owned Arena bridge session.
    if (eventCount >= 64) return;
    const signature = JSON.stringify(record);
    if (emitted.has(signature)) return;
    emitted.add(signature);
    eventCount++;
    send(record);
  }
  function exactSelectedCollision(model, item) {
    const vector = model.add(0xa0);
    const count = vector.add(4).readU32();
    if (count < 2 || count > 15) return false;
    const base = vector.add(8).readPointer();
    if (base.isNull()) return false;
    let selected = 0;
    let builtin = 0;
    for (let i = 0; i < count; i++) {
      const row = base.add(i * 0x4c);
      const preferred = row.add(0x24).readU32() | 0;
      const f = flags(row);
      if (publicKey(row) === item.key && preferred === item.preferred &&
          f.draw && f.skip === 0 && f.mode === item.mode && f.field38) selected++;
      if (preferred === item.preferred && f.draw && f.skip === 0 &&
          f.mode === 0 && !f.field38) builtin++;
    }
    return selected === 1 && builtin === 1;
  }
  // Every ArenaAbilityList refresh invalidates the previous widget mapping,
  // including refreshes that skip drawing an ability row altogether.
  Interceptor.attach(game.base.add(0xd83620), {
    onEnter(_args) {
      rendered.clear();
      generation++;
      selection = null;
    }
  });
  // Render: caller D83BFC has passed a temporary 0x4C row at args[0].
  // ECX is the chosen controller; controller+4 is its UI component.
  Interceptor.attach(game.base.add(0xe6de80), {
    onEnter(args) {
      if (this.returnAddress.sub(game.base).toUInt32() !== 0xd83bfc) return;
      try {
        const row = args[0];
        const widget = this.context.ecx.add(4).readPointer();
        if (widget.isNull()) return;
        const identity = widget.toString(); // internal only; never emitted
        // A controller is normally reused on refresh or unit switch. Every
        // trusted render supersedes its previous association, including a
        // fixed/unknown/nonvisible row which must erase a stale mutable row.
        rendered.delete(identity);
        const key = publicKey(row);
        const preferred = row.add(0x24).readU32() | 0;
        const f = flags(row);
        if (!mutableKeys.has(key) || !Object.prototype.hasOwnProperty.call(arcaniItemByKey, key) ||
            !slot(preferred) || !f.draw ||
            f.skip !== 0 || (f.mode !== 1 && f.mode !== 2) || !f.field38) return;
        const unitDefinition = args[2]; // D83BF7 passes [owner+0x54][0].
        if (unitDefinition.isNull()) return;
        const item = {key, preferred, mode:f.mode,
                      unitDefinition, controller:this.context.ecx,
                      generation};
        if (rendered.size >= 64) return;
        rendered.set(identity, item);
      } catch (_) { /* Invalid memory cannot alter native state. */ }
    }
  });
  // Click: E0096F calls D84100 with a 20-byte local descriptor.
  // Descriptor +0/+4/+8/+C/+10 = owner/widget/model/unit/clicked index.
  Interceptor.attach(game.base.add(0xd84100), {
    onEnter(args) {
      const caller = this.returnAddress.sub(game.base).toUInt32();
      if (caller === 0xdd3009) {
        // R3's automatic re-selection follows a profile/hotbar refresh.
        // It supplies the new owner/model but copies panel+6C (logical token)
        // into descriptor+10, which need not equal the physical widget index.
        selection = null;
        try {
          const desc = args[0];
          const panel = this.context.ecx;
          const owner = desc.readPointer();
          const widget = desc.add(4).readPointer();
          const model = desc.add(8).readPointer();
          const unit = desc.add(12).readPointer();
          const token = desc.add(16).readU32() | 0;
          if (owner.isNull() || widget.isNull() || model.isNull() || unit.isNull() ||
              token !== 5 && token !== 6 ||
              unit.add(0x18).readU64().toString() !== arcaniUnitId ||
              panel.add(0x60).readPointer().isNull() ||
              panel.add(0x5c).readPointer().isNull() ||
              !panel.add(0x4c).readPointer().equals(owner) ||
              !panel.add(0x68).readPointer().equals(widget) ||
              (panel.add(0x6c).readU32() | 0) !== token ||
              !panel.add(0x44).readPointer().equals(model.readPointer()) ||
              !owner.add(0x54).readPointer().equals(model) ||
              !owner.add(0x50).readPointer().equals(unit)) return;
          const count = owner.add(0x48).readU32();
          const widgets = owner.add(0x4c).readPointer();
          if (count < 1 || count > 15 || widgets.isNull()) return;
          let physical = -1;
          for (let i = 0; i < count; i++) {
            if (widgets.add(i * 4).readPointer().equals(widget)) {
              if (physical !== -1) return;
              physical = i;
            }
          }
          if (physical < 0) return;
          const item = rendered.get(widget.toString());
          if (!item || item.generation !== generation ||
              item.preferred !== token ||
              (item.mode !== 1 && item.mode !== 2) ||
              !Object.prototype.hasOwnProperty.call(arcaniItemByKey, item.key) ||
              !item.unitDefinition.equals(model.readPointer()) ||
              widget.add(0x1d8).readU32() < 1) return;
          const childArray = widget.add(0x1dc).readPointer();
          if (childArray.isNull() ||
              !childArray.readPointer().equals(item.controller) ||
              !item.controller.add(4).readPointer().equals(widget)) return;
          const nativeState = nativeUnitState(unit, model, item.key);
          if (!nativeState ||
              (nativeState.selected_owned_slot !== null &&
               nativeState.selected_owned_slot !== token) ||
              !exactSelectedCollision(model, item)) return;
          selection = {panel, owner, widget, model, unit, key:item.key,
                       logical:token, physical, mode:item.mode, generation,
                       expectedToken:token};
          emit({kind:'slot_trial_reselect_fresh', public_key:item.key,
                logical_slot:token, physical_slot:physical,
                selected_mode:item.mode});
        } catch (_) { /* Refuse unsafe context; native auto-selection continues. */ }
        return;
      }
      if (caller !== 0xe00974) return;
      selection = null;
      try {
        const desc = args[0];
        const owner = desc.readPointer();
        const widget = desc.add(4).readPointer();
        const model = desc.add(8).readPointer();
        const unit = desc.add(12).readPointer();
        const clicked = desc.add(16).readU32() | 0;
        if (owner.isNull() || widget.isNull() || model.isNull() || unit.isNull() ||
            !slot(clicked) || clicked < 0) return;
        const item = rendered.get(widget.toString());
        if (!item || item.generation !== generation) return;
        if (!owner.add(0x54).readPointer().equals(model) ||
            !owner.add(0x50).readPointer().equals(unit)) return;
        const controllerCount = owner.add(0x48).readU32();
        const widgets = owner.add(0x4c).readPointer();
        if (controllerCount < 1 || controllerCount > 15 || clicked >= controllerCount ||
            widgets.isNull()) return;
        const indexedWidget = widgets.add(clicked * 4).readPointer();
        if (indexedWidget.isNull() || !indexedWidget.equals(widget) ||
            widget.add(0x1d8).readU32() < 1) return;
        let widgetOccurrences = 0;
        for (let i = 0; i < controllerCount; i++) {
          if (widgets.add(i * 4).readPointer().equals(widget)) widgetOccurrences++;
        }
        if (widgetOccurrences !== 1) return;
        const childArray = widget.add(0x1dc).readPointer();
        if (childArray.isNull()) return;
        const controller = childArray.readPointer();
        if (controller.isNull() || !controller.equals(item.controller) ||
            !controller.add(4).readPointer().equals(widget)) return;
        if (!model.readPointer().equals(item.unitDefinition)) return;
        const nativeState = nativeUnitState(unit, model, item.key);
        if (!nativeState) return;
        if (nativeState.selected_owned_slot !== null &&
            nativeState.selected_owned_slot !== item.preferred) return;
        const vector = model.add(0xa0);
        const count = vector.add(4).readU32();
        if (count < 1 || count > 15) return;
        const base = vector.add(8).readPointer();
        if (base.isNull()) return;
        let matched = 0;
        let firstPreferredKey = null;
        let firstClickedKey = null;
        let hasPreferred = false;
        let hasClicked = false;
        for (let i = 0; i < count; i++) {
          const row = base.add(i * 0x4c);
          const preferred = row.add(0x24).readU32() | 0;
          const f = flags(row);
          const rowKey = publicKey(row);
          if (f.skip === 0 && preferred === item.preferred && !hasPreferred) {
            firstPreferredKey = rowKey; hasPreferred = true;
          }
          if (f.skip === 0 && preferred === clicked && !hasClicked) {
            firstClickedKey = rowKey; hasClicked = true;
          }
          if (rowKey === item.key && preferred === item.preferred &&
              f.draw && f.skip === 0 && f.mode === item.mode && f.field38) matched++;
        }
        if (matched !== 1) return;
        emit({kind:'slot_mapper_read_only', public_key:item.key,
              preferred_slot:item.preferred, clicked_index:clicked,
              selected_mode:item.mode,
              selected_count:count, owner_model_match:true,
              widget_match:true, owner_widget_index_match:true,
              unique_source_row:true,
              preferred_first_row_same_key:hasPreferred && firstPreferredKey === item.key,
              clicked_first_row_same_key:hasClicked && firstClickedKey === item.key,
              native_unit_verified:true,
              owned_count:nativeState.owned_count,
              selected_owned_slot:nativeState.selected_owned_slot});
        // Only the Arcani Y/I mutable hotbar rows are candidates for the
        // copy-only trial. R/T/U, builtins, and immutable assembly stay native.
        if (item.preferred !== 5 && item.preferred !== 6) return;
        const proposed = {panel:this.context.ecx, owner, widget, model, unit,
                          key:item.key, logical:item.preferred, physical:clicked,
                          mode:item.mode, generation,
                          expectedToken:APPLY ? item.preferred : clicked};
        if (APPLY) {
          const clone = Memory.alloc(20);
          Memory.copy(clone, desc, 20);
          clone.add(16).writeU32(item.preferred);
          this.keepalive = clone;
          args[0] = clone;
        }
        selection = proposed;
        emit({kind:APPLY ? 'slot_trial_descriptor_copy' : 'slot_trial_descriptor_plan',
              public_key:item.key, logical_slot:item.preferred,
              physical_slot:clicked, selected_mode:item.mode});
      } catch (_) { /* Fail closed; no native argument or memory writes. */ }
    }
  });
  Interceptor.attach(game.base.add(0xdcb880), {
    onEnter(args) {
      if (selection === null) return;
      try {
        const caller = this.returnAddress.sub(game.base).toUInt32();
        if (caller !== 0xd98334 && caller !== 0xdd0a94) return;
        const chosen = selection;
        if (chosen.generation !== generation ||
            !chosen.owner.add(0x54).readPointer().equals(chosen.model) ||
            !chosen.owner.add(0x50).readPointer().equals(chosen.unit) ||
            !chosen.panel.add(0x4c).readPointer().equals(chosen.owner) ||
            !chosen.panel.add(0x44).readPointer().equals(chosen.model.readPointer()) ||
            !chosen.panel.add(0x68).readPointer().equals(chosen.widget) ||
            !chosen.panel.add(0x40).readPointer().equals(chosen.model) ||
            chosen.panel.add(0x6c).readU32() !== chosen.expectedToken) {
          selection = null;
          return;
        }
        if (!args[1].equals(chosen.model.add(0xa0))) return;
        // The click guard was true earlier, but a native loadout or unit
        // switch may have occurred before the picker examines this vector.
        const currentNativeState = nativeUnitState(chosen.unit, chosen.model, chosen.key);
        if (!currentNativeState ||
            (currentNativeState.selected_owned_slot !== null &&
             currentNativeState.selected_owned_slot !== chosen.logical)) {
          selection = null;
          return;
        }
        const actualSlot = args[0].toUInt32() | 0;
        if (actualSlot !== chosen.expectedToken) return;
        const candidate = this.context.ecx.add(0x40).readPointer();
        if (candidate.isNull()) return;
        const candidateKey = publicKey(candidate);
        const candidateFlags = flags(candidate);
        if (!mutableKeys.has(candidateKey) ||
            !Object.prototype.hasOwnProperty.call(arcaniItemByKey, candidateKey) ||
            (candidateFlags.mode !== 1 && candidateFlags.mode !== 2) ||
            !candidateFlags.draw || candidateFlags.skip !== 0 ||
            !candidateFlags.field38) return;
        const vector = args[1];
        const count = vector.add(4).readU32();
        if (count < 2 || count > 15) return;
        const base = vector.add(8).readPointer();
        if (base.isNull()) return;
        let selectedCount = 0;
        let builtinCount = 0;
        let builtinIndex = -1;
        for (let i = 0; i < count; i++) {
          const row = base.add(i * 0x4c);
          const preferred = row.add(0x24).readU32() | 0;
          const f = flags(row);
          if (publicKey(row) === chosen.key && preferred === chosen.logical &&
              f.draw && f.skip === 0 && f.mode === chosen.mode && f.field38)
            selectedCount++;
          if (preferred === chosen.logical && f.draw && f.skip === 0 &&
              f.mode === 0 && !f.field38) {
            builtinCount++;
            builtinIndex = i;
          }
        }
        if (selectedCount !== 1 || builtinCount !== 1) return;
        if (APPLY) {
          const header = Memory.alloc(12);
          const rows = Memory.alloc((count - 1) * 0x4c);
          Memory.copy(header, vector, 12);
          let out = 0;
          for (let i = 0; i < count; i++) {
            if (i === builtinIndex) continue;
            Memory.copy(rows.add(out * 0x4c), base.add(i * 0x4c), 0x4c);
            out++;
          }
          if (out !== count - 1) return;
          header.add(4).writeU32(out);
          header.add(8).writePointer(rows);
          this.keepalive = [header, rows];
          args[1] = header;
        }
        emit({kind:APPLY ? 'slot_trial_vector_copy' : 'slot_trial_vector_plan',
              public_key:chosen.key, candidate_public_key:candidateKey,
              logical_slot:chosen.logical, physical_slot:chosen.physical,
              selected_mode:chosen.mode, original_rows:count,
              copied_rows:count-1, removed_builtin_rows:1,
              caller_rva:caller});
      } catch (_) { /* No raw addresses or native state enter the trace. */ }
    }
  });
  send({kind:'slot_mapper_ready'});
})();
"""


def build_source(expected_path: str, *, apply: bool = False) -> str:
    if (not isinstance(expected_path, str) or
            not expected_path.replace("/", "\\").lower().endswith("\\client\\game.dll")):
        raise ValueError("slot_mapper_path_invalid")
    if any(_SOURCE.count(marker) != 1 for marker in
           ("__EXPECTED_PATH__", "__PUBLIC_KEYS__", "__MUTABLE_KEYS__",
            "__ARCANI_IDS__", "__ARCANI_UNIT_ID__", "__APPLY__")):
        raise RuntimeError("slot_mapper_template_invalid")
    if type(apply) is not bool:
        raise ValueError("slot_trial_apply_must_be_bool")
    from tools import native_fixed_family_mapper as fixed_family
    if fixed_family.GAME_SHA256 != GAME_SHA256:
        raise ValueError("fixed_family_game_pin_mismatch")
    # The reviewed v4 source must validate original bytes before either
    # observer attaches to the same entry addresses.
    public, mutable, arcani, arcani_unit_id = _keys()
    v4_source = (_SOURCE.replace("__EXPECTED_PATH__", json.dumps(expected_path))
            .replace("__PUBLIC_KEYS__", json.dumps(public))
            .replace("__MUTABLE_KEYS__", json.dumps(mutable))
            .replace("__ARCANI_IDS__", json.dumps(arcani, sort_keys=True))
            .replace("__ARCANI_UNIT_ID__", arcani_unit_id)
            .replace("__APPLY__", "true" if apply else "false"))
    family_source = fixed_family.build_source(
        expected_path, verified_v4_source=v4_source, apply=apply)
    return v4_source + "\n" + family_source


def safe_record(payload: dict) -> dict | None:
    if not isinstance(payload, dict):
        return None
    if payload.get("kind") in {
            "slot_mapper_family_ready", "slot_mapper_family_read_only",
            "slot_mapper_family_candidate_read_only",
            "slot_mapper_family_descriptor_plan", "slot_mapper_family_descriptor_copy",
            "slot_mapper_family_vector_plan", "slot_mapper_family_vector_copy",
            "slot_mapper_family_reselect_fresh"}:
        from tools import native_fixed_family_mapper as fixed_family
        return fixed_family.safe_record(payload)
    if payload.get("kind") == "slot_trial_reselect_fresh":
        _public, _mutable, arcani, _unit_id = _keys()
        key = payload.get("public_key")
        logical = payload.get("logical_slot")
        physical = payload.get("physical_slot")
        mode = payload.get("selected_mode")
        if (type(key) is not str or key not in arcani or
                type(logical) is not int or logical not in (5, 6) or
                type(physical) is not int or not 0 <= physical <= 15 or
                type(mode) is not int or mode not in (1, 2)):
            return None
        return {"event": "slot_trial_reselect_fresh", "public_key": key,
                "logical_slot": logical, "physical_slot": physical,
                "selected_mode": mode}
    if payload.get("kind") == "slot_mapper_ready":
        return {"event": "slot_mapper_ready"}
    if payload.get("kind") in {
            "slot_trial_descriptor_plan", "slot_trial_descriptor_copy",
            "slot_trial_vector_plan", "slot_trial_vector_copy"}:
        kind = payload["kind"]
        _public, _mutable, arcani, _unit_id = _keys()
        key = payload.get("public_key")
        logical = payload.get("logical_slot")
        physical = payload.get("physical_slot")
        mode = payload.get("selected_mode")
        if (type(key) is not str or key not in arcani or
                type(logical) is not int or logical not in (5, 6) or
                type(physical) is not int or not 0 <= physical <= 15 or
                type(mode) is not int or mode not in (1, 2)):
            return None
        clean = {"event": kind, "public_key": key,
                 "logical_slot": logical, "physical_slot": physical,
                 "selected_mode": mode}
        if "vector" in kind:
            candidate = payload.get("candidate_public_key")
            original = payload.get("original_rows")
            copied = payload.get("copied_rows")
            if (type(candidate) is not str or candidate not in arcani or
                    type(original) is not int or not 2 <= original <= MAX_ROWS or
                    type(copied) is not int or copied != original - 1 or
                    payload.get("removed_builtin_rows") != 1 or
                    type(payload.get("caller_rva")) is not int or
                    payload["caller_rva"] not in PICKER_CALLERS):
                return None
            clean.update(candidate_public_key=candidate, original_rows=original,
                         copied_rows=copied, removed_builtin_rows=1,
                         caller_rva=payload["caller_rva"])
        return clean
    if payload.get("kind") != "slot_mapper_read_only":
        return None
    _public, mutable, arcani, _unit_id = _keys()
    key = payload.get("public_key")
    if (type(key) is not str or key not in mutable or key not in arcani or
            type(payload.get("preferred_slot")) is not int or
            not 0 <= payload["preferred_slot"] <= 15 or
            type(payload.get("clicked_index")) is not int or
            not 0 <= payload["clicked_index"] <= 15 or
            type(payload.get("selected_mode")) is not int or
            payload["selected_mode"] not in (1, 2) or
            type(payload.get("selected_count")) is not int or
            not 1 <= payload["selected_count"] <= MAX_ROWS or
            type(payload.get("owned_count")) is not int or
            not 0 <= payload["owned_count"] <= MAX_ROWS or
            (payload.get("selected_owned_slot") is not None and
             (type(payload["selected_owned_slot"]) is not int or
              not -1 <= payload["selected_owned_slot"] <= 15)) or
            type(payload.get("preferred_first_row_same_key")) is not bool or
            type(payload.get("clicked_first_row_same_key")) is not bool or
            any(payload.get(field) is not True for field in
                ("owner_model_match", "widget_match", "owner_widget_index_match",
                 "unique_source_row",
                 "native_unit_verified"))):
        return None
    return {"event": "slot_mapper_read_only", "public_key": key,
            "preferred_slot": payload["preferred_slot"],
            "clicked_index": payload["clicked_index"],
            "selected_mode": payload["selected_mode"],
            "selected_count": payload["selected_count"],
            "owned_count": payload["owned_count"],
            "selected_owned_slot": payload["selected_owned_slot"],
            "preferred_first_row_same_key": payload["preferred_first_row_same_key"],
            "clicked_first_row_same_key": payload["clicked_first_row_same_key"],
            "owner_model_match": True, "widget_match": True,
            "owner_widget_index_match": True,
            "unique_source_row": True, "native_unit_verified": True}
