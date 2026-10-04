"""Durable, account-scoped career statistics from completed native battles.

This store is separate from reward/profile state. Callers must supply the
server-frozen allocation context and the durable settlement, never a browser
request body. Kills are native soldier kills, not destroyed unit formations.
Only complete public PvE/PvP reports are admitted. Missing counters remain
unknown, preserving verified battle counts without inventing zero performance.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
import time

from local_economy import EconomyError
from native_economy_service import resolve_native_final_outcome

MAX_COUNTER = 2**31 - 1
MAX_CURRENCY = 2**64 - 1
REWARD_FIELDS = ('free_xp_cents', 'unit_xp_cents', 'silver_cents')


class CareerStatsError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _canonical(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False,
                          separators=(',', ':'), allow_nan=False)
    except (ValueError, TypeError):
        raise CareerStatsError('invalid_career_json') from None


def _identity(value: object) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 128
            or any(ord(c) < 32 for c in value)):
        raise CareerStatsError('invalid_career_identity')
    return value


def _counter(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_COUNTER:
        raise CareerStatsError('invalid_career_counter')
    return value


def _currency_or_unknown(value: object) -> int | None:
    return value if type(value) is int and 0 <= value <= MAX_CURRENCY else None


class NativeCareerStats:
    """One SQLite file may safely contain several accounts and bridge runs."""

    def __init__(self, path: str | Path, native_catalog: dict):
        try:
            units = native_catalog['units']
            commanders = native_catalog['commanders']
            self._units = {r['key']: r['item_id'] for r in units}
            self._keys_by_item = {v: k for k, v in self._units.items()}
            self._commanders = {r['key'] for r in commanders}
            if (len(self._units) != len(units) or not self._units
                    or len(self._commanders) != len(commanders)
                    or not self._commanders or len(self._keys_by_item) != len(units)
                    or any(not isinstance(k, str) or not k or type(v) is not int
                           or not 0 < v < 2**64 for k, v in self._units.items())):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise CareerStatsError('invalid_career_catalogue') from None
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(self.path), timeout=10,
                                   check_same_thread=False)
        with self._db:
            self._db.execute('''CREATE TABLE IF NOT EXISTS career_battles (
                user_id TEXT NOT NULL, battle_id TEXT NOT NULL,
                record_json TEXT NOT NULL, record_digest TEXT NOT NULL,
                recorded_ms INTEGER NOT NULL,
                PRIMARY KEY(user_id,battle_id))''')

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def _record(self, context: object, final_event: object,
                settlement: object, user_id: str) -> tuple[dict | None, str | None]:
        user_id = _identity(user_id)
        if not all(isinstance(v, dict) for v in (context, final_event, settlement)):
            raise CareerStatsError('invalid_career_source')
        if context.get('mode') not in ('pve', 'pvp'):
            return None, 'unsupported_mode'
        if settlement.get('verified') is not True:
            return None, 'unverified'
        for field in ('settlement_pending', 'disputed'):
            if field in settlement and type(settlement[field]) is not bool:
                raise CareerStatsError('invalid_career_settlement_flag')
            if settlement.get(field) is True:
                return None, field
        if settlement.get('outcome') not in ('victory', 'defeat', 'draw'):
            return None, 'incomplete_outcome'
        battle_id = _identity(final_event.get('battle_id'))
        if settlement.get('match_id') != battle_id:
            raise CareerStatsError('career_battle_mismatch')
        commander = context.get('commander_key')
        if commander not in self._commanders:
            raise CareerStatsError('unknown_career_commander')
        if settlement.get('commander') != commander:
            raise CareerStatsError('career_commander_mismatch')
        mode = context['mode']
        if settlement.get('kind') != 'settle_' + mode:
            raise CareerStatsError('career_mode_mismatch')
        if ('cloud_battle_id' in context and context['cloud_battle_id'] != battle_id):
            raise CareerStatsError('career_battle_mismatch')
        if (not isinstance(context.get('roster_hash'), str)
                or settlement.get('roster_hash') != context['roster_hash']):
            raise CareerStatsError('career_roster_mismatch')
        participants = context.get('result_participants')
        if not isinstance(participants, list) or not participants:
            raise CareerStatsError('career_frozen_roster_required')
        policy = context.get('roster_policy')
        # Recent coordinated contexts also retain an identical policy under
        # pvp; reject disagreement instead of preferring either copy.
        pvp = context.get('pvp')
        if isinstance(pvp, dict) and pvp.get('roster_policy') is not None:
            if policy is not None and pvp['roster_policy'] != policy:
                raise CareerStatsError('career_roster_policy_mismatch')
            policy = pvp['roster_policy']
        try:
            outcome, verified = resolve_native_final_outcome(
                final_event, user_id=user_id, party_id=context.get('party_id'),
                map_key=context.get('map'), commander_key=commander,
                result_participants=participants, roster_policy=policy,
                display_name=context.get('display_name'))
        except EconomyError as error:
            raise CareerStatsError(error.code) from None
        if not verified:
            return None, 'afk'
        if outcome != settlement['outcome']:
            raise CareerStatsError('career_outcome_mismatch')
        items = context.get('unit_item_ids')
        if (not isinstance(items, list) or len(items) != 3
                or any(type(v) is not int or not 0 < v < 2**64 for v in items)):
            raise CareerStatsError('career_frozen_units_required')
        local = next(e['result_details'] for e in final_event['events']
                     if e['user_id'] == user_id)
        units = local['unit_results']
        if len(units) > len(items):
            raise CareerStatsError('invalid_career_unit_count')
        if any(item not in self._keys_by_item for item in items):
            raise CareerStatsError('career_unit_mismatch')
        normalized = []
        remaining = Counter(items)
        seen = set()
        for unit in units:
            if not isinstance(unit, dict):
                raise CareerStatsError('invalid_career_unit')
            slot = unit.get('merge_idx')
            key = unit.get('unit_record_key')
            item = unit.get('unit_id')
            if type(slot) is not int or not 0 <= slot < len(items) or slot in seen:
                raise CareerStatsError('invalid_career_unit_slot')
            if (not isinstance(key, str) or key not in self._units
                    or type(item) is not int or remaining[item] <= 0
                    or self._units[key] != item):
                raise CareerStatsError('career_unit_mismatch')
            seen.add(slot)
            remaining[item] -= 1
            known = 'kills' in unit
            kills = _counter(unit['kills']) if known else None
            normalized.append({'slot': slot, 'unit_key': key, 'kills': kills,
                               'kills_known': known})
        # Native merge indices follow the battle's display order, which real
        # results prove can differ from the frozen hangar order. Validate the
        # catalogue item multiset; never compare merge_idx to the hangar slot.
        for item, count in sorted(remaining.items()):
            normalized.extend({'slot': None, 'unit_key': self._keys_by_item[item],
                               'kills': None, 'kills_known': False}
                              for _ in range(count))
        normalized.sort(key=lambda r: (r['unit_key'], -1 if r['slot'] is None else r['slot']))
        kills_known = all(r['kills_known'] for r in normalized)
        raw_rewards = settlement.get('rewards')
        rewards = {key: _currency_or_unknown(raw_rewards.get(key))
                   if isinstance(raw_rewards, dict) else None for key in REWARD_FIELDS}
        # Canonical native finals have no per-unit currency awards. A known
        # zero total guarantees zero for each unit type; positive player-level
        # awards do not reveal how to attribute them between unit types.
        unit_rewards = {key: {field: 0 if rewards[field] == 0 else None
                              for field in REWARD_FIELDS}
                        for key in {r['unit_key'] for r in normalized}}
        # Retain an immutable proof digest, not raw player names/other players'
        # result payloads. A changed result retry must conflict even when the
        # changed field is not currently displayed by the career UI.
        return {
            'schema_version': 1, 'mode': mode, 'ruleset': context.get('ruleset'),
            'map': context.get('map'), 'commander': commander, 'outcome': outcome,
            'units': normalized, 'kills_known': kills_known,
            'kills': sum(r['kills'] for r in normalized) if kills_known else None,
            'rewards': rewards, 'unit_rewards': unit_rewards,
            'roster_hash': context['roster_hash'],
            'final_digest': hashlib.sha256(_canonical(final_event).encode()).hexdigest(),
        }, None

    def record_completed(self, context: object, final_event: object,
                         settlement: object, user_id: str) -> dict:
        """Insert one valid completion, or explicitly exclude incomplete data.

        Returns accepted/created booleans. Identical cross-run/process retries
        return created=False. Conflicting completed reports raise a stable
        CareerStatsError and leave the existing record intact.
        """
        record, reason = self._record(context, final_event, settlement, user_id)
        if record is None:
            return {'accepted': False, 'created': False, 'reason': reason}
        encoded = _canonical(record)
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        battle_id = final_event['battle_id']
        with self._lock, self._db:
            cursor = self._db.execute('''INSERT OR IGNORE INTO career_battles
                VALUES (?,?,?,?,?)''', (user_id, battle_id, encoded, digest,
                                        time.time_ns() // 1_000_000))
            created = cursor.rowcount == 1
            if created:
                prior = self._db.execute('''SELECT MAX(recorded_ms) FROM career_battles
                    WHERE user_id=? AND battle_id<>?''', (user_id, battle_id)).fetchone()[0]
                stamp = max(time.time_ns() // 1_000_000, (prior or 0) + 1)
                self._db.execute('''UPDATE career_battles SET recorded_ms=?
                    WHERE user_id=? AND battle_id=?''', (stamp, user_id, battle_id))
            existing = self._db.execute('''SELECT record_digest FROM career_battles
                WHERE user_id=? AND battle_id=?''', (user_id, battle_id)).fetchone()
            if existing[0] != digest:
                raise CareerStatsError('career_result_conflict')
        return {'accepted': True, 'created': created, 'reason': None}

    @staticmethod
    def _aggregate(records: list[dict]) -> dict:
        battles = len(records)
        counts = Counter(r['outcome'] for r in records)
        known = [r for r in records if r['kills'] is not None]
        samples = len(known)
        kills = sum(r['kills'] for r in known)
        rewards = {}
        for field in REWARD_FIELDS:
            values = [r.get('rewards', {}).get(field) for r in records]
            total = sum(v for v in values if v is not None)
            rewards[field] = (total if all(v is not None for v in values)
                              and total <= MAX_CURRENCY else None)
        # A positive player-level unit XP quote does not prove a maximum
        # individual unit award. Only an explicit zero is losslessly known.
        max_unit_xp = 0 if rewards['unit_xp_cents'] == 0 else None
        return {'battles': battles, 'wins': counts['victory'],
                'losses': counts['defeat'], 'draws': counts['draw'],
                'win_percent': counts['victory'] * 100 / battles if battles else None,
                'kills': kills if samples == battles and battles else None,
                'known_kills': kills,
                'kill_sample_battles': samples, 'unknown_kill_battles': battles - samples,
                'kills_known': bool(battles and samples == battles),
                'max_kills': max((r['kills'] for r in known), default=None),
                **rewards, 'max_unit_xp_cents': max_unit_xp,
                'average_kills': kills / samples if samples else None}

    def summary(self, user_id: str) -> dict:
        user_id = _identity(user_id)
        with self._lock:
            rows = self._db.execute('''SELECT record_json,recorded_ms FROM career_battles
                WHERE user_id=? ORDER BY battle_id''', (user_id,)).fetchall()
        records = [json.loads(r[0]) for r in rows]
        commanders = {}
        units = {}
        commander_units = {}
        for record in records:
            commanders.setdefault(record['commander'], []).append(record)
            unit_kills = {}
            for unit in record['units']:
                key = unit['unit_key']
                old = unit_kills.get(key, 0)
                unit_kills[key] = (old + unit['kills']
                                   if old is not None and unit['kills'] is not None else None)
            for key, kills in unit_kills.items():
                unit_record = {'outcome': record['outcome'], 'kills': kills,
                               'rewards': record.get('unit_rewards', {}).get(key, {})}
                units.setdefault(key, []).append(unit_record)
                commander_units.setdefault(record['commander'], {}).setdefault(key, []).append(unit_record)
        return {'schema_version': 1, 'kill_measure': 'soldiers',
                'last_updated': max((r[1] for r in rows), default=0),
                'overall': self._aggregate(records),
                'commanders': {k: self._aggregate(v) for k, v in sorted(commanders.items())},
                'units': {k: self._aggregate(v) for k, v in sorted(units.items())},
                'commander_units': {commander: {k: self._aggregate(v)
                    for k, v in sorted(group.items())}
                    for commander, group in sorted(commander_units.items())},
                'modes': {mode: self._aggregate([r for r in records if r['mode'] == mode])
                          for mode in ('pve', 'pvp')}}

    def import_battle_state(self, path: str | Path, user_id: str) -> dict:
        """Import settled rows for this account through the same validation.

        The source SQLite DB is always opened read-only with query_only enabled.
        It remains the caller's responsibility to choose trusted bridge-run
        paths. Corrupt/missing DBs raise; individual invalid results are counted
        by value-free reason, without preventing other valid historical rows.
        """
        user_id = _identity(user_id)
        imported = duplicates = excluded = 0
        reasons = Counter()
        con = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
        try:
            con.execute('PRAGMA query_only=ON')
            rows = con.execute('''SELECT b.battle_id,b.users_json,b.context_json,
                f.event_json,s.settlement_json
                FROM battles b JOIN final_events f ON f.battle_id=b.battle_id
                JOIN settlements s ON s.battle_id=f.battle_id AND s.user_id=f.user_id
                WHERE f.user_id=? AND b.phase IN ('result_ready','settled','delivered')''', (user_id,))
            for battle_id, members, context, final, settlement in rows:
                try:
                    member_ids = json.loads(members)
                    final = json.loads(final)
                    if (not isinstance(member_ids, list) or user_id not in member_ids
                            or not isinstance(final, dict) or final.get('battle_id') != battle_id):
                        raise CareerStatsError('career_source_identity_mismatch')
                    result = self.record_completed(json.loads(context), final,
                                                   json.loads(settlement), user_id)
                except (CareerStatsError, ValueError) as error:
                    result = {'accepted': False, 'reason': getattr(error, 'code', 'invalid_json')}
                if result['accepted']:
                    if result['created']:
                        imported += 1
                    else:
                        duplicates += 1
                else:
                    excluded += 1
                    reasons[result['reason']] += 1
        finally:
            con.close()
        return {'imported': imported, 'duplicates': duplicates, 'excluded': excluded,
                'reasons': dict(sorted(reasons.items()))}


__all__ = ['NativeCareerStats', 'CareerStatsError']
