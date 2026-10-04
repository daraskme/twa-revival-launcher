"""Validated account/origin-scoped cache of GET /v1/career, never local career data.

The Worker owns settled results. This module never uploads aggregates, merges
local battle history, awards rewards, or writes the local career database.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import sqlite3
import threading
import time
from urllib.parse import urlsplit

MAX_COUNT = 2**53 - 1
MAX_MONEY = 2**64 - 1
MAX_WATERMARK = 2**63 - 1
COUNTS = ('battles', 'wins', 'losses', 'draws', 'known_kills',
          'kill_sample_battles', 'unknown_kill_battles')
MONEY = ('free_xp_cents', 'unit_xp_cents', 'silver_cents', 'max_unit_xp_cents')
SUM_MONEY = MONEY[:3]
SOURCE = 'cloudflare-d1-settled-native-reports'


class CloudCareerError(ValueError):
    """A fixed diagnostic code, never a server body, account or token."""


def _fail(code):
    raise CloudCareerError('cloud_career_' + code)


def _integer(value, maximum=MAX_COUNT):
    if type(value) is not int or not 0 <= value <= maximum:
        _fail('invalid_counter')
    return value


def _money(value):
    if value is None:
        return None
    if not isinstance(value, str) or re.fullmatch(r'0|[1-9][0-9]{0,19}', value) is None:
        _fail('invalid_money')
    result = int(value)
    if result > MAX_MONEY:
        _fail('invalid_money')
    return result


def _aggregate(value):
    if not isinstance(value, dict):
        _fail('invalid_aggregate')
    try:
        out = {key: _integer(value[key]) for key in COUNTS}
        out.update({key: _money(value[key]) for key in MONEY})
        kills, maximum = value['kills'], value['max_kills']
    except KeyError:
        _fail('incomplete_aggregate')
    b, samples = out['battles'], out['kill_sample_battles']
    if (b != out['wins'] + out['losses'] + out['draws']
            or b != samples + out['unknown_kill_battles']):
        _fail('inconsistent_denominator')
    if samples == 0:
        if out['known_kills'] != 0 or maximum is not None:
            _fail('inconsistent_unknown_kills')
    else:
        maximum = _integer(maximum)
        if maximum > out['known_kills'] or out['known_kills'] > maximum * samples:
            _fail('inconsistent_max_kills')
    complete = bool(b and samples == b)
    if complete:
        if _integer(kills) != out['known_kills']:
            _fail('inconsistent_kills')
    elif kills is not None:
        _fail('unknown_kills_coerced')
    if 'kills_known' in value and (type(value['kills_known']) is not bool
                                  or value['kills_known'] != complete):
        _fail('inconsistent_kills_known')
    for key in ('win_percent', 'average_kills'):
        number = value.get(key)
        if number is not None and (type(number) not in (int, float)
                                   or number < 0
                                   or number > (100 if key == 'win_percent' else MAX_COUNT)
                                   or not math.isfinite(number)):
            _fail('invalid_ratio')
    if (out['max_unit_xp_cents'] is not None and out['unit_xp_cents'] is not None
            and out['max_unit_xp_cents'] > out['unit_xp_cents']):
        _fail('inconsistent_max_xp')
    # The v1 aggregate has no individual-unit positive award evidence: a
    # zero total proves a zero maximum, otherwise that maximum is unknown.
    if out['max_unit_xp_cents'] != (0 if out['unit_xp_cents'] == 0 else None):
        _fail('inconsistent_max_xp')
    out.update(kills=kills, max_kills=maximum, kills_known=complete,
               win_percent=out['wins'] * 100 / b if b else None,
               average_kills=out['known_kills'] / samples if samples else None)
    return out


def _partition(total, children):
    children = list(children)
    for key in COUNTS:
        if sum(child[key] for child in children) != total[key]:
            _fail('inconsistent_group_totals')
    maximum = max((child['max_kills'] for child in children
                   if child['max_kills'] is not None), default=None)
    if total['max_kills'] != maximum:
        _fail('inconsistent_group_maximum')
    for key in SUM_MONEY:
        values = [child[key] for child in children]
        amount = sum(v for v in values if v is not None)
        expected = amount if all(v is not None for v in values) and amount <= MAX_MONEY else None
        if total[key] != expected:
            _fail('inconsistent_group_money')


def _catalog_keys(catalog, kind):
    try:
        rows = catalog[kind]
        keys = [row['key'] for row in rows]
        if (not isinstance(rows, list) or not keys or len(set(keys)) != len(keys)
                or any(not isinstance(k, str) or not k for k in keys)):
            _fail('invalid_catalogue')
        return set(keys)
    except (KeyError, TypeError):
        _fail('invalid_catalogue')


def _groups(value, allowed, *, allow_empty=False):
    if not isinstance(value, dict) or any(key not in allowed for key in value):
        _fail('invalid_group_keys')
    groups = {key: _aggregate(group) for key, group in sorted(value.items())}
    if not allow_empty and any(group['battles'] == 0 for group in groups.values()):
        _fail('empty_named_group')
    return groups


def _snapshot_revision(payload):
    revision = payload.get('snapshot_revision') if isinstance(payload, dict) else None
    if not isinstance(revision, str) or re.fullmatch(r'[0-9a-f]{64}', revision) is None:
        _fail('invalid_snapshot_revision')
    return revision


def normalize_cloud_summary(payload, native_catalog):
    """Convert the complete Worker snapshot to NativeCareerStats.summary schema.

    Money remains unknown when null and becomes a lossless Python int only
    from canonical decimal strings. Ratios derive from validated counters.
    Additional metadata/source fields do not enter the UI's semantic snapshot.
    """
    if (not isinstance(payload, dict) or type(payload.get('schema_version')) is not int
            or payload['schema_version'] != 1 or payload.get('kill_measure') != 'soldiers'):
        _fail('invalid_schema')
    _snapshot_revision(payload)
    if 'source' in payload and payload['source'] != SOURCE:
        _fail('invalid_source')
    commander_keys = _catalog_keys(native_catalog, 'commanders')
    unit_keys = _catalog_keys(native_catalog, 'units')
    try:
        overall = _aggregate(payload['overall'])
        commanders = _groups(payload['commanders'], commander_keys)
        units = _groups(payload['units'], unit_keys)
        modes = _groups(payload['modes'], {'pve', 'pvp'}, allow_empty=True)
        raw_joint = payload['commander_units']
        remote_time = _integer(payload['last_updated'])
    except KeyError:
        _fail('incomplete_snapshot')
    if set(modes) != {'pve', 'pvp'}:
        _fail('incomplete_modes')
    if not isinstance(raw_joint, dict) or set(raw_joint) != set(commanders):
        _fail('inconsistent_joint_commanders')
    joint = {key: _groups(value, unit_keys) for key, value in sorted(raw_joint.items())}
    _partition(overall, commanders.values())
    _partition(overall, modes.values())
    joint_units = {key for group in joint.values() for key in group}
    if set(units) != joint_units:
        _fail('inconsistent_joint_units')
    for key, unit in units.items():
        _partition(unit, (group[key] for group in joint.values() if key in group))
    for key, commander in commanders.items():
        group = joint[key]
        for field in ('battles', 'wins', 'losses', 'draws'):
            appearances = sum(unit[field] for unit in group.values())
            if (any(unit[field] > commander[field] for unit in group.values())
                    or not commander[field] <= appearances <= commander[field] * 3):
                _fail('inconsistent_unit_denominator')
        # An unknown same-type unit sample makes that battle's commander
        # total unknown; 1..3 distinct types can contribute that uncertainty.
        unknown = commander['unknown_kill_battles']
        unit_unknown = [unit['unknown_kill_battles'] for unit in group.values()]
        if any(count > unknown for count in unit_unknown) or not unknown <= sum(unit_unknown) <= unknown * 3:
            _fail('inconsistent_unit_samples')
        if len(group) == 1:
            only = next(iter(group.values()))
            if any(only[field] != commander[field] for field in COUNTS + ('max_kills',)):
                _fail('inconsistent_single_unit_totals')
        if all(unit['kills_known'] for unit in group.values()) and commander['kills_known']:
            if sum(unit['kills'] for unit in group.values()) != commander['kills']:
                _fail('inconsistent_commander_unit_kills')
        if sum(unit['known_kills'] for unit in group.values()) < commander['known_kills']:
            _fail('inconsistent_known_unit_kills')
        if commander['kills_known'] and any(unit['max_kills'] > commander['max_kills'] for unit in group.values()):
            _fail('inconsistent_unit_maximum')
        for field in SUM_MONEY:
            total, values = commander[field], [unit[field] for unit in group.values()]
            if total is not None:
                known = [value for value in values if value is not None]
                if (sum(known) > total or (total == 0 and len(known) != len(values))
                        or (len(known) == len(values) and sum(known) != total)):
                    _fail('inconsistent_unit_money')
    return {'schema_version': 1, 'kill_measure': 'soldiers', 'last_updated': remote_time,
            'overall': overall, 'commanders': commanders, 'units': units,
            'commander_units': joint, 'modes': modes}


def _identity(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 256
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        _fail('invalid_identity')
    return value


def _origin(value):
    if (not isinstance(value, str) or not value or '\\' in value
            or any(ord(c) < 33 for c in value)):
        _fail('invalid_origin')
    try:
        parts = urlsplit(value)
        host, port = parts.hostname, parts.port
    except ValueError:
        _fail('invalid_origin')
    if (not host or parts.username is not None or parts.password is not None
            or parts.query or parts.fragment or parts.path not in ('', '/')
            or parts.scheme not in ('http', 'https')):
        _fail('invalid_origin')
    host = host.rstrip('.').lower()
    if parts.scheme == 'http':
        try:
            loopback = host == 'localhost' or ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            _fail('invalid_origin')
    host = '[' + host + ']' if ':' in host else host
    suffix = '' if port is None or (parts.scheme, port) in (('http', 80), ('https', 443)) else ':' + str(port)
    return parts.scheme + '://' + host + suffix


def _path(value):
    value = Path(value).absolute()
    try:
        if (value.is_symlink() or value.resolve() != value
                or (value.is_file() and value.stat().st_nlink > 1)):
            _fail('aliased_path')
    except RuntimeError:
        _fail('aliased_path')
    return value


def cloud_career_cache_path(career_state_path, api_origin, account_id):
    """A separate cache path; never the supplied local career database itself."""
    state = _path(career_state_path)
    namespace = json.dumps([_origin(api_origin), _identity(account_id)], separators=(',', ':'))
    digest = hashlib.sha256(namespace.encode()).hexdigest()
    return _path(state.parent / 'cloud-career' / digest / 'snapshot.sqlite3')


def _encoded(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(',', ':'))


class CloudCareerCache:
    """One bounded-fetch background worker and an atomic, persistent snapshot."""

    def __init__(self, path, *, api_origin, account_id, native_user_id, native_catalog,
                 fetch_summary, trace=None, clock_ms=None, refresh_interval=30):
        if not callable(fetch_summary) or (trace is not None and not callable(trace)):
            _fail('invalid_callback')
        if clock_ms is not None and not callable(clock_ms):
            _fail('invalid_clock')
        if (type(refresh_interval) not in (int, float) or not math.isfinite(refresh_interval)
                or refresh_interval <= 0):
            _fail('invalid_refresh_interval')
        self.path = _path(path)
        self._namespace = (_origin(api_origin), _identity(account_id), _identity(native_user_id))
        self._catalog = copy.deepcopy(native_catalog)
        _catalog_keys(self._catalog, 'commanders'); _catalog_keys(self._catalog, 'units')
        self._fetch, self._trace_callback = fetch_summary, trace
        self._clock = clock_ms or (lambda: time.time_ns() // 1_000_000)
        self._interval = float(refresh_interval)
        self._condition = threading.Condition(threading.RLock())
        self._thread = None
        self._stopping = False
        self._closed = False
        self._running = False
        self._next_due = 0.0
        self._summary = None
        self._semantic = None
        self._revision = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _path(self.path)
        self._db = sqlite3.connect(str(self.path), timeout=3, check_same_thread=False)
        try:
            tables = {row[0] for row in self._db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables and tables != {'namespace', 'snapshot', 'revisions'}:
                _fail('unrelated_database')
            with self._db:
                self._db.execute('CREATE TABLE IF NOT EXISTS namespace (id INTEGER PRIMARY KEY CHECK(id=1), origin TEXT, account TEXT, native_user TEXT)')
                self._db.execute('CREATE TABLE IF NOT EXISTS snapshot (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL, semantic TEXT NOT NULL, revision TEXT NOT NULL, remote_time INTEGER NOT NULL, watermark INTEGER NOT NULL)')
                self._db.execute('CREATE TABLE IF NOT EXISTS revisions (revision TEXT PRIMARY KEY, semantic TEXT NOT NULL)')
                namespace = self._db.execute('SELECT origin,account,native_user FROM namespace WHERE id=1').fetchone()
                if namespace is None:
                    if tables:
                        _fail('missing_namespace')
                    self._db.execute('INSERT INTO namespace VALUES (1,?,?,?)', self._namespace)
                elif tuple(namespace) != self._namespace:
                    _fail('namespace_mismatch')
            saved = self._db.execute('SELECT payload,semantic,revision,watermark FROM snapshot WHERE id=1').fetchone()
            if saved is not None:
                payload = json.loads(saved[0])
                normalized = normalize_cloud_summary(payload, self._catalog)
                semantic = self._semantic_hash(normalized)
                if semantic != saved[1] or payload['snapshot_revision'] != saved[2]:
                    _fail('invalid_cached_snapshot')
                normalized['last_updated'] = _integer(saved[3], MAX_WATERMARK)
                self._summary, self._semantic, self._revision = normalized, semantic, saved[2]
        except BaseException:
            self._db.close()
            raise

    @staticmethod
    def _semantic_hash(summary):
        semantic = {key: value for key, value in summary.items() if key != 'last_updated'}
        return hashlib.sha256(_encoded(semantic).encode()).hexdigest()

    def _trace(self, event, *, battles=None, status=None):
        if self._trace_callback is None:
            return
        row = {'event': event}
        if type(battles) is int and 0 <= battles <= MAX_COUNT:
            row['battles'] = battles
        if type(status) is int and 100 <= status <= 599:
            row['status'] = status
        try:
            self._trace_callback(row)
        except Exception:
            pass

    def _accept(self, payload):
        # Identity fields are not required by the self-only API, but an
        # explicit contradictory identity must never enter this account cache.
        if isinstance(payload, dict):
            for key, expected in (('account_id', self._namespace[1]), ('user_id', self._namespace[1]),
                                  ('native_user_id', self._namespace[2])):
                if key in payload and payload[key] != expected:
                    _fail('response_account_mismatch')
        normalized = normalize_cloud_summary(payload, self._catalog)
        revision = _snapshot_revision(payload)
        semantic = self._semantic_hash(normalized)
        remote_time = normalized['last_updated']
        # Persist only normalized fields converted back to canonical wire
        # money, plus the opaque revision; discard source metadata/identities.
        cached_payload = copy.deepcopy(normalized)
        groups = [cached_payload['overall'], *cached_payload['commanders'].values(),
                  *cached_payload['units'].values(), *cached_payload['modes'].values(),
                  *(v for group in cached_payload['commander_units'].values() for v in group.values())]
        for group in groups:
            for key in MONEY:
                if group[key] is not None:
                    group[key] = str(group[key])
        cached_payload['snapshot_revision'] = revision
        with self._condition:
            if self._stopping:
                return
            with self._db:
                # Also serialize against an overlapping bridge process using
                # this account cache. Never derive a durable watermark from
                # just this process's potentially older in-memory snapshot.
                self._db.execute('BEGIN IMMEDIATE')
                prior = self._db.execute('SELECT semantic FROM revisions WHERE revision=?', (revision,)).fetchone()
                if prior is not None and prior[0] != semantic:
                    _fail('revision_content_conflict')
                current = self._db.execute('SELECT semantic,watermark FROM snapshot WHERE id=1').fetchone()
                changed = current is None or semantic != current[0]
                watermark = _integer(current[1], MAX_WATERMARK) if current is not None else 0
                if changed:
                    now = _integer(self._clock(), MAX_WATERMARK)
                    watermark = max(watermark + 1, now, remote_time)
                    _integer(watermark, MAX_WATERMARK)
                normalized['last_updated'] = watermark
                self._db.execute('INSERT OR IGNORE INTO revisions VALUES (?,?)', (revision, semantic))
                self._db.execute('INSERT OR REPLACE INTO snapshot VALUES (1,?,?,?,?,?)',
                                 (_encoded(cached_payload), semantic, revision, remote_time, watermark))
            self._summary, self._semantic, self._revision = normalized, semantic, revision
        self._trace('cloud_career_updated' if changed else 'cloud_career_unchanged',
                    battles=normalized['overall']['battles'])

    def _worker(self):
        while True:
            with self._condition:
                while not self._stopping:
                    delay = self._next_due - time.monotonic()
                    if delay <= 0:
                        break
                    self._condition.wait(delay)
                if self._stopping:
                    return
                self._running = True
            try:
                self._accept(self._fetch())
            except Exception as error:
                if isinstance(error, CloudCareerError):
                    event = 'cloud_career_invalid_snapshot'
                elif isinstance(error, sqlite3.Error):
                    event = 'cloud_career_cache_failed'
                else:
                    event = 'cloud_career_fetch_failed'
                self._trace(event, status=getattr(error, 'status', None))
            finally:
                with self._condition:
                    self._running = False
                    self._next_due = time.monotonic() + self._interval
                    self._condition.notify_all()

    def start(self):
        with self._condition:
            if self._closed or self._stopping:
                _fail('closed')
            if self._thread is not None:
                return
            thread = threading.Thread(target=self._worker, name='cloud-career-cache', daemon=True)
            try:
                thread.start()
            except BaseException:
                # A failed OS thread creation leaves a non-joinable Thread.
                # Do not retain it: startup cleanup must still close SQLite.
                # If a custom Thread implementation raised after starting,
                # retain that real worker so close() joins it before DB close.
                if thread.ident is not None:
                    self._thread = thread
                raise
            self._thread = thread

    def request_refresh(self):
        """Wake an eligible refresh; the interval also debounces explicit calls.

        A request during a fetch/cooldown is covered by the next periodic poll.
        The bridge's bounded transport runs on this worker, never a UI thread.
        """
        with self._condition:
            if self._closed or self._stopping or self._running:
                return False
            if time.monotonic() < self._next_due:
                return False
            self._condition.notify_all()
            return True

    def summary(self, user_id):
        if user_id != self._namespace[2]:
            _fail('summary_account_mismatch')
        with self._condition:
            return copy.deepcopy(self._summary)

    def close(self):
        with self._condition:
            if self._closed:
                return
            self._stopping = True
            thread = self._thread
            self._condition.notify_all()
        if thread is not None:
            thread.join(timeout=5)
            if thread.is_alive():
                # The bounded root transport should have returned by now.
                # Never close SQLite while an in-flight worker could use it.
                _fail('stop_unconfirmed')
        with self._condition:
            self._db.close()
            self._closed = True
