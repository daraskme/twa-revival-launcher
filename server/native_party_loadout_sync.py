"""Own-account party selection synchronization using the existing Worker API.

Created from the WIN-local economy, loadout, party and bridge contracts. No
request-supplied loadouts, peer state or additional transport enter this seam.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import threading
import time

from native_cloud_loadout import CloudLoadoutError, sync_cloud_loadout
from native_identity import NativeIdentity, derive_native_user_id
from native_social_party import PartyError


class PartyLoadoutSyncError(PartyError):
    pass


class SerializedLoadoutApi:
    """Serialize a complete existing sync operation, including its read checks."""
    def __init__(self, api, mutation_lock):
        if not callable(getattr(api, 'sync_loadout', None)):
            raise TypeError('api must implement sync_loadout')
        self._api, self._mutation_lock = api, mutation_lock

    def sync_loadout(self, *args, **kwargs):
        with self._mutation_lock:
            return self._api.sync_loadout(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._api, name)


@dataclass(frozen=True)
class _Selection:
    saved: int
    commander: str
    items: tuple[str, str, str]

    @property
    def key(self):
        return self.commander, self.items


class PartyLoadoutSync:
    PREPARE_PATHS = frozenset(('/create_party', '/respond_to_party_invitation',
                               '/reconnect_to_party', '/ready_party'))

    def __init__(self, *, identity, economy_service, client, api_errors,
                 social_snapshot, refresh_social, mutation_lock=None,
                 background_allowed=None, debounce_seconds=0.1,
                 close_timeout=6.0, trace=None):
        if (not isinstance(identity, NativeIdentity)
                or derive_native_user_id(identity.puid) != identity.native_user_id
                or getattr(economy_service, 'user_id', None) != identity.native_user_id):
            raise PartyLoadoutSyncError('party_loadout_identity_mismatch', 403)
        if (not callable(social_snapshot) or not callable(refresh_social)
                or (background_allowed is not None and not callable(background_allowed))
                or not isinstance(api_errors, tuple) or len(api_errors) != 3
                or any(not isinstance(error, type) or not issubclass(error, Exception)
                       for error in api_errors)
                or any(not callable(getattr(client, name, None))
                       for name in ('get_loadout', 'select_commander', 'put_loadout'))):
            raise TypeError('invalid party loadout dependencies')
        if (type(debounce_seconds) not in (int, float) or not 0 <= debounce_seconds <= 5
                or type(close_timeout) not in (int, float) or not 0 < close_timeout <= 60):
            raise ValueError('invalid party loadout timing')
        self._account_id, self._native_user_id = identity.puid, identity.native_user_id
        self._service, self._client, self._api_errors = economy_service, client, api_errors
        self._social_snapshot, self._refresh_social = social_snapshot, refresh_social
        self._background_allowed = background_allowed or (lambda: True)
        self._mutation_lock = mutation_lock if mutation_lock is not None else threading.RLock()
        self._debounce, self._close_timeout = debounce_seconds, close_timeout
        self._trace = trace or (lambda _event: None)
        self._condition = threading.Condition()
        self._closed = False
        self._pending = None
        self._deadline = 0.0
        self._observed_key = None
        self._inflight = 0
        # Validate the authority and catalog seam before creating a thread.
        self._selection()
        self._thread = threading.Thread(target=self._run, name='native-party-loadout', daemon=True)
        self._thread.start()

    def _selection(self):
        service = self._service
        if service.user_id != self._native_user_id:
            raise PartyLoadoutSyncError('party_loadout_identity_mismatch', 403)
        try:
            economy = service.economy
            # The existing service->economy ordering makes saved and loadout
            # one immutable observation. No network call holds either lock.
            with service._lock, economy._lock:
                state = economy.snapshot()
                loadout = economy.battle_loadout()
                saved, commander_key = state['saved'], state['active_commander']
                if (type(saved) is not int or not 0 < saved < 2**64
                        or loadout['commander'] != commander_key):
                    raise ValueError
                commander = economy.commanders[commander_key]
                own = state['commanders'][commander_key]
                units = loadout['units']
                if (type(commander['item_id']) is not int
                        or not 0 < commander['item_id'] < 2**64
                        or loadout['commander_item_id'] != commander['item_id']
                        or not isinstance(units, list) or len(units) != 3
                        or not isinstance(own['equipped_units'], list)
                        or len(own['equipped_units']) != 3):
                    raise ValueError
                items = []
                for slot, row in enumerate(units):
                    key = own['equipped_units'][slot]
                    catalog = economy.units[key]
                    if (type(row['slot']) is not int or row['slot'] != slot
                            or row['key'] != key or type(row['item_id']) is not int
                            or row['item_id'] != catalog['item_id']
                            or type(catalog['item_id']) is not int
                            or not 0 < catalog['item_id'] < 2**64
                            or catalog['faction'] != commander['faction']
                            or row['faction'] != commander['faction']):
                        raise ValueError
                    items.append(str(catalog['item_id']))
                return _Selection(saved, str(commander['item_id']), tuple(items))
        except PartyLoadoutSyncError:
            raise
        except Exception:
            raise PartyLoadoutSyncError('party_loadout_invalid_selection', 409) from None

    def _own_party(self):
        state = self._social_snapshot()  # Cached read only; never social.command here.
        party = state.get('party') if isinstance(state, dict) else None
        if party is None:
            return None
        if not isinstance(party, dict):
            return None
        members = party.get('members')
        own = (isinstance(members, list) and 1 <= len(members) <= 4
                and sum(isinstance(row, dict) and row.get('id') == self._account_id
                        for row in members) == 1)
        return party if own else None

    def _check_open(self):
        with self._condition:
            if self._closed:
                raise PartyLoadoutSyncError('party_loadout_closed', 503)

    def _report(self, result, error=None):
        event = {'event': 'native_party_loadout_sync', 'result': result}
        if error is not None:
            event['error_type'] = type(error).__name__
        try:
            self._trace(event)
        except Exception:
            pass

    def mark_dirty(self):
        """Capture committed own selection; caller supplies no identity or data."""
        self._check_open()
        if self._own_party() is None:
            return False
        selection = self._selection()
        with self._condition:
            if self._closed:
                raise PartyLoadoutSyncError('party_loadout_closed', 503)
            if selection.key == self._observed_key:
                return False
            self._observed_key = selection.key
            self._pending = selection
            self._deadline = time.monotonic() + self._debounce
            self._condition.notify_all()
        return True

    def ensure(self, path):
        """Fail closed before an already authorized create/join/reconnect/ready."""
        if path not in self.PREPARE_PATHS:
            raise PartyLoadoutSyncError('party_loadout_invalid_prepare_path', 400)
        self._check_open()
        self._execute(None)

    def _execute(self, pending):
        with self._condition:
            if self._closed:
                raise PartyLoadoutSyncError('party_loadout_closed', 503)
            self._inflight += 1
        try:
            with self._mutation_lock:
                self._check_open()
                if pending is not None:
                    party = self._own_party()
                    if party is None:
                        return True
                    if party.get('state') != 'lobby':
                        return False
                try:
                    allowed = self._background_allowed() is True
                except Exception:
                    raise PartyLoadoutSyncError('party_loadout_gate_unavailable', 503) from None
                if not allowed:
                    if pending is not None:
                        return False
                    raise PartyLoadoutSyncError('party_loadout_busy', 409)
                current = self._selection()  # Re-read after a competing save releases the lock.
                if pending is not None and current.key != pending.key:
                    # A newer dirty snapshot owns any follow-up. Never send a
                    # captured older selection merely because it was queued first.
                    return True
                try:
                    sync_cloud_loadout(self._client, current.commander, list(current.items),
                                       api_errors=self._api_errors)
                except CloudLoadoutError as error:
                    code = error.code if re.fullmatch(r'[a-z_]{1,64}', error.code) else 'failed'
                    raise PartyLoadoutSyncError('party_loadout_' + code, 409 if
                        ('conflict' in code or 'mismatch' in code) else 503) from None
                self._check_open()
                if self._selection().key != current.key:
                    raise PartyLoadoutSyncError('party_loadout_local_selection_changed', 409)
                with self._condition:
                    self._observed_key = current.key
                    if self._pending is not None and self._pending.key == current.key:
                        self._pending = None
            # Publish only after releasing shared/economy locks. The controller
            # may already hold its RLock while ensure waits for this sync lock.
            self._check_open()
            try:
                self._refresh_social()
            except Exception:
                raise PartyLoadoutSyncError('party_loadout_refresh_unconfirmed', 503) from None
            self._check_open()
            if self._selection().key != current.key:
                raise PartyLoadoutSyncError('party_loadout_local_selection_changed', 409)
            self._report('synchronized')
            return True
        finally:
            with self._condition:
                self._inflight -= 1
                self._condition.notify_all()

    def _run(self):
        while True:
            with self._condition:
                while not self._closed:
                    if self._pending is None:
                        self._condition.wait()
                    else:
                        delay = self._deadline - time.monotonic()
                        if delay <= 0:
                            break
                        self._condition.wait(delay)
                if self._closed:
                    return
                pending, self._pending = self._pending, None
            try:
                completed = self._execute(pending)
                if completed is False:
                    with self._condition:
                        if not self._closed and self._pending is None:
                            self._pending = pending
                            self._deadline = time.monotonic() + max(self._debounce, 0.5)
            except Exception as error:
                # The existing helper already resolves uncertain writes with
                # GET. Do not retry a failed generation on every timer tick.
                self._report('unconfirmed', error)

    def close(self):
        deadline = time.monotonic() + self._close_timeout
        with self._condition:
            self._closed = True
            self._pending = None
            self._condition.notify_all()
        if self._thread is threading.current_thread():
            raise PartyLoadoutSyncError('party_loadout_stop_unconfirmed', 503)
        self._thread.join(max(0, deadline - time.monotonic()))
        with self._condition:
            while self._inflight and time.monotonic() < deadline:
                self._condition.wait(max(0, deadline - time.monotonic()))
            if self._thread.is_alive() or self._inflight:
                # Python cannot cancel an in-flight transport. Retain the
                # owner and refuse to claim shutdown until it really ends.
                raise PartyLoadoutSyncError('party_loadout_stop_unconfirmed', 503)
