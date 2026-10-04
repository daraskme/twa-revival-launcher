"""Bind own party selection updates to existing local bridge lifetimes."""
from __future__ import annotations

import threading

from native_custom_lobby import NativeLobbyError
from native_party_loadout_sync import PartyLoadoutSync, SerializedLoadoutApi


class _ReservedPrivateAdapter:
    _ADMISSION_PATHS = {'/create', '/join', '/ready', '/start_game',
                        '/change_team', '/change_squad'}

    def __init__(self, binding, adapter):
        self._binding, self._adapter = binding, adapter

    def handle_native(self, *args, **kwargs):
        path = args[0] if args else kwargs.get('path')
        # A retained post-battle /join is a read/return in this adapter. Keep
        # the existing private RLock through classification and its reentrant
        # handler so a concurrent leave cannot turn that read into a new join.
        # Lock ordering is private -> selection, matching the runtime's sync.
        private_lock = getattr(self._adapter, '_lock', None)
        if path == '/join' and private_lock is not None:
            with private_lock:
                return self._handle_reserved(path, args, kwargs,
                                             retained_join=self._retained_join(args, kwargs))
        return self._handle_reserved(path, args, kwargs)

    def _retained_join(self, args, kwargs):
        room_id = getattr(self._adapter, 'room_id', None)
        parser = getattr(self._adapter, '_request', None)
        if (room_id is None or getattr(self._adapter, '_battle', None) is None
                or not callable(parser)):
            return False
        names = ('raw', 'content_type', 'profile')
        values = [args[index + 1] if len(args) > index + 1 else kwargs.get(name)
                  for index, name in enumerate(names)]
        request = parser(*values)
        return isinstance(request, dict) and request.get('game_id') == room_id

    def _handle_reserved(self, path, args, kwargs, *, retained_join=False):
        owner = self._binding
        # Reserve before the adapter can read/sync a selection or create a
        # room. Never hold this lock while entering the private runtime lock:
        # its background step already uses private -> loadout lock ordering.
        with owner.mutation_lock:
            if owner.stop.is_set():
                raise NativeLobbyError(503, 'party_loadout_closed')
            if (path in self._ADMISSION_PATHS and not retained_join
                    and (owner._group_inflight or not owner._public_queue_idle())):
                raise NativeLobbyError(409, 'party_matchmaking_active')
            owner._private_inflight += 1
        try:
            return self._adapter.handle_native(*args, **kwargs)
        finally:
            # The adapter has released its private runtime lock by now.
            with owner.mutation_lock:
                owner._private_inflight -= 1

    def __getattr__(self, name):
        return getattr(self._adapter, name)


class PartySelectionBinding:
    def __init__(self, *, identity, economy_service, api, social, matchmaking,
                 stop, private_source, trace=None):
        self.stop, self.matchmaking = stop, matchmaking
        self._private_source = private_source
        self._trace = trace or (lambda _event: None)
        self._private_inflight = 0
        self._group_inflight = 0
        self.mutation_lock = threading.RLock()
        self.public_api = self.wrap_api(api)
        self.sync = PartyLoadoutSync(
            identity=identity, economy_service=economy_service,
            client=api._client, api_errors=api._errors,
            social_snapshot=social.snapshot,
            refresh_social=lambda: social.command('get'),
            mutation_lock=self.mutation_lock,
            background_allowed=self.background_allowed,
            close_timeout=17.0, trace=self._trace,
        )
        # Keep the exact bound-method object to detach only this owner's hook.
        self.dirty_callback = self.sync.mark_dirty

    def wrap_api(self, api):
        return SerializedLoadoutApi(api, self.mutation_lock)

    def wrap_private_adapter(self, adapter):
        return _ReservedPrivateAdapter(self, adapter)

    def _public_queue_idle(self):
        lab = getattr(self.matchmaking, 'lab_state', None)
        return isinstance(lab, dict) and lab.get('queue_state') == 'idle'

    def _private_idle(self):
        private = self._private_source()
        if private is None:
            return True
        adapter = getattr(private, 'adapter', None)
        coordinator = getattr(private, 'coordinator', None)
        # Read-only snapshot under mutation_lock. Never acquire private._lock
        # here: private callbacks already take private -> selection locks.
        return (adapter is not None and coordinator is not None
                and adapter.room_id is None and coordinator.state == 'idle')

    def reserve_public(self):
        """Reserve leader/follower admission without holding a lock over I/O.

        A leader's native queue is already matching at this point. Private
        inflight/retained state, rather than public queue idleness, is the gate.
        The caller must release exactly once, including exception paths.
        """
        with self.mutation_lock:
            if self.stop.is_set():
                raise NativeLobbyError(503, 'party_loadout_closed')
            if self._private_inflight or not self._private_idle():
                raise NativeLobbyError(409, 'private_matchmaking_active')
            self._group_inflight += 1

    def release_public(self):
        with self.mutation_lock:
            if self._group_inflight <= 0:
                raise NativeLobbyError(503, 'party_reservation_mismatch')
            self._group_inflight -= 1

    def background_allowed(self):
        # Called by the sync service with mutation_lock held. Public admission
        # sets this queue state before syncing its frozen battle selection.
        if self.stop.is_set() or self._private_inflight or self._group_inflight:
            return False
        if not self._public_queue_idle():
            return False
        # Do not acquire private._lock here (the reverse ordering deadlocks).
        # The reservation covers the initial None -> room transition; any
        # retained room or non-idle battle keeps background writes suspended.
        return self._private_idle()

    def observe_social(self, before, after):
        old = before.get('party') if isinstance(before, dict) else None
        new = after.get('party') if isinstance(after, dict) else None
        old_id = old.get('id') if isinstance(old, dict) else None
        new_id = new.get('id') if isinstance(new, dict) else None
        if new_id is not None and new_id != old_id:
            try:
                self.dirty_callback()
            except Exception as error:
                self._trace({'event': 'native_party_loadout_hint_failed',
                             'error_type': type(error).__name__})

    def close(self):
        self.sync.close()
