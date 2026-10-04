"""Owned Recent Players overlay for native preference GET/HEAD responses.

The underlying preference object remains opaque and is not rewritten here.
Only a response view is merged. A later native PUT retains its original byte
contract; a subsequent GET overlays the current authoritative recent value
again, so stale whole-object writes cannot become the recent-view authority.
"""
from __future__ import annotations

import hashlib
import struct
import threading
import time

from native_recent_players import RecentPlayersError, project_social_recent
from native_recent_storage import NativeRecentStorageError, merge_recent_players_storage
from native_user_storage import StorageResponse


def fetch_owned_recent_snapshot(api):
    """Read with the existing authenticated configuration and a fresh budget.

    The long-lived social/matchmaking client's timeout and state are unchanged.
    No account identifier or history supplied by native input is sent.
    """
    from companion.api_client import ApiClient
    reader = ApiClient(api.base_url, api.client_version,
                       session_token=api.session_token,
                       timeout=min(api.timeout, 2.0), total_timeout=3.0)
    return reader._request('GET', '/v1/social')


class RecentPlayersProjection:
    def __init__(self, *, account_id, native_user_id, native_id_for,
                 fetch_snapshot, trace=None, now_seconds=None):
        # The account owns the Worker session; the storage route uses the
        # separately bound native identity. Never derive either from a name.
        project_social_recent({'recent': []}, account_id=account_id,
                              source_account_id=account_id)
        if native_id_for(account_id) != native_user_id:
            raise RecentPlayersError('recent_storage_identity_mismatch')
        if not callable(fetch_snapshot):
            raise TypeError('fetch_snapshot must be callable')
        self.account_id, self.native_user_id = account_id, native_user_id
        self.fetch_snapshot = fetch_snapshot
        self.trace = trace or (lambda _: None)
        self.now_seconds = now_seconds or (lambda: int(time.time()))
        self._lock = threading.RLock()
        self._projection = None
        self._revision = None
        self._modified = 0
        self._rich_signature = None
        self._needs_refresh = False

    def _trace(self, event, **metadata):
        try:
            self.trace({'event': event, **metadata})
        except Exception:
            pass

    def update(self, snapshot, *, source_account_id):
        """Observe an authenticated social view; no preference IO occurs."""
        if source_account_id != self.account_id:
            raise RecentPlayersError('recent_source_account_mismatch')
        try:
            projection = project_social_recent(snapshot, account_id=self.account_id,
                                              source_account_id=source_account_id)
            # GET enriches mapKey, whereas heartbeat/mutation omit it. Compare
            # only the encounter fields shared by those authenticated views.
            signature = tuple((row.get('id'), row.get('displayName'),
                               row.get('battleId'), row.get('playedAt'))
                              for row in snapshot['recent'] if isinstance(row, dict))
            revision = snapshot.get('revision')
            if 'revision' in snapshot and (type(revision) is not int or not 0 <= revision < 2**53):
                raise RecentPlayersError('invalid_recent_revision')
            modified = self.now_seconds()
            if type(modified) is not int or not 0 <= modified <= 0xffffffff:
                raise RecentPlayersError('invalid_recent_clock')
        except RecentPlayersError:
            self._trace('native_recent_projection_skipped', reason='invalid_snapshot')
            return False
        with self._lock:
            if self._revision is not None and (revision is None or revision < self._revision):
                return False
            previous = self._projection
            self._revision = revision
            if projection.value is None:
                # Missing enrichment is not deletion. Keep a previously
                # verified view while a changed encounter set awaits GET.
                self._needs_refresh = previous is None or signature != self._rich_signature
            else:
                self._projection = projection
                self._rich_signature = signature
                self._needs_refresh = False
                if previous is None or previous.value != projection.value:
                    self._modified = modified
        if projection.value is None:
            self._trace('native_recent_projection_skipped', reason='missing_metadata',
                        rows=projection.missing_metadata)
            return False
        if previous != projection:
            self._trace('native_recent_projection_ready', players=projection.players,
                        battles=projection.battles, omitted=projection.omitted_for_capacity)
        return True

    def project(self, blob, *, storage_owner_id):
        if storage_owner_id != self.native_user_id:
            raise RecentPlayersError('recent_storage_identity_mismatch')
        with self._lock:
            ready = self._projection is not None and self._projection.value is not None
            needs_refresh = self._needs_refresh
        if not ready or needs_refresh:
            # MPFileStorage reads once during login. If the background social
            # poll has not delivered usable metadata yet, make that first read
            # obtain the owned view rather than serving a permanent empty UI.
            # No projection lock is held while API callbacks run.
            try:
                snapshot = self.fetch_snapshot()
                self.update(snapshot, source_account_id=self.account_id)
            except Exception:
                self._trace('native_recent_projection_skipped', reason='fetch_failed')
        with self._lock:
            projection, modified = self._projection, self._modified
        if projection is None or projection.value is None:
            return blob
        if blob is None and not projection.players:
            return None  # Do not create an empty preference object needlessly.
        original = struct.pack('<II', 1, 0) if blob is None else blob
        try:
            return merge_recent_players_storage(original, projection.value,
                owner_id=storage_owner_id, authenticated_user_id=self.native_user_id,
                modified_at_seconds=modified)
        except NativeRecentStorageError:
            # Unsupported/malformed/unreadable preference data is never reset.
            self._trace('native_recent_projection_skipped', reason='unsupported_blob')
            return blob


class ProjectedNativeUserStorage:
    """Wrap the existing process-bound storage; modify read responses only."""
    def __init__(self, storage, projection: RecentPlayersProjection):
        if storage.current_user_id() != projection.native_user_id:
            raise RecentPlayersError('recent_storage_identity_mismatch')
        self.storage, self.projection = storage, projection

    def __getattr__(self, name):
        return getattr(self.storage, name)

    def handle(self, method, path, body=b''):
        if (method not in ('GET', 'HEAD')
                or not self.storage.matches_path(path)
                or self.storage.current_user_id() != self.projection.native_user_id):
            return self.storage.handle(method, path, body)
        # A HEAD needs the same representation length/ETag as GET, so obtain
        # the original bytes through the existing validated read path.
        response = self.storage.handle('GET', path, body)
        if response is None or response.status not in (200, 404):
            return response
        original = response.body if response.status == 200 else None
        value = self.projection.project(original, storage_owner_id=self.storage.current_user_id())
        if value is None:
            return self.storage._missing(method)  # Confirmed owned NoSuchKey.
        headers = {**(response.headers or {}), 'Content-Length': str(len(value)),
                   'ETag': '"' + hashlib.sha256(value).hexdigest() + '"'}
        return StorageResponse(200, value if method == 'GET' else b'',
                               content_type='application/octet-stream', headers=headers)


__all__ = ['RecentPlayersProjection', 'ProjectedNativeUserStorage', 'fetch_owned_recent_snapshot']
