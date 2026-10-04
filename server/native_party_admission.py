"""Own-authenticated public party admission and follower queue adoption.

Only the leader sends a start intent. Every companion discovers its own frozen
seat, verifies its own saved squad and uploads only its own rows. The social
party is never replaced by the battle's native party_id.
"""
from __future__ import annotations

import copy
import threading
import uuid
from contextlib import contextmanager

from native_cloud_loadout import CloudLoadoutError, _view
from native_custom_lobby import NativeLobbyError
from native_pvp_coordinator import PvpCoordinatorError, _canonical_uuid
from native_social_party import PartyError, validate_snapshot

ACTIVE = {'pending', 'queued', 'assigned', 'battle', 'cancelling'}
TERMINAL = {'cancelled', 'expired', 'completed', 'failed'}


def validated_attempt(view, own_id):
    if not isinstance(view, dict) or 'partyAttempt' not in view:
        raise PvpCoordinatorError('invalid_party_attempt_view')
    attempt = view['partyAttempt']
    if attempt is None:
        return None
    required = {'attemptId', 'partyId', 'phase', 'mode', 'ruleset', 'memberIds',
                'memberCount', 'ownLoadoutRevision', 'createdAt', 'expiresAt',
                'rosterPolicyVersion'}
    if (not isinstance(attempt, dict) or not required <= attempt.keys()
            or set(attempt) - required - {'assignmentId', 'battleId'}):
        raise PvpCoordinatorError('invalid_party_attempt')
    for key in ('attemptId', 'partyId'):
        _canonical_uuid(attempt[key], 'invalid_party_attempt')
    for key in ('assignmentId', 'battleId'):
        if key in attempt:
            _canonical_uuid(attempt[key], 'invalid_party_attempt')
    members = attempt['memberIds']
    if (not isinstance(members, list) or not 1 <= len(members) <= 4
            or any(not isinstance(item, str) or not 1 <= len(item) <= 36
                   or not all(char.isascii() and (char.isalnum() or char in '_-') for char in item)
                   for item in members)
            or len(set(members)) != len(members) or own_id not in members
            or type(attempt['memberCount']) is not int or attempt['memberCount'] != len(members)
            or attempt['phase'] not in ACTIVE | TERMINAL
            or attempt['mode'] not in ('pve', 'pvp')
            or attempt['ruleset'] not in ('territory', 'annihilation')
            or type(attempt['rosterPolicyVersion']) is not int or attempt['rosterPolicyVersion'] not in (2, 3, 4, 5)
            or any(type(attempt[key]) is not int or not 0 <= attempt[key] < 2**53
                   for key in ('ownLoadoutRevision', 'createdAt', 'expiresAt'))
            or attempt['expiresAt'] <= attempt['createdAt']):
        raise PvpCoordinatorError('invalid_party_attempt')
    return copy.deepcopy(attempt)


class NativePartyAdmission:
    def __init__(self, api, *, social, identity, binding, matchmaking,
                 profile_source, stop, trace=None, notify=None):
        if identity.puid != identity.native_user_id:
            raise PvpCoordinatorError('party_admission_identity_mismatch')
        self._api, self._client = api, api._client
        self.social, self.own_id = social, identity.puid
        self.binding, self.matchmaking = binding, matchmaking
        self.profile_source, self.stop = profile_source, stop
        self.trace = trace or (lambda _event: None)
        self.notify = notify or (lambda _state: None)
        self._lock = threading.RLock()
        self._thread = None
        self._attempt = None
        self._request = None
        self._ignored = set()
        # Adoption failures also enter _ignored; they do not prove that an
        # already owned local queue has been released by its coordinator.
        self._retired = set()
        self._cancel_attempted = set()
        self._local_loadout = None
        self._local_generation = None
        self._local_attempt = None
        self._prepared_release = None
        self._peer_cancel = None
        self._self_cancel_generation = None
        self._last_error = None
        self.cancel_guard = self._guard_cancel
        self.cancel_scope = self._cancel_scope

    def __getattr__(self, name):
        return getattr(self._api, name)

    def _request_api(self, method, path, body=None):
        return self._api._call(lambda: self._client._request(
            method, path, **({} if body is None else {'body': body})))

    def _social_party(self, *, cached=False):
        try:
            snapshot = self.social.snapshot() if cached else self.social.command('get')
            return validate_snapshot(snapshot, self.own_id)['party']
        except PartyError as error:
            raise PvpCoordinatorError(error.code, error.status) from None
        except self._api._errors as error:
            raise PvpCoordinatorError('party_social_unavailable') from None

    def _remember(self, view):
        attempt = validated_attempt(view, self.own_id)
        local = self._local_attempt
        completed = getattr(self.matchmaking, 'is_completed_pvp_generation', None)
        if (local is not None and self._attempt is not None
                and local[0] == self._attempt['attemptId']
                and self.matchmaking.lab_state.get('queue_state') == 'idle'
                and callable(completed) and completed(local[1]) is True):
            # A native final can clear MM before the coordinator observes it.
            # Only its atomic, generation-specific completion receipt proves
            # completion; idle, cancellation and adoption failure do not.
            # Keep replacement fenced until released() has also retired the
            # old coordinator and transport. Its callback must not retire a
            # newer attempt adopted in this intervening window.
            self._ignored.add(local[0])
        if self._attempt is not None and self._attempt['phase'] in ACTIVE:
            replacement = attempt is not None and attempt['attemptId'] != self._attempt['attemptId']
            if replacement:
                # A delayed poll may skip the old terminal receipt. Accept the
                # new authoritative attempt only after explicit local release,
                # never merely because adoption failed or a queue is idle.
                if (self._attempt['attemptId'] not in self._retired
                        or self.matchmaking.lab_state.get('queue_state') != 'idle'):
                    raise PvpCoordinatorError('party_attempt_lost')
            else:
                if attempt is None:
                    raise PvpCoordinatorError('party_attempt_lost')
                keys = ('partyId', 'mode', 'ruleset', 'memberIds', 'ownLoadoutRevision',
                        'createdAt', 'expiresAt', 'rosterPolicyVersion')
                if any(attempt[key] != self._attempt[key] for key in keys):
                    raise PvpCoordinatorError('party_attempt_changed')
        self._attempt = attempt
        return attempt

    def _get(self):
        view = self._request_api('GET', '/v1/matchmaking/party')
        self._remember(view)
        # Only an own-authenticated read can establish a remote cancellation.
        # A cancel POST response or an old attempt seen by a new queue cannot.
        local = self._local_attempt
        if (local is not None and self._attempt is not None
                and self._attempt['phase'] == 'cancelled'
                and self._attempt['attemptId'] == local[0]
                and self._local_generation is local[1]
                and self._self_cancel_generation is not local[1]
                and self.matchmaking.pvp_queue_generation is local[1]):
            self._peer_cancel = local
        return view

    def _own_loadout(self):
        try:
            return _view(self._api._call(self._client.get_loadout))
        except CloudLoadoutError as error:
            raise PvpCoordinatorError(error.code) from None

    def _verify_selection(self, attempt, desired):
        selected = self._own_loadout()
        if (selected.revision != attempt['ownLoadoutRevision']
                or (selected.commander_id, list(selected.item_ids)) != (
                    desired['commander_id'], desired['item_ids'])):
            raise PvpCoordinatorError('party_local_selection_changed')

    @contextmanager
    def _public_reservation(self):
        self.binding.reserve_public()
        try:
            yield
        finally:
            self.binding.release_public()

    def sync_loadout(self, commander_id, item_ids):
        with self._lock, self._public_reservation():
            if self.stop.is_set():
                raise PvpCoordinatorError('party_admission_closed')
            self._local_generation = self.matchmaking.pvp_queue_generation
            self._check_generation()
            self._local_loadout = {'commander_id': commander_id, 'item_ids': list(item_ids)}
            self._get()
            if self._attempt and self._attempt['phase'] in ACTIVE:
                self._verify_selection(self._attempt, self._local_loadout)
            else:
                if self.stop.is_set():
                    raise PvpCoordinatorError('party_admission_closed')
                self._check_generation()
                self._api.sync_loadout(commander_id, item_ids)

    def sync_current_queue(self):
        # Capture the trusted selection while cancellation holds the same
        # admission lock. A second /matchmake cannot substitute its squad
        # between the coordinator's local read and this cloud write.
        with self._lock:
            generation = self.matchmaking.pvp_queue_generation
            if generation is None:
                raise PvpCoordinatorError('party_local_queue_changed', 409)
            desired = self.matchmaking.pvp_local_cloud_loadout()
            if self.matchmaking.pvp_queue_generation is not generation:
                raise PvpCoordinatorError('party_local_queue_changed', 409)
            self.sync_loadout(desired['commander_id'], desired['item_ids'])

    def _check_generation(self):
        if (self._local_generation is None
                or self.matchmaking.pvp_queue_generation is not self._local_generation):
            raise PvpCoordinatorError('party_local_queue_changed', 409)

    def join(self, ruleset):
        return self._join('pvp', ruleset)

    def join_coop(self, ruleset):
        return self._join('pve', ruleset)

    def _join(self, mode, ruleset):
        with self._lock, self._public_reservation():
            self._check_generation()
            if self.stop.is_set():
                raise PvpCoordinatorError('party_admission_closed')
            if self._request is not None:
                if (self._request['mode'], self._request['ruleset']) != (mode, ruleset):
                    raise PvpCoordinatorError('party_matchmaking_mode_mismatch')
                return self._active_view(self._resolve_request(), mode, ruleset)
            view = self._get()
            if self._attempt and self._attempt['phase'] in ACTIVE:
                result = self._active_view(view, mode, ruleset)
                self._request = None
                return result
            party = self._social_party()
            if party is None:
                if self.stop.is_set():
                    raise PvpCoordinatorError('party_admission_closed')
                self._check_generation()
                return self._api.join_coop(ruleset) if mode == 'pve' else self._api.join(ruleset)
            if (party['leader'] != self.own_id or party['state'] != 'lobby'
                    or (party['mode'], party['ruleset']) != (mode, ruleset)):
                raise PvpCoordinatorError('party_leader_start_required', 409)
            selected = self._own_loadout()
            if self._local_loadout != {'commander_id': selected.commander_id,
                                       'item_ids': list(selected.item_ids)}:
                raise PvpCoordinatorError('party_local_selection_changed')
            # Persist this request in the process across uncertain HTTP results.
            # Worker also converges compatible requests after a process restart.
            request = {'partyId': party['id'], 'partyRevision': party['revision'],
                       'mode': mode, 'ruleset': ruleset,
                       'leaderLoadoutRevision': selected.revision}
            if self._request is None or any(self._request[key] != value for key, value in request.items()):
                self._request = dict(request, requestId=str(uuid.uuid4()))
            if self.stop.is_set():
                raise PvpCoordinatorError('party_admission_closed')
            return self._active_view(self._resolve_request(), mode, ruleset)

    def _resolve_request(self):
        # Replay the exact key, including when another member already cancelled
        # it. A fresh party revision is a different Play intent, never a retry.
        if self.stop.is_set():
            raise PvpCoordinatorError('party_admission_closed')
        self._check_generation()
        view = self._request_api('POST', '/v1/matchmaking/party/start', self._request)
        self._remember(view)
        self._request = None
        return view

    def _active_view(self, view, mode, ruleset):
        attempt = self._attempt
        if (attempt is None or attempt['phase'] in TERMINAL | {'cancelling'}
                or attempt['attemptId'] in self._ignored):
            raise PvpCoordinatorError('party_matchmaking_finished', 409)
        if (attempt['mode'], attempt['ruleset']) != (mode, ruleset):
            raise PvpCoordinatorError('party_matchmaking_mode_mismatch')
        if (self._local_generation is not None
                and self.matchmaking.pvp_queue_generation is self._local_generation):
            self._local_attempt = (attempt['attemptId'], self._local_generation)
        if view.get('status') == 'idle':
            # A reserved group is never converted into an individual rejoin.
            if attempt['phase'] == 'pending':
                return dict(view, status='queued', pollAfterMs=1000)
            raise PvpCoordinatorError('party_matchmaking_state_mismatch')
        return view

    def status(self):
        with self._lock:
            if self._request is not None:
                return self._join(self._request['mode'], self._request['ruleset'])
            if self._attempt:
                mode, ruleset = self._attempt['mode'], self._attempt['ruleset']
                return self._active_view(self._get(), mode, ruleset)
            return self._api.status()

    def prepared_battle_terminal(self, prepared, generation):
        terminal = getattr(self._api, 'prepared_battle_terminal', None)
        if not callable(terminal):
            return False
        with self._lock:
            if (self.stop.is_set()
                    or self.matchmaking.pvp_queue_generation is not generation):
                return False
            local, known = self._local_attempt, self._attempt
            if terminal(prepared, generation) is not True:
                return False
            if (self.stop.is_set()
                    or self.matchmaking.pvp_queue_generation is not generation):
                return False
            if local is not None and known is not None:
                if (local[0] != known['attemptId']
                        or self._local_generation is not local[1]
                        or known.get('assignmentId') != prepared.assignment_id
                        or known.get('battleId') not in (None, prepared.battle_id)):
                    return False
                self._prepared_release = (generation, local[0], local[1])
            return True

    def prepared_party_terminal(self, prepared, generation):
        """Read a terminal receipt for this exact party's prepared battle.

        No cancellation or rejoin is inferred from an idle/missing response.
        The caller must recheck the native READY barrier after this network
        read before clearing the generation. A started battle is independent
        of the party admission lease and must not use this proof.
        """
        with self._lock:
            local, known = self._local_attempt, self._attempt
            if (self.stop.is_set() or local is None or known is None
                    or local[0] != known['attemptId']
                    or self._local_generation is not local[1]
                    or not self.matchmaking.is_current_pvp_generation(local[1])
                    or self.matchmaking.pvp_queue_generation is not generation
                    or known.get('battleId') not in (None, prepared.battle_id)
                    or (known.get('assignmentId'), known['mode'], known['ruleset']) != (
                        prepared.assignment_id, prepared.mode, prepared.ruleset)):
                return False
            binding = self.matchmaking.pvp_binding
            if (not isinstance(binding, dict)
                    or (binding.get('battle_id'), binding.get('assignment_id')) != (
                        prepared.battle_id, prepared.assignment_id)):
                return False
            view = self._request_api('GET', '/v1/matchmaking/party')
            try:
                remote = validated_attempt(view, self.own_id)
            except (KeyError, TypeError, ValueError):
                # Malformed JSON types (for example an array-valued phase)
                # cannot become a generic coordinator failure and abort it.
                raise PvpCoordinatorError('invalid_party_attempt_view') from None
            if (remote is None or remote['phase'] not in TERMINAL
                    or view.get('status') != 'idle'
                    or 'assignment' not in view or view['assignment'] is not None):
                return False
            frozen = ('attemptId', 'partyId', 'mode', 'ruleset', 'memberIds',
                      'ownLoadoutRevision', 'createdAt', 'expiresAt',
                      'rosterPolicyVersion')
            if (any(remote.get(key) != known.get(key) for key in frozen)
                    or (remote.get('battleId'), remote.get('assignmentId')) != (
                        prepared.battle_id, prepared.assignment_id)
                    or self.stop.is_set()
                    or self.matchmaking.pvp_queue_generation is not generation
                    or not self.matchmaking.is_current_pvp_generation(local[1])):
                return False
            # Keep the active admission fence until native phase is rechecked
            # and the exact queue is cleared. READY can win during this GET.
            self._prepared_release = (generation, local[0], local[1])
            return True

    def retryable_admission_error(self, error):
        # The native queue's original deadline still bounds retries. A lost
        # cross-DO response never becomes a solo join or a fabricated success.
        with self._lock:
            if self._request is None and self._attempt is None:
                return False
            return error.status in (0, 503) and error.code in {
                'worker_unreachable', 'party_attempt_reconciling', 'service_unavailable'}

    def cancel(self):
        with self._lock:
            if self._attempt and self._attempt['phase'] in ACTIVE:
                view = self._request_api('POST', '/v1/matchmaking/party/cancel',
                                         {'attemptId': self._attempt['attemptId']})
                self._remember(view)
                if self._attempt and self._attempt['phase'] not in TERMINAL:
                    raise PvpCoordinatorError('party_cancel_unconfirmed', 409)
                return view
            return self._api.cancel()

    def _guard_cancel(self):
        with self._lock:
            self._self_cancel_generation = self.matchmaking.pvp_queue_generation
            self._peer_cancel = None
            # Serializes against a leader's in-flight start and a follower's
            # admission, including the interval before local attempt adoption.
            try:
                if self._request is not None:
                    self._resolve_request()
                if self._attempt is not None and self._attempt['phase'] in ACTIVE:
                    self.cancel()
            except PvpCoordinatorError as error:
                raise NativeLobbyError(error.status or 503, error.code) from None

    @contextmanager
    def _cancel_scope(self):
        # Keep the admission lock until NativeMatchmaking has cleared the
        # acknowledged queue. This closes the guard-return/local-clear gap.
        with self._lock:
            self._guard_cancel()
            yield

    def validate_party_participants(self, rows, policy):
        with self._lock:
            if self._attempt is None or self._attempt['phase'] not in ACTIVE:
                return
            # Public assignments now use v5 (independent T10 CPU seats).
            # Party validation must accept the same reviewed versions as
            # validated_attempt and the coordinator's frozen roster parser.
            if (not isinstance(policy, dict) or type(policy.get('version')) is not int
                    or policy['version'] not in (2, 3, 4, 5)):
                raise PvpCoordinatorError('party_roster_policy_required')
            members = self._attempt['memberIds']
            admitted = [row for row in rows if row['userId'] in members]
            if (len(admitted) != len(members) or len({row['userId'] for row in admitted}) != len(members)
                    or len({row['team'] for row in admitted}) != 1):
                raise PvpCoordinatorError('party_roster_split')

    def released(self, reason, *, generation=None):
        with self._lock:
            if generation is not None:
                receipt = self._prepared_release
                if receipt is None or receipt[0] is not generation:
                    return
                self._prepared_release = None
                self._ignored.add(receipt[1])
                if self.matchmaking.is_cleared_pvp_generation(generation):
                    self._retired.add(receipt[1])
                # Native Play/admission can enter another generation after
                # the old abort edge, before this callback. Retire only the
                # proven old receipt; preserve every new request and context.
                local = self._local_attempt
                if (local is None or local[0] != receipt[1]
                        or local[1] is not receipt[2]
                        or self._local_generation is not receipt[2]
                        or self._attempt is None
                        or self._attempt['attemptId'] != receipt[1]):
                    return
            else:
                self._prepared_release = None
            peer_cancel, self._peer_cancel = self._peer_cancel, None
            if self._attempt is not None:
                self._ignored.add(self._attempt['attemptId'])
                if self.matchmaking.lab_state.get('queue_state') == 'idle':
                    self._retired.add(self._attempt['attemptId'])
            self._request = None
            if (peer_cancel is None or reason == 'queue_cleared'
                    or self.stop.is_set() or self._attempt is None
                    or self._attempt['phase'] != 'cancelled'
                    or self._attempt['attemptId'] != peer_cancel[0]
                    or self._local_attempt is None
                    or self._local_attempt[0] != peer_cancel[0]
                    or self._local_attempt[1] is not peer_cancel[1]):
                return
            # Reserve the public boundary, but do not hold the shared account
            # mutation lock while sending to the local XMPP socket.
            try:
                with self.binding.mutation_lock:
                    if not self.binding.background_allowed():
                        return
                    self.binding.reserve_public()
                try:
                    count = self.matchmaking.notify_cancelled_party_queue(
                        peer_cancel[1], self.notify, stop=self.stop)
                    if count is not None:
                        self.trace({'event': 'native_party_peer_cancel_notification',
                                    'state': 'cancelled', 'clients': count})
                finally:
                    self.binding.release_public()
            except Exception as error:
                # Cleanup must finish even when sendall wrote an unknown prefix.
                # The queue gate already consumed that send; never replay it.
                try:
                    self.trace({'event': 'native_party_peer_cancel_notification_failed',
                                'reason': getattr(error, 'code', type(error).__name__)})
                except Exception:
                    pass

    def step(self):
        with self._lock:
            if self.stop.is_set():
                return
            lab = self.matchmaking.lab_state
            if lab.get('queue_state') != 'idle':
                return
            if self._attempt is None:
                with self.binding.mutation_lock:
                    if not self.binding.background_allowed():
                        return
                # NativeSocial already refreshes this cache every five seconds
                # and after local party actions. It is only a discovery hint:
                # the following own-authenticated GET remains authoritative.
                # Avoid doubling idle polling past the 120/min API budget.
                party = self._social_party(cached=True)
                if party is None:
                    return
            view = self._get()
            attempt = self._attempt
            if attempt is None or attempt['phase'] in TERMINAL:
                return
            attempt_id = attempt['attemptId']
            if attempt_id in self._ignored:
                if attempt_id not in self._cancel_attempted:
                    try:
                        self.cancel()
                    except PvpCoordinatorError as error:
                        if error.status != 409:
                            raise
                    self._cancel_attempted.add(attempt_id)
                return
            if attempt['phase'] in ('pending', 'cancelling'):
                return
            # Reserve against the background writer and initial private room
            # admission, then do cloud reads outside the selection lock.
            with self.binding.mutation_lock:
                if not self.binding.background_allowed():
                    return
            self.binding.reserve_public()
            try:
                selected = self._own_loadout()
                if selected.revision != attempt['ownLoadoutRevision']:
                    raise PvpCoordinatorError('party_local_selection_changed')
                desired = {'commander_id': selected.commander_id, 'item_ids': list(selected.item_ids)}
                if self.stop.is_set():
                    return
                self.matchmaking.enter_party_attempt(self.profile_source(),
                    mode=attempt['mode'], ruleset=attempt['ruleset'], loadout=desired)
                self._local_generation = self.matchmaking.pvp_queue_generation
                self._local_loadout = desired
                self._local_attempt = (attempt_id, self._local_generation)
                self.notify('waiting')
                self.trace({'event': 'native_party_adopted', 'mode': attempt['mode'],
                            'members': attempt['memberCount']})
            except (PvpCoordinatorError, NativeLobbyError):
                self._ignored.add(attempt_id)
                raise
            finally:
                self.binding.release_public()

    def start(self):
        self.matchmaking.party_cancel_guard = self.cancel_guard
        self.matchmaking.party_cancel_scope = self.cancel_scope
        def run():
            while not self.stop.wait(1.0):
                try:
                    self.step()
                    self._last_error = None
                except Exception as error:
                    code = getattr(error, 'code', type(error).__name__)
                    if code != self._last_error:
                        self.trace({'event': 'native_party_admission_failed', 'reason': code})
                    self._last_error = code
        self._thread = threading.Thread(target=run, name='native-party-admission', daemon=True)
        self._thread.start()

    def close(self):
        if self._thread is not None:
            self._thread.join(timeout=35)
            if self._thread.is_alive():
                raise PvpCoordinatorError('party_admission_stop_unconfirmed')
        if getattr(self.matchmaking, 'party_cancel_guard', None) is self.cancel_guard:
            self.matchmaking.party_cancel_guard = None
        if getattr(self.matchmaking, 'party_cancel_scope', None) is self.cancel_scope:
            self.matchmaking.party_cancel_scope = None
