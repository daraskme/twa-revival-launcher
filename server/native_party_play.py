"""Connect authenticated native party Play/Cancel to existing public admission.

No new transport or thread. The coordinator uses this forwarding API, so an
admitted local queue cannot progress before its native HTTP response is written.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
import threading
import uuid

from native_custom_lobby import NativeLobbyError
from native_party_admission import ACTIVE, TERMINAL
from native_pvp_coordinator import PvpCoordinatorError
from native_social_party import PartyError, validate_snapshot


@dataclass(frozen=True)
class PartyPlayResult:
    snapshot: dict
    token: object


@dataclass(frozen=True)
class _Response:
    action: str
    party_id: str
    generation: object


class NativePartyPlay:
    def __init__(self, admission, *, prepare_own_loadout):
        if not callable(prepare_own_loadout):
            raise TypeError('prepare_own_loadout must be callable')
        self.admission = admission
        self.prepare_own_loadout = prepare_own_loadout
        self._lock = threading.RLock()
        self._context = None
        self._response = None
        self._cancel_context = None

    def __getattr__(self, name):
        return getattr(self.admission, name)

    def _snapshot(self, party_id):
        owner = self.admission
        snapshot = validate_snapshot(owner.social.command('get'), owner.own_id)
        party = snapshot['party']
        if party is None or party['id'] != party_id:
            raise PartyError('party_membership_mismatch', 409)
        return snapshot

    def _stopped(self):
        if self.admission.stop.is_set():
            raise PartyError('party_admission_closed', 503)

    def _current_context(self):
        context = self._context
        if (context is not None and self.admission.matchmaking.pvp_queue_generation
                is context['generation']):
            return context
        return None

    def _hold_response(self):
        context = self._current_context()
        if context is not None and not context['delivered']:
            raise PvpCoordinatorError('party_response_pending', 503)

    def ready(self, party_id):
        try:
            return self._ready(party_id)
        except (PvpCoordinatorError, NativeLobbyError) as error:
            raise PartyError(error.code, error.status or 503) from None

    def _ready(self, party_id):
        owner = self.admission
        with self._lock, owner._lock:
            self._stopped()
            snapshot = self._snapshot(party_id)
            party = snapshot['party']
            requested_mode = (party['mode'], party['ruleset'])
            if party['leader'] != owner.own_id:
                raise PartyError('party_leader_start_required', 409)
            context = self._current_context()
            if context is not None:
                if (context['party_id'], context['mode'], context['ruleset']) != (
                        party_id, party['mode'], party['ruleset']):
                    raise PartyError('party_play_context_changed', 409)
            elif owner.matchmaking.pvp_queue_generation is not None:
                raise PartyError('matchmaking_already_queued', 409)
            # Exact current-party intent only. Never call the join method's
            # solo fallback if another device changed membership after Play.
            with owner._public_reservation():
                view = owner._get()
                attempt = owner._attempt
                if attempt is not None and attempt['phase'] in ACTIVE:
                    if (attempt['partyId'], attempt['mode'], attempt['ruleset']) != (
                            party_id, party['mode'], party['ruleset']):
                        raise PartyError('party_play_context_changed', 409)
                    if attempt['phase'] == 'cancelling':
                        raise PartyError('party_cancel_unconfirmed', 409)
                elif context is not None and owner._request is None:
                    raise PartyError('party_matchmaking_finished', 409)
            if context is None:
                if attempt is None or attempt['phase'] not in ACTIVE:
                    if party['state'] != 'lobby':
                        raise PartyError('party_busy', 409)
                    # Existing sync owns its short selection lock and releases
                    # it before Social publication. Reserve after that sync.
                    self.prepare_own_loadout('/ready_party')
                with owner._public_reservation():
                    snapshot = self._snapshot(party_id)
                    party = snapshot['party']
                    if party['leader'] != owner.own_id:
                        raise PartyError('party_leader_start_required', 409)
                    if (party['mode'], party['ruleset']) != requested_mode:
                        raise PartyError('party_play_context_changed', 409)
                    if (attempt is None or attempt['phase'] not in ACTIVE) and party['state'] != 'lobby':
                        raise PartyError('party_busy', 409)
                    selected = owner._own_loadout()
                    desired = {'commander_id': selected.commander_id,
                               'item_ids': list(selected.item_ids)}
                    if attempt is not None and attempt['phase'] in ACTIVE:
                        owner._verify_selection(attempt, desired)
                    self._stopped()
                    owner.matchmaking.enter_party_attempt(copy.deepcopy(owner.profile_source()),
                        mode=party['mode'], ruleset=party['ruleset'], loadout=desired)
                    generation = owner.matchmaking.pvp_queue_generation
                    if generation is None:
                        raise PartyError('party_local_queue_changed', 409)
                    owner._local_generation, owner._local_loadout = generation, desired
                    context = self._context = {'party_id': party_id, 'mode': party['mode'],
                        'ruleset': party['ruleset'], 'generation': generation, 'delivered': False,
                        'notification_attempted': False}
                    self._cancel_context = None
                    if attempt is None or attempt['phase'] not in ACTIVE:
                        owner._request = {'partyId': party_id, 'partyRevision': party['revision'],
                            'mode': party['mode'], 'ruleset': party['ruleset'],
                            'leaderLoadoutRevision': selected.revision, 'requestId': str(uuid.uuid4())}
            with owner._public_reservation():
                self._stopped()
                if owner._request is not None:
                    if owner._request['partyId'] != party_id:
                        raise PartyError('party_play_context_changed', 409)
                    try:
                        view = owner._resolve_request()
                    except PvpCoordinatorError as error:
                        if error.status in (400, 403, 409):
                            # A rejected pre-admission request can release the
                            # local frozen queue only after a fresh own GET
                            # proves no active remote attempt. A failed proof
                            # retains the exact request for reconciliation.
                            try:
                                owner._get()
                                if owner._attempt is None or owner._attempt['phase'] in TERMINAL:
                                    owner._request = None
                                    owner.matchmaking.abort_pvp('party_start_rejected')
                                    owner.released('party_start_rejected')
                                    self._context = self._response = None
                            except (PvpCoordinatorError, NativeLobbyError):
                                pass
                        raise
                owner._active_view(view, context['mode'], context['ruleset'])
                owner._verify_selection(owner._attempt, owner._local_loadout)
                snapshot = self._snapshot(party_id)
                # A new successful HTTP retry can release the original fenced
                # queue, but neither extends its deadline nor issues new intent.
                token = self._response = _Response('start', party_id, context['generation'])
                return PartyPlayResult(snapshot, token)

    def unready(self, party_id, *, leader_only=False):
        try:
            return self._unready(party_id, leader_only=leader_only)
        except (PvpCoordinatorError, NativeLobbyError) as error:
            raise PartyError(error.code, error.status or 503) from None

    def _unready(self, party_id, *, leader_only=False):
        owner = self.admission
        with self._lock, owner._lock:
            self._stopped()
            snapshot = self._snapshot(party_id)
            if leader_only and snapshot['party']['leader'] != owner.own_id:
                raise PartyError('party_leader_cancel_required', 403)
            with owner._public_reservation():
                owner._get()
                attempt = owner._attempt
                request = owner._request
                if request is not None and request.get('partyId') != party_id:
                    raise PartyError('party_play_context_changed', 409)
                if attempt is not None and attempt['phase'] in ACTIVE and attempt['partyId'] != party_id:
                    raise PartyError('party_play_context_changed', 409)
                generation = owner.matchmaking.pvp_queue_generation
                terminal_owned = (attempt is not None and attempt['partyId'] == party_id
                    and attempt['phase'] == 'cancelled' and generation is not None
                    and generation is owner._local_generation
                    and owner._local_attempt is not None
                    and owner._local_attempt[0] == attempt['attemptId']
                    and owner._local_attempt[1] is generation)
                if request is None and (attempt is None or attempt['phase'] not in ACTIVE) and not terminal_owned:
                    cancelled = self._cancel_context
                    if (cancelled is not None and attempt is not None
                            and attempt['phase'] == 'cancelled'
                            and (cancelled['party_id'], cancelled['attempt_id']) == (
                                party_id, attempt['attemptId'])
                            and generation is None
                            and (cancelled['generation'] is None or
                                 owner.matchmaking._last_cleared_queue is cancelled['generation'])):
                        token = self._response = _Response('cancel', party_id, cancelled['generation'])
                        return PartyPlayResult(self._snapshot(party_id), token)
                    if leader_only:
                        raise PartyError('party_matchmaking_not_active', 409)
                    return None  # Ordinary lobby unready remains a Social op.
                if generation is not None and generation is not owner._local_generation:
                    raise PartyError('party_local_queue_changed', 409)
                # Existing cancellation scope resolves an uncertain start and
                # requires Worker confirmation before its local queue clear.
                owner.matchmaking.cancel(copy.deepcopy(owner.profile_source()))
                self._cancel_context = {'party_id': party_id,
                    'attempt_id': owner._attempt['attemptId'], 'generation': generation,
                    'delivered': False, 'notification_attempted': False}
                snapshot = self._snapshot(party_id)
                token = self._response = _Response('cancel', party_id, generation)
                return PartyPlayResult(snapshot, token)

    def finish_response(self, token, *, delivered):
        owner = self.admission
        with self._lock, owner._lock:
            if token is not self._response:
                return 0
            self._response = None
            if not delivered:
                return 0
            self._stopped()
            if token.action == 'cancel':
                cancelled = self._cancel_context
                if (cancelled is None or cancelled['party_id'] != token.party_id
                        or cancelled['generation'] is not token.generation):
                    raise PartyError('party_response_context_changed', 409)
                if cancelled['delivered']:
                    return 0
                if token.generation is None:
                    cancelled['delivered'] = True
                    return 0
                if cancelled['notification_attempted']:
                    raise PartyError('party_notification_uncertain', 503)
                cancelled['notification_attempted'] = True
                with owner._public_reservation():
                    mm = owner.matchmaking
                    count = mm.notify_cancelled_party_queue(
                        token.generation, owner.notify, stop=owner.stop,
                        retry_if_no_recipient=True)
                    if type(count) is int and count == 0:
                        cancelled['notification_attempted'] = False
                if type(count) is not int or not 1 <= count <= 32:
                    raise PartyError('party_notification_uncertain', 503)
                cancelled['delivered'] = True
                return count
            context = self._current_context()
            if context is None or token.generation is not context['generation']:
                return 0
            # Fence new native queue mutations through the same existing MM
            # lock/reentry guard used by its terminal notification operation.
            with owner._public_reservation(), owner.matchmaking._lock:
                mm = owner.matchmaking
                if (mm.pvp_queue_generation is not token.generation
                        or context['notification_attempted']):
                    return 0
                context['notification_attempted'] = True
                try:
                    mm._mutation()
                    mm._in_callback = True
                    count = owner.notify('waiting')
                    if type(count) is int and count == 0:
                        # Strict hub semantics: zero is definitely no eligible
                        # stream. Only another explicit HTTP retry may retry it.
                        context['notification_attempted'] = False
                    if type(count) is not int or not 1 <= count <= 32:
                        raise PartyError('party_notification_uncertain', 503)
                    context['delivered'] = True
                    return count
                finally:
                    mm._in_callback = False

    def sync_current_queue(self):
        with self._lock:
            self._hold_response()
            return self.admission.sync_current_queue()

    def join(self, ruleset):
        with self._lock:
            self._hold_response()
            return self.admission.join(ruleset)

    def join_coop(self, ruleset):
        with self._lock:
            self._hold_response()
            return self.admission.join_coop(ruleset)

    def status(self):
        with self._lock:
            self._hold_response()
            return self.admission.status()

    def retryable_admission_error(self, error):
        with self._lock:
            if error.code == 'party_response_pending' and error.status == 503:
                context = self._current_context()
                return context is not None and not context['delivered']
            return self.admission.retryable_admission_error(error)

    def released(self, reason, *, generation=None):
        with self._lock:
            if generation is None:
                self.admission.released(reason)
            else:
                self.admission.released(reason, generation=generation)
            if self._current_context() is None:
                self._context = None
                if self._response is not None and self._response.action == 'start':
                    self._response = None
