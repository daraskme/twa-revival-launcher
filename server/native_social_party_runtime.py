"""Lifecycle-neutral controller for the verified native lobby party seam.

The owner composes ``publish`` with NativeSocial's friend publisher, wraps
``handle_native`` output in the existing CA envelope, then calls
``flush_notifications`` only after that response was successfully written.
On write failure it calls ``discard_notifications``. A newly bound native
notification resource calls ``resync``. No thread or transport is created here.
"""
from __future__ import annotations

import copy
import threading
import time

from native_social_party import (
    NativeSocialParty, NATIVE_PARTY_CAPACITY, PartyDisplayPolicy, PartyError, create_response, decline_response,
    invite_response, invitation_notification, leader_notification,
    member_added_notification, member_removed_notification,
    member_status_notification, party_id_notification, reconnect_response,
    remaining_invitation_ms, removal_response, validate_request,
    validate_snapshot, presentation_details,
)

POLICY = PartyDisplayPolicy(1, 10, 9, NATIVE_PARTY_CAPACITY)


def notification_delta(before, after, *, account_id, native_id_for, now_ms,
                       details_for=None, suppress_reconnect=False):
    """Return addressed event names and escaped inner XML, with no transport."""
    output = []
    old_party, new_party = before['party'], after['party']
    old_invites = {row['partyId']: row for row in before['invitations']}
    new_invites = {row['partyId']: row for row in after['invitations']}
    for party_id in sorted(old_invites.keys() - new_invites.keys()):
        if new_party is None or party_id != new_party['id']:
            output.append(('party_invite_revoked', party_id_notification('party_invite_revoked', party_id)))
    for party_id, invitation in new_invites.items():
        if invitation != old_invites.get(party_id):
            expiry = remaining_invitation_ms(invitation, now_ms=now_ms)
            if expiry:
                output.append(('party_invite', invitation_notification(invitation, native_id_for, expires_in=expiry)))
    if old_party is not None and (new_party is None or old_party['id'] != new_party['id']):
        output.append(('party_member_removed', member_removed_notification(old_party['id'], account_id, native_id_for)))
    if new_party is None:
        return output
    if old_party is None or old_party['id'] != new_party['id']:
        if not suppress_reconnect:
            output.append(('reconnected_to_party', party_id_notification('reconnected_to_party', new_party['id'])))
        return output
    old_members = {row['id']: row for row in old_party['members']}
    members = {row['id']: row for row in new_party['members']}
    # Change leader while the previous member still exists in the native
    # model; removal comes afterwards. The new leader is a proven member.
    if old_party['leader'] != new_party['leader']:
        output.append(('new_party_leader', leader_notification(
            new_party['id'], old_party['leader'], new_party['leader'], native_id_for)))
    for account in sorted(old_members.keys() - members.keys()):
        output.append(('party_member_removed', member_removed_notification(new_party['id'], account, native_id_for)))
    for account, person in members.items():
        if account not in old_members:
            output.append(('party_member_added', member_added_notification(
                new_party['id'], person, new_party['members'], native_id_for,
                expires_in=0, details_for=details_for)))
    settings_changed = any(old_party[key] != new_party[key] for key in ('mode', 'ruleset', 'state'))
    for account, person in members.items():
        if settings_changed or old_members.get(account) != person:
            output.append(('party_member_status_changed', member_status_notification(
                new_party, person, native_id_for, expires_in=0,
                min_tier=POLICY.min_tier, max_tier=POLICY.max_tier,
                details_for=details_for)))
    return output


class NativePartyController:
    """One bound account; serialized HTTP mutation and deferred notification.

    ``broadcast(event_name, inner_xml)`` returns the number of eligible
    notification resources. A zero result or send failure requires resync.
    ``own_details(account_id)`` may return validated local presentation fields;
    it is never called for another account.
    """
    def __init__(self, adapter: NativeSocialParty, *, broadcast=None, own_details=None,
                 now_ms=None):
        if not isinstance(adapter, NativeSocialParty):
            raise TypeError('adapter must be NativeSocialParty')
        if broadcast is not None and not callable(broadcast):
            raise TypeError('broadcast must be callable')
        if own_details is not None and not callable(own_details):
            raise TypeError('own_details must be callable')
        self.adapter = adapter
        self.broadcast = broadcast
        self.own_details = own_details
        self.now_ms = now_ms or (lambda: time.time_ns() // 1_000_000)
        self._lock = threading.RLock()
        self._current = None
        self._pending = []
        self._awaiting_response = False
        self._suppress_reconnect = False
        self._needs_resync = False
        self._departures = {}
        self._response_token = None

    def _details_for(self, account_id, *, snapshot=None):
        view = self._current if snapshot is None else snapshot
        party = None if view is None else view['party']
        member = next((row for row in party['members'] if row['id'] == account_id), None) if party else None
        if member is not None and 'presentation' in member:
            return presentation_details(member['presentation'])
        # Legacy Workers may omit the new DTO. A peer never falls back to
        # this machine's selection or an arbitrary local profile reader.
        if account_id != self.adapter.account_id or self.own_details is None:
            return None
        return self.own_details(account_id)

    @staticmethod
    def _empty():
        return {'party': None, 'invitations': [], 'friends': []}

    def _delta(self, before, after):
        return notification_delta(before, after, account_id=self.adapter.account_id,
            native_id_for=self.adapter.native_id_for, now_ms=self.now_ms(),
            details_for=lambda account: self._details_for(account, snapshot=after),
            suppress_reconnect=self._suppress_reconnect)

    def _deliver(self, messages):
        sent = 0
        if self.broadcast is None:
            self._needs_resync = True
            return sent
        for event, payload in messages:
            try:
                recipients = self.broadcast(event, payload)
            except Exception:
                # Never turn an already-written HTTP success into a second
                # response, and do not blindly retry uncertain partial sends.
                self._needs_resync = True
                break
            if type(recipients) is not int or recipients <= 0:
                self._needs_resync = True
                break
            sent += 1
            if event == 'party_member_removed':
                for party_id, removal in list(self._departures.items()):
                    if removal == payload:
                        del self._departures[party_id]
        return sent

    def _resync_messages(self):
        # An empty -> current replay cannot clear a stale native party after
        # leave's HTTP write failed. Retain unconfirmed self-removal messages
        # until delivery; their consumer checks the old party ID and self ID.
        return [('party_member_removed', payload) for payload in self._departures.values()] + self._delta(self._empty(), self._current)

    def publish(self, before, after):
        """Compose after the friend publisher; accepts only validated views."""
        after = validate_snapshot(after, self.adapter.account_id)
        with self._lock:
            current = self._current
            if current is not None:
                old_revision, revision = current.get('revision'), after.get('revision')
                if type(old_revision) is int and type(revision) is int and revision < old_revision:
                    return  # Late pre-mutation poll cannot undo party membership.
            if current is None:
                current = self._empty() if not before else validate_snapshot(before, self.adapter.account_id)
            old_party, new_party = current['party'], after['party']
            if old_party is not None and (new_party is None or old_party['id'] != new_party['id']):
                self._departures[old_party['id']] = member_removed_notification(
                    old_party['id'], self.adapter.account_id, self.adapter.native_id_for)
            if new_party is not None:
                self._departures.pop(new_party['id'], None)
            self._current = copy.deepcopy(after)
            if self._needs_resync and not self._awaiting_response:
                self._needs_resync = False
                messages = self._resync_messages()
            else:
                messages = self._delta(current, after)
            if self._awaiting_response:
                self._pending.extend(messages)
                if len(self._pending) > 512:
                    self._pending.clear()
                    self._needs_resync = True
            else:
                self._deliver(messages)

    def handle_native(self, path, request, *, authenticated_native_user_id):
        """Return a raw endpoint body; keep notifications deferred until flush.

        Explicit decline removes the invitation and returns the proven empty
        endpoint body. The stock UI dismisses it without entering accept state.
        """
        request = validate_request(path, request)
        with self._lock:
            if self._awaiting_response:
                raise PartyError('party_response_pending', 409)
            self._awaiting_response = True
            self._suppress_reconnect = path in ('/create_party', '/respond_to_party_invitation', '/reconnect_to_party')
        try:
            operation = self.adapter.handle(path, request,
                authenticated_native_user_id=authenticated_native_user_id)
            with self._lock:
                self._response_token = operation.response_token
                # Also supports an adapter whose owner has not installed the
                # publish callback yet. Real callbacks already advanced state,
                # so this second observation produces no duplicate messages.
                self.publish(operation.before, operation.after)
                current_party = operation.after['party']
                details_for = lambda account: self._details_for(account, snapshot=operation.after)
                if path == '/create_party':
                    result = create_response(current_party, self.adapter.account_id,
                        self.adapter.native_id_for, policy=POLICY, details_for=details_for)
                    if operation.restored_party:
                        # Create's stock parser has only one party_user and
                        # cannot restore peers/leader. After its HTTP response
                        # installs that model, force the complete reconnect.
                        self._pending.append(('reconnected_to_party',
                            party_id_notification('reconnected_to_party', current_party['id'])))
                elif path in ('/ready_party', '/unready_party', '/cancel_party_matchmake',
                              '/change_party_settings'):
                    # Stock ready response vtable 143BF2C uses the empty
                    # endpoint parser AE750. Readiness travels in the member
                    # status notification, deferred until this HTTP is sent.
                    # Settings response vtable 143BD7C also uses AE750;
                    # its shared game_mode travels in the same notification.
                    result = {}
                elif path == '/invite_to_party':
                    result = invite_response(operation.target_account_id, self.adapter.native_id_for,
                        expires_in=operation.invitation_expires_in_ms)
                elif path == '/respond_to_party_invitation' and not request['response']:
                    result = decline_response()
                elif path in ('/respond_to_party_invitation', '/reconnect_to_party'):
                    result = reconnect_response(current_party, self.adapter.native_id_for,
                        policy=POLICY, expires_in_for=lambda _person: 0, details_for=details_for)
                else:
                    result = removal_response()
        except BaseException:
            self.discard_notifications()
            raise
        finally:
            with self._lock:
                self._suppress_reconnect = False
        return result

    def flush_notifications(self):
        """Finish exact HTTP intent before emitting its buffered Social delta."""
        with self._lock:
            token, self._response_token = self._response_token, None
        try:
            # Keep _awaiting_response true while this callback runs, but do
            # not hold controller lock across admission/MM callbacks. Cancel
            # must clear native MM before the ready=false edge reaches 884e.
            if token is not None:
                self.adapter.party_play.finish_response(token, delivered=True)
        except BaseException:
            self.discard_notifications()
            raise
        with self._lock:
            messages, self._pending = self._pending, []
            self._awaiting_response = False
            if self._needs_resync and self._current is not None:
                self._needs_resync = False
                party = self._current['party']
                if token is not None and party is not None and token.party_id == party['id']:
                    # The retried ready/cancel response proves this existing
                    # party. Reconnect is a lobby-only operation and cannot
                    # restore an already admitted queue. Replay the proven
                    # member-status fields after its MM transition instead.
                    messages = [('party_member_removed', payload)
                                for payload in self._departures.values()]
                    messages.extend(('party_member_status_changed', member_status_notification(
                        party, person, self.adapter.native_id_for, expires_in=0,
                        min_tier=POLICY.min_tier, max_tier=POLICY.max_tier,
                        details_for=lambda account: self._details_for(account, snapshot=self._current)))
                        for person in party['members'])
                else:
                    messages = self._resync_messages()
            return self._deliver(messages)

    def discard_notifications(self):
        """A failed response leaves its exact admission fenced for retry/cancel."""
        with self._lock:
            token, self._response_token = self._response_token, None
            self._pending.clear()
            self._awaiting_response = False
            self._suppress_reconnect = False
            self._needs_resync = True
        if token is not None:
            self.adapter.party_play.finish_response(token, delivered=False)

    def resync(self):
        """Rehydrate a newly bound notification resource from cached state."""
        with self._lock:
            if self._current is None:
                self._needs_resync = True
                return 0
            messages = self._resync_messages()
            if self._awaiting_response:
                self._needs_resync = True
                return 0
            self._needs_resync = False
            self._pending.clear()
            return self._deliver(messages)

    def set_broadcast(self, callback):
        if not callable(callback):
            raise TypeError('broadcast must be callable')
        with self._lock:
            self.broadcast = callback
            return self.resync()
