"""Stock lobby-party contracts over an authenticated Social Worker adapter.

This module opens no sockets and does not publish by itself. An optional
party_play owner delegates authenticated leader Play and group cancellation
to the existing public matchmaking services.
The HTTP seam must verify the native session before calling ``handle``; the
Worker continues to authorize the bound account, never an actor from JSON.
See analysis/PARTY_NOTIFICATION_CONTRACT.md for addressed static evidence.
The outer XMPP sender must be exactly camm.xmpp.twa, as verified in the stock
dispatch. Native expires_in values are remaining milliseconds.
"""
from __future__ import annotations

from dataclasses import dataclass
import copy
import json
import re
import time
from typing import Callable
from xml.sax.saxutils import escape

NAMESPACE = 'http://arenatw.co.uk/xmpp'
NATIVE_ID = re.compile(r'[A-Za-z0-9_-]{1,36}\Z')
PARTY_ID = re.compile(r'[A-Za-z0-9_-]{1,128}\Z')
PATHS = frozenset(('/create_party', '/invite_to_party',
                   '/respond_to_party_invitation', '/reconnect_to_party',
                   '/remove_player_from_party', '/ready_party', '/unready_party',
                   '/cancel_party_matchmake', '/change_party_settings'))
MODES = {'territory_pve': ('pve', 'territory'),
         'annihilation_pve': ('pve', 'annihilation'),
         'territory_pvp': ('pvp', 'territory'),
         'annihilation_pvp': ('pvp', 'annihilation'),
         'pve': ('pve', 'territory'), 'pvp': ('pvp', 'territory')}
PRESENCE = frozenset(('offline', 'online', 'in_party', 'matchmaking', 'in_battle'))
INVITE_LIFETIME_MS = 300_000  # Existing Worker social-state.ts policy.
# The stock lobby creates four portrait slots. Match capacity is independent.
NATIVE_PARTY_CAPACITY = 4
MEMBER_FIELDS = frozenset(('nickname', 'commander_key', 'commander_skin_key', 'units'))
CREATE_FIELDS = MEMBER_FIELDS | frozenset((
    'version', 'country_code', 'player_regions', 'autotest', 'sessionguid',
    'build_id', 'player_region', 'game_mode'))
# Stock ready serializer BCEB10..BCEF98; common presentation BDE8A0.
READY_FIELDS = MEMBER_FIELDS | frozenset((
    'party_id', 'profile_timestamp', 'appid', 'version', 'commander_id',
    'display_name', 'game_data_version', 'player_regions', 'autotest',
    'sessionguid', 'build_id'))
REQUEST_FIELDS = {
    '/create_party': (CREATE_FIELDS, CREATE_FIELDS | {'mm_teamsize', 'mm_map'}),
    '/invite_to_party': ({'party_id', 'user_id', 'nickname'}, {'party_id', 'user_id', 'nickname'}),
    '/respond_to_party_invitation': (MEMBER_FIELDS | {'party_id', 'response'}, MEMBER_FIELDS | {'party_id', 'response'}),
    '/reconnect_to_party': ({'party_id'}, {'party_id'}),
    '/ready_party': (READY_FIELDS, READY_FIELDS),
    '/unready_party': ({'party_id'}, {'party_id'}),
    '/cancel_party_matchmake': ({'party_id'}, {'party_id'}),
    # Stock BCD850: party ID, common presentation BDE8A0, game mode.
    '/change_party_settings': (MEMBER_FIELDS | {'party_id', 'game_mode'},
                               MEMBER_FIELDS | {'party_id', 'game_mode'}),
    '/remove_player_from_party': ({'party_id', 'user_id'}, {'party_id', 'user_id'}),
}


class PartyError(ValueError):
    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code, self.status = code, status


def _text(value, *, maximum=128, empty=False):
    if (not isinstance(value, str) or len(value) > maximum
            or (not empty and not value)
            or any(not (char in '\t\n\r' or 0x20 <= ord(char) <= 0xd7ff
                        or 0xe000 <= ord(char) <= 0xfffd
                        or 0x10000 <= ord(char) <= 0x10ffff) for char in value)):
        raise PartyError('invalid_party_text')
    return value


def _identifier(value, pattern=PARTY_ID):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise PartyError('invalid_party_identifier')
    return value


def _uint(value, bits=32):
    if type(value) is not int or not 0 <= value < 2 ** bits:
        raise PartyError('invalid_party_integer')
    return value


def validate_request(path: str, request: object) -> dict:
    if path not in PATHS:
        raise PartyError('unsupported_party_operation', 404)
    required, allowed = REQUEST_FIELDS[path]
    if (not isinstance(request, dict) or not required <= request.keys()
            or request.keys() - allowed):
        raise PartyError('invalid_party_request_fields')
    try:
        size = len(json.dumps(request, ensure_ascii=False, allow_nan=False).encode('utf-8'))
    except (TypeError, ValueError, UnicodeError):
        raise PartyError('invalid_party_request') from None
    if size > 32 * 1024:
        raise PartyError('party_request_too_large', 413)
    for key in ('party_id', 'user_id'):
        if key in request:
            _identifier(request[key])
    for key in ('nickname', 'commander_key', 'commander_skin_key',
                'country_code', 'sessionguid', 'player_region', 'mm_map',
                'display_name', 'game_data_version'):
        if key in request:
            _text(request[key], maximum=256, empty=True)
    if 'units' in request:
        units = request['units']
        if not isinstance(units, list) or len(units) > 3:
            raise PartyError('invalid_party_units')
        for unit in units:
            _text(unit, maximum=128)
    for key in ('version', 'build_id', 'mm_teamsize', 'appid'):
        if key in request:
            _uint(request[key])
    for key in ('profile_timestamp', 'commander_id'):
        if key in request:
            _uint(request[key], 64)
    for key in ('response', 'autotest'):
        if key in request and type(request[key]) is not bool:
            raise PartyError('invalid_party_boolean')
    if 'player_regions' in request and not isinstance(request['player_regions'], dict):
        raise PartyError('invalid_party_regions')
    if 'game_mode' in request and (not isinstance(request['game_mode'], str)
                                   or request['game_mode'] not in MODES):
        raise PartyError('unsupported_party_game_mode')
    # Nickname/loadout/region fields prove only the stock wire shape. They are
    # never persisted as another person's identity or authoritative loadout.
    return copy.deepcopy(request)


def _person(value, *, member=False):
    if not isinstance(value, dict):
        raise PartyError('invalid_party_snapshot', 502)
    _text(value.get('id'))
    _text(value.get('displayName'))
    if member and (value.get('status') not in PRESENCE or type(value.get('ready')) is not bool):
        raise PartyError('invalid_party_member', 502)
    if member and 'presentation' in value:
        presentation_details(value['presentation'])
    return value


def presentation_details(value):
    """Validate the authenticated Worker's selected, ordered catalog keys.

    The Worker resolves ownership/faction and strips unit-instance IDs. This
    boundary accepts its versioned display DTO, never a native request body.
    Missing selection stays missing instead of inventing another loadout.
    """
    if value is None:
        return None
    if (not isinstance(value, dict) or set(value) != {
            'commanderId', 'loadoutRevision', 'commander_key', 'commander_skin_key', 'units'}):
        raise PartyError('invalid_party_presentation', 502)
    commander_id = value['commanderId']
    if (not isinstance(commander_id, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', commander_id)
            or int(commander_id) >= 2 ** 64):
        raise PartyError('invalid_party_presentation', 502)
    _uint(value['loadoutRevision'], 53)
    for field in ('commander_key', 'commander_skin_key'):
        key = value[field]
        if field == 'commander_skin_key' and key == '':
            continue
        if not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9_]{1,128}', key):
            raise PartyError('invalid_party_presentation', 502)
    units = value['units']
    if (not isinstance(units, list) or len(units) != 3 or
            any(not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9_]{1,128}', key) for key in units)):
        raise PartyError('invalid_party_presentation', 502)
    return {key: copy.deepcopy(value[key]) for key in ('commander_key', 'commander_skin_key', 'units')}


def validate_snapshot(value: object, actor_account_id: str) -> dict:
    if (not isinstance(value, dict) or not {'party', 'invitations', 'friends'} <= value.keys()
            or not isinstance(value['invitations'], list)
            or not isinstance(value['friends'], list)):
        raise PartyError('invalid_party_snapshot', 502)
    if len(value['invitations']) > 200 or len(value['friends']) > 200:
        raise PartyError('oversized_party_snapshot', 502)
    for row in value['friends']:
        _person(row)
    party = value['party']
    if party is not None:
        if not isinstance(party, dict):
            raise PartyError('invalid_party_snapshot', 502)
        _identifier(party.get('id'))
        members = party.get('members')
        if not isinstance(members, list) or not 1 <= len(members) <= NATIVE_PARTY_CAPACITY:
            raise PartyError('invalid_party_members', 502)
        ids = [_person(row, member=True)['id'] for row in members]
        if len(set(ids)) != len(ids) or actor_account_id not in ids or party.get('leader') not in ids:
            raise PartyError('invalid_party_membership', 502)
        if ((party.get('mode'), party.get('ruleset')) not in MODES.values()
                or party.get('state') not in ('lobby', 'matchmaking', 'battle')):
            raise PartyError('invalid_party_state', 502)
        _uint(party.get('revision'), 53)
    invitation_ids = set()
    for invitation in value['invitations']:
        if not isinstance(invitation, dict):
            raise PartyError('invalid_party_invitation', 502)
        party_id = _identifier(invitation.get('partyId'))
        _person(invitation.get('leader'))
        _uint(invitation.get('expiresAt'), 53)
        if party_id in invitation_ids:
            raise PartyError('duplicate_party_invitation', 502)
        invitation_ids.add(party_id)
    return copy.deepcopy(value)


def user_record(person: dict, native_id_for: Callable[[str], str], details: dict | None = None) -> dict:
    """Use account-storage names and explicitly supplied presentation details.

    Empty loadout fields preserve missing information. They are parser-valid;
    the stock UI's treatment of missing portraits still needs a live check.
    """
    _person(person)
    user = _identifier(native_id_for(person['id']), NATIVE_ID)
    details = {} if details is None else details
    if not isinstance(details, dict) or details.keys() - {'commander_key', 'commander_skin_key', 'units'}:
        raise PartyError('invalid_party_presentation')
    commander = _text(details.get('commander_key', ''), empty=True)
    skin = _text(details.get('commander_skin_key', ''), empty=True)
    units = details.get('units', [])
    if not isinstance(units, list) or len(units) > 3:
        raise PartyError('invalid_party_units')
    # Stored/cloud/battle slots are 0/1/2, but the native owner's lower
    # cards are left/middle/right = 2/1/0 (unit_drag_bridge._target_slot).
    # Convert only this compact party display record to the same visual order.
    return {'user_id': user, 'display_name': person['displayName'],
            'commander_key': commander, 'commander_skin_key': skin,
            'units': [_text(unit) for unit in reversed(units)]}


def users_json(people: list[dict], native_id_for: Callable[[str], str], details_for=None) -> str:
    if len(people) > NATIVE_PARTY_CAPACITY:
        raise PartyError('invalid_party_members')
    rows = [user_record(person, native_id_for,
                        None if details_for is None else details_for(person['id'])) for person in people]
    result = {row['user_id']: row for row in rows}
    if len(result) != len(rows):
        raise PartyError('party_identity_collision')
    return json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def _notification(event: str, fields: dict) -> str:
    inner = ''.join('<' + name + '>' + escape(str(value)) + '</' + name + '>'
                    for name, value in fields.items())
    return '<' + event + " xmlns='" + NAMESPACE + "'>" + inner + '</' + event + '>'


def remaining_invitation_ms(invitation: dict, *, now_ms: int) -> int:
    """Convert the Worker's epoch-ms deadline to bounded remaining native ms.

    Client clock skew can affect display timing; Worker join authorization
    remains authoritative and enforces the actual invitation deadline.
    """
    expires = _uint(invitation.get('expiresAt'), 53)
    now = _uint(now_ms, 53)
    return min(INVITE_LIFETIME_MS, max(0, expires - now))


def invitation_notification(invitation: dict, native_id_for, *, expires_in: int) -> str:
    """Expiry is remaining milliseconds (GetTickCount consumer verified)."""
    leader = _person(invitation.get('leader'))
    return _notification('party_invite', {
        'party_id': _identifier(invitation.get('partyId')),
        'party_leader_user_id': _identifier(native_id_for(leader['id']), NATIVE_ID),
        'party_leader_nickname': leader['displayName'], 'expires_in': _uint(expires_in)})


def party_id_notification(event: str, party_id: str) -> str:
    if event not in ('reconnected_to_party', 'party_invite_revoked'):
        raise PartyError('unsupported_party_notification')
    return _notification(event, {'party_id': _identifier(party_id)})


def member_added_notification(party_id, person, people, native_id_for, *, expires_in, details_for=None):
    _person(person)
    return _notification('party_member_added', {
        'party_id': _identifier(party_id),
        'new_player': _identifier(native_id_for(person['id']), NATIVE_ID),
        'nickname': person['displayName'], 'expires_in': _uint(expires_in, 64),
        'users': users_json(people, native_id_for, details_for)})


def member_removed_notification(party_id, account_id, native_id_for):
    return _notification('party_member_removed', {'party_id': _identifier(party_id),
        'removed_player': _identifier(native_id_for(account_id), NATIVE_ID)})


def leader_notification(party_id, previous, current, native_id_for):
    return _notification('new_party_leader', {
        'previous_leader': _identifier(native_id_for(previous), NATIVE_ID),
        'new_leader': _identifier(native_id_for(current), NATIVE_ID),
        'party_id': _identifier(party_id)})


def member_status_notification(party, person, native_id_for, *, expires_in,
                               min_tier: int, max_tier: int, details_for=None):
    _person(person, member=True)
    if type(min_tier) is not int or type(max_tier) is not int or not 1 <= min_tier <= max_tier <= 10:
        raise PartyError('invalid_party_tier_policy')
    if person['id'] not in {row['id'] for row in party['members']}:
        raise PartyError('party_member_not_found')
    return _notification('party_member_status_changed', {
        'party_id': _identifier(party['id']),
        'player': _identifier(native_id_for(person['id']), NATIVE_ID),
        # Only these positive tokens are proven by native equality checks.
        # Empty text deliberately represents false, not an invented enum.
        'matchmaking_status': 'ready' if person['ready'] else '',
        'online_status': '' if person['status'] == 'offline' else 'connected',
        'invite_status': 'accepted', 'expires_in': _uint(expires_in, 64),
        'min_tier': min_tier, 'max_tier': max_tier, 'max_party_size': NATIVE_PARTY_CAPACITY,
        'game_mode': party['ruleset'] + '_' + party['mode'],
        'users': users_json(party['members'], native_id_for, details_for)})


@dataclass(frozen=True)
class PartyDisplayPolicy:
    """Explicit local limits, not recovered original service defaults."""
    min_tier: int
    max_tier: int
    max_party_range: int
    max_party_size: int

    def __post_init__(self):
        if (any(type(value) is not int for value in (
                self.min_tier, self.max_tier, self.max_party_range, self.max_party_size))
                or not 1 <= self.min_tier <= self.max_tier <= 10
                or not 0 <= self.max_party_range <= 9
                or not 1 <= self.max_party_size <= NATIVE_PARTY_CAPACITY):
            raise PartyError('invalid_party_display_policy')


def create_response(party, account_id, native_id_for, *, policy: PartyDisplayPolicy,
                    details_for=None):
    """Raw /create_party payload: linked parser RVA 0xBF6500.

    The existing HTTP seam supplies its CA response envelope. A chat room JID
    is omitted because this module does not implement a party chat service.
    """
    own = next((row for row in party['members'] if row['id'] == account_id), None)
    if own is None:
        raise PartyError('party_membership_mismatch', 403)
    return {'party_id': _identifier(party['id']), 'min_tier': policy.min_tier,
            'max_tier': policy.max_tier, 'max_party_range': policy.max_party_range,
            'max_party_size': policy.max_party_size,
            'party_user': user_record(own, native_id_for,
                None if details_for is None else details_for(account_id))}


def reconnect_response(party, native_id_for, *, policy: PartyDisplayPolicy,
                       expires_in_for: Callable[[dict], int], details_for=None):
    """Raw /reconnect_to_party payload: linked parser RVA 0xBF9B30.

    HTTP uses a boolean matchmaking_status, whereas XMPP compares the string
    'ready'. Each member's presentation belongs in game_specific_party_user.
    Expiry is remaining milliseconds. Accepted Worker members may use zero:
    the stock tick clamps this field to zero without removing those members.
    """
    records = []
    identities = set()
    for person in party['members']:
        _person(person, member=True)
        user = user_record(person, native_id_for,
            None if details_for is None else details_for(person['id']))
        if user['user_id'] in identities:
            raise PartyError('party_identity_collision')
        identities.add(user['user_id'])
        records.append({'user_id': user['user_id'], 'matchmaking_status': person['ready'],
                        'online_status': '' if person['status'] == 'offline' else 'connected',
                        'invite_status': 'accepted', 'expires_in': _uint(expires_in_for(person), 64),
                        'game_specific_party_user': user})
    if not 1 <= len(records) <= policy.max_party_size:
        raise PartyError('invalid_party_members')
    leader = _identifier(native_id_for(party['leader']), NATIVE_ID)
    if leader not in identities:
        raise PartyError('invalid_party_leader')
    return {'party_id': _identifier(party['id']), 'leader_id': leader,
            'game_mode': party['ruleset'] + '_' + party['mode'],
            'party_members': records, 'max_party_size': policy.max_party_size,
            'min_tier': policy.min_tier, 'max_tier': policy.max_tier,
            # The create parser uses max_party_range; reconnect uses this
            # different spelling. They are not interchangeable wire fields.
            'max_tier_range': policy.max_party_range}


def invite_response(target_account_id: str, native_id_for, *, expires_in: int) -> dict:
    """/invite_to_party parser RVA 0xBF98D0: target string and uint32."""
    return {'user_id': _identifier(native_id_for(target_account_id), NATIVE_ID),
            'expires_in': _uint(expires_in)}


def removal_response() -> dict:
    """/remove_player_from_party endpoint parser RVA 0xAE750 reads no fields."""
    return {}


def decline_response() -> dict:
    """Explicit decline uses an empty successful endpoint body.

    UI CEF610 calls B50F60, which queues response=false and dismisses the
    invitation without entering accept state 2. Callback B6E5D0 therefore
    returns before reading response fields; BF9B30 also accepts a root object
    with no fields. This does not invent an empty party membership response.
    """
    return {}


@dataclass(frozen=True)
class PartyOperation:
    path: str
    before: dict
    after: dict
    target_account_id: str | None = None
    invitation_expires_in_ms: int | None = None
    restored_party: bool = False
    response_token: object | None = None


class NativeSocialParty:
    """Translate verified decoded HTTP bodies to existing Social operations.

    ``social.command`` uses the already authenticated Worker session. Supply
    the native resolver's account and native identifiers separately. Targets
    are resolved only among known friends or current party members; raw actor
    IDs and caller-supplied names never become Worker authority.
    """
    def __init__(self, social, *, account_id: str, native_user_id: str, native_id_for,
                 monotonic_ms: Callable[[], int] | None = None,
                 prepare_own_loadout: Callable[[str], None] | None = None,
                 party_play=None):
        _text(account_id)
        _identifier(native_user_id, NATIVE_ID)
        if native_id_for(account_id) != native_user_id:
            raise PartyError('party_bound_identity_mismatch', 403)
        self.social, self.account_id, self.native_user_id = social, account_id, native_user_id
        self.native_id_for = native_id_for
        if prepare_own_loadout is not None and not callable(prepare_own_loadout):
            raise TypeError('prepare_own_loadout must be callable')
        self.prepare_own_loadout = prepare_own_loadout
        if party_play is not None and any(not callable(getattr(party_play, name, None))
                                         for name in ('ready', 'unready', 'finish_response')):
            raise TypeError('party_play must implement ready, unready and finish_response')
        self.party_play = party_play
        self.monotonic_ms = monotonic_ms or (lambda: time.monotonic_ns() // 1_000_000)

    def _get(self):
        return validate_snapshot(self.social.command('get'), self.account_id)

    def _command(self, action, body=None):
        return validate_snapshot(self.social.command(action, body or {}), self.account_id)

    def _own_party(self, snapshot, party_id):
        party = snapshot['party']
        if party is None or party['id'] != party_id:
            raise PartyError('party_membership_mismatch', 403)
        if party['state'] != 'lobby':
            raise PartyError('party_busy', 409)
        return party

    def _target(self, supplied, people):
        # Existing friend JIDs use Worker IDs; native member records can use a
        # derived wire ID. Accept either only through this known-person map.
        candidates = {person['id'] for person in people
                      if supplied in (person['id'], self.native_id_for(person['id']))}
        if len(candidates) != 1:
            raise PartyError('unknown_or_ambiguous_party_target', 403)
        return candidates.pop()

    def handle(self, path: str, request: object, *, authenticated_native_user_id: str) -> PartyOperation:
        if authenticated_native_user_id != self.native_user_id:
            raise PartyError('party_request_identity_mismatch', 403)
        request = validate_request(path, request)
        before = self._get()
        target = None
        invitation_expires_in_ms = None
        restored_party = False
        response_token = None
        if path == '/create_party':
            # A restarted client can send create before its restoration
            # notification arrives. Existing membership is authoritative;
            # this is not an implicit leader-only settings operation.
            if before['party'] is not None:
                self._own_party(before, before['party']['id'])
            if self.prepare_own_loadout is not None:
                self.prepare_own_loadout(path)
            if before['party'] is not None:
                after = self._get() if self.prepare_own_loadout is not None else before
                restored_party = True
            else:
                after = self._command('create')
            mode, ruleset = MODES[request['game_mode']]
            if after['party'] is None:
                raise PartyError('missing_created_party', 502)
            party = self._own_party(after, after['party']['id'])
            # A second device may have joined between get and create.
            if party['leader'] != self.account_id or len(party['members']) != 1:
                restored_party = True
            if not restored_party and (party['mode'], party['ruleset']) != (mode, ruleset):
                # Existing API has separate idempotent create/settings calls.
                # If settings fails, return the failure; never claim rollback
                # or success. A retry reuses the durable party.
                after = self._command('settings', {'mode': mode, 'ruleset': ruleset})
                if (after['party'] is None
                        or (after['party']['mode'], after['party']['ruleset']) != (mode, ruleset)):
                    raise PartyError('unconfirmed_party_settings', 502)
        elif path == '/respond_to_party_invitation':
            party_id = request['party_id']
            already_member = before['party'] is not None and before['party']['id'] == party_id
            if not already_member and party_id not in {row['partyId'] for row in before['invitations']}:
                raise PartyError('unknown_party_invitation', 403)
            if request['response'] and self.prepare_own_loadout is not None:
                if already_member:
                    self._own_party(before, party_id)
                self.prepare_own_loadout(path)
            after = self._command('join', {'partyId': party_id, 'accept': request['response']})
            if request['response'] and (after['party'] is None or after['party']['id'] != party_id):
                raise PartyError('unconfirmed_party_join', 502)
            if not request['response'] and party_id in {row['partyId'] for row in after['invitations']}:
                raise PartyError('unconfirmed_party_decline', 502)
        elif path == '/reconnect_to_party':
            self._own_party(before, request['party_id'])
            if self.prepare_own_loadout is not None:
                self.prepare_own_loadout(path)
                after = self._get()
                self._own_party(after, request['party_id'])
            else:
                after = before
        elif path in ('/ready_party', '/unready_party', '/cancel_party_matchmake'):
            wanted = path == '/ready_party'
            party = before['party']
            if party is None or party['id'] != request['party_id']:
                raise PartyError('party_membership_mismatch', 403)
            if path == '/cancel_party_matchmake' and party['leader'] != self.account_id:
                raise PartyError('party_leader_cancel_required', 403)
            if path == '/cancel_party_matchmake' and self.party_play is None:
                raise PartyError('party_matchmaking_unavailable', 503)
            result = None
            if self.party_play is not None:
                if wanted and party['leader'] == self.account_id:
                    result = self.party_play.ready(party['id'])
                elif not wanted:
                    result = (self.party_play.unready(party['id'], leader_only=True)
                              if path == '/cancel_party_matchmake'
                              else self.party_play.unready(party['id']))
            if result is not None:
                after = validate_snapshot(result.snapshot, self.account_id)
                if after['party'] is None or after['party']['id'] != request['party_id']:
                    raise PartyError('party_membership_mismatch', 409)
                response_token = result.token
            else:
                expected_party = self._own_party(before, request['party_id'])
                if wanted and self.prepare_own_loadout is not None:
                    self.prepare_own_loadout(path)
                # Ordinary follower Ready/lobby Cancel stays authenticated
                # Social state. A native body never supplies Worker authority.
                after = self._command('ready', {'ready': wanted, 'partyId': expected_party['id']})
                party = self._own_party(after, request['party_id'])
                own = next(row for row in party['members'] if row['id'] == self.account_id)
                if own['ready'] is not wanted:
                    raise PartyError('unconfirmed_party_readiness', 502)
        elif path == '/change_party_settings':
            party = self._own_party(before, request['party_id'])
            if party['leader'] != self.account_id:
                raise PartyError('party_leader_required', 403)
            mode, ruleset = MODES[request['game_mode']]
            # The Worker checks this party ID in the same serialized operation
            # as the update. A delayed request cannot edit a replacement party.
            after = self._command('settings', {'mode': mode, 'ruleset': ruleset,
                                                'partyId': party['id']})
            current = self._own_party(after, party['id'])
            if (current['mode'], current['ruleset']) != (mode, ruleset):
                raise PartyError('unconfirmed_party_settings', 502)
        elif path == '/invite_to_party':
            party = self._own_party(before, request['party_id'])
            if len(party['members']) >= NATIVE_PARTY_CAPACITY:
                raise PartyError('party_full', 409)
            target = self._target(request['user_id'], before['friends'])
            started_ms = _uint(self.monotonic_ms(), 64)
            after = self._command('invite', {'target': target})
            self._own_party(after, request['party_id'])
            elapsed_ms = _uint(self.monotonic_ms(), 64) - started_ms
            if elapsed_ms < 0:
                raise PartyError('invalid_party_monotonic_clock', 502)
            # Leader snapshots do not expose invitation deadlines. The
            # Worker's creation instant lies inside this request interval;
            # subtracting the whole interval is conservative, never extends
            # the Worker's fixed five-minute lifetime, and needs no wall clock.
            invitation_expires_in_ms = max(0, INVITE_LIFETIME_MS - elapsed_ms)
        else:
            party = self._own_party(before, request['party_id'])
            target = self._target(request['user_id'], party['members'])
            after = self._command('leave', {'target': target})
            if target == self.account_id:
                if after['party'] is not None:
                    raise PartyError('unconfirmed_party_leave', 502)
            elif (after['party'] is None or after['party']['id'] != party['id']
                  or target in {row['id'] for row in after['party']['members']}):
                raise PartyError('unconfirmed_party_removal', 502)
        return PartyOperation(path, copy.deepcopy(before), copy.deepcopy(after),
                              target, invitation_expires_in_ms, restored_party, response_token)
