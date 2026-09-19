"""Bounded projection of authenticated recent encounters to stock UTF-16.

This is the value for exactly ``recent_players_storage``. It neither writes a
preference file nor knows its containing blob. Battle/map metadata must come
from the server's own settlement/battle join. The legacy social response does
not expose that metadata and cannot safely be projected by guessing it.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

STORAGE_KEY = 'recent_players_storage'
MAGIC = 0x8EBEB556
VERSION = 1
MAX_BYTES = 5000
SOCIAL_ID = re.compile(r'[A-Za-z0-9_-]{1,36}\Z')
MAP_KEY = re.compile(r'[A-Za-z0-9_-]{1,128}\Z')


class RecentPlayersError(ValueError):
    pass


@dataclass(frozen=True)
class RecentPlayer:
    account_id: str
    display_name: str


@dataclass(frozen=True)
class RecentBattle:
    timestamp: int
    map_key: str
    players: tuple[RecentPlayer, ...]


@dataclass(frozen=True)
class RecentProjection:
    value: bytes | None
    players: int
    battles: int
    omitted_for_capacity: int = 0
    missing_metadata: int = 0


def _id(value):
    if not isinstance(value, str) or SOCIAL_ID.fullmatch(value) is None:
        raise RecentPlayersError('invalid_recent_identity')
    return value


def _line(value, *, maximum=128):
    if (not isinstance(value, str) or not value or len(value) > maximum
            or any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in value)):
        raise RecentPlayersError('invalid_recent_line')
    return value


def _uint(value):
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise RecentPlayersError('invalid_recent_uint32')
    return value


def encode_recent(battles: tuple[RecentBattle, ...] | list[RecentBattle]) -> bytes:
    # The game's typed card32 formatter prints this magic as 2394862934,
    # despite its generic %d format string. Its parser rejects a minus sign.
    lines = [str(MAGIC), str(VERSION)]
    for battle in battles:
        if not isinstance(battle, RecentBattle) or not 1 <= len(battle.players) <= 19:
            raise RecentPlayersError('invalid_recent_battle')
        if not isinstance(battle.map_key, str) or MAP_KEY.fullmatch(battle.map_key) is None:
            raise RecentPlayersError('invalid_recent_map')
        lines.extend((str(_uint(battle.timestamp)), battle.map_key))
        identities = set()
        for player in battle.players:
            if not isinstance(player, RecentPlayer):
                raise RecentPlayersError('invalid_recent_player')
            user = _id(player.account_id)
            if user in identities:
                raise RecentPlayersError('duplicate_recent_player')
            identities.add(user)
            lines.extend((_line(player.display_name), user))
        lines.append('')
    encoded = ('\n'.join(lines) + '\n\0').encode('utf-16-le')
    if len(encoded) > MAX_BYTES:
        raise RecentPlayersError('recent_value_too_large')
    return encoded


def decode_recent(value: bytes) -> tuple[RecentBattle, ...]:
    """Strict subset accepted by the stock loader; never parse arbitrary blob.

    The native integer routine wraps uint32 on overflow. New values use the
    canonical bounded decimal form instead of accepting aliased headers.
    """
    if (not isinstance(value, bytes) or not 0 < len(value) <= MAX_BYTES
            or len(value) % 2 or not value.endswith(b'\0\0')):
        raise RecentPlayersError('invalid_recent_encoding')
    try:
        text = value.decode('utf-16-le')
    except UnicodeError:
        raise RecentPlayersError('invalid_recent_encoding') from None
    if '\0' in text[:-1] or not text.endswith('\n\0'):
        raise RecentPlayersError('invalid_recent_terminator')
    lines = text[:-1].split('\n')
    if lines[:2] != [str(MAGIC), str(VERSION)]:
        raise RecentPlayersError('unsupported_recent_header')
    result = []
    cursor = 2
    while cursor < len(lines) - 1:
        timestamp_text = lines[cursor]
        if not re.fullmatch(r'0|[1-9][0-9]{0,9}', timestamp_text):
            raise RecentPlayersError('invalid_recent_timestamp')
        if cursor + 1 >= len(lines) - 1:
            raise RecentPlayersError('truncated_recent_battle')
        timestamp, map_key = _uint(int(timestamp_text)), lines[cursor + 1]
        if MAP_KEY.fullmatch(map_key) is None:
            raise RecentPlayersError('invalid_recent_map')
        cursor += 2
        people = []
        while cursor < len(lines) - 1 and lines[cursor] != '':
            if cursor + 1 >= len(lines) - 1:
                raise RecentPlayersError('truncated_recent_player')
            people.append(RecentPlayer(_id(lines[cursor + 1]), _line(lines[cursor])))
            cursor += 2
        if cursor >= len(lines) - 1 or not 1 <= len(people) <= 19:
            raise RecentPlayersError('truncated_recent_battle')
        if len({player.account_id for player in people}) != len(people):
            raise RecentPlayersError('duplicate_recent_player')
        result.append(RecentBattle(timestamp, map_key, tuple(people)))
        cursor += 1
    return tuple(result)


def project_social_recent(snapshot, *, account_id, source_account_id) -> RecentProjection:
    """Project a view fetched using the bound account's authenticated API.

    Additional recent-row fields required: battleId and mapKey, both returned
    by a server-authoritative join. Existing relationship/status metadata is
    irrelevant. Missing metadata leaves the existing storage value untouched.
    The exact Worker ID is stored because stock friend actions use that string
    as the JID username; display names never resolve the target.
    """
    own = _id(account_id)
    if source_account_id != own:
        raise RecentPlayersError('recent_source_account_mismatch')
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get('recent'), list):
        raise RecentPlayersError('invalid_recent_snapshot')
    rows = snapshot['recent']
    if len(rows) > 50:
        raise RecentPlayersError('oversized_recent_snapshot')
    missing = sum(not isinstance(row, dict) or row.get('battleId') is None
                  or row.get('mapKey') is None for row in rows)
    if missing:
        return RecentProjection(None, 0, 0, missing_metadata=missing)
    groups = {}
    encountered = set()
    for row in rows:
        user = _id(row.get('id'))
        if user == own or user in encountered:
            raise RecentPlayersError('invalid_recent_roster')
        encountered.add(user)
        name = _line(row.get('displayName'))
        played_at = row.get('playedAt')
        if type(played_at) is not int or played_at < 0 or played_at % 1000:
            raise RecentPlayersError('invalid_recent_played_at')
        timestamp = _uint(played_at // 1000)
        battle_id, map_key = row['battleId'], row['mapKey']
        if (not isinstance(battle_id, str) or MAP_KEY.fullmatch(battle_id) is None
                or not isinstance(map_key, str) or MAP_KEY.fullmatch(map_key) is None):
            raise RecentPlayersError('invalid_recent_metadata')
        old = groups.setdefault(battle_id, (timestamp, map_key, []))
        if old[:2] != (timestamp, map_key):
            raise RecentPlayersError('conflicting_recent_battle_metadata')
        old[2].append(RecentPlayer(user, name))
        if len(old[2]) > 19:
            raise RecentPlayersError('invalid_recent_roster')
    selected = []
    omitted = 0
    for _, (timestamp, map_key, players) in sorted(groups.items(), key=lambda item: (-item[1][0], item[0])):
        included = []
        for person in sorted(players, key=lambda player: player.account_id):
            proposal = RecentBattle(timestamp, map_key, tuple(included + [person]))
            try:
                encode_recent(selected + [proposal])
            except RecentPlayersError as error:
                if str(error) != 'recent_value_too_large':
                    raise
                omitted += 1
            else:
                included.append(person)
        if included:
            selected.append(RecentBattle(timestamp, map_key, tuple(included)))
    return RecentProjection(encode_recent(selected), sum(len(row.players) for row in selected),
                            len(selected), omitted_for_capacity=omitted)


def project_recent_blob(blob, snapshot, *, account_id, source_account_id,
                        storage_owner_id, authenticated_native_user_id,
                        native_id_for, modified_at_seconds):
    """Pure GET-view projection; no persistence or unrelated preference edit.

    Keep the account/native mapping explicit. Friend targets in the recent
    value stay Worker IDs while the containing storage route uses the bound
    native identity. Missing cloud metadata preserves the original blob.
    """
    if native_id_for(account_id) != storage_owner_id:
        raise RecentPlayersError('recent_storage_identity_mismatch')
    if authenticated_native_user_id != storage_owner_id:
        raise RecentPlayersError('recent_storage_identity_mismatch')
    projection = project_social_recent(snapshot, account_id=account_id,
                                       source_account_id=source_account_id)
    if projection.value is None:
        return blob, projection
    from native_recent_storage import merge_recent_players_storage
    merged = merge_recent_players_storage(blob, projection.value,
        owner_id=storage_owner_id, authenticated_user_id=authenticated_native_user_id,
        modified_at_seconds=modified_at_seconds)
    return merged, projection
