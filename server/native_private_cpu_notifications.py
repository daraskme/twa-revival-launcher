"""Inert XML builders for statically identified custom-game CPU events.

The pristine native ``game.dll`` contains parsers for these payloads:

* ``cg_member_removed``: ``cg_id``, ``removed_player``
* ``player_joined_cg``: ``cg_id``, ``new_player``, ``nickname``, ``loadout``,
  ``teamid``
* the loadout branch of ``player_state_changed``: ``cg_id``, ``player_id``,
  ``loadout``

These helpers only build the inner element.  They do not select a recipient,
open a socket, register an HTTP route, or claim live interoperability.  A live
adapter still needs an atomic room mutation and an idempotent notification
outbox before it may call the XMPP probe's broadcast boundary.
"""
from __future__ import annotations

import re
import json
import uuid
from xml.sax.saxutils import escape

from native_battle_maps import is_native_battle_map


NATIVE_CPU_ROSTER_XMPP_SCHEMA_STATICALLY_IDENTIFIED = True
_NATIVE_XMLNS = "http://arenatw.co.uk/xmpp"
_PLAYER_ID = re.compile(r"[\x21-\x7e]{1,128}\Z")
_UUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)
_MAX_LOADOUT_ROWS = 512
_MAX_LOADOUT_BYTES = 32768
_UINT64_MAX = (1 << 64) - 1


class CpuNotificationDeliveryUncertain(OSError):
    """A CPU stanza may already have reached the native client."""

    def __init__(self):
        super().__init__("native_cpu_notification_delivery_uncertain")


def _game_id(value: object) -> str:
    if type(value) is not str or _UUID.fullmatch(value) is None:
        raise ValueError("game_id must be a canonical UUID string")
    return str(uuid.UUID(value))


def _loadout_json(details: object) -> str:
    """Validate the same bounded loadout branch as ``NativeXmppProbe``.

    This module intentionally owns the small wire validator.  Importing the
    probe's private helpers would create a cycle once the probe calls these
    builders at its broadcast boundary.
    """
    required = {"commander_tier", "full_squad_setup"}
    if (type(details) is not dict or not required <= details.keys()
            or details.keys() - required - {"new_player", "premium"}):
        raise ValueError("invalid_loadout_fields")
    tier, rows = details["commander_tier"], details["full_squad_setup"]
    if type(tier) is not int or not 1 <= tier <= 10:
        raise ValueError("invalid_loadout_commander_tier")
    if type(rows) is not list or not 1 <= len(rows) <= _MAX_LOADOUT_ROWS:
        raise ValueError("invalid_loadout_rows")
    validated = []
    for row in rows:
        if type(row) is not list or len(row) != 4:
            raise ValueError("invalid_loadout_row")
        values = row.copy()
        if (any(type(value) is not int or not 0 <= value <= _UINT64_MAX
                for value in values) or values[1] == 0 or values[2] == 0):
            raise ValueError("invalid_loadout_uint64")
        validated.append(values)
    payload = {"commander_tier": tier, "full_squad_setup": validated}
    for key in ("new_player", "premium"):
        if key in details:
            if type(details[key]) is not bool:
                raise ValueError("invalid_loadout_boolean")
            payload[key] = details[key]
    text = json.dumps(payload, separators=(",", ":"), allow_nan=False)
    if len(text.encode("utf-8")) > _MAX_LOADOUT_BYTES:
        raise ValueError("loadout_body_limit")
    return text


def _text(value: object, name: str, maximum: int = 128) -> str:
    if (type(value) is not str or not value
            or len(value.encode("utf-8")) > maximum
            or any(ord(char) < 0x20 or ord(char) == 0x7f for char in value)):
        raise ValueError("invalid_" + name)
    return value


def _player_id(value: object, name: str) -> str:
    if type(value) is not str or _PLAYER_ID.fullmatch(value) is None:
        raise ValueError("invalid_" + name)
    return value


def build_cpu_member_removed(game_id: str, removed_player: str) -> str:
    """Build the native owner-visible roster removal element."""
    game_id = _game_id(game_id)
    removed_player = _player_id(removed_player, "removed_player")
    return ("<cg_member_removed xmlns='" + _NATIVE_XMLNS + "'><cg_id>"
            + escape(game_id) + "</cg_id><removed_player>"
            + escape(removed_player) + "</removed_player></cg_member_removed>")


def build_cpu_member_joined(game_id: str, player: object) -> str:
    """Build a native CPU roster-add element from one server-owned player row."""
    game_id = _game_id(game_id)
    if type(player) is not dict or player.get("is_ai") is not True:
        raise ValueError("invalid_cpu_player")
    user_id = _player_id(player.get("user_id"), "cpu_user_id")
    nickname = _text(player.get("display_name"), "cpu_nickname", 256)
    team_id = player.get("team_id")
    if type(team_id) is not int or not 1 <= team_id <= 20:
        raise ValueError("invalid_cpu_team_id")
    loadout = _loadout_json(player.get("profile_matchmaking_details"))
    return ("<player_joined_cg xmlns='" + _NATIVE_XMLNS + "'><cg_id>"
            + escape(game_id) + "</cg_id><new_player>" + escape(user_id)
            + "</new_player><nickname>" + escape(nickname)
            + "</nickname><loadout>" + escape(loadout)
            + "</loadout><teamid>" + str(team_id)
            + "</teamid></player_joined_cg>")


def build_cpu_loadout_changed(game_id: str, player_id: str, details: object) -> str:
    """Build the existing native loadout branch for a server-owned CPU row."""
    game_id = _game_id(game_id)
    player_id = _player_id(player_id, "cpu_user_id")
    loadout = _loadout_json(details)
    return ("<player_state_changed xmlns='" + _NATIVE_XMLNS + "'><cg_id>"
            + escape(game_id) + "</cg_id><player_id>" + escape(player_id)
            + "</player_id><loadout>" + escape(loadout)
            + "</loadout></player_state_changed>")


def build_cpu_ready_changed(game_id: str, player_id: str) -> str:
    """Build the fixed ready branch required after a late CPU joins."""
    game_id = _game_id(game_id)
    player_id = _player_id(player_id, "cpu_user_id")
    return ("<player_state_changed xmlns='" + _NATIVE_XMLNS + "'><cg_id>"
            + escape(game_id) + "</cg_id><player_id>" + escape(player_id)
            + "</player_id><new_state>ready</new_state>"
            "</player_state_changed>")


def build_human_member_joined(game_id: str, player: object) -> str:
    """Build the same parser-backed join element for a validated human row."""
    game_id = _game_id(game_id)
    if type(player) is not dict or player.get("is_ai") is not False:
        raise ValueError("invalid_human_player")
    user_id = _player_id(player.get("user_id"), "human_user_id")
    nickname = _text(player.get("display_name"), "human_nickname", 256)
    team_id = player.get("team_id")
    if type(team_id) is not int or team_id not in (1, 2):
        raise ValueError("invalid_human_team_id")
    loadout = _loadout_json(player.get("profile_matchmaking_details"))
    return ("<player_joined_cg xmlns='" + _NATIVE_XMLNS + "'><cg_id>"
            + escape(game_id) + "</cg_id><new_player>" + escape(user_id)
            + "</new_player><nickname>" + escape(nickname)
            + "</nickname><loadout>" + escape(loadout)
            + "</loadout><teamid>" + str(team_id)
            + "</teamid></player_joined_cg>")


def build_human_member_removed(game_id: str, player_id: str) -> str:
    return build_cpu_member_removed(game_id, player_id)


def build_human_loadout_changed(game_id: str, player_id: str, details: object) -> str:
    return build_cpu_loadout_changed(game_id, player_id, details)


def build_human_ready_changed(game_id: str, player_id: str, ready: bool) -> str:
    game_id = _game_id(game_id)
    player_id = _player_id(player_id, "human_user_id")
    if type(ready) is not bool:
        raise ValueError("invalid_human_ready")
    state = "ready" if ready else "not_ready"
    return ("<player_state_changed xmlns='" + _NATIVE_XMLNS + "'><cg_id>"
            + escape(game_id) + "</cg_id><player_id>" + escape(player_id)
            + "</player_id><new_state>" + state + "</new_state>"
            "</player_state_changed>")


def build_private_settings_changed(game_id: str, settings: object) -> str:
    """Build cg_state_changed's six direct children, identified in game.dll.

    Parser 0x10b6a0a0 reads cg_id/title/length/max_players/map/privacy;
    privacy is compared with the literal 'private', not parsed as a boolean.
    See docs/PRIVATE_LOBBY_SETTINGS.md for the pinned binary and evidence.
    """
    game_id = _game_id(game_id)
    if type(settings) is not dict or set(settings) != {
            "title", "length", "max_players", "map", "privacy"}:
        raise ValueError("invalid_private_settings")
    title = _text(settings["title"], "private_title", 320)
    if title != title.strip() or len(title) > 80:
        raise ValueError("invalid_private_title")
    length, maximum = settings["length"], settings["max_players"]
    if type(length) is not int or not 1 <= length <= 7200:
        raise ValueError("invalid_private_length")
    if type(maximum) is not int or not 2 <= maximum <= 20:
        raise ValueError("invalid_private_max_players")
    map_key, privacy = settings["map"], settings["privacy"]
    if not any(is_native_battle_map(map_key, ruleset)
               for ruleset in ("annihilation", "territory")):
        raise ValueError("invalid_private_map")
    if type(privacy) is not bool:
        raise ValueError("invalid_private_privacy")
    values = {"cg_id": game_id, "title": title, "length": str(length),
              "max_players": str(maximum), "map": map_key,
              "privacy": "private" if privacy else "public"}
    return ("<cg_state_changed xmlns='" + _NATIVE_XMLNS + "'>"
            + "".join("<" + key + ">" + escape(value) + "</" + key + ">"
                      for key, value in values.items()) + "</cg_state_changed>")
