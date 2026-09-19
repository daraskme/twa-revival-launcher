"""Pure contract for pre-battle CPU removal from a native private lobby.

The native client has been observed sending ``POST /kick_player`` when the
room owner removes a CPU card.  In that request, the body ``user_id`` is the
*target* player while the authenticated/local actor remains in the native
header ``user_id``.  Keeping those identities separate is the main security
boundary in this module.

This file deliberately does not register an HTTP path, send XMPP, or mutate a
``NativeCustomLobby`` instance.  ``apply_cpu_kick`` returns complete copies for
an owning adapter to commit atomically before it emits any notification.

No native CPU-add request or roster-add/remove notification has been proven.
The false capability flag prevents this removal contract from being mistaken
for a complete live add/remove implementation.
"""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Mapping


NATIVE_CPU_ADD_WIRE_VERIFIED = False

_GAME_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_USER_ID = re.compile(r"[\x21-\x7e]{1,128}\Z")
_ACTION_FIELDS = frozenset({
    "game_id",
    "user_id",
    "xmpp_region",
    "game_group",
    "build_id",
    "commander_id",
    "game_checksum",
    "game_data_hash",
})
_COMPATIBILITY_FIELDS = frozenset({
    "build_id", "commander_id", "game_checksum", "game_data_hash",
})
_UINT64_MAX = (1 << 64) - 1


class PrivateCpuContractError(ValueError):
    """Stable failure code that does not include request or profile data."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise PrivateCpuContractError(code)


def _user_id(value: object, code: str) -> str:
    if type(value) is not str or _USER_ID.fullmatch(value) is None:
        _fail(code)
    return value


def _metadata_text(value: object) -> bool:
    return (type(value) is str and len(value.encode("utf-8")) <= 128
            and all(ord(char) >= 32 and ord(char) != 127 for char in value))


@dataclass(frozen=True)
class NativeKickRequest:
    """Validated actor/target split from one native ``/kick_player`` call."""

    game_id: str
    actor_user_id: str
    target_user_id: str


@dataclass(frozen=True)
class CpuKickMutation:
    """Copied room/state pair for one atomic owner-controlled commit."""

    game: dict
    lab_state: dict
    removed_player: dict
    cleared_human_user_ids: tuple[str, ...]

    @property
    def cpu_opponents(self) -> int:
        return self.lab_state["cpu_opponents"]

    @property
    def ready_was_cleared(self) -> bool:
        return bool(self.cleared_human_user_ids)


def parse_native_kick_request(
        request: object,
        headers: object,
        *,
        local_user_id: str,
) -> NativeKickRequest:
    """Validate the observed native kick schema without conflating identities.

    ``headers['user_id']`` is required and must be the trusted local identity.
    ``request['user_id']`` is intentionally *not* compared to that identity;
    it names the roster row which the owner wants to remove.
    """
    local_user_id = _user_id(local_user_id, "invalid_local_user_id")
    if not isinstance(request, Mapping) or not isinstance(headers, Mapping):
        _fail("invalid_kick_request")
    if set(request) - _ACTION_FIELDS or not {"game_id", "user_id"} <= set(request):
        _fail("invalid_kick_request")
    if headers.get("user_id") != local_user_id:
        _fail("native_lobby_actor_mismatch")

    game_id = request["game_id"]
    if type(game_id) is not str or _GAME_ID.fullmatch(game_id) is None:
        _fail("invalid_game_id")
    target_user_id = _user_id(request["user_id"], "invalid_kick_target")

    for key in ("xmpp_region", "game_group"):
        if key in request and not _metadata_text(request[key]):
            _fail("invalid_native_metadata")
    for key in _COMPATIBILITY_FIELDS:
        if key not in request:
            continue
        value = request[key]
        if not ((type(value) is str and len(value.encode("utf-8")) <= 512)
                or (type(value) is int and 0 <= value <= _UINT64_MAX)):
            _fail("invalid_native_metadata")
    return NativeKickRequest(
        game_id=game_id,
        actor_user_id=local_user_id,
        target_user_id=target_user_id,
    )


def apply_cpu_kick(
        game: object,
        lab_state: object,
        kick: NativeKickRequest,
) -> CpuKickMutation:
    """Prepare an owner-only CPU removal while preserving every remaining ID.

    The operation is allowed only before battle start.  Zero CPUs is a valid
    result; the existing start boundary can continue rejecting a room until a
    CPU is added again through a future, proven protocol.  Every human ready
    flag is cleared because the frozen battle roster has changed.
    """
    if not isinstance(kick, NativeKickRequest):
        _fail("invalid_kick_request")
    if not isinstance(game, Mapping) or not isinstance(lab_state, Mapping):
        _fail("invalid_private_lobby_state")
    if game.get("game_id") != kick.game_id:
        _fail("native_lobby_not_found")
    if game.get("owner_id") != kick.actor_user_id:
        _fail("native_lobby_actor_mismatch")
    if lab_state.get("battle_started") is not False:
        _fail("private_battle_already_started")

    players = game.get("players")
    if not isinstance(players, list) or not players:
        _fail("invalid_private_lobby_roster")
    normalized: list[Mapping[str, object]] = []
    player_ids: set[str] = set()
    for player in players:
        if not isinstance(player, Mapping) or type(player.get("is_ai")) is not bool:
            _fail("invalid_private_lobby_roster")
        player_id = _user_id(player.get("user_id"), "invalid_private_lobby_roster")
        if player_id in player_ids or type(player.get("ready")) is not bool:
            _fail("invalid_private_lobby_roster")
        player_ids.add(player_id)
        normalized.append(player)

    owner_rows = [player for player in normalized
                  if player["user_id"] == kick.actor_user_id]
    if len(owner_rows) != 1 or owner_rows[0]["is_ai"] is not False:
        _fail("invalid_private_lobby_roster")
    target_rows = [player for player in normalized
                   if player["user_id"] == kick.target_user_id]
    if not target_rows:
        _fail("cpu_kick_target_not_found")
    target = target_rows[0]
    if target["is_ai"] is not True:
        _fail("cannot_kick_human_player")

    cpu_count = sum(player["is_ai"] is True for player in normalized)
    if (type(lab_state.get("cpu_opponents")) is not int
            or lab_state["cpu_opponents"] != cpu_count):
        _fail("invalid_private_lobby_roster")
    if type(lab_state.get("ready")) is not bool:
        _fail("invalid_private_lobby_state")

    new_game = copy.deepcopy(dict(game))
    new_state = copy.deepcopy(dict(lab_state))
    # Filter by the stable target ID.  Remaining rows keep their original
    # order, user_id and display_name; there is deliberately no CPU reindexing.
    new_game["players"] = [copy.deepcopy(dict(player)) for player in normalized
                           if player["user_id"] != kick.target_user_id]
    cleared: list[str] = []
    for player in new_game["players"]:
        if player["is_ai"] is False and player["ready"] is True:
            player["ready"] = False
            cleared.append(player["user_id"])
    new_state["ready"] = False
    new_state["cpu_opponents"] = cpu_count - 1

    return CpuKickMutation(
        game=new_game,
        lab_state=new_state,
        removed_player=copy.deepcopy(dict(target)),
        cleared_human_user_ids=tuple(cleared),
    )
