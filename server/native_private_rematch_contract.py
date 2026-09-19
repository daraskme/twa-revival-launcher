"""Pure state transition from a delivered private battle to its next round."""
from __future__ import annotations

import copy
import re
import uuid
from dataclasses import dataclass
from typing import Mapping


_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_DECIMAL_KEY = re.compile(r"[1-9][0-9]{0,19}\Z")
_UINT64_MAX = (1 << 64) - 1


class PrivateRematchContractError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise PrivateRematchContractError(code)


def _uuid(value: object, code: str) -> str:
    if type(value) is not str or _UUID.fullmatch(value) is None:
        _fail(code)
    try:
        canonical = str(uuid.UUID(value))
    except ValueError:
        _fail(code)
    if canonical != value:
        _fail(code)
    return value


def _key(value: object) -> str:
    if (type(value) is not str or _DECIMAL_KEY.fullmatch(value) is None
            or int(value) > _UINT64_MAX or str(int(value)) != value):
        _fail("invalid_private_rematch_credential")
    return value


@dataclass(frozen=True)
class PrivateRematchMutation:
    game: dict
    lab_state: dict
    room_game_id: str
    completed_battle_instance_id: str
    next_battle_instance_id: str
    next_battle_key: str
    battle_round: int


def apply_private_rematch(
    game: object,
    lab_state: object,
    *,
    completed_battle_instance_id: str,
    completed_phase: str,
    next_battle_instance_id: str,
    next_battle_key: str,
) -> PrivateRematchMutation:
    """Prepare the same native room only after its final result was delivered.

    ``game_id`` is the stable custom-room identity consumed by the native UI.
    ``battle_instance_id`` is the unique durable LocalBattleState identity.
    The caller stores each old result under the latter before invoking this
    transition; this function never mutates or deletes result storage.
    """
    if not isinstance(game, Mapping) or not isinstance(lab_state, Mapping):
        _fail("invalid_private_rematch_state")
    room_id = _uuid(game.get("game_id"), "invalid_private_room_id")
    current_id = _uuid(lab_state.get("battle_instance_id"),
                       "invalid_private_battle_instance_id")
    completed_id = _uuid(completed_battle_instance_id,
                         "invalid_private_battle_instance_id")
    next_id = _uuid(next_battle_instance_id,
                    "invalid_private_battle_instance_id")
    next_key = _key(next_battle_key)
    if completed_phase != "delivered":
        _fail("private_result_not_delivered")
    if lab_state.get("battle_started") is not True or completed_id != current_id:
        _fail("private_battle_completion_mismatch")

    history = lab_state.get("completed_battle_instance_ids")
    battle_round = lab_state.get("battle_round")
    if (not isinstance(history, list)
            or any(type(value) is not str or _UUID.fullmatch(value) is None
                   for value in history)
            or len(history) != len(set(history))
            or current_id in history
            or type(battle_round) is not int
            or battle_round != len(history) + 1):
        _fail("invalid_private_rematch_state")
    if next_id == current_id or next_id in history:
        _fail("duplicate_private_battle_instance_id")
    old_key = _key(game.get("battle_key"))
    if next_key == old_key:
        _fail("duplicate_private_battle_credential")

    players = game.get("players")
    if not isinstance(players, list) or not players:
        _fail("invalid_private_rematch_roster")
    humans = [row for row in players
              if isinstance(row, Mapping) and row.get("is_ai") is False]
    cpus = [row for row in players
            if isinstance(row, Mapping) and row.get("is_ai") is True]
    if (len(humans) != 1 or humans[0].get("user_id") != game.get("owner_id")
            or not isinstance(players[0], Mapping)
            or players[0].get("is_ai") is not False
            or players[0].get("user_id") != game.get("owner_id")
            or len(players) != len(humans) + len(cpus)
            or any(row.get("ready") is not True for row in players)
            or any(row.get("team_id") != 2 for row in cpus)):
        _fail("invalid_private_rematch_roster")

    updated_game = copy.deepcopy(dict(game))
    updated_state = copy.deepcopy(dict(lab_state))
    for player in updated_game["players"]:
        if player["is_ai"] is False:
            player["ready"] = False
        else:
            player["ready"] = True
    updated_game["battle_key"] = next_key
    updated_state["ready"] = False
    updated_state["battle_started"] = False
    updated_state["completed_battle_instance_ids"] = [*history, current_id]
    updated_state["battle_instance_id"] = next_id
    updated_state["battle_round"] = battle_round + 1

    return PrivateRematchMutation(
        game=updated_game,
        lab_state=updated_state,
        room_game_id=room_id,
        completed_battle_instance_id=current_id,
        next_battle_instance_id=next_id,
        next_battle_key=next_key,
        battle_round=battle_round + 1,
    )
