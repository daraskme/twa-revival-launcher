"""Pure 20-seat native battle roster contract used by local PvE matchmaking.

This module only builds an immutable *rendered* roster.  It deliberately does
not assign native player ids, create credentials, enroll users, open a relay,
or mutate a profile.  The NativeMatchmaking adapter keeps the human transport
list separate from rendered CPU rows; runtime battle behavior remains
unverified until a user completes both PvE rulesets.
"""
from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

try:
    from .native_battle_maps import (
        NATIVE_BATTLE_RULESET_MAPS,
        is_native_battle_map,
    )
except ImportError:
    from native_battle_maps import (
        NATIVE_BATTLE_RULESET_MAPS,
        is_native_battle_map,
    )


RUNTIME_VERIFIED = False
MAX_SEATS_PER_TEAM = 10
TOTAL_SEATS = 20
UNITS_PER_SEAT = 3
TOTAL_DIRECT_UNITS = TOTAL_SEATS * UNITS_PER_SEAT
COMBAT_TIER = 10
# Explicit legacy defaults for callers that do not yet carry a frozen map.
MAP_BY_RULESET = dict(NATIVE_BATTLE_RULESET_MAPS)


class BattleRosterError(ValueError):
    """Stable validation code; never includes secrets or opaque payloads."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class CpuCommander:
    key: str
    faction: str
    combat_tier: int = COMBAT_TIER
    build_state: str = "live"


@dataclass(frozen=True)
class CpuUnit:
    key: str
    faction: str
    combat_tier: int = COMBAT_TIER
    build_state: str = "live"


@dataclass(frozen=True)
class RosterSeat:
    """One rendered player seat; no native player id is invented here."""

    roster_slot: int
    team: int
    is_ai: bool
    human_transport_index: int | None
    user_id: str | None
    commander_key: str
    faction: str
    combat_tier: int
    unit_keys: tuple[str, str, str]


@dataclass(frozen=True)
class BattleRoster:
    """Canonical immutable rendered roster and its human-only boundaries."""

    mode: str
    ruleset: str
    map_key: str
    battle_id: str
    seats: tuple[RosterSeat, ...]
    human_transport_ids: tuple[str, ...]
    reward_participant_ids: tuple[str, ...]
    auth_participant_ids: tuple[str, ...]
    digest: str
    runtime_verified: bool = RUNTIME_VERIFIED

    @property
    def seat_count(self) -> int:
        return len(self.seats)

    @property
    def direct_unit_count(self) -> int:
        return sum(len(seat.unit_keys) for seat in self.seats)

    @property
    def ai_seats(self) -> tuple[RosterSeat, ...]:
        return tuple(seat for seat in self.seats if seat.is_ai)

    @property
    def human_seats(self) -> tuple[RosterSeat, ...]:
        return tuple(seat for seat in self.seats if not seat.is_ai)

    def canonical(self) -> dict[str, Any]:
        """Return JSON-safe data without exposing the server seed."""
        return {
            "mode": self.mode,
            "ruleset": self.ruleset,
            "map_key": self.map_key,
            "battle_id": self.battle_id,
            "seats": [_seat_dict(seat) for seat in self.seats],
            "human_transport_ids": list(self.human_transport_ids),
            "reward_participant_ids": list(self.reward_participant_ids),
            "auth_participant_ids": list(self.auth_participant_ids),
            "runtime_verified": self.runtime_verified,
        }


def _error(code: str) -> None:
    raise BattleRosterError(code)


def _text(value: object, code: str, *, maximum: int = 128) -> str:
    if (type(value) is not str or not value or len(value.encode("utf-8")) > maximum
            or any(ord(char) < 0x20 or ord(char) == 0x7f for char in value)):
        _error(code)
    return value


def _unit_keys(value: object, code: str) -> tuple[str, str, str]:
    if isinstance(value, Mapping):
        value = value.get("unit_keys", value.get("units"))
    if (not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray))
            or len(value) != UNITS_PER_SEAT):
        _error(code)
    result = tuple(_text(item, code, maximum=256) for item in value)
    return result  # type: ignore[return-value]


def _cpu_commander(value: object) -> CpuCommander:
    if isinstance(value, CpuCommander):
        result = value
    elif isinstance(value, Mapping):
        result = CpuCommander(
            key=value.get("key", value.get("commander_key")),
            faction=value.get("faction"),
            combat_tier=value.get("combat_tier", value.get("tier", COMBAT_TIER)),
            build_state=value.get("build_state", "live"),
        )
    else:
        _error("invalid_cpu_commander")
    _text(result.key, "invalid_cpu_commander_key", maximum=256)
    _text(result.faction, "invalid_cpu_commander_faction", maximum=128)
    if (result.build_state != "live" or type(result.combat_tier) is not int
            or result.combat_tier != COMBAT_TIER):
        _error("unsupported_cpu_commander")
    return result


def _cpu_commanders(value: object) -> tuple[CpuCommander, ...]:
    if isinstance(value, (CpuCommander, Mapping)):
        values = (value,)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        values = value
    else:
        _error("invalid_cpu_commander_pool")
    result = tuple(_cpu_commander(row) for row in values)
    if not result:
        _error("empty_cpu_commander_pool")
    if len({commander.key for commander in result}) != len(result):
        _error("duplicate_cpu_commander")
    return tuple(sorted(result, key=lambda commander: commander.key))


def _cpu_units(value: object, commanders: Sequence[CpuCommander]) -> tuple[CpuUnit, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        _error("invalid_cpu_unit_pool")
    result: list[CpuUnit] = []
    seen: set[str] = set()
    for row in value:
        if isinstance(row, CpuUnit):
            unit = row
        elif isinstance(row, Mapping):
            unit = CpuUnit(
                key=row.get("key", row.get("unit_key")),
                faction=row.get("faction"),
                combat_tier=row.get("combat_tier", row.get("tier", COMBAT_TIER)),
                build_state=row.get("build_state", "live"),
            )
        else:
            _error("invalid_cpu_unit")
        _text(unit.key, "invalid_cpu_unit_key", maximum=256)
        _text(unit.faction, "invalid_cpu_unit_faction", maximum=128)
        if unit.key in seen:
            _error("duplicate_cpu_unit")
        seen.add(unit.key)
        if (unit.build_state != "live" or type(unit.combat_tier) is not int
                or unit.combat_tier != COMBAT_TIER
                or unit.faction not in {commander.faction for commander in commanders}):
            _error("unsupported_cpu_unit")
        result.append(unit)
    if not result:
        _error("empty_cpu_unit_pool")
    if any(not any(unit.faction == commander.faction for unit in result)
           for commander in commanders):
        _error("cpu_commander_without_units")
    # Pool ordering is not part of the server-owned battle input.  Canonical
    # sorting makes a retry with the same pool produce the same roster.
    return tuple(sorted(result, key=lambda unit: unit.key))


def _human(value: object, index: int, mode: str) -> RosterSeat:
    if not isinstance(value, Mapping):
        _error("invalid_human")
    user_id = _text(value.get("user_id"), "invalid_human_user_id")
    team = value.get("team")
    if team is not None and (type(team) is not int or team not in (0, 1)):
        _error("invalid_human_team")
    if mode == "pve" and team not in (None, 0):
        _error("pve_human_team")
    if team is None:
        team = 0
    commander_key = _text(
        value.get("commander_key", value.get("commander", "human")),
        "invalid_human_commander", maximum=256,
    )
    faction = _text(value.get("faction", "human"), "invalid_human_faction")
    tier = value.get("combat_tier", value.get("tier", COMBAT_TIER))
    if type(tier) is not int or tier != COMBAT_TIER:
        _error("invalid_human_combat_tier")
    units = _unit_keys(value, "invalid_human_units")
    return RosterSeat(-1, team, False, index, user_id, commander_key,
                      faction, tier, units)


def _seat_dict(seat: RosterSeat) -> dict[str, Any]:
    return {
        "roster_slot": seat.roster_slot,
        "team": seat.team,
        "is_ai": seat.is_ai,
        "human_transport_index": seat.human_transport_index,
        "user_id": seat.user_id,
        "commander_key": seat.commander_key,
        "faction": seat.faction,
        "combat_tier": seat.combat_tier,
        "unit_keys": list(seat.unit_keys),
    }


def _seed_bytes(seed: object) -> bytes:
    if isinstance(seed, bytes):
        value = seed
    elif type(seed) is str:
        value = seed.encode("utf-8")
    else:
        _error("invalid_roster_seed")
    if not 1 <= len(value) <= 4096:
        _error("invalid_roster_seed")
    return value


def select_cpu_asset_palette_v3(
        commanders: (CpuCommander | Mapping[str, object]
                     | Sequence[CpuCommander | Mapping[str, object]]),
        units: Sequence[CpuUnit | Mapping[str, object]],
        seed: str | bytes,
) -> tuple[tuple[CpuCommander, ...], tuple[CpuUnit, ...]]:
    """Select a small, seeded CPU asset palette from a trusted full pool.

    The caller remains responsible for supplying its approved non-premium pool.
    Validate that entire pool before selection, so an invalid omitted row
    cannot be hidden by the palette. This function creates no seats or digest;
    the caller passes the result to the unchanged roster builder.
    """
    normalized_commanders = _cpu_commanders(commanders)
    normalized_units = _cpu_units(units, normalized_commanders)
    seed_hash = hashlib.sha256(_seed_bytes(seed)).digest()

    def rank(domain: bytes, key: str) -> tuple[bytes, str]:
        encoded_key = key.encode("utf-8")
        value = hashlib.sha256(
            b"twa-revival:cpu-asset-palette:v3\0" + domain + b"\0"
            + seed_hash + len(encoded_key).to_bytes(4, "big") + encoded_key
        ).digest()
        return value, key

    commander = min(normalized_commanders,
                    key=lambda row: rank(b"commander", row.key))
    compatible_units = (row for row in normalized_units
                        if row.faction == commander.faction)
    chosen_units = tuple(sorted(compatible_units,
                                key=lambda row: rank(b"unit", row.key))
                         [:UNITS_PER_SEAT])
    return (commander,), chosen_units


def select_cpu_asset_palette_v4(
        commanders: (CpuCommander | Mapping[str, object]
                     | Sequence[CpuCommander | Mapping[str, object]]),
        units: Sequence[CpuUnit | Mapping[str, object]],
        seed: str | bytes,
) -> tuple[tuple[CpuCommander, ...], tuple[CpuUnit, ...]]:
    """Bound one battle to two same-faction commanders and three T10 units.

    The caller supplies the trusted non-premium T10 catalogue. Every commander
    remains eligible across seeds, while each battle loads a small asset set.
    Validate the full pool before selecting, as v3 does.
    """
    normalized_commanders = _cpu_commanders(commanders)
    normalized_units = _cpu_units(units, normalized_commanders)
    seed_hash = hashlib.sha256(_seed_bytes(seed)).digest()

    def rank(domain: bytes, key: str) -> tuple[bytes, str]:
        encoded_key = key.encode("utf-8")
        return (hashlib.sha256(
            b"twa-revival:cpu-asset-palette:v4\0" + domain + b"\0"
            + seed_hash + len(encoded_key).to_bytes(4, "big") + encoded_key
        ).digest(), key)

    primary = min(normalized_commanders,
                  key=lambda row: rank(b"commander", row.key))
    faction_commanders = sorted(
        (row for row in normalized_commanders if row.faction == primary.faction),
        key=lambda row: rank(b"commander", row.key))
    faction_units = sorted(
        (row for row in normalized_units if row.faction == primary.faction),
        key=lambda row: rank(b"unit", row.key))
    if len(faction_commanders) < 2 or len(faction_units) < UNITS_PER_SEAT:
        _error("cpu_palette_v4_insufficient_faction_assets")
    return tuple(faction_commanders[:2]), tuple(faction_units[:UNITS_PER_SEAT])


def _digest(data: Mapping[str, Any]) -> str:
    encoded = json.dumps(data, ensure_ascii=True, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_battle_roster(*, mode: str, ruleset: str,
                        battle_id: str,
                        humans: Sequence[Mapping[str, object]],
                        cpu_commander: (CpuCommander | Mapping[str, object]
                                        | Sequence[CpuCommander | Mapping[str, object]]),
                        cpu_unit_pool: Sequence[CpuUnit | Mapping[str, object]],
                        seed: str | bytes, map_key: str | None = None,
                        honor_explicit_teams: bool = False,
                        allow_one_sided_pvp: bool = False,
                        independent_cpu_commanders: bool = False) -> BattleRoster:
    """Build a deterministic 20-seat roster for a trusted runtime adapter.

    ``battle_id`` is a required bounded lifecycle binding.  It is included in
    the canonical digest and deterministic CPU seed; the raw server seed is
    never returned.  PvE accepts one to ten humans, all on team 0.  PvP accepts two to twenty
    distinct humans and deterministically assigns them in input order to the
    currently smaller team (therefore team counts differ by at most one).
    ``honor_explicit_teams`` is reserved for a future trusted private-lobby
    caller; the standard path deliberately ignores optional input team hints.
    Both paths fill each team to ten seats.
    All remaining seats are server-authored AI rows.  Every seat always has
    exactly three direct unit keys; AI rows never enter the human transport,
    reward, or authentication participant tuples.
    """
    if mode not in ("pve", "pvp"):
        _error("unsupported_mode")
    if ruleset not in MAP_BY_RULESET:
        _error("unsupported_ruleset")
    expected_map = MAP_BY_RULESET[ruleset]
    battle_id = _text(battle_id, "invalid_battle_id", maximum=128)
    if map_key is None:
        map_key = expected_map
    elif not is_native_battle_map(map_key, ruleset):
        _error("ruleset_map_mismatch")
    seed_value = _seed_bytes(seed)
    if type(honor_explicit_teams) is not bool:
        _error("invalid_explicit_team_mode")
    if type(independent_cpu_commanders) is not bool:
        _error("invalid_cpu_commander_selection")
    if (type(allow_one_sided_pvp) is not bool
            or allow_one_sided_pvp and (mode != 'pvp' or not honor_explicit_teams)):
        _error('invalid_one_sided_pvp_mode')
    if (not isinstance(humans, Sequence)
            or isinstance(humans, (str, bytes, bytearray))):
        _error("invalid_humans")
    if mode == "pve" and not 1 <= len(humans) <= MAX_SEATS_PER_TEAM:
        _error("invalid_pve_human_count")
    if mode == "pvp" and not 1 <= len(humans) <= TOTAL_SEATS:
        _error("invalid_pvp_human_count")

    normalized_humans = [_human(row, index, mode)
                         for index, row in enumerate(humans)]
    user_ids = [seat.user_id for seat in normalized_humans]
    if len(set(user_ids)) != len(user_ids):
        _error("duplicate_human")
    if mode == "pvp" and not honor_explicit_teams:
        counts = [0, 0]
        reassigned: list[RosterSeat] = []
        for seat in normalized_humans:
            team = 0 if counts[0] <= counts[1] else 1
            counts[team] += 1
            reassigned.append(replace(seat, team=team))
        normalized_humans = reassigned
    elif mode == "pvp" and any(value.get("team") is None
                               for value in humans if isinstance(value, Mapping)):
        _error("explicit_human_team_required")
    team_counts = {team: sum(seat.team == team for seat in normalized_humans)
                   for team in (0, 1)}
    if any(count > MAX_SEATS_PER_TEAM for count in team_counts.values()):
        _error("team_capacity_exceeded")
    if (mode == "pvp" and len(humans) > 1 and not all(team_counts.values())
            and not allow_one_sided_pvp):
        _error("pvp_both_teams_required")

    commanders = _cpu_commanders(cpu_commander)
    units = _cpu_units(cpu_unit_pool, commanders)
    human_seed_data = [{"user_id": seat.user_id, "team": seat.team,
                        "commander_key": seat.commander_key,
                        "faction": seat.faction, "combat_tier": seat.combat_tier,
                        "unit_keys": list(seat.unit_keys)}
                       for seat in normalized_humans]
    rng_seed = hashlib.sha256(
        b"twa-revival:native-battle-roster:v1\0" + hashlib.sha256(seed_value).digest()
        + battle_id.encode("utf-8") + b"\0" + mode.encode("ascii")
        + b"\0" + ruleset.encode("ascii") + b"\0" + map_key.encode("ascii")
        + json.dumps(human_seed_data, ensure_ascii=True, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
    ).digest()
    rng = random.Random(int.from_bytes(rng_seed, "big"))

    ai_needed = TOTAL_SEATS - len(normalized_humans)
    seats: list[RosterSeat] = []
    transport_ids = tuple(user_ids)  # type: ignore[arg-type]
    commander_bag: list[CpuCommander] = []

    def next_commander() -> CpuCommander:
        # Seeded shuffled cycles give variety without letting a large pool
        # collapse into an all-identical CPU roster by chance.
        nonlocal commander_bag
        if not commander_bag:
            commander_bag = list(commanders)
            rng.shuffle(commander_bag)
        return commander_bag.pop()

    for team in (0, 1):
        team_humans = [seat for seat in normalized_humans if seat.team == team]
        for seat in team_humans:
            seats.append(seat)
        for _ in range(MAX_SEATS_PER_TEAM - len(team_humans)):
            # Choice is server-seeded and deterministic.  The full output is
            # frozen once returned; this function never rerolls on retry.
            # v5 has a separate stream per seat, so one bot's commander and
            # units cannot consume the random draws of a later bot.
            seat_rng = (random.Random(int.from_bytes(hashlib.sha256(
                b"twa-revival:native-battle-roster:v5-seat\0" + rng_seed
                + len(seats).to_bytes(2, "big")).digest(), "big"))
                if independent_cpu_commanders else rng)
            commander = (seat_rng.choice(commanders) if independent_cpu_commanders
                         else next_commander())
            compatible = tuple(unit for unit in units
                               if unit.faction == commander.faction)
            selected = tuple(seat_rng.choice(compatible).key
                             for _ in range(UNITS_PER_SEAT))
            seats.append(RosterSeat(-1, team, True, None, None, commander.key,
                                    commander.faction, COMBAT_TIER, selected))

    if sum(seat.is_ai for seat in seats) != ai_needed:
        _error("roster_count_mismatch")
    seats = [RosterSeat(slot, seat.team, seat.is_ai, seat.human_transport_index,
                        seat.user_id, seat.commander_key, seat.faction,
                        seat.combat_tier, seat.unit_keys)
             for slot, seat in enumerate(seats)]
    if (len(seats) != TOTAL_SEATS
            or sum(len(seat.unit_keys) for seat in seats) != TOTAL_DIRECT_UNITS
            or [seat.roster_slot for seat in seats] != list(range(TOTAL_SEATS))):
        _error("roster_shape_invalid")

    canonical = {
        "mode": mode,
        "ruleset": ruleset,
        "map_key": map_key,
        "battle_id": battle_id,
        "seats": [_seat_dict(seat) for seat in seats],
        "human_transport_ids": list(transport_ids),
        "reward_participant_ids": list(transport_ids),
        "auth_participant_ids": list(transport_ids),
        "runtime_verified": RUNTIME_VERIFIED,
    }
    digest = _digest(canonical)
    return BattleRoster(mode, ruleset, map_key, battle_id, tuple(seats),
                        transport_ids, transport_ids, transport_ids, digest)


# Readable alias for callers that prefer a constructor-like name.
create_battle_roster = build_battle_roster
