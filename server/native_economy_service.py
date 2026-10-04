"""HTTP-facing composition boundary for native profile and public economy.

The service keeps HTTP decoding and battle-result policy out of
``LocalEconomy``.  It exposes the same ``respond(raw, accept_selection)``
shape as ``SelectionState``, forwards only proven purchase requests to
``NativeEconomyAdapter``, and accepts only the statically proven native final
result object before settling rewards.  Native result rows are never rewritten
here.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import threading
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

from local_economy import (
    EFFECTIVE_CONSUMABLE_SLOTS,
    EconomyError,
    LocalEconomy,
)
from native_economy_adapter import NativeEconomyAdapter

try:
    from .specialization_ui_status import UI_STATUS_VERSION
except ImportError:
    from specialization_ui_status import UI_STATUS_VERSION

try:
    from .native_battle_maps import is_native_battle_map
except ImportError:
    from native_battle_maps import is_native_battle_map


UINT64_MAX = 2**64 - 1
_FINAL_EVENT_FIELDS = {
    "battle_id",
    "seq_id",
    "user_id",
    "events",
}
_FINAL_PLAYER_EVENT_FIELDS = {
    "user_id",
    "party_id",
    "type",
    "result_details",
}
_FINAL_RESULT_FIELDS = {
    "battle_map_key",
    "duration",
    "result",
    "victory_mean",
    "scale",
    "character_key",
    "commander_skin",
    "portrait_key",
    "is_premium",
    "alliance_id",
    "player_name",
    "was_afk",
    "badges",
    "unit_results",
}
_NATIVE_RESULT_OUTCOMES = {
    "result_close_victory": "victory",
    "result_decisive_victory": "victory",
    "result_heroic_victory": "victory",
    "result_pyrrhic_victory": "victory",
    "result_victory": "victory",
    "result_close_defeat": "defeat",
    "result_crushing_defeat": "defeat",
    "result_decisive_defeat": "defeat",
    "result_valiant_defeat": "defeat",
    "result_draw": "draw",
}
_SELECTION_FIELDS = {"profile_timestamp", "active_commander"}
_OPTIONAL_SELECTION_FIELDS = {"active_title"}
_PROFILE_READ_FIELDS = ({"timestamp"}, {"profile_timestamp"})
_TUTORIAL_PROGRESS_FIELDS = {"profile_timestamp", "tutorial_progress"}
_OPTIONAL_TUTORIAL_PROGRESS_FIELDS = {"active_commander", "active_title"}
_MAX_TUTORIAL_PROGRESS = 4
# One-shot causal gate after an acknowledged commander selection (see
# ``respond_profile_message``).  The R20 trace measured 0.17-2.4 s between an
# accepted ``active_commander`` POST and the client's ``timestamp:0`` follow-up
# read; five seconds is twice that maximum while still expiring long before a
# user could reach another screen that legitimately needs a full read.
_SELECTION_ZERO_READ_WINDOW_SECONDS = 5.0
# A stock unit-card drop is persisted by the loopback companion rather than by
# Arena's retired profile protocol.  The companion then raises Arena's stock
# deferred-profile flag, which posts the still-visible selection. Keep a
# separate, narrowly correlated window for that request; it is longer than the
# ordinary selection -> zero-read gate but still too short to survive
# navigation to an unrelated hangar interaction.
_EXTERNAL_PROFILE_REFRESH_WINDOW_SECONDS = 10.0
# v14 still posts the commander from which a hangar rebuild started after a
# real selection (live: Crixus -> Xerxes after 5.7 s).  The guard below blocks
# only that exact chain-origin return; other commander/faction selections are
# accepted during the same window.
_SELECTION_CHAIN_SUPPRESS_SECONDS = 10.0
# The stock hangar posts a faction-derived commander shortly after installing
# its initial full profile, before the player can interact with the UI.  Treat
# mismatching selections in this bounded startup window as presentation noise;
# echo the authoritative property but never persist them.
_BOOTSTRAP_SELECTION_SUPPRESS_SECONDS = 12.0
# Bound on remembered client watermark -> selection watermark links.
_MAX_SELECTION_WATERMARKS = 64
_CONTEXT_FIELDS = {
    "mode",
    "ruleset",
    "map",
    "party_id",
    "profile_saved",
    "commander_key",
    "commander_item_id",
    "commander_tier",
    "unit_tiers",
    "unit_item_ids",
    "unit_instance_ids",
    "battle_tier",
    "pve_enemy_tier",
    "roster_hash",
    "full_squad_setup",
    "result_participants",
    "roster_policy",
    "display_name",
}
_REQUIRED_CONTEXT_FIELDS = {
    "mode",
    "profile_saved",
    "commander_key",
    "commander_tier",
    "unit_tiers",
    "battle_tier",
    "pve_enemy_tier",
    "full_squad_setup",
}


class NativeResultSchemaError(EconomyError):
    """A stable economy error with a value-free validation location."""

    def __init__(self, code: str, failure: str):
        super().__init__(code)
        self.failure = failure


def _valid_public_cpu_fill_policy(value: object) -> bool:
    """Recognize only NativeMatchmaking's frozen public CPU-fill policy."""
    if not isinstance(value, dict):
        return False
    version = value.get('version')
    if type(version) is not int or version not in (1, 2, 3, 4, 5):
        return False
    expected = {
        "version": version, "totalSeats": 20, "seatsPerTeam": 10,
        "unitsPerSeat": 3, "humanParticipantsOnly": True, "cpuFill": True,
    }
    if (set(value) != set(expected) | {"seed"}
            or type(value.get("version")) is not int
            or type(value.get("totalSeats")) is not int
            or type(value.get("seatsPerTeam")) is not int
            or type(value.get("unitsPerSeat")) is not int
            or type(value.get("humanParticipantsOnly")) is not bool
            or type(value.get("cpuFill")) is not bool
            or any(value.get(key) != expected_value
                   for key, expected_value in expected.items())
            or not isinstance(value.get("seed"), str)):
        return False
    seed = value["seed"]
    if not seed.startswith((f"pvp-roster-v{version}:", f"pve-roster-v{version}:")):
        return False
    try:
        assignment_id = seed.split(":", 1)[1]
        return str(uuid.UUID(assignment_id)) == assignment_id
    except (ValueError, AttributeError, TypeError):
        return False


def _valid_public_cpu_fill_participants(
    rows: list[dict], humans: int, ais: int, policy: object,
) -> bool:
    return (
        _valid_public_cpu_fill_policy(policy)
        and len(rows) == 20
        and 1 <= humans <= (10 if policy["seed"].startswith("pve-") else 20)
        and ais == 20 - humans
        and all(
            not row["is_ai"] or re.fullmatch(
                r"cpu-pvp-[0-9a-f]{24}", row["user_id"]
            ) is not None
            for row in rows
        )
    )


def _json_type(value: object) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "bool"
    if type(value) is int:
        return "int"
    if type(value) is float:
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unsupported"


def _safe_schema_key(value: object) -> str:
    """Return a bounded field name, never an attacker-controlled scalar value."""
    if (isinstance(value, str) and 1 <= len(value) <= 64
            and all(character.isascii()
                    and (character.isalnum() or character in "_-")
                    for character in value)):
        return value
    return "<unsafe-key>"


def _schema_shape(value: object, *, depth: int = 0) -> dict:
    """Describe JSON structure without copying any scalar value."""
    kind = _json_type(value)
    shape: dict[str, object] = {"type": kind}
    if depth >= 5:
        return shape
    if isinstance(value, str):
        shape["length"] = len(value)
    elif isinstance(value, dict):
        fields: dict[str, object] = {}
        for key in sorted(value, key=lambda item: str(item))[:64]:
            safe = _safe_schema_key(key)
            if safe in fields:
                safe = "<unsafe-key-duplicate>"
            fields[safe] = _schema_shape(value[key], depth=depth + 1)
        shape.update({"count": len(value), "fields": fields})
    elif isinstance(value, list):
        counts = Counter(_json_type(item) for item in value)
        shape.update({
            "count": len(value),
            "item_types": {key: counts[key] for key in sorted(counts)},
            # Three samples distinguish native unit/ability row shapes while
            # remaining bounded. Samples contain types and keys only.
            "items": [_schema_shape(item, depth=depth + 1)
                      for item in value[:3]],
        })
    return shape


def native_result_schema_fingerprint(request: object, failure: str) -> dict:
    """Build a bounded diagnostic containing no IDs, credentials, or values."""
    return {
        "validation_failure": failure,
        "shape": _schema_shape(request),
    }


def _result_error(failure: str, code: str = "unsupported_battle_result_schema") -> None:
    raise NativeResultSchemaError(code, failure)


def _uint64(value: object, code: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if type(value) is not int or not minimum <= value <= UINT64_MAX:
        raise EconomyError(code)
    return value


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                         allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _strict_json(raw: bytes) -> dict:
    if not isinstance(raw, bytes):
        raise EconomyError("invalid_native_json")

    def pairs(values: list[tuple[str, Any]]) -> dict:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise EconomyError("duplicate_native_json_key")
            result[key] = value
        return result

    def constant(_value: str) -> None:
        raise EconomyError("invalid_native_json_number")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except EconomyError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EconomyError("invalid_native_json") from exc
    if not isinstance(value, dict):
        raise EconomyError("invalid_native_json")
    return value


def _wire_properties(properties: list) -> list:
    """Encode selected model IDs with SelectionState's signed-int64 policy."""
    result = copy.deepcopy(properties)
    if not isinstance(result, list):
        raise EconomyError("invalid_profile_properties")
    for row in result:
        if not isinstance(row, list) or len(row) != 4:
            raise EconomyError("invalid_profile_properties")
        if row[0] in ("active_commander", "active_title"):
            active = _uint64(row[3], "invalid_profile_property")
            row[3] = active if active < 2**63 else active - 2**64
    return result


def _validated_result_participants(
    value: object,
    *,
    local_user_id: str,
    party_id: object,
    mode: str,
    roster_policy: object = None,
) -> list[dict] | None:
    """Validate an optional server-frozen native result roster."""
    if value is None:
        # A public PvP settlement is meaningful only when the server froze
        # the complete human roster before battle.  Without it, a single
        # client could submit an otherwise valid one-player final and receive
        # the PvP multiplier without a proven opponent.
        if mode == "pvp":
            raise EconomyError("invalid_allocation_result_participants")
        return None
    if (not isinstance(value, list) or not 1 <= len(value) <= 20
            or not isinstance(party_id, str) or len(party_id) > 128):
        raise EconomyError("invalid_allocation_result_participants")
    result: list[dict] = []
    seen: set[str] = set()
    humans = 0
    ais = 0
    for row in value:
        if (not isinstance(row, dict)
                or set(row) != {"user_id", "party_id", "is_ai"}):
            raise EconomyError("invalid_allocation_result_participants")
        user_id = row.get("user_id")
        is_ai = row.get("is_ai")
        result_party = row.get("party_id")
        if (not isinstance(user_id, str) or not 1 <= len(user_id) <= 128
                or user_id in seen or type(is_ai) is not bool
                or not isinstance(result_party, str) or len(result_party) > 128):
            raise EconomyError("invalid_allocation_result_participants")
        if is_ai:
            ais += 1
            if user_id == local_user_id or result_party != "":
                raise EconomyError("invalid_allocation_result_participants")
        else:
            humans += 1
            if user_id == local_user_id and result_party != party_id:
                raise EconomyError("invalid_allocation_result_participants")
        seen.add(user_id)
        result.append({"user_id": user_id, "party_id": result_party,
                       "is_ai": is_ai})
    if not any(row["user_id"] == local_user_id and not row["is_ai"]
               for row in result):
        raise EconomyError("invalid_allocation_result_participants")
    if mode == "pvp" and ais and roster_policy is None:
        raise EconomyError("invalid_allocation_result_participants")
    if roster_policy is not None:
        # Only NativeMatchmaking's frozen public CPU renderer may add AI rows.
        # Legacy/no-policy PvP and arbitrary caller-supplied AI identities are
        # intentionally rejected at the economy boundary.
        if (not _valid_public_cpu_fill_participants(
                result, humans, ais, roster_policy)
                or not roster_policy["seed"].startswith(mode + "-roster-v" + str(roster_policy['version']) + ":")):
            raise EconomyError("invalid_allocation_result_participants")
    if ((mode == "pve" and (not 1 <= humans <= (10 if roster_policy else 1) or ais < 1))
            or (mode == "pvp" and humans < (1 if roster_policy else 2))
            or mode not in {"pve", "pvp"}):
        raise EconomyError("invalid_allocation_result_participants")
    return result


def native_final_result_rows(
    request: object,
    *,
    result_participants: object = None,
    roster_policy: object = None,
    custom_battle_no_party: bool = False,
) -> list[dict]:
    """Validate the native final POST shape and build GET result rows.

    ``battle_key`` is deliberately absent: the HTTP handler verifies and
    removes that credential before durable storage or this trust boundary.
    The response-side parser expects a different envelope from the POST, so
    only that envelope is rebuilt; ``type`` and ``result_details`` are direct
    row fields (``results`` is the discriminator value, never a wrapper key).
    Every native ``result_details`` object is retained unchanged.
    """
    if not isinstance(request, dict):
        _result_error("request.type")
    if set(request) != _FINAL_EVENT_FIELDS:
        _result_error("request.fields")
    try:
        sequence = _uint64(request.get("seq_id"), "invalid_battle_result_sequence")
    except EconomyError:
        _result_error("request.seq_id.type_or_range",
                      "invalid_battle_result_sequence")
    if sequence >= 2**63:
        _result_error("request.seq_id.signed_range",
                      "invalid_battle_result_sequence")
    for key in ("battle_id", "user_id"):
        value = request.get(key)
        if not isinstance(value, str):
            _result_error(f"request.{key}.type")
        if not 1 <= len(value) <= 128:
            _result_error(f"request.{key}.length")
    events = request.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= 20:
        _result_error("request.events.type_or_count")
    if type(custom_battle_no_party) is not bool:
        _result_error("custom_battle_no_party.type")
    participant_rows = None
    if result_participants is not None:
        if not isinstance(result_participants, list):
            _result_error("frozen_result_participants.type")
        participant_rows = result_participants
        if len(events) != len(participant_rows):
            _result_error("request.events.frozen_count")
        participant_by_user: dict[str, dict] = {}
        human_rows = 0
        ai_rows = 0
        for row in participant_rows:
            if (not isinstance(row, dict)
                    or set(row) != {"user_id", "party_id", "is_ai"}):
                _result_error("frozen_result_participants.invalid")
            participant_user = row.get("user_id")
            participant_party = row.get("party_id")
            is_ai = row.get("is_ai")
            if (not isinstance(participant_user, str)
                    or not 1 <= len(participant_user) <= 128
                    or participant_user in participant_by_user
                    or not isinstance(participant_party, str)
                    or type(is_ai) is not bool):
                _result_error("frozen_result_participants.invalid")
            if is_ai:
                ai_rows += 1
                if participant_user == request["user_id"] or participant_party != "":
                    _result_error("frozen_result_participants.invalid_ai")
            else:
                human_rows += 1
                if (custom_battle_no_party and participant_party != ""
                        or not custom_battle_no_party
                        and not 0 <= len(participant_party) <= 128):
                    _result_error("frozen_result_participants.invalid_human")
            participant_by_user[participant_user] = row
        if (roster_policy is not None
                and not _valid_public_cpu_fill_participants(
                    participant_rows, human_rows, ai_rows, roster_policy)):
            _result_error("frozen_result_participants.invalid_policy")
        requester = participant_by_user.get(request.get("user_id"))
        public_cpu_fill = _valid_public_cpu_fill_participants(
            participant_rows, human_rows, ai_rows, roster_policy)
        if (requester is None or requester.get("is_ai") is not False
                or not ((human_rows == 1 and ai_rows >= 1)
                        or (human_rows >= 2 and
                            (ai_rows == 0 or public_cpu_fill)))):
            _result_error("frozen_result_participants.invalid")
    elif custom_battle_no_party:
        # The empty-party exception is meaningful only against a complete,
        # immutable server roster. Never use it for an unfrozen final.
        _result_error("frozen_result_participants.required")

    rows: list[dict] = []
    event_users: set[str] = set()
    for index, event in enumerate(events):
        prefix = f"request.events[{index}]"
        if not isinstance(event, dict):
            _result_error(prefix + ".type")
        if set(event) != _FINAL_PLAYER_EVENT_FIELDS:
            _result_error(prefix + ".fields")
        event_user = event.get("user_id")
        party_id = event.get("party_id")
        if not isinstance(event_user, str):
            _result_error(prefix + ".user_id.type")
        if not 1 <= len(event_user) <= 128:
            _result_error(prefix + ".user_id.length")
        if event_user in event_users:
            _result_error(prefix + ".user_id.duplicate")
        if not isinstance(party_id, str):
            _result_error(prefix + ".party_id.type")
        participant = (participant_by_user.get(event_user)
                       if participant_rows is not None else None)
        if participant_rows is None:
            if not 1 <= len(party_id) <= 128:
                _result_error(prefix + ".party_id.length")
        elif participant is None:
            _result_error(prefix + ".user_id.not_in_frozen_roster")
        elif party_id != participant.get("party_id"):
            _result_error(prefix + ".party_id.frozen_mismatch")
        if event.get("type") != "results":
            _result_error(prefix + ".type.value")
        event_users.add(event_user)
        details = event.get("result_details")
        if not isinstance(details, dict):
            _result_error(prefix + ".result_details.type")
        if set(details) != _FINAL_RESULT_FIELDS:
            _result_error(prefix + ".result_details.fields")
        for key in ("battle_map_key", "result", "victory_mean", "scale",
                    "character_key", "commander_skin", "portrait_key",
                    "player_name"):
            value = details.get(key)
            if not isinstance(value, str):
                _result_error(prefix + f".result_details.{key}.type")
            if len(value) > 256:
                _result_error(prefix + f".result_details.{key}.length")
        if (details.get("is_premium") not in {"true", "false"}
                or type(details.get("was_afk")) is not bool
                or type(details.get("alliance_id")) is not int
                or not -1 <= details["alliance_id"] <= 20):
            _result_error(prefix + ".result_details.flags",
                          "invalid_battle_result_flag")
        duration = details.get("duration")
        if (type(duration) not in (int, float) or not math.isfinite(duration)
                or duration < 0 or duration > 86_400_000):
            _result_error(prefix + ".result_details.duration.type_or_range",
                          "invalid_battle_duration")
        if (not isinstance(details.get("badges"), list)
                or len(details["badges"]) > 256
                or not isinstance(details.get("unit_results"), list)
                or len(details["unit_results"]) > 64):
            _result_error(prefix + ".result_details.result_arrays.type_or_count",
                          "invalid_unit_results")
        rows.append({
            "user_id": event_user,
            "type": "results",
            "result_details": copy.deepcopy(details),
        })
    if participant_rows is not None and event_users != set(participant_by_user):
        _result_error("request.events.frozen_roster_mismatch")
    try:
        encoded = json.dumps(request, ensure_ascii=False, separators=(",", ":"),
                             allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise EconomyError("invalid_battle_result_json") from exc
    if len(encoded.encode("utf-8")) > 1_000_000:
        raise EconomyError("battle_result_too_large")
    return rows


def resolve_native_final_outcome(
    request: object,
    *,
    user_id: str,
    party_id: object,
    map_key: str,
    commander_key: str,
    result_participants: object = None,
    roster_policy: object = None,
    custom_battle_no_party: bool = False,
    display_name: str | None = None,
) -> tuple[str, bool]:
    """Resolve the statically proven native final-result schema.

    game.dll BCFFB0..BD12C8 serializes the credential-free fields validated by
    :func:`native_final_result_rows`. The local player's explicit native
    result token is mapped through a fixed allowlist. Winner names, scores,
    ticket counts and unit statistics are never used to guess an outcome.
    ``was_afk`` keeps a valid result record but marks it unverified so
    LocalEconomy awards zero.
    """
    native_final_result_rows(
        request, result_participants=result_participants,
        roster_policy=roster_policy,
        custom_battle_no_party=custom_battle_no_party,
    )
    if request.get("user_id") != user_id:
        raise EconomyError("battle_result_user_mismatch")
    matches = [event for event in request["events"]
               if event["user_id"] == user_id]
    if len(matches) != 1:
        raise EconomyError("battle_result_user_mismatch")
    event = matches[0]
    if event.get("party_id") != party_id:
        raise EconomyError("battle_result_party_mismatch")
    result = event["result_details"]
    outcome = _NATIVE_RESULT_OUTCOMES.get(result.get("result"))
    if outcome is None:
        raise EconomyError("invalid_battle_outcome")
    if result.get("battle_map_key") != map_key:
        raise EconomyError("battle_result_map_mismatch")
    if result.get("character_key") != commander_key:
        raise EconomyError("battle_result_commander_mismatch")
    expected_name = user_id
    if display_name is not None:
        from companion.player_name import validate_display_name
        try:
            expected_name = validate_display_name(display_name)
        except ValueError:
            raise EconomyError("invalid_allocation_display_name") from None
    if result.get("player_name") != expected_name:
        raise EconomyError("battle_result_player_mismatch")
    duration = result.get("duration")
    if (type(duration) not in (int, float) or not math.isfinite(duration)
            or duration < 0 or duration > 86_400_000
            or duration == 0):
        raise EconomyError("invalid_battle_duration")
    return outcome, not result["was_afk"]


class NativeEconomyService:
    """Compose LocalEconomy and NativeEconomyAdapter for loopback handlers."""

    def __init__(
        self,
        economy: LocalEconomy,
        catalog: dict,
        official: dict,
        native: dict,
        *,
        adapter: NativeEconomyAdapter | None = None,
    ) -> None:
        if not isinstance(economy, LocalEconomy):
            raise TypeError("economy must be LocalEconomy")
        if adapter is not None and (not isinstance(adapter, NativeEconomyAdapter)
                                    or adapter.economy is not economy):
            raise TypeError("adapter must belong to economy")
        self.economy = economy
        self.adapter = adapter or NativeEconomyAdapter(economy, catalog, official, native)
        # Activation is derived from the durable journal, never a constructor
        # flag. Reading an inactive profile is side-effect-free.
        self.specializations_enabled = bool(
            callable(getattr(economy, "specialization_enabled", None))
            and economy.specialization_enabled())
        self._lock = threading.RLock()
        # Commander-selection causal state.  ``_selection_watermarks`` maps a
        # watermark the client may still hold to the watermark produced by the
        # client's own accepted commander selection at that watermark: the
        # profile-GET acknowledgement ``{"profile":"already_in_sync"}`` carries
        # no ``saved``, so the client keeps sending the pre-selection value.
        # ``_selection_zero_read`` arms the one-shot ``timestamp:0`` gate.
        # Both are per-service, which is per user economy; a multi-user host
        # must therefore keep one service per account.
        self._selection_watermarks: dict[int, int] = {}
        self._selection_zero_read: dict | None = None
        # A full profile replacement can synchronously make the retired client
        # post ``{"timestamp": 0}``.  Most intentional replacement paths arm
        # ``_selection_zero_read`` themselves.  This second gate covers only a
        # full response from an otherwise-uncovered stale/rejected read, and is
        # usable only after the HTTP handler confirms that exact response
        # object was completely written.
        self._profile_graph_zero_followup: dict | None = None
        self._external_profile_refresh: dict | None = None
        self._specialization_profile_refresh: dict | None = None
        self._specialization_profile_refresh_ack: dict | None = None
        # Last receipt-correlated full graph built for the stock deferred
        # profile request.  This is deliberately distinct from the pending
        # gate: the companion must prove both that Arena consumed its request
        # byte and that the HTTP handler completed the corresponding response
        # write. It is not evidence that Scaleform applied the graph.
        self._external_profile_refresh_ack: dict | None = None
        self._selection_chain_suppress: dict | None = None
        self._bootstrap_selection_suppress: dict | None = None
        self.selection_zero_read_window_seconds = _SELECTION_ZERO_READ_WINDOW_SECONDS
        self.external_profile_refresh_window_seconds = (
            _EXTERNAL_PROFILE_REFRESH_WINDOW_SECONDS
        )
        self.selection_chain_suppress_seconds = _SELECTION_CHAIN_SUPPRESS_SECONDS
        self.bootstrap_selection_suppress_seconds = _BOOTSTRAP_SELECTION_SUPPRESS_SECONDS
        self._clock = time.monotonic
        profile = self.adapter.build_profile()["profile"]
        self.user_id = profile["user_id"]
        if not isinstance(self.user_id, str) or not self.user_id:
            raise EconomyError("invalid_profile_user")

    @classmethod
    def persistent(
        cls,
        path: Path,
        catalog: dict,
        official: dict,
        native: dict,
        *,
        zero_pve_rewards: bool = False,
        economy_cls: type[LocalEconomy] | None = None,
    ) -> "NativeEconomyService":
        """Create a service whose authoritative state survives restart."""
        if economy_cls is not None and (
                not isinstance(economy_cls, type)
                or not issubclass(economy_cls, LocalEconomy)):
            raise TypeError("economy_cls must be a LocalEconomy subclass")
        if economy_cls is None:
            # File-backed services understand the specialization journal, but
            # construction remains read-only and never enables it.
            try:
                from specialization_economy import SpecializationEconomy
            except ImportError as exc:
                raise EconomyError("specialization_backend_unavailable") from exc
            economy_cls = SpecializationEconomy
        selected_cls = economy_cls
        return cls(
            selected_cls(
                native, Path(path),
                zero_pve_rewards=zero_pve_rewards,
            ),
            catalog, official, native,
        )

    @staticmethod
    def _wire_full(profile: dict) -> dict:
        response = copy.deepcopy(profile)
        response["profile"]["properties"] = _wire_properties(
            response["profile"]["properties"]
        )
        return response

    @staticmethod
    def _wire_unchanged(profile: dict) -> dict:
        """Acknowledge an exact profile watermark without forcing a resync."""
        inner = profile["profile"]
        return {
            "result": "ok",
            "saved": inner["saved"],
            "events": [],
            "properties": [],
        }

    def _wire_tutorial_ack(
        self,
        profile: dict,
        *,
        active_commander_key: str | None = None,
    ) -> dict:
        """Acknowledge a tutorial heartbeat without clearing selection state.

        The tutorial response enters the ordinary event-result parser.  Even
        with no events that parser rebuilds the native derived profile maps,
        including clearing the current commander, before applying the
        response properties.  Return the complete trusted property set so the
        rebuild restores its selection.  A heartbeat at a proven current
        watermark may carry a newly clicked, owned commander before its
        selection POST; override only that one property with the commander's
        canonical item identity so this acknowledgement does not undo the
        pending local click.
        """
        inner = profile.get("profile") if isinstance(profile, dict) else None
        if not isinstance(inner, dict) or type(inner.get("saved")) is not int:
            raise EconomyError("invalid_profile_properties")
        properties = copy.deepcopy(inner.get("properties"))
        if not isinstance(properties, list):
            raise EconomyError("invalid_profile_properties")
        if active_commander_key is not None:
            commander = self.economy.commanders.get(active_commander_key)
            if not isinstance(commander, dict):
                raise EconomyError("invalid_active_commander")
            canonical = commander.get("item_id")
            if type(canonical) is not int or not 0 < canonical <= UINT64_MAX:
                raise EconomyError("invalid_active_commander")
            matches = 0
            for row in properties:
                if not isinstance(row, list) or len(row) != 4:
                    raise EconomyError("invalid_profile_properties")
                if row[0] == "active_commander":
                    row[3] = canonical
                    matches += 1
            if matches != 1:
                raise EconomyError("invalid_profile_properties")
        return {
            "result": "ok",
            "saved": inner["saved"],
            "events": [],
            "properties": _wire_properties(properties),
        }

    @staticmethod
    def _wire_profile_already_in_sync() -> dict:
        """Use the profile-GET message's native no-change sentinel.

        ``F2P_PROFILE_GET_MESSAGE::set`` does not consume the event-style
        ``result/saved/events/properties`` acknowledgement.  Its separate
        no-change branch requires ``profile`` to be the exact string below.
        """
        return {"profile": "already_in_sync"}

    @staticmethod
    def _wire_resync(profile: dict) -> dict:
        """Silently replace the client's profile with the signed full graph.

        ``F2P_PROFILE_GET_MESSAGE::set`` distinguishes its no-change sentinel
        from a full replacement by the type of ``profile``: an object with a
        ``user_id`` enters the graph-apply path, irrespective of ``result``.
        ``result: ok_resync`` and the duplicate top-level fields are retained
        because this shape is also accepted by the event-response path.
        BD8540 accepts an equal or newer watermark and rebuilds every derived
        profile view from the embedded graph.
        """
        inner = copy.deepcopy(profile["profile"])
        inner["properties"] = _wire_properties(inner["properties"])
        return {
            "result": "ok_resync",
            "profile": inner,
            "saved": inner["saved"],
            "events": [],
            "properties": copy.deepcopy(inner["properties"]),
        }

    # ---- commander-selection causal gate ----------------------------------

    def _current_wire_saved(self) -> int:
        return self.adapter.wire_saved(self.economy.snapshot()["saved"])

    def _translate_watermark(self, timestamp: int, current: int) -> int:
        """Advance a watermark across this client's own commander selections.

        A commander selection is acknowledged on the profile-GET message with
        the native ``already_in_sync`` sentinel, which carries no ``saved``.
        Until the client receives a full graph it therefore keeps sending the
        watermark it held before its own selection.  Each link recorded by
        ``_record_selection_watermark`` proves that the only mutation between
        the two values is that client's accepted selection, so following the
        links yields the watermark the client would hold had the sentinel
        carried ``saved``.  Any other mutation produces a value that is not a
        link and stops the walk, keeping every other stale read fail-closed.
        """
        if type(timestamp) is not int or timestamp <= 0 or timestamp >= current:
            return timestamp
        for _ in range(_MAX_SELECTION_WATERMARKS):
            produced = self._selection_watermarks.get(timestamp)
            if produced is None or produced <= timestamp or produced > current:
                break
            timestamp = produced
            if timestamp == current:
                break
        return timestamp

    def _record_selection_watermark(self, before: int, after: int) -> None:
        if type(before) is not int or type(after) is not int or after <= before:
            return
        self._selection_watermarks.pop(before, None)
        self._selection_watermarks[before] = after
        while len(self._selection_watermarks) > _MAX_SELECTION_WATERMARKS:
            del self._selection_watermarks[next(iter(self._selection_watermarks))]

    def _disarm_selection_zero_read(self) -> None:
        self._selection_zero_read = None

    def _arm_selection_zero_read(
        self, *, resync: bool = False,
        preserve_external_selection: bool = False,
    ) -> None:
        # A specialized causal gate supersedes the generic post-full gate;
        # keeping both could suppress two zero reads from one replacement.
        self._disarm_profile_graph_zero_followup()
        self._selection_zero_read = {
            "saved": self._current_wire_saved(),
            "armed_at": self._clock(),
            "resync": resync,
            "preserve_external_selection": preserve_external_selection,
        }

    def _consume_selection_zero_read(self) -> dict | None:
        """Return the valid one-shot read gate, or ``None`` when disarmed."""
        gate = self._selection_zero_read
        self._selection_zero_read = None
        if gate is None:
            return None
        if self._clock() - gate["armed_at"] > self.selection_zero_read_window_seconds:
            return None
        if self._current_wire_saved() != gate["saved"]:
            return None
        return gate

    def _disarm_profile_graph_zero_followup(self) -> None:
        self._profile_graph_zero_followup = None

    def _arm_profile_graph_zero_followup(self, response: dict) -> None:
        """Await HTTP completion for one otherwise-uncovered full graph."""
        self._disarm_profile_graph_zero_followup()
        if self._selection_zero_read is not None:
            return
        embedded = response.get("profile") if isinstance(response, dict) else None
        saved = embedded.get("saved") if isinstance(embedded, dict) else None
        if type(saved) is not int or saved != self._current_wire_saved():
            return
        self._profile_graph_zero_followup = {
            "saved": saved,
            "armed_at": self._clock(),
            "response": response,
            "http_response_written": False,
        }

    def confirm_profile_graph_http(self, response: object) -> bool:
        """Confirm the exact full response object after its HTTP body write."""
        with self._lock, self.economy._lock:  # type: ignore[attr-defined]
            gate = self._profile_graph_zero_followup
            if (not isinstance(gate, dict)
                    or set(gate) != {
                        "saved", "armed_at", "response",
                        "http_response_written",
                    }
                    or gate.get("response") is not response
                    or gate.get("http_response_written") is not False):
                return False
            embedded = response.get("profile") if isinstance(response, dict) else None
            if (not isinstance(embedded, dict)
                    or embedded.get("saved") != gate.get("saved")):
                return False
            # Release the potentially large graph as soon as the exact write
            # completes.  The saved watermark and bounded age are sufficient
            # for the following zero-read check.
            gate["response"] = None
            gate["http_response_written"] = True
            return True

    def _consume_profile_graph_zero_followup(self) -> bool:
        """Consume one HTTP-proven, same-profile zero-read follow-up."""
        gate = self._profile_graph_zero_followup
        self._profile_graph_zero_followup = None
        if (not isinstance(gate, dict)
                or set(gate) != {
                    "saved", "armed_at", "response", "http_response_written",
                }
                or type(gate.get("saved")) is not int
                or type(gate.get("armed_at")) not in {int, float}
                or gate.get("response") is not None
                or gate.get("http_response_written") is not True):
            return False
        age = self._clock() - gate["armed_at"]
        return (
            0 <= age <= self.selection_zero_read_window_seconds
            and self._current_wire_saved() == gate["saved"]
        )

    def _disarm_external_profile_refresh(self) -> None:
        self._external_profile_refresh = None

    def arm_external_profile_refresh(
        self,
        operation_id: str,
        *,
        previous_saved: int,
        current_saved: int,
        commander_key: str,
    ) -> None:
        """Correlate one companion loadout write with its native refresh.

        This is deliberately not a generic "make the next profile read fresh"
        switch.  The durable operation must be the exact ``equip_units`` write
        that produced the current watermark and current active commander's
        three-unit loadout.  The stock deferred ``/profile`` request must
        present that same commander at the immediately preceding watermark.
        That exact request consumes the authorization and receives the
        current full graph once; a duplicate ``timestamp:0`` read caused by
        applying the graph is suppressed separately.
        """
        with self._lock, self.economy._lock:  # type: ignore[attr-defined]
            previous_gate = self._external_profile_refresh
            # A failed/retried arm must never leave an older authorization
            # live.  The external write also invalidates any earlier
            # commander-selection zero-read gate.
            self._disarm_external_profile_refresh()
            self._external_profile_refresh_ack = None
            self._disarm_selection_zero_read()
            self._disarm_profile_graph_zero_followup()
            if (not isinstance(operation_id, str) or not operation_id
                    or type(previous_saved) is not int
                    or type(current_saved) is not int
                    or not 0 < previous_saved < current_saved <= UINT64_MAX
                    or not isinstance(commander_key, str)
                    or not commander_key):
                raise EconomyError("invalid_external_profile_refresh")

            snapshot = self.economy.snapshot()
            if (snapshot.get("saved") != current_saved
                    or snapshot.get("active_commander") != commander_key):
                raise EconomyError("external_profile_refresh_mismatch")
            commander_state = snapshot.get("commanders", {}).get(commander_key)
            operation = snapshot.get("operations", {}).get(operation_id)
            receipt = (operation.get("receipt")
                       if isinstance(operation, dict) else None)
            units = (commander_state.get("equipped_units")
                     if isinstance(commander_state, dict) else None)
            expected_receipt_fields = {
                "operation_id", "kind", "saved", "commander", "units",
                "battle_tier", "unit_change_cleanup",
            }
            if (not isinstance(units, list) or len(units) != 3
                    or not isinstance(receipt, dict)
                    or set(receipt) != expected_receipt_fields
                    or receipt.get("operation_id") != operation_id
                    or receipt.get("kind") != "equip_units"
                    or receipt.get("saved") != current_saved
                    or receipt.get("commander") != commander_key
                    or receipt.get("units") != units
                    or operation.get("request_hash") != _canonical_hash({
                        "kind": "equip_units",
                        "request": {
                            "commander": commander_key,
                            "units": units,
                        },
                    })):
                raise EconomyError("external_profile_refresh_mismatch")

            previous_wire = self.adapter.wire_saved(previous_saved)
            current_wire = self.adapter.wire_saved(current_saved)
            if current_wire <= previous_wire:
                # Below the native saved floor there is no distinct stale
                # watermark to correlate, so fail closed rather than turning
                # a later unrelated selection into a refresh trigger.
                raise EconomyError("external_profile_refresh_mismatch")
            accepted_wire_saved = [previous_wire]
            chain_previous_saved = previous_saved
            now = self._clock()
            if (isinstance(previous_gate, dict)
                    and 0 <= now - previous_gate.get("armed_at", -1)
                    <= self.external_profile_refresh_window_seconds
                    and previous_gate.get("commander") == commander_key
                    and previous_gate.get("current_saved") == previous_saved
                    and previous_gate.get("current_wire_saved")
                    == previous_wire):
                # Two real drags can complete before the stock frame loop
                # consumes the already-raised refresh flag.  Preserve every
                # causal watermark from that unconsumed chain so the single
                # coalesced native request may install the latest durable
                # three-slot profile, whether the client still holds the
                # first timestamp or a compact tutorial reply advanced it to
                # an intermediate one.
                inherited = previous_gate.get("accepted_wire_saved")
                if (isinstance(inherited, list)
                        and inherited
                        and all(type(value) is int and value > 0
                                for value in inherited)):
                    accepted_wire_saved = list(inherited)
                else:
                    accepted_wire_saved = [
                        previous_gate["previous_wire_saved"]
                    ]
                accepted_wire_saved.append(previous_wire)
                accepted_wire_saved = list(dict.fromkeys(
                    accepted_wire_saved
                ))
                chain_previous_saved = previous_gate["previous_saved"]
                inherited_cleanup_emissions = previous_gate.get(
                    "cleanup_delta_emissions"
                )
                if (not isinstance(inherited_cleanup_emissions, list)
                        or any(
                            not isinstance(value, str) or len(value) != 64
                            for value in inherited_cleanup_emissions
                        )):
                    inherited_cleanup_emissions = []
            else:
                inherited_cleanup_emissions = []
            self._external_profile_refresh = {
                "operation_id": operation_id,
                "previous_saved": chain_previous_saved,
                "current_saved": current_saved,
                "previous_wire_saved": accepted_wire_saved[0],
                "accepted_wire_saved": accepted_wire_saved,
                "current_wire_saved": current_wire,
                "commander": commander_key,
                "armed_at": now,
                "tutorial_acknowledged": False,
                "cleanup_acknowledged": False,
                "cleanup_delta_emissions": list(
                    inherited_cleanup_emissions
                ),
            }

    def _external_profile_refresh_is_current(self, gate: object) -> bool:
        """Revalidate one pending refresh against its durable operation.

        The gate is only an in-memory hint.  Before exposing or consuming it,
        prove again that it names the latest ``equip_units`` receipt and the
        exact current commander/loadout.  This lets a restarted bridge ask
        whether catch-up is required without turning an arbitrary current
        profile read into refresh authority.
        """
        expected_gate_fields = {
            "operation_id", "previous_saved", "current_saved",
            "previous_wire_saved", "accepted_wire_saved",
            "current_wire_saved", "commander", "armed_at",
            "tutorial_acknowledged", "cleanup_acknowledged",
            "cleanup_delta_emissions",
        }
        if not isinstance(gate, dict) or set(gate) != expected_gate_fields:
            return False
        operation_id = gate.get("operation_id")
        previous_saved = gate.get("previous_saved")
        current_saved = gate.get("current_saved")
        previous_wire = gate.get("previous_wire_saved")
        accepted_wire = gate.get("accepted_wire_saved")
        current_wire = gate.get("current_wire_saved")
        commander = gate.get("commander")
        armed_at = gate.get("armed_at")
        cleanup_emissions = gate.get("cleanup_delta_emissions")
        if (not isinstance(operation_id, str) or not operation_id
                or type(previous_saved) is not int
                or type(current_saved) is not int
                or not 0 < previous_saved < current_saved <= UINT64_MAX
                or type(previous_wire) is not int
                or type(current_wire) is not int
                or not isinstance(accepted_wire, list) or not accepted_wire
                or any(type(value) is not int for value in accepted_wire)
                or len(set(accepted_wire)) != len(accepted_wire)
                or accepted_wire[0] != previous_wire
                or any(not 0 < value < current_wire for value in accepted_wire)
                or not isinstance(commander, str) or not commander
                or type(gate.get("tutorial_acknowledged")) is not bool
                or type(gate.get("cleanup_acknowledged")) is not bool
                or not isinstance(cleanup_emissions, list)
                or len(cleanup_emissions)
                > self.adapter.max_unit_change_cleanup_emissions
                or any(
                    not isinstance(value, str)
                    or len(value) != 64
                    or any(character not in "0123456789abcdef"
                           for character in value)
                    for value in cleanup_emissions
                )
                or len(set(cleanup_emissions)) != len(cleanup_emissions)
                or type(armed_at) not in {int, float}):
            return False
        age = self._clock() - armed_at
        if not 0 <= age <= self.external_profile_refresh_window_seconds:
            return False

        snapshot = self.economy.snapshot()
        if (snapshot.get("saved") != current_saved
                or snapshot.get("active_commander") != commander
                or self.adapter.wire_saved(previous_saved) != previous_wire
                or self.adapter.wire_saved(current_saved) != current_wire):
            return False
        commanders = snapshot.get("commanders")
        operations = snapshot.get("operations")
        if not isinstance(commanders, dict) or not isinstance(operations, dict):
            return False
        commander_state = commanders.get(commander)
        units = (commander_state.get("equipped_units")
                 if isinstance(commander_state, dict) else None)
        operation = operations.get(operation_id)
        receipt = (operation.get("receipt")
                   if isinstance(operation, dict) else None)
        expected_receipt_fields = {
            "operation_id", "kind", "saved", "commander", "units",
            "battle_tier", "unit_change_cleanup",
        }
        return (
            isinstance(units, list)
            and len(units) == 3
            and isinstance(receipt, dict)
            and set(receipt) == expected_receipt_fields
            and receipt.get("operation_id") == operation_id
            and receipt.get("kind") == "equip_units"
            and receipt.get("saved") == current_saved
            and receipt.get("commander") == commander
            and receipt.get("units") == units
            and operation.get("request_hash") == _canonical_hash({
                "kind": "equip_units",
                "request": {"commander": commander, "units": units},
            })
        )

    def pending_external_profile_refresh(self) -> bool:
        """Return true only for a fresh, receipt-proven catch-up operation."""
        with self._lock, self.economy._lock:  # type: ignore[attr-defined]
            gate = self._external_profile_refresh
            if self._external_profile_refresh_is_current(gate):
                return True
            # Expired, malformed, or no-longer-current authority must not be
            # advertised to a later bridge attachment.
            self._disarm_external_profile_refresh()
            return False

    def external_profile_refresh_status(self) -> dict:
        """Expose the pending operation and last server resync separately.

        The public acknowledgement proves that this service built the
        correlated full-profile response and its HTTP handler completed the
        body write. The companion combines it with the game's request-byte
        consumption observation; visual application remains a separate live
        acceptance check.
        """
        with self._lock, self.economy._lock:  # type: ignore[attr-defined]
            gate = self._external_profile_refresh
            pending = self._external_profile_refresh_is_current(gate)
            if not pending:
                self._disarm_external_profile_refresh()
                gate = None

            ack = self._external_profile_refresh_ack
            if isinstance(ack, dict):
                valid_ack = (
                    set(ack) == {
                            "operation_id", "saved", "status",
                            "acknowledged_at", "http_response_written",
                        }
                    and isinstance(ack.get("operation_id"), str)
                    and type(ack.get("saved")) is int
                    and ack.get("status") == "external_refresh_resynced"
                    and type(ack.get("acknowledged_at")) in {int, float}
                    and type(ack.get("http_response_written")) is bool
                )
                if valid_ack:
                    age = self._clock() - ack["acknowledged_at"]
                    valid_ack = (
                        0 <= age
                        <= self.external_profile_refresh_window_seconds
                    )
                if not valid_ack:
                    ack = None
                    self._external_profile_refresh_ack = None
            else:
                ack = None
            return {
                "pending": pending,
                "operation_id": (
                    gate["operation_id"] if isinstance(gate, dict) else None
                ),
                "saved": (
                    gate["current_saved"] if isinstance(gate, dict) else None
                ),
                "ack": (None if ack is None
                        or ack["http_response_written"] is not True else {
                    "operation_id": ack["operation_id"],
                    "saved": ack["saved"],
                    "status": ack["status"],
                }),
            }

    def confirm_external_profile_refresh_http(
        self, expected_wire_saved: int,
    ) -> bool:
        """Mark the exact correlated response after the HTTP write returns."""
        with self._lock, self.economy._lock:  # type: ignore[attr-defined]
            ack = self._external_profile_refresh_ack
            if (not isinstance(ack, dict)
                    or type(expected_wire_saved) is not int
                    or type(ack.get("saved")) is not int
                    or self.adapter.wire_saved(ack["saved"])
                    != expected_wire_saved
                    or ack.get("status") != "external_refresh_resynced"
                    or ack.get("http_response_written") is not False):
                return False
            ack["http_response_written"] = True
            return True

    def _consume_external_profile_refresh_selection(
        self, raw: bytes,
    ) -> tuple[dict, dict] | None:
        """Consume the exact stock selection and return its built profile.

        Validation already needs the authoritative graph to resolve the
        commander property.  Returning that same immutable-by-convention
        value avoids rebuilding the entire graph a second time immediately
        before serializing the correlated response.
        """
        gate = self._external_profile_refresh
        self._external_profile_refresh = None
        if gate is None:
            return None
        if not self._external_profile_refresh_is_current(gate):
            return None
        profile = self.adapter.build_profile()
        try:
            commander_key, _operation, timestamp = self._selection_request(
                raw, profile,
            )
        except EconomyError:
            return None
        previous_matches = self._external_refresh_previous_matches(
            gate, timestamp,
        )
        current_matches = False
        if (gate["tutorial_acknowledged"] is True
                or gate["cleanup_acknowledged"] is True):
            # A validated tutorial or exact old-unit cleanup reply carries the
            # current saved watermark. The delayed selection may use that
            # acknowledged value, or retain a previous selection-chain value.
            # A current timestamp without either causal reply grants nothing.
            current_matches = timestamp == gate["current_wire_saved"]
        if (commander_key == gate["commander"]
                and (previous_matches or current_matches)):
            return profile, gate
        return None

    def _external_profile_refresh_cached_read(
        self, raw: bytes,
    ) -> tuple[dict, dict] | None:
        """Answer a cleanup-proven cache read without spending UI authority.

        BCE500 serializes a separate cached cursor, not the selection request
        created by the deferred refresh. Live observation proves its full
        reply does not invoke BD8540 and cannot confirm hangar application.
        Keep the bounded receipt gate for the later queue-idle selection.
        Repeated cache reads are read-only and revalidate that same exact
        current loadout and cleanup; they never acknowledge the refresh job.
        """
        gate = self._external_profile_refresh
        if gate is None:
            return None
        if not self._external_profile_refresh_is_current(gate):
            self._external_profile_refresh = None
            return None
        if gate.get("cleanup_acknowledged") is not True:
            return None
        try:
            body = _strict_json(raw)
            if (not isinstance(body, dict)
                    or "request" not in body
                    or not set(body) <= {"request", "headers"}
                    or ("headers" in body and not isinstance(body["headers"], dict))):
                return None
            request = body.get("request")
            if not isinstance(request, dict) or set(request) != {"timestamp"}:
                return None
            timestamp = _uint64(
                request.get("timestamp"), "invalid_profile_timestamp",
            )
        except EconomyError:
            return None
        if not 0 < timestamp <= gate["current_wire_saved"]:
            return None
        profile = self.adapter.build_profile()
        embedded = profile.get("profile") if isinstance(profile, dict) else None
        if (not isinstance(embedded, dict)
                or embedded.get("saved") != gate["current_wire_saved"]):
            self._external_profile_refresh = None
            return None
        return profile, gate

    def _external_refresh_previous_matches(
        self, gate: dict, timestamp: int,
    ) -> bool:
        """Match one timestamp against a verified, possibly coalesced chain."""
        accepted = gate.get("accepted_wire_saved")
        if not isinstance(accepted, list):
            accepted = [gate.get("previous_wire_saved")]
        return any(
            type(previous_wire) is int
            and self._translate_watermark(timestamp, previous_wire)
            == previous_wire
            for previous_wire in accepted
        )

    def _normalize_external_unit_cleanup_request(
        self, request: object,
    ) -> object:
        """Recover an exact old-unit cleanup across selection-only saves.

        Commander selection replies use the profile-message sentinel and do
        not advance the retired client's local watermark.  A later unit drag
        can therefore be followed by an otherwise exact cleanup carrying the
        watermark from before that selection.  Translate only across this
        service instance's recorded selection chain, and still require the
        existing receipt/before-image validator to match every event.

        The returned copy is used only while the exact external-refresh gate
        is current.  An arbitrary old timestamp, an intervening mutation, or
        a malformed/unrelated cleanup cannot create a translated candidate.
        """
        if self.adapter.is_unit_change_cleanup_request(request):
            return request
        gate = self._external_profile_refresh
        if (not self._external_profile_refresh_is_current(gate)
                or not isinstance(request, dict)):
            return request
        raw_timestamp = request.get("profile_timestamp")
        if type(raw_timestamp) is not int:
            return request
        try:
            raw_wire = _uint64(
                raw_timestamp, "invalid_profile_timestamp",
            )
        except EconomyError:
            return request
        accepted = gate.get("accepted_wire_saved")
        if not isinstance(accepted, list):
            return request
        for candidate in accepted:
            if (type(candidate) is not int
                    or self._translate_watermark(raw_wire, candidate)
                    != candidate):
                continue
            normalized = copy.deepcopy(request)
            normalized["profile_timestamp"] = candidate
            if self.adapter.is_unit_change_cleanup_request(normalized):
                return normalized
        return request

    def _arm_selection_chain_suppress(self, previous_commander: str) -> None:
        snapshot = self.economy.snapshot()
        existing = self._selection_chain_suppress
        fallback = previous_commander
        if (existing is not None
                and self._clock() - existing["armed_at"]
                <= self.selection_chain_suppress_seconds):
            # Keep the commander from which this rebuild chain originally
            # started.  A physical click may legitimately move through another
            # faction before the native fill finishes, but the observed bug
            # always posts the chain origin again (normally Xerxes).
            fallback = existing["fallback"]
        self._selection_chain_suppress = {
            "commander": snapshot["active_commander"],
            "fallback": fallback,
            "armed_at": self._clock(),
        }

    def _selection_chain_is_suppressed(self, requested_commander: str) -> bool:
        gate = self._selection_chain_suppress
        if gate is None or self.selection_chain_suppress_seconds <= 0:
            return False
        if self._clock() - gate["armed_at"] > self.selection_chain_suppress_seconds:
            self._selection_chain_suppress = None
            return False
        # Suppress only the automatic return to the chain origin.  Other
        # commander/faction clicks remain usable during the window.
        return requested_commander == gate["fallback"]

    def _arm_bootstrap_selection_suppress(self) -> None:
        self._bootstrap_selection_suppress = {
            "saved": self._current_wire_saved(),
            "armed_at": self._clock(),
        }

    def _bootstrap_selection_is_suppressed(self, raw: bytes) -> bool:
        gate = self._bootstrap_selection_suppress
        if gate is None or self.bootstrap_selection_suppress_seconds <= 0:
            return False
        if (self._clock() - gate["armed_at"]
                > self.bootstrap_selection_suppress_seconds
                or self._current_wire_saved() != gate["saved"]):
            self._bootstrap_selection_suppress = None
            return False
        profile = self.adapter.build_profile()
        try:
            commander_key, _operation, _timestamp = self._selection_request(
                raw, profile,
            )
        except EconomyError:
            return False
        return commander_key != self.economy.snapshot()["active_commander"]

    @staticmethod
    def _profile_message_shape(raw: bytes) -> str | None:
        """Classify a ``/profile`` POST body without trusting its values."""
        try:
            body = _strict_json(raw)
        except EconomyError:
            return None
        request = body.get("request")
        if not isinstance(request, dict):
            return None
        fields = set(request)
        if fields == {"timestamp"}:
            value = request["timestamp"]
            if type(value) is int and value == 0:
                return "zero_read"
            return "read"
        if fields == {"profile_timestamp"}:
            return "bootstrap"
        if (_SELECTION_FIELDS <= fields
                and fields <= _SELECTION_FIELDS | _OPTIONAL_SELECTION_FIELDS):
            return "selection"
        return None

    def _has_settlement_chain_since(self, timestamp: int, profile: dict) -> bool:
        """Validate an unbroken settlement chain from a stale watermark.

        A stale watermark is not, by itself, permission to acknowledge every
        intervening mutation.  Each battle begin stores the profile watermark
        it froze without advancing it, which supplies a durable link from the
        client's prior watermark to the exactly-once settlement receipt.
        Once that chain is proven, ``ok_resync`` can safely carry the complete
        current graph, including Tier and ability rows created by a level-up.
        """
        inner = profile.get("profile") if isinstance(profile, dict) else None
        if not isinstance(inner, dict):
            return False
        current = inner.get("saved")
        if type(timestamp) is not int or type(current) is not int or timestamp >= current:
            return False
        snapshot = self.economy.snapshot()
        operations = snapshot.get("operations")
        battles = snapshot.get("battles")
        if not isinstance(operations, dict) or not isinstance(battles, dict):
            return False

        receipts: list[dict] = []
        for entry in operations.values():
            receipt = entry.get("receipt") if isinstance(entry, dict) else None
            if not isinstance(receipt, dict):
                return False
            try:
                saved = self.adapter.wire_saved(receipt.get("saved"))
            except EconomyError:
                return False
            if timestamp < saved <= current:
                receipts.append(receipt)

        public_kinds = {
            "begin_pve", "settle_pve", "begin_pvp", "settle_pvp",
        }
        settlements = [
            row for row in receipts
            if row.get("kind") in {"settle_pve", "settle_pvp"}
        ]
        if not settlements:
            return False
        try:
            settlements.sort(key=lambda row: self.adapter.wire_saved(row.get("saved")))
            settlement_saves = {
                self.adapter.wire_saved(row["saved"]) for row in settlements
            }
        except EconomyError:
            return False

        # A profile-visible non-settlement operation has a unique advanced
        # saved value.  Server-only begin records and no-op selections can
        # legitimately share the preceding/settlement watermark.
        for receipt in receipts:
            kind = receipt.get("kind")
            try:
                saved = self.adapter.wire_saved(receipt["saved"])
            except EconomyError:
                return False
            if kind not in public_kinds | {"select_commander"}:
                return False
            if kind == "select_commander" and saved not in settlement_saves:
                return False

        cursor = timestamp
        for receipt in settlements:
            try:
                saved = self.adapter.wire_saved(receipt["saved"])
            except EconomyError:
                return False
            if saved <= cursor:
                return False
            match_id = receipt.get("match_id")
            battle = battles.get(match_id) if isinstance(match_id, str) else None
            reward_policy = (
                battle.get("reward_policy") if isinstance(battle, dict) else None
            )
            if (not isinstance(battle, dict)
                    or reward_policy not in {"pve", "pvp"}
                    or receipt.get("kind") != f"settle_{reward_policy}"
                    or battle.get("status") != "settled"
                    or battle.get("settlement_operation") != receipt.get("operation_id")
                    or receipt.get("commander") != battle.get("commander")
                    or receipt.get("outcome") != battle.get("outcome")
                    or receipt.get("verified") != battle.get("verified")
                    or receipt.get("battle_tier") != battle.get("battle_tier")
                    or receipt.get("roster_hash") != battle.get("roster_hash")):
                return False
            begin_entry = operations.get(battle.get("begin_operation"))
            begin = (begin_entry.get("receipt")
                     if isinstance(begin_entry, dict) else None)
            if (not isinstance(begin, dict)
                    or begin.get("kind") != f"begin_{reward_policy}"
                    or begin.get("match_id") != match_id):
                return False
            try:
                begin_saved = self.adapter.wire_saved(begin.get("saved"))
            except EconomyError:
                return False
            if begin_saved != cursor:
                return False
            try:
                quote = self.economy.reward_quote(
                    battle["battle_tier"], battle["outcome"], battle["verified"],
                    reward_policy=battle.get("reward_policy", "pve"),
                )
            except EconomyError:
                return False
            zero_rewards = begin.get("zero_rewards", False)
            if type(zero_rewards) is not bool:
                return False
            if zero_rewards:
                # This is a local, server-owned diagnostic override frozen in
                # the begin receipt.  Keep the legacy quote for every receipt
                # without the marker, including historical retries.
                if (battle.get("reward_policy", "pve") != "pve"
                        or begin.get("kind") != "begin_pve"):
                    return False
                quote = {
                    **quote,
                    **{key: 0 for key in (
                        "unit_xp_cents", "commander_xp_cents",
                        "free_xp_cents", "silver_cents")},
                }
            # Rebuild the same local-only frozen quote used by settlement.
            # A receipt carrying a remote authority remains fail-closed here;
            # its Worker-owned amounts are never inferred from local policy.
            if "reward_authority" not in receipt:
                adjust = getattr(self.economy, "_adjust_local_reward_quote", None)
                if not callable(adjust):
                    return False
                try:
                    quote = adjust(
                        snapshot, battle, begin, receipt["outcome"],
                        receipt["verified"], reward_policy, quote, None,
                    )
                except EconomyError:
                    return False
            daily_awards = receipt.get("daily_quests")
            if (not isinstance(daily_awards, list)
                    or any(not isinstance(row, dict)
                           or set(row) != {"key", "gold_cents"}
                           or not isinstance(row["key"], str)
                           or type(row["gold_cents"]) is not int
                           or row["gold_cents"] < 0
                           for row in daily_awards)):
                return False
            expected_rewards = {
                **quote,
                "gold_cents": sum(row["gold_cents"] for row in daily_awards),
                "unit_xp_by_unit": {
                    unit_key: quote["unit_xp_cents"]
                    for unit_key in sorted(set(battle.get("units", [])))
                },
            }
            if receipt.get("rewards") != expected_rewards:
                return False
            cursor = saved
        return cursor == current

    def _owned_commander_ids(self, profile: dict) -> dict[int, str]:
        snapshot = self.economy.snapshot()
        by_item = {
            self.economy.commanders[key]["item_id"]: key
            for key in snapshot["commanders"]
        }
        identities: dict[int, str] = {}
        for parent, item, instance, quantity in profile["profile"]["profile_records"]:
            commander_key = by_item.get(item)
            if parent != 0 or commander_key is None or quantity <= 0:
                continue
            for identity in (item, instance):
                existing = identities.get(identity)
                if existing is not None and existing != commander_key:
                    raise EconomyError("ambiguous_commander_identity")
                identities[identity] = commander_key
        if set(identities.values()) != set(snapshot["commanders"]):
            raise EconomyError("owned_commander_missing_from_profile")
        return identities

    def respond_daily_missions(self) -> dict:
        """Return a schema-compatible empty native Daily state.

        Daily quest rows are retired from the game UI.  Keep the wrapper,
        parser configuration, and next-UTC reset timestamp from the legacy
        read envelope, but publish no active or special rows, so no quest
        labels, rewards, or notification-like mission entries can be
        rendered.  Reading that envelope does not advance progress or mutate
        legacy ``daily`` state.
        """
        daily = self.economy.daily_missions()
        return {
            "new_state": {
                "mission_data": {
                    "rerolls_used": 0,
                    "num_queued": 0,
                },
                "mission_extras": {
                    "conf": {
                        "max_queued": 3,
                        "max_f2p": 3,
                        "max_premium": 3,
                        "max_new_per_day": 3,
                        "max_free_mission_rerolls": 0,
                        "daily_allowance_reset": daily["reset_at_ms"] // 1000,
                    },
                    "global_data": [],
                },
                "active": [],
                "special": [],
            },
        }

    def _selection_request(self, raw: bytes, profile: dict) -> tuple[str, int, int]:
        body = _strict_json(raw)
        request = body.get("request")
        if (not isinstance(request, dict)
                or not _SELECTION_FIELDS <= set(request)
                or not set(request) <= _SELECTION_FIELDS | _OPTIONAL_SELECTION_FIELDS):
            raise EconomyError("invalid_profile_selection")
        timestamp = _uint64(request.get("profile_timestamp"), "invalid_profile_timestamp")
        if timestamp > profile["profile"]["saved"]:
            raise EconomyError("future_profile_timestamp")
        active = _uint64(request.get("active_commander"), "invalid_active_commander",
                         positive=True)
        commander_key = self._owned_commander_ids(profile).get(active)
        if commander_key is None:
            raise EconomyError("commander_not_owned")
        if "active_title" in request:
            title = _uint64(request["active_title"], "invalid_active_title", positive=True)
            expected = {row[3] for row in profile["profile"]["properties"]
                        if row[0] == "active_title"}
            if title not in expected:
                raise EconomyError("active_title_mismatch")
        operation = "profile-select:" + _canonical_hash({
            "commander": commander_key,
            "profile_timestamp": timestamp,
        })
        return commander_key, operation, timestamp

    def respond(
        self,
        raw: bytes = b"",
        accept_selection: bool = False,
        *,
        accept_current_selection_noop: bool = False,
        accept_zero_profile_read_noop: bool = False,
    ) -> tuple[dict, str]:
        """Return a full profile, synchronized no-change reply, or selection delta."""
        with self._lock, self.economy._lock:  # type: ignore[attr-defined]
            profile = self.adapter.build_profile()
            if not accept_selection or not raw:
                return self._wire_full(profile), "unchanged"
            try:
                body = _strict_json(raw)
                request = body.get("request")
                fields = set(request) if isinstance(request, dict) else set()
                if fields in _PROFILE_READ_FIELDS:
                    field = next(iter(fields))
                    timestamp = _uint64(
                        request[field], "invalid_profile_timestamp",
                    )
                    current = profile["profile"]["saved"]
                    if timestamp > current:
                        return self._wire_full(profile), "rejected"
                    timestamp = self._translate_watermark(timestamp, current)
                    # The native profile manager uses zero as its explicit
                    # bootstrap/full-read sentinel.  A private battle changes
                    # no persistent state; once the HTTP layer has waited for
                    # the profile callback target, acknowledge that postbattle
                    # bootstrap without rebuilding the equal graph.  Outside
                    # that narrowly enabled path, retain the normal silent full
                    # replacement used by initial startup and public rewards.
                    if timestamp == 0:
                        if accept_zero_profile_read_noop:
                            return self._wire_unchanged(profile), "unchanged"
                        return self._wire_resync(profile), "resynced"
                    if timestamp == current:
                        return self._wire_unchanged(profile), "unchanged"
                    if self._has_settlement_chain_since(timestamp, profile):
                        return self._wire_resync(profile), "resynced"
                    return self._wire_full(profile), "stale"
            except EconomyError:
                return self._wire_full(profile), "rejected"
            try:
                commander_key, operation, timestamp = self._selection_request(raw, profile)
            except EconomyError:
                return self._wire_full(profile), "rejected"
            snapshot = self.economy.snapshot()
            current = profile["profile"]["saved"]
            timestamp = self._translate_watermark(timestamp, current)
            if (accept_current_selection_noop and timestamp == current
                    and commander_key == snapshot["active_commander"]):
                # A private battle changes no persistent profile state.  Its
                # post-battle read is selection-shaped and echoes the already
                # active commander/title at the exact current watermark.  The
                # HTTP layer has already waited for the native message target,
                # so an ordinary no-change acknowledgement is sufficient and
                # avoids the UI warning caused by a full graph replacement.
                # This neither records a selection operation nor advances the
                # persistent profile watermark.
                return self._wire_unchanged(profile), "unchanged"
            existing = snapshot["operations"].get(operation)
            receipt = existing.get("receipt") if isinstance(existing, dict) else None
            settlement_resync = False
            if timestamp != current:
                retry_at_current = False
                if isinstance(receipt, dict):
                    try:
                        retry_at_current = (
                            self.adapter.wire_saved(receipt.get("saved")) == current
                        )
                    except EconomyError:
                        retry_at_current = False
                # A same-commander post is also the client's normal way of
                # confirming its hangar selection after battle.  It may carry
                # the pre-battle watermark.  The native profile GET parser
                # rejects purchase-shaped receiving events here; use its
                # silent full-replacement branch after proving the exact
                # settlement chain instead.  Check this before accepting an
                # idempotent receipt so a retry of a lost resync response also
                # receives the full graph.
                if commander_key == snapshot["active_commander"]:
                    settlement_resync = self._has_settlement_chain_since(
                        timestamp, profile,
                    )
                if not settlement_resync and not retry_at_current:
                    return self._wire_full(profile), "stale"
            if (commander_key != snapshot["active_commander"]
                    and self._selection_chain_is_suppressed(commander_key)):
                # v6 still treats hangar rebuilds as physical clicks, so a
                # burst of different-commander POSTs follows one real click.
                # Keep the commander already committed; the profile-GET
                # sentinel avoids an out_of_sync modal and another rebuild.
                return self._wire_unchanged(profile), "unchanged"
            self.economy.select_commander(operation, commander_key)
            updated = self.adapter.build_profile()
            if updated["profile"]["saved"] != current:
                # A changed selection advanced the watermark.  Remember the
                # link so the client's next requests, which still carry the
                # pre-selection watermark, are not mistaken for a stale view.
                self._record_selection_watermark(
                    current, updated["profile"]["saved"],
                )
                self._arm_selection_chain_suppress(
                    snapshot["active_commander"],
                )
            if settlement_resync:
                return self._wire_resync(updated), "resynced"
            inner = updated["profile"]
            return {
                "result": "ok",
                # A delayed retry may return an old idempotency receipt after
                # battle rewards advanced the account.  Never move the
                # client's profile watermark backwards.
                "saved": inner["saved"],
                "events": [],
                "properties": _wire_properties(inner["properties"]),
            }, "accepted"

    def _adapt_profile_message_response(
        self, response: dict, status: str,
    ) -> tuple[dict, str]:
        """Translate economy replies to the distinct profile-GET contract."""
        if (status == "unchanged" and response.get("result") == "ok"
                and response.get("events") == []
                and response.get("properties") == []
                and "profile" not in response):
            return self._wire_profile_already_in_sync(), status
        if status == "accepted" and "profile" not in response:
            # The profile-GET parser rejects the event-style ``ok`` property
            # delta, while an immediate full replacement can run the faction
            # listener against the previous tab body and select its first
            # commander.  The click has already updated the native selection
            # model and this method has durably committed it.  Acknowledge the
            # save without replacing that live graph; the client's normal
            # timestamp-zero follow-up receives the complete selected profile.
            return self._wire_profile_already_in_sync(), status
        return response, status

    def respond_profile_message(
        self,
        raw: bytes = b"",
        *,
        accept_current_selection_noop: bool = False,
    ) -> tuple[dict, str]:
        """Answer one native ``/profile`` request using its own wire schema.

        Commander-selection causal gate: after a selection-shaped POST has
        changed the commander, been durably committed and been acknowledged
        with ``{"profile":"already_in_sync"}``, the client follows up with a
        strict ``{"request":{"timestamp":0}}`` full read.  R20 showed that
        answering it with the complete ``ok_resync`` graph rebuilt the hangar
        and preceded the next autonomous commander change.  The local UI
        already reflects the selection and the server holds the same state,
        so the very next profile message, when it is that read, arrives
        within ``selection_zero_read_window_seconds`` and the watermark is
        unchanged, is answered with the same sentinel exactly once. That
        commander-selection gate is disarmed by any other profile message
        (including a retried or same-commander no-op selection), any
        ``/event`` request, battle allocation/settlement, the private
        post-battle path, an advanced watermark, or window expiry; the
        ``profile_timestamp`` bootstrap always receives the full graph.

        The separately armed external-loadout gate may race with harmless
        ``read``, ``zero_read`` or ``bootstrap`` profile messages before the
        companion raises the stock deferred flag, so those recognized
        read-only shapes preserve it. Unknown/write-shaped messages and a
        mismatching selection consume it. An intervening mutation or expiry
        prevents its later exact selection from matching. The one exact
        selection consumes the gate, receives the authoritative full graph,
        and arms only duplicate-zero-read suppression.
        """
        with self._lock, self.economy._lock:  # type: ignore[attr-defined]
            shape = self._profile_message_shape(raw)
            specialization = self._consume_specialization_profile_refresh(
                raw, shape,
            )
            if specialization is not None:
                profile, gate = specialization
                response = self._wire_resync(profile)
                self._specialization_profile_refresh_ack = {
                    "operation_id": gate["operation_id"],
                    "saved": gate["current_saved"],
                    "status": "specialization_refresh_resynced",
                    "response": response,
                    "response_hash": _canonical_hash(response),
                    "http_response_written": False,
                }
                self._arm_selection_zero_read()
                return response, "specialization_refresh_resynced"
            if shape != "zero_read":
                # A response-correlated zero read must be the immediately next
                # profile message.  In particular, a fresh-process bootstrap
                # invalidates any gate retained by a reused service instance.
                self._disarm_profile_graph_zero_followup()
            if shape == "read":
                cached = self._external_profile_refresh_cached_read(raw)
                if cached is not None:
                    refresh_profile, _refresh_gate = cached
                    # This callback updates a cache, not the hangar graph.
                    # Do not consume the gate or publish a server refresh ack.
                    return self._wire_resync(refresh_profile), "external_refresh_cached"
            if shape == "selection":
                external_refresh = (
                    self._consume_external_profile_refresh_selection(raw)
                )
                if external_refresh is not None:
                    refresh_profile, refresh_gate = external_refresh
                    # Live stock behavior does not issue a causal zero read
                    # after the deferred selection sentinel. Install the
                    # persisted three-slot graph on this precisely correlated
                    # request instead. The external gate was consumed above,
                    # so this full replacement is authorized exactly once;
                    # suppress only a redundant zero read caused by applying
                    # the replacement.
                    response = self._wire_resync(refresh_profile)
                    self._external_profile_refresh_ack = {
                        "operation_id": refresh_gate["operation_id"],
                        "saved": refresh_gate["current_saved"],
                        "status": "external_refresh_resynced",
                        "acknowledged_at": self._clock(),
                        "http_response_written": False,
                    }
                    self._arm_selection_zero_read()
                    return response, "external_refresh_resynced"
            elif shape not in {"read", "zero_read", "bootstrap"}:
                # Harmless profile reads can race between the endpoint reply
                # and the companion raising the stock deferred flag. Preserve
                # the exact, bounded operation gate across those reads. An
                # unknown or write-shaped message still consumes its authority
                # so it can never leak into later navigation.
                self._disarm_external_profile_refresh()
            if (shape == "selection"
                    and self._bootstrap_selection_is_suppressed(raw)):
                profile = self.adapter.build_profile()["profile"]
                self._arm_selection_zero_read()
                return {
                    "result": "ok",
                    "saved": profile["saved"],
                    "events": [],
                    "properties": _wire_properties(profile["properties"]),
                }, "bootstrap_selection_suppressed"
            if shape == "zero_read":
                zero_gate = self._consume_selection_zero_read()
                if (zero_gate is not None
                        and zero_gate.get("preserve_external_selection") is True
                        and self._external_profile_refresh_is_current(
                            self._external_profile_refresh
                        )):
                    # The stock old-unit cleanup sequence can post a zero read
                    # before consuming its deferred commander-selection flag.
                    # Replacing the graph in this earlier callback did not
                    # update the live hangar and spent the exact operation
                    # authority before the selection arrived.  Acknowledge
                    # only this cleanup-proven zero read compactly and retain
                    # the receipt gate for the immediately following exact
                    # commander/faction selection.
                    return (
                        self._wire_profile_already_in_sync(),
                        "selection_gated",
                    )
                if zero_gate is not None and zero_gate.get("resync") is True:
                    # Some builds follow the correlated tutorial heartbeat
                    # directly with a causal zero-read instead of posting the
                    # deferred selection. Install the selected commander's
                    # full graph there and suppress the one redundant zero-read
                    # normally caused by that replacement. Once it arrives,
                    # the retained external receipt authority is spent.
                    self._disarm_external_profile_refresh()
                    response = self._wire_resync(self.adapter.build_profile())
                    self._arm_selection_zero_read()
                    return response, "selection_resynced"
                if zero_gate is not None:
                    return self._wire_profile_already_in_sync(), "selection_gated"
                if self._consume_profile_graph_zero_followup():
                    return (
                        self._wire_profile_already_in_sync(),
                        "profile_graph_followup_gated",
                    )
            else:
                self._disarm_selection_zero_read()
            response, status = self.respond(
                raw,
                accept_selection=True,
                accept_current_selection_noop=accept_current_selection_noop,
                accept_zero_profile_read_noop=False,
            )
            # A fresh native process starts with a profile_timestamp-only
            # bootstrap read.  Its durable watermark can already equal the
            # server value even though the in-memory profile graph has not yet
            # been installed.  Returning already_in_sync in that state makes
            # the client wait forever at "getting user profile".  Install the
            # full graph for this exact bootstrap shape; later timestamp-only
            # reads and the causally gated private post-battle path can use the
            # proven no-change sentinel safely.
            if status == "unchanged":
                try:
                    body = _strict_json(raw)
                    request = body.get("request")
                    if (isinstance(request, dict)
                            and set(request) == {"profile_timestamp"}):
                        response = self._wire_resync(
                            self.adapter.build_profile()
                        )
                        status = "resynced"
                except EconomyError:
                    pass
            response, status = self._adapt_profile_message_response(
                response, status,
            )
            # The profile-GET no-change sentinel cannot carry the new saved
            # watermark.  Native follows every accepted or already-current
            # commander selection with timestamp:0.  Replacing the full graph
            # there rebuilds all hangar panels and replays stale commander/unit
            # context, so consume that one causal read with the same sentinel.
            if (shape == "selection"
                    and status in {"accepted", "unchanged"}
                    and response == self._wire_profile_already_in_sync()):
                self._arm_selection_zero_read()
            elif (shape == "bootstrap" and status == "resynced"
                  and isinstance(response.get("profile"), dict)):
                # Native always follows its initial bootstrap install with a
                # timestamp:0 read.  A second identical full replacement was
                # the source of the automatic Xerxes selection seen on every
                # launch; the graph is already installed, so acknowledge that
                # one causal read without rebuilding the hangar again.
                self._arm_selection_zero_read()
                self._arm_bootstrap_selection_suppress()
            if isinstance(response.get("profile"), dict):
                self._arm_profile_graph_zero_followup(response)
            return response, status

    def respond_tutorial_progress(self, raw: bytes) -> tuple[dict, str]:
        """Acknowledge the native tutorial heartbeat without a warning modal.

        This endpoint carries a profile watermark and the visible commander,
        but it is not the authoritative commander-selection endpoint.  An
        exact request needs only the event-style compact acknowledgement used
        by its BF6CE0 parser.  A valid stale view receives the parser's silent
        ``ok_resync`` replacement; malformed, future, or unowned data remains
        fail-closed.

        At the exact current watermark the server cannot have changed the
        commander (every change advances ``saved``), so a different visible
        commander or title means the client's view is *ahead*: a local
        selection whose authoritative ``/profile`` save is still in flight.
        R20 showed this heartbeat firing within a second before each
        ``active_commander`` POST and receiving the full previous graph, which
        reverted the hangar under the pending selection.  Such a request now
        receives the compact acknowledgement; only a genuinely stale watermark
        still triggers the silent replacement.  A watermark that predates only
        this client's own acknowledged selections counts as current and the
        acknowledgement carries the advanced ``saved``. The same compact
        reply is used for a precisely correlated heartbeat while an external
        unit-loadout refresh is armed. Its exact deferred selection installs
        the new graph directly; builds that instead send a causal zero-read
        remain supported.
        """
        with self._lock, self.economy._lock:  # type: ignore[attr-defined]
            profile = self.adapter.build_profile()
            try:
                body = _strict_json(raw)
                request = body.get("request")
                if (not isinstance(request, dict)
                        or not _TUTORIAL_PROGRESS_FIELDS <= set(request)
                        or not set(request) <= (
                            _TUTORIAL_PROGRESS_FIELDS
                            | _OPTIONAL_TUTORIAL_PROGRESS_FIELDS
                        )):
                    raise EconomyError("invalid_tutorial_progress")
                timestamp = _uint64(
                    request.get("profile_timestamp"),
                    "invalid_profile_timestamp",
                )
                current = profile["profile"]["saved"]
                if timestamp > current:
                    raise EconomyError("future_profile_timestamp")
                requested_timestamp = timestamp
                timestamp = self._translate_watermark(timestamp, current)
                progress = _uint64(
                    request.get("tutorial_progress"),
                    "invalid_tutorial_progress",
                )
                if progress > _MAX_TUTORIAL_PROGRESS:
                    raise EconomyError("invalid_tutorial_progress")
                snapshot = self.economy.snapshot()
                requested_commander_key = None
                commander_matches = True
                if "active_commander" in request:
                    active = _uint64(
                        request["active_commander"],
                        "invalid_active_commander",
                        positive=True,
                    )
                    commander_key = self._owned_commander_ids(profile).get(active)
                    if commander_key is None:
                        raise EconomyError("commander_not_owned")
                    requested_commander_key = commander_key
                    commander_matches = (
                        commander_key == snapshot["active_commander"]
                    )
                title_matches = True
                if "active_title" in request:
                    title = _uint64(
                        request["active_title"],
                        "invalid_active_title",
                        positive=True,
                    )
                    expected_titles = {
                        row[3] for row in profile["profile"]["properties"]
                        if row[0] == "active_title"
                    }
                    title_matches = title in expected_titles
                external_gate = self._external_profile_refresh
                if external_gate is not None:
                    if (self._external_profile_refresh_is_current(external_gate)
                            and (
                                self._external_refresh_previous_matches(
                                    external_gate, requested_timestamp,
                                )
                                or (
                                    external_gate["cleanup_acknowledged"]
                                    is True
                                    and requested_timestamp
                                    == external_gate["current_wire_saved"]
                                )
                            )
                            and commander_matches and title_matches):
                        # Some flows send this heartbeat before the deferred
                        # stale selection.
                        # Replacing the complete graph inside this earlier
                        # callback can replay stale hangar listeners.  Carry
                        # the current watermark compactly and authorize either
                        # the proven selection or a direct causal zero read.
                        external_gate["tutorial_acknowledged"] = True
                        zero_gate = self._selection_zero_read
                        if (external_gate["cleanup_acknowledged"] is not True
                                and (not isinstance(zero_gate, dict)
                                or zero_gate.get(
                                    "preserve_external_selection"
                                ) is not True)):
                            self._arm_selection_zero_read(resync=True)
                        return (
                            self._wire_tutorial_ack(profile),
                            "external_refresh_pending",
                        )
                    self._disarm_external_profile_refresh()
                if timestamp == current:
                    # ``commander_matches``/``title_matches`` are validated
                    # above for ownership, but a mismatch at the exact
                    # watermark is a pending local selection, not staleness.
                    return self._wire_tutorial_ack(
                        profile,
                        active_commander_key=requested_commander_key,
                    ), "unchanged"
                return self._wire_resync(profile), "resynced"
            except EconomyError:
                self._disarm_external_profile_refresh()
                return self._wire_full(profile), "rejected"

    def respond_private_postbattle(
        self,
        raw: bytes,
        *,
        profile_target_ready: bool,
        expected_saved: int | None,
    ) -> tuple[dict, str, dict[str, bool]]:
        """Atomically validate and answer one private post-battle profile read.

        The HTTP gate records the authoritative watermark at battle
        completion.  Another loopback request must not be able to mutate the
        profile after that watermark is compared but before ``respond`` builds
        its reply.  Hold both service locks across the comparison and response
        construction, and enable the private compact acknowledgement only
        when the causal profile target is ready and the watermark is still
        exact.

        The returned metadata contains fixed booleans only.  It is safe for a
        metadata trace and deliberately carries no timestamp or profile ID.
        """
        if type(profile_target_ready) is not bool:
            raise TypeError("profile_target_ready must be bool")
        if (expected_saved is not None
                and (type(expected_saved) is not int or expected_saved < 0)):
            raise ValueError("invalid expected profile watermark")
        with self._lock, self.economy._lock:  # type: ignore[attr-defined]
            # The private post-battle read has its own ready/saved gate.
            self._disarm_selection_zero_read()
            self._disarm_profile_graph_zero_followup()
            self._disarm_external_profile_refresh()
            snapshot = self.economy.snapshot()
            current_saved = snapshot["saved"]
            profile_saved = self.adapter.wire_saved(current_saved)
            saved_matches = (
                expected_saved is not None and expected_saved == current_saved
            )
            trace_metadata = {
                "private_profile_gate_saved_matches_current": saved_matches,
            }
            try:
                body = _strict_json(raw)
                request = body.get("request")
                if isinstance(request, dict):
                    for field in ("profile_timestamp", "timestamp"):
                        if field not in request:
                            continue
                        value = request[field]
                        trace_metadata[field + "_zero"] = (
                            type(value) is int and value == 0
                        )
                        trace_metadata[field + "_matches_current"] = (
                            type(value) is int and value == profile_saved
                        )
            except EconomyError:
                # ``respond`` retains its normal fail-closed response for an
                # invalid body.  Omit classification rather than deriving a
                # misleading value from permissive JSON parsing.
                pass
            response, status = self.respond(
                raw,
                accept_selection=True,
                accept_current_selection_noop=(
                    profile_target_ready and saved_matches
                ),
                accept_zero_profile_read_noop=(
                    profile_target_ready and saved_matches
                ),
            )
            response, status = self._adapt_profile_message_response(
                response, status,
            )
            return response, status, trace_metadata

    def handle_event_request(self, request: object) -> dict:
        """Forward only the proven purchase variant of decoded ``/event``."""
        if (not isinstance(request, dict)
                or "results" in request
                or "events" not in request
                or "profile_timestamp" not in request):
            with self._lock:
                self._disarm_selection_zero_read()
                self._disarm_profile_graph_zero_followup()
                self._disarm_external_profile_refresh()
            if not isinstance(request, dict):
                raise EconomyError("invalid_event_request")
            if "results" in request:
                raise EconomyError("battle_result_not_purchase")
            raise EconomyError("unsupported_event_request")
        # Keep the projection watermark stable across the complete event
        # transaction.  An idempotent LocalEconomy receipt deliberately keeps
        # the timestamp from its first application; after another legitimate
        # profile mutation that stored timestamp can be older than the profile
        # with which this retry began.  Never move the native client backwards.
        # Ability retries return the current full profile because their deltas
        # are additive; other idempotent purchase kinds may replay an exact
        # delta.  In either case, never let the response-level watermark move
        # behind the request-start profile floor.
        with self._lock, self.economy._lock:  # type: ignore[attr-defined]
            self._disarm_profile_graph_zero_followup()
            # Old-unit cleanup is a delayed, fully proven acknowledgement. It
            # must not consume the independent deferred profile-refresh gate
            # armed by the unit drag; the following stock selection still
            # needs that gate to install the current graph. Requests that do
            # not pass the durable before-image proof follow the ordinary
            # disarming path.
            request = self._normalize_external_unit_cleanup_request(request)
            cleanup_request = self.adapter.is_unit_change_cleanup_request(request)
            cleanup_delta_authorized = False
            if not cleanup_request:
                self._disarm_external_profile_refresh()
            elif self._external_profile_refresh_is_current(
                    self._external_profile_refresh
            ) and (
                self._external_refresh_previous_matches(
                    self._external_profile_refresh,
                    self.adapter.wire_saved(request["profile_timestamp"]),
                )
                or self.adapter.unit_change_cleanup_covers_operation(
                    request,
                    self._external_profile_refresh["operation_id"],
                )
            ):
                cleanup_delta_authorized = True
                # The cleanup ACK itself advances the native client watermark
                # to the already-installed post-drag profile.  Some builds
                # consequently send the deferred commander selection with
                # that current watermark instead of the old one. Treat that
                # exact cleanup/gate chain as the same bounded causal proof;
                # unrelated stale cleanup cannot arm this flag.
                self._external_profile_refresh["tutorial_acknowledged"] = True
                self._external_profile_refresh["cleanup_acknowledged"] = True
                # This exact cleanup is stronger evidence than a previously
                # armed generic tutorial zero-read. Upgrade that one-shot so
                # timestamp:0 cannot consume the deferred selection route.
                self._arm_selection_zero_read(
                    resync=True,
                    preserve_external_selection=True,
                )
            saved_floor = self.adapter.wire_saved(
                self.economy.snapshot()["saved"]
            )
            request_events = request.get("events")
            is_loadout_resync = (
                isinstance(request_events, list)
                and bool(request_events)
                and all(
                    isinstance(event, dict)
                    and isinstance(event.get("po"), str)
                    and isinstance(self.adapter.offers.get(event["po"]), dict)
                    and self.adapter.offers[event["po"]].get("kind") in {
                        "equipment", "unit_ability",
                    }
                    for event in request_events
                )
            )
            unit_ability_contract = None
            if (not cleanup_request
                    and isinstance(request_events, list) and request_events
                    and all(
                        isinstance(event, dict)
                        and isinstance(event.get("po"), str)
                        and isinstance(
                            self.adapter.offers.get(event["po"]), dict,
                        )
                        and self.adapter.offers[event["po"]].get("kind")
                        == "unit_ability"
                        for event in request_events
                    )):
                resolved = [
                    self.adapter.unit_ability_by_option[event["po"]]
                    for event in request_events
                ]
                unit_keys = {row["unit"] for _action, row in resolved}
                if len(unit_keys) != 1:
                    raise EconomyError("invalid_event_response")
                previous = next((row["db_key"] for action, row in resolved
                                 if action == "unequip"), None)
                selected = next((row["db_key"] for action, row in resolved
                                 if action == "equip"), None)
                operation_id = self.adapter._loadout_operation_id(
                    "unit-ability", request, request_events,
                )
                unit_ability_contract = {
                    "before": self.adapter.build_profile()["profile"],
                    "unit": next(iter(unit_keys)),
                    "previous": previous,
                    "selected": selected,
                    "binding_pair": (
                        tuple(row["db_key"] for _action, row in resolved)
                        if len(resolved) == 2
                        and all(action == "equip" for action, _row in resolved)
                        else None
                    ),
                    "preferred_parent": request_events[-1].get("parent_id"),
                    "retry": operation_id
                    in self.economy.snapshot()["operations"],
                }
            response = self.adapter.handle_purchase_request(request)
            if not isinstance(response, dict):
                raise EconomyError("invalid_event_response")
            result = response.get("result")
            expected_fields = {"result", "saved", "events", "properties"}
            if result == "ok_resync":
                expected_fields.add("profile")
            elif result != "ok":
                raise EconomyError("invalid_event_response")
            if (set(response) != expected_fields
                    or not isinstance(response.get("events"), list)
                    or any(not isinstance(event, dict)
                           for event in response["events"])):
                raise EconomyError("invalid_event_response")

            response_saved = _uint64(
                response.get("saved"),
                "invalid_event_response_saved",
                positive=True,
            )
            if cleanup_request:
                authoritative = self.adapter.build_profile()["profile"]
                try:
                    expected_cleanup_events = (
                        self.adapter.unit_change_cleanup_delta_events(request)
                    )
                    response_properties = json.dumps(
                        response.get("properties"), ensure_ascii=False,
                        sort_keys=True, separators=(",", ":"),
                        allow_nan=False,
                    )
                    authoritative_properties = json.dumps(
                        authoritative.get("properties"), ensure_ascii=False,
                        sort_keys=True, separators=(",", ":"),
                        allow_nan=False,
                    )
                except (TypeError, ValueError):
                    raise EconomyError("invalid_event_response") from None
                if (result != "ok"
                        or response["events"] != []
                        or response_saved != authoritative.get("saved")
                        or response_properties != authoritative_properties):
                    raise EconomyError("invalid_event_response")
                gate = self._external_profile_refresh
                if (cleanup_delta_authorized
                        and self._external_profile_refresh_is_current(gate)):
                    emitted = gate["cleanup_delta_emissions"]
                    pending_events = []
                    for event in expected_cleanup_events:
                        child_key = _canonical_hash(event)
                        if child_key not in emitted:
                            if len(emitted) >= (
                                self.adapter.max_unit_change_cleanup_emissions
                            ):
                                # The catalogue-derived ceiling covers every
                                # removable child of all three deployed slots.
                                # A wider chain is ambiguous; fail compact by
                                # leaving further rows for the full refresh.
                                continue
                            pending_events.append(event)
                            emitted.append(child_key)
                    # Negative child deltas are not replayable.  A duplicate
                    # batch, or an overlapping subset, omits every row whose
                    # first response may already have destroyed the object.
                    # The empty ACK still preserves the correlated refresh.
                    response["events"] = pending_events
                else:
                    # Without the exact live drag generation the native graph
                    # may already contain the replacement unit.  Never remove
                    # an old child from that unknown graph.
                    response["events"] = []
            if result == "ok_resync":
                embedded = response.get("profile")
                if (response["events"] != []
                        or not isinstance(embedded, dict)
                        or response_saved != embedded.get("saved")
                        or not embedded.get("profile_records")):
                    raise EconomyError("invalid_event_response")
                response["profile"]["properties"] = _wire_properties(
                    response["profile"].get("properties")
                )

            if unit_ability_contract is not None:
                authoritative = self.adapter.build_profile()["profile"]
                if result == "ok":
                    if unit_ability_contract["retry"] is True:
                        raise EconomyError("invalid_event_response")
                    try:
                        if unit_ability_contract["binding_pair"] is not None:
                            expected_events = self.adapter.unit_ability_pair_delta_events(
                                unit_ability_contract["before"], authoritative,
                                unit_ability_contract["unit"],
                                binding_pair=unit_ability_contract["binding_pair"],
                                preferred_parent=unit_ability_contract["preferred_parent"],
                            )
                        else:
                            expected_events = self.adapter.unit_ability_delta_events(
                                unit_ability_contract["before"],
                                authoritative,
                                unit_ability_contract["unit"],
                                previous_db_key=unit_ability_contract["previous"],
                                selected_db_key=unit_ability_contract["selected"],
                                preferred_parent=unit_ability_contract[
                                    "preferred_parent"
                                ],
                            )
                    except EconomyError:
                        raise EconomyError("invalid_event_response") from None
                    typed_events = (
                        len(response["events"]) == len(expected_events)
                        and all(
                            set(actual) == set(expected)
                            and all(
                                type(actual[key]) is int
                                and actual[key] == expected[key]
                                for key in expected
                            )
                            for actual, expected
                            in zip(response["events"], expected_events)
                        )
                    )
                    if (not typed_events
                            or response_saved != authoritative.get("saved")):
                        raise EconomyError("invalid_event_response")
                    # Preserve JSON scalar types while comparing.  Python's
                    # ordinary equality treats True as 1, but the native
                    # property parser does not: unit-ability deltas must carry
                    # the exact authoritative active commander/title before
                    # _wire_properties converts high-bit uint64 values to the
                    # signed representation expected on the wire.
                    try:
                        response_properties = json.dumps(
                            response.get("properties"), ensure_ascii=False,
                            sort_keys=True, separators=(",", ":"),
                            allow_nan=False,
                        )
                        authoritative_properties = json.dumps(
                            authoritative.get("properties"), ensure_ascii=False,
                            sort_keys=True, separators=(",", ":"),
                            allow_nan=False,
                        )
                    except (TypeError, ValueError):
                        raise EconomyError("invalid_event_response") from None
                    if response_properties != authoritative_properties:
                        raise EconomyError("invalid_event_response")
                else:
                    # Additive deltas are never replayed.  The established
                    # retry fallback must be a silent, current authoritative
                    # graph; its runtime lifetime behavior remains a separate
                    # verification boundary.
                    if (unit_ability_contract["retry"] is not True
                            or response["events"] != []):
                        raise EconomyError("invalid_event_response")
                    authoritative_wire_profile = copy.deepcopy(authoritative)
                    authoritative_wire_profile["properties"] = _wire_properties(
                        authoritative_wire_profile.get("properties")
                    )
                    try:
                        embedded_wire = json.dumps(
                            response.get("profile"), ensure_ascii=False,
                            sort_keys=True, separators=(",", ":"),
                            allow_nan=False,
                        )
                        authoritative_wire = json.dumps(
                            authoritative_wire_profile, ensure_ascii=False,
                            sort_keys=True, separators=(",", ":"),
                            allow_nan=False,
                        )
                    except (TypeError, ValueError):
                        raise EconomyError("invalid_event_response") from None
                    if embedded_wire != authoritative_wire:
                        raise EconomyError("invalid_event_response")

            response["saved"] = max(response_saved, saved_floor)
            # Requests keep positive uint64 identities, but BD81E9/BD8292
            # require the signed-int64 JSON flag in response properties before
            # using the same raw 64 bits for commander/title lookup.
            response["properties"] = _wire_properties(
                response.get("properties")
            )
            if cleanup_request:
                # A cleanup ACK carries no profile delta and is independent
                # of the selection-zero gate (which may belong to an earlier
                # legitimate operation). Preserve that gate exactly.
                pass
            elif result == "ok_resync" and is_loadout_resync:
                # Equipment and type-19 abilities use the full event response
                # to rebuild their selection frames. The native client follows it
                # with timestamp:0; sending the same 100+ KiB graph twice makes
                # the frame visibly stall and can restart commander fills.
                self._arm_selection_zero_read()
            else:
                self._disarm_selection_zero_read()
        return response

    def specialization_ui_status(self, language: str) -> dict:
        """Build one locked, read-only presentation response for UI transport."""
        with self._lock, self.economy._lock:  # type: ignore[attr-defined]
            snapshot = self.economy.snapshot()
            builder = getattr(self.economy, "specialization_ui_status", None)
            if not callable(builder):
                raise EconomyError("specialization_ui_status_unavailable")
            commander = snapshot["active_commander"]
            raw_saved = snapshot.get("saved")
            if (type(raw_saved) is not int
                    or not 0 < raw_saved < 2**64):
                raise EconomyError("invalid_specialization_ui_status")
            try:
                result = builder(commander, language, snapshot)
            except EconomyError:
                # Preserve readiness/state errors such as
                # ``specializations_not_enabled`` for the existing HTTP
                # error mapping.  EconomyError subclasses ValueError, so it
                # must be caught before malformed-builder failures below.
                raise
            except ValueError as exc:
                # Preserve the service's historical direct-call error for an
                # unsupported language; the HTTP route validates the query
                # before calling this method. Other builder failures become a
                # stable economy error rather than escaping the handler.
                if isinstance(language, str) and language not in {'en', 'ja', 'ru'}:
                    raise
                raise EconomyError("invalid_specialization_ui_status") from exc
            except (KeyError, TypeError) as exc:
                raise EconomyError("invalid_specialization_ui_status") from exc
            if (not isinstance(result, dict)
                    or result.get("language") != language
                    or result.get("version") != UI_STATUS_VERSION
                    or result.get("commander_key") != commander
                    ):
                raise EconomyError("invalid_specialization_ui_status")
            return {
                **result,
                "raw_saved": raw_saved,
                "saved": self.adapter.wire_saved(raw_saved),
            }

    def specialization_control(self, request: dict | None = None) -> dict:
        """Read or mutate the local specialization policy through a strict IPC.

        This is deliberately separate from native ``/event`` and from the
        unit-drag external-profile refresh gate.  The caller is responsible
        for transporting the returned authoritative profile to its UI client.
        """
        with self._lock, self.economy._lock:  # type: ignore[attr-defined]
            snapshot = self.economy.snapshot()
            enabled = getattr(self.economy, "specialization_enabled", None)
            status_fn = getattr(self.economy, "specialization_status", None)
            if not callable(enabled) or not callable(status_fn) or not enabled(snapshot):
                raise EconomyError("specializations_not_enabled")
            commander = snapshot["active_commander"]
            pending = any(row.get("status") == "pending"
                          for row in snapshot.get("battles", {}).values())
            if request is None:
                return {"result": "ok", "commander_key": commander,
                        "saved": snapshot["saved"], "pending_battle": pending,
                        "free_xp_cents": snapshot["wallet"]["free_xp_cents"],
                        "status": status_fn(commander, snapshot)}
            if (not isinstance(request, dict) or set(request) != {
                    "action", "commander_key", "operation_id", "expected_saved"}):
                raise EconomyError("invalid_specialization_control_request")
            action = request["action"]
            operation_id = request["operation_id"]
            expected = request["expected_saved"]
            if not isinstance(action, str) or action not in {
                    "purchase_talent_point", "respec_commander"}:
                raise EconomyError("invalid_specialization_action")
            if not isinstance(request["commander_key"], str):
                raise EconomyError("specialization_commander_mismatch")
            if (not isinstance(operation_id, str)
                    or re.fullmatch(r"native-specialization-[0-9a-f]{32}", operation_id) is None):
                raise EconomyError("invalid_specialization_operation_id")
            if type(expected) is not int or not 0 <= expected < 2**64:
                raise EconomyError("invalid_specialization_watermark")
            if request["commander_key"] != commander:
                raise EconomyError("specialization_commander_mismatch")
            existing = snapshot.get("operations", {}).get(operation_id)
            retry = isinstance(existing, dict)
            if not retry and snapshot["saved"] != expected:
                raise EconomyError("specialization_state_changed")
            if pending and not retry:
                raise EconomyError("specialization_change_pending_battle")
            mutate = getattr(self.economy, action, None)
            if not callable(mutate):
                raise EconomyError("specialization_action_unavailable")
            receipt = mutate(operation_id, commander)
            current = self.economy.snapshot()
            if (receipt.get("operation_id") != operation_id
                    or receipt.get("commander") != commander
                    or type(receipt.get("saved")) is not int
                    or receipt["saved"] > current["saved"]):
                raise EconomyError("invalid_specialization_receipt")
            profile = self.adapter.build_profile()["profile"]
            ack = self._specialization_profile_refresh_ack
            already_written = (isinstance(ack, dict)
                and ack.get("operation_id") == operation_id
                and ack.get("http_response_written") is True)
            if receipt["saved"] == current["saved"] and not already_written:
                self._specialization_profile_refresh = {
                    "operation_id": operation_id, "action": action,
                    "commander": commander, "previous_saved": expected,
                    "current_saved": current["saved"], "armed_at": self._clock(),
                }
            return {"result": "ok", "action": action,
                    "commander_key": commander, "saved": current["saved"],
                    "receipt": receipt, "status": status_fn(commander, current),
                    "profile": profile}

    def _consume_specialization_profile_refresh(
        self, raw: bytes, shape: str | None,
    ) -> tuple[dict, dict] | None:
        gate = self._specialization_profile_refresh
        if not isinstance(gate, dict):
            return None
        self._specialization_profile_refresh = None
        if (set(gate) != {"operation_id", "action", "commander",
                          "previous_saved", "current_saved", "armed_at"}
                or not isinstance(gate["operation_id"], str)
                or gate["action"] not in {"purchase_talent_point", "respec_commander"}
                or not isinstance(gate["commander"], str)
                or type(gate["previous_saved"]) is not int
                or type(gate["current_saved"]) is not int
                or type(gate["armed_at"]) not in {int, float}):
            return None
        snapshot = self.economy.snapshot()
        age = self._clock() - gate["armed_at"]
        if (not math.isfinite(age) or age < 0
                or age > self.external_profile_refresh_window_seconds
                or snapshot["saved"] != gate["current_saved"]
                or snapshot["active_commander"] != gate["commander"]):
            return None
        entry = snapshot.get("operations", {}).get(gate["operation_id"])
        receipt = entry.get("receipt") if isinstance(entry, dict) else None
        expected_kind = gate["action"]
        if expected_kind == "purchase_talent_point" and isinstance(receipt, dict):
            expected_request = {"commander": gate["commander"], "amount": 1,
                                "price_free_xp_cents": receipt.get("price_free_xp_cents")}
        elif expected_kind == "respec_commander" and isinstance(receipt, dict):
            expected_request = {"commander": gate["commander"],
                                "policy_version": receipt.get("policy_version")}
        else:
            expected_request = None
        if (not isinstance(receipt, dict)
                or receipt.get("operation_id") != gate["operation_id"]
                or receipt.get("kind") != expected_kind
                or receipt.get("commander") != gate["commander"]
                or receipt.get("saved") != gate["current_saved"]
                or not isinstance(entry.get("request_hash"), str)
                or expected_request is None
                or entry["request_hash"] != _canonical_hash({
                    "kind": expected_kind, "request": expected_request})):
            return None
        profile = self.adapter.build_profile()
        allowed = {self.adapter.wire_saved(gate["previous_saved"]),
                   self.adapter.wire_saved(gate["current_saved"])}
        try:
            if shape == "read":
                body = _strict_json(raw); request = body["request"]
                if set(request) != {"timestamp"} or type(request["timestamp"]) is not int:
                    return None
                if request["timestamp"] not in allowed:
                    return None
            elif shape == "selection":
                commander, _operation, timestamp = self._selection_request(raw, profile)
                if commander != gate["commander"] or timestamp not in allowed:
                    return None
            else:
                return None
        except (EconomyError, KeyError, TypeError):
            return None
        return profile, gate

    def confirm_specialization_profile_refresh_http(self, response: object) -> bool:
        """Confirm only the exact specialization graph after a successful write."""
        with self._lock, self.economy._lock:  # type: ignore[attr-defined]
            ack = self._specialization_profile_refresh_ack
            if (not isinstance(ack, dict) or ack.get("response") is not response
                    or ack.get("status") != "specialization_refresh_resynced"
                    or ack.get("http_response_written") is not False
                    or _canonical_hash(response) != ack.get("response_hash")
                    or not isinstance(response, dict)
                    or response.get("saved") != self.adapter.wire_saved(ack.get("saved"))):
                return False
            ack["response"] = None
            ack["http_response_written"] = True
            ack["acknowledged_at"] = self._clock()
            return True

    def specialization_profile_refresh_ack(
        self, operation_id: object, saved: object,
    ) -> dict | None:
        """Read one fresh, exact, post-body-write specialization ACK."""
        with self._lock, self.economy._lock:  # type: ignore[attr-defined]
            ack = self._specialization_profile_refresh_ack
            if (not isinstance(operation_id, str)
                    or re.fullmatch(r"native-specialization-[0-9a-f]{32}",
                                    operation_id) is None
                    or type(saved) is not int or not 0 < saved < 2**64
                    or not isinstance(ack, dict)
                    or ack.get("operation_id") != operation_id
                    or ack.get("saved") != saved
                    or ack.get("status") != "specialization_refresh_resynced"
                    or ack.get("http_response_written") is not True
                    or ack.get("response") is not None
                    or type(ack.get("acknowledged_at")) not in {int, float}):
                return None
            age = self._clock() - ack["acknowledged_at"]
            snapshot = self.economy.snapshot()
            if (not math.isfinite(age) or age < 0
                    or age > self.external_profile_refresh_window_seconds
                    or snapshot.get("saved") != saved):
                return None
            return {"result": "ok", "operation_id": operation_id,
                    "saved": saved,
                    "status": "specialization_refresh_resynced",
                    "http_response_written": True}

    @staticmethod
    def _validate_records(value: object) -> list[list[int]]:
        if not isinstance(value, list) or not value or len(value) > 10_000:
            raise EconomyError("invalid_allocation_loadout")
        records: list[list[int]] = []
        instances: set[int] = set()
        for row in value:
            if not isinstance(row, list) or len(row) != 4:
                raise EconomyError("invalid_allocation_loadout")
            parent = _uint64(row[0], "invalid_allocation_loadout")
            item = _uint64(row[1], "invalid_allocation_loadout", positive=True)
            instance = _uint64(row[2], "invalid_allocation_loadout", positive=True)
            quantity = _uint64(row[3], "invalid_allocation_loadout")
            if instance in instances:
                raise EconomyError("invalid_allocation_loadout")
            instances.add(instance)
            records.append([parent, item, instance, quantity])
        return records

    def _validate_allocation_context(
        self,
        context: object,
        loadout: dict,
        *,
        expected_profile_saved: int,
        exact_profile_saved: bool,
        allow_legacy_frozen_unit_abilities: bool = False,
    ) -> dict:
        if (not isinstance(context, dict)
                or not _REQUIRED_CONTEXT_FIELDS <= set(context)
                or not set(context) <= _CONTEXT_FIELDS):
            raise EconomyError("invalid_allocation_context")
        mode = context.get("mode")
        if mode not in {"pve", "pvp"}:
            raise EconomyError("invalid_allocation_mode")
        ruleset = context.get("ruleset")
        if ruleset is not None:
            if not is_native_battle_map(context.get("map"), ruleset):
                raise EconomyError("invalid_allocation_ruleset")
        if "map" in context and (not isinstance(context["map"], str) or not context["map"]):
            raise EconomyError("invalid_allocation_map")
        if "party_id" in context:
            party_id = context["party_id"]
            if (type(party_id) is int and 0 <= party_id <= UINT64_MAX):
                pass
            elif (isinstance(party_id, str) and 0 <= len(party_id) <= 128
                  and (party_id or isinstance(context.get("result_participants"), list))
                  and all(32 <= ord(char) <= 126 for char in party_id)):
                pass
            else:
                raise EconomyError("invalid_allocation_party")
        result_participants = _validated_result_participants(
            context.get("result_participants"), local_user_id=self.user_id,
            party_id=context.get("party_id"), mode=mode,
            roster_policy=context.get("roster_policy"),
        )
        if "display_name" in context:
            from companion.player_name import validate_display_name
            try:
                validate_display_name(context["display_name"])
            except ValueError:
                raise EconomyError("invalid_allocation_display_name") from None
        profile_saved = _uint64(context.get("profile_saved"), "invalid_profile_timestamp")
        if ((exact_profile_saved and profile_saved != expected_profile_saved)
                or (not exact_profile_saved and profile_saved > expected_profile_saved)):
            raise EconomyError("allocation_profile_mismatch")

        units = loadout.get("units")
        if not isinstance(units, list) or len(units) != 3:
            raise EconomyError("invalid_frozen_loadout")
        expected_items = [row["item_id"] for row in units]
        expected_instances = [row["instance_id"] for row in units]
        expected_tiers = [row["tier"] for row in units]
        if (context.get("commander_key") != loadout.get("commander")
                or context.get("commander_tier") != loadout.get("commander_tier")
                or context.get("battle_tier") != loadout.get("battle_tier")
                or context.get("pve_enemy_tier") != loadout.get("enemy_tier")
                or context.get("unit_tiers") != expected_tiers):
            raise EconomyError("allocation_loadout_mismatch")
        optional_values = {
            "commander_item_id": loadout.get("commander_item_id"),
            "unit_item_ids": expected_items,
            "unit_instance_ids": expected_instances,
            "roster_hash": loadout.get("roster_hash"),
        }
        if any(key in context and context[key] != value for key, value in optional_values.items()):
            raise EconomyError("allocation_loadout_mismatch")

        records = self._validate_records(context.get("full_squad_setup"))
        counts = Counter(tuple(row) for row in records)
        commander_item = loadout["commander_item_id"]
        if counts[(0, commander_item, commander_item, 1)] != 1:
            raise EconomyError("allocation_commander_mismatch")
        expected_equipped = [
            (commander_item, item, instance, 1)
            for item, instance in zip(expected_items, expected_instances)
        ]
        if any(counts[row] != 1 for row in expected_equipped):
            raise EconomyError("allocation_unit_mismatch")
        for item in set(expected_items):
            if counts[(0, item, item, 1)] != 1:
                raise EconomyError("allocation_unit_mismatch")

        # ``full_squad_setup`` is supplied by the matchmaking bridge, but it
        # still crosses an HTTP trust boundary.  Require its type-19 rows to
        # equal the frozen LocalEconomy selection exactly: no forged ability,
        # cross-unit junction, omitted selection, or duplicate is accepted.
        all_ability_items = {
            row["item_id"]
            for row in self.adapter.unit_abilities["items"]
        }
        actual_abilities = Counter(
            tuple(row) for row in records if row[1] in all_ability_items
        )
        expected_abilities: Counter[tuple[int, int, int, int]] = Counter()
        legacy_expected_abilities: Counter[tuple[int, int, int, int]] = Counter()
        commander_key = loadout["commander"]
        for unit in units:
            slot = unit.get("slot")
            if type(slot) is not int:
                raise EconomyError("invalid_frozen_unit_ability")
            for db_key in unit.get("abilities", []):
                ability = self.adapter.unit_abilities_by_db_key.get(db_key)
                if ability is None or ability["unit"] != unit["key"]:
                    raise EconomyError("invalid_frozen_unit_ability")
                expected_abilities.update({(
                    self.economy.slot_instances[(commander_key, slot)],
                    ability["item_id"],
                    self.adapter.deployed_unit_ability_instance_id(
                        commander_key, slot, db_key,
                    ),
                    1,
                ): 1})
        if allow_legacy_frozen_unit_abilities:
            # Before deployed-parent type-19 support, an already frozen battle
            # contained one owned-unit-root row per selected unit/ability even
            # when the same unit occupied several slots.  Accept only that
            # exact historical projection for an existing immutable battle;
            # new allocations must use the deployed-slot shape above.
            for unit in {row["key"]: row for row in units}.values():
                for db_key in unit.get("abilities", []):
                    ability = self.adapter.unit_abilities_by_db_key.get(db_key)
                    if ability is None or ability["unit"] != unit["key"]:
                        raise EconomyError("invalid_frozen_unit_ability")
                    legacy_expected_abilities.update({(
                        unit["item_id"], ability["item_id"],
                        self.adapter.unit_ability_instance_id(db_key), 1,
                    ): 1})
        if (actual_abilities != expected_abilities
                and (not allow_legacy_frozen_unit_abilities
                     or actual_abilities != legacy_expected_abilities)):
            raise EconomyError("allocation_unit_ability_mismatch")

        # Consumables and type-19 abilities are children of deployed unit
        # instances. Freeze them just as strictly: a bridge may not omit a selected
        # consumable, substitute another compatible definition, add a lower-
        # Tier row, or duplicate one after LocalEconomy fixed the roster hash.
        all_consumable_items = {
            row["item_id"] for row in self.adapter.consumables["definitions"]
        }
        actual_consumables = Counter(
            tuple(row) for row in records if row[1] in all_consumable_items
        )
        expected_consumables: Counter[tuple[int, int, int, int]] = Counter()
        for unit in units:
            selected = unit.get("consumables")
            slot = unit.get("slot")
            if not isinstance(selected, dict) or type(slot) is not int:
                raise EconomyError("invalid_frozen_consumable")
            for consumable_slot, db_key in selected.items():
                definition = self.adapter.consumables_by_db_key.get(db_key)
                if (not isinstance(consumable_slot, str)
                        or not consumable_slot.isascii()
                        or not consumable_slot.isdigit()
                        or str(int(consumable_slot)) != consumable_slot
                        or not 0 <= int(consumable_slot) < EFFECTIVE_CONSUMABLE_SLOTS
                        or definition is None
                        or db_key not in {
                            row["db_key"]
                            for row in self.adapter.consumables_by_unit.get(
                                unit["key"], []
                            )
                        }):
                    raise EconomyError("invalid_frozen_consumable")
                expected_consumables.update({(
                    unit["instance_id"],
                    definition["item_id"],
                    self.adapter.consumable_instance_id(
                        commander_key, slot, db_key,
                    ),
                    definition["quantity"],
                ): 1})
        if actual_consumables != expected_consumables:
            raise EconomyError("allocation_consumable_mismatch")

        canonical = {
            "mode": mode,
            "map": context.get("map"),
            "party_id": context.get("party_id"),
            "commander": loadout["commander"],
            "commander_item_id": commander_item,
            "commander_tier": loadout["commander_tier"],
            "unit_item_ids": list(expected_items),
            "unit_instance_ids": list(expected_instances),
            "unit_tiers": list(expected_tiers),
            "battle_tier": loadout["battle_tier"],
            "roster_hash": loadout["roster_hash"],
            "result_participants": copy.deepcopy(result_participants),
        }
        if "display_name" in context:
            canonical["display_name"] = context["display_name"]
        if ruleset is not None:
            canonical["ruleset"] = ruleset
        if "roster_policy" in context:
            canonical["roster_policy"] = copy.deepcopy(context["roster_policy"])
        return canonical

    def begin_public_allocation(self, battle_id: str, context: object) -> dict:
        """Freeze one public roster and its server-selected reward policy."""
        with self._lock, self.economy._lock:  # type: ignore[attr-defined]
            self._disarm_selection_zero_read()
            self._disarm_profile_graph_zero_followup()
            self._disarm_external_profile_refresh()
            if not isinstance(context, dict) or context.get("mode") not in {"pve", "pvp"}:
                raise EconomyError("invalid_allocation_mode")
            mode = context["mode"]
            snapshot = self.economy.snapshot()
            existing = snapshot["battles"].get(battle_id)
            if existing is None:
                preview = self.economy.battle_loadout()
                profile_saved = self.adapter.wire_saved(snapshot["saved"])
                canonical = self._validate_allocation_context(
                    context,
                    preview,
                    expected_profile_saved=profile_saved,
                    exact_profile_saved=True,
                )
                receipt = self.economy.begin_battle(
                    battle_id, reward_policy=mode,
                )
                if receipt["loadout"] != preview:
                    raise EconomyError("allocation_loadout_changed")
            else:
                receipt = self.economy.begin_battle(
                    battle_id, reward_policy=mode,
                )
                canonical = self._validate_allocation_context(
                    context,
                    receipt["loadout"],
                    expected_profile_saved=self.adapter.wire_saved(snapshot["saved"]),
                    exact_profile_saved=False,
                    allow_legacy_frozen_unit_abilities=True,
                )
            return {
                "battle_id": battle_id,
                "loadout": copy.deepcopy(receipt["loadout"]),
                "context": canonical,
                "saved": receipt["saved"],
            }

    def begin_pve_allocation(self, battle_id: str, context: object) -> dict:
        if not isinstance(context, dict) or context.get("mode") != "pve":
            raise EconomyError("invalid_allocation_mode")
        return self.begin_public_allocation(battle_id, context)

    def settle_native_public_result(
        self,
        battle_id: str,
        final_request: object,
        context: object,
        *,
        battle_phase: str,
    ) -> dict:
        """Validate a proven native final report and return settlement metadata.

        The caller retains and publishes the original native result rows.  No
        reward field or new result schema is injected by this method.
        """
        with self._lock:
            self._disarm_selection_zero_read()
            self._disarm_profile_graph_zero_followup()
            self._disarm_external_profile_refresh()
            if battle_phase not in {
                "result_reported", "result_ready", "settled", "delivered",
            }:
                raise EconomyError("battle_result_state_mismatch")
            snapshot = self.economy.snapshot()
            battle = snapshot["battles"].get(battle_id)
            if battle is None:
                raise EconomyError("battle_not_found")
            begin = snapshot["operations"].get(battle["begin_operation"])
            receipt = begin.get("receipt") if isinstance(begin, dict) else None
            loadout = receipt.get("loadout") if isinstance(receipt, dict) else None
            if not isinstance(loadout, dict):
                raise EconomyError("invalid_battle_operation")
            canonical = self._validate_allocation_context(
                context,
                loadout,
                expected_profile_saved=self.adapter.wire_saved(snapshot["saved"]),
                exact_profile_saved=False,
                allow_legacy_frozen_unit_abilities=True,
            )
            party_id = canonical.get("party_id")
            if party_id is None:
                raise EconomyError("unverifiable_battle_party")
            if not isinstance(canonical.get("map"), str):
                raise EconomyError("unverifiable_battle_map")
            outcome, verified = resolve_native_final_outcome(
                final_request,
                user_id=self.user_id,
                party_id=party_id,
                map_key=canonical["map"],
                commander_key=loadout["commander"],
                result_participants=canonical.get("result_participants"),
                roster_policy=canonical.get("roster_policy"),
                display_name=canonical.get("display_name"),
            )
            return self.economy.settle_battle(
                battle_id,
                outcome,
                battle["roster_hash"],
                verified=verified,
                reward_policy=canonical["mode"],
            )

    def settle_native_pve_result(
        self,
        battle_id: str,
        final_request: object,
        context: object,
        *,
        battle_phase: str,
    ) -> dict:
        if not isinstance(context, dict) or context.get("mode") != "pve":
            raise EconomyError("invalid_allocation_mode")
        return self.settle_native_public_result(
            battle_id, final_request, context, battle_phase=battle_phase,
        )


__all__ = [
    "NativeEconomyService",
    "native_final_result_rows",
    "native_result_schema_fingerprint",
    "resolve_native_final_outcome",
]
