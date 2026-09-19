"""Cloud battle registration and server-authoritative settlement (option C).

``docs/archive/pve_e2e_audit_20260902.md`` 5-2(4) chose option C: the companion keeps
computing the *base* reward amounts from its own catalogue, and the Cloudflare
Worker owns the multiplier, the AFK/abort zeroing, the reward caps and the
exactly-once rule (``private-server/src/settlement.ts``).  This module is the
companion half of that split.

Flow
----
1. ``/check`` freezes the roster  ->  ``POST /v1/battles``  ->  ``battleId``
   is stored in the SQLite allocation context as ``cloud_battle_id``.
2. the final ``/event`` arrives   ->  base amounts from ``reward_quote``
   ->  ``POST /v1/battles/:id/result``  ->  the returned ``awarded`` amounts
   are registered on ``LocalEconomy`` and applied by ``settle_battle``.
3. the Worker is unreachable / rejects  ->  a zero award is registered and the
   settlement is marked ``settlement_pending``.  Rewards fail closed; the
   client's result screen is never blocked, because the native result rows and
   the local lifecycle are untouched.

Frozen legacy ``standard-reward-v1`` battles retain base-derived rewards.
Frozen ``public-fxp-reward-v2`` battles retain their fixed-outcome Free XP
contract. New standard battles use ``public-zero-reward-v3`` and award zero
in every currency, including Free XP, while preserving the result record.
``wasAfk`` is reported rather than pre-applied because the Worker owns the
authoritative AFK/abort zeroing. See ``docs/CURRENT_SPEC.md``.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Protocol, runtime_checkable

from local_economy import REWARD_AMOUNT_FIELDS, EconomyError, LocalEconomy
from native_cloud_loadout import CloudLoadoutError, sync_cloud_loadout
from native_battle_maps import is_native_battle_map, native_battle_map_key

UINT64_MASK = (1 << 64) - 1
SETTLEMENT_AUTHORITY = "cloudflare-worker"
LOCAL_AUTHORITY = "local"
# private-server/src/battles.ts reportBattleResult: 409 when this seat's
# implied winner contradicts the winner the first report already fixed.
RESULT_DISAGREEMENT = "result_disagreement"
ZERO_AWARD = {field: 0 for field in REWARD_AMOUNT_FIELDS}
# private-server/src/battles.ts RESULT_ROWS_LIMIT.
RESULT_ROWS_LIMIT = 64 * 1024
PUBLIC_ZERO_POLICY_ID = "public-zero-reward-v3"
PUBLIC_FXP_POLICY_ID = "public-fxp-reward-v2"
STANDARD_POLICY_ID = "standard-reward-v1"
PUBLIC_FXP_OUTCOMES = {
    "victory": 300_000, "draw": 250_000, "defeat": 200_000, "aborted": 0,
}


class BattleApiError(Exception):
    """A cloud battle failure with a stable, value-free code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@runtime_checkable
class BattleApi(Protocol):
    """The two Worker routes the PvE flow needs."""

    def create_battle(self, mode: str, ruleset: str, loadout: dict,
                      map_key: str | None = None) -> dict:
        """-> ``{battleId, mapKey, rewardPolicy}``."""

    def report_result(self, battle_id: str, payload: dict) -> dict:
        """-> the Worker's settlement view for this participant."""


def uint64_text(value: object) -> str:
    """Native item IDs travel to the Worker as unsigned decimal strings."""
    if type(value) is not int or not -(1 << 63) <= value <= UINT64_MASK:
        raise BattleApiError("invalid_item_id")
    return str(value & UINT64_MASK)


def worker_loadout(context: dict) -> dict:
    """Build ``POST /v1/battles`` ``loadout`` from a frozen allocation context."""
    if not isinstance(context, dict):
        raise BattleApiError("invalid_battle_context")
    commander = context.get("commander_item_id")
    units = context.get("unit_item_ids")
    tier = context.get("battle_tier")
    if not isinstance(units, list) or len(units) != 3:
        raise BattleApiError("invalid_battle_context")
    if type(tier) is not int or not 1 <= tier <= 10:
        raise BattleApiError("invalid_battle_context")
    return {
        "commanderId": uint64_text(commander),
        "unitIds": [uint64_text(item) for item in units],
        "tier": tier,
    }


def report_hash(durable_event: object) -> str:
    """Stable fingerprint of the native final report (Worker: 16-128 chars)."""
    encoded = json.dumps(durable_event, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class FakeBattleApi:
    """Deterministic in-memory ``BattleApi`` mirroring the Worker's rules."""

    def __init__(self, *, multiplier: float = 1.0,
                 reward_policy: dict | None = None,
                 battle_id: str = "11111111-1111-4111-8111-111111111111") -> None:
        self.multiplier = multiplier
        self.battle_id = battle_id
        self.reward_policy = reward_policy or {
            "policyId": STANDARD_POLICY_ID, "authority": "server",
            "modeMultiplier": multiplier, "afkMultiplier": 0,
        }
        self.created: list[dict] = []
        self.reported: list[tuple[str, dict]] = []
        self.settlements: dict[str, dict] = {}
        self.fail_create: Exception | None = None
        self.fail_report: Exception | None = None

    def create_battle(self, mode: str, ruleset: str, loadout: dict,
                      map_key: str | None = None) -> dict:
        if self.fail_create is not None:
            error, self.fail_create = self.fail_create, None
            raise error
        if mode not in ("pve", "pvp") or ruleset not in ("territory", "annihilation"):
            raise BattleApiError("invalid_battle_request")
        expected_map = native_battle_map_key(ruleset)
        if map_key is not None and not is_native_battle_map(map_key, ruleset):
            raise BattleApiError("invalid_map_key")
        self.created.append({"mode": mode, "ruleset": ruleset, "loadout": loadout,
                             "mapKey": map_key})
        return {
            "battleId": self.battle_id,
            "mapKey": map_key or expected_map,
            "rewardPolicy": json.loads(json.dumps(self.reward_policy)),
        }

    def report_result(self, battle_id: str, payload: dict) -> dict:
        if self.fail_report is not None:
            error, self.fail_report = self.fail_report, None
            raise error
        if battle_id != self.battle_id:
            raise BattleApiError("battle_not_found")
        existing = self.settlements.get(battle_id)
        if existing is not None:
            if existing["reportHash"] != payload.get("reportHash"):
                raise BattleApiError("settlement_conflict")
            return json.loads(json.dumps(existing))
        base = payload["base"]
        zero_reason = ("afk" if payload.get("wasAfk")
                       else "aborted" if payload.get("result") == "aborted" else None)
        multiplier = 0 if zero_reason else self.multiplier

        def scale(value: int) -> int:
            return int(value * multiplier)

        if self.reward_policy["policyId"] in (PUBLIC_FXP_POLICY_ID, PUBLIC_ZERO_POLICY_ID):
            awarded = {"silver": 0,
                       "freeXp": (0 if zero_reason == "afk" else
                                  self.reward_policy["outcomeAwards"][payload.get("result")]),
                       "commanderXp": 0, "unitXp": []}
            applied_multiplier = None
        else:
            awarded = {
                "silver": scale(base["silver"]),
                "freeXp": scale(base["freeXp"]),
                "commanderXp": scale(base["commanderXp"]),
                "unitXp": [{"unitId": unit["unitId"], "xp": scale(unit["xp"])}
                           for unit in base["unitXp"]],
            }
            applied_multiplier = multiplier
        settlement = {
            "battleId": battle_id,
            "result": payload.get("result"),
            "wasAfk": bool(payload.get("wasAfk")),
            "base": base,
            "reportHash": payload.get("reportHash"),
            "settlement": {
                "policyId": self.reward_policy["policyId"], "authority": "server",
                "appliedMultiplier": applied_multiplier, "zeroReason": zero_reason,
                "awarded": awarded,
            },
        }
        self.settlements[battle_id] = settlement
        self.reported.append((battle_id, payload))
        return json.loads(json.dumps(settlement))


class CloudBattleApi:
    """``BattleApi`` over ``companion.api_client.ApiClient``.

    The client module is imported lazily by the caller (see
    :func:`battle_api_from_api_client`), so ``server/`` keeps working with no
    ``companion`` package installed.
    """

    def __init__(self, client: object) -> None:
        self._client = client
        self._errors = _api_client_errors()

    def create_battle(self, mode: str, ruleset: str, loadout: dict,
                      map_key: str | None = None) -> dict:
        try:
            sync_cloud_loadout(
                self._client, loadout.get("commanderId"), loadout.get("unitIds"),
                api_errors=self._errors)
        except CloudLoadoutError as error:
            raise BattleApiError(error.code) from None
        # Build one callable for either API shape.  Keeping the conditional
        # outside the lambda is important: a conditional nested in the lambda
        # would return the no-map lambda itself when ``map_key`` is omitted,
        # so the client would never receive the create request.
        if map_key is None:
            action = lambda: self._client.create_battle(mode, ruleset, loadout)
        else:
            action = lambda: self._client.create_battle(
                mode, ruleset, loadout, map_key)
        view = self._call(action)
        if not isinstance(view, dict) or not isinstance(view.get("battleId"), str):
            raise BattleApiError("invalid_battle_response")
        return {"battleId": view["battleId"], "mapKey": view.get("mapKey"),
                "rewardPolicy": view.get("rewardPolicy")}

    def report_result(self, battle_id: str, payload: dict) -> dict:
        view = self._call(
            lambda: self._client.report_battle_result(battle_id, payload))
        if not isinstance(view, dict) or not isinstance(view.get("settlement"), dict):
            raise BattleApiError("invalid_settlement_response")
        return view

    def _call(self, action, *, on_commander_mismatch: object = None):
        api_error, conflict, network = self._errors
        try:
            return action()
        except conflict as error:
            code = str(getattr(error, "code", "conflict"))
            # The Worker pins the battle loadout to the account's selected
            # commander.  Sync it once, then retry exactly once.
            if (on_commander_mismatch is not None
                    and code in ("loadout_commander_mismatch", "commander_selection_required")
                    and self._select_commander(on_commander_mismatch)):
                try:
                    return action()
                except (api_error, network) as retry_error:
                    raise BattleApiError(str(getattr(retry_error, "code", "unreachable"))) from None
            raise BattleApiError(code) from None
        except api_error as error:
            raise BattleApiError(str(getattr(error, "code", "error"))) from None
        except network:
            raise BattleApiError("worker_unreachable") from None

    def _select_commander(self, commander_id: object) -> bool:
        selector = getattr(self._client, "select_commander", None)
        if not callable(selector) or not isinstance(commander_id, str):
            return False
        try:
            selector(commander_id)
        except Exception:
            return False
        return True


def _api_client_errors() -> tuple[type, type, type]:
    try:
        from companion.api_client import ApiError, ConflictError, NetworkError
    except Exception:  # pragma: no cover - companion package is optional
        class _Missing(Exception):
            pass
        return _Missing, _Missing, _Missing
    return ApiError, ConflictError, NetworkError


def battle_api_from_api_client(client: object) -> CloudBattleApi:
    if not hasattr(client, "create_battle") or not hasattr(client, "report_battle_result"):
        raise BattleApiError("invalid_battle_api")
    return CloudBattleApi(client)


class CloudSettlementAuthority:
    """Register a cloud battle and apply the Worker's settlement amounts.

    Every method fails *closed for rewards and open for the client*: a cloud
    error returns a zero award plus ``settlement_pending`` rather than raising,
    so the native result flow (rows, ``/battle_results``, hangar return) keeps
    working exactly as it does in pure-local mode.
    """

    def __init__(self, battle_api: BattleApi, *, trace=None) -> None:
        self.battle_api = battle_api
        self._trace = trace
        self._registered: dict[str, str | None] = {}
        self._registered_policies: dict[str, dict] = {}
        self._registered_maps: dict[str, str] = {}

    # -- allocation ------------------------------------------------------

    def register_battle(self, battle_id: str, context: dict) -> str | None:
        """Create the cloud battle for one frozen roster; ``None`` on failure.

        Memoized by the local ``battle_id`` (including a failure) because the
        frozen allocation context is digest-compared on every ``/check`` retry:
        a second cloud battle would change that digest and turn an idempotent
        retry into ``allocation_conflict``.
        """
        if battle_id in self._registered:
            requested_map = context.get("map")
            frozen_map = self._registered_maps.get(battle_id)
            if (requested_map is not None and frozen_map is not None
                    and requested_map != frozen_map):
                self._emit("cloud_battle_registration_failed", reason="map_conflict")
                return None
            return self._registered[battle_id]
        result = self._create_battle(context)
        cloud_id = result[0] if result is not None else None
        self._registered[battle_id] = cloud_id
        if result is not None:
            self._registered_policies[battle_id] = result[1]
            requested_map = context.get("map")
            if isinstance(requested_map, str):
                self._registered_maps[battle_id] = requested_map
        return cloud_id

    def registered_reward_policy(self, battle_id: str) -> dict | None:
        """Return the exact policy captured with a successful registration."""
        policy = self._registered_policies.get(battle_id)
        return json.loads(json.dumps(policy)) if policy is not None else None

    def bind_assigned_battle(self, battle_id: str,
                             reward_policy: object = None) -> str:
        """Record a Worker-created PvP battle as its own cloud battle.

        ``POST /v1/battles/from-assignment`` already created the battle for
        both participants, and the native ``battle_id`` *is* the Worker
        ``battleId``; nothing is created here.  Memoized like
        :meth:`register_battle` so a ``/check`` retry stays idempotent.
        """
        if not isinstance(battle_id, str) or not 1 <= len(battle_id) <= 64:
            raise BattleApiError("invalid_battle_id")
        if reward_policy is not None:
            policy = self._reward_policy(reward_policy)
            prior = self._registered_policies.get(battle_id)
            if prior is not None and prior != policy:
                raise BattleApiError("cloud_battle_conflict")
            self._registered_policies[battle_id] = policy
        existing = self._registered.get(battle_id)
        if existing is not None and existing != battle_id:
            raise BattleApiError("cloud_battle_conflict")
        self._registered[battle_id] = battle_id
        self._emit("cloud_battle_bound", mode="pvp")
        return battle_id

    def _create_battle(self, context: dict) -> tuple[str, dict] | None:
        mode = context.get("mode")
        ruleset = context.get("ruleset")
        if mode != "pve" or ruleset not in ("territory", "annihilation"):
            # PvP battles exist before /check (from-assignment); see
            # bind_assigned_battle.  Never create a second one here.
            self._emit("cloud_battle_registration_skipped", reason="unsupported_mode")
            return None
        try:
            loadout = worker_loadout(context)
            requested_map = context.get("map")
            if requested_map is not None and not isinstance(requested_map, str):
                raise BattleApiError("invalid_map_key")
            view = self.battle_api.create_battle(mode, ruleset, loadout, requested_map)
        except (BattleApiError, KeyError, TypeError, ValueError) as error:
            self._emit("cloud_battle_registration_failed",
                       reason=getattr(error, "code", type(error).__name__))
            return None
        battle_id = view.get("battleId") if isinstance(view, dict) else None
        if not isinstance(battle_id, str) or not 1 <= len(battle_id) <= 64:
            self._emit("cloud_battle_registration_failed", reason="invalid_battle_id")
            return None
        returned_map = view.get("mapKey")
        if not isinstance(returned_map, str):
            self._emit("cloud_battle_registration_failed", reason="invalid_map_key")
            return None
        requested_map = context.get("map")
        if requested_map is not None and returned_map != requested_map:
            self._emit("cloud_battle_registration_failed", reason="map_conflict")
            return None
        try:
            policy = self._reward_policy(view.get("rewardPolicy"))
        except BattleApiError as error:
            self._emit("cloud_battle_registration_failed", reason=error.code)
            return None
        self._emit("cloud_battle_registered", ruleset=ruleset)
        return battle_id, policy

    # -- settlement ------------------------------------------------------

    @staticmethod
    def base_amounts(battle_tier: int, outcome: str) -> dict:
        """Local base amounts: outcome percentage only, no mode multiplier."""
        return LocalEconomy.reward_quote(
            battle_tier, outcome, True, reward_policy="pve")

    def authorize(
        self,
        economy: LocalEconomy,
        *,
        match_id: str,
        cloud_battle_id: object,
        battle_tier: int,
        unit_item_ids: list,
        outcome: str,
        verified: bool,
        durable_event: object,
        result_rows: list,
        reward_policy: object = None,
    ) -> dict:
        """Decide the amounts ``settle_battle`` must apply for ``match_id``.

        Returns ``{"authority", "amounts", "settlement_pending", "reason"}``
        and leaves the decision registered on ``economy``.
        """
        if not isinstance(cloud_battle_id, str) or not cloud_battle_id:
            return self._pending(economy, match_id, "cloud_battle_missing")
        try:
            policy = self._reward_policy(reward_policy, legacy_missing=True)
            quote = self.base_amounts(battle_tier, outcome)
            unit_ids = [uint64_text(item) for item in unit_item_ids]
        except (BattleApiError, EconomyError, TypeError, ValueError) as error:
            return self._pending(economy, match_id,
                                 getattr(error, "code", "invalid_base_amounts"))
        distinct: list[str] = []
        for unit_id in unit_ids:
            if unit_id not in distinct:
                distinct.append(unit_id)
        if policy["policyId"] in (PUBLIC_FXP_POLICY_ID, PUBLIC_ZERO_POLICY_ID):
            base = {"silver": 0, "freeXp": 0, "commanderXp": 0, "unitXp": []}
        else:
            base = {
                "silver": quote["silver_cents"],
                "freeXp": quote["free_xp_cents"],
                "commanderXp": quote["commander_xp_cents"],
                "unitXp": [{"unitId": unit_id, "xp": quote["unit_xp_cents"]}
                           for unit_id in distinct],
            }
        payload = {
            "result": outcome,
            # The Worker, not this process, decides what an AFK report earns.
            "wasAfk": not verified,
            "base": base,
            "resultRows": result_rows if isinstance(result_rows, list) else [],
            "reportHash": report_hash(durable_event),
        }
        if len(json.dumps(payload["resultRows"], separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")) > RESULT_ROWS_LIMIT:
            payload["resultRows"] = []
        try:
            view = self.battle_api.report_result(cloud_battle_id, payload)
            self._validate_settlement_view(
                view, cloud_battle_id, payload, policy, outcome, verified)
            amounts = self.applied_amounts(view)
        except BattleApiError as error:
            if error.code == RESULT_DISAGREEMENT:
                # PvP: this report contradicts the winner the other seat
                # already settled.  The Worker flagged the battle for review
                # and will never settle this seat; award zero, mark disputed
                # and let the client's result screen proceed.
                return self._disputed(economy, match_id)
            return self._pending(economy, match_id, error.code)
        except (KeyError, TypeError, ValueError) as error:
            return self._pending(economy, match_id, type(error).__name__)
        try:
            economy.register_settlement_award(
                match_id, amounts, authority=SETTLEMENT_AUTHORITY)
        except EconomyError as error:
            return self._pending(economy, match_id, error.code)
        self._emit("cloud_settlement_applied", outcome=outcome, verified=verified)
        return {"authority": SETTLEMENT_AUTHORITY, "amounts": amounts,
                "settlement_pending": False, "reason": None}

    @staticmethod
    def _reward_policy(value: object, *, legacy_missing: bool = False) -> dict:
        if value is None and legacy_missing:
            return {"policyId": STANDARD_POLICY_ID, "authority": "server",
                    "modeMultiplier": 1, "afkMultiplier": 0}
        if not isinstance(value, dict) or value.get("authority") != "server":
            raise BattleApiError("invalid_reward_policy")
        policy_id = value.get("policyId")
        if policy_id in (PUBLIC_FXP_POLICY_ID, PUBLIC_ZERO_POLICY_ID):
            expected = {"policyId": policy_id, "authority": "server",
                        "currency": "free_xp_cents",
                        "outcomeAwards": ({key: 0 for key in PUBLIC_FXP_OUTCOMES}
                                          if policy_id == PUBLIC_ZERO_POLICY_ID else dict(PUBLIC_FXP_OUTCOMES)),
                        "afkAward": 0, "otherRewardsZero": True}
            awards = value.get("outcomeAwards")
            if (set(value) != set(expected) or not isinstance(awards, dict)
                    or set(awards) != set(PUBLIC_FXP_OUTCOMES)
                    or any(type(awards[key]) is not int
                           for key in PUBLIC_FXP_OUTCOMES)
                    or type(value.get("afkAward")) is not int
                    or type(value.get("otherRewardsZero")) is not bool
                    or value != expected):
                raise BattleApiError("invalid_reward_policy")
        elif policy_id == STANDARD_POLICY_ID:
            if (set(value) != {"policyId", "authority", "modeMultiplier", "afkMultiplier"}
                    or type(value.get("modeMultiplier")) not in (int, float)
                    or isinstance(value.get("modeMultiplier"), bool)
                    or value.get("modeMultiplier") not in (1, 1.5)
                    or type(value.get("afkMultiplier")) is not int
                    or value.get("afkMultiplier") != 0):
                raise BattleApiError("invalid_reward_policy")
        else:
            raise BattleApiError("invalid_reward_policy")
        return json.loads(json.dumps(value))

    @staticmethod
    def _validate_settlement_view(view: object, battle_id: str, payload: dict,
                                  policy: dict, outcome: str,
                                  verified: bool) -> None:
        if (not isinstance(view, dict) or view.get("battleId") != battle_id
                or view.get("result") != outcome
                or view.get("wasAfk") is not (not verified)
                or view.get("base") != payload["base"]
                or view.get("reportHash") != payload["reportHash"]):
            raise BattleApiError("invalid_settlement_response")
        settlement = view.get("settlement")
        if not isinstance(settlement, dict) or settlement.get("policyId") != policy["policyId"] \
                or settlement.get("authority") != "server":
            raise BattleApiError("invalid_settlement_response")
        if policy["policyId"] not in (PUBLIC_FXP_POLICY_ID, PUBLIC_ZERO_POLICY_ID):
            return
        zero_reason = "afk" if not verified else "aborted" if outcome == "aborted" else None
        free_xp = 0 if not verified else policy["outcomeAwards"][outcome]
        expected = {"silver": 0, "freeXp": free_xp, "commanderXp": 0, "unitXp": []}
        awarded = settlement.get("awarded")
        if (set(settlement) != {"policyId", "authority", "appliedMultiplier",
                               "zeroReason", "awarded"}
                or settlement["appliedMultiplier"] is not None
                or settlement.get("zeroReason") != zero_reason
                or not isinstance(awarded, dict) or set(awarded) != set(expected)
                or any(type(awarded[key]) is not int
                       for key in ("silver", "freeXp", "commanderXp"))
                or not isinstance(awarded["unitXp"], list)
                or awarded != expected):
            raise BattleApiError("invalid_settlement_response")

    @staticmethod
    def applied_amounts(view: object) -> dict:
        """Map the Worker's ``awarded`` object onto local ``*_cents`` fields."""
        settlement = view.get("settlement") if isinstance(view, dict) else None
        awarded = settlement.get("awarded") if isinstance(settlement, dict) else None
        if not isinstance(awarded, dict):
            raise BattleApiError("invalid_settlement_response")
        unit_xp = awarded.get("unitXp")
        if not isinstance(unit_xp, list):
            raise BattleApiError("invalid_settlement_response")
        values = set()
        for entry in unit_xp:
            if not isinstance(entry, dict) or type(entry.get("xp")) is not int:
                raise BattleApiError("invalid_settlement_response")
            values.add(entry["xp"])
        if len(values) > 1:
            # The base is one uniform per-unit amount and the Worker applies a
            # single multiplier, so a non-uniform reply is a contract break.
            raise BattleApiError("non_uniform_unit_award")
        amounts = {
            "silver_cents": awarded.get("silver"),
            "free_xp_cents": awarded.get("freeXp"),
            "commander_xp_cents": awarded.get("commanderXp"),
            "unit_xp_cents": values.pop() if values else 0,
        }
        for value in amounts.values():
            if type(value) is not int or value < 0:
                raise BattleApiError("invalid_settlement_response")
        return amounts

    # -- fail-closed helper ----------------------------------------------

    def fail_closed(self, economy: LocalEconomy, match_id: str, reason: str) -> dict:
        """Register a zero award so no local amount can be applied instead."""
        return self._pending(economy, match_id, reason)

    def _pending(self, economy: LocalEconomy, match_id: str, reason: str) -> dict:
        try:
            economy.register_settlement_award(
                match_id, dict(ZERO_AWARD), authority=LOCAL_AUTHORITY)
        except EconomyError:
            pass
        self._emit("cloud_settlement_pending", reason=str(reason)[:64])
        return {"authority": LOCAL_AUTHORITY, "amounts": dict(ZERO_AWARD),
                "settlement_pending": True, "reason": str(reason)[:64]}

    def _disputed(self, economy: LocalEconomy, match_id: str) -> dict:
        """A final zero: the Worker rejected this seat's contradictory report."""
        try:
            economy.register_settlement_award(
                match_id, dict(ZERO_AWARD), authority=LOCAL_AUTHORITY)
        except EconomyError:
            pass
        self._emit("cloud_settlement_disputed")
        return {"authority": LOCAL_AUTHORITY, "amounts": dict(ZERO_AWARD),
                "settlement_pending": False, "reason": RESULT_DISAGREEMENT,
                "disputed": True}

    def _emit(self, event: str, **fields: Any) -> None:
        if self._trace is None:
            return
        try:
            self._trace({"event": event, **fields})
        except Exception:  # pragma: no cover - tracing must never fail a battle
            pass


__all__ = [
    "BattleApi",
    "BattleApiError",
    "CloudBattleApi",
    "CloudSettlementAuthority",
    "FakeBattleApi",
    "LOCAL_AUTHORITY",
    "RESULT_DISAGREEMENT",
    "RESULT_ROWS_LIMIT",
    "SETTLEMENT_AUTHORITY",
    "ZERO_AWARD",
    "battle_api_from_api_client",
    "report_hash",
    "uint64_text",
    "worker_loadout",
]
