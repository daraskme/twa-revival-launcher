"""Explicit, opt-in specialization economy layered over schema-12 LocalEconomy.

Importing and default construction never enable or migrate specialization.
An explicit fresh-account bootstrap may atomically enable it before the first
backend persist; loaded profiles remain unchanged. All durable policy state is
an audited operation receipt in the existing journal.
"""
from __future__ import annotations

import copy

from commander_specialization_policy import (
    FIXED_20_POLICY_VERSION, LEGACY_POLICY_VERSION, POLICY_VERSION,
    SpecializationPolicyError, derive_policies, evaluate_selection, point_balance,
)
from economy_backend import CloudEconomyBackend, FileEconomyBackend
from local_economy import (EconomyError, LocalEconomy, MAX_BALANCE,
    REWARD_AMOUNT_FIELDS, _canonical_hash)
from native_commander_talents import load_native_commander_talents
from specialization_ui_status import build_specialization_ui_status


INITIAL_ENTITLEMENT = 20
# V1 receipts remain immutable evidence for accounts created under the old
# purchasable, exclusive-route draft. V2 fixed-20 receipts also remain
# immutable; new writes use the fixed-30 open-route policy.
PREVIOUS_FIXED_TALENT_BUDGET = 20
FIXED_TALENT_BUDGET = 30
BOOTSTRAP_OPERATION_ID = "bootstrap-new-account-specializations-v3-fixed-30"
FIXED_BUDGET_MIGRATION_KIND = "migrate_specializations_fixed_budget"
FIXED_30_MIGRATION_KIND = "migrate_specializations_fixed_30"
TALENT_POINT_PRICE_FREE_XP_CENTS = 1_000_000
REWARD_PROFILE = "specialization-free-xp-v1"
FREE_XP_REWARD_CENTS = {
    "victory": 300_000,
    "draw": 250_000,
    "defeat": 200_000,
    "aborted": 0,
}


class SpecializationEconomy(LocalEconomy):
    """LocalEconomy with an explicitly enabled, journal-derived talent policy."""

    def __init__(self, native: dict, *args,
                 bootstrap_new_specializations: bool = False, **kwargs):
        if type(bootstrap_new_specializations) is not bool:
            raise EconomyError("invalid_specialization_bootstrap")
        self._bootstrap_new_specializations = bootstrap_new_specializations
        self._specialization_native = copy.deepcopy(native)
        self._specialization_talents = load_native_commander_talents()
        self.specialization_policies = derive_policies(native, self._specialization_talents)
        super().__init__(native, *args, **kwargs)

    def _enable_specializations_state(self, state: dict) -> dict:
        if self._journal(state)[0] is not None:
            raise EconomyError("specializations_already_enabled")
        if self._pending_battle(state):
            raise EconomyError("specialization_change_pending_battle")
        for key, policy in self.specialization_policies.items():
            commander = state.get("commanders", {}).get(key)
            if commander is None:
                raise EconomyError("commander_not_owned")
            if commander.get("tier") != 10:
                raise EconomyError("specialization_requires_tier_x")
            commander["abilities"] = {root: 1 for root in policy.roots}
            commander["talent_points"] = FIXED_TALENT_BUDGET
        return {"policy_version": POLICY_VERSION,
                "fixed_talent_budget": FIXED_TALENT_BUDGET,
                "commanders_reset": sorted(self.specialization_policies)}

    def _prepare_new_account(self, state: dict) -> bool:
        if not self._bootstrap_new_specializations:
            return False
        details = self._enable_specializations_state(state)
        request = {"policy_version": POLICY_VERSION}
        saved = state["saved"]
        receipt = {"operation_id": BOOTSTRAP_OPERATION_ID,
                   "kind": "enable_specializations", "saved": saved,
                   **details}
        state["operations"][BOOTSTRAP_OPERATION_ID] = {
            "request_hash": _canonical_hash({
                "kind": "enable_specializations", "request": request}),
            "receipt": receipt,
        }
        return True

    def _persist(self, state: dict) -> None:
        if self._journal(state)[0] is None:
            return super()._persist(state)
        if isinstance(self._backend, CloudEconomyBackend):
            # The cloud backend compares its separately tracked stored
            # revision; the blob's native watermark must remain untouched.
            return super()._persist(state)
        if not isinstance(self._backend, FileEconomyBackend):
            if self._backend is None:
                return
            raise EconomyError("specialization_requires_guarded_backend")
        # Keep inactive legacy behavior byte-for-byte compatible.  The file
        # watermark guard is enabled only for a specialization-state write.
        prior = self._backend._enforce
        self._backend._enforce = True
        try:
            return super()._persist(state)
        finally:
            self._backend._enforce = prior

    @staticmethod
    def _pending_battle(state: dict) -> bool:
        return any(item.get("status") == "pending" for item in state.get("battles", {}).values())

    def _journal(self, state: dict) -> tuple[
            dict | None, dict[str, int], dict | None]:
        enable = None
        migration = None
        current_version = None
        purchases = {key: 0 for key in self.specialization_policies}
        relevant = []
        for operation_id, entry in state.get("operations", {}).items():
            receipt = entry.get("receipt", {})
            kind = receipt.get("kind")
            if kind in {"enable_specializations", "purchase_talent_point",
                        "respec_commander", FIXED_BUDGET_MIGRATION_KIND,
                        FIXED_30_MIGRATION_KIND}:
                saved = receipt.get("saved")
                if (type(saved) is not int or not 0 < saved <= state.get("saved", 0)
                        or receipt.get("operation_id") != operation_id):
                    raise EconomyError("invalid_specialization_journal")
                relevant.append((saved, operation_id, entry, receipt))
        relevant.sort()
        if len({item[0] for item in relevant}) != len(relevant):
            raise EconomyError("invalid_specialization_journal")
        for _saved, operation_id, entry, receipt in relevant:
            kind = receipt["kind"]
            if kind == "enable_specializations":
                version = receipt.get("policy_version")
                legacy = version == LEGACY_POLICY_VERSION
                fixed_budget = {
                    FIXED_20_POLICY_VERSION: PREVIOUS_FIXED_TALENT_BUDGET,
                    POLICY_VERSION: FIXED_TALENT_BUDGET,
                }.get(version)
                expected = ({"operation_id", "kind", "saved", "policy_version",
                             "initial_entitlement", "commanders_reset"} if legacy
                            else {"operation_id", "kind", "saved", "policy_version",
                                  "fixed_talent_budget", "commanders_reset"})
                if (set(receipt) != expected or enable is not None
                        or version not in {LEGACY_POLICY_VERSION,
                                           FIXED_20_POLICY_VERSION,
                                           POLICY_VERSION}
                        or (legacy and (type(receipt.get("initial_entitlement"))
                            is not int or receipt.get("initial_entitlement") !=
                            INITIAL_ENTITLEMENT))
                        or (not legacy and
                            (type(receipt.get("fixed_talent_budget")) is not int
                             or receipt.get("fixed_talent_budget") !=
                             fixed_budget))):
                    raise EconomyError("invalid_specialization_journal")
                request = {"policy_version": version}
                if receipt["commanders_reset"] != sorted(self.specialization_policies):
                    raise EconomyError("invalid_specialization_journal")
                enable = receipt
                current_version = version
            elif kind == "purchase_talent_point":
                commander = receipt.get("commander")
                if (set(receipt) != {"operation_id","kind","saved","commander","amount",
                                    "price_free_xp_cents","policy_version","balance_free_xp_cents"}
                        or enable is None
                        or current_version != LEGACY_POLICY_VERSION
                        or commander not in purchases
                        or type(receipt.get("amount")) is not int or receipt["amount"] != 1
                        or type(receipt.get("price_free_xp_cents")) is not int
                        or receipt["price_free_xp_cents"] != TALENT_POINT_PRICE_FREE_XP_CENTS
                        or type(receipt.get("balance_free_xp_cents")) is not int
                        or not 0 <= receipt["balance_free_xp_cents"] <= MAX_BALANCE
                        or receipt.get("policy_version") != LEGACY_POLICY_VERSION):
                    raise EconomyError("invalid_specialization_journal")
                request = {"commander": commander, "amount": 1,
                           "price_free_xp_cents": TALENT_POINT_PRICE_FREE_XP_CENTS}
                purchases[commander] += 1
                if purchases[commander] > (
                        self.specialization_policies[commander].max_unselected_budget
                        - INITIAL_ENTITLEMENT):
                    raise EconomyError("invalid_specialization_journal")
            elif kind == "respec_commander":
                commander = receipt.get("commander")
                version = current_version
                legacy = version == LEGACY_POLICY_VERSION
                expected = ({"operation_id", "kind", "saved", "commander",
                             "policy_version", "entitled_total", "selected_route"}
                            if legacy else
                            {"operation_id", "kind", "saved", "commander",
                             "policy_version", "entitled_total", "selected_routes"})
                entitled = (INITIAL_ENTITLEMENT + purchases.get(commander, 0)
                            if legacy else PREVIOUS_FIXED_TALENT_BUDGET
                            if version == FIXED_20_POLICY_VERSION
                            else FIXED_TALENT_BUDGET)
                if (set(receipt) != expected or enable is None
                        or commander not in purchases
                        or receipt.get("policy_version") != version
                        or type(receipt.get("entitled_total")) is not int
                        or receipt["entitled_total"] != entitled
                        or (legacy and receipt.get("selected_route") is not None)
                        or (not legacy and receipt.get("selected_routes") != [])):
                    raise EconomyError("invalid_specialization_journal")
                request = {"commander": commander, "policy_version": version}
            elif kind == FIXED_BUDGET_MIGRATION_KIND:
                expected_purchases = dict(sorted(purchases.items()))
                if (set(receipt) != {"operation_id", "kind", "saved",
                                    "from_policy_version", "policy_version",
                                    "fixed_talent_budget", "historical_purchases",
                                    "commanders_preserved"}
                        or enable is None
                        or current_version != LEGACY_POLICY_VERSION
                        or receipt.get("from_policy_version") != LEGACY_POLICY_VERSION
                        or receipt.get("policy_version") != FIXED_20_POLICY_VERSION
                        or type(receipt.get("fixed_talent_budget")) is not int
                        or receipt.get("fixed_talent_budget") !=
                            PREVIOUS_FIXED_TALENT_BUDGET
                        or receipt.get("historical_purchases") != expected_purchases
                        or receipt.get("commanders_preserved") !=
                            sorted(self.specialization_policies)):
                    raise EconomyError("invalid_specialization_journal")
                request = {
                    "from_policy_version": LEGACY_POLICY_VERSION,
                    "policy_version": FIXED_20_POLICY_VERSION,
                    "fixed_talent_budget": PREVIOUS_FIXED_TALENT_BUDGET,
                    "historical_purchases": expected_purchases,
                }
                migration = receipt
                current_version = FIXED_20_POLICY_VERSION
            else:
                expected_purchases = dict(sorted(purchases.items()))
                if (set(receipt) != {"operation_id", "kind", "saved",
                                    "from_policy_version", "policy_version",
                                    "from_fixed_talent_budget", "fixed_talent_budget",
                                    "historical_purchases", "commanders_preserved"}
                        or enable is None
                        or current_version != FIXED_20_POLICY_VERSION
                        or receipt.get("from_policy_version") != FIXED_20_POLICY_VERSION
                        or receipt.get("policy_version") != POLICY_VERSION
                        or receipt.get("from_fixed_talent_budget") !=
                            PREVIOUS_FIXED_TALENT_BUDGET
                        or receipt.get("fixed_talent_budget") != FIXED_TALENT_BUDGET
                        or receipt.get("historical_purchases") != expected_purchases
                        or receipt.get("commanders_preserved") !=
                            sorted(self.specialization_policies)):
                    raise EconomyError("invalid_specialization_journal")
                request = {
                    "from_policy_version": FIXED_20_POLICY_VERSION,
                    "policy_version": POLICY_VERSION,
                    "from_fixed_talent_budget": PREVIOUS_FIXED_TALENT_BUDGET,
                    "fixed_talent_budget": FIXED_TALENT_BUDGET,
                    "historical_purchases": expected_purchases,
                }
                migration = receipt
                current_version = POLICY_VERSION
            if entry.get("request_hash") != _canonical_hash({"kind": kind, "request": request}):
                raise EconomyError("invalid_specialization_journal")
        return enable, purchases, migration

    @staticmethod
    def _effective_policy_version(enable: dict, migration: dict | None) -> str:
        return (migration.get("policy_version") if migration is not None
                else enable.get("policy_version"))

    @staticmethod
    def _budget_for_version(version: str) -> int:
        if version in {LEGACY_POLICY_VERSION, FIXED_20_POLICY_VERSION}:
            return PREVIOUS_FIXED_TALENT_BUDGET
        if version == POLICY_VERSION:
            return FIXED_TALENT_BUDGET
        raise EconomyError("invalid_specialization_journal")

    def specialization_enabled(self, snapshot: dict | None = None) -> bool:
        state = self.snapshot() if snapshot is None else snapshot
        return self._journal(state)[0] is not None

    def specialization_status(self, commander_key: str, snapshot: dict | None = None) -> dict:
        state = self.snapshot() if snapshot is None else snapshot
        enabled, purchases, migration = self._journal(state)
        if enabled is None:
            raise EconomyError("specializations_not_enabled")
        commander = state.get("commanders", {}).get(commander_key)
        if commander is None or commander_key not in self.specialization_policies:
            raise EconomyError("commander_not_owned")
        try:
            version = self._effective_policy_version(enabled, migration)
            legacy = version == LEGACY_POLICY_VERSION
            fixed_budget = self._budget_for_version(version)
            selection = evaluate_selection(
                self.specialization_policies[commander_key], self._specialization_native,
                self._specialization_talents, commander["abilities"], commander["tier"],
                exclusive_routes=legacy, fixed_budget=fixed_budget,
            )
            entitled = (INITIAL_ENTITLEMENT + purchases[commander_key]
                        if legacy else fixed_budget)
            balance = point_balance(
                selection, entitled, purchases_allowed=False)
        except (KeyError, SpecializationPolicyError) as exc:
            raise EconomyError("invalid_specialization_state") from exc
        return {"selected_route": selection["selected_route"],
                "selected_routes": selection["selected_routes"],
                "route_spent": selection["route_spent"], **balance,
                "fixed_talent_budget": fixed_budget,
                "purchase_enabled": False,
                "migration_required": version != POLICY_VERSION,
                "policy_version": version}

    def specialization_ui_status(self, commander_key: str, language: str,
                                 snapshot: dict | None = None) -> dict:
        state = self.snapshot() if snapshot is None else snapshot
        status = self.specialization_status(commander_key, state)
        return build_specialization_ui_status(
            self.specialization_policies[commander_key],
            status,
            state["wallet"]["free_xp_cents"], self._pending_battle(state), language,
        )

    def talent_point_totals(self, snapshot: dict | None = None) -> dict[str, int]:
        state = self.snapshot() if snapshot is None else snapshot
        if not self.specialization_enabled(state):
            return {key: self._talent_total_with_local_grants(
                state, key, item["tier"]) for key, item in state["commanders"].items()}
        return {key: self.specialization_status(key, state)["active_total"]
                for key in state["commanders"]}

    def _validate_extended_state(self, state: dict) -> None:
        enable, _purchases, _migration = self._journal(state)
        enable_saved = None if enable is None else enable["saved"]
        for entry in state.get("operations", {}).values():
            receipt = entry.get("receipt", {})
            if "reward_profile" not in receipt:
                continue
            if (receipt.get("reward_profile") != REWARD_PROFILE
                    or receipt.get("kind") not in {"begin_pve", "begin_pvp"}
                    or enable_saved is None
                    or type(receipt.get("saved")) is not int
                    or receipt["saved"] < enable_saved):
                raise EconomyError("invalid_battle_operation")

    def _talent_total_with_local_grants(self, state, commander_key, tier, grants=None):
        enabled, purchases, migration = self._journal(state)
        if enabled is None:
            return super()._talent_total_with_local_grants(state, commander_key, tier, grants)
        commander = state["commanders"][commander_key]
        version = self._effective_policy_version(enabled, migration)
        legacy = version == LEGACY_POLICY_VERSION
        fixed_budget = self._budget_for_version(version)
        selection = evaluate_selection(
            self.specialization_policies[commander_key], self._specialization_native,
            self._specialization_talents, commander["abilities"], tier,
            exclusive_routes=legacy, fixed_budget=fixed_budget,
        )
        entitlement = (INITIAL_ENTITLEMENT + purchases[commander_key]
                       if legacy else fixed_budget)
        return point_balance(
            selection, entitlement, purchases_allowed=False)["active_total"]

    def enable_specializations(self, operation_id: str) -> dict:
        request = {"policy_version": POLICY_VERSION}
        def apply(state): return self._enable_specializations_state(state)
        return self._run_operation(operation_id, "enable_specializations", request, apply)

    def migrate_specializations_fixed_budget(self, operation_id: str) -> dict:
        """Preserve the historical explicit V1-to-V2 fixed-20 transition."""
        snapshot = self.snapshot()
        enable, purchases, migration = self._journal(snapshot)
        if enable is None:
            raise EconomyError("specializations_not_enabled")
        version = self._effective_policy_version(enable, migration)
        replaying = (snapshot.get("operations", {}).get(operation_id, {})
                     .get("receipt", {}).get("kind") == FIXED_BUDGET_MIGRATION_KIND)
        if (version != LEGACY_POLICY_VERSION
                and not (version == FIXED_20_POLICY_VERSION and replaying)):
            raise EconomyError("specialization_migration_not_required")
        request = {
            "from_policy_version": LEGACY_POLICY_VERSION,
            "policy_version": FIXED_20_POLICY_VERSION,
            "fixed_talent_budget": PREVIOUS_FIXED_TALENT_BUDGET,
            "historical_purchases": dict(sorted(purchases.items())),
        }

        def apply(state):
            current_enable, current_purchases, current_migration = self._journal(state)
            if (current_enable is None or self._effective_policy_version(
                    current_enable, current_migration) != LEGACY_POLICY_VERSION):
                raise EconomyError("specialization_migration_not_required")
            if current_migration is not None:
                raise EconomyError("specialization_migration_already_applied")
            if dict(sorted(current_purchases.items())) != request["historical_purchases"]:
                raise EconomyError("specialization_migration_history_changed")
            if self._pending_battle(state):
                raise EconomyError("specialization_change_pending_battle")
            for key, policy in self.specialization_policies.items():
                commander = state.get("commanders", {}).get(key)
                if commander is None:
                    raise EconomyError("commander_not_owned")
                try:
                    selection = evaluate_selection(
                        policy, self._specialization_native,
                        self._specialization_talents, commander["abilities"],
                        commander["tier"], exclusive_routes=False,
                        fixed_budget=PREVIOUS_FIXED_TALENT_BUDGET,
                    )
                except (KeyError, SpecializationPolicyError) as exc:
                    raise EconomyError("fixed_budget_migration_requires_review") from exc
                commander["talent_points"] = (
                    PREVIOUS_FIXED_TALENT_BUDGET - selection["spent"])
            return {
                "from_policy_version": LEGACY_POLICY_VERSION,
                "policy_version": FIXED_20_POLICY_VERSION,
                "fixed_talent_budget": PREVIOUS_FIXED_TALENT_BUDGET,
                "historical_purchases": dict(sorted(current_purchases.items())),
                "commanders_preserved": sorted(self.specialization_policies),
            }

        return self._run_operation(
            operation_id, FIXED_BUDGET_MIGRATION_KIND, request, apply)

    def migrate_specializations_fixed_30(self, operation_id: str) -> dict:
        """Explicitly migrate one fixed-20 account to fixed 30, preserving choices."""
        snapshot = self.snapshot()
        enable, purchases, migration = self._journal(snapshot)
        if enable is None:
            raise EconomyError("specializations_not_enabled")
        version = self._effective_policy_version(enable, migration)
        replaying = (snapshot.get("operations", {}).get(operation_id, {})
                     .get("receipt", {}).get("kind") == FIXED_30_MIGRATION_KIND)
        if (version != FIXED_20_POLICY_VERSION
                and not (version == POLICY_VERSION and replaying)):
            raise EconomyError("specialization_migration_not_required")
        request = {
            "from_policy_version": FIXED_20_POLICY_VERSION,
            "policy_version": POLICY_VERSION,
            "from_fixed_talent_budget": PREVIOUS_FIXED_TALENT_BUDGET,
            "fixed_talent_budget": FIXED_TALENT_BUDGET,
            "historical_purchases": dict(sorted(purchases.items())),
        }

        def apply(state):
            current_enable, current_purchases, current_migration = self._journal(state)
            if (current_enable is None or self._effective_policy_version(
                    current_enable, current_migration) != FIXED_20_POLICY_VERSION):
                raise EconomyError("specialization_migration_not_required")
            if dict(sorted(current_purchases.items())) != request["historical_purchases"]:
                raise EconomyError("specialization_migration_history_changed")
            if self._pending_battle(state):
                raise EconomyError("specialization_change_pending_battle")
            for key, policy in self.specialization_policies.items():
                commander = state.get("commanders", {}).get(key)
                if commander is None:
                    raise EconomyError("commander_not_owned")
                try:
                    selection = evaluate_selection(
                        policy, self._specialization_native,
                        self._specialization_talents, commander["abilities"],
                        commander["tier"], exclusive_routes=False,
                        fixed_budget=FIXED_TALENT_BUDGET,
                    )
                except (KeyError, SpecializationPolicyError) as exc:
                    raise EconomyError("fixed_30_migration_requires_review") from exc
                commander["talent_points"] = (
                    FIXED_TALENT_BUDGET - selection["spent"])
            return {
                "from_policy_version": FIXED_20_POLICY_VERSION,
                "policy_version": POLICY_VERSION,
                "from_fixed_talent_budget": PREVIOUS_FIXED_TALENT_BUDGET,
                "fixed_talent_budget": FIXED_TALENT_BUDGET,
                "historical_purchases": dict(sorted(current_purchases.items())),
                "commanders_preserved": sorted(self.specialization_policies),
            }

        return self._run_operation(
            operation_id, FIXED_30_MIGRATION_KIND, request, apply)

    def purchase_talent_point(self, operation_id: str, commander_key: str) -> dict:
        raise EconomyError("talent_point_purchase_disabled")

    def respec_commander(self, operation_id: str, commander_key: str) -> dict:
        version = self.specialization_status(commander_key)["policy_version"]
        request = {"commander": commander_key, "policy_version": version}
        def apply(state):
            if self._journal(state)[0] is None:
                raise EconomyError("specializations_not_enabled")
            if self._pending_battle(state):
                raise EconomyError("specialization_change_pending_battle")
            if commander_key not in state["commanders"]:
                raise EconomyError("commander_not_owned")
            policy = self.specialization_policies[commander_key]
            commander = state["commanders"][commander_key]
            status = self.specialization_status(commander_key, state)
            entitled = status["entitled_total"]
            commander["abilities"] = {root: 1 for root in policy.roots}
            commander["talent_points"] = entitled
            result = {"commander": commander_key,
                      "policy_version": status["policy_version"],
                      "entitled_total": entitled}
            if status["policy_version"] == LEGACY_POLICY_VERSION:
                result["selected_route"] = None
            else:
                result["selected_routes"] = []
            return result
        return self._run_operation(operation_id, "respec_commander", request, apply)

    def _prepare_ability_purchase_balance(self, state: dict, offer: dict) -> None:
        if not self.specialization_enabled(state):
            return
        key = offer["commander_key"]; commander = state["commanders"][key]
        prospective = copy.deepcopy(commander["abilities"])
        prospective[offer["ability_key"]] = offer["ability_level"]
        try:
            status = self.specialization_status(key, state)
            legacy = status["policy_version"] == LEGACY_POLICY_VERSION
            selection = evaluate_selection(self.specialization_policies[key],
                self._specialization_native, self._specialization_talents,
                prospective, commander["tier"], exclusive_routes=legacy,
                fixed_budget=status["fixed_talent_budget"])
            entitled = status["entitled_total"]
            active = min(entitled, selection["route_capacity"])
        except SpecializationPolicyError as exc:
            raise EconomyError("specialization_route_violation") from exc
        if self._talent_points_spent(key, prospective) > active:
            raise EconomyError("insufficient_commander_talent_points")
        commander["talent_points"] = active - self._talent_points_spent(
            key, commander["abilities"])

    def _prepare_ability_refund_balance(self, state: dict, offer: dict, total: int) -> None:
        if not self.specialization_enabled(state):
            return
        key = offer["commander_key"]
        spent_after = self._talent_points_spent(key, state["commanders"][key]["abilities"])
        # Base adds the refunded point immediately after this hook.
        state["commanders"][key]["talent_points"] = total - spent_after - 1

    def grant_local_commander_talent_points(self, *args, **kwargs):
        if self.specialization_enabled():
            raise EconomyError("legacy_talent_grant_disabled_by_specialization")
        return super().grant_local_commander_talent_points(*args, **kwargs)

    def reset_local_commander_talent_points(self, *args, **kwargs):
        if self.specialization_enabled():
            raise EconomyError("legacy_talent_reset_disabled_by_specialization")
        return super().reset_local_commander_talent_points(*args, **kwargs)

    def _battle_begin_reward_metadata(self, state: dict, reward_policy: str) -> dict:
        if reward_policy in {"pve", "pvp"} and self.specialization_enabled(state):
            return {"reward_profile": REWARD_PROFILE}
        return {}

    def _adjust_local_reward_quote(
        self, state: dict, battle: dict, begin_receipt: dict,
        outcome: str, verified: bool, reward_policy: str,
        quote: dict, award: dict | None,
    ) -> dict:
        profile = begin_receipt.get("reward_profile")
        if profile is None:
            return quote
        if profile != REWARD_PROFILE or reward_policy not in {"pve", "pvp"}:
            raise EconomyError("invalid_battle_operation")
        # A registered remote authority remains authoritative and is never
        # silently replaced by this explicitly local policy.
        if award is not None:
            return quote
        amount = FREE_XP_REWARD_CENTS[outcome] if verified else 0
        return {**quote, **{key: 0 for key in REWARD_AMOUNT_FIELDS},
                "free_xp_cents": amount}
