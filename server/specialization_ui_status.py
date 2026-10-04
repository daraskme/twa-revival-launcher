"""Pure, read-only v1 presentation contract for commander specialization UI."""
from __future__ import annotations

import copy

from commander_specialization_policy import (
    FIXED_20_POLICY_VERSION, LEGACY_POLICY_VERSION, POLICY_VERSION,
)

UI_STATUS_VERSION = "specialization-ui-status-v3-fixed-30"
SUPPORTED_LANGUAGES = frozenset(("en", "ja", "ru"))
ROUTE_NAME_KEY_PREFIX = "arena_commander_abilities_com_ability_localized_name_"

TEXT = {
    "en": {
        "fixed_budget": "Each commander has a fixed 30-point talent budget. Points cannot be purchased.",
        "pending": "Unavailable while a battle is pending.",
        "ready_respec": "Remove acquired talents and return the points. Free; outside battle only.",
        "banked": "{count} entitled point(s) are banked because this route has a lower cap.",
    },
    "ja": {
        "fixed_budget": "各指揮官のタレントポイントは30固定です。追加購入はできません。",
        "pending": "戦闘が保留中のため利用できません。",
        "ready_respec": "取得したタレントを解除し、ポイントを戻します。無料・戦闘外のみ。",
        "banked": "このルートの上限が低いため、権利済みポイント{count}は保留されています。",
    },
    "ru": {
        "fixed_budget": "У каждого командира фиксированный бюджет в 30 очков. Покупка очков недоступна.",
        "pending": "Недоступно, пока ожидается бой.",
        "ready_respec": "Снимите полученные таланты и верните очки. Бесплатно; только вне боя.",
        "banked": "Очки в запасе: {count}. Предел этой ветки ниже общего числа очков.",
    },
}


class SpecializationUiStatusError(ValueError):
    pass


def build_specialization_ui_status(policy, status: dict, free_xp_cents: int,
                                   pending_battle: bool, language: str) -> dict:
    """Return presentation data without mutating policy, status, or economy."""
    if type(language) is not str or language not in SUPPORTED_LANGUAGES:
        raise SpecializationUiStatusError("unsupported_specialization_ui_language")
    if type(free_xp_cents) is not int or free_xp_cents < 0 or type(pending_battle) is not bool:
        raise SpecializationUiStatusError("invalid_specialization_ui_context")
    required = {"selected_route", "selected_routes", "route_spent",
                "route_capacity", "entitled_total", "active_total",
                "banked", "spent", "remaining", "purchasable_capacity",
                "fixed_talent_budget", "purchase_enabled",
                "migration_required", "policy_version"}
    if not isinstance(status, dict) or not required <= set(status):
        raise SpecializationUiStatusError("invalid_specialization_ui_status")
    roots = tuple(policy.roots)
    routes = tuple(policy.routes)
    if len(roots) != 3 or len(routes) != 3 or {route.root for route in routes} != set(roots):
        raise SpecializationUiStatusError("invalid_specialization_ui_policy")
    selected = status["selected_route"]
    if selected is not None and selected not in roots:
        raise SpecializationUiStatusError("invalid_specialization_selected_route")
    selected_routes = status["selected_routes"]
    route_spent = status["route_spent"]
    if (not isinstance(selected_routes, list)
            or len(selected_routes) != len(set(selected_routes))
            or any(root not in roots for root in selected_routes)
            or selected != (selected_routes[0] if len(selected_routes) == 1 else None)
            or not isinstance(route_spent, dict) or set(route_spent) != set(roots)
            or any(type(value) is not int or value < 0
                   for value in route_spent.values())):
        raise SpecializationUiStatusError("invalid_specialization_selected_routes")
    numeric = ("route_capacity", "entitled_total", "active_total", "banked", "spent",
               "remaining", "purchasable_capacity")
    version = status.get("policy_version")
    expected_budget = (20 if version in {
        LEGACY_POLICY_VERSION, FIXED_20_POLICY_VERSION} else
        30 if version == POLICY_VERSION else None)
    if (expected_budget is None
            or status.get("fixed_talent_budget") != expected_budget
            or type(status.get("fixed_talent_budget")) is not int
            or status.get("purchase_enabled") is not False
            or type(status.get("migration_required")) is not bool
            or any(type(status[key]) is not int or status[key] < 0 for key in numeric)):
        raise SpecializationUiStatusError("invalid_specialization_ui_balance")
    legacy = version == LEGACY_POLICY_VERSION
    if status["migration_required"] is not (version != POLICY_VERSION):
        raise SpecializationUiStatusError("invalid_specialization_ui_balance")
    expected_capacity = ((policy.max_unselected_budget if selected is None else next(
        route.cost for route in routes if route.root == selected))
        if legacy else status["fixed_talent_budget"])
    if (status["route_capacity"] != expected_capacity
            or status["active_total"] != min(status["entitled_total"], expected_capacity)
            or status["banked"] != status["entitled_total"] - status["active_total"]
            or status["remaining"] != status["active_total"] - status["spent"]
            or status["purchasable_capacity"] != 0
            or sum(route_spent.values()) != status["spent"]
            or status["spent"] > status["active_total"]):
        raise SpecializationUiStatusError("inconsistent_specialization_ui_balance")
    strings = TEXT[language]
    if pending_battle:
        respec_reason = "pending_battle"
    else:
        respec_reason = "ready"
    purchase_reason = "fixed_budget"
    purchase_text = strings["fixed_budget"]
    respec_text = strings["pending" if respec_reason == "pending_battle" else "ready_respec"]
    route_rows = []
    for route in routes:
        is_selected = route.root in selected_routes
        route_rows.append({
            "root": route.root,
            "name_localization_key": ROUTE_NAME_KEY_PREFIX + route.root,
            "capacity": route.cost,
            "selected": is_selected,
            "locked": False,
            "spent": route_spent[route.root],
            "completed": is_selected and route_spent[route.root] >= route.cost,
        })
    result = {
        "version": UI_STATUS_VERSION, "language": language,
        "commander_key": policy.commander, "policy_version": status["policy_version"],
        "balances": {key: status[key] for key in numeric},
        "fixed_talent_budget": status["fixed_talent_budget"],
        "selected_route": selected, "selected_routes": selected_routes,
        "routes": route_rows,
        "purchase": {"enabled": False, "reason": purchase_reason,
                     "text": purchase_text},
        "respec": {"enabled": respec_reason == "ready", "reason": respec_reason,
                   "free": True, "outside_battle_only": True, "text": respec_text},
        "banked": {"visible": status["banked"] > 0, "count": status["banked"],
                   "text": strings["banked"].format(count=status["banked"])
                   if status["banked"] else ""},
    }
    return copy.deepcopy(result)
