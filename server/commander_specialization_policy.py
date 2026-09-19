"""Pure, opt-in commander specialization policy derived from native catalogues."""
from __future__ import annotations

from dataclasses import dataclass


LEGACY_POLICY_VERSION = "commander-specialization-v1-draft"
FIXED_20_POLICY_VERSION = "commander-specialization-v2-fixed-20-open-routes"
POLICY_VERSION = "commander-specialization-v3-fixed-30-open-routes"
DEFAULT_FIXED_TALENT_BUDGET = 30


class SpecializationPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Route:
    root: str
    nodes: frozenset[str]
    cost: int


@dataclass(frozen=True)
class CommanderPolicy:
    commander: str
    roots: tuple[str, str, str]
    routes: tuple[Route, Route, Route]
    max_unselected_budget: int


def _plain_positive(value: object, label: str) -> int:
    if type(value) is not int or value < 1:
        raise SpecializationPolicyError(label)
    return value


def derive_policies(native: dict, talents: dict) -> dict[str, CommanderPolicy]:
    if not isinstance(native, dict) or not isinstance(talents, dict):
        raise SpecializationPolicyError("invalid_catalogue")
    commanders = {row.get("key") for row in native.get("commanders", [])
                  if isinstance(row, dict) and row.get("build_state", "live") == "live"}
    if None in commanders or not commanders:
        raise SpecializationPolicyError("invalid_commanders")
    owners: dict[str, str] = {}
    max_rank: dict[tuple[str, str], int] = {}
    required: dict[tuple[str, str, int], int] = {}
    for row in native.get("ability_levels", []):
        if not isinstance(row, dict) or row.get("commander") not in commanders:
            raise SpecializationPolicyError("unknown_or_malformed_ability_owner")
        meta = row.get("metadata")
        if not isinstance(meta, dict):
            raise SpecializationPolicyError("invalid_ability_level")
        commander, key = row["commander"], meta.get("ability_key")
        rank = _plain_positive(meta.get("ability_level"), "invalid_rank")
        tier = _plain_positive(meta.get(commander), "invalid_tier")
        if not isinstance(key, str) or not key or tier > 10:
            raise SpecializationPolicyError("invalid_ability_level")
        old_owner = owners.setdefault(key, commander)
        if old_owner != commander or (commander, key, rank) in required:
            raise SpecializationPolicyError("duplicate_or_cross_commander_ability")
        required[(commander, key, rank)] = tier
        max_rank[(commander, key)] = max(max_rank.get((commander, key), 0), rank)
    for (commander, key), maximum in max_rank.items():
        if set(range(1, maximum + 1)) != {rank for c, ability, rank in required
                                         if c == commander and ability == key}:
            raise SpecializationPolicyError("rank_gap")

    outgoing: dict[str, set[str]] = {key: set() for key in owners}
    incoming: dict[str, set[str]] = {key: set() for key in owners}
    edges: set[tuple[str, str]] = set()
    for edge in talents.get("ability_links", []):
        if not isinstance(edge, dict):
            raise SpecializationPolicyError("invalid_edge")
        source, target = edge.get("source"), edge.get("target")
        if source not in owners or target not in owners:
            raise SpecializationPolicyError("unknown_edge_node")
        if owners[source] != owners[target]:
            raise SpecializationPolicyError("cross_commander_edge")
        if source == target or (source, target) in edges:
            raise SpecializationPolicyError("duplicate_or_self_edge")
        edges.add((source, target))
        outgoing[source].add(target); incoming[target].add(source)

    policies: dict[str, CommanderPolicy] = {}
    for commander in sorted(commanders):
        nodes = {key for key, owner in owners.items() if owner == commander}
        roots = tuple(sorted(key for key in nodes if not incoming[key]))
        if len(roots) != 3:
            raise SpecializationPolicyError("commander_must_have_three_roots")
        routes = []
        seen_by_root: list[set[str]] = []
        for root in roots:
            seen, active = set(), set()
            def visit(node: str) -> None:
                if node in active:
                    raise SpecializationPolicyError("ability_cycle")
                if node in seen:
                    return
                active.add(node)
                for child in outgoing[node]: visit(child)
                active.remove(node); seen.add(node)
            visit(root)
            seen_by_root.append(seen)
            cost = sum(max_rank[(commander, key)] - (1 if key == root else 0)
                       for key in seen)
            routes.append(Route(root, frozenset(seen), cost))
        if set.union(*seen_by_root) != nodes:
            raise SpecializationPolicyError("orphan_ability_node")
        if any(seen_by_root[i] & seen_by_root[j] for i in range(3) for j in range(i + 1, 3)):
            raise SpecializationPolicyError("overlapping_specialization_routes")
        policies[commander] = CommanderPolicy(
            commander, roots, tuple(routes), max(route.cost for route in routes))
    return policies


def evaluate_selection(policy: CommanderPolicy, native: dict, talents: dict,
                       abilities: dict, tier: int, *,
                       exclusive_routes: bool = False,
                       fixed_budget: int | None = DEFAULT_FIXED_TALENT_BUDGET) -> dict:
    if type(tier) is not int or not 1 <= tier <= 10 or not isinstance(abilities, dict):
        raise SpecializationPolicyError("invalid_selection_input")
    all_nodes = set().union(*(route.nodes for route in policy.routes))
    if set(abilities) - all_nodes:
        raise SpecializationPolicyError("unknown_or_wrong_owner_ability")
    levels = {}
    required = {}
    for row in native.get("ability_levels", []):
        if row.get("commander") == policy.commander:
            meta = row["metadata"]; key = meta["ability_key"]; rank = meta["ability_level"]
            levels[key] = max(levels.get(key, 0), rank); required[(key, rank)] = meta[policy.commander]
    incoming = {key: set() for key in all_nodes}
    for edge in talents.get("ability_links", []):
        if edge.get("target") in incoming and edge.get("source") in all_nodes:
            incoming[edge["target"]].add(edge["source"])
    for key, rank in abilities.items():
        rank = _plain_positive(rank, "invalid_selected_rank")
        if rank > levels[key] or any((key, item) not in required for item in range(1, rank + 1)):
            raise SpecializationPolicyError("selected_rank_gap")
        if any(required[(key, item)] > tier for item in range(1, rank + 1)):
            raise SpecializationPolicyError("selected_rank_above_tier")
    for root in policy.roots:
        if abilities.get(root) != 1:
            raise SpecializationPolicyError("all_free_roots_rank_one_required")
    manual = {key for key, rank in abilities.items()
              if key not in policy.roots or rank > 1}
    selected = [route for route in policy.routes if manual & route.nodes]
    if exclusive_routes and len(selected) > 1:
        raise SpecializationPolicyError("multiple_specialization_routes")
    for key in manual:
        parents = incoming[key]
        if parents and not any(abilities.get(parent, 0) >= 1 for parent in parents):
            raise SpecializationPolicyError("missing_any_parent")
    spent = sum(rank - (1 if key in policy.roots else 0) for key, rank in abilities.items())
    route = selected[0] if len(selected) == 1 else None
    if exclusive_routes:
        capacity = route.cost if route else policy.max_unselected_budget
    else:
        if type(fixed_budget) is not int or fixed_budget < 0:
            raise SpecializationPolicyError("invalid_fixed_talent_budget")
        capacity = fixed_budget
    if spent > capacity:
        raise SpecializationPolicyError("specialization_overspent")
    route_spent = {
        item.root: sum(
            rank - (1 if key == item.root else 0)
            for key, rank in abilities.items() if key in item.nodes
        ) for item in policy.routes
    }
    return {"policy_version": POLICY_VERSION, "commander": policy.commander,
            "selected_route": route.root if route else None,
            "selected_routes": [item.root for item in selected],
            "route_spent": route_spent, "route_capacity": capacity,
            "spent": spent, "unselected_capacity_is_draft": False}


def point_balance(selection: dict, entitled_total: int, *,
                  purchases_allowed: bool = True) -> dict:
    """Validate separately acquired points against the selected route capacity."""
    if (type(entitled_total) is not int or entitled_total < 0
            or type(purchases_allowed) is not bool):
        raise SpecializationPolicyError("invalid_entitled_point_total")
    capacity, spent = selection.get("route_capacity"), selection.get("spent")
    if (type(capacity) is not int or type(spent) is not int
            or capacity < 0 or spent < 0):
        raise SpecializationPolicyError("invalid_selection_summary")
    active_total = min(entitled_total, capacity)
    if spent > active_total:
        raise SpecializationPolicyError("spent_points_exceed_active_total")
    return {"route_capacity": capacity, "entitled_total": entitled_total,
            "active_total": active_total, "banked": entitled_total - active_total,
            "spent": spent, "remaining": active_total - spent,
            "purchasable_capacity": (max(0, capacity - entitled_total)
                                      if purchases_allowed else 0)}
