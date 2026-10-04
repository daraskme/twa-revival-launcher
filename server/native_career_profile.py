"""Pure projection for Arena's native career profile, not inventory records.

Wire evidence (game.dll RVAs): bce500 sends timestamp-only /profile;
bf70d0 reads response.user_id; c2c740 reads last_updated/stats/totals;
c1adf0 parses each stats value; d66590 separates commander records (empty
unit_key) from unit records and sums commander records for overall totals.
Nothing here writes a database or changes an inventory profile watermark.

The reviewed client leaves some omitted numeric fields uninitialized. Every
known native numeric slot is therefore populated on the wire. Unknown
ancillary values use neutral zero only for memory initialization; they remain
unknown in the source summary and must not be presented as measured rewards.
"""
from __future__ import annotations

import copy
from collections.abc import Mapping

MAX_INTEGER = 2**63 - 1
MAX_CURRENCY = 2**64 - 1
MONEY_FIELDS = ('unit_xp_cents', 'max_unit_xp_cents', 'free_xp_cents', 'silver_cents')
POINT_FIELDS = ('battle_points_cents', 'max_points_cents')
RECORD_ANCILLARY_FIELDS = MONEY_FIELDS + POINT_FIELDS
TOTAL_ANCILLARY_FIELDS = ('free_xp_cents', 'silver_cents', 'unit_xp_cents',
                          'battle_points_cents', 'damage')


class CareerProfileError(ValueError):
    pass


def _count(value: object, name: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_INTEGER:
        raise CareerProfileError('invalid_career_' + name)
    return value


def _aggregate(value: object) -> dict:
    if not isinstance(value, Mapping):
        raise CareerProfileError('invalid_career_aggregate')
    result = {key: _count(value.get(key), key)
              for key in ('battles', 'wins', 'losses', 'draws')}
    if result['battles'] != result['wins'] + result['losses'] + result['draws']:
        raise CareerProfileError('inconsistent_career_outcomes')
    unknown = _count(value.get('unknown_kill_battles', 0), 'unknown_kill_battles')
    # The native parser only supports kills / all battles. Never manufacture
    # zero kills for unmeasured historical battles or silently change the
    # denominator to battles with telemetry.
    if unknown:
        raise CareerProfileError('incomplete_career_kills')
    if result['battles'] == 0:
        result.update(kills=0, max_kills=0)
    else:
        result['kills'] = _count(value.get('kills'), 'kills')
        result['max_kills'] = _count(value.get('max_kills'), 'max_kills')
        if result['max_kills'] > result['kills']:
            raise CareerProfileError('inconsistent_career_max_kills')
    for key in (*RECORD_ANCILLARY_FIELDS, 'damage'):
        amount = value.get(key)
        if amount is None:
            continue
        if type(amount) is not int or not 0 <= amount <= MAX_CURRENCY:
            raise CareerProfileError('invalid_career_' + key)
        result[key] = amount
    return result


def _record(aggregate: dict, commander_key: str, unit_key: str) -> dict:
    # c1b347 / c1b3af skip the points writes when keys are absent, leaving
    # uninitialized storage later read by the UI. c1b029..c1b173 also reads
    # six mandatory numeric fields without a missing-value conversion.
    # Zero below is a wire initialization placeholder, not a measured value.
    # The career UI replaces commander max-points with the measured kill mean
    # and masks unattributed unit FreeXP. Other unknown currencies additionally
    # require a UI mask before their numeric value may be claimed as measured.
    return {
        'commander_key': commander_key, 'unit_key': unit_key,
        **{key: aggregate.get(key, 0) for key in RECORD_ANCILLARY_FIELDS},
        'kills': aggregate['kills'], 'max_kills': aggregate['max_kills'],
        'unique_victories': aggregate['wins'],
        'unique_defeats': aggregate['losses'],
        'unique_draws': aggregate['draws'],
        'maps': {}, 'rewards': {}, 'battle_tier_history': {},
    }


def build_career_profile(summary: dict, user_id: str,
                         native_catalog: dict) -> dict:
    """Return measured career counters plus safe ancillary wire initializers.

    `summary` comes from NativeCareerStats.summary. It must include the joint
    commander_units groups: summing three unit slots must not triple a battle
    in the commander/overview rows. `native_catalog` supplies canonical keys.
    This function rejects incomplete kill telemetry because the native layout
    cannot express an unknown kill count separately from measured zero.
    Ancillary unknowns are initialized to zero on this transport only; the
    caller must apply the career UI adapter and disclose any unmasked unknown
    currencies. This function never changes the original summary's None.
    """
    if (not isinstance(user_id, str) or not 1 <= len(user_id) <= 128
            or any(ord(c) < 32 for c in user_id)):
        raise CareerProfileError('invalid_career_user_id')
    if not isinstance(summary, Mapping) or summary.get('schema_version') != 1:
        raise CareerProfileError('invalid_career_summary')
    try:
        commanders = {r['key'] for r in native_catalog['commanders']}
        units = {r['key'] for r in native_catalog['units']}
    except (TypeError, KeyError):
        raise CareerProfileError('invalid_career_catalogue') from None
    if (any(not isinstance(k, str) or not k for k in commanders | units)
            or not commanders or not units):
        raise CareerProfileError('invalid_career_catalogue')
    overall = _aggregate(summary.get('overall'))
    groups = summary.get('commanders')
    joint = summary.get('commander_units')
    if not isinstance(groups, Mapping) or not isinstance(joint, Mapping):
        raise CareerProfileError('invalid_career_groups')
    if any(k not in commanders for k in groups) or any(k not in groups for k in joint):
        raise CareerProfileError('unknown_career_commander')
    stats = {}
    aggregates = {}
    for key, aggregate in sorted(groups.items()):
        parsed = _aggregate(aggregate)
        aggregates[key] = parsed
        stats['commander:' + key] = _record(parsed, key, '')
    for field in ('battles', 'wins', 'losses', 'draws', 'kills'):
        if sum(row[field] for row in aggregates.values()) != overall[field]:
            raise CareerProfileError('inconsistent_career_commander_totals')
    for field in ('unit_xp_cents', 'free_xp_cents', 'silver_cents'):
        if (field in overall and all(field in row for row in aggregates.values())
                and sum(row[field] for row in aggregates.values()) != overall[field]):
            raise CareerProfileError('inconsistent_career_commander_rewards')
    for commander, unit_groups in sorted(joint.items()):
        if not isinstance(unit_groups, Mapping):
            raise CareerProfileError('invalid_career_unit_groups')
        for unit, aggregate in sorted(unit_groups.items()):
            if unit not in units:
                raise CareerProfileError('unknown_career_unit')
            parsed = _aggregate(aggregate)
            if parsed['battles'] > aggregates[commander]['battles']:
                raise CareerProfileError('inconsistent_career_unit_battles')
            stats['unit:' + commander + ':' + unit] = _record(parsed, commander, unit)
    return {
        'user_id': user_id,
        'last_updated': _count(summary.get('last_updated'), 'last_updated'),
        'players_level': _count(summary.get('players_level', 0), 'players_level'),
        'max_eagles': [], 'stats': stats,
        'totals': {'kills': overall['kills'],
                   **{key: overall.get(key, 0) for key in TOTAL_ANCILLARY_FIELDS}},
        'achievements': {},
    }


def attach_profile_career(response: dict, request: object, career: dict) -> dict:
    """Add career fields to a timestamp-only response without inventory edits.

    Accept the *unwrapped* CA response body. Existing `result`, `profile`,
    `saved`, and all other fields are deep-copied without modification.
    Root routing can envelope the returned object as usual.
    """
    if not isinstance(response, dict):
        raise CareerProfileError('invalid_career_response')
    result = copy.deepcopy(response)
    if (not isinstance(request, dict) or set(request) != {'timestamp'}
            or type(request['timestamp']) is not int or request['timestamp'] < 0):
        return result
    allowed = {'user_id', 'last_updated', 'players_level', 'max_eagles',
               'stats', 'totals', 'achievements'}
    if not isinstance(career, dict) or set(career) != allowed:
        raise CareerProfileError('invalid_career_projection')
    if (result.get('user_id', career['user_id']) != career['user_id']):
        raise CareerProfileError('career_user_id_conflict')
    result.update(copy.deepcopy(career))
    return result
