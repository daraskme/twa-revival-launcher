"""Add the career response consumed by the native timestamp-only request.

Inventory and career requests share /profile. Preserve the existing response
and its causal synchronization behavior; the career consumer reads its own
top-level user_id/stats fields while the inventory consumer reads profile.
"""
from __future__ import annotations
import json


def is_career_request(raw: bytes) -> bool:
    try:
        body = json.loads(raw)
    except (ValueError, UnicodeError):
        return False
    request = body.get('request') if isinstance(body, dict) else None
    return (isinstance(request, dict) and set(request) == {'timestamp'}
            and type(request['timestamp']) is int
            and 0 <= request['timestamp'] < 2**64)


def decorate_career_response(body: bytes, career: dict) -> bytes:
    """Keep envelope timestamps, inventory contents and result markers intact."""
    envelope = json.loads(body)
    response = envelope.get('response') if isinstance(envelope, dict) else None
    if not isinstance(response, dict):
        raise ValueError('invalid_career_response_envelope')
    if not isinstance(career, dict) or not isinstance(career.get('user_id'), str):
        raise ValueError('invalid_career_response')
    protected = {'profile', 'saved', 'result', 'events', 'properties'}
    if protected.intersection(career):
        raise ValueError('career_inventory_field_collision')
    for key in career.keys() & response.keys():
        if response[key] != career[key]:
            raise ValueError('career_response_field_collision')
    response.update(career)
    return json.dumps(envelope, ensure_ascii=False, allow_nan=False,
                      separators=(',', ':')).encode('utf-8')
