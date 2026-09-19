"""Account display names, kept separate from native transport identities."""
from __future__ import annotations

import unicodedata


def validate_display_name(value: object) -> str:
    """Accept a bounded Unicode name that can be quoted in native scripts."""
    if (not isinstance(value, str) or not 1 <= len(value) <= 32
            or not value.strip()
            or any(char in '\\";' or unicodedata.category(char).startswith('C')
                   or unicodedata.category(char) in {'Zl', 'Zp'} for char in value)):
        raise ValueError('invalid_native_display_name')
    return value


def account_display_name(api: object, puid: str) -> str:
    """Read the name only from this authenticated account's /v1/me reply."""
    body = api.me()
    user = body.get('user') if isinstance(body, dict) else None
    if not isinstance(user, dict) or user.get('id') != puid:
        raise ValueError('display_name_account_mismatch')
    return validate_display_name(user.get('displayName'))
