"""Pure merge of one Recent Players key in the verified MPFileStorage v1 blob.

No filesystem, transport, clock, or identity lookup is performed here. The caller
must obtain ``blob`` from the object belonging to ``authenticated_user_id`` and
provide an already encoded Recent Players value. Every other serialized record
is retained byte for byte, including its opaque pointer/timestamp fields.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import struct


MAX_NATIVE_BLOB_BYTES = 512 * 1024
MAX_RECENT_STORAGE_BYTES = 5000
RECENT_STORAGE_KEY = "recent_players_storage"
_TARGET_KEY = RECENT_STORAGE_KEY.encode("utf-16-le")
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_HEADER = struct.Struct("<II")
_DESCRIPTOR = struct.Struct("<III")


class NativeRecentStorageError(ValueError):
    """The supplied object cannot be safely merged."""


@dataclass(frozen=True)
class _Record:
    key: bytes
    start: int
    descriptor: int
    payload: int
    end: int


def _records(blob: bytes) -> tuple[_Record, ...]:
    if not isinstance(blob, bytes):
        raise NativeRecentStorageError("storage_blob_must_be_bytes")
    if len(blob) > MAX_NATIVE_BLOB_BYTES:
        raise NativeRecentStorageError("storage_blob_too_large")
    if len(blob) < _HEADER.size:
        raise NativeRecentStorageError("storage_header_truncated")
    version, count = _HEADER.unpack_from(blob)
    if version != 1:
        raise NativeRecentStorageError("storage_version_unsupported")
    # A nonempty UTF-16 key plus the two headers consumes at least 18 bytes.
    if count > (len(blob) - _HEADER.size) // 18:
        raise NativeRecentStorageError("storage_record_count_invalid")
    offset = _HEADER.size
    result: list[_Record] = []
    seen: set[bytes] = set()
    for _ in range(count):
        start = offset
        if offset + 4 > len(blob):
            raise NativeRecentStorageError("storage_key_header_truncated")
        units, = struct.unpack_from("<I", blob, offset)
        offset += 4
        if units == 0:
            raise NativeRecentStorageError("storage_key_empty")
        if units > (len(blob) - offset - _DESCRIPTOR.size) // 2:
            raise NativeRecentStorageError("storage_key_truncated")
        key = blob[offset:offset + units * 2]
        try:
            decoded_key = key.decode("utf-16-le", errors="strict")
        except UnicodeDecodeError as exc:
            raise NativeRecentStorageError("storage_key_invalid_utf16") from exc
        if "\0" in decoded_key:
            raise NativeRecentStorageError("storage_key_contains_nul")
        if key in seen:
            raise NativeRecentStorageError("storage_key_duplicate")
        seen.add(key)
        offset += len(key)
        descriptor = offset
        _pointer, length, _timestamp = _DESCRIPTOR.unpack_from(blob, offset)
        offset += _DESCRIPTOR.size
        if length > len(blob) - offset:
            raise NativeRecentStorageError("storage_payload_truncated")
        end = offset + length
        result.append(_Record(key, start, descriptor, offset, end))
        offset = end
    if offset != len(blob):
        raise NativeRecentStorageError("storage_trailing_bytes")
    return tuple(result)


def _validate_recent_value(value: bytes) -> None:
    if not isinstance(value, bytes):
        raise NativeRecentStorageError("recent_value_must_be_bytes")
    if len(value) < 2 or len(value) > MAX_RECENT_STORAGE_BYTES or len(value) % 2:
        raise NativeRecentStorageError("recent_value_size_invalid")
    if not value.endswith(b"\0\0"):
        raise NativeRecentStorageError("recent_value_missing_terminator")
    try:
        text = value[:-2].decode("utf-16-le", errors="strict")
    except UnicodeDecodeError as exc:
        raise NativeRecentStorageError("recent_value_invalid_utf16") from exc
    if "\0" in text:
        raise NativeRecentStorageError("recent_value_embedded_nul")


def merge_recent_players_storage(
    blob: bytes,
    recent_utf16: bytes,
    *,
    owner_id: str,
    authenticated_user_id: str,
    modified_at_seconds: int,
) -> bytes:
    """Replace/add only ``recent_players_storage`` without altering other keys.

    The v1 blob does not encode an owner, so identity comes from the trusted
    transport/object lookup. Explicit unequal identities are always refused.
    A missing object is not an empty blob: a caller may deliberately initialize
    ``b'\x01\x00\x00\x00\x00\x00\x00\x00'`` only after confirming absence.
    Equal target bytes return the original object without advancing its time.
    """
    for identity in (owner_id, authenticated_user_id):
        if not isinstance(identity, str) or _IDENTITY.fullmatch(identity) is None:
            raise NativeRecentStorageError("storage_identity_invalid")
    if owner_id != authenticated_user_id:
        raise NativeRecentStorageError("storage_owner_mismatch")
    if type(modified_at_seconds) is not int or not 0 <= modified_at_seconds <= 0xFFFFFFFF:
        raise NativeRecentStorageError("storage_timestamp_invalid")
    _validate_recent_value(recent_utf16)
    records = _records(blob)
    target = next((record for record in records if record.key == _TARGET_KEY), None)
    if target is not None:
        if blob[target.payload:target.end] == recent_utf16:
            return blob
        # The native reader discards pointer32; retain it when replacing a record.
        record_bytes = (
            blob[target.start:target.descriptor + 4]
            + struct.pack("<II", len(recent_utf16), modified_at_seconds)
            + recent_utf16
        )
        result = blob[:target.start] + record_bytes + blob[target.end:]
    else:
        record_bytes = (
            struct.pack("<I", len(_TARGET_KEY) // 2)
            + _TARGET_KEY
            + _DESCRIPTOR.pack(0, len(recent_utf16), modified_at_seconds)
            + recent_utf16
        )
        result = _HEADER.pack(1, len(records) + 1) + blob[_HEADER.size:] + record_bytes
    if len(result) > MAX_NATIVE_BLOB_BYTES:
        raise NativeRecentStorageError("storage_merge_too_large")
    return result


__all__ = [
    "MAX_NATIVE_BLOB_BYTES", "MAX_RECENT_STORAGE_BYTES", "RECENT_STORAGE_KEY",
    "NativeRecentStorageError", "merge_recent_players_storage",
]
