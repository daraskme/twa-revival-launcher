"""Pluggable persistence for one account's ``LocalEconomy`` state.

``LocalEconomy`` used to own an ``os.replace`` write of a single JSON file.
That write is now one backend among several so the companion can keep the
authoritative blob in the Cloudflare Worker profile API instead
(``private-server/src/profiles.ts``) while the lab keeps the file.

Contract
--------
``load(user) -> (state | None, saved)``
    ``state`` is ``None`` when nothing is stored yet; ``saved`` is the stored
    native profile watermark, or ``0`` when nothing is stored.
``save(user, state, expected_saved) -> saved``
    Optimistic-concurrency write.  ``expected_saved`` is the watermark the
    caller believes is stored (``0`` = "create only").  A mismatch raises
    ``BackendConflict`` and must leave the caller's in-memory state untouched.

This module deliberately does not import ``local_economy``: the dependency
runs the other way, so ``BackendError`` carries a code that ``LocalEconomy``
re-raises as an ``EconomyError`` with the same string.
"""
from __future__ import annotations

import json
import base64
import binascii
import os
import tempfile
import zlib
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

# The Worker's blob ceiling (private-server/src/profiles.ts PROFILE_BLOB_LIMIT).
PROFILE_BLOB_LIMIT = 512 * 1024
CLOUD_RAW_BLOB_LIMIT = 16 * 1024 * 1024
CLOUD_ENVELOPE_KEY = "__twa_cloud_profile_codec__"
SAVED_CONFLICT = "saved_conflict"


class BackendError(Exception):
    """A fail-closed persistence error with a stable economy-facing code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class BackendConflict(BackendError):
    """The stored watermark moved: reload and replay the operation."""

    def __init__(self, code: str = SAVED_CONFLICT, saved: int | None = None):
        super().__init__(code)
        self.saved = saved


def read_state_json(path: Path) -> dict:
    """Strict state read: no duplicate keys, no JSON constants, object root."""

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise BackendError("duplicate_state_key")
            result[key] = value
        return result

    def constant(_value: str) -> None:
        raise BackendError("invalid_state_number")

    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"),
                           object_pairs_hook=object_pairs, parse_constant=constant)
    except BackendError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BackendError("invalid_state_json") from exc
    if not isinstance(value, dict):
        raise BackendError("invalid_state_schema")
    return value


def _stored_saved(state: object) -> int:
    saved = state.get("saved") if isinstance(state, dict) else None
    return saved if type(saved) is int and saved >= 0 else 0


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise BackendError("invalid_state_json") from exc


def _cloud_encode_blob(state: dict) -> dict:
    raw = _canonical_json(state)
    if len(raw) > CLOUD_RAW_BLOB_LIMIT:
        raise BackendError("profile_raw_too_large")
    if len(raw) <= PROFILE_BLOB_LIMIT:
        return state
    compressed = zlib.compress(raw, 9)
    if len(compressed) > PROFILE_BLOB_LIMIT:
        raise BackendError("profile_too_large")
    envelope = {CLOUD_ENVELOPE_KEY: {
        "version": 1, "encoding": "zlib+base64", "rawBytes": len(raw),
        "data": base64.b64encode(compressed).decode("ascii"),
    }}
    if len(_canonical_json(envelope)) > PROFILE_BLOB_LIMIT:
        raise BackendError("profile_too_large")
    return envelope


def _strict_json_object(raw: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise BackendError("duplicate_state_key")
            result[key] = value
        return result
    def constant(_value):
        raise BackendError("invalid_state_number")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=constant)
    except BackendError:
        raise BackendError("invalid_cloud_profile_envelope") from None
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise BackendError("invalid_cloud_profile_envelope") from exc
    if not isinstance(value, dict) or _canonical_json(value) != raw:
        raise BackendError("invalid_cloud_profile_envelope")
    return value


def _cloud_decode_blob(blob: dict) -> dict:
    if CLOUD_ENVELOPE_KEY not in blob:
        return blob
    if set(blob) != {CLOUD_ENVELOPE_KEY}:
        raise BackendError("invalid_cloud_profile_envelope")
    row = blob[CLOUD_ENVELOPE_KEY]
    if (not isinstance(row, dict)
            or set(row) != {"version", "encoding", "rawBytes", "data"}
            or type(row.get("version")) is not int
            or row["version"] != 1
            or row.get("encoding") != "zlib+base64"
            or type(row.get("rawBytes")) is not int
            or not 0 <= row["rawBytes"] <= CLOUD_RAW_BLOB_LIMIT
            or not isinstance(row.get("data"), str)):
        raise BackendError("invalid_cloud_profile_envelope")
    if len(_canonical_json(blob)) > PROFILE_BLOB_LIMIT:
        raise BackendError("profile_too_large")
    try:
        compressed = base64.b64decode(row["data"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BackendError("invalid_cloud_profile_envelope") from exc
    if len(compressed) > PROFILE_BLOB_LIMIT:
        raise BackendError("profile_too_large")
    try:
        decoder = zlib.decompressobj()
        raw = decoder.decompress(compressed, CLOUD_RAW_BLOB_LIMIT + 1)
    except zlib.error as exc:
        raise BackendError("invalid_cloud_profile_envelope") from exc
    if (len(raw) > CLOUD_RAW_BLOB_LIMIT or len(raw) != row["rawBytes"]
            or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail):
        raise BackendError("invalid_cloud_profile_envelope")
    return _strict_json_object(raw)


@runtime_checkable
class EconomyBackend(Protocol):
    """Where one account's economy blob lives."""

    def load(self, user: object) -> tuple[dict | None, int]: ...

    def save(self, user: object, state: dict, expected_saved: int) -> int: ...


class FileEconomyBackend:
    """The original single-file persistence, moved here unchanged.

    The write is still temp-file + ``os.fsync`` + ``os.replace``.  The
    watermark check is advisory only: a local file has no other writer, so a
    mismatch means this process's own view drifted and is reported rather than
    silently overwritten.
    """

    def __init__(self, path: str | Path, *, enforce_expected_saved: bool = False) -> None:
        self.path = Path(path)
        self._enforce = bool(enforce_expected_saved)

    def load(self, user: object = None) -> tuple[dict | None, int]:
        if not self.path.is_file():
            return None, 0
        state = read_state_json(self.path)
        return state, _stored_saved(state)

    def save(self, user: object, state: dict, expected_saved: int = 0) -> int:
        if not isinstance(state, dict):
            raise BackendError("invalid_state_schema")
        if self._enforce and self.path.is_file():
            current = _stored_saved(read_state_json(self.path))
            if current != expected_saved:
                raise BackendConflict(saved=current)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.path.parent,
                                             prefix=self.path.name + ".", suffix=".tmp", delete=False) as handle:
                temporary = Path(handle.name)
                json.dump(state, handle, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            temporary = None
        except OSError as error:
            raise BackendError("state_write_failed") from error
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()
        return _stored_saved(state)


@runtime_checkable
class ProfileApi(Protocol):
    """The two Worker routes ``CloudEconomyBackend`` needs.

    ``get_profile()`` returns ``{schemaVersion, saved, blob}`` or ``None``
    (HTTP 404).  ``put_profile()`` writes with ``If-Match: "<expectedSaved>"``
    and raises on 409 ``profile_conflict`` / 400 ``profile_not_monotonic``.
    """

    def get_profile(self) -> dict | None: ...

    def put_profile(self, schema_version: int, saved: int, blob: Any,
                    expected_saved: int) -> dict: ...


class FakeProfileApi:
    """In-memory ``ProfileApi`` with the Worker's exact rejection rules."""

    def __init__(self) -> None:
        self.row: dict | None = None
        self.puts = 0
        self.gets = 0
        self.fail_next: Exception | None = None

    def get_profile(self) -> dict | None:
        self.gets += 1
        self._maybe_fail()
        return None if self.row is None else json.loads(json.dumps(self.row))

    def put_profile(self, schema_version: int, saved: int, blob: Any,
                    expected_saved: int) -> dict:
        self.puts += 1
        self._maybe_fail()
        if type(schema_version) is not int or type(saved) is not int or saved < 0:
            raise BackendError("invalid_saved")
        if not isinstance(blob, dict):
            raise BackendError("invalid_blob")
        serialized = json.dumps(blob, separators=(",", ":"), allow_nan=False)
        if len(serialized.encode("utf-8")) > PROFILE_BLOB_LIMIT:
            raise BackendError("profile_too_large")
        if self.row is None:
            # ``INSERT`` branch: only the create-only precondition may insert.
            if expected_saved:
                raise BackendConflict("profile_conflict", saved=0)
        else:
            current = int(self.row["saved"])
            if not expected_saved or current != expected_saved:
                raise BackendConflict("profile_conflict", saved=current)
            if saved <= current:
                raise BackendConflict("profile_not_monotonic", saved=current)
        self.row = {"schemaVersion": schema_version, "saved": saved,
                    "blob": json.loads(serialized)}
        return {"schemaVersion": schema_version, "saved": saved}

    def _maybe_fail(self) -> None:
        if self.fail_next is not None:
            error, self.fail_next = self.fail_next, None
            raise error


class CloudEconomyBackend:
    """Store the economy blob in the Worker profile API.

    The Worker never interprets the blob; it owns only the ``saved`` column's
    monotonicity and the optimistic-concurrency precondition, matching
    ``docs/EOS_CLOUDFLARE_ARCHITECTURE.md`` "Worker が必ず自分で決めるもの".

    Two different meanings of ``saved`` meet here and must not be conflated:

    * inside the blob, ``saved`` is the **native profile watermark**.  Durable
      server-only bookkeeping (freezing a battle roster) deliberately does not
      advance it, or a client that had just queued would look stale.
    * in the ``profiles`` row, ``saved`` is the **stored revision**, and
      ``private-server/src/profiles.ts`` enforces ``excluded.saved >
      profiles.saved`` on every write.

    They coincide for every profile-visible mutation.  For an unchanged
    watermark the row still has to advance, so the revision sent is
    ``max(native watermark, stored revision + 1)``: monotonic for the Worker,
    and the blob's own watermark is never rewritten.
    """

    def __init__(self, profile_api: ProfileApi, *, schema_version: int | None = None) -> None:
        self.profile_api = profile_api
        self._schema_version = schema_version

    def load(self, user: object = None) -> tuple[dict | None, int]:
        row = self.profile_api.get_profile()
        if row is None:
            return None, 0
        if not isinstance(row, dict):
            raise BackendError("invalid_state_schema")
        blob = row.get("blob")
        saved = row.get("saved")
        if not isinstance(blob, dict) or type(saved) is not int or saved < 0:
            raise BackendError("invalid_state_schema")
        return _cloud_decode_blob(blob), saved

    def save(self, user: object, state: dict, expected_saved: int = 0) -> int:
        if not isinstance(state, dict):
            raise BackendError("invalid_state_schema")
        schema_version = self._schema_version
        if schema_version is None:
            schema_version = state.get("schema_version")
        if type(schema_version) is not int or schema_version < 0:
            raise BackendError("invalid_state_schema")
        native_saved = _stored_saved(state)
        if native_saved <= 0:
            raise BackendError("invalid_saved")
        if type(expected_saved) is not int or expected_saved < 0:
            raise BackendError("invalid_saved")
        revision = max(native_saved, expected_saved + 1)
        encoded = _cloud_encode_blob(state)
        result = self.profile_api.put_profile(
            schema_version, revision, encoded, expected_saved)
        written = result.get("saved") if isinstance(result, dict) else None
        return written if type(written) is int and written >= 0 else revision


class _ApiClientProfileApi:
    """Adapt ``companion.api_client.ApiClient`` to :class:`ProfileApi`.

    ``ApiClient`` raises its own ``ConflictError``/``ApiError``/``NetworkError``
    hierarchy; those are translated so ``LocalEconomy`` sees one vocabulary.
    """

    def __init__(self, client: object) -> None:
        self._client = client
        self._errors = _api_client_errors()

    def get_profile(self) -> dict | None:
        api_error, conflict, network = self._errors
        try:
            return self._client.get_profile()
        except conflict as error:  # pragma: no cover - GET has no 409 route
            raise BackendConflict(getattr(error, "code", "profile_conflict")) from None
        except api_error as error:
            raise BackendError("profile_" + str(getattr(error, "code", "error"))) from None
        except network:
            raise BackendError("profile_unreachable") from None

    def put_profile(self, schema_version: int, saved: int, blob: Any,
                    expected_saved: int) -> dict:
        api_error, conflict, network = self._errors
        try:
            return self._client.put_profile(schema_version, saved, blob, expected_saved)
        except conflict as error:
            payload = getattr(error, "payload", {})
            stored = payload.get("saved") if isinstance(payload, dict) else None
            raise BackendConflict(
                str(getattr(error, "code", "profile_conflict")),
                saved=stored if type(stored) is int else None) from None
        except api_error as error:
            code = str(getattr(error, "code", "error"))
            if code == "profile_not_monotonic":
                raise BackendConflict(code) from None
            raise BackendError("profile_" + code) from None
        except network:
            raise BackendError("profile_unreachable") from None


def _api_client_errors() -> tuple[type, type, type]:
    """Import the companion error classes lazily; absence is not fatal."""
    try:
        from companion.api_client import ApiError, ConflictError, NetworkError
    except Exception:  # pragma: no cover - companion package is optional
        class _Missing(Exception):
            pass
        return _Missing, _Missing, _Missing
    return ApiError, ConflictError, NetworkError


def cloud_backend_from_api_client(client: object, *,
                                  schema_version: int | None = None) -> CloudEconomyBackend:
    """Wrap a ``companion.api_client.ApiClient`` as an ``EconomyBackend``."""
    if not hasattr(client, "get_profile") or not hasattr(client, "put_profile"):
        raise BackendError("invalid_profile_api")
    return CloudEconomyBackend(_ApiClientProfileApi(client), schema_version=schema_version)


def build_api_client(base_url: str, session_token: str, client_version: str,
                     timeout: float = 15.0) -> object:
    """Construct ``companion.api_client.ApiClient`` without a hard dependency."""
    try:
        from companion.api_client import ApiClient
    except Exception as error:  # pragma: no cover - companion package is optional
        raise BackendError("companion_package_unavailable") from error
    return ApiClient(base_url, client_version, session_token=session_token, timeout=timeout)


__all__ = [
    "BackendConflict",
    "BackendError",
    "CloudEconomyBackend",
    "EconomyBackend",
    "FakeProfileApi",
    "FileEconomyBackend",
    "PROFILE_BLOB_LIMIT",
    "ProfileApi",
    "SAVED_CONFLICT",
    "build_api_client",
    "cloud_backend_from_api_client",
    "read_state_json",
]
