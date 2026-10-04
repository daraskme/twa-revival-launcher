"""Narrow local implementation of Arena's native profile preference object.

This is intentionally separate from the economy/profile authority.  Arena's
``MPFileStorage`` uses one opaque preference byte object at ``/<user_id>/blob``
for a small amount of native UI state (including ability slot indices).  The
local probe only serves the one identity bound to the process and stores the
exact bytes in the configured preference directory; it does not interpret
the payload or synthesize tutorial acknowledgements.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable


MAX_BLOB_BYTES = 512 * 1024
_USER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class NativeUserStorageError(ValueError):
    """A fail-closed request or storage error with an HTTP status."""

    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status = status
        self.code = code


@dataclass(frozen=True)
class StorageResponse:
    status: int
    body: bytes = b""
    content_type: str = "application/json"
    headers: dict[str, str] | None = None


def read_bounded_body(headers: object, stream: BinaryIO, *,
                      timeout_socket: object | None = None,
                      timeout_seconds: float = 5.0) -> bytes:
    """Read a fixed-length native PUT body; reject chunked/invalid framing."""
    get_all = getattr(headers, "get_all", None)
    transfer_values = get_all("Transfer-Encoding") if callable(get_all) else None
    if transfer_values is not None and len(transfer_values) != 1:
        raise NativeUserStorageError(400, "duplicate_transfer_encoding")
    transfer = (transfer_values[0] if transfer_values else
                headers.get("Transfer-Encoding") if hasattr(headers, "get") else None)
    if transfer is not None:
        raise NativeUserStorageError(400, "transfer_encoding_unsupported")
    length_values = get_all("Content-Length") if callable(get_all) else None
    if length_values is not None and len(length_values) != 1:
        raise NativeUserStorageError(400, "duplicate_content_length")
    raw_length = (length_values[0] if length_values else
                  headers.get("Content-Length") if hasattr(headers, "get") else None)
    raw_length_text = str(raw_length) if raw_length is not None else ""
    if raw_length is None or re.fullmatch(r"[0-9]+", raw_length_text) is None:
        raise NativeUserStorageError(400, "invalid_content_length")
    # A huge decimal must be rejected before int() so Python's conversion
    # digit limit cannot turn malformed framing into an uncaught exception.
    if len(raw_length_text) > len(str(MAX_BLOB_BYTES)):
        raise NativeUserStorageError(413, "profile_too_large")
    length = int(raw_length_text)
    if length > MAX_BLOB_BYTES:
        raise NativeUserStorageError(413, "profile_too_large")
    previous_timeout = None
    timeout_changed = False
    if timeout_socket is not None:
        get_timeout = getattr(timeout_socket, "gettimeout", None)
        set_timeout = getattr(timeout_socket, "settimeout", None)
        if not callable(get_timeout) or not callable(set_timeout):
            raise NativeUserStorageError(503, "body_timeout_unavailable")
        try:
            previous_timeout = get_timeout()
            set_timeout(timeout_seconds)
            timeout_changed = True
        except (OSError, TimeoutError) as exc:
            raise NativeUserStorageError(503, "body_timeout_unavailable") from exc
    try:
        body = stream.read(length)
    except (OSError, TimeoutError) as exc:
        raise NativeUserStorageError(408, "body_read_failed") from exc
    finally:
        if timeout_changed:
            try:
                set_timeout(previous_timeout)
            except (OSError, TimeoutError):
                pass
    if len(body) != length:
        raise NativeUserStorageError(400, "truncated_body")
    return body


def _is_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise NativeUserStorageError(503, "storage_stat_failed") from exc
    if stat.S_ISLNK(info.st_mode):
        return True
    # Windows junctions and other reparse points are not always symlinks.
    return bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _safe_child(root: Path, child: Path) -> Path:
    # Inspect the lexical path before resolving it.  Resolving first would
    # hide a junction/symlink through which mkdir or replace could escape.
    root = Path(os.path.abspath(root))
    child = Path(os.path.abspath(child))
    for path in (root, child):
        cursor = path
        while True:
            if _is_reparse(cursor):
                raise NativeUserStorageError(503, "storage_reparse_rejected")
            parent = cursor.parent
            if parent == cursor:
                break
            cursor = parent
    root_real = root.resolve(strict=False)
    candidate = child.resolve(strict=False)
    try:
        if os.path.commonpath((os.fspath(root_real), os.fspath(candidate))) != os.fspath(root_real):
            raise NativeUserStorageError(400, "invalid_storage_path")
    except ValueError as exc:
        raise NativeUserStorageError(400, "invalid_storage_path") from exc
    return candidate


class NativeUserStorage:
    """Persist exactly one process-bound ``/<user_id>/blob`` object."""

    def __init__(self, root: str | Path, user_id: str | Callable[[], str]):
        self.root = Path(root)
        self._user_id = user_id
        _safe_child(self.root, self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        _safe_child(self.root, self.root)
        self._lock = threading.RLock()

    def current_user_id(self) -> str:
        value = self._user_id() if callable(self._user_id) else self._user_id
        if not isinstance(value, str) or _USER_ID.fullmatch(value) is None:
            raise NativeUserStorageError(503, "native_identity_unavailable")
        return value

    @staticmethod
    def is_blob_path(path: str) -> bool:
        normalized = path.rstrip("/") or "/"
        return normalized.endswith("/blob") and normalized.count("/") >= 2

    def matches_path(self, path: str, user_id: str | None = None) -> bool:
        expected = f"/{self.current_user_id() if user_id is None else user_id}/blob"
        return (path.rstrip("/") or "/") == expected

    def _path(self, user_id: str) -> Path:
        if _USER_ID.fullmatch(user_id) is None:
            raise NativeUserStorageError(400, "invalid_storage_path")
        # Keep the native user id out of the filesystem path; this also makes
        # separator and reparse attacks impossible even if validation changes.
        filename = hashlib.sha256(user_id.encode("utf-8")).hexdigest() + ".blob"
        return _safe_child(self.root, self.root / filename)

    def handle(self, method: str, path: str, body: bytes = b"") -> StorageResponse | None:
        """Handle the exact object, or return ``None`` for unrelated routes."""
        with self._lock:
            normalized = path.rstrip("/") or "/"
            if not self.is_blob_path(normalized):
                return None
            user_id = self.current_user_id()
            if not self.matches_path(normalized, user_id):
                return self._missing(method)
            if method not in {"GET", "PUT", "HEAD"}:
                return StorageResponse(405, b'{"error":"method_not_allowed"}',
                                       headers={"Allow": "GET, PUT, HEAD"})
            target = self._path(user_id)
            if method == "PUT":
                if not isinstance(body, bytes):
                    return StorageResponse(400, b'{"error":"invalid_body"}')
                if len(body) > MAX_BLOB_BYTES:
                    return StorageResponse(413, b'{"error":"profile_too_large"}')
                temporary: Path | None = None
                try:
                    _safe_child(self.root, self.root)
                    with tempfile.NamedTemporaryFile(dir=self.root, prefix=".blob-", suffix=".tmp", delete=False) as stream:
                        temporary = Path(stream.name)
                        _safe_child(self.root, temporary)
                        stream.write(body)
                        stream.flush()
                        os.fsync(stream.fileno())
                    _safe_child(self.root, target)
                    self._validate_existing(target)
                    os.replace(temporary, target)
                    temporary = None
                except OSError as exc:
                    raise NativeUserStorageError(503, "storage_write_failed") from exc
                finally:
                    if temporary is not None:
                        temporary.unlink(missing_ok=True)
            try:
                data = self._read_existing(target)
            except FileNotFoundError:
                return self._missing(method)
            etag = '"' + hashlib.sha256(data).hexdigest() + '"'
            # PUT is an S3-style acknowledgement; GET returns bytes while
            # HEAD carries the representation length without a body.
            response_body = data if method == "GET" else b""
            response_headers = {"ETag": etag}
            if method != "PUT":
                response_headers["Content-Length"] = str(len(data))
            return StorageResponse(200, response_body,
                                   content_type="application/octet-stream",
                                   headers=response_headers)

    @staticmethod
    def _missing(method: str) -> StorageResponse:
        error = (b'<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>')
        return StorageResponse(404, b"" if method == "HEAD" else error,
                               content_type="application/xml",
                               headers={"Content-Length": str(0 if method == "HEAD" else len(error))})

    def _validate_existing(self, target: Path) -> None:
        try:
            info = target.lstat()
        except FileNotFoundError:
            return
        if _is_reparse(target) or not stat.S_ISREG(info.st_mode):
            raise NativeUserStorageError(503, "storage_object_invalid")
        if info.st_nlink != 1:
            raise NativeUserStorageError(503, "storage_object_hardlinked")
        if info.st_size > MAX_BLOB_BYTES:
            raise NativeUserStorageError(413, "profile_too_large")

    def _read_existing(self, target: Path) -> bytes:
        self._validate_existing(target)
        with target.open("rb") as stream:
            data = stream.read(MAX_BLOB_BYTES + 1)
        if len(data) > MAX_BLOB_BYTES:
            raise NativeUserStorageError(413, "profile_too_large")
        return data


__all__ = [
    "MAX_BLOB_BYTES", "NativeUserStorage", "NativeUserStorageError",
    "StorageResponse", "read_bounded_body",
]
