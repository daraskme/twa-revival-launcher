"""Update manifest schema, canonical-JSON signing, and path safety.

Manifest schema (the Worker side implements the same shape when it starts
signing real manifests -- see docs/companion_updater_20260902.md for a
worked example)::

    {
      "channel": "stable",
      "version": "0.2.0",
      "createdAt": 1756800000000,
      "files": [
        {"path": "game.dll", "sha256": "<hex64>", "size": 12345678,
         "url": "https://.../game.dll"}
      ],
      "publicKeyId": "dev-2026-09",
      "signature": "<base64 Ed25519 signature>"
    }

The signature covers the *canonical JSON* of every field except
``signature`` itself. Canonical JSON here means: keys sorted recursively,
``separators=(",", ":")`` (no whitespace), ``ensure_ascii=False``, encoded
UTF-8. ``json.dumps(..., sort_keys=True)`` already sorts every nested dict,
so no manual recursive sort is needed.

Path safety follows the self-contained staging boundary in
``tools/stage_client.py``. ``client\\data`` and ``client\\cef`` are
Revival-owned real directories; ``client\\data.original-junction`` is the
only reference to the player's original data and is never updateable. A
manifest path must be a canonical relative path and match the explicit
allow-list below. Nested updates are limited to the copied WAD and the
fourteen terrain packs used by the reviewed deployment-point update.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import _ed25519

_REPO_ROOT = Path(__file__).resolve().parents[1]

_SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)

REQUIRED_TOP_FIELDS = {"channel", "version", "createdAt", "files", "publicKeyId", "signature"}
REQUIRED_FILE_FIELDS = {"path", "sha256", "size", "url"}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ManifestError(Exception):
    """Malformed manifest, untrusted key, or bad signature -- always reject."""


def canonical_json_bytes(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def semver_tuple(version: str) -> tuple[int, int, int, bool, tuple[Any, ...]]:
    """Comparable key for a semver string (release > any prerelease of the same core)."""
    match = _SEMVER_RE.match(version)
    if not match:
        raise ManifestError(f"invalid semver version: {version!r}")
    major, minor, patch, pre = match.groups()
    if pre is None:
        pre_key: tuple[Any, ...] = ()
    else:
        pre_key = tuple((0, int(p)) if p.isdigit() else (1, p) for p in pre.split("."))
    # `pre is None` sorts True > False, so a release outranks any prerelease
    # sharing the same major.minor.patch, matching semver precedence.
    return (int(major), int(minor), int(patch), pre is None, pre_key)


@dataclass(frozen=True)
class ManifestFile:
    path: str
    sha256: str
    size: int
    url: str


@dataclass(frozen=True)
class Manifest:
    channel: str
    version: str
    created_at: int
    files: tuple[ManifestFile, ...]
    public_key_id: str
    signature: str
    raw: dict[str, Any]


def verify_signature(data: dict[str, Any], trusted_keys: dict[str, str]) -> None:
    """Raise ManifestError unless data['signature'] is a valid Ed25519 signature
    over the canonical JSON of every other field, made by a key in trusted_keys."""
    if not isinstance(data, dict):
        raise ManifestError("manifest must be a JSON object")
    if "signature" not in data or "publicKeyId" not in data:
        raise ManifestError("manifest is missing signature/publicKeyId")
    key_id = data["publicKeyId"]
    pubkey_hex = trusted_keys.get(key_id)
    if pubkey_hex is None:
        raise ManifestError(f"untrusted publicKeyId: {key_id!r}")
    unsigned = {k: v for k, v in data.items() if k != "signature"}
    message = canonical_json_bytes(unsigned)
    try:
        signature = base64.b64decode(data["signature"], validate=True)
        pubkey = bytes.fromhex(pubkey_hex)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise ManifestError(f"malformed signature or pinned key: {exc}") from exc
    if not _ed25519.verify(pubkey, message, signature):
        raise ManifestError("manifest signature verification failed")


def parse_manifest(data: dict[str, Any]) -> Manifest:
    """Validate shape (not signature -- call verify_signature separately) and parse."""
    if not isinstance(data, dict):
        raise ManifestError("manifest must be a JSON object")
    missing = REQUIRED_TOP_FIELDS - data.keys()
    if missing:
        raise ManifestError(f"manifest missing fields: {sorted(missing)}")
    files_raw = data["files"]
    if not isinstance(files_raw, list):
        raise ManifestError("manifest 'files' must be a list")
    files: list[ManifestFile] = []
    for entry in files_raw:
        if not isinstance(entry, dict) or (REQUIRED_FILE_FIELDS - entry.keys()):
            raise ManifestError(f"invalid manifest file entry: {entry!r}")
        sha256 = str(entry["sha256"]).lower()
        if not _SHA256_RE.match(sha256):
            raise ManifestError(f"invalid sha256 in manifest: {entry['sha256']!r}")
        files.append(
            ManifestFile(
                path=validate_relative_path(str(entry["path"])),
                sha256=sha256,
                size=int(entry["size"]),
                url=str(entry["url"]),
            )
        )
    # Validated as a side effect: raises ManifestError on a bad semver string.
    semver_tuple(str(data["version"]))
    return Manifest(
        channel=str(data["channel"]),
        version=str(data["version"]),
        created_at=int(data["createdAt"]),
        files=tuple(files),
        public_key_id=str(data["publicKeyId"]),
        signature=str(data["signature"]),
        raw=data,
    )


# The observation-only link into the original install is never a distribution
# target. Keep the exact name here even though it is not in either allow-list,
# so failures explain the ownership boundary rather than merely "unknown".
PROTECTED_REFERENCE_DIRS = {"data.original-junction"}

# Explicit allow-list, not just "anything outside the original reference". These
# are the files stage_client.py currently vendors into client\ (COPY_NAMES)
# plus the small set of Revival-generated top-level files it also writes
# there. Extend this deliberately and add an exact nested path when needed,
# rather than loosening the check to a whole directory prefix.
try:
    _server_dir = str(_REPO_ROOT / "tools")
    if _server_dir not in sys.path:
        sys.path.insert(0, _server_dir)
    from stage_client import COPY_NAMES as _STAGE_COPY_NAMES  # type: ignore
except Exception:  # pragma: no cover - defensive: never let this import fail closed
    _STAGE_COPY_NAMES = []

ALLOWED_TOP_LEVEL_NAMES = {name.lower() for name in _STAGE_COPY_NAMES} | {
    "stack_config.json",
    "npl.conf",
    "language.txt",
}

# Exact owned assets: the Tier-X pack and the 14 reviewed deployment maps.
# Other terrain packs and arbitrary data/ or cef/ paths remain denied.
DEPLOYMENT_PACK_PATHS = frozenset({
    f"data/terrain_maps_{index}.pack"
    for index in (0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14)
})
ALLOWED_NESTED_PATHS = {"data/wad.pack"} | DEPLOYMENT_PACK_PATHS


def validate_relative_path(path: str) -> str:
    """Validate (and return unchanged) a manifest file path.

    Rejects: empty paths, backslashes, a leading '/', a drive letter, any
    '.' or '..' or empty path segment, the original-data reference, and
    anything not exactly named in the root or nested allow-list.
    """
    if not path or not isinstance(path, str):
        raise ManifestError("empty or non-string manifest path")
    if "\\" in path:
        raise ManifestError(f"backslash not allowed in manifest path: {path!r}")
    if path.startswith("/"):
        raise ManifestError(f"absolute manifest path not allowed: {path!r}")
    if re.match(r"^[A-Za-z]:", path):
        raise ManifestError(f"drive letter not allowed in manifest path: {path!r}")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ManifestError(f"invalid manifest path segment: {path!r}")
    top = parts[0].lower()
    if top in PROTECTED_REFERENCE_DIRS:
        raise ManifestError(f"manifest path targets the original-data reference: {path!r}")
    if len(parts) == 1 and top in ALLOWED_TOP_LEVEL_NAMES:
        return path
    if path in ALLOWED_NESTED_PATHS:
        return path
    raise ManifestError(f"manifest path is not in the client\\ allow-list: {path!r}")
