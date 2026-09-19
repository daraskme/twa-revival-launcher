"""Fetch, verify, stage, and atomically apply a signed client update.

Manifest paths are validated before use and then checked again against the
live filesystem. A newly staged client owns real ``client/data`` and
``client/cef`` directories; nested payloads are limited to the copied WAD
and the explicitly allowed terrain packs. Every existing component on that target path must
be a normal file/directory, never a symlink or Windows junction.

Downloads are hash/size verified in the companion state directory. Existing
targets are backed up atomically, replacements use a same-directory temporary
file plus ``os.replace()``, and any later failure rolls back already replaced
files. Both the client and companion state trees must be disjoint from the
read-only original tree. Arena.exe must be closed for every non-empty plan.
"""
from __future__ import annotations

import csv
import hashlib
import json
import ntpath
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .api_client import ApiClient
from .client_lock import ClientOperationLockError, client_operation_lock
from .config import CLIENT_UPDATE_STATE_FILENAME, Config, save_update_state
from .manifest import (
    Manifest,
    ManifestError,
    parse_manifest,
    semver_tuple,
    validate_relative_path,
    verify_signature,
)
from .trusted_keys import PUBLIC_DOWNLOAD_ORIGIN, RELEASE_TRUSTED_KEYS, TRUSTED_KEYS

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class UpdaterError(Exception):
    """A check/apply failure; unsafe filesystem targets are always rejected."""


class ArenaRunningError(UpdaterError):
    """apply() refuses to touch client files while Arena.exe is running."""


class ArenaDetectionError(UpdaterError):
    """Arena process state could not be established safely."""


@dataclass(frozen=True)
class UpdatePlanFile:
    path: str
    sha256: str
    size: int
    url: str


@dataclass(frozen=True)
class UpdatePlan:
    channel: str
    version: str
    current_version: str
    files: tuple[UpdatePlanFile, ...]

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self.files)


@dataclass(frozen=True)
class _AppliedFile:
    plan_file: UpdatePlanFile
    backup_path: Path | None


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return path.is_symlink() or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _require_real_directory(path: Path, label: str) -> None:
    if not _lexists(path) or _is_reparse_point(path) or not path.is_dir():
        raise UpdaterError(f"{label} must be an existing real directory: {path}")


def _require_regular_or_missing(path: Path, label: str) -> None:
    if not _lexists(path):
        return
    if _is_reparse_point(path) or not path.is_file():
        raise UpdaterError(f"{label} must be a regular file, not a symlink/junction: {path}")


def _require_unshared_regular_or_missing(path: Path, label: str) -> None:
    """Reject links whose content or directory entry is not updater-owned."""
    _require_regular_or_missing(path, label)
    if not _lexists(path):
        return
    try:
        link_count = path.lstat().st_nlink
    except OSError as exc:
        raise UpdaterError(f"cannot inspect {label}: {path}: {exc}") from exc
    if link_count != 1:
        raise UpdaterError(
            f"{label} must not be a hard link (link count {link_count}): {path}"
        )


def _is_same_or_beneath(candidate: Path, root: Path) -> bool:
    """Compare absolute paths with Windows' case-insensitive semantics."""
    candidate_text = ntpath.normcase(ntpath.abspath(os.fspath(candidate)))
    root_text = ntpath.normcase(ntpath.abspath(os.fspath(root)))
    try:
        return ntpath.commonpath((candidate_text, root_text)) == root_text
    except ValueError:
        return False


def _resolve_boundary_directory(
    path: Path, label: str, *, allow_missing: bool
) -> tuple[Path, Path]:
    try:
        raw = Path(os.path.abspath(path))
    except (OSError, TypeError, ValueError) as exc:
        raise UpdaterError(f"cannot resolve {label} safely: {exc}") from exc

    exists = _lexists(raw)
    if exists:
        _require_real_directory(raw, label)
    elif not allow_missing:
        raise UpdaterError(f"{label} must be an existing real directory: {raw}")
    else:
        # state_dir normally does not exist before the first successful use.
        # Its nearest existing parent must itself be a real directory, and
        # resolve(strict=False) below canonicalizes any earlier path aliases.
        parent = raw.parent
        while not _lexists(parent):
            if parent.parent == parent:
                raise UpdaterError(f"cannot resolve {label} safely: {raw}")
            parent = parent.parent
        _require_real_directory(parent, f"existing parent of {label}")

    try:
        resolved = raw.resolve(strict=exists)
    except (OSError, RuntimeError) as exc:
        raise UpdaterError(f"cannot resolve {label} safely: {exc}") from exc
    return raw, resolved


def _require_safe_update_boundaries(config: Config) -> None:
    """Prove that every updater-owned tree is disjoint from the original.

    The client and original must already be real directories. The state tree
    may be absent on first use, but its canonical location must still resolve
    safely. Checking in both directions prevents the original from being
    placed below a mutable client/state root as well as preventing writes
    below the original. Custom Config objects receive the same checks.
    """
    if config.original_dir is None:
        raise UpdaterError("original directory is not configured; cannot verify update boundary")

    raw_original, resolved_original = _resolve_boundary_directory(
        config.original_dir, "original directory", allow_missing=False
    )
    destinations = (
        (*_resolve_boundary_directory(
            config.client_dir, "client directory", allow_missing=False
        ), "client directory"),
        (*_resolve_boundary_directory(
            config.state_dir, "companion state directory", allow_missing=True
        ), "companion state directory"),
    )
    for raw_destination, resolved_destination, label in destinations:
        raw_overlap = _is_same_or_beneath(
            raw_destination, raw_original
        ) or _is_same_or_beneath(raw_original, raw_destination)
        resolved_overlap = _is_same_or_beneath(
            resolved_destination, resolved_original
        ) or _is_same_or_beneath(resolved_original, resolved_destination)
        if raw_overlap or resolved_overlap:
            raise UpdaterError(
                f"{label} must be disjoint from the owned original directory: "
                f"{label}={raw_destination}, original={raw_original}"
            )


def _safe_client_target(config: Config, relative_path: str) -> Path:
    """Return an allow-listed target after rejecting every traversed reparse point."""
    _require_safe_update_boundaries(config)
    relative_path = validate_relative_path(relative_path)
    root = Path(os.path.abspath(config.client_dir))
    _require_real_directory(root, "client directory")
    parts = relative_path.split("/")
    parent = root
    for segment in parts[:-1]:
        parent = parent / segment
        _require_real_directory(parent, f"client path component {segment!r}")
    target = parent / parts[-1]
    _require_regular_or_missing(target, "client update target")
    return target


def _safe_state_target(root: Path, version: str, relative_path: str) -> Path:
    """Create state subdirectories one at a time while refusing reparse points."""
    semver_tuple(version)
    relative_path = validate_relative_path(relative_path)
    root = Path(os.path.abspath(root))
    if not _lexists(root):
        root.mkdir(parents=True)
    _require_real_directory(root, "companion update state directory")
    current = root
    for segment in (version, *relative_path.split("/")[:-1]):
        current = current / segment
        if not _lexists(current):
            current.mkdir()
        _require_real_directory(current, "companion update state path")
    target = current / relative_path.split("/")[-1]
    _require_regular_or_missing(target, "companion update state file")
    return target


def _prepare_state_root(config: Config) -> None:
    root = Path(os.path.abspath(config.state_dir))
    if not _lexists(root):
        root.mkdir(parents=True)
    _require_real_directory(root, "companion state directory")


def _safe_common_update_state_path(config: Config) -> Path:
    """Return the canonical client-local update floor after strict checks."""
    _require_safe_update_boundaries(config)
    root = Path(os.path.abspath(config.client_dir))
    _require_real_directory(root, "client directory")
    expected = root / CLIENT_UPDATE_STATE_FILENAME
    path = Path(os.path.abspath(config.update_state_path))
    if ntpath.normcase(os.fspath(path)) != ntpath.normcase(os.fspath(expected)):
        raise UpdaterError(
            "update state must use the canonical client-local path: "
            f"expected {expected}, got {path}"
        )
    _require_unshared_regular_or_missing(path, "client update state file")
    return path


def _safe_legacy_update_state_path(config: Config) -> Path:
    """Return the old state-dir floor, which is migration-read-only."""
    _require_safe_update_boundaries(config)
    root = Path(os.path.abspath(config.state_dir))
    expected = root / "update_state.json"
    path = Path(os.path.abspath(config.legacy_update_state_path))
    if ntpath.normcase(os.fspath(path)) != ntpath.normcase(os.fspath(expected)):
        raise UpdaterError(
            "legacy update state must use the canonical state-directory path: "
            f"expected {expected}, got {path}"
        )
    _require_unshared_regular_or_missing(path, "legacy update state file")
    return path


def local_sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    hasher = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _verified_size_and_hash(path: Path, expected_sha256: str, expected_size: int, label: str) -> None:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise UpdaterError(f"cannot inspect {label}: {path}: {exc}") from exc
    if size != expected_size:
        raise UpdaterError(f"{label} size mismatch: {path}")
    if local_sha256(path) != expected_sha256:
        raise UpdaterError(f"{label} hash mismatch: {path}")


def _atomic_verified_copy(source: Path, target: Path, expected_sha256: str, expected_size: int) -> None:
    """Copy to a unique same-directory file, verify, then atomically replace."""
    fd, raw_tmp = tempfile.mkstemp(
        prefix=f".{target.name}.update-", suffix=".tmp", dir=target.parent
    )
    os.close(fd)
    tmp = Path(raw_tmp)
    try:
        shutil.copy2(source, tmp)
        _verified_size_and_hash(tmp, expected_sha256, expected_size, "temporary update file")
        os.replace(tmp, target)
    finally:
        tmp.unlink(missing_ok=True)


def _default_process_lister() -> str:
    """Return a complete CSV process snapshot, failing closed on tool errors.

    Listing every process avoids tasklist's localized, non-CSV "no matches"
    message.  A successful snapshot therefore has a parseable row even when
    Arena is absent.
    """
    try:
        result = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ArenaDetectionError(f"cannot inspect Arena.exe process state: {exc}") from exc
    if result.returncode != 0 or result.stderr.strip():
        detail = (result.stderr or result.stdout).strip()
        raise ArenaDetectionError(
            "cannot inspect Arena.exe process state"
            + (f": {detail}" if detail else f" (tasklist exit {result.returncode})")
        )
    return result.stdout


def is_arena_running(process_lister: Callable[[], str] | None = None) -> bool:
    lister = process_lister or _default_process_lister
    try:
        output = lister()
    except ArenaDetectionError:
        raise
    except Exception as exc:
        raise ArenaDetectionError(f"cannot inspect Arena.exe process state: {exc}") from exc
    if not isinstance(output, str):
        raise ArenaDetectionError("Arena.exe process snapshot is not text")
    lines = [line for line in output.splitlines() if line.strip()]
    if not lines:
        raise ArenaDetectionError("Arena.exe process snapshot is empty")
    # Keep the exact English filtered-tasklist sentinel for injected/legacy
    # callers. Other prose is ambiguous and must never be treated as "closed".
    if len(lines) == 1 and re.fullmatch(
        r"INFO:\s*No tasks are running which match the specified criteria\.?",
        lines[0].strip(), re.IGNORECASE,
    ):
        return False
    found = False
    for line in lines:
        try:
            row = next(csv.reader([line], strict=True))
        except (csv.Error, StopIteration) as exc:
            raise ArenaDetectionError("Arena.exe process snapshot is malformed") from exc
        if (len(row) != 5 or not row[0].strip()
                or not row[1].strip().isdigit()):
            raise ArenaDetectionError("Arena.exe process snapshot is ambiguous")
        if row[0].strip().casefold() == "arena.exe":
            found = True
    return found


def _reject_duplicate_json_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _read_update_state_version(path: Path, label: str) -> str | None:
    """Read an exact updater-owned state shape, or fail closed if it is corrupt."""
    if not _lexists(path):
        return None
    _require_unshared_regular_or_missing(path, label)
    try:
        raw = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_fields,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise UpdaterError(f"{label} is unreadable or corrupt: {path}: {exc}") from exc

    required_fields = {"version", "applied_at", "files"}
    if not isinstance(raw, dict) or set(raw) != required_fields:
        raise UpdaterError(
            "update state has invalid fields; expected exactly "
            f"{sorted(required_fields)}: {path}"
        )
    version = raw["version"]
    applied_at = raw["applied_at"]
    files = raw["files"]
    if not isinstance(version, str):
        raise UpdaterError(f"update state version must be a semver string: {path}")
    try:
        semver_tuple(version)
    except ManifestError as exc:
        raise UpdaterError(f"update state version is invalid: {path}: {exc}") from exc
    if isinstance(applied_at, bool) or not isinstance(applied_at, int) or applied_at < 0:
        raise UpdaterError(f"update state applied_at must be a non-negative integer: {path}")
    if not isinstance(files, list) or any(not isinstance(item, str) for item in files):
        raise UpdaterError(f"update state files must be a list of path strings: {path}")
    if len(files) != len(set(files)):
        raise UpdaterError(f"update state files contains duplicate paths: {path}")
    try:
        for item in files:
            validate_relative_path(item)
    except ManifestError as exc:
        raise UpdaterError(f"update state contains an invalid file path: {path}: {exc}") from exc
    return version


def _read_installed_update_versions(config: Config) -> tuple[str, ...]:
    """Read the common floor and the legacy override floor, both fail-closed."""
    versions: list[str] = []
    common_version = _read_common_update_version(config)
    if common_version is not None:
        versions.append(common_version)
    legacy_version = _read_update_state_version(
        _safe_legacy_update_state_path(config), "legacy update state file"
    )
    if legacy_version is not None:
        versions.append(legacy_version)
    return tuple(versions)


def _read_common_update_version(config: Config) -> str | None:
    return _read_update_state_version(
        _safe_common_update_state_path(config), "client update state file"
    )


def _effective_current_version(
    config: Config,
) -> tuple[str, tuple[int, int, int, bool, tuple[object, ...]]]:
    """Return max(config, common-client, and legacy installed-state versions)."""
    try:
        configured_key = semver_tuple(config.client_version)
    except (ManifestError, TypeError) as exc:
        raise UpdaterError(f"configured client version is invalid: {exc}") from exc
    highest_version = config.client_version
    highest_key = configured_key
    for installed_version in _read_installed_update_versions(config):
        installed_key = semver_tuple(installed_version)
        if installed_key > highest_key:
            highest_version = installed_version
            highest_key = installed_key
    return highest_version, highest_key


def fetch_manifest(config: Config, api: ApiClient, trusted_keys: dict[str, str] | None = None) -> Manifest:
    public_release = getattr(api, "base_url", None) == PUBLIC_DOWNLOAD_ORIGIN
    default_keys = RELEASE_TRUSTED_KEYS if public_release else TRUSTED_KEYS
    trusted = default_keys if trusted_keys is None else trusted_keys
    raw = api.update_manifest(config.channel)
    verify_signature(raw, trusted)
    manifest = parse_manifest(raw)
    if manifest.channel != config.channel:
        raise UpdaterError(
            f"manifest channel {manifest.channel!r} does not match configured channel {config.channel!r}"
        )
    if public_release:
        for entry in manifest.files:
            if entry.url != f'{PUBLIC_DOWNLOAD_ORIGIN}/v1/update/object/game/{manifest.version}/{entry.path}':
                raise UpdaterError('game update URL does not match the public release')
    return manifest


def check(config: Config, api: ApiClient, trusted_keys: dict[str, str] | None = None) -> UpdatePlan:
    """Fetch+verify the manifest and diff it against client_dir. Never writes."""
    _require_safe_update_boundaries(config)
    current_version, current_v = _effective_current_version(config)
    manifest = fetch_manifest(config, api, trusted_keys)
    manifest_v = semver_tuple(manifest.version)
    if manifest_v < current_v:
        raise UpdaterError(
            f"manifest version {manifest.version} is older than installed {current_version}; "
            "refusing a signed downgrade"
        )
    files: list[UpdatePlanFile] = []
    for entry in manifest.files:
        target = _safe_client_target(config, entry.path)
        if local_sha256(target) != entry.sha256:
            files.append(
                UpdatePlanFile(
                    path=entry.path,
                    sha256=entry.sha256,
                    size=entry.size,
                    url=entry.url,
                )
            )
    return UpdatePlan(
        channel=manifest.channel,
        version=manifest.version,
        current_version=current_version,
        files=tuple(files),
    )


def _validate_plan(
    config: Config,
    plan: UpdatePlan,
    current_version: str,
    current_v: tuple[int, int, int, bool, tuple[object, ...]],
) -> None:
    try:
        plan_v = semver_tuple(plan.version)
        semver_tuple(plan.current_version)
    except (ManifestError, TypeError) as exc:
        raise UpdaterError(f"update plan contains an invalid version: {exc}") from exc
    if plan_v < current_v:
        raise UpdaterError(
            f"update plan version {plan.version} is older than installed {current_version}; "
            "refusing a downgrade"
        )
    seen: set[str] = set()
    for plan_file in plan.files:
        if plan_file.path.casefold() == CLIENT_UPDATE_STATE_FILENAME.casefold():
            raise UpdaterError(
                f"update plan path is reserved for the version floor: {plan_file.path}"
            )
        if plan_file.path in seen:
            raise UpdaterError(f"duplicate update path: {plan_file.path}")
        seen.add(plan_file.path)
        validate_relative_path(plan_file.path)
        if not _SHA256_RE.fullmatch(plan_file.sha256):
            raise UpdaterError(f"invalid update sha256: {plan_file.path}")
        if plan_file.size < 0:
            raise UpdaterError(f"invalid update size: {plan_file.path}")
        _safe_client_target(config, plan_file.path)


def _rollback(config: Config, version: str, applied: list[_AppliedFile]) -> list[str]:
    """Restore replaced files without ever following a newly introduced link."""
    errors: list[str] = []
    for record in reversed(applied):
        plan_file = record.plan_file
        try:
            target = _safe_client_target(config, plan_file.path)
            if record.backup_path is None:
                target.unlink(missing_ok=True)
                continue
            backup = _safe_state_target(config.backup_dir, version, plan_file.path)
            if backup != record.backup_path:
                raise UpdaterError(f"rollback backup path changed: {backup}")
            if not backup.is_file():
                raise UpdaterError(f"rollback backup is missing: {backup}")
            digest = local_sha256(backup)
            if digest is None:
                raise UpdaterError(f"cannot hash rollback backup: {backup}")
            _atomic_verified_copy(backup, target, digest, backup.stat().st_size)
            _verified_size_and_hash(target, digest, backup.stat().st_size, "restored target")
        except Exception as exc:  # report every failed restore to the caller
            errors.append(f"{plan_file.path}: {exc}")
    return errors


def _write_plan_state(config: Config, plan: UpdatePlan) -> None:
    """Durably record a successful manifest in the canonical client state."""
    state = {
        "version": plan.version,
        "applied_at": int(time.time()),
        "files": [f.path for f in plan.files],
    }
    path = _safe_common_update_state_path(config)
    save_update_state(config, state)
    path = _safe_common_update_state_path(config)
    if _read_update_state_version(path, "client update state file") != plan.version:
        raise UpdaterError(f"client update state did not record version {plan.version}: {path}")


def _publish_staged_update(
    config: Config,
    plan: UpdatePlan,
    staged: dict[str, Path],
    process_lister: Callable[[], str] | None,
) -> dict[str, object]:
    """Publish verified payloads while the caller holds the client lock."""
    # Another updater may have advanced (or corrupted) the common or legacy
    # update state during a long download. The shared lock makes this floor
    # check and the eventual common-state write one serialized critical section.
    current_version, current_v = _effective_current_version(config)
    _validate_plan(config, plan, current_version, current_v)

    # A Companion launch takes the same lock around process creation. Thus a
    # supported launch cannot enter between this check and the final publish.
    if is_arena_running(process_lister):
        raise ArenaRunningError(
            "Arena.exe started while the update was staging; "
            "close it before applying the verified payload"
        )

    applied: list[_AppliedFile] = []
    try:
        for plan_file in plan.files:
            target = _safe_client_target(config, plan_file.path)
            backup_path: Path | None = None
            if target.is_file():
                original_hash = local_sha256(target)
                if original_hash is None:
                    raise UpdaterError(f"cannot hash existing target: {target}")
                original_size = target.stat().st_size
                backup_path = _safe_state_target(
                    config.backup_dir, plan.version, plan_file.path
                )
                _atomic_verified_copy(
                    target,
                    backup_path,
                    original_hash,
                    original_size,
                )
                _verified_size_and_hash(
                    backup_path,
                    original_hash,
                    original_size,
                    "update backup",
                )

            # Recheck both paths immediately before publishing. This catches a
            # local symlink/junction swap between download and apply.
            target = _safe_client_target(config, plan_file.path)
            source = _safe_state_target(config.staging_dir, plan.version, plan_file.path)
            if staged.get(plan_file.path) != source:
                raise UpdaterError(f"staged update path changed: {plan_file.path}")
            _verified_size_and_hash(
                source,
                plan_file.sha256,
                plan_file.size,
                "staged update file",
            )
            _atomic_verified_copy(
                source,
                target,
                plan_file.sha256,
                plan_file.size,
            )
            applied.append(_AppliedFile(plan_file=plan_file, backup_path=backup_path))
            target = _safe_client_target(config, plan_file.path)
            _verified_size_and_hash(
                target,
                plan_file.sha256,
                plan_file.size,
                "applied update file",
            )

        _write_plan_state(config, plan)
    except Exception as exc:
        rollback_errors = _rollback(config, plan.version, applied)
        if rollback_errors:
            raise UpdaterError(
                "update failed and rollback was incomplete: " + "; ".join(rollback_errors)
            ) from exc
        raise

    return {
        "ok": True,
        "applied": True,
        "version": plan.version,
        "files": [f.path for f in plan.files],
    }


def apply(
    config: Config,
    api: ApiClient,
    plan: UpdatePlan,
    process_lister: Callable[[], str] | None = None,
) -> dict[str, object]:
    _require_safe_update_boundaries(config)
    current_version, current_v = _effective_current_version(config)
    _validate_plan(config, plan, current_version, current_v)
    if not plan.files:
        # A newer signed manifest can already match every local byte (for
        # example after a manually staged, subsequently published build). If
        # we merely report success, the installed-version floor remains old
        # and an older signed manifest can later be replayed as an apparent
        # upgrade. Serialize the final floor check and durable observation
        # with normal update/launch operations even though no client file is
        # replaced. Equal-version checks are a true no-op only after the
        # canonical client-local floor exists at that same version; otherwise
        # this pass also migrates a legacy/config-only floor.
        try:
            with client_operation_lock(config.client_dir):
                _require_safe_update_boundaries(config)
                locked_version, locked_v = _effective_current_version(config)
                _validate_plan(config, plan, locked_version, locked_v)
                common_version = _read_common_update_version(config)
                common_v = (
                    semver_tuple(common_version)
                    if common_version is not None
                    else None
                )
                if semver_tuple(plan.version) == locked_v and common_v == locked_v:
                    return {
                        "ok": True,
                        "applied": False,
                        "version": plan.version,
                        "reason": "up_to_date",
                        "files": [],
                    }
                _write_plan_state(config, plan)
                return {
                    "ok": True,
                    "applied": False,
                    "version": plan.version,
                    "reason": "verified_version_recorded",
                    "files": [],
                }
        except ClientOperationLockError as exc:
            raise UpdaterError(f"cannot record update safely: {exc}") from exc
    if is_arena_running(process_lister):
        raise ArenaRunningError("Arena.exe is running; close it before applying an update")

    _prepare_state_root(config)

    # Download into the private state directory. ApiClient verifies while
    # streaming; the checks here defend the hand-off and reject stale links.
    staged: dict[str, Path] = {}
    for plan_file in plan.files:
        destination = _safe_state_target(config.staging_dir, plan.version, plan_file.path)
        partial = destination.with_name(destination.name + ".part")
        _require_regular_or_missing(partial, "partial download file")
        # ApiClient opens this deterministic name for writing. Remove a stale
        # regular file first so even an unexpected hard link cannot be edited
        # in place; a reparse point was rejected above.
        partial.unlink(missing_ok=True)
        api.download_object(
            plan_file.url,
            destination,
            plan_file.sha256,
            plan_file.size,
        )
        destination = _safe_state_target(config.staging_dir, plan.version, plan_file.path)
        _verified_size_and_hash(
            destination,
            plan_file.sha256,
            plan_file.size,
            "staged update file",
        )
        staged[plan_file.path] = destination

    try:
        with client_operation_lock(config.client_dir):
            return _publish_staged_update(config, plan, staged, process_lister)
    except ClientOperationLockError as exc:
        raise UpdaterError(f"cannot apply update safely: {exc}") from exc
