"""Guarded local installer for one reviewed five-file native-mode bundle.

This is a review/install tool, not the Companion updater.  It is read-only by
default.  The manifest and every agent receipt are checked before any target
replacement; ``--apply`` then performs same-directory atomic replacements
under the shared copied-client lock.  The owned original is only hashed.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import ntpath
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from companion.client_lock import ClientOperationLockError, client_operation_lock
from tools.original_safety import (OriginalSafetyError, atomic_write_output,
                                   configured_original)


DESTINATIONS = (
    "game.dll",
    "data/dui5.pack",
    "data/local_en.pack",
    "data/local_ja.pack",
    "data/local_ru.pack",
)
DEFAULT_INSTALL_MANIFEST = Path("work/native-battle-mode-install.json")
TARGET_WAD = "data/wad.pack"
ORIGINAL_SNAPSHOT = ("game.dll", "data/dui5.pack", "data/local_en.pack",
                     "data/local_ja.pack", "data/local_ru.pack", TARGET_WAD)
OPTIONAL_ORIGINAL_SNAPSHOT = {"data/local_ru.pack"}
SELECTOR_PATHS = ("language.txt", "data/language.txt")
PROFILE_RELATIVE = "work/live_v30_tier10_abilities/economy.json"
RECEIPT_FIELDS = {"input_sha256", "output_sha256", "written", "runtime_verified"}


class InstallError(RuntimeError):
    """A required trust boundary or review receipt could not be proven."""


@dataclass(frozen=True)
class InstallItem:
    destination: str
    source: Path
    source_sha256: str
    expected_existing_sha256: str
    receipt_path: Path
    receipt_sha256: str


@dataclass(frozen=True)
class InstallPlan:
    repo_root: Path
    client: Path
    data: Path
    original: Path
    profile_snapshot: Path
    manifest_path: Path
    manifest_bytes: bytes
    items: tuple[InstallItem, ...]
    original_before: dict[str, str | None]
    selectors_before: dict[str, str | None]
    target_wad_before: str
    profile_before: str


def _is_reparse(path: Path) -> bool:
    metadata = path.lstat()
    return path.is_symlink() or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _same_path(left: Path, right: Path) -> bool:
    return ntpath.normcase(ntpath.abspath(os.fspath(left))) == ntpath.normcase(
        ntpath.abspath(os.fspath(right)))


def _same_or_beneath(candidate: Path, root: Path) -> bool:
    try:
        return ntpath.commonpath((ntpath.normcase(ntpath.abspath(os.fspath(candidate))),
                                  ntpath.normcase(ntpath.abspath(os.fspath(root))))) \
            == ntpath.normcase(ntpath.abspath(os.fspath(root)))
    except ValueError:
        return False


def _require_real_directory(path: Path, label: str) -> Path:
    current = Path(os.path.abspath(path))
    if not os.path.lexists(current):
        raise InstallError(f"{label} is missing")
    while True:
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise InstallError(f"cannot inspect {label}") from exc
        if not current.is_dir() or _is_reparse(current):
            raise InstallError(f"{label} contains a non-directory or reparse point")
        if current.parent == current:
            return Path(os.path.abspath(path))
        current = current.parent


def _work_file(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, (str, os.PathLike)) or not os.fspath(value):
        raise InstallError(f"{label} path must be a non-empty string")
    raw = Path(value)
    path = Path(os.path.abspath(raw if raw.is_absolute() else root / raw))
    work = (root / "work").resolve(strict=True)
    if (not _same_or_beneath(path, work)
            or not _same_or_beneath(path.resolve(strict=False), work)):
        raise InstallError(f"{label} must be beneath repo work/")
    _require_real_directory(path.parent, f"{label} parent")
    return _regular(path, label, unique=True)


def _fixed_client_boundaries(root: Path, *, original_override: Path | None):
    root = Path(root).resolve(strict=True)
    client = _require_real_directory(root / "client", "fixed copied client")
    data = _require_real_directory(client / "data", "fixed copied client data")
    if original_override is not None:
        # Check the caller-supplied spelling before resolving it.  Resolving a
        # junction/symlink first would erase the evidence that the override
        # crossed a reparse boundary.
        raw_original = Path(os.path.abspath(original_override))
        _require_real_directory(raw_original, "owned original")
        original = raw_original.resolve(strict=True)
    else:
        original = configured_original(root)
    _require_real_directory(original, "owned original")
    _require_real_directory(original / "data", "owned original data")
    raw_overlap = _same_or_beneath(client, original) or _same_or_beneath(original, client)
    resolved_client, resolved_original = client.resolve(strict=True), original.resolve(strict=True)
    resolved_overlap = (_same_or_beneath(resolved_client, resolved_original)
                        or _same_or_beneath(resolved_original, resolved_client))
    if raw_overlap or resolved_overlap:
        raise InstallError("copied client and owned original must be disjoint")
    return client, data, original


def strict_arena_is_running() -> bool:
    """Fail closed unless a complete Windows task snapshot proves stopped."""
    if os.name != "nt":
        raise InstallError("Arena.exe stopped state is supported only on Windows")
    try:
        completed = subprocess.run(
            ["tasklist.exe", "/FO", "CSV", "/NH"], check=False,
            capture_output=True, text=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallError("Arena.exe process enumeration failed") from exc
    if completed.returncode != 0 or not completed.stdout.strip():
        raise InstallError("Arena.exe process enumeration was incomplete")
    try:
        rows = list(csv.reader(io.StringIO(completed.stdout)))
    except csv.Error as exc:
        raise InstallError("Arena.exe process enumeration was malformed") from exc
    if not rows or any(len(row) < 2 or not row[0].strip()
                       or not row[1].replace(",", "").isdigit() for row in rows):
        raise InstallError("Arena.exe process enumeration was malformed")
    return any(row[0].casefold() == "arena.exe" for row in rows)


def _regular(path: Path, label: str, *, unique: bool = False) -> Path:
    if not os.path.lexists(path):
        raise InstallError(f"{label} is missing")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise InstallError(f"cannot inspect {label}") from exc
    if not path.is_file() or _is_reparse(path):
        raise InstallError(f"{label} must be a regular non-reparse file")
    if unique and metadata.st_nlink != 1:
        raise InstallError(f"{label} must have exactly one hard link")
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise InstallError("cannot hash protected file") from exc
    return digest.hexdigest()


def _hash_required(value: object, label: str) -> str:
    if (type(value) is not str or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)):
        raise InstallError(f"{label} must be a lowercase SHA-256")
    return value


def _parse_json_bytes(raw: bytes, label: str) -> dict[str, object]:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InstallError(f"{label} could not be read") from exc
    except ValueError as exc:
        raise InstallError(f"{label} contains duplicate JSON keys") from exc
    if not isinstance(value, dict):
        raise InstallError(f"{label} must be an object")
    return value


def _read_json(path: Path) -> dict[str, object]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise InstallError("review JSON could not be read") from exc
    return _parse_json_bytes(raw, "review JSON")


def _target(client: Path, data: Path, destination: str) -> Path:
    if destination not in DESTINATIONS and destination != TARGET_WAD:
        raise InstallError("destination is outside the fixed five-file allowlist")
    target = client / destination if destination == "game.dll" else data / destination[5:]
    parent = client if destination == "game.dll" else data
    _require_real_directory(parent, "copied client destination parent")
    if not _same_path(target.parent, parent) or target.name != Path(destination).name:
        raise InstallError("destination escaped its fixed parent")
    return _regular(target, f"destination {destination}")


def _snapshot_original(original: Path) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for relative in ORIGINAL_SNAPSHOT:
        path = original / relative
        if not os.path.lexists(path) and relative in OPTIONAL_ORIGINAL_SNAPSHOT:
            result[relative] = None
            continue
        result[relative] = _sha256(_regular(path, f"owned original {relative}"))
    return result


def _snapshot_selectors(client: Path, data: Path) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for relative, path in (("language.txt", client / "language.txt"),
                           ("data/language.txt", data / "language.txt")):
        if os.path.lexists(path):
            result[relative] = _sha256(_regular(path, f"selector {relative}"))
        else:
            result[relative] = None
    return result


def _validate_report(report: dict[str, object], item: InstallItem) -> None:
    # A wrapper is accepted only when explicitly marked, so a casually nested
    # or stale agent report cannot be mistaken for a receipt.
    if not RECEIPT_FIELDS <= set(report):
        if (set(report) == {"wrapper_receipt", "report"}
                and report.get("wrapper_receipt") is True
                and isinstance(report.get("report"), dict)):
            report = report["report"]
        else:
            raise InstallError(f"receipt report fields are incomplete: {item.destination}")
    if (_hash_required(report.get("input_sha256"), "receipt input")
            != item.expected_existing_sha256
            or _hash_required(report.get("output_sha256"), "receipt output")
            != item.source_sha256
            or report.get("written") is not True
            or report.get("runtime_verified") is not False):
        raise InstallError(f"receipt does not match candidate boundary: {item.destination}")


def _manifest_items(root: Path, client: Path, data: Path,
                    files: object, receipts: object,
                    *, check_existing_hash: bool = True) -> tuple[InstallItem, ...]:
    if not isinstance(files, list) or len(files) != len(DESTINATIONS):
        raise InstallError("manifest must contain exactly five files")
    if not isinstance(receipts, dict) or set(receipts) != set(DESTINATIONS):
        raise InstallError("manifest receipts must cover exactly five destinations")
    items: list[InstallItem] = []
    seen: set[str] = set()
    receipt_paths: list[Path] = []
    for row in files:
        if not isinstance(row, dict) or set(row) != {
            "destination", "source", "sha256", "expected_existing_sha256",
        }:
            raise InstallError("manifest file row has invalid fields")
        destination = row.get("destination")
        if type(destination) is not str or destination not in DESTINATIONS or destination in seen:
            raise InstallError("manifest destination is invalid or duplicated")
        seen.add(destination)
        source = _work_file(root, row.get("source"), f"candidate {destination}")
        source_hash = _hash_required(row.get("sha256"), f"candidate {destination}")
        expected = _hash_required(row.get("expected_existing_sha256"),
                                  f"expected existing {destination}")
        target = _target(client, data, destination)
        if _sha256(source) != source_hash or (
                check_existing_hash and _sha256(target) != expected):
            raise InstallError(f"manifest hash mismatch: {destination}")
        receipt = receipts[destination]
        if not isinstance(receipt, dict) or set(receipt) != {"path", "sha256"}:
            raise InstallError(f"receipt reference is invalid: {destination}")
        receipt_path = _work_file(root, receipt.get("path"),
                                  f"receipt {destination}")
        receipt_hash = _hash_required(receipt.get("sha256"),
                                      f"receipt hash {destination}")
        if _sha256(receipt_path) != receipt_hash:
            raise InstallError(f"receipt hash mismatch: {destination}")
        item = InstallItem(destination, source, source_hash, expected,
                           receipt_path, receipt_hash)
        _validate_report(_read_json(receipt_path), item)
        items.append(item)
        receipt_paths.append(receipt_path)
    if seen != set(DESTINATIONS):
        raise InstallError("manifest does not cover the fixed five destinations")
    paths = [item.source for item in items] + receipt_paths
    targets = [_target(client, data, destination) for destination in DESTINATIONS]
    for index, left in enumerate(paths + targets):
        for right in (paths + targets)[index + 1:]:
            try:
                aliases = left.exists() and right.exists() and os.path.samefile(left, right)
            except OSError as exc:
                raise InstallError("cannot verify source identity") from exc
            if _same_path(left, right) or aliases:
                raise InstallError("source, receipt, and destination aliases are forbidden")
    return tuple(items)


def _verify_installed_manifest(manifest_path: Path,
                               *, repo_root: Path = ROOT) -> dict[str, object]:
    """Verify a reviewed five-file install without changing any filesystem state.

    This is deliberately independent of the installer transaction: launch
    preflight must accept targets already at their candidate hashes, while the
    installer manifest's ``expected_existing_sha256`` describes the pre-image.
    Receipt files are local review evidence only; this function does not turn
    them into production signing or authenticity proof.
    """
    root = Path(repo_root).resolve(strict=True)
    client, data, _original = _fixed_client_boundaries(root, original_override=None)
    manifest = _work_file(root, manifest_path, "native mode manifest")
    payload = _read_json(manifest)
    if (set(payload) != {"version", "files", "receipts"}
            or type(payload.get("version")) is not int
            or payload.get("version") != 1):
        raise InstallError("installed manifest must be version 1 with exactly files and receipts")
    items = _manifest_items(root, client, data, payload["files"], payload["receipts"],
                            check_existing_hash=False)
    artifacts: dict[str, dict[str, str]] = {}
    for item in items:
        if item.expected_existing_sha256 == item.source_sha256:
            raise InstallError(f"installed manifest has indistinguishable pre/post hash: {item.destination}")
        actual = _sha256(_target(client, data, item.destination))
        if actual != item.source_sha256:
            raise InstallError(f"installed target hash does not match reviewed candidate: {item.destination}")
        artifacts[item.destination] = {
            "actual_sha256": actual,
            "expected_installed_sha256": item.source_sha256,
        }
    return {"verified": True, "manifest": str(manifest), "artifacts": artifacts}


def verify_installed_manifest(manifest_path: Path,
                              *, repo_root: Path = ROOT) -> dict[str, object]:
    try:
        return _verify_installed_manifest(manifest_path, repo_root=repo_root)
    except InstallError:
        raise
    except (OriginalSafetyError, OSError, RuntimeError) as exc:
        raise InstallError("installed native mode boundary could not be verified") from exc


def _classify_selector_state(root: Path) -> tuple[str, Path, tuple[InstallItem, ...] | None,
                                                  dict[str, str] | None]:
    manifest = root / DEFAULT_INSTALL_MANIFEST
    if not os.path.lexists(manifest):
        return "legacy", manifest, None, None
    _require_real_directory(manifest.parent, "native mode manifest parent")
    client, data, _original = _fixed_client_boundaries(root, original_override=None)
    manifest = _work_file(root, manifest, "native mode manifest")
    try:
        manifest_bytes = manifest.read_bytes()
    except OSError as exc:
        raise InstallError("native mode manifest could not be read") from exc
    payload = _parse_json_bytes(manifest_bytes, "native mode manifest")
    if (set(payload) != {"version", "files", "receipts"}
            or type(payload.get("version")) is not int
            or payload.get("version") != 1):
        raise InstallError("installed manifest must be version 1 with exactly files and receipts")
    items = _manifest_items(root, client, data, payload["files"], payload["receipts"],
                            check_existing_hash=False)
    if any(item.expected_existing_sha256 == item.source_sha256 for item in items):
        raise InstallError("installed manifest has indistinguishable pre/post hash")
    actual = {item.destination: _sha256(_target(client, data, item.destination))
              for item in items}
    before = {item.destination: item.expected_existing_sha256 for item in items}
    after = {item.destination: item.source_sha256 for item in items}
    if all(actual[destination] == before[destination] for destination in DESTINATIONS):
        return "legacy", manifest, items, actual
    if all(actual[destination] == after[destination] for destination in DESTINATIONS):
        return "verified", manifest, items, actual
    raise InstallError("native five-mode artifacts are partially installed or unknown")


def classify_selector_installation(*, repo_root: Path = ROOT) -> str:
    """Classify the fixed selector manifest without considering ON/OFF policy."""
    root = Path(repo_root).resolve(strict=True)
    try:
        status, _manifest, _items, _actual = _classify_selector_state(root)
        return status
    except InstallError:
        raise
    except (OriginalSafetyError, OSError, RuntimeError) as exc:
        raise InstallError("native mode selector boundary could not be verified") from exc


def _check_selector_installation(enabled: bool, *, repo_root: Path = ROOT) -> dict[str, object]:
    """Return the safe selector state for the optional native five-mode UI.

    The selector never auto-enables.  A missing default manifest is the only
    normal legacy/off case.  If a manifest exists, it must prove either a
    complete pre-image (legacy) or a complete candidate install (ON); mixed or
    unknown target states are refused.
    """
    root = Path(repo_root).resolve(strict=True)
    status, manifest, items, actual = _classify_selector_state(root)
    if status == "legacy":
        if enabled:
            raise InstallError("native five-mode selector is enabled but artifacts are not installed")
        return {"enabled": False, "status": "legacy", "manifest": str(manifest)}
    if not enabled:
        raise InstallError("native five-mode artifacts are installed while selector is OFF")
    assert items is not None and actual is not None
    verification = {
        "verified": True,
        "manifest": str(manifest),
        "artifacts": {
            item.destination: {
                "actual_sha256": actual[item.destination],
                "expected_installed_sha256": item.source_sha256,
            }
            for item in items
        },
    }
    return {"enabled": True, "status": "verified", "manifest": str(manifest),
            "verification": verification}


def check_selector_installation(enabled: bool, *, repo_root: Path = ROOT) -> dict[str, object]:
    try:
        return _check_selector_installation(enabled, repo_root=repo_root)
    except InstallError:
        raise
    except (OriginalSafetyError, OSError, RuntimeError) as exc:
        raise InstallError("native mode selector boundary could not be verified") from exc


def load_plan(manifest_path: Path, *, repo_root: Path = ROOT,
              original_override: Path | None = None,
              profile_override: Path | None = None) -> InstallPlan:
    root = Path(repo_root).resolve(strict=True)
    client, data, original = _fixed_client_boundaries(
        root, original_override=original_override,
    )
    manifest = _work_file(root, manifest_path, "native mode manifest")
    manifest_bytes = manifest.read_bytes()
    payload = _parse_json_bytes(manifest_bytes, "manifest")
    if (set(payload) != {"version", "files", "receipts"}
            or type(payload.get("version")) is not int
            or payload.get("version") != 1):
        raise InstallError("manifest must be version 1 with exactly files and receipts")
    items = _manifest_items(root, client, data, payload["files"], payload["receipts"])
    profile = (_work_file(root, profile_override, "profile snapshot")
               if profile_override is not None else _work_file(root, PROFILE_RELATIVE,
                                                               "profile snapshot"))
    return InstallPlan(
        root, client, data, original, profile, manifest, manifest_bytes, items,
        _snapshot_original(original), _snapshot_selectors(client, data),
        _sha256(_target(client, data, TARGET_WAD)), _sha256(profile),
    )


def _verify_unchanged(plan: InstallPlan) -> None:
    if _snapshot_original(plan.original) != plan.original_before:
        raise InstallError("owned original snapshot changed")
    if _snapshot_selectors(plan.client, plan.data) != plan.selectors_before:
        raise InstallError("client selectors changed")
    if _sha256(_target(plan.client, plan.data, TARGET_WAD)) != plan.target_wad_before:
        raise InstallError("target WAD changed")
    if _sha256(plan.profile_snapshot) != plan.profile_before:
        raise InstallError("profile snapshot changed")


def _verify_plan_inputs(plan: InstallPlan) -> None:
    """Re-read review inputs immediately before any target replacement."""
    try:
        manifest = _work_file(plan.repo_root, plan.manifest_path,
                              "native mode manifest")
        if not _same_path(manifest, plan.manifest_path) \
                or manifest.read_bytes() != plan.manifest_bytes:
            raise InstallError("native mode manifest changed after preflight")
    except OSError as exc:
        raise InstallError("native mode manifest became unreadable") from exc
    payload = _parse_json_bytes(plan.manifest_bytes, "manifest")
    if (set(payload) != {"version", "files", "receipts"}
            or type(payload.get("version")) is not int
            or payload.get("version") != 1):
        raise InstallError("native mode manifest became invalid")
    refreshed = _manifest_items(plan.repo_root, plan.client, plan.data,
                                payload["files"], payload["receipts"],
                                check_existing_hash=False)
    if len(refreshed) != len(plan.items):
        raise InstallError("native mode manifest file set changed")
    for old, current in zip(plan.items, refreshed):
        if (old.destination != current.destination
                or not _same_path(old.source, current.source)
                or old.source_sha256 != current.source_sha256
                or old.expected_existing_sha256 != current.expected_existing_sha256
                or not _same_path(old.receipt_path, current.receipt_path)
                or old.receipt_sha256 != current.receipt_sha256):
            raise InstallError(f"native mode review inputs changed: {old.destination}")


def _revalidate(plan: InstallPlan) -> None:
    client, data, original = _fixed_client_boundaries(
        plan.repo_root, original_override=plan.original,
    )
    if not (_same_path(client, plan.client) and _same_path(data, plan.data)
            and _same_path(original, plan.original)):
        raise InstallError("client/original boundary changed")
    _verify_plan_inputs(plan)
    _verify_unchanged(plan)


def _recheck_target(plan: InstallPlan, item: InstallItem) -> Path:
    target = _target(plan.client, plan.data, item.destination)
    if _sha256(target) != item.expected_existing_sha256:
        raise InstallError(f"target changed after preflight: {item.destination}")
    return target


def _stage(source: Path, target: Path, expected: str) -> Path:
    descriptor, raw = tempfile.mkstemp(prefix=f".{target.name}.native-mode-",
                                        suffix=".tmp", dir=target.parent)
    temporary = Path(raw)
    try:
        with source.open("rb") as source_handle, os.fdopen(descriptor, "wb") as output:
            shutil.copyfileobj(source_handle, output, 1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        metadata = temporary.lstat()
        if metadata.st_nlink != 1 or _is_reparse(temporary) or _sha256(temporary) != expected:
            raise InstallError("staged candidate failed independent-file/hash verification")
        return temporary
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _backup(plan: InstallPlan) -> tuple[Path, dict[str, Path]]:
    root = plan.repo_root / "work/native-battle-mode-backups"
    if not root.exists():
        root.mkdir()
    _require_real_directory(root, "native mode backup root")
    backup = root / f"backup-{uuid.uuid4().hex}"
    backup.mkdir()
    _require_real_directory(backup, "native mode backup")
    atomic_write_output(plan.repo_root, backup / "install-manifest.json",
                        plan.manifest_bytes, original=plan.original)
    old: dict[str, Path] = {}
    rows: list[dict[str, object]] = []
    for item in plan.items:
        target = _recheck_target(plan, item)
        name = "old." + item.destination.replace("/", "_")
        old_path = backup / name
        atomic_write_output(plan.repo_root, old_path, target.read_bytes(), original=plan.original)
        if _sha256(old_path) != item.expected_existing_sha256:
            raise InstallError(f"backup hash mismatch: {item.destination}")
        old[item.destination] = old_path
        rows.append({"destination": item.destination, "expected_existing_sha256": item.expected_existing_sha256,
                     "installed_sha256": item.source_sha256, "backup": name})
    state = {
        "version": 1,
        "manifest_sha256": hashlib.sha256(plan.manifest_bytes).hexdigest(),
        "files": rows,
        "original_before": plan.original_before,
        "selectors_before": plan.selectors_before,
        "target_wad_before": plan.target_wad_before,
        "profile_before": plan.profile_before,
    }
    atomic_write_output(plan.repo_root, backup / "backup-state.json",
                        (json.dumps(state, sort_keys=True, indent=2) + "\n").encode(),
                        original=plan.original)
    return backup, old


def _restore(plan: InstallPlan, old: dict[str, Path], attempted: list[InstallItem],
             replace_func: Callable[[object, object], None]) -> None:
    unknown: list[str] = []
    for item in reversed(attempted):
        target = _target(plan.client, plan.data, item.destination)
        current = _sha256(target)
        if current == item.expected_existing_sha256:
            continue
        if current != item.source_sha256:
            unknown.append(item.destination)
            continue
        staged = _stage(old[item.destination], target, item.expected_existing_sha256)
        try:
            if _sha256(target) != item.source_sha256:
                unknown.append(item.destination)
                continue
            replace_func(staged, target)
        finally:
            staged.unlink(missing_ok=True)
    if unknown:
        raise InstallError("externally changed targets were left untouched")


def _apply(plan: InstallPlan, replace_func: Callable[[object, object], None]) -> dict[str, object]:
    staged: dict[str, Path] = {}
    attempted: list[InstallItem] = []
    backup: Path | None = None
    old: dict[str, Path] = {}
    try:
        _revalidate(plan)
        # All five candidates are independent, flushed, and hash-verified
        # before the first target namespace replacement.
        for item in plan.items:
            target = _target(plan.client, plan.data, item.destination)
            if _sha256(item.source) != item.source_sha256:
                raise InstallError(f"candidate changed after preflight: {item.destination}")
            staged[item.destination] = _stage(item.source, target, item.source_sha256)
        backup, old = _backup(plan)
        for item in plan.items:
            _revalidate(plan)
            target = _recheck_target(plan, item)
            _regular(staged[item.destination],
                     f"staged candidate {item.destination}", unique=True)
            if _sha256(staged[item.destination]) != item.source_sha256:
                raise InstallError(f"staged candidate changed before replacement: {item.destination}")
            attempted.append(item)
            replace_func(staged[item.destination], target)
            installed = _target(plan.client, plan.data, item.destination)
            if installed.lstat().st_nlink != 1 or _sha256(installed) != item.source_sha256:
                raise InstallError(f"installed candidate failed verification: {item.destination}")
        _verify_unchanged(plan)
        return {
            "mode": "apply", "written": True, "runtime_verified": False,
            "backup": str(backup),
            "receipts": {item.destination: {"path": str(item.receipt_path),
                                             "sha256": item.receipt_sha256}
                         for item in plan.items},
        }
    except Exception as exc:
        if attempted and backup is not None:
            try:
                _restore(plan, old, attempted, replace_func)
                _verify_unchanged(plan)
            except Exception as rollback_error:
                raise InstallError("native mode rollback requires manual recovery") from rollback_error
        raise InstallError("native mode transaction failed and was rolled back") from exc
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)


def install_manifest(manifest_path: Path, *, apply: bool = False,
                     repo_root: Path = ROOT, original_override: Path | None = None,
                     profile_override: Path | None = None,
                     process_check: Callable[[], bool] = strict_arena_is_running,
                     replace_func: Callable[[object, object], None] = os.replace) -> dict[str, object]:
    root = Path(repo_root).resolve(strict=True)
    try:
        with client_operation_lock(root / "client"):
            plan = load_plan(manifest_path, repo_root=root,
                             original_override=original_override,
                             profile_override=profile_override)
            if not apply:
                _verify_unchanged(plan)
                return {"mode": "dry-run", "written": False,
                        "runtime_verified": False,
                        "validated_targets": list(DESTINATIONS),
                        "receipts": {item.destination: {"path": str(item.receipt_path),
                                                         "sha256": item.receipt_sha256}
                                     for item in plan.items}}
            if process_check():
                raise InstallError("Arena.exe is running")
            return _apply(plan, replace_func)
    except (ClientOperationLockError, OriginalSafetyError, OSError) as exc:
        raise InstallError("native mode installer boundary failed") from exc


def rollback_backup(backup_path: Path, *, repo_root: Path = ROOT,
                    original_override: Path | None = None,
                    profile_override: Path | None = None,
                    process_check: Callable[[], bool] = strict_arena_is_running,
                    replace_func: Callable[[object, object], None] = os.replace) -> dict[str, object]:
    """Restore only leaves still owned by this install transaction.

    A target is restored only while its current hash is the candidate hash
    recorded by the backup.  An externally changed target is reported and
    left untouched.  This operation never reads a secret or writes the owned
    original.
    """
    root = Path(repo_root).resolve(strict=True)
    backup = Path(os.path.abspath(backup_path if Path(backup_path).is_absolute()
                                  else root / backup_path))
    backup_root = (root / "work/native-battle-mode-backups").resolve(strict=True)
    if (not _same_or_beneath(backup, backup_root)
            or not _same_or_beneath(backup.resolve(strict=False), backup_root)):
        raise InstallError("rollback backup is outside the fixed work boundary")
    _require_real_directory(backup, "rollback backup")
    state = _read_json(_regular(backup / "backup-state.json", "rollback state"))
    state_fields = {"version", "manifest_sha256", "files", "original_before",
                    "selectors_before", "target_wad_before", "profile_before"}
    if (set(state) != state_fields or type(state.get("version")) is not int
            or state.get("version") != 1):
        raise InstallError("rollback state is invalid")
    manifest = _regular(backup / "install-manifest.json", "rollback manifest")
    manifest_hash = _hash_required(state.get("manifest_sha256"),
                                   "rollback manifest hash")
    try:
        manifest_bytes = manifest.read_bytes()
    except OSError as exc:
        raise InstallError("rollback manifest could not be read") from exc
    if hashlib.sha256(manifest_bytes).hexdigest() != manifest_hash:
        raise InstallError("rollback manifest hash mismatch")
    client, data, original = _fixed_client_boundaries(
        root, original_override=original_override,
    )
    # Validate the saved manifest/receipt chain before examining or changing
    # any target.  State rows below are then bound to this exact manifest.
    payload = _parse_json_bytes(manifest_bytes, "rollback manifest")
    if (set(payload) != {"version", "files", "receipts"}
            or type(payload.get("version")) is not int
            or payload.get("version") != 1):
        raise InstallError("rollback manifest is invalid")
    manifest_items = _manifest_items(root, client, data, payload["files"],
                                     payload["receipts"], check_existing_hash=False)
    manifest_by_destination = {
        item.destination: (item.expected_existing_sha256, item.source_sha256)
        for item in manifest_items
    }
    if set(manifest_by_destination) != set(DESTINATIONS):
        raise InstallError("rollback manifest does not cover the fixed five destinations")

    profile = (_work_file(root, profile_override, "profile snapshot")
               if profile_override is not None else _work_file(root, PROFILE_RELATIVE,
                                                               "profile snapshot"))
    original_before = state["original_before"]
    selectors_before = state["selectors_before"]
    if (not isinstance(original_before, dict) or set(original_before) != set(ORIGINAL_SNAPSHOT)
            or not isinstance(selectors_before, dict) or set(selectors_before) != set(SELECTOR_PATHS)):
        raise InstallError("rollback snapshots are invalid")
    normalized_original: dict[str, str | None] = {}
    for key, value in original_before.items():
        if value is None and key in OPTIONAL_ORIGINAL_SNAPSHOT:
            normalized_original[key] = None
        else:
            normalized_original[key] = _hash_required(value, "rollback original hash")
    normalized_selectors = {
        key: (None if value is None else _hash_required(value, "rollback selector hash"))
        for key, value in selectors_before.items()
    }
    target_wad_before = _hash_required(state.get("target_wad_before"), "rollback WAD hash")
    # The profile hash is retained as historical backup metadata, but the
    # user's current profile is never required to equal the pre-install copy.
    _hash_required(state.get("profile_before"), "rollback profile hash")
    if (_snapshot_original(original) != normalized_original
            or _sha256(_target(client, data, TARGET_WAD)) != target_wad_before):
        raise InstallError("owned original or target WAD snapshot changed")
    selectors_at_start = _snapshot_selectors(client, data)
    profile_at_start = _sha256(profile)

    rows = state.get("files")
    if not isinstance(rows, list) or len(rows) != len(DESTINATIONS):
        raise InstallError("rollback file state is invalid")
    prepared: list[tuple[str, str, str, Path, Path, str]] = []
    seen_destinations: set[str] = set()
    seen_backup_names: set[str] = set()
    for row in rows:
        if (not isinstance(row, dict)
                or set(row) != {"destination", "expected_existing_sha256",
                                 "installed_sha256", "backup"}):
            raise InstallError("rollback file row is invalid")
        destination = row.get("destination")
        if (destination not in DESTINATIONS or destination in seen_destinations
                or type(row.get("backup")) is not str or not row["backup"]):
            raise InstallError("rollback destination is invalid")
        seen_destinations.add(destination)
        expected = _hash_required(row.get("expected_existing_sha256"),
                                  "rollback old hash")
        installed = _hash_required(row.get("installed_sha256"),
                                   "rollback installed hash")
        if manifest_by_destination.get(destination) != (expected, installed):
            raise InstallError("rollback state is not bound to its saved manifest")
        backup_name = row["backup"]
        if backup_name in seen_backup_names or ntpath.basename(backup_name) != backup_name:
            raise InstallError("rollback backup leaf is invalid")
        seen_backup_names.add(backup_name)
        backup_leaf = backup / backup_name
        if not _same_path(backup_leaf.parent, backup):
            raise InstallError("rollback backup leaf escaped backup directory")
        _regular(backup_leaf, "rollback backup leaf", unique=True)
        if _sha256(backup_leaf) != expected:
            raise InstallError("rollback backup leaf hash mismatch")
        target = _target(client, data, destination)
        current = _sha256(target)
        prepared.append((destination, expected, installed, backup_leaf, target, current))
    if seen_destinations != set(DESTINATIONS):
        raise InstallError("rollback state does not cover the fixed five destinations")
    if process_check():
        raise InstallError("Arena.exe is running")

    restored: list[str] = []
    external: list[str] = []
    try:
        with client_operation_lock(client):
            staged: dict[str, Path] = {}
            try:
                # Pre-stage every owned old image before the first replacement.
                for destination, expected, installed, backup_leaf, target, _current in prepared:
                    if _sha256(_target(client, data, destination)) == installed:
                        staged[destination] = _stage(backup_leaf, target, expected)
                if (_snapshot_original(original) != normalized_original
                        or _sha256(_target(client, data, TARGET_WAD)) != target_wad_before
                        or _snapshot_selectors(client, data) != selectors_at_start
                        or _sha256(profile) != profile_at_start):
                    raise InstallError("rollback protected snapshot changed before replacement")
                for destination, expected, installed, backup_leaf, target, _current in prepared:
                    current = _sha256(_target(client, data, destination))
                    if current == expected:
                        continue
                    if current != installed:
                        external.append(destination)
                        continue
                    staged_path = staged[destination]
                    _regular(staged_path, f"staged rollback {destination}", unique=True)
                    if _sha256(staged_path) != expected:
                        raise InstallError("staged rollback candidate changed")
                    replace_func(staged_path, target)
                    if _sha256(_target(client, data, destination)) != expected:
                        raise InstallError("rollback target verification failed")
                    restored.append(destination)
            finally:
                for staged_path in staged.values():
                    staged_path.unlink(missing_ok=True)
            if (_snapshot_original(original) != normalized_original
                    or _sha256(_target(client, data, TARGET_WAD)) != target_wad_before
                    or _snapshot_selectors(client, data) != selectors_at_start
                    or _sha256(profile) != profile_at_start):
                raise InstallError("rollback protected snapshot changed")
    except (ClientOperationLockError, OriginalSafetyError, OSError) as exc:
        raise InstallError("native mode rollback boundary failed") from exc
    return {"mode": "rollback", "restored": restored,
            "externally_changed_targets": external,
            "runtime_verified": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--manifest", type=Path)
    operation.add_argument("--rollback", type=Path)
    operation.add_argument("--check-selector-installation", choices=("on", "off"))
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        if args.rollback is not None:
            if args.apply:
                parser.error("--apply cannot be combined with --rollback")
            report = rollback_backup(args.rollback)
        elif args.check_selector_installation is not None:
            if args.apply:
                parser.error("--apply cannot be combined with --check-selector-installation")
            report = check_selector_installation(
                args.check_selector_installation == "on",
            )
        else:
            report = install_manifest(args.manifest, apply=args.apply)
    except InstallError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
