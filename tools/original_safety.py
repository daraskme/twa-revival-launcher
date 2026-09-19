"""Fail-closed output guard for tools that read the owned TWA install.

Generation tools may read the configured original, but every output belongs to
the Revival repository or its work tree. This module rejects lexical and
resolved aliases into the original before creating a directory or file, then
publishes through a new same-directory file so an existing hard link is never
opened for writing.
"""
from __future__ import annotations

import ntpath
import os
import stat
import tempfile
from pathlib import Path

try:
    from .original_paths import read_original_path
except ImportError:
    from original_paths import read_original_path


class OriginalSafetyError(RuntimeError):
    """The configured original or requested output boundary is unsafe."""


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _is_reparse_point(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise OriginalSafetyError(f"cannot inspect path {path}: {exc}") from exc
    return path.is_symlink() or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _same_or_beneath(candidate: Path, root: Path) -> bool:
    candidate_text = ntpath.normcase(ntpath.abspath(os.fspath(candidate)))
    root_text = ntpath.normcase(ntpath.abspath(os.fspath(root)))
    try:
        return ntpath.commonpath((candidate_text, root_text)) == root_text
    except ValueError:
        return False


def _require_real_existing_ancestors(path: Path, label: str) -> None:
    current = path
    while not _lexists(current):
        if current.parent == current:
            raise OriginalSafetyError(f"{label} has no existing parent: {path}")
        current = current.parent
    while True:
        if not current.is_dir() or _is_reparse_point(current):
            raise OriginalSafetyError(
                f"{label} must contain only real directory ancestors: {current}"
            )
        if current.parent == current:
            return
        current = current.parent


def configured_original(repo_root: Path) -> Path:
    """Load one absolute, existing, non-reparse original from paths.ini."""
    paths_ini = Path(repo_root) / "config" / "paths.ini"
    try:
        original = read_original_path(paths_ini)
    except (OSError, UnicodeError, ValueError) as exc:
        raise OriginalSafetyError(
            f"cannot verify owned original because {paths_ini} is unreadable: {exc}"
        ) from exc
    if not original.is_absolute():
        raise OriginalSafetyError("configured original directory must be absolute")
    raw = Path(os.path.abspath(original))
    _require_real_existing_ancestors(raw, "configured original directory")
    try:
        return raw.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise OriginalSafetyError(
            f"cannot resolve configured original directory {raw}: {exc}"
        ) from exc


def require_safe_output(
    repo_root: Path,
    output: Path,
    *,
    original: Path | None = None,
) -> Path:
    """Return an absolute output that cannot name or alias the original tree."""
    raw_original = Path(os.path.abspath(
        original if original is not None else configured_original(repo_root)
    ))
    _require_real_existing_ancestors(raw_original, "configured original directory")
    try:
        resolved_original = raw_original.resolve(strict=True)
        raw_output = Path(os.path.abspath(output))
        resolved_output = raw_output.resolve(strict=False)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise OriginalSafetyError(f"cannot resolve output boundary safely: {exc}") from exc
    if (_same_or_beneath(raw_output, raw_original)
            or _same_or_beneath(resolved_output, resolved_original)):
        raise OriginalSafetyError(
            f"refusing to write into the owned original tree: {raw_output}"
        )
    _require_real_existing_ancestors(raw_output.parent, "output directory")
    if _lexists(raw_output):
        if not raw_output.is_file() or _is_reparse_point(raw_output):
            raise OriginalSafetyError(
                f"output must be a regular file or a new leaf: {raw_output}"
            )
        try:
            links = raw_output.lstat().st_nlink
        except OSError as exc:
            raise OriginalSafetyError(f"cannot inspect output {raw_output}: {exc}") from exc
        if links != 1:
            raise OriginalSafetyError(
                f"output must not be a hard link shared with another path: {raw_output}"
            )
    return raw_output


def atomic_write_output(
    repo_root: Path,
    output: Path,
    data: bytes,
    *,
    original: Path | None = None,
) -> Path:
    """Write a validated output through a unique, flushed replacement file."""
    target = require_safe_output(repo_root, output, original=original)
    target.parent.mkdir(parents=True, exist_ok=True)
    target = require_safe_output(repo_root, target, original=original)
    descriptor, raw_temporary = tempfile.mkstemp(
        prefix=f".{target.name}.build-", suffix=".tmp", dir=target.parent,
    )
    temporary = Path(raw_temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        target = require_safe_output(repo_root, target, original=original)
        os.replace(temporary, target)
        return target
    finally:
        temporary.unlink(missing_ok=True)
