"""Create a self-contained Revival client without modifying the original.

The owned TotalWar_Arena install is a read-only source. A fresh stage owns
real ``client/data`` and ``client/cef`` directories; the only filesystem
reference back to the original is ``client/data.original-junction`` and that
reference is for read-only extraction/validation tools.

Staging is deliberately fail-closed. A non-empty destination is never
merged, deleted, or overwritten. The complete client is assembled beside
the destination and renamed into place only after every copy succeeds.
"""
from __future__ import annotations

import json
import ntpath
import os
import shutil
import stat
import subprocess
import sys
import uuid
import argparse
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from companion.client_lock import ClientOperationLockError, client_operation_lock
try:
    from tools.client_language import (
        ClientLanguageError, atomic_write_language_files, stage_language,
    )
except ImportError:  # Direct execution from the tools directory.
    from client_language import (
        ClientLanguageError, atomic_write_language_files, stage_language,
    )

# Keep the owned original client beside the Revival checkout. This avoids a
# machine-specific C:\Users\... path and works for the current D:\TWA layout.
ORIGINAL = ROOT.parent / "totalwar-Arena" / "TotalWar_Arena"
CLIENT = ROOT / "client"

COPY_NAMES = [
    "Arena.exe",
    "cef_process.exe",
    "ChromiumCapsule.Release.exe",
    "game.dll",
    "CALibsWinExt.zIntelUnityRelease.dll",
    "chrome_elf.dll",
    "ChromiumWebCore.Release.dll",
    "icudtl.dat",
    "libcef.dll",
    "msvcp140.dll",
    "msvcp140_1.dll",
    "msvcp140_2.dll",
    "msvcr120.dll",
    "natives_blob.bin",
    "NGL-49.ins",
    "npl-base.dll",
    "npl-common.dll",
    "npl-net.dll",
    "npl-sdk.dll",
    "online_platform.Release.dll",
    "online_platform_netease.Release.dll",
    "sensitiveWord.txt",
    "snapshot_blob.bin",
    "tbb.dll",
    "tbbmalloc.dll",
    "ucrtbase.dll",
    "v8_context_snapshot.bin",
    "vccorlib140.dll",
    "vcruntime140.dll",
]

OWNED_COPY_DIRS = ("data", "cef")
ORIGINAL_DATA_REFERENCE = "data.original-junction"


class StageError(RuntimeError):
    """The source/destination boundary is unsafe; staging must not start."""


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _is_reparse_point(path: Path) -> bool:
    """Return True for Windows junctions/symlinks without following them."""
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return path.is_symlink() or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _same_path(left: Path, right: Path) -> bool:
    try:
        return os.path.normcase(str(left.resolve(strict=True))) == os.path.normcase(
            str(right.resolve(strict=True))
        )
    except OSError:
        return False


def _is_same_or_beneath(candidate: Path, root: Path) -> bool:
    """Compare absolute paths with Windows' case-insensitive semantics."""
    candidate_text = ntpath.normcase(ntpath.abspath(os.fspath(candidate)))
    root_text = ntpath.normcase(ntpath.abspath(os.fspath(root)))
    try:
        return ntpath.commonpath((candidate_text, root_text)) == root_text
    except ValueError:
        # Paths on different drives cannot overlap.
        return False


def _require_disjoint_trees(original: Path, client: Path) -> Path:
    """Resolve both boundaries and reject overlap in either direction.

    Both the spelling supplied by the caller and the resolved filesystem
    locations are checked. The former catches case-only/lexical nesting and
    the latter catches an existing parent junction or symlink. Resolution is
    read-only and happens before staging creates any directory.
    """
    try:
        raw_original = Path(os.path.abspath(original))
        raw_client = Path(os.path.abspath(client))
        resolved_original = raw_original.resolve(strict=True)
        resolved_client = raw_client.resolve(strict=False)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise StageError(f"cannot resolve source/destination boundary safely: {exc}") from exc

    for source, destination in (
        (raw_original, raw_client),
        (resolved_original, resolved_client),
    ):
        if _is_same_or_beneath(destination, source) or _is_same_or_beneath(
            source, destination
        ):
            raise StageError(
                "original and Revival client trees must be disjoint: "
                f"original={raw_original}, client={raw_client}"
            )
    return resolved_original


def _require_real_source_tree(path: Path) -> int:
    """Validate a source tree and return its byte size without following links."""
    if not path.is_dir() or _is_reparse_point(path):
        raise StageError(f"original source must be a real directory: {path}")
    total = 0
    pending = [path]
    while pending:
        directory = pending.pop()
        try:
            children = list(directory.iterdir())
        except OSError as exc:
            raise StageError(f"cannot read original source directory: {directory}: {exc}") from exc
        for child in children:
            if _is_reparse_point(child):
                raise StageError(f"original source contains a reparse point: {child}")
            if child.is_dir():
                pending.append(child)
            elif child.is_file():
                total += child.stat().st_size
            else:
                raise StageError(f"unsupported original source entry: {child}")
    return total


def _require_empty_destination(client: Path) -> None:
    if not _lexists(client):
        return
    if _is_reparse_point(client) or not client.is_dir():
        raise StageError(f"client destination must be a real directory: {client}")
    try:
        first = next(client.iterdir(), None)
    except OSError as exc:
        raise StageError(f"cannot inspect client destination: {client}: {exc}") from exc
    if first is not None:
        raise StageError(
            f"refusing to merge into non-empty Revival client: {client}; "
            "the existing copy was left untouched"
        )


def _nearest_existing_directory(path: Path) -> Path:
    current = path
    while not current.exists():
        parent = current.parent
        if parent == current:
            raise StageError(f"no existing parent for client destination: {path}")
        current = parent
    if not current.is_dir():
        current = current.parent
    return current


def _required_bytes(original: Path) -> int:
    total = sum(_require_real_source_tree(original / name) for name in OWNED_COPY_DIRS)
    for name in COPY_NAMES:
        source = original / name
        if source.is_file() and not _is_reparse_point(source):
            total += source.stat().st_size
            if name in ("npl-base.dll", "npl-sdk.dll"):
                total += source.stat().st_size
        elif _lexists(source) and _is_reparse_point(source):
            raise StageError(f"original source file is a reparse point: {source}")
        else:
            raise StageError(f"required original file is missing: {name}")
    for source in original.glob("api-ms-win-*.dll"):
        if _is_reparse_point(source) or not source.is_file():
            raise StageError(f"original API DLL is not a real file: {source}")
        total += source.stat().st_size
    return total


def _check_free_space(client: Path, required: int) -> None:
    anchor = _nearest_existing_directory(client.parent)
    if _is_reparse_point(anchor):
        raise StageError(f"client destination parent is a reparse point: {anchor}")
    free = shutil.disk_usage(anchor).free
    if free < required:
        raise StageError(
            f"insufficient free space for Revival client: need {required} bytes, "
            f"have {free} bytes on {anchor}"
        )


def create_original_data_junction(link: Path, target: Path) -> None:
    """Create, but never replace, the observation-only original-data junction."""
    if _lexists(link):
        raise StageError(f"refusing to replace existing original-data reference: {link}")
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        check=True,
        capture_output=True,
        text=True,
    )
    if not _is_reparse_point(link) or not _same_path(link, target):
        raise StageError(f"created original-data reference does not target {target}: {link}")


def _remove_staging_tree(path: Path) -> None:
    """Remove only our private staging tree, detaching its junction first."""
    reference = path / ORIGINAL_DATA_REFERENCE
    if _lexists(reference) and _is_reparse_point(reference):
        try:
            os.rmdir(reference)
        except OSError:
            # Never let rmtree traverse an unresolved reference.
            return
    if path.exists() and not _is_reparse_point(path):
        shutil.rmtree(path)


def _stage_client_unlocked(
    original: Path,
    client: Path,
    *,
    reference_creator: Callable[[Path, Path], None] = create_original_data_junction,
    language: str | None = None,
) -> None:
    """Build a fresh Revival-owned client and atomically publish it."""
    # Do not resolve the destination: resolving first would follow a hostile
    # client symlink/junction and hide precisely the entry we must reject.
    client = Path(os.path.abspath(client))
    original = _require_disjoint_trees(original, client)
    selected_language = stage_language(original, language)
    if not (original / "Arena.exe").is_file():
        raise StageError(f"missing original client: {original}")

    # All validation, including capacity, happens before the first write.
    _require_empty_destination(client)
    required = _required_bytes(original)
    _check_free_space(client, required)

    client.parent.mkdir(parents=True, exist_ok=True)
    staging = client.parent / f".{client.name}.stage-{uuid.uuid4().hex}"
    empty_backup = client.parent / f".{client.name}.empty-{uuid.uuid4().hex}"
    try:
        staging.mkdir()
        for name in COPY_NAMES:
            source = original / name
            shutil.copy2(source, staging / name)
            if name in ("npl-base.dll", "npl-sdk.dll"):
                shutil.copy2(source, staging / name.replace(".dll", ".original.dll"))
            print(f"copy {name}")
        for source in original.glob("api-ms-win-*.dll"):
            shutil.copy2(source, staging / source.name)
        for name in OWNED_COPY_DIRS:
            shutil.copytree(original / name, staging / name, copy_function=shutil.copy2)
            print(f"copy directory {name}")

        stack = {"config_domain": "127.0.0.1:18765"}
        (staging / "stack_config.json").write_text(
            json.dumps(stack, indent=2), encoding="utf-8"
        )
        (staging / "npl.conf").write_text(
            json.dumps({"AppId": 49001, "appId": 49001, "launcherId": 1}, indent=2),
            encoding="utf-8",
        )
        atomic_write_language_files(
            staging, selected_language, repo_root=client.parent, original=original,
        )
        (staging / "ORIGINAL_PATH.txt").write_text(str(original), encoding="utf-8")

        reference_creator(staging / ORIGINAL_DATA_REFERENCE, original / "data")

        if client.exists():
            # Preflight proved this is an empty real directory. Preserve it
            # until the completed staging tree is in place, so rename failure
            # can restore the exact pre-stage state.
            os.replace(client, empty_backup)
        try:
            os.replace(staging, client)
        except Exception:
            if empty_backup.exists() and not client.exists():
                os.replace(empty_backup, client)
            raise
        if empty_backup.exists():
            try:
                empty_backup.rmdir()
            except OSError:
                # Publication already succeeded; an empty private marker is
                # harmless and must not turn success into a reported failure.
                pass
    finally:
        if staging.exists():
            _remove_staging_tree(staging)
        if empty_backup.exists() and not client.exists():
            os.replace(empty_backup, client)


def stage_client(
    original: Path,
    client: Path,
    *,
    reference_creator: Callable[[Path, Path], None] = create_original_data_junction,
    language: str | None = None,
) -> None:
    """Build a fresh Revival-owned client under the shared operation lock."""
    client_path = Path(os.path.abspath(client))
    with client_operation_lock(client_path):
        _stage_client_unlocked(
            original, client_path, reference_creator=reference_creator,
            language=language,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", type=Path, default=ORIGINAL)
    parser.add_argument(
        "--language", default=None, choices=("EN", "JA", "RU", "en", "ja", "ru"),
        help="language selector; omitted preserves the owned source selector",
    )
    args = parser.parse_args()
    try:
        stage_client(args.original, CLIENT, language=args.language)
    except (
        OSError, StageError, subprocess.SubprocessError,
        ClientLanguageError, ClientOperationLockError,
    ) as exc:
        print(f"stage failed: {exc}", file=sys.stderr)
        return 1
    print(f"staged {CLIENT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
