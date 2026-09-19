"""Safe language-selector handling for the Revival-owned client copy.

The native client reads selectors from loose files and mounted archives.
This module keeps the two loose selectors and a text-only archive overlay in
sync, requires an existing language pack, and never writes through the
configured read-only original install. Russian requires a real ``local_ru.pack``;
an English copy is not relabelled as Russian.
"""
from __future__ import annotations

import os
import stat
import struct
import tempfile
from contextlib import suppress
from pathlib import Path

from companion.client_lock import client_operation_lock

try:
    from tools.original_safety import OriginalSafetyError, require_safe_output
except ImportError:  # Direct execution from the tools directory.
    from original_safety import OriginalSafetyError, require_safe_output


SUPPORTED_LANGUAGES = ("EN", "JA", "RU")
_ALIASES = {language.lower(): language for language in SUPPORTED_LANGUAGES}
_LANGUAGE_FILES = ("language.txt", os.path.join("data", "language.txt"))
_LANGUAGE_OVERLAY = os.path.join("data", "zz_twa_active_locale.pack")


class ClientLanguageError(RuntimeError):
    """A language selection cannot be applied safely."""


def normalize_language(value: str) -> str:
    """Return the canonical two-letter selector, accepting lower-case aliases."""
    if not isinstance(value, str):
        raise ClientLanguageError("language must be EN, JA, or RU")
    canonical = _ALIASES.get(value.strip().lower())
    if canonical is None:
        raise ClientLanguageError("language must be EN, JA, or RU")
    return canonical


def _is_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ClientLanguageError(f"cannot inspect language path: {path}") from exc
    return path.is_symlink() or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _require_pack(client: Path, language: str) -> Path:
    data = client / "data"
    if _is_reparse(data) or not data.is_dir():
        raise ClientLanguageError(f"client data must be a real directory: {data}")
    pack = data / f"local_{language.lower()}.pack"
    if _is_reparse(pack) or not pack.is_file():
        raise ClientLanguageError(
            f"language pack is unavailable for {language}: {pack}"
        )
    # Packs are read-only inputs; an existing hard link is safe here.  The
    # selector files themselves are writable and are checked by
    # ``require_safe_output`` below.
    if language == "RU":
        try:
            from tools.unpack_pfh5 import parse_pack, read_pack_index
        except ImportError:  # Direct execution from the tools directory.
            from unpack_pfh5 import parse_pack, read_pack_index
        try:
            entries = [entry for entry in parse_pack(read_pack_index(pack))
                       if entry.path.replace("\\", "/").lower() == "language.txt"]
            declared = None
            if len(entries) == 1 and entries[0].size == 2:
                with pack.open('rb') as stream:
                    stream.seek(entries[0].start)
                    declared = stream.read(2)
        except (OSError, RuntimeError, ValueError, IndexError, struct.error) as exc:
            raise ClientLanguageError(
                f"cannot verify RU language-pack metadata: {pack}"
            ) from exc
        if declared != b"RU":
            raise ClientLanguageError(
                f"RU language pack does not declare RU: {pack}"
            )
    return pack


def _read_selector(path: Path) -> str | None:
    if not os.path.lexists(path):
        return None
    if _is_reparse(path):
        raise ClientLanguageError(f"language selector must be a real file: {path}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ClientLanguageError(f"cannot read language selector: {path}") from exc
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ClientLanguageError(f"language selector is not ASCII: {path}") from exc
    return normalize_language(text)


def build_active_language_overlay(client: Path, language: str) -> bytes:
    """Prioritize translated text without duplicating font or audio resources.

    Arena's VFS reads language.txt from mounted archives. All installed locale
    packs coexist, so the two loose selectors alone do not select native text.
    PFH type 4 is auto-loaded after release packs; type 3 requires opting in.
    """
    from tools.unpack_pfh5 import parse_pack, read_pack_index
    from tools.pack_pfh5 import build_pack
    canonical = normalize_language(language)
    pack = _require_pack(client, canonical)
    try:
        entries = parse_pack(read_pack_index(pack))
        selected = []
        seen = set()
        total = 0
        with pack.open('rb') as stream:
            for entry in entries:
                name = entry.path.replace('\\', '/').lower()
                if name != 'language.txt' and not (name.startswith('text/') and name.endswith('.loc')):
                    continue
                if '..' in name.split('/') or name in seen:
                    raise ValueError('duplicate or invalid locale entry')
                seen.add(name)
                total += entry.size
                if total > 64 * 1024 * 1024:
                    raise ValueError('locale text exceeds supported size')
                stream.seek(entry.start)
                value = stream.read(entry.size)
                if len(value) != entry.size:
                    raise ValueError('truncated locale entry')
                if name == 'language.txt':
                    if value != canonical.encode('ascii'):
                        raise ValueError('locale metadata mismatch')
                elif not value.startswith((b'\xff\xfeLOC\0', b'LOC\0')):
                    raise ValueError('invalid locale text header')
                selected.append((entry.path, value))
        if 'language.txt' not in seen or len(selected) < 2:
            raise ValueError('locale text or selector missing')
        return build_pack(selected, flags=0x184)
    except (OSError, ValueError, RuntimeError, IndexError, struct.error) as exc:
        raise ClientLanguageError('cannot build verified active locale text') from exc


def current_client_language(client: str | Path) -> str:
    """Read the current selector without changing it; default only if absent."""
    root = Path(os.path.abspath(client))
    values = [_read_selector(root / relative) for relative in _LANGUAGE_FILES]
    present = [value for value in values if value is not None]
    if len(set(present)) > 1:
        raise ClientLanguageError("client language selectors disagree")
    language = present[0] if present else "EN"
    _require_pack(root, language)
    return language


def _verified_overlay_language(client: Path, overlay: bytes) -> str:
    """Recognize our output independently of loose selectors an update may reset."""
    from tools.unpack_pfh5 import parse_pack, extract_file
    try:
        entries = [entry for entry in parse_pack(overlay)
                   if entry.path.replace('\\', '/').lower() == 'language.txt']
        if len(entries) != 1 or entries[0].size != 2:
            raise ValueError('invalid overlay language metadata')
        language = normalize_language(extract_file(overlay, entries[0]).decode('ascii'))
        if overlay != build_active_language_overlay(client, language):
            raise ValueError('overlay differs from the verified translation pack')
        return language
    except (ClientLanguageError, OSError, ValueError, RuntimeError, IndexError, struct.error) as exc:
        raise ClientLanguageError('existing active locale overlay is unrecognized') from exc


def stage_language(original: str | Path, requested: str | None) -> str:
    """Choose a stage language, preserving the source selector by default."""
    if requested is not None:
        language = normalize_language(requested)
        _require_pack(Path(os.path.abspath(original)), language)
        return language
    return current_client_language(original)


def _safe_target(repo_root: Path, original: Path | None, target: Path) -> Path:
    try:
        return require_safe_output(repo_root, target, original=original)
    except (OriginalSafetyError, OSError, RuntimeError, ValueError) as exc:
        raise ClientLanguageError(f"unsafe language selector path: {target}") from exc


def _read_original(target: Path, repo_root: Path, original: Path | None) -> bytes | None:
    if not os.path.lexists(target):
        return None
    _safe_target(repo_root, original, target)
    try:
        return target.read_bytes()
    except OSError as exc:
        raise ClientLanguageError(f"cannot snapshot language selector: {target}") from exc


def _write_temp(parent: Path, data: bytes) -> Path:
    descriptor, raw = tempfile.mkstemp(
        prefix=".language-", suffix=".tmp", dir=parent,
    )
    temporary = Path(raw)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return temporary


def _restore_target(
    target: Path, previous: bytes | None, repo_root: Path, original: Path | None,
) -> None:
    _safe_target(repo_root, original, target)
    if previous is None:
        if os.path.lexists(target):
            target.unlink()
        return
    temporary = _write_temp(target.parent, previous)
    try:
        _safe_target(repo_root, original, target)
        os.replace(temporary, target)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def atomic_write_language_files(
    client: str | Path,
    language: str,
    *,
    repo_root: str | Path,
    original: str | Path | None = None,
) -> str:
    """Publish selectors and translated-text overlay, rolling all back on failure.

    The caller must hold ``client_operation_lock`` when updating an existing
    client.  ``stage_client`` holds that lock around its complete publication.
    """
    root = Path(os.path.abspath(client))
    boundary = Path(os.path.abspath(repo_root))
    owned_original = (Path(os.path.abspath(original)) if original is not None else None)
    canonical = normalize_language(language)
    _require_pack(root, canonical)
    targets = (root / _LANGUAGE_FILES[0], root / _LANGUAGE_FILES[1], root / _LANGUAGE_OVERLAY)
    previous = tuple(_read_original(target, boundary, owned_original) for target in targets)
    data = canonical.encode("ascii")
    overlay = build_active_language_overlay(root, canonical)
    if previous[2] is not None:
        _verified_overlay_language(root, previous[2])
    if previous == (data, data, overlay):
        return canonical
    temporary: list[Path] = []
    try:
        for target, contents in zip(targets, (data, data, overlay)):
            _safe_target(boundary, owned_original, target)
            temporary.append(_write_temp(target.parent, contents))
        for target, staged in zip(targets, temporary):
            _safe_target(boundary, owned_original, target)
            os.replace(staged, target)
        if current_client_language(root) != canonical:
            raise ClientLanguageError("language selector verification failed")
        temporary.clear()
    except (ClientLanguageError, OSError, RuntimeError, ValueError) as exc:
        rollback_error: Exception | None = None
        try:
            # Restore every target, including the one that was replaced first.
            for target, old in zip(targets, previous):
                _restore_target(target, old, boundary, owned_original)
        except Exception as restore_exc:  # pragma: no cover - catastrophic I/O
            rollback_error = restore_exc
        if rollback_error is not None:
            raise ClientLanguageError("language selector rollback failed") from rollback_error
        raise ClientLanguageError("language selector update failed") from exc
    finally:
        for staged in temporary:
            with suppress(OSError):
                staged.unlink()
    return canonical


def set_client_language(
    client: str | Path,
    language: str,
    *,
    repo_root: str | Path,
    original: str | Path | None = None,
) -> str:
    """Update selectors under the shared copied-client operation lock."""
    with client_operation_lock(Path(client)):
        return atomic_write_language_files(
            client, language, repo_root=repo_root, original=original,
        )


__all__ = [
    "SUPPORTED_LANGUAGES", "ClientLanguageError", "normalize_language",
    "current_client_language", "stage_language", "atomic_write_language_files",
    "set_client_language",
]
