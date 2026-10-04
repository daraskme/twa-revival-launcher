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
_GRAPHICS_OPTIONS_LOC = "text/db/ui_options.loc"
_UNLIMITED_MEMORY_KEY = "ui_options_localised_label_checkbox_unlimited_memorygraphics"
_UNLIMITED_MEMORY_LABELS = {
    "EN": "Unlimited video memory",
    "JA": "ビデオメモリの制限を解除",
    "RU": "Неограниченная видеопамять",
}
_RECONNECT_UI_LOC = "text/db/uied_component_texts.loc"
_LEAVE_BATTLE_ACTIVE_KEY = "uied_component_texts_localised_string_button_quit_active_Text_630012"
_LEAVE_BATTLE_INACTIVE_KEY = "uied_component_texts_localised_string_button_quit_inactive_Text_630012"
_RECONNECT_RETURN_KEY = "uied_component_texts_localised_string_button_return_to_frontend_active_Text_0"


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


def _correct_graphics_memory_caption(value: bytes, language: str) -> bytes:
    """Correct the inverted stock caption, retaining all other LOC bytes.

    The native checkbox enables unlimited memory: checked saves
    gfx_automatic_assets_downgrade=false. The stock caption says the opposite.
    Only the exact label row in ui_options.loc is changed, never its binding.
    """
    base = 2 if value.startswith(b'\xff\xfe') else 0
    if value[base:base + 4] != b'LOC\0':
        raise ValueError('invalid graphics options text')
    count = struct.unpack_from('<I', value, base + 8)[0]
    offset = base + 12
    target = _UNLIMITED_MEMORY_KEY.encode('utf-16-le')
    replacement = None
    for _ in range(count):
        key_size = 2 * struct.unpack_from('<H', value, offset)[0]
        offset += 2
        key = value[offset:offset + key_size]
        offset += key_size
        value_start = offset
        text_size = 2 * struct.unpack_from('<H', value, offset)[0]
        offset += 2 + text_size
        if offset >= len(value):
            raise ValueError('truncated graphics options row')
        if key == target:
            if replacement is not None:
                raise ValueError('duplicate graphics memory caption')
            replacement = (value_start, offset)
        offset += 1  # Preserve the existing tooltip flag.
    if replacement is None:
        return value
    start, end = replacement
    caption = _UNLIMITED_MEMORY_LABELS[language].encode('utf-16-le')
    return value[:start] + struct.pack('<H', len(caption) // 2) + caption + value[end:]


def _copy_leave_battle_caption(value: bytes, target_key: str) -> bytes:
    """Fill one exact missing/empty LOC row from the verified stock translation."""
    base = 2 if value.startswith(b'\xff\xfe') else 0
    if len(value) < base + 12 or value[base:base + 4] != b'LOC\0':
        raise ValueError('invalid reconnect UI text')
    if struct.unpack_from('<I', value, base + 4)[0] != 1:
        raise ValueError('unsupported reconnect UI text version')
    count = struct.unpack_from('<I', value, base + 8)[0]
    offset = base + 12
    active_key = _LEAVE_BATTLE_ACTIVE_KEY.encode('utf-16-le')
    target_key_bytes = target_key.encode('utf-16-le')
    active_caption = None
    target_span = None
    for _ in range(count):
        if offset + 2 > len(value):
            raise ValueError('truncated reconnect UI key length')
        key_size = 2 * struct.unpack_from('<H', value, offset)[0]
        offset += 2
        if offset + key_size + 2 > len(value):
            raise ValueError('truncated reconnect UI key')
        key = value[offset:offset + key_size]
        offset += key_size
        text_size = 2 * struct.unpack_from('<H', value, offset)[0]
        caption_span = (offset, offset + 2 + text_size)
        offset += 2
        if offset + text_size + 1 > len(value):
            raise ValueError('truncated reconnect UI caption')
        caption = value[offset:offset + text_size]
        offset += text_size
        offset += 1
        if key == active_key:
            if active_caption is not None or not caption:
                raise ValueError('invalid active leave battle caption')
            caption.decode('utf-16-le')
            active_caption = caption
        elif key == target_key_bytes:
            if target_span is not None:
                raise ValueError('duplicate target leave battle caption')
            target_span = (caption_span, caption)
    if offset != len(value):
        raise ValueError('invalid reconnect UI trailing bytes')
    if active_caption is None:
        raise ValueError('missing active leave battle caption')
    if target_span is not None:
        (start, end), caption = target_span
        if caption:
            return value
        return (value[:start] + struct.pack('<H', len(active_caption) // 2)
                + active_caption + value[end:])
    if count == 0xffffffff:
        raise ValueError('reconnect UI row count overflow')
    if len(target_key_bytes) // 2 > 0xffff or len(active_caption) // 2 > 0xffff:
        raise ValueError('reconnect UI caption too long')
    row = (struct.pack('<H', len(target_key_bytes) // 2) + target_key_bytes
           + struct.pack('<H', len(active_caption) // 2) + active_caption + b'\x01')
    return (value[:base + 8] + struct.pack('<I', count + 1)
            + value[base + 12:] + row)


def _add_leave_battle_inactive_caption(value: bytes) -> bytes:
    """Retain the exact 0.2.35/0.2.36 quit-menu inactive-caption correction."""
    return _copy_leave_battle_caption(value, _LEAVE_BATTLE_INACTIVE_KEY)


def _add_reconnect_return_caption(value: bytes) -> bytes:
    """Resolve the real reconnection dialog key shared by all five states.

    Version119 reconnection_dialogue_box binds button_return_to_frontend to
    active_Text_0 in active/down/down_off/hover/inactive. The quit-menu 630012
    key does not occur in that dialog. Keep the UIC and its behavior unchanged.
    """
    return _copy_leave_battle_caption(value, _RECONNECT_RETURN_KEY)


def build_active_language_overlay(client: Path, language: str) -> bytes:
    return _build_active_language_overlay(
        client, language, correct_graphics_caption=True,
        correct_reconnect_caption=True,
        correct_reconnect_return_caption=True)


def _build_active_language_overlay(client: Path, language: str, *,
                                   correct_graphics_caption: bool,
                                   correct_reconnect_caption: bool,
                                   correct_reconnect_return_caption: bool = False) -> bytes:
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
                if name == _GRAPHICS_OPTIONS_LOC and correct_graphics_caption:
                    value = _correct_graphics_memory_caption(value, canonical)
                if name == _RECONNECT_UI_LOC and correct_reconnect_caption:
                    value = _add_leave_battle_inactive_caption(value)
                if name == _RECONNECT_UI_LOC and correct_reconnect_return_caption:
                    value = _add_reconnect_return_caption(value)
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
            # A signed launcher update may encounter the exact old overlay.
            # Rebuild that historical form from the same verified pack; never
            # accept an arbitrary overlay based only on its language selector.
            current_0236 = _build_active_language_overlay(
                client, language, correct_graphics_caption=True,
                correct_reconnect_caption=True)
            previous = _build_active_language_overlay(
                client, language, correct_graphics_caption=True,
                correct_reconnect_caption=False)
            legacy = _build_active_language_overlay(
                client, language, correct_graphics_caption=False,
                correct_reconnect_caption=False)
            if overlay not in (current_0236, previous, legacy):
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
