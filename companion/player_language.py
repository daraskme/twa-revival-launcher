"""Persist launcher choice and apply it to the copied game's text overlay."""
from __future__ import annotations

import os
from pathlib import Path

from .client_lock import ClientOperationLockBusy, client_operation_lock
from .config import Config, _read_original_dir, _write_json_private
from .updater import is_arena_running
from tools.client_language import ClientLanguageError, atomic_write_language_files

LANGUAGES = ("JA", "EN", "RU")


def player_state_dir() -> Path:
    # Public preferences must not follow an internal-test state override.
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        raise OSError("local player state unavailable")
    return Path(local) / "TWARevival" / "Player"


def _validate_language(language: str) -> str:
    if language not in LANGUAGES:
        raise ValueError("invalid player language")
    return language


def load_player_language(*, state_dir: Path | None = None) -> str:
    import json
    try:
        path = (state_dir if state_dir is not None else player_state_dir()) / "launcher-preferences.json"
        with path.open("rb") as stream:
            raw = stream.read(1025)
        if len(raw) > 1024:
            return "EN"
        value = json.loads(raw)
        if (not isinstance(value, dict) or set(value) != {"schemaVersion", "language"}
                or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1):
            return "EN"
        return _validate_language(value["language"])
    except (OSError, ValueError, TypeError):
        return "EN"


def save_player_language(language: str, *, state_dir: Path | None = None) -> None:
    language = _validate_language(language)
    path = (state_dir if state_dir is not None else player_state_dir()) / "launcher-preferences.json"
    _write_json_private(path, {"schemaVersion": 1, "language": language})


def load_player_name_draft(*, state_dir: Path | None = None) -> str:
    """A local input draft, never an authenticated account name."""
    import json
    from .player_name import validate_display_name
    try:
        path = (state_dir if state_dir is not None else player_state_dir()) / "launcher-name-draft.json"
        with path.open("rb") as stream:
            raw = stream.read(1025)
        value = json.loads(raw)
        if (len(raw) > 1024 or not isinstance(value, dict)
                or set(value) != {"schemaVersion", "draft"}
                or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1):
            return ""
        return "" if value["draft"] == "" else validate_display_name(value["draft"])
    except (OSError, ValueError, TypeError):
        return ""


def save_player_name_draft(draft: str, *, state_dir: Path | None = None) -> None:
    from .player_name import validate_display_name
    if draft != "":
        validate_display_name(draft)
    path = (state_dir if state_dir is not None else player_state_dir()) / "launcher-name-draft.json"
    _write_json_private(path, {"schemaVersion": 1, "draft": draft})


def apply_launch_language(config: Config, language: str) -> str:
    """Caller holds the native lifecycle lock, after signed updates finish."""
    _validate_language(language)
    if is_arena_running():
        raise ClientLanguageError("close Arena before changing its language")
    return atomic_write_language_files(config.client_dir, language,
        repo_root=config.repo_root, original=config.original_dir)


def apply_player_language(root: Path, language: str) -> dict:
    """UI worker: defer a running/locked/missing game, never edit live packs.

    The GUI alone saves the preference. An older worker finishing later must
    not replace a newer selection that the user made while it was running.
    """
    _validate_language(language)
    config = Config(repo_root=root, client_dir=root / "client",
                    original_dir=_read_original_dir(root / "config" / "paths.ini"))
    result = {"language": language, "applied": False}
    try:
        with client_operation_lock(config.client_dir):
            if not (config.client_dir / "Arena.exe").is_file():
                return {**result, "reason": "not_installed"}
            if is_arena_running():
                return {**result, "reason": "running"}
            atomic_write_language_files(config.client_dir, language,
                repo_root=config.repo_root, original=config.original_dir)
    except ClientOperationLockBusy:
        return {**result, "reason": "busy"}
    return {**result, "applied": True}
