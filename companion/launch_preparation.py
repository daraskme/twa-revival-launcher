"""Guarded production preparation for one authenticated Arena launch.

This adapter consumes an already validated immutable :class:`LaunchPlan`.
It never reloads a session, authenticates, starts/stops a process, patches a
DLL, or changes profile economy.  The caller owns the canonical client lock.
"""
from __future__ import annotations

import hashlib
from decimal import Decimal, InvalidOperation
import os
import re
import stat
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Protocol

from .config import Config
from .launcher import LaunchPlan
from .updater import (
    UpdaterError, _is_same_or_beneath, _lexists,
    _require_safe_update_boundaries, _require_unshared_regular_or_missing,
    _safe_client_target, is_arena_running,
)


_NPL_STUB_SHA256 = {
    "npl-base.dll": "9ab3d54d9d5f28d1ad1802a621d8e68f6f9f37f10808f8b3586d5949f32c424d",
    "npl-sdk.dll": "65122308d752e5a39e749737900222e5f5518b48a4a2381f10c1eff2dcc66591",
}
_REGISTRY_PATH = r"Software\The Creative Assembly\Arena"
_REGISTRY_NAME = "machine_fingerprint"
_SESSION_TOKEN_RE = re.compile(r"[a-f0-9]{64}\Z")
_NATIVE_USER_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,36}\Z")
_SAFE_ENV_NAMES = frozenset(name.casefold() for name in (
    "ALLUSERSPROFILE", "APPDATA", "COMPUTERNAME", "COMSPEC",
    "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(X86)", "COMMONPROGRAMW6432",
    "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "NUMBER_OF_PROCESSORS",
    "OS", "PATH", "PATHEXT", "PUBLIC", "SESSIONNAME", "SYSTEMDRIVE",
    "SYSTEMROOT", "TEMP", "TMP", "USERDOMAIN", "USERNAME", "USERPROFILE",
    "WINDIR", "LANG", "LC_ALL", "TZ", "PROGRAMFILES",
    "PROGRAMFILES(X86)", "PROGRAMW6432", "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER", "PROCESSOR_LEVEL", "PROCESSOR_REVISION",
))
_PREFERENCE_KEYS = {
    "x_res": "int", "y_res": "int", "x_pos": "int", "y_pos": "int",
    "gfx_fullscreen": "bool", "fix_res": "bool", "fix_window_pos": "bool",
    "gfx_show_pre_launch_window": "bool", "write_preferences_at_exit": "bool",
    "FRONTEND_SCENE_ENABLED": "bool", "PERMANENTLY_SKIP_TUTORIAL": "bool",
    "show_frontend_movies": "bool", "ONLINE_PLATFORM": "string",
    "fake_auth_token": "string", "display_name_override": "string",
    "startup_frontend_scene": "string",
    "gfx_aa": "int", "gfx_texture_quality": "int", "gfx_sky_quality": "int",
    "gfx_unit_quality": "int", "gfx_building_quality": "int", "gfx_shadow_quality": "int",
    "gfx_tree_quality": "int", "gfx_grass_quality": "int", "gfx_terrain_quality": "int",
    "gfx_water_quality": "int", "gfx_effects_quality": "int", "gfx_vsync": "bool",
    "gfx_ssao": "bool", "gfx_distortion": "bool", "gfx_gpu": "string",
}
# Values exposed by the native graphics menu, including resolution and display
# mode, survive a game-side preferences write. Window placement, platform,
# identity and auth settings remain owned by the launch transaction.
_PERSISTENT_GRAPHICS_KEYS = {
    "x_res": "width", "y_res": "height", "gfx_fullscreen": "bool",
    "gfx_aa": "int", "gfx_texture_quality": "int",
    "gfx_texture_filtering": "int", "gfx_sky_quality": "int",
    "gfx_unit_quality": "int", "gfx_building_quality": "int",
    "gfx_shadow_quality": "int", "gfx_tree_quality": "int",
    "gfx_grass_quality": "int", "gfx_terrain_quality": "int",
    "gfx_water_quality": "int", "gfx_effects_quality": "int",
    "gfx_depth_of_field": "int", "gfx_hdr": "int",
    "gfx_alpha_blend": "int", "gfx_auto_resolution_scale_target_fps": "fps",
    "gfx_gamma_setting": "float", "gfx_brightness_setting": "float",
    "gfx_fixed_resolution_scale": "scale",
    "gfx_vsync": "bool", "gfx_ssao": "bool",
    "gfx_distortion": "bool", "gfx_ssr": "bool",
    "gfx_tesselation": "bool", "gfx_vignette": "bool",
    "gfx_blood_effects": "bool", "gfx_auto_resolution_scale": "bool",
    "gfx_automatic_assets_downgrade": "bool",
    # Native Apply also records the detected adapter and first-run state.
    "gfx_gpu": "gpu", "gfx_first_run": "bool",
}
_LAUNCH_ONLY_PREFERENCE_KEYS = (
    "ONLINE_PLATFORM", "fake_auth_token", "display_name_override",
    "startup_frontend_scene", "FRONTEND_SCENE_ENABLED",
    "PERMANENTLY_SKIP_TUTORIAL", "show_frontend_movies",
    "write_preferences_at_exit", "fix_res", "fix_window_pos",
    "gfx_show_pre_launch_window",
)
# preferences.template.txt belongs to the immutable core of older installers.
# Keep fallback graphics in signed, updateable code so upgrades and new ZIPs
# agree without replacing a valid user's chosen settings.
_FALLBACK_GRAPHICS = {
    "gfx_aa": 0, "gfx_texture_quality": 1, "gfx_sky_quality": 1,
    "gfx_unit_quality": 1, "gfx_building_quality": 1, "gfx_shadow_quality": 0,
    "gfx_tree_quality": 1, "gfx_grass_quality": 1, "gfx_terrain_quality": 1,
    "gfx_water_quality": 1, "gfx_effects_quality": 1, "gfx_vsync": True,
    "gfx_ssao": False, "gfx_distortion": False, "gfx_gpu": '""',
}


class LaunchPreparationError(RuntimeError):
    """Authenticated launch inputs or owned preparation state are unsafe."""


class _Operations(Protocol):
    environ: Mapping[str, str]

    def arena_running(self) -> bool: ...
    def verify_native_install(self, config: Config) -> None: ...
    def validate_wad_catalogue(self, config: Config, wad: Path) -> None: ...
    def primary_monitor(self) -> dict[str, int]: ...
    def registry_read(self) -> tuple[bool, str | None, int | None]: ...
    def registry_write(self, value: str) -> None: ...
    def registry_delete(self) -> None: ...


class _ProductionOperations:
    def __init__(self) -> None:
        self.environ = dict(os.environ)

    def arena_running(self) -> bool:
        return is_arena_running()

    def verify_native_install(self, config: Config) -> None:
        from tools.install_native_battle_modes import (
            DEFAULT_INSTALL_MANIFEST, verify_installed_manifest,
        )
        verify_installed_manifest(
            config.repo_root / DEFAULT_INSTALL_MANIFEST,
            repo_root=config.repo_root,
        )

    def validate_wad_catalogue(self, config: Config, wad: Path) -> None:
        server = str(config.repo_root / "server")
        if server not in sys.path:
            sys.path.insert(0, server)
        from native_unit_abilities import (  # type: ignore
            load_native_unit_abilities, validate_deployed_unit_ability_wad,
        )
        catalogue = load_native_unit_abilities(
            config.repo_root / "catalog" / "native_unit_abilities.json")
        validate_deployed_unit_ability_wad(catalogue, wad)

    def primary_monitor(self) -> dict[str, int]:
        from tools.pin_primary_monitor import primary_monitor
        return primary_monitor()

    def registry_read(self) -> tuple[bool, str | None, int | None]:
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REGISTRY_PATH)
        except FileNotFoundError:
            return False, None, None
        try:
            try:
                value, value_type = winreg.QueryValueEx(key, _REGISTRY_NAME)
            except FileNotFoundError:
                return False, None, None
            return True, str(value), int(value_type)
        finally:
            winreg.CloseKey(key)

    def registry_write(self, value: str) -> None:
        import winreg
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, _REGISTRY_PATH)
        try:
            winreg.SetValueEx(key, _REGISTRY_NAME, 0, winreg.REG_SZ, value)
        finally:
            winreg.CloseKey(key)

    def registry_delete(self) -> None:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _REGISTRY_PATH, 0, winreg.KEY_SET_VALUE)
        try:
            winreg.DeleteValue(key, _REGISTRY_NAME)
        finally:
            winreg.CloseKey(key)


def _production_operations() -> _Operations:
    return _ProductionOperations()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(path: Path, label: str, *, strict: bool) -> Path:
    try:
        return Path(os.path.realpath(os.path.abspath(path))).resolve(strict=strict)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise LaunchPreparationError(f"cannot resolve {label} safely") from exc


def _is_reparse(path: Path) -> bool:
    try:
        attrs = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError as exc:
        raise LaunchPreparationError(f"cannot inspect path: {path}") from exc
    return path.is_symlink() or bool(
        attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(os.path.abspath(right))


def _paths_overlap(left: Path, right: Path) -> bool:
    return (_is_same_or_beneath(left, right)
            or _is_same_or_beneath(right, left))


def _require_real_ancestors(path: Path, label: str) -> Path:
    """Resolve an existing directory only after checking every lexical ancestor."""
    current = Path(os.path.abspath(path))
    while True:
        if not _lexists(current) or _is_reparse(current) or not current.is_dir():
            raise LaunchPreparationError(
                f"{label} must traverse only existing real directories: {current}")
        if current.parent == current:
            break
        current = current.parent
    return _canonical(path, label, strict=True)


@dataclass(frozen=True)
class _ParentGuard:
    lexical: Path
    canonical: Path


def _capture_parent_guard(path: Path, label: str) -> _ParentGuard:
    lexical = Path(os.path.abspath(path.parent))
    canonical = _require_real_ancestors(lexical, label)
    return _ParentGuard(lexical=lexical, canonical=canonical)


def _validate_parent_guard(path: Path, guard: _ParentGuard, label: str) -> None:
    lexical = Path(os.path.abspath(path.parent))
    if not _same_path(lexical, guard.lexical):
        raise LaunchPreparationError(f"{label} parent path changed: {path.parent}")
    canonical = _require_real_ancestors(lexical, label)
    if not _same_path(canonical, guard.canonical):
        raise LaunchPreparationError(
            f"{label} parent changed externally; refusing mutation: {path.parent}")


def _validate_config(config: Config) -> Path:
    try:
        _require_safe_update_boundaries(config)
    except UpdaterError as exc:
        raise LaunchPreparationError(f"unsafe configured launch boundary: {exc}") from exc
    root = _canonical(config.repo_root, "repository root", strict=True)
    client = _canonical(config.client_dir, "copied client", strict=True)
    expected_client = _canonical(root / "client", "canonical copied client", strict=True)
    if not _same_path(client, expected_client):
        raise LaunchPreparationError(
            "configured client must be the canonical repository client directory")
    raw_state = Path(os.path.abspath(config.state_dir))
    state = _canonical(raw_state, "companion state directory", strict=_lexists(raw_state))
    if _paths_overlap(Path(os.path.abspath(config.client_dir)), raw_state) \
            or _paths_overlap(client, state):
        raise LaunchPreparationError(
            "client and companion state directories must be disjoint")
    return client


def _frontend_script(config: Config, token: str, native_user_id: str) -> str:
    server = str(config.repo_root / "server")
    if server not in sys.path:
        sys.path.insert(0, server)
    from f2p_fake import frontend_user_script  # type: ignore
    return frontend_user_script(token, native_user_id)


def _stack_config_bytes(config: Config) -> bytes:
    server = str(config.repo_root / "server")
    if server not in sys.path:
        sys.path.insert(0, server)
    from f2p_fake import LOCAL_STACK_FILE, ca_json  # type: ignore
    return ca_json(LOCAL_STACK_FILE).encode("utf-8")


def _token_and_identity(config: Config, plan: LaunchPlan, client: Path) -> tuple[str, str]:
    if type(plan.argv) is not tuple or len(plan.argv) != 3:
        raise LaunchPreparationError("launch argv must be an immutable three-item tuple")
    if any(not isinstance(item, str) or not item or "\0" in item for item in plan.argv):
        raise LaunchPreparationError("launch argv contains an invalid value")
    exe = _safe_client_target(config, "Arena.exe")
    if not exe.is_file() or not _same_path(Path(plan.argv[0]), exe):
        raise LaunchPreparationError("launch argv does not target the copied Arena executable")
    if plan.argv[1] != "+auth":
        raise LaunchPreparationError("launch argv must contain exactly one +auth token")
    token = plan.argv[2]
    if _SESSION_TOKEN_RE.fullmatch(token) is None:
        raise LaunchPreparationError("launch token does not match the authenticated session format")
    if not isinstance(plan.cwd, str) or not _same_path(Path(plan.cwd), client):
        raise LaunchPreparationError("launch cwd does not match the copied client")
    native_user_id = plan.native_user_id
    if (not isinstance(native_user_id, str)
            or _NATIVE_USER_ID_RE.fullmatch(native_user_id) is None):
        raise LaunchPreparationError("launch plan has no validated native user identity")
    display_name = plan.display_name
    if display_name is not None:
        from .player_name import validate_display_name
        validate_display_name(display_name)
    expected_script = _frontend_script(
        config, token, native_user_id if display_name is None else display_name)
    if plan.user_script_text != expected_script:
        raise LaunchPreparationError(
            "launch User.script does not match the plan token/native identity")
    return token, native_user_id


def _require_source_file(path: Path, label: str) -> Path:
    if not _lexists(path) or _is_reparse(path) or not path.is_file():
        raise LaunchPreparationError(f"{label} must be an existing regular file: {path}")
    current = path.parent
    while True:
        if _is_reparse(current) or not current.is_dir():
            raise LaunchPreparationError(
                f"{label} must not traverse a reparse point: {current}")
        if current.parent == current:
            break
        current = current.parent
    try:
        if path.lstat().st_nlink != 1:
            raise LaunchPreparationError(f"{label} must not be a hard link: {path}")
    except OSError as exc:
        raise LaunchPreparationError(f"cannot inspect {label}: {path}") from exc
    return path


def _validate_installed_artifacts(config: Config, operations: _Operations) -> None:
    try:
        operations.verify_native_install(config)
        wad = _safe_client_target(config, "data/wad.pack")
        operations.validate_wad_catalogue(config, wad)
    except (OSError, RuntimeError, ValueError) as exc:
        raise LaunchPreparationError(f"installed native client validation failed: {exc}") from exc
    for name, expected in _NPL_STUB_SHA256.items():
        installed = _safe_client_target(config, name)
        reviewed = config.repo_root / "npl_stub" / name
        _require_source_file(installed, f"installed {name}")
        _require_source_file(reviewed, f"reviewed {name}")
        try:
            installed_hash = _sha256(installed.read_bytes())
            reviewed_hash = _sha256(reviewed.read_bytes())
        except OSError as exc:
            raise LaunchPreparationError(f"cannot read existing NPL stub {name}") from exc
        if installed_hash != expected or reviewed_hash != expected:
            raise LaunchPreparationError(
                f"existing NPL stub {name} is missing or unreviewed; reinstall it before launch")


def _profile_scripts_path(config: Config, supplied: Path | None,
                          operations: _Operations) -> Path:
    if supplied is None:
        raw_appdata = operations.environ.get("APPDATA")
        if not isinstance(raw_appdata, str) or not raw_appdata:
            raise LaunchPreparationError("APPDATA is unavailable for Arena scripts")
        supplied = (Path(raw_appdata) / "The Creative Assembly" / "Arena" / "scripts")
    if not Path(supplied).is_absolute():
        raise LaunchPreparationError("Arena scripts directory must be absolute")
    path = Path(os.path.abspath(supplied))
    for protected, label in ((config.client_dir, "client"),
                             (config.original_dir, "original"),
                             (config.state_dir, "state")):
        if protected is None:
            continue
        if (_is_same_or_beneath(path, protected)
                or _is_same_or_beneath(protected, path)):
            raise LaunchPreparationError(
                f"Arena scripts directory must be disjoint from {label} directory")
    existing = path
    while not _lexists(existing):
        if existing.parent == existing:
            raise LaunchPreparationError("cannot find a safe Arena scripts parent")
        existing = existing.parent
    current = existing
    while True:
        if _is_reparse(current) or not current.is_dir():
            raise LaunchPreparationError("Arena scripts parent is not a real directory")
        if current.parent == current:
            break
        current = current.parent
    return path


@dataclass
class _OwnedDirectory:
    path: Path
    parent_guard: _ParentGuard
    complete: bool = False

    def remove_if_empty(self) -> None:
        if self.complete:
            return
        _validate_parent_guard(self.path, self.parent_guard, "owned launch directory")
        if not _lexists(self.path):
            self.complete = True
            return
        if _is_reparse(self.path) or not self.path.is_dir():
            raise LaunchPreparationError(
                f"owned directory changed externally: {self.path}")
        try:
            next(self.path.iterdir())
        except StopIteration:
            _validate_parent_guard(
                self.path, self.parent_guard, "owned launch directory")
            if not _lexists(self.path) or _is_reparse(self.path) or not self.path.is_dir():
                raise LaunchPreparationError(
                    f"owned directory changed externally: {self.path}")
            self.path.rmdir()
        except OSError as exc:
            raise LaunchPreparationError(
                f"cannot inspect owned launch directory: {self.path}") from exc
        else:
            # Runtime output makes the directory caller/external-owned. Never delete it.
            self.complete = True
            return
        self.complete = True


def _create_directories(path: Path) -> list[_OwnedDirectory]:
    missing: list[Path] = []
    current = path
    while not _lexists(current):
        missing.append(current)
        current = current.parent
    if _is_reparse(current) or not current.is_dir():
        raise LaunchPreparationError(f"directory parent is unsafe: {current}")
    created: list[_OwnedDirectory] = []
    try:
        for directory in reversed(missing):
            parent_guard = _capture_parent_guard(
                directory, "launch directory parent")
            _validate_parent_guard(directory, parent_guard, "launch directory parent")
            directory.mkdir()
            if _is_reparse(directory) or not directory.is_dir():
                raise LaunchPreparationError(f"created directory is unsafe: {directory}")
            created.append(_OwnedDirectory(directory, parent_guard))
    except Exception:
        for owned in reversed(created):
            try:
                owned.remove_if_empty()
            except Exception:
                pass
        raise
    return created


def _read_pref_text(raw: bytes) -> str:
    if raw.startswith(b"\xff\xfe"):
        return raw.decode("utf-16-le").lstrip("\ufeff")
    if raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16-be").lstrip("\ufeff")
    if len(raw) > 3 and raw[1] == 0:
        return raw.decode("utf-16-le").lstrip("\ufeff")
    return raw.decode("utf-8", errors="replace").lstrip("\ufeff")


def _set_preference(text: str, key: str, value: object) -> str:
    kind = _PREFERENCE_KEYS[key]
    if kind == "bool":
        rendered = "true" if value is True else "false"
        pattern = re.compile(rf"^[ \t]*{re.escape(key)}[ \t]+\w+;(.*)$", re.M)
    elif kind == "int":
        rendered = str(int(value))
        pattern = re.compile(rf"^[ \t]*{re.escape(key)}[ \t]+-?\d+;(.*)$", re.M)
    else:
        rendered = str(value)
        if any(char in rendered for char in ("\r", "\n", ";", "\0")):
            raise LaunchPreparationError(f"unsafe preference value for {key}")
        pattern = re.compile(rf"^[ \t]*{re.escape(key)}[ \t]+.+$", re.M)
    replacement = f"{key} {rendered};"
    return pattern.sub(lambda _match: replacement, text, count=1) if pattern.search(text) \
        else replacement + "\n" + text


def _preferences_corrupt(text: str) -> bool:
    if "\ufeff" in text:
        return True
    counts: dict[str, int] = {}
    # Stock files repeat each setting name in its trailing documentation and
    # may contain several comment-only lines. Count assignments, not comments.
    for key in re.findall(r"^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]+[^;\r\n]+;", text, re.M):
        counts[key] = counts.get(key, 0) + 1
    return any(count > 1 for count in counts.values())


def _build_preferences(current: bytes | None, template: str,
                       monitor: dict[str, int], token: str,
                       native_user_id: str, display_name: str | None = None) -> bytes:
    if set(monitor) != {"x", "y", "w", "h"} or any(
            type(monitor[key]) is not int for key in monitor):
        raise LaunchPreparationError("primary monitor result is invalid")
    if monitor["w"] <= 0 or monitor["h"] <= 0:
        raise LaunchPreparationError("primary monitor dimensions are invalid")
    if display_name is not None:
        from .player_name import validate_display_name
        validate_display_name(display_name)
    text = _read_pref_text(current) if current is not None else ""
    use_fallback = (not text.strip() or _preferences_corrupt(text)
                   or len(re.findall(r"^[ \t]*x_res[ \t]+\d+;", text, re.M)) != 1)
    if use_fallback:
        text = template
        for key, value in _FALLBACK_GRAPHICS.items():
            text = _set_preference(text, key, value)
    display: dict[str, object] = {
        "x_res": min(monitor["w"], 1600),
        "y_res": min(monitor["h"], 900),
        "gfx_fullscreen": False,
    }
    if not use_fallback:
        saved = {key: _graphics_assignment(text, key) for key in display}
        # Treat width/height as a pair. Do not clamp a valid saved mode to the
        # desktop size: fullscreen and supersampled modes can exceed it.
        if all(saved[key] is not None and _valid_graphics_value(key, saved[key][2].strip())
               for key in ("x_res", "y_res")):
            for key in ("x_res", "y_res"):
                display[key] = int(saved[key][2].strip())
        mode = saved["gfx_fullscreen"]
        if mode is not None and _valid_graphics_value("gfx_fullscreen", mode[2].strip()):
            display["gfx_fullscreen"] = mode[2].strip() == "true"
    # Remove malformed display assignments too, so fallback cannot append a
    # second definition after an invalid value such as `y_res unknown;`.
    for key, value in display.items():
        text = re.sub(rf"(?m)^[ \t]*{re.escape(key)}[ \t]+[^\r\n]*(?:\r?\n|$)", "", text)
        text = _set_preference(text, key, value)
    values: tuple[tuple[str, object], ...] = (
        ("x_pos", monitor["x"]), ("y_pos", monitor["y"]),
        ("fix_res", True),
        ("fix_window_pos", True), ("gfx_show_pre_launch_window", False),
        ("write_preferences_at_exit", False), ("FRONTEND_SCENE_ENABLED", True),
        ("PERMANENTLY_SKIP_TUTORIAL", True), ("show_frontend_movies", False),
        ("ONLINE_PLATFORM", "fake"), ("fake_auth_token", token),
        ("display_name_override", native_user_id if display_name is None
         else '"' + display_name + '"'),
        ("startup_frontend_scene", "frontend_1"),
    )
    for key, value in values:
        text = _set_preference(text, key, value)
    return b"\xff\xfe" + text.replace("\r\n", "\n").encode("utf-16-le")


def _decode_owned_preferences(raw: bytes) -> tuple[str, str]:
    if len(raw) > 256 * 1024:
        raise LaunchPreparationError("owned preferences exceed the merge limit")
    try:
        if raw.startswith(b"\xff\xfe"):
            return raw[2:].decode("utf-16-le"), "utf-16-le"
        if raw.startswith(b"\xfe\xff"):
            return raw[2:].decode("utf-16-be"), "utf-16-be"
        return raw.decode("utf-8-sig"), "utf-8"
    except UnicodeError:
        raise LaunchPreparationError("owned preferences have invalid encoding") from None


def _graphics_assignment(text: str, key: str):
    pattern = re.compile(
        rf"(?m)^([ \t]*{re.escape(key)}[ \t]+)([^;\r\n]+)(;[^\r\n]*)(\r?\n|$)")
    matches = list(pattern.finditer(text))
    if len(matches) > 1:
        raise LaunchPreparationError("owned preferences contain duplicate graphics settings")
    return matches[0] if matches else None


def _preference_assignments(text: str) -> dict[str, str]:
    """Parse values independently of native writer ordering and documentation."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(
            r"[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]+([^;\r\n\0]+);[ \t]*(?:#.*)?", line)
        if match is None or match[1] in values:
            raise LaunchPreparationError("owned preferences contain invalid assignments")
        values[match[1]] = match[2].strip()
    return values


def _valid_graphics_value(key: str, value: str) -> bool:
    kind = _PERSISTENT_GRAPHICS_KEYS[key]
    if kind == "gpu":
        return len(value) <= 258 and re.fullmatch(r'"[^";\r\n\0]*"', value) is not None
    if kind == "bool":
        return value in ("true", "false")
    if kind in ("width", "height"):
        if re.fullmatch(r"[0-9]{3,5}", value) is None:
            return False
        return (640 if kind == "width" else 480) <= int(value) <= 16384
    if kind in ("int", "fps"):
        if re.fullmatch(r"[0-9]{1,3}", value) is None:
            return False
        number = int(value)
        return 10 <= number <= 240 if kind == "fps" else 0 <= number <= 16
    if re.fullmatch(r"(?:[0-9]{1,2})(?:\.[0-9]{1,6})?", value) is None:
        return False
    try:
        number = Decimal(value)
    except InvalidOperation:
        return False
    return (Decimal("0.25") <= number <= Decimal("2") if kind == "scale"
            else Decimal("0.1") <= number <= Decimal("5"))


def _merge_verified_graphics(before: bytes | None, after: bytes,
                             current: bytes) -> bytes:
    expected, expected_encoding = _decode_owned_preferences(after)
    observed, observed_encoding = _decode_owned_preferences(current)
    if before is None:
        # First launch: retain verified menu choices using the generated
        # preferences, but strip every launch-only binding before persisting.
        baseline, baseline_encoding = expected, expected_encoding
        for key in _LAUNCH_ONLY_PREFERENCE_KEYS:
            pattern = re.compile(rf"(?m)^[ \t]*{re.escape(key)}[ \t]+[^\r\n]*\r?\n?")
            baseline = pattern.sub("", baseline)
    else:
        baseline, baseline_encoding = _decode_owned_preferences(before)
    if (expected_encoding != "utf-16-le" or observed_encoding != expected_encoding
            or _preferences_corrupt(baseline) or _preferences_corrupt(observed)
            or len(re.findall(r"^[ \t]*x_res[ \t]+\d+;", baseline, re.M)) != 1):
        raise LaunchPreparationError("owned preferences cannot be safely merged")
    original_values = _preference_assignments(expected)
    observed_values = _preference_assignments(observed)
    _preference_assignments(baseline)
    # Apply writes the native settings table from scratch: CRLF, stock comments,
    # its own ordering, and no launcher-only platform/authentication entries.
    # Compare the full assignment map, then retain only verified menu values.
    if (observed_values.keys() - original_values.keys()
            or original_values.keys() - observed_values.keys()
               - set(_LAUNCH_ONLY_PREFERENCE_KEYS)):
        raise LaunchPreparationError("owned preferences changed outside graphics values")
    merged = baseline
    for key, value in observed_values.items():
        if value == original_values[key]:
            continue
        if key in ("x_pos", "y_pos"):
            # Native Apply may record the window frame position. Keep the
            # launch-owned baseline, after checking that this is only a
            # bounded coordinate rewrite.
            if (re.fullmatch(r"-?[0-9]{1,6}", value) is None
                    or not -131072 <= int(value) <= 131072):
                raise LaunchPreparationError(
                    "owned preferences contain an invalid window position")
            continue
        if key == "battle_advice_level" and value == "0":
            # User.script requests level 0, which native Apply may copy into
            # preferences. It is a launch-time override, not a menu choice;
            # retain the user's original preference in the durable file.
            continue
        if key not in _PERSISTENT_GRAPHICS_KEYS or not _valid_graphics_value(key, value):
            raise LaunchPreparationError("owned preferences contain an invalid graphics value")
        durable = _graphics_assignment(merged, key)
        if durable is None:
            merged = f"{key} {value};\n" + merged
        else:
            merged = merged[:durable.start(2)] + value + merged[durable.end(2):]
    if baseline_encoding == "utf-16-le":
        result = b"\xff\xfe" + merged.encode("utf-16-le")
    elif baseline_encoding == "utf-16-be":
        result = b"\xfe\xff" + merged.encode("utf-16-be")
    else:
        result = merged.encode("utf-8")
    # The current launch's bearer token must not survive a graphics update.
    token = re.search(r"(?m)^[ \t]*fake_auth_token[ \t]+([^;\r\n]+);", expected)
    if token is None or token.group(1) in merged:
        raise LaunchPreparationError("owned preferences retain the launch token")
    return result


def sanitized_launch_environment(source: Mapping[str, str]) -> dict[str, str]:
    """Return the exact, secret-minimized environment allowed for native children."""
    result: dict[str, str] = {}
    seen: dict[str, str] = {}
    for key, value in source.items():
        if not isinstance(key, str) or "\0" in key:
            raise LaunchPreparationError("environment contains an invalid variable name")
        folded = key.casefold()
        if folded in seen:
            raise LaunchPreparationError(
                f"environment contains case-colliding variable names: {seen[folded]!r}, {key!r}")
        seen[folded] = key
        if folded in _SAFE_ENV_NAMES:
            if isinstance(value, str) and "\0" not in value:
                result[key] = value
    for key in list(result):
        if key.casefold() == "online_platform":
            del result[key]
    result["ONLINE_PLATFORM"] = "fake"
    return result


def _atomic_replace(path: Path, data: bytes, expected_before: bytes | None,
                    parent_guard: _ParentGuard) -> None:
    _validate_parent_guard(path, parent_guard, "launch preparation target")
    _require_unshared_regular_or_missing(path, "launch preparation target")
    current = path.read_bytes() if _lexists(path) else None
    if current != expected_before:
        raise LaunchPreparationError(f"launch preparation target changed before write: {path}")
    fd, raw_tmp = tempfile.mkstemp(prefix=f".{path.name}.prepare-", suffix=".tmp",
                                   dir=path.parent)
    tmp = Path(raw_tmp)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _validate_parent_guard(path, parent_guard, "launch preparation target")
        _require_unshared_regular_or_missing(path, "launch preparation target")
        current = path.read_bytes() if _lexists(path) else None
        if current != expected_before:
            raise LaunchPreparationError(
                f"launch preparation target changed during write: {path}")
        _validate_parent_guard(path, parent_guard, "launch preparation target")
        _require_unshared_regular_or_missing(path, "launch preparation target")
        current = path.read_bytes() if _lexists(path) else None
        if current != expected_before:
            raise LaunchPreparationError(
                f"launch preparation target changed immediately before replace: {path}")
        os.replace(tmp, path)
    finally:
        _validate_parent_guard(tmp, parent_guard, "launch temporary file")
        if _lexists(tmp):
            _require_unshared_regular_or_missing(tmp, "launch temporary file")
            tmp.unlink()


@dataclass
class _OwnedFile:
    path: Path
    before: bytes | None
    after: bytes
    parent_guard: _ParentGuard
    commit_state: str = "not_applied"
    restored: bool = False

    def apply(self) -> None:
        if self.before == self.after:
            self.restored = True
            return
        try:
            _atomic_replace(self.path, self.after, self.before, self.parent_guard)
        except Exception:
            try:
                _validate_parent_guard(
                    self.path, self.parent_guard, "owned launch file")
                _require_unshared_regular_or_missing(self.path, "owned launch file")
                current = self.path.read_bytes() if _lexists(self.path) else None
            except Exception:
                self.commit_state = "ambiguous"
            else:
                if current == self.after:
                    self.commit_state = "applied"
                elif current == self.before:
                    self.commit_state = "not_applied"
                    self.restored = True
                else:
                    self.commit_state = "ambiguous"
            raise
        self.commit_state = "applied"

    def restore(self) -> None:
        if self.restored:
            return
        if self.commit_state == "not_applied":
            self.restored = True
            return
        _validate_parent_guard(self.path, self.parent_guard, "owned launch file")
        _require_unshared_regular_or_missing(self.path, "owned launch file")
        if not _lexists(self.path) or self.path.read_bytes() != self.after:
            raise LaunchPreparationError(
                f"owned launch file changed externally; refusing overwrite: {self.path}")
        if self.before is None:
            _validate_parent_guard(self.path, self.parent_guard, "owned launch file")
            _require_unshared_regular_or_missing(self.path, "owned launch file")
            if not _lexists(self.path) or self.path.read_bytes() != self.after:
                raise LaunchPreparationError(
                    f"owned launch file changed externally; refusing unlink: {self.path}")
            self.path.unlink()
        else:
            _atomic_replace(
                self.path, self.before, self.after, self.parent_guard)
        self.restored = True


class _OwnedPreferences(_OwnedFile):
    def restore(self) -> None:
        if self.restored or self.commit_state == "not_applied":
            super().restore()
            return
        _validate_parent_guard(self.path, self.parent_guard, "owned preferences")
        _require_unshared_regular_or_missing(self.path, "owned preferences")
        if not _lexists(self.path):
            raise LaunchPreparationError("owned preferences disappeared during launch")
        current = self.path.read_bytes()
        if current == self.after:
            super().restore()
            return
        merged = _merge_verified_graphics(self.before, self.after, current)
        _atomic_replace(self.path, merged, current, self.parent_guard)
        self.restored = True


@dataclass
class _OwnedRegistry:
    operations: _Operations
    value: str
    value_type: int | None
    owned: bool
    restored: bool = False

    def restore(self) -> None:
        if self.restored or not self.owned:
            self.restored = True
            return
        exists, current, current_type = self.operations.registry_read()
        if not exists:
            self.restored = True
            return
        if current != self.value or current_type != self.value_type:
            raise LaunchPreparationError(
                "owned machine_fingerprint changed externally; refusing registry overwrite")
        self.operations.registry_delete()
        self.restored = True


@dataclass
class PreparedClient:
    argv: tuple[str, ...] = field(repr=False)
    cwd: Path
    env: dict[str, str] = field(repr=False)
    _files: list[_OwnedFile] = field(default_factory=list, repr=False)
    _registry: _OwnedRegistry | None = field(default=None, repr=False)
    _created_directories: list[_OwnedDirectory] = field(default_factory=list, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def rollback(self) -> None:
        if self._closed:
            return
        failures: list[str] = []
        if self._registry is not None:
            try:
                self._registry.restore()
            except Exception as exc:
                failures.append(str(exc))
        for owned in reversed(self._files):
            try:
                owned.restore()
            except Exception as exc:
                failures.append(str(exc))
        for owned_directory in reversed(self._created_directories):
            try:
                owned_directory.remove_if_empty()
            except Exception as exc:
                failures.append(str(exc))
        if failures:
            raise LaunchPreparationError("; ".join(failures))
        self._closed = True

    def close(self) -> None:
        self.rollback()

    def __enter__(self) -> "PreparedClient":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def _snapshot_owned_file(path: Path, after: bytes) -> _OwnedFile:
    parent_guard = _capture_parent_guard(path, "launch preparation target")
    _validate_parent_guard(path, parent_guard, "launch preparation target")
    _require_unshared_regular_or_missing(path, "launch preparation target")
    before = path.read_bytes() if _lexists(path) else None
    _validate_parent_guard(path, parent_guard, "launch preparation target")
    return _OwnedFile(
        path=path, before=before, after=after, parent_guard=parent_guard)


def prepare_authenticated_client(
    config: Config,
    plan: LaunchPlan,
    *,
    profile_scripts_dir: Path | None = None,
) -> PreparedClient:
    """Prepare one authenticated launch and return guarded rollback handles."""
    operations = _production_operations()
    prepared: PreparedClient | None = None
    try:
        client = _validate_config(config)
        token, native_user_id = _token_and_identity(config, plan, client)
        if operations.arena_running():
            raise LaunchPreparationError("Arena.exe is already running; refusing preparation")
        _validate_installed_artifacts(config, operations)

        prepared = PreparedClient(
            argv=tuple(plan.argv), cwd=client,
            env=sanitized_launch_environment(operations.environ),
        )
        scripts = _profile_scripts_path(config, profile_scripts_dir, operations)
        created = _create_directories(scripts)
        prepared._created_directories.extend(created)
        log_dir = client / "log"
        if _lexists(log_dir):
            if _is_reparse(log_dir) or not log_dir.is_dir():
                raise LaunchPreparationError("client log path is not a real directory")
            log_created: list[_OwnedDirectory] = []
        else:
            log_created = _create_directories(log_dir)
        prepared._created_directories.extend(log_created)

        monitor = operations.primary_monitor()
        template_path = _require_source_file(
            config.repo_root / "config" / "preferences.template.txt",
            "preferences template")
        template = template_path.read_text(encoding="utf-8")
        preference_path = scripts / "preferences.script.txt"
        user_script_path = scripts / "User.script.txt"
        preference_guard = _capture_parent_guard(
            preference_path, "Arena preferences parent")
        _validate_parent_guard(
            preference_path, preference_guard, "Arena preferences parent")
        _require_unshared_regular_or_missing(preference_path, "Arena preferences")
        current_preferences = preference_path.read_bytes() if _lexists(preference_path) else None
        _validate_parent_guard(
            preference_path, preference_guard, "Arena preferences parent")

        stack_bytes = _stack_config_bytes(config)
        user_script_bytes = b"\xff\xfe" + plan.user_script_text.encode("utf-16-le")
        preference_bytes = _build_preferences(
            current_preferences, template, monitor, token, native_user_id, plan.display_name)

        for owned in (
            _snapshot_owned_file(_safe_client_target(config, "stack_config.json"), stack_bytes),
            _snapshot_owned_file(user_script_path, user_script_bytes),
            _OwnedPreferences(path=preference_path, before=current_preferences,
                              after=preference_bytes, parent_guard=preference_guard),
        ):
            prepared._files.append(owned)
            owned.apply()

        exists, fingerprint, fingerprint_type = operations.registry_read()
        if exists:
            prepared._registry = _OwnedRegistry(
                operations, fingerprint or "", fingerprint_type, owned=False)
        else:
            generated = f"{uuid.getnode():012x}"
            prepared._registry = _OwnedRegistry(
                operations, generated, 1, owned=True)
            operations.registry_write(generated)
            confirmed, current, current_type = operations.registry_read()
            if not confirmed or current != generated or current_type != 1:
                raise LaunchPreparationError("machine_fingerprint write could not be verified")
        return prepared
    except Exception as exc:
        if prepared is not None:
            try:
                prepared.rollback()
            except Exception as rollback_exc:
                raise LaunchPreparationError(
                    f"launch preparation failed and rollback was incomplete: {rollback_exc}") from exc
        if isinstance(exc, LaunchPreparationError):
            raise
        raise LaunchPreparationError(f"launch preparation failed: {exc}") from exc


__all__ = [
    "LaunchPreparationError", "PreparedClient", "prepare_authenticated_client",
    "sanitized_launch_environment",
]
