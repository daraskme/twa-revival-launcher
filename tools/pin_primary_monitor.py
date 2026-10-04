"""Pin Arena to the Windows primary monitor only."""
from __future__ import annotations

import ctypes
import os
import re
from ctypes import wintypes
from pathlib import Path

user32 = ctypes.WinDLL("user32", use_last_error=True)

MONITORINFOF_PRIMARY = 1
SWP_NOZORDER = 0x0004
SWP_SHOWWINDOW = 0x0040


class RECT(ctypes.Structure):
    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


class MONITORINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("rcMonitor", RECT),
        ("rcWork", RECT),
        ("dwFlags", wintypes.DWORD),
    ]


MonitorEnumProc = ctypes.WINFUNCTYPE(
    ctypes.c_int, wintypes.HMONITOR, wintypes.HDC, ctypes.POINTER(RECT), wintypes.LPARAM
)


def primary_monitor() -> dict[str, int]:
    found: dict[str, int] = {}

    def callback(hmon: int, _hdc: int, _rect: object, _lp: int) -> int:
        info = MONITORINFO()
        info.cbSize = ctypes.sizeof(MONITORINFO)
        user32.GetMonitorInfoW(hmon, ctypes.byref(info))
        if info.dwFlags & MONITORINFOF_PRIMARY:
            box = info.rcMonitor
            found["x"] = box.left
            found["y"] = box.top
            found["w"] = box.right - box.left
            found["h"] = box.bottom - box.top
        return 1

    user32.EnumDisplayMonitors(0, None, MonitorEnumProc(callback), 0)
    if not found:
        raise RuntimeError("primary monitor not found")
    return found


def preferences_path() -> Path:
    return (
        Path(os.environ["APPDATA"])
        / "The Creative Assembly"
        / "Arena"
        / "scripts"
        / "preferences.script.txt"
    )


TEMPLATE = Path(__file__).resolve().parents[1] / "config" / "preferences.template.txt"


def set_pref_int(text: str, key: str, value: int) -> str:
    pattern = re.compile(rf"^{re.escape(key)}\s+-?\d+;(.*)$", re.M)
    repl = rf"{key} {value};\1"
    if pattern.search(text):
        return pattern.sub(repl, text, count=1)
    return f"{key} {value};\n" + text


def set_pref_bool(text: str, key: str, value: bool) -> str:
    word = "true" if value else "false"
    pattern = re.compile(rf"^{re.escape(key)}\s+\w+;(.*)$", re.M)
    repl = rf"{key} {word};\1"
    if pattern.search(text):
        return pattern.sub(repl, text, count=1)
    return f"{key} {word};\n" + text


def set_pref_string(text: str, key: str, value: str) -> str:
    pattern = re.compile(rf"^{re.escape(key)}\s+.+$", re.M)
    repl = f"{key} {value};"
    if pattern.search(text):
        return pattern.sub(repl, text, count=1)
    return f"{key} {value};\n" + text


def read_pref_text(path: Path) -> str:
    raw = path.read_bytes()
    if raw.startswith(b"\xff\xfe"):
        return raw.decode("utf-16-le").lstrip("\ufeff")
    if raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16-be").lstrip("\ufeff")
    if len(raw) > 3 and raw[1] == 0:
        return raw.decode("utf-16-le").lstrip("\ufeff")
    return raw.decode("utf-8", errors="replace").lstrip("\ufeff")


def write_pref_text(path: Path, text: str) -> None:
    path.write_text(text.replace("\r\n", "\n"), encoding="utf-16")


def prefs_are_corrupt(text: str) -> bool:
    if "\ufeff" in text:
        return True
    counts: dict[str, int] = {}
    for line in text.splitlines():
        key = line.split(" ", 1)[0].rstrip(";")
        if key:
            counts[key] = counts.get(key, 0) + 1
    return any(n > 1 for n in counts.values())


def pin_preferences(monitor: dict[str, int], auth_token: str = "revival-token",
                    display_name: str = "player") -> Path:
    path = preferences_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        text = read_pref_text(path)
    else:
        text = ""
    if TEMPLATE.is_file() and (
        (not text.strip()) or prefs_are_corrupt(text) or text.count("x_res") != 1
    ):
        text = TEMPLATE.read_text(encoding="utf-8")
    # Windowed 1600x900 was the last config that reached hangar (04:15-04:23).
    width = min(monitor["w"], 1600)
    height = min(monitor["h"], 900)
    text = set_pref_int(text, "x_res", width)
    text = set_pref_int(text, "y_res", height)
    text = set_pref_int(text, "x_pos", monitor["x"])
    text = set_pref_int(text, "y_pos", monitor["y"])
    text = set_pref_bool(text, "gfx_fullscreen", False)
    text = set_pref_bool(text, "fix_res", True)
    text = set_pref_bool(text, "fix_window_pos", True)
    text = set_pref_bool(text, "gfx_show_pre_launch_window", False)
    text = set_pref_bool(text, "write_preferences_at_exit", False)
    text = set_pref_bool(text, "FRONTEND_SCENE_ENABLED", True)
    text = set_pref_bool(text, "PERMANENTLY_SKIP_TUTORIAL", True)
    text = set_pref_bool(text, "show_frontend_movies", False)
    text = set_pref_string(text, "ONLINE_PLATFORM", "fake")
    # ``fake_auth_token`` must equal the ``+auth`` argument, and
    # ``display_name_override`` must equal the resolved native user id: the
    # final report's ``player_name`` is matched against it before settlement.
    text = set_pref_string(text, "fake_auth_token", auth_token)
    text = set_pref_string(text, "display_name_override", display_name)
    text = set_pref_string(text, "startup_frontend_scene", "frontend_1")
    write_pref_text(path, text)
    return path


def move_arena_windows(monitor: dict[str, int]) -> int:
    moved = 0

    def enum_cb(hwnd: int, _lp: int) -> int:
        if not user32.IsWindowVisible(hwnd):
            return 1
        length = user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        title = buf.value
        if "Arena" not in title and "Total War" not in title:
            return 1
        user32.SetWindowPos(
            hwnd,
            0,
            monitor["x"],
            monitor["y"],
            monitor["w"],
            monitor["h"],
            SWP_NOZORDER | SWP_SHOWWINDOW,
        )
        moved_holder[0] += 1
        return 1

    moved_holder = [0]
    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_int, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows(WNDENUMPROC(enum_cb), 0)
    moved = moved_holder[0]
    return moved


def apply(auth_token: str = "revival-token", display_name: str = "player") -> dict[str, int]:
    monitor = primary_monitor()
    pin_preferences(monitor, auth_token=auth_token, display_name=display_name)
    move_arena_windows(monitor)
    return monitor


def main() -> int:
    monitor = apply()
    print(
        f"primary {monitor['w']}x{monitor['h']} at {monitor['x']},{monitor['y']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
