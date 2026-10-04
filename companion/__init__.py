"""Player-side EOS/Cloudflare companion.

Owns: update distribution (manifest verification + atomic apply/rollback),
maintenance gating, the Cloudflare Worker session/API client, and a safe
Arena.exe launch plan. ``python -m companion serve`` delegates to the current
loopback bridge. The launch-plan helper still does not start that bridge or
prepare every local Arena setting automatically. EOS is imported lazily so
status and update commands do not require an SDK DLL.

See docs/STATUS.md for current completion status.
"""
from __future__ import annotations

from pathlib import Path

__all__ = ["__version__"]


def _read_version() -> str:
    try:
        return (Path(__file__).resolve().parent / "VERSION").read_text(encoding="utf-8").strip() or "0.0.0"
    except OSError:
        return "0.0.0"


__version__ = _read_version()
