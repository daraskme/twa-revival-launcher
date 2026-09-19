"""Maintenance-mode check against the Worker.

A maintenance window can surface two ways:

  * `/health` itself returns 503 with body {"error": "maintenance", ...} --
    companion/api_client.ApiClient raises MaintenanceError for that, exactly
    like it would for any other endpoint returning the same 503 shape (a
    maintenance window blocks every authenticated call, not just health).
  * `/health` returns 200 with a non-blocking `maintenance` object describing
    an announced-but-not-yet-enforced window (`enabled` may be False here).

Callers elsewhere in companion (companion/__main__.py) should catch
MaintenanceError from *any* API call the same way they would from health --
status_from_error() below builds the same MaintenanceStatus either way, so
the display path is one function regardless of which call surfaced it.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .api_client import ApiClient, MaintenanceError


@dataclass(frozen=True)
class MaintenanceStatus:
    enabled: bool
    message: str
    ends_at: int | None


def status_from_error(exc: MaintenanceError) -> MaintenanceStatus:
    return MaintenanceStatus(enabled=True, message=exc.message, ends_at=exc.ends_at)


def check_maintenance(api: ApiClient) -> MaintenanceStatus:
    try:
        body: Any = api.health()
    except MaintenanceError as exc:
        return status_from_error(exc)
    info = body.get("maintenance") if isinstance(body, dict) else None
    if isinstance(info, dict):
        return MaintenanceStatus(
            enabled=bool(info.get("enabled", False)),
            message=str(info.get("message", "")),
            ends_at=info.get("endsAt"),
        )
    return MaintenanceStatus(enabled=False, message="", ends_at=None)


def format_notice(status: MaintenanceStatus) -> str:
    """Japanese-language notice for display to the player."""
    if not status.enabled:
        return "現在メンテナンス中ではありません。"
    lines = ["現在メンテナンス中です。しばらくお待ちください。"]
    if status.message:
        lines.append(status.message)
    if status.ends_at:
        try:
            local_end = datetime.fromtimestamp(status.ends_at).astimezone()
            lines.append(f"終了予定: {local_end:%Y-%m-%d %H:%M:%S %Z}")
        except (OSError, OverflowError, ValueError):
            lines.append(f"終了予定（UNIX秒）: {status.ends_at}")
    return "\n".join(lines)
