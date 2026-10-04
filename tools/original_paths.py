"""Select a machine-specific original without changing its safety boundary."""
from __future__ import annotations

import socket
from pathlib import Path


def read_original_path(paths_ini: Path) -> Path:
    """Prefer original.<OS hostname>; preserve original as the default.

    A present but empty/duplicate selected entry is an error, never a fallback
    to another computer's original. Consumers retain their existing checks for
    absolute paths, real directories, aliases, and protected output boundaries.
    """
    hostname = socket.gethostname().casefold()
    host_key = 'original.' + hostname
    entries: dict[str, list[str]] = {'original': [], host_key: []}
    for line in paths_ini.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        key, separator, value = line.partition('=')
        key = key.strip().casefold()
        if separator and key in entries:
            entries[key].append(value.strip())
    values = entries[host_key] if entries[host_key] else entries['original']
    if len(values) != 1 or not values[0]:
        raise ValueError('paths.ini needs one non-empty original for this computer')
    return Path(values[0])
