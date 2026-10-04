"""EOS (Epic Online Services) companion login prototype.

Scope of this package: obtain an EOS **Connect ID token** for the local
player's Epic Games account, so the launcher-style companion process can
send it to the Cloudflare Worker's ``POST /v1/auth/eos`` (see
``private-server/src/eos.ts`` and ``docs/EOS_CLOUDFLARE_ARCHITECTURE.md``).

Modules:
    bindings  -- ctypes struct/function declarations for the EOS SDK
                 (Platform + Auth + Connect interfaces). No network calls,
                 no DLL loaded at import time.
    session   -- EosSession (real DLL backend) and FakeEosBackend (no DLL,
                 no network -- used by tests and ``--fake`` CLI runs).
    login     -- CLI entry point: ``python -m companion.eos.login``.

Full research notes, what is verified vs UNVERIFIED, and the manual test
plan (Dev Auth Tool) live in ``docs/eos_companion_20260902.md``.

This package intentionally owns only ``companion/eos/*``. It does not
import or modify anything else under ``companion/`` (that belongs to a
different, concurrently-running work thread -- see that package's
``__init__.py`` docstring).
"""
from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.0.1-prototype"
