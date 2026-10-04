"""Private child entry point for :func:`companion.launcher.start_bridge`.

This is intentionally not a user-facing CLI.  It waits for the parent to put
it into an owned OS lifetime container before it imports or starts any bridge
component.  Closing the control pipe asks the existing BridgeRuntime stop
event to perform its ordered shutdown.
"""
from __future__ import annotations

import json
import hashlib
import os
import re
import sys
import threading
from pathlib import Path

from .bridge_protocol import (
    MAX_CONTROL_LINE, PROTOCOL, ready_proof, valid_client_version,
)


class ChildProtocolError(RuntimeError):
    pass


def _read_command() -> dict:
    raw = sys.stdin.buffer.readline(MAX_CONTROL_LINE + 1)
    if not raw or len(raw) > MAX_CONTROL_LINE or not raw.endswith(b"\n"):
        raise ChildProtocolError("invalid_start_record")
    try:
        value = json.loads(raw)
    except (UnicodeError, ValueError):
        raise ChildProtocolError("invalid_start_record") from None
    if not isinstance(value, dict):
        raise ChildProtocolError("invalid_start_record")
    return value


def _write_record(stream, lock: threading.Lock, record: dict) -> None:
    encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(encoded) > MAX_CONTROL_LINE:
        raise ChildProtocolError("control_record_too_large")
    with lock:
        stream.write(encoded)
        stream.flush()


def _validated_start(command: dict) -> dict:
    expected = {
        "protocol", "command", "nonce", "mode", "ruleset", "api_base_url",
        "session_path", "run_dir", "relay_timeout", "private_mode",
        "private_ai_opponents",
        "internal_pvp_test",
        "client_version",
        "unit_control_capability",
    }
    if set(command) != expected or command.get("protocol") != PROTOCOL \
            or command.get("command") != "start":
        raise ChildProtocolError("invalid_start_record")
    nonce = command.get("nonce")
    if not isinstance(nonce, str) or len(nonce) != 64 \
            or any(char not in "0123456789abcdef" for char in nonce):
        raise ChildProtocolError("invalid_nonce")
    if command.get("mode") not in ("pve", "pvp"):
        raise ChildProtocolError("invalid_mode")
    if command.get("private_mode") != command.get("mode"):
        raise ChildProtocolError("invalid_private_mode")
    if type(command.get("internal_pvp_test")) is not bool:
        raise ChildProtocolError("invalid_internal_pvp_test")
    ai_opponents = command.get("private_ai_opponents")
    if (type(ai_opponents) is not int
            or (command["private_mode"] == "pvp" and ai_opponents != 0)
            or (command["private_mode"] == "pve"
                and not 1 <= ai_opponents <= 10)):
        raise ChildProtocolError("invalid_private_ai_opponents")
    if command.get("ruleset") not in ("territory", "annihilation"):
        raise ChildProtocolError("invalid_ruleset")
    if not isinstance(command.get("api_base_url"), str):
        raise ChildProtocolError("invalid_api_base_url")
    if not valid_client_version(command.get("client_version")):
        raise ChildProtocolError("invalid_client_version")
    capability = command.get("unit_control_capability")
    if (not isinstance(capability, str) or len(capability) != 64
            or any(char not in "0123456789abcdef" for char in capability)):
        raise ChildProtocolError("invalid_unit_control_capability")
    if not isinstance(command.get("session_path"), str) \
            or not isinstance(command.get("run_dir"), str):
        raise ChildProtocolError("invalid_paths")
    timeout = command.get("relay_timeout")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) \
            or not 0.1 <= float(timeout) <= 120.0:
        raise ChildProtocolError("invalid_relay_timeout")
    return command


def _preference_directory(run_dir: Path, api_base_url: str) -> Path:
    # Launcher runs have fresh nonces, but native acknowledgements must survive
    # those runs. Standalone callers remain inside their explicit run directory.
    state_root = (run_dir.parent.parent
                  if run_dir.parent.name == "bridge-runs"
                  and re.fullmatch(r"[0-9a-f]{64}", run_dir.name)
                  else run_dir)
    environment = hashlib.sha256(api_base_url.encode("utf-8")).hexdigest()
    return state_root / "native-preferences" / environment


def main() -> int:
    from .diagnostics import DiagnosticLog
    diagnostic = DiagnosticLog("bridge")
    diagnostic.install_exception_hooks()
    control_out = sys.stdout.buffer
    write_lock = threading.Lock()
    stop = threading.Event()
    try:
        command = _validated_start(_read_command())
        diagnostic.close()
        diagnostic = DiagnosticLog("bridge", state_dir=Path(command["session_path"]).parent)
        diagnostic.refresh_versions(client_version=command["client_version"])
        diagnostic.install_exception_hooks()
    except ChildProtocolError as error:
        diagnostic.event("operation_failed", "bridge_start", error=error, code="failed", crash=True)
        _write_record(control_out, write_lock, {
            "protocol": PROTOCOL, "event": "error", "error": str(error)})
        return 2

    def watch_parent() -> None:
        while True:
            raw = sys.stdin.buffer.readline(MAX_CONTROL_LINE + 1)
            if not raw:
                stop.set()
                return
            if len(raw) > MAX_CONTROL_LINE or not raw.endswith(b"\n"):
                stop.set()
                return
            try:
                record = json.loads(raw)
            except (UnicodeError, ValueError):
                stop.set()
                return
            if (not isinstance(record, dict) or record.get("protocol") != PROTOCOL
                    or record.get("command") != "stop"
                    or record.get("nonce") != command["nonce"]):
                stop.set()
                return
            stop.set()
            return

    threading.Thread(target=watch_parent, daemon=True,
                     name="bridge-parent-watch").start()
    original_stdout = sys.stdout
    try:
        # Reserve the captured stdout buffer for authenticated control records
        # before importing server modules that may emit startup diagnostics.
        sys.stdout = sys.stderr
        repo_root = Path(__file__).resolve().parents[1]
        server_dir = str(repo_root / "server")
        if server_dir not in sys.path:
            sys.path.insert(0, server_dir)
        from companion.api_client import normalize_api_base_url
        from native_career_history import career_storage_paths
        from native_identity import hash_session_token, read_session_token_file
        from companion_bridge import BridgeError, main as bridge_main

        run_dir = Path(command["run_dir"])
        if run_dir.name != command["nonce"]:
            raise BridgeError("career_run_nonce_mismatch")
        career_state_path, career_history_root = career_storage_paths(
            run_dir / "battle_state.sqlite3")
        if (career_history_root is None
                or career_history_root != run_dir.absolute().parent):
            raise BridgeError("invalid_career_run_root")
        session_path = Path(command["session_path"])
        api_base_url = normalize_api_base_url(command["api_base_url"])
        args = [
            "--mode", command["mode"], "--ruleset", command["ruleset"],
            "--economy-backend", "cloud", "--api-base-url", api_base_url,
            "--session-token-file", str(session_path),
            "--battle-state", str(run_dir / "battle_state.sqlite3"),
            "--economy-state", str(run_dir / "economy.json"),
            "--native-user-storage", str(_preference_directory(run_dir, api_base_url)),
            "--trace", str(run_dir / "http.jsonl"),
            "--relay-trace", str(run_dir / "relay.jsonl"),
            "--native-five-mode-selector",
            "--cloud-private-mode", command["private_mode"],
            "--cloud-private-ai-opponents", str(command["private_ai_opponents"]),
            "--client-version", command["client_version"],
        ]

        if command["internal_pvp_test"]:
            args.append("--internal-pvp-test")

        def lifecycle_ready(runtime, services) -> None:
            runtime.diagnostic = diagnostic
            if stop.is_set():
                raise BridgeError("bridge_parent_gone")
            relay = runtime.relay
            if relay is None or relay.target != "local":
                raise BridgeError("owned_local_relay_missing")
            relay.wait_ready(float(command["relay_timeout"]))
            if (services.get("xmpp_hub") is None
                    or services.get("region_ping") is None
                    or services.get("matchmaking") is None
                    or services.get("battle_state") is None
                    or not services.get("servers")):
                raise BridgeError("bridge_surface_not_ready")
            token, puid = read_session_token_file(
                session_path, expected_api_base_url=api_base_url)
            identity = runtime.resolver.identity
            runtime_client_version = getattr(runtime.private_client,
                                             "client_version", None)
            if runtime_client_version != command["client_version"]:
                raise BridgeError("bridge_client_version_changed")
            if (identity.puid != puid
                    or identity.session_token_hash != hash_session_token(token)):
                raise BridgeError("bridge_session_changed")
            expected_capability_digest = hashlib.sha256(
                command["unit_control_capability"].encode("ascii")
            ).hexdigest()
            if services.get("unit_control_capability_sha256") \
                    != expected_capability_digest:
                raise BridgeError("bridge_unit_control_binding_changed")
            payload = {
                "protocol": PROTOCOL,
                "event": "ready",
                "nonce": command["nonce"],
                "pid": os.getpid(),
                "mode": runtime.plan.mode,
                "ruleset": runtime.plan.ruleset,
                "private_mode": runtime.private_mode,
                "private_ai_opponents": runtime.private_ai_opponents,
                "internal_pvp_test": runtime.plan.internal_pvp_test,
                "puid": identity.puid,
                "native_user_id": identity.native_user_id,
                "display_name": identity.display_name,
                "api_base_url": api_base_url,
                "client_version": runtime_client_version,
                "unit_control_capability_sha256": expected_capability_digest,
                "surfaces": {
                    "http": list(runtime.plan.http_ports),
                    "xmpp": list(runtime.plan.xmpp_ports),
                    "region_udp": runtime.plan.region_ping_port,
                    "relay_tcp": runtime.plan.relay_port,
                },
            }
            payload["proof"] = ready_proof(token, payload)
            _write_record(control_out, write_lock, payload)

        if stop.is_set():
            return 1
        return int(bridge_main(
            args, lifecycle_stop=stop, lifecycle_ready=lifecycle_ready,
            unit_control_capability=command["unit_control_capability"],
            career_state_path=career_state_path,
            career_history_root=career_history_root,
        ) or 0)
    except BaseException as error:
        if not isinstance(error, (KeyboardInterrupt, SystemExit)):
            diagnostic.event("python_unhandled", "bridge_start", error=error, code="failed", crash=True)
        try:
            _write_record(control_out, write_lock, {
                "protocol": PROTOCOL, "event": "error",
                "nonce": command["nonce"], "error": "bridge_start_failed",
            })
        except (BrokenPipeError, OSError):
            pass
        return 1
    finally:
        sys.stdout = original_stdout
        diagnostic.close()


if __name__ == "__main__":
    raise SystemExit(main())
