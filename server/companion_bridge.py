"""One-command companion bridge for standard PvE / PvP (territory / annihilation).

    python -m server.companion_bridge --mode pve --ruleset territory \
        --economy-backend cloud --api-base-url http://127.0.0.1:8787 \
        --session-token-file <run>\\session.json \
        --battle-state <run>\\battle_state.sqlite3 --trace <run>\\http.jsonl

``--mode pvp`` keeps the same loopback service set but the battle is fixed by
the Cloudflare Worker: ``native_pvp_coordinator.PvpCoordinator`` joins the
Worker queue when the game sends ``/v8/matchmake`` (pvp), claims the
assignment, exchanges squads, takes the relay ticket and binds the frozen
20-seat roster into ``NativeMatchmaking``; the relay is then the BattleRelay
Durable Object, reached through ``native_relay_ws_bridge`` on loopback 19000
(``RelaySupervisor`` target ``durable_object``).  Settlement goes through
``CloudSettlementAuthority`` with the Worker's frozen policy. New standard
battles use ``public-zero-reward-v3``; older policies are retained for already
registered battles. The cloud PvE path uses the same coordinator and relay
with all human participants assigned to one team.

What it replaces
----------------
The original 2026-09-02 standard PvE prototype needed two manual processes and
``Invoke-RestMethod`` (docs/archive/pve_e2e_audit_20260902.md phase E2 and
"Companion 化にあたって追加で必要なもの").  This entry point starts exactly the
standard-PvE service set --- the equivalent of
``--xmpp --matchmaking --pve-battle-probe --local-region --battle-mode <preset>``
--- pins the ruleset, supervises the relay, and fires the matchmaking announce
by itself inside the native admission window, which includes the maximum
300 s public player collection and a bounded roster/connection grace period.

Process layout (and why)
------------------------
HTTP/TLS + XMPP + region ping + matchmaking run **in this process**: the
identity resolver, the economy backend and the settlement authority are live
Python objects and cannot be handed to a child over a command line.

The relay runs as a supervised child process: ``native_relay_ws_bridge`` for
cloud battles, or ``native_battle_probe`` for the standalone local probe.

* it owns a separate asyncio event loop so relay work does not run in the
  hangar HTTP event loop,
* the local probe's diagnostic session/idle caps are not public battle rules,
* the child can be restarted between battles without dropping the game's HTTP
  session, and a supervisor restart is observable in the trace.

Nothing here launches, stops or patches ``Arena.exe``.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    # Sibling modules are imported flat (``import local_stack``) so this file
    # works both as ``python -m server.companion_bridge`` and as a script.
    sys.path.insert(0, str(_HERE))
_REPO_ROOT = _HERE.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.append(str(_REPO_ROOT))

from companion.loopback_ports import annotate_bind_error, parse_bind_failure_code
import local_stack as offline  # noqa: E402
import native_connection_probe as probe  # noqa: E402
from battle_api import (  # noqa: E402
    BattleApiError, CloudSettlementAuthority, battle_api_from_api_client,
)
from economy_backend import (  # noqa: E402
    BackendError, FileEconomyBackend, build_api_client,
    cloud_backend_from_api_client,
)
from native_identity import (  # noqa: E402
    IdentityError, IdentityResolver, StaticIdentityResolver,
    read_session_token_file,
)
from native_auto_announcer import (  # noqa: E402
    ANNOUNCE_DEADLINE_SECONDS, ANNOUNCE_POLL_SECONDS, QUEUE_SECONDS,
    AnnounceResult, AutoAnnouncer as _SharedAutoAnnouncer,
)
from native_pvp_coordinator import (  # noqa: E402
    DurableObjectRelayRunner, PvpCoordinator, PvpCoordinatorError, WorkerPvpApi,
    pvp_battle_credentials as _pvp_battle_credentials,
)
from native_private_runtime import NativePrivateRuntime  # noqa: E402
from native_party_selection_binding import PartySelectionBinding  # noqa: E402
from native_private_notifier import NativePrivateXmppNotifier  # noqa: E402

DEFAULT_HTTP_PORTS = (18765, 443)
MODES = ("pve", "pvp")
RELAY_TARGETS = ("local", "durable_object", "switchable")
XMPP_PORTS = (5222, 5223)
REGION_PING_PORT = 19063
RELAY_PORT = 19000
DEFAULT_FIXTURES = _REPO_ROOT / "catalog" / "native_matchmaking.json"
DEFAULT_CLIENT_VERSION = "0.0.0-companion-bridge"
USER_STORAGE_HOST = f"{offline.STACK['stack']}-user-storage.{offline.STACK['domain']}"
RULESETS = ("territory", "annihilation")


class BridgeError(RuntimeError):
    """A configuration failure that must stop before anything binds."""


# ---------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BridgePlan:
    """Everything the bridge will do, computable without binding a socket."""

    mode: str
    ruleset: str
    battle_mode_preset: str
    native_user_id: str
    economy_backend: str
    api_base_url: str | None
    http_ports: tuple[int, ...]
    xmpp_ports: tuple[int, ...]
    region_ping_port: int
    relay_port: int
    battle_state: str
    economy_state: str
    trace: str
    fixtures: str
    relay_argv: tuple[str, ...]
    probe_argv: tuple[str, ...]
    native_five_mode_selector: bool
    user_storage_host: str
    user_storage_loopback: bool
    announce_deadline_seconds: float
    relay_supervised: bool
    # The client must be launched with these; the token itself is never printed.
    launch_display_name: str
    launch_auth_token_source: str
    # ``local``: the PvE CA command relay child (native_battle_probe).
    # ``durable_object``: native_relay_ws_bridge -> BattleRelay DO (PvP).
    relay_target: str = "local"
    # Explicit staging CLI opt-in; authentication and Worker gates still apply.
    internal_pvp_test: bool = False

    @property
    def public_dual_mode(self) -> bool:
        """Whether one cloud process serves both ordinary PvE and PvP."""
        return (self.native_five_mode_selector
                and self.economy_backend == "cloud")

    def as_dict(self) -> dict:
        # Never includes the session token or the PUID-bearing token file body.
        return {
            "event": "companion_bridge_plan",
            "internal_pvp_test": self.internal_pvp_test,
            "mode": self.mode,
            "ruleset": self.ruleset,
            "battle_mode_preset": self.battle_mode_preset,
            "native_user_id": self.native_user_id,
            "economy_backend": self.economy_backend,
            "api_base_url": self.api_base_url,
            "http_ports": list(self.http_ports),
            "xmpp_ports": list(self.xmpp_ports),
            "region_ping_port": self.region_ping_port,
            "relay_port": self.relay_port,
            "relay_target": self.relay_target,
            "relay_supervised": self.relay_supervised,
            "battle_state": self.battle_state,
            "economy_state": self.economy_state,
            "trace": self.trace,
            "fixtures": self.fixtures,
            "probe_argv": list(self.probe_argv),
            "relay_argv": list(self.relay_argv),
            "native_five_mode_selector": self.native_five_mode_selector,
            "user_storage_host": self.user_storage_host,
            "user_storage_loopback": self.user_storage_loopback,
            "announce_deadline_seconds": self.announce_deadline_seconds,
            "launch_display_name": self.launch_display_name,
            "launch_auth_token_source": self.launch_auth_token_source,
        }


def loopback_resolves(host: str) -> bool:
    """Audit 2-9-1: the S3-style user-storage host must reach this process.

    ``*.localhost`` already resolves to loopback on this machine, so the bridge
    verifies rather than edits the hosts file: silently rewriting a system file
    is never an acceptable side effect of starting a game session.
    """
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    addresses = {info[4][0] for info in infos}
    return bool(addresses) and all(
        address in ("127.0.0.1", "::1") or address.startswith("127.")
        for address in addresses)


def build_plan(args: argparse.Namespace, native_user_id: str) -> BridgePlan:
    public_pvp_only = args.native_five_mode_selector and args.economy_backend == "cloud"
    mode = 'pvp' if public_pvp_only else args.mode
    preset = f"{args.ruleset}-{mode}"
    if preset not in probe.BATTLE_MODE_PRESETS:
        raise BridgeError(f"unsupported battle mode preset {preset}")
    battle_state = str(Path(args.battle_state).resolve())
    economy_state = str(Path(args.economy_state).resolve())
    trace = str(Path(args.trace).resolve())
    fixtures = str(Path(args.fixtures).resolve())
    probe_args = [
        "--fixtures", fixtures,
        "--trace", trace,
        "--ports", *[str(port) for port in args.ports],
        "--xmpp", "--matchmaking", "--pve-battle-probe", "--local-region",
        "--battle-mode", preset,
        "--battle-state", battle_state,
        "--economy-state", economy_state,
    ]
    if args.native_user_storage is not None:
        probe_args.extend(("--native-user-storage", str(args.native_user_storage.absolute())))
    if args.native_five_mode_selector:
        probe_args.append("--native-five-mode-selector")
    probe_argv = tuple(probe_args)
    public_dual_mode = (args.native_five_mode_selector
                        and args.economy_backend == "cloud")
    relay_target = ("switchable" if public_dual_mode else
                    "durable_object" if args.mode == "pvp" else "local")
    relay_argv: tuple[str, ...] = ()
    if relay_target in ("local", "switchable"):
        relay_argv = (
            sys.executable, "-u", str(_HERE / "native_battle_probe.py"),
            "--enable-join-payload-echo", "--enable-natural-ticks", "--enable-reconnect",
            "--battle-state", battle_state,
            "--trace", str(Path(args.relay_trace).resolve()),
        )
    return BridgePlan(
        mode=mode,
        ruleset=args.ruleset,
        battle_mode_preset=preset,
        native_user_id=native_user_id,
        economy_backend=args.economy_backend,
        api_base_url=args.api_base_url,
        http_ports=tuple(args.ports),
        xmpp_ports=XMPP_PORTS,
        region_ping_port=REGION_PING_PORT,
        relay_port=RELAY_PORT,
        battle_state=battle_state,
        economy_state=economy_state,
        trace=trace,
        fixtures=fixtures,
        relay_argv=relay_argv,
        probe_argv=probe_argv,
        native_five_mode_selector=args.native_five_mode_selector,
        user_storage_host=USER_STORAGE_HOST,
        user_storage_loopback=loopback_resolves(USER_STORAGE_HOST),
        announce_deadline_seconds=float(args.announce_deadline),
        relay_supervised=not args.no_relay,
        # ``resolve_native_final_outcome`` matches the final report's
        # ``player_name`` against the resolved native user id, so the client's
        # ``display_name_override`` has to be exactly this value or no battle
        # can settle.  ``fake_auth_token`` / ``+auth`` must be the token in the
        # session file; it is deliberately never echoed here.
        launch_display_name=native_user_id,
        launch_auth_token_source=("session_token_file"
                                  if args.session_token_file is not None
                                  else "f2p_fake.TOKEN"),
        relay_target=relay_target,
        internal_pvp_test=args.internal_pvp_test,
    )


def verify_selector_installation(enabled: bool) -> dict[str, object]:
    """Apply the installer's shared, read-only five-artifact launch gate."""
    try:
        from tools.install_native_battle_modes import (
            InstallError as NativeModeInstallError,
            check_selector_installation,
        )
    except ImportError as exc:
        raise BridgeError("native five-mode installation verifier is unavailable") from exc
    try:
        return check_selector_installation(enabled, repo_root=_REPO_ROOT)
    except NativeModeInstallError as exc:
        raise BridgeError(f"native five-mode installation refused: {exc}") from exc


# ---------------------------------------------------------------------------
# automatic matchmaking announce
# ---------------------------------------------------------------------------

def _current_profile() -> dict:
    """The same source ``/native-probe/matchmaking-start`` reads."""
    profile, _ = offline.PROFILE_STATE.respond()
    return profile["profile"]


class AutoAnnouncer(_SharedAutoAnnouncer):
    """Compatibility wrapper using the bridge's authoritative profile source."""

    def __init__(self, matchmaking, xmpp_hub, **kwargs) -> None:
        kwargs.setdefault("profile_source", _current_profile)
        super().__init__(matchmaking, xmpp_hub, **kwargs)


# ---------------------------------------------------------------------------
# relay supervision
# ---------------------------------------------------------------------------

class RelaySupervisor:
    """Keep the battle relay alive for the current mode.

    ``target="local"`` (PvE) supervises the CA command relay as a separate
    child process (``native_battle_probe``).  ``target="durable_object"``
    (PvP) runs ``native_relay_ws_bridge`` in-process through a
    :class:`native_pvp_coordinator.DurableObjectRelayRunner`: the game still
    connects to loopback 19000, the bridge forwards to the BattleRelay
    Durable Object with the seat's (renewable) relay ticket.
    """

    def __init__(self, argv=(), *, target: str = "local", runner=None,
                 trace=None, restart_delay: float = 2.0,
                 max_restarts: int = 20, spawn=None,
                 port: int = RELAY_PORT) -> None:
        if target not in RELAY_TARGETS:
            raise ValueError(f"unsupported relay target {target}")
        if target == "durable_object" and runner is None:
            raise ValueError("durable_object relay needs a runner")
        self._target = target
        self._runner = runner
        self._argv = list(argv)
        self._trace = trace
        self._restart_delay = restart_delay
        self._max_restarts = max_restarts
        self._spawn = spawn or self._default_spawn
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._process_lock = threading.RLock()
        self._ready = threading.Event()
        self._failed = threading.Event()
        self._output_drained = threading.Event()
        self._bind_failure: OSError | None = None
        self._generation = 0
        self._ready_generation = -1
        self.process = None
        self.restarts = 0
        self.port: int | None = None if target == "durable_object" else port

    @property
    def target(self) -> str:
        return self._target

    @staticmethod
    def _default_spawn(argv):  # pragma: no cover - exercised only live
        return subprocess.Popen(argv, cwd=str(_HERE),
                                env={**os.environ, "PYTHONUNBUFFERED": "1"},
                                # The parent watcher owns the bridge control
                                # pipe. Inheriting its pending read can block
                                # Python startup on Windows; the relay has no
                                # stdin protocol of its own.
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL,
                                text=True, encoding="utf-8", errors="replace",
                                bufsize=1)

    def _drain_process_output(self, process, generation: int) -> None:
        """Consume the exact relay child's output and capture its bind ACK."""
        stream = getattr(process, "stdout", None)
        if stream is None:
            self._output_drained.set()
            return
        try:
            for line in stream:
                # The real ready record includes relay capabilities (~570 chars).
                # Keep a bounded limit without dropping that startup acknowledgement.
                if len(line) > 4096:
                    continue
                try:
                    row = json.loads(line)
                except (TypeError, ValueError):
                    continue
                if not isinstance(row, dict):
                    continue
                if (row.get("event") == "ready"
                        and row.get("host") == "127.0.0.1"
                        and row.get("port") == self.port):
                    with self._process_lock:
                        if self.process is process and self._generation == generation:
                            self._ready_generation = generation
                            self._ready.set()
                elif (row.get('event') == 'bind_error'
                      and set(row) == {'time', 'event', 'host', 'port', 'code'}
                      and row.get('host') == '127.0.0.1'
                      and type(row.get('port')) is int
                      and row['port'] == self.port):
                    details = parse_bind_failure_code(row.get('code'))
                    if (details is None or details['bind_transport'] != 'tcp'
                            or details['bind_family'] != 'ipv4'
                            or details['bind_port'] != self.port):
                        continue
                    error = OSError('owned local relay listener unavailable')
                    annotate_bind_error(error, transport='tcp', family='ipv4', port=self.port)
                    if details['windows_error'] is not None:
                        error.winerror = details['windows_error']
                    with self._process_lock:
                        if self.process is process and self._generation == generation:
                            self._bind_failure = error
                            self._failed.set()
        finally:
            with self._process_lock:
                if self.process is process and self._generation == generation:
                    self._output_drained.set()
            try:
                stream.close()
            except OSError:
                pass

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                process = self._spawn(self._argv)
                with self._process_lock:
                    self._generation += 1
                    generation = self._generation
                    self._ready.clear()
                    self._output_drained.clear()
                    self._bind_failure = None
                    self.process = process
            except OSError as error:
                self._emit("companion_relay_spawn_failed", reason=type(error).__name__)
                self._failed.set()
                return
            output_thread = threading.Thread(
                target=self._drain_process_output, args=(process, generation), daemon=True,
                name="companion-relay-output")
            output_thread.start()
            if self._stop.is_set():
                self._terminate_owned(process)
                return
            self._emit("companion_relay_started", restarts=self.restarts)
            while not self._stop.is_set():
                if process.poll() is not None:
                    break
                self._stop.wait(0.25)
            if self._stop.is_set():
                return
            output_thread.join(timeout=1.0)
            if self._failed.is_set():
                return
            self.restarts += 1
            self._emit("companion_relay_exited", restarts=self.restarts,
                       returncode=process.returncode)
            if self.restarts > self._max_restarts:
                self._emit("companion_relay_gave_up", restarts=self.restarts)
                self._failed.set()
                return
            self._stop.wait(self._restart_delay)

    def start(self) -> None:
        if self._target == "durable_object":
            # Raises PvpCoordinatorError when loopback 19000 cannot bind; the
            # coordinator traces it and the queue stays bound so the operator
            # sees the failure instead of a silent local relay.
            self.port = self._runner.start()
            self._emit("companion_relay_started", target=self._target, port=self.port)
            return
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="companion-relay")
        self._thread.start()

    def wait_ready(self, timeout: float) -> None:
        """Wait for this supervisor's exact child to report its owned bind."""
        if self._target == "durable_object":
            if self.port is None:
                raise BridgeError("relay_not_ready")
            return
        deadline = time.monotonic() + timeout
        stable_since = None
        stable_generation = None
        while True:
            with self._process_lock:
                process = self.process
                generation = self._generation
                ready = (self._ready.is_set()
                         and self._ready_generation == generation)
            exited = process is not None and process.poll() is not None
            if exited and not self._failed.is_set():
                self._output_drained.wait(min(0.5, max(0.0, deadline - time.monotonic())))
            if self._failed.is_set() or exited:
                with self._process_lock:
                    bind_failure = self._bind_failure
                if bind_failure is not None:
                    raise bind_failure
                raise BridgeError("local_relay_start_failed")
            if ready:
                if stable_generation != generation:
                    stable_generation = generation
                    stable_since = time.monotonic()
                elif time.monotonic() - stable_since >= 0.1:
                    with self._process_lock:
                        if (self.process is process
                                and self._generation == generation
                                and self._ready_generation == generation
                                and process.poll() is None):
                            return
                    stable_since = None
                    stable_generation = None
            else:
                stable_since = None
                stable_generation = None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BridgeError("local_relay_start_timeout")
            if ready:
                time.sleep(min(0.01, remaining))
            else:
                self._ready.wait(min(0.05, remaining))

    def stop(self) -> None:
        self._stop.set()
        if self._target == "durable_object":
            self._runner.stop()
            self._emit("companion_relay_stopped", target=self._target)
            return
        with self._process_lock:
            process = self.process
        if process is not None:
            self._terminate_owned(process)
        thread = self._thread
        if thread is not None:
            thread.join(timeout=5.0)
            if thread.is_alive():
                raise BridgeError("relay_supervisor_stop_timeout")
        # A spawn may have completed while stop was joining. Re-read the exact
        # owned handle; never search for or terminate an unrelated process.
        with self._process_lock:
            late_process = self.process
        if late_process is not None:
            self._terminate_owned(late_process)

    def _terminate_owned(self, process) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            kill = getattr(process, "kill", None)
            if not callable(kill):
                raise BridgeError("relay_process_stop_unconfirmed") from None
            kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                raise BridgeError("relay_process_stop_unconfirmed") from None
        if process.poll() is None:
            raise BridgeError("relay_process_stop_unconfirmed")

    def _emit(self, event: str, **fields) -> None:
        if self._trace is None:
            return
        try:
            self._trace({"event": event, **fields})
        except Exception:  # pragma: no cover
            pass


# ---------------------------------------------------------------------------
# composition
# ---------------------------------------------------------------------------

@dataclass
class BridgeRuntime:
    """The live objects the bridge injected, for tests and for shutdown."""

    plan: BridgePlan
    resolver: object
    economy_backend: object | None = None
    settlement_authority: object | None = None
    announcer: AutoAnnouncer | None = None
    relay: RelaySupervisor | None = None
    pvp_api: WorkerPvpApi | None = None
    pvp: PvpCoordinator | None = None
    stop: threading.Event = field(default_factory=threading.Event)
    relay_lock: threading.RLock = field(default_factory=threading.RLock)
    relay_battle_id: str | None = None
    relay_owner: object | None = None
    social: object | None = None
    social_party: object | None = None
    party_selection: PartySelectionBinding | None = None
    party_admission: object | None = None
    party_play: object | None = None
    recent_projection: object | None = None
    recent_storage: object | None = None
    private_client: object | None = None
    private: NativePrivateRuntime | None = None
    private_thread: threading.Thread | None = None
    private_mode: str | None = None
    private_ai_opponents: int = 0
    private_stop_timeout: float = 17.0


def build_identity_resolver(args: argparse.Namespace):
    """Resolve the ``+auth`` session this process will accept.

    Without a token file the bridge keeps the legacy lab identity so the
    existing loopback workflow (``+auth revival-token``) still works.
    """
    if args.session_token_file is None:
        return StaticIdentityResolver(), None
    try:
        expected_api_base_url = (args.api_base_url
                                 if args.economy_backend == "cloud"
                                 or args.mode == "pvp" else None)
        token, puid = read_session_token_file(
            args.session_token_file,
            expected_api_base_url=expected_api_base_url)
    except IdentityError as error:
        raise BridgeError(f"session token file rejected: {error.code}") from None
    display_name = None
    if args.economy_backend == "cloud" and not args.dry_run:
        from companion.player_name import account_display_name
        client = build_api_client(args.api_base_url, token,
                                  args.client_version, timeout=args.api_timeout)
        display_name = account_display_name(client, puid)
    resolver = IdentityResolver()
    resolver.register(token, puid, display_name=display_name)
    return resolver, token


def build_backends(args: argparse.Namespace, session_token: str | None):
    """Return ``(economy_backend, settlement_authority)`` for this run."""
    if args.economy_backend == "file":
        # ``None`` keeps native_connection_probe's historical file path and its
        # one-shot legacy progression migration.
        return None, None
    if not args.api_base_url:
        raise BridgeError("--economy-backend cloud requires --api-base-url")
    if session_token is None:
        raise BridgeError("--economy-backend cloud requires --session-token-file")
    try:
        client = build_api_client(args.api_base_url, session_token,
                                  args.client_version, timeout=args.api_timeout)
        backend = cloud_backend_from_api_client(client)
        battle_api = battle_api_from_api_client(client)
    except (BackendError, BattleApiError) as error:
        raise BridgeError(f"cloud backend unavailable: {error.code}") from None
    authority = CloudSettlementAuthority(battle_api, trace=probe.ProbeHandler._trace)
    return backend, authority


def build_career_cloud_factory(args: argparse.Namespace, session_token: str | None,
                               resolver):
    """Bind the reader to this authenticated identity and API environment.

    Each poll gets a fresh deadline. Reusing a client with a construction-time
    total deadline would make every later background poll expire immediately.
    """
    if args.economy_backend != "cloud":
        return None
    if session_token is None:
        raise BridgeError("cloud career requires an authenticated session")
    from companion.api_client import ApiClient, normalize_api_base_url
    from native_cloud_career import CloudCareerCache, cloud_career_cache_path
    from native_identity import hash_session_token
    identity = resolver.identity
    if hash_session_token(session_token) != identity.session_token_hash:
        raise BridgeError("cloud career session identity mismatch")
    origin = normalize_api_base_url(args.api_base_url)

    def fetch_summary():
        client = ApiClient(origin, client_version=args.client_version,
                           session_token=session_token, timeout=1.0,
                           total_timeout=3.0)
        return client.get_career()

    def create(state_path, native_catalog, trace):
        return CloudCareerCache(
            cloud_career_cache_path(state_path, origin, identity.puid),
            api_origin=origin, account_id=identity.puid,
            native_user_id=identity.native_user_id,
            native_catalog=native_catalog, fetch_summary=fetch_summary,
            trace=trace)
    return create


def build_pvp_api(args: argparse.Namespace, session_token: str | None) -> WorkerPvpApi | None:
    """The Worker matchmaking/battle client the PvP coordinator drives."""
    public_dual_mode = (args.native_five_mode_selector
                        and args.economy_backend == "cloud")
    if args.mode != "pvp" and not public_dual_mode:
        return None
    if not args.api_base_url or session_token is None:
        raise BridgeError("--mode pvp requires --api-base-url and --session-token-file")
    try:
        client = build_api_client(args.api_base_url, session_token,
                                  args.client_version, timeout=args.api_timeout)
        return WorkerPvpApi(client)
    except (BackendError, PvpCoordinatorError) as error:
        raise BridgeError(f"worker pvp api unavailable: {error.code}") from None


def build_private_client(args: argparse.Namespace, session_token: str | None):
    if args.cloud_private_mode is None:
        return None
    if not args.api_base_url or session_token is None:
        raise BridgeError("cloud private requires --api-base-url and --session-token-file")
    try:
        return build_api_client(args.api_base_url, session_token,
                                args.client_version, timeout=args.api_timeout)
    except BackendError as error:
        raise BridgeError(f"cloud private api unavailable: {error.code}") from None


def _on_ready(runtime: BridgeRuntime, trace):
    def start_local_relay() -> None:
        with runtime.relay_lock:
            if (not runtime.plan.relay_supervised or runtime.stop.is_set()
                    or runtime.relay is not None):
                return
            relay = RelaySupervisor(runtime.plan.relay_argv, trace=trace)
            relay.start()
            runtime.relay = relay

    def start_durable_object_relay(prepared, ticket_source) -> None:
        matchmaking = getattr(runtime.pvp, "_matchmaking", None)
        lab = getattr(matchmaking, "lab_state", {})
        mode = getattr(prepared, "mode", "pvp")
        if (not isinstance(lab, dict) or mode not in ("pve", "pvp")
                or lab.get("game_mode") != mode
                or (mode == "pve" and lab.get("cloud_matchmaking") is not True)
                or lab.get("queue_state") not in
                ("matching", "queued", "battle_ready", "notification_uncertain")):
            raise PvpCoordinatorError("pvp_relay_handoff_without_active_queue")
        battle_id = getattr(prepared, "battle_id", None)
        if not isinstance(battle_id, str) or not battle_id:
            raise PvpCoordinatorError("invalid_pvp_relay_lease")
        with runtime.relay_lock:
            if runtime.stop.is_set():
                raise PvpCoordinatorError("bridge_shutting_down")
            if runtime.relay_battle_id == battle_id:
                return
            if runtime.relay_battle_id is not None or runtime.relay_owner is not None:
                raise PvpCoordinatorError("pvp_relay_lease_conflict")
            if runtime.relay is not None:
                runtime.relay.stop()
                runtime.relay = None
            try:
                runner = DurableObjectRelayRunner(
                    prepared.relay_url, ticket_source, port=runtime.plan.relay_port,
                    trace=trace,
                    on_relay_event=runtime.pvp.on_relay_event)
                relay = RelaySupervisor(target="durable_object", runner=runner,
                                        trace=trace)
                runtime.relay = relay
                relay.start()
                runtime.relay_battle_id = battle_id
                runtime.relay_owner = prepared
                if getattr(runtime, "diagnostic", None) is not None:
                    runtime.diagnostic.bind_battle(battle_id)
            except Exception:
                partial = runtime.relay
                if partial is not None:
                    try:
                        partial.stop()
                    except Exception:
                        # Retain the exact owner reference. Starting the local
                        # relay while this listener may bind late would create
                        # two owners for port 19000.
                        raise BridgeError("durable_relay_cleanup_unconfirmed") from None
                runtime.relay = None
                runtime.relay_battle_id = None
                runtime.relay_owner = None
                start_local_relay()
                raise

    def stop_durable_object_relay(prepared, _reason) -> None:
        battle_id = getattr(prepared, "battle_id", None)
        with runtime.relay_lock:
            if battle_id is None or battle_id != runtime.relay_battle_id:
                return
            if (runtime.relay is not None
                    and runtime.relay.target == "durable_object"):
                runtime.relay.stop()
                runtime.relay = None
            runtime.relay_battle_id = None
            runtime.relay_owner = None
            if runtime.plan.public_dual_mode:
                start_local_relay()

    def ready(services: dict) -> None:
        matchmaking = services.get("matchmaking")
        xmpp_hub = services.get("xmpp_hub")
        publish_social = getattr(xmpp_hub, "publish_social", None)
        if (runtime.plan.economy_backend == "cloud" and callable(publish_social)
                and runtime.pvp_api is not None):
            from native_social import NativeSocial
            client = getattr(runtime.pvp_api, '_client', None)
            if client is not None:
                runtime.social = NativeSocial(client, runtime.plan.native_user_id, trace=trace)
                xmpp_hub.social = runtime.social
                from native_identity import derive_native_user_id
                from native_social_party import NativeSocialParty
                from native_social_party_runtime import NativePartyController
                identity = probe.ProbeHandler.identity_resolver.identity
                selection_binding = PartySelectionBinding(
                    identity=identity, economy_service=services.get("economy_service"),
                    api=runtime.pvp_api, social=runtime.social, matchmaking=matchmaking,
                    stop=runtime.stop, private_source=lambda: runtime.private, trace=trace)
                runtime.party_selection = selection_binding
                from native_party_admission import NativePartyAdmission
                runtime.party_admission = NativePartyAdmission(
                    selection_binding.public_api, social=runtime.social,
                    identity=identity, binding=selection_binding, matchmaking=matchmaking,
                    profile_source=_current_profile, stop=runtime.stop, trace=trace,
                    notify=xmpp_hub.send_matchmaking_state)
                from native_party_play import NativePartyPlay
                runtime.party_play = NativePartyPlay(runtime.party_admission,
                    prepare_own_loadout=selection_binding.sync.ensure)
                runtime.pvp_api = runtime.party_play
                probe.ProbeHandler.party_loadout_changed = selection_binding.dirty_callback

                def own_party_details(account_id):
                    if account_id != identity.puid:
                        return {}
                    try:
                        from native_custom_lobby import analyze_active_squad, NativeLobbyError
                        squad = analyze_active_squad(_current_profile(), offline._NATIVE)
                        units = {row['item_id']: row['key']
                                 for row in offline._NATIVE['units']}
                        return {'commander_key': squad.commander_key,
                                'commander_skin_key': '',
                                'units': [units[row[1]] for row in squad.records
                                          if row[0] == squad.commander_instance_id
                                          and row[1] in units]}
                    except (NativeLobbyError, KeyError, TypeError, ValueError):
                        return {}

                adapter = NativeSocialParty(runtime.social, account_id=identity.puid,
                    native_user_id=identity.native_user_id,
                    native_id_for=derive_native_user_id,
                    prepare_own_loadout=selection_binding.sync.ensure,
                    party_play=runtime.party_play)
                runtime.social_party = NativePartyController(adapter,
                    broadcast=xmpp_hub.send_social_party, own_details=own_party_details)
                xmpp_hub.social_party = runtime.social_party
                probe.ProbeHandler.native_social_party = runtime.social_party
                party_controller = runtime.social_party
                from native_recent_projection import (
                    RecentPlayersProjection, ProjectedNativeUserStorage, fetch_owned_recent_snapshot)
                storage = probe.ProbeHandler.native_user_storage
                recent_projection = None
                if storage is not None:
                    recent_projection = RecentPlayersProjection(
                        account_id=identity.puid, native_user_id=identity.native_user_id,
                        native_id_for=derive_native_user_id,
                        fetch_snapshot=lambda: fetch_owned_recent_snapshot(client), trace=trace)
                    runtime.recent_projection = recent_projection
                    runtime.recent_storage = ProjectedNativeUserStorage(storage, recent_projection)
                    probe.ProbeHandler.native_user_storage = runtime.recent_storage

                def publish_social(before, after):
                    xmpp_hub.publish_social(before, after)
                    try:
                        party_controller.publish(before, after)
                    except Exception as error:
                        trace({'event': 'native_social_party_publish_failed',
                               'error_type': type(error).__name__})
                    selection_binding.observe_social(before, after)
                    if recent_projection is not None:
                        try:
                            recent_projection.update(after, source_account_id=identity.puid)
                        except Exception:
                            trace({'event': 'native_recent_projection_skipped',
                                   'reason': 'publisher_failed'})

                runtime.social.start(publish_social, deliver_chat=xmpp_hub.send_chat)
        if matchmaking is not None and xmpp_hub is not None:
            runtime.announcer = AutoAnnouncer(
                matchmaking, xmpp_hub, trace=trace,
                profile_source=_current_profile,
                deadline_seconds=runtime.plan.announce_deadline_seconds)
            runtime.announcer.start()
        if matchmaking is not None and runtime.pvp_api is not None:
            runtime.pvp = PvpCoordinator(
                runtime.pvp_api, matchmaking, runtime.plan.native_user_id,
                api_base_url=runtime.plan.api_base_url, trace=trace,
                on_prepared=(start_durable_object_relay
                             if runtime.plan.relay_supervised else None),
                on_released=stop_durable_object_relay,
                battle_state=services.get("battle_state"),
                recovery_profile_source=_current_profile,
                recovery_ready=lambda: xmpp_hub is not None and xmpp_hub.notification_client_count > 0,
                allow_native_test_candidate=runtime.plan.internal_pvp_test)
            runtime.pvp.start()
        if (runtime.plan.relay_supervised
                and runtime.plan.relay_target in ("local", "switchable")):
            start_local_relay()
        if runtime.private_client is not None:
            if matchmaking is None or xmpp_hub is None or services.get("battle_state") is None:
                raise BridgeError("cloud private requires matchmaking, XMPP, and battle state")

            class SharedPrivateRelayLease:
                def __init__(self, prepared, ticket_source, on_relay_event):
                    self.prepared, self.ticket_source = prepared, ticket_source
                    self.on_relay_event, self.relay = on_relay_event, None

                def start(self):
                    battle_id = self.prepared.battle_id
                    with runtime.relay_lock:
                        if runtime.stop.is_set():
                            raise BridgeError("bridge_shutting_down")
                        if runtime.relay_owner is not None:
                            raise BridgeError("private_relay_lease_conflict")
                        lab = getattr(matchmaking, "lab_state", {})
                        if isinstance(lab, dict) and lab.get("queue_state") not in (None, "idle"):
                            raise BridgeError("private_relay_public_battle_active")
                        if runtime.relay is not None:
                            runtime.relay.stop()
                            runtime.relay = None
                        try:
                            runner = DurableObjectRelayRunner(
                                self.prepared.relay_url, self.ticket_source,
                                port=runtime.plan.relay_port, trace=trace,
                                on_relay_event=self.on_relay_event)
                            self.relay = RelaySupervisor(
                                target="durable_object", runner=runner, trace=trace)
                            runtime.relay = self.relay
                            runtime.relay_battle_id = battle_id
                            runtime.relay_owner = self
                            self.relay.start()
                            if getattr(runtime, "diagnostic", None) is not None:
                                runtime.diagnostic.bind_battle(battle_id)
                        except Exception:
                            # Keep both references until the exact partial
                            # owner is confirmed stopped by this lease.
                            try:
                                if self.relay is not None:
                                    self.relay.stop()
                            except Exception:
                                raise BridgeError(
                                    "private_relay_cleanup_unconfirmed") from None
                            runtime.relay = None
                            runtime.relay_battle_id = None
                            runtime.relay_owner = None
                            self.relay = None
                            if runtime.plan.public_dual_mode and not runtime.stop.is_set():
                                start_local_relay()
                            raise

                def stop(self):
                    with runtime.relay_lock:
                        if self.relay is None or runtime.relay_owner is not self \
                                or runtime.relay is not self.relay:
                            return
                        self.relay.stop()
                        runtime.relay = None
                        runtime.relay_battle_id = None
                        runtime.relay_owner = None
                        self.relay = None
                        if runtime.plan.public_dual_mode and not runtime.stop.is_set():
                            start_local_relay()

            sync_api = WorkerPvpApi(runtime.private_client)
            if runtime.party_selection is not None:
                sync_api = runtime.party_selection.wrap_api(sync_api)
            def sync_private_loadout():
                squad, _saved = matchmaking._trusted_battle_squad(_current_profile())
                details = matchmaking._squad_details(
                    squad.commander_tier, squad.records)
                loadout = matchmaking.pvp_rows_cloud_loadout(details)
                sync_api.sync_loadout(loadout["commander_id"], loadout["item_ids"])

            runtime.private = NativePrivateRuntime(
                room_api=runtime.private_client, battle_api=runtime.private_client,
                state=services["battle_state"], matchmaking=matchmaking,
                native_user_id=runtime.plan.native_user_id,
                mode=runtime.private_mode, ai_opponents=runtime.private_ai_opponents,
                sync_loadout=sync_private_loadout,
                notifier=NativePrivateXmppNotifier(xmpp_hub),
                starting_notifier=xmpp_hub.send_or_queue_custom_starting,
                relay_factory=SharedPrivateRelayLease,
                api_base_url=runtime.plan.api_base_url)
            probe.ProbeHandler.private_cloud_adapter = (
                runtime.party_selection.wrap_private_adapter(runtime.private.adapter)
                if runtime.party_selection is not None else runtime.private.adapter)
            public_completion = probe.ProbeHandler.completion_callback
            def complete_cloud_battle(battle_id, user_id, event, rows):
                snapshot = services["battle_state"].snapshot(battle_id)
                if snapshot.get("context", {}).get("private") is True:
                    return probe._complete_private_battle(
                        services["battle_state"], battle_id, user_id, event, rows)
                if public_completion is None:
                    raise BridgeError("public_completion_unavailable")
                return public_completion(battle_id, user_id, event, rows)
            probe.ProbeHandler.completion_callback = complete_cloud_battle

            def private_loop():
                while not runtime.stop.wait(0.5):
                    try:
                        runtime.private.step(_current_profile())
                    except Exception as error:
                        trace({"event": "cloud_private_step_failed",
                               "error": getattr(error, "code", type(error).__name__)})
            runtime.private_thread = threading.Thread(
                target=private_loop, name="cloud-private-runtime", daemon=True)
            runtime.private_thread.start()
        if runtime.party_admission is not None:
            runtime.party_admission.start()
        trace({"event": "companion_bridge_ready",
               **{key: value for key, value in runtime.plan.as_dict().items()
                  if key not in ("event", "probe_argv", "relay_argv")}})
    return ready


def _shutdown_runtime(runtime: BridgeRuntime) -> None:
    """Stop every owner of SQLite/relay resources before the probe closes them."""
    runtime.stop.set()
    # Stop the public admission caller before detaching its party/sync owners.
    if runtime.pvp is not None:
        runtime.pvp.stop()
        pvp_thread = getattr(runtime.pvp, "_thread", None)
        if pvp_thread is not None and pvp_thread.is_alive():
            raise BridgeError("public_pvp_stop_unconfirmed")
        runtime.pvp = None
    if runtime.party_admission is not None:
        runtime.party_admission.close()
        runtime.party_admission = None
    if runtime.party_selection is not None:
        binding = runtime.party_selection
        if probe.ProbeHandler.party_loadout_changed is binding.dirty_callback:
            probe.ProbeHandler.party_loadout_changed = None
        # Refuse dependency teardown until every own selection writer
        # has stopped; retain the owner reference if confirmation fails.
        try:
            binding.close()
        except Exception as error:
            raise BridgeError("party_loadout_stop_unconfirmed") from error
        runtime.party_selection = None
    if runtime.social is not None:
        runtime.social.stop()
        runtime.social = None
    if runtime.recent_storage is not None:
        if probe.ProbeHandler.native_user_storage is runtime.recent_storage:
            probe.ProbeHandler.native_user_storage = runtime.recent_storage.storage
        runtime.recent_storage = None
        runtime.recent_projection = None
    if runtime.social_party is not None:
        if probe.ProbeHandler.native_social_party is runtime.social_party:
            probe.ProbeHandler.native_social_party = None
        runtime.social_party = None
    thread = runtime.private_thread
    if thread is not None and thread is not threading.current_thread():
        thread.join(timeout=runtime.private_stop_timeout)
        if thread.is_alive():
            raise BridgeError("cloud_private_step_stop_unconfirmed")
        runtime.private_thread = None
    private = runtime.private
    if private is not None:
        private.close()
        runtime.private = None
    if runtime.announcer is not None:
        runtime.announcer.stop()
        runtime.announcer = None
    with runtime.relay_lock:
        if runtime.relay is not None:
            runtime.relay.stop()
            runtime.relay = None
        runtime.relay_battle_id = None
        runtime.relay_owner = None


def _compose_ready_callback(runtime: BridgeRuntime, trace, lifecycle_ready=None):
    """Run ordinary bridge composition before the private lifecycle ACK."""
    bridge_ready = _on_ready(runtime, trace)

    def ready(services):
        bridge_ready(services)
        if lifecycle_ready is not None:
            lifecycle_ready(runtime, services)
    return ready


# ---------------------------------------------------------------------------
# PvP battle identity
# ---------------------------------------------------------------------------

def pvp_battle_credentials(battle_view, ticket_view, native_user_id):
    """The native ``/check`` credentials of a Worker-assigned PvP battle.

    PvE keeps generating ``battle_id``/``battle_key`` locally in
    ``native_matchmaking._new_credentials`` -- correct, because the only
    participant is this machine.  PvP must not: both companions have to agree
    on one battle, so the native wire values come from the Worker.

      * ``battle_id``  = the Worker's ``battleId`` UUID from
        ``POST /v1/battles/from-assignment`` (private-server/src/battles.ts).
      * ``battle_key`` = ``battleKeyHex`` from
        ``POST /v1/battles/:id/relay-ticket``, canonical lowercase hex with no
        leading zeros, which is exactly what the native ``/check`` response and
        the GAME_JOIN uint64 already expect.
      * the seat ``userId`` in that ticket is ``actor.id`` (the PUID), which is
        why ``native_identity.derive_native_user_id`` passes a PUID through
        verbatim -- the GAME_JOIN identity slot must match it byte for byte.

    ``native_pvp_coordinator.PvpCoordinator`` binds the result into
    ``NativeMatchmaking.bind_pvp_battle`` and hands the ticket to
    ``native_relay_ws_bridge`` through ``DurableObjectRelayRunner``.
    """
    return _pvp_battle_credentials(battle_view, ticket_view, native_user_id)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m server.companion_bridge",
        description="Run the native ordinary-battle companion bridge on loopback.")
    parser.add_argument("--mode", choices=MODES, default="pve",
                        help="pve: local CPU battle; pvp: Worker matchmaking + "
                             "BattleRelay Durable Object (needs --economy-backend cloud)")
    parser.add_argument("--ruleset", choices=RULESETS, required=True)
    parser.add_argument("--internal-pvp-test", action="store_true", default=False,
                        help="Internal staging trial only: accept native_test_candidate assignments; "
                             "does not bypass authentication or enable the Worker gate")
    parser.add_argument("--economy-backend", choices=("file", "cloud"), default="file")
    parser.add_argument("--api-base-url",
                        help="Worker origin, e.g. http://127.0.0.1:8787 for wrangler dev")
    parser.add_argument("--session-token-file", type=Path,
                        help='JSON {"token": ..., "puid": ...} (or a /v1/auth/eos reply)')
    parser.add_argument("--battle-state", type=Path,
                        default=probe.DEFAULT_BATTLE_STATE_PATH)
    parser.add_argument("--economy-state", type=Path,
                        default=probe.DEFAULT_ECONOMY_STATE_PATH)
    parser.add_argument("--native-user-storage", type=Path,
                        help="Persistent native UI preferences, separate from economy state")
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--relay-trace", type=Path,
                        help="Relay child trace (default: <trace>.relay.jsonl)")
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument("--ports", type=int, nargs="+", default=list(DEFAULT_HTTP_PORTS))
    parser.add_argument("--client-version", default=DEFAULT_CLIENT_VERSION)
    parser.add_argument("--api-timeout", type=float, default=15.0)
    parser.add_argument("--announce-deadline", type=float,
                        default=ANNOUNCE_DEADLINE_SECONDS,
                        help=f"Must stay under the {QUEUE_SECONDS}s queue window")
    parser.add_argument("--no-relay", action="store_true",
                        help="Do not supervise native_battle_probe (start it yourself)")
    parser.add_argument(
        "--native-five-mode-selector", action="store_true",
        help="Opt in to the paired native five-mode selector capability")
    parser.add_argument("--cloud-private-mode", choices=("pve", "pvp"),
                        help="Opt in to the cloud private-room runtime")
    parser.add_argument("--cloud-private-ai-opponents", type=int, default=0)
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the effective plan and exit without binding")
    return parser


def normalize_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> argparse.Namespace:
    if args.relay_trace is None:
        args.relay_trace = Path(str(args.trace) + ".relay.jsonl")
    if not 1.0 <= args.announce_deadline < QUEUE_SECONDS:
        parser.error(f"--announce-deadline must be in [1, {QUEUE_SECONDS})")
    if args.economy_backend == "cloud" and not args.api_base_url:
        parser.error("--economy-backend cloud requires --api-base-url")
    if args.economy_backend == "cloud" and args.session_token_file is None:
        parser.error("--economy-backend cloud requires --session-token-file")
    if args.mode == "pvp" and args.economy_backend != "cloud":
        # The opponent, the battle id/key, the relay and the settlement all
        # live in the Worker; there is no file-backed PvP.
        parser.error("--mode pvp requires --economy-backend cloud")
    if args.cloud_private_mode is not None:
        if args.economy_backend != "cloud" or not args.native_five_mode_selector:
            parser.error("cloud private requires cloud economy and --native-five-mode-selector")
        if (args.cloud_private_mode == "pvp" and args.cloud_private_ai_opponents != 0):
            parser.error("cloud private pvp requires zero AI opponents")
        if (args.cloud_private_mode == "pve"
                and not 1 <= args.cloud_private_ai_opponents <= 10):
            parser.error("cloud private pve AI opponents must be 1..10")
    elif args.cloud_private_ai_opponents != 0:
        parser.error("--cloud-private-ai-opponents requires --cloud-private-mode")
    if any(not 1 <= port <= 65535 for port in args.ports):
        parser.error("--ports must be 1..65535")
    return args


def main(argv: list[str] | None = None, *, lifecycle_stop=None,
         lifecycle_ready=None, unit_control_capability=None,
         career_state_path: Path | None = None,
         career_history_root: Path | None = None) -> int:
    parser = build_arg_parser()
    args = normalize_args(parser, parser.parse_args(argv))
    try:
        verify_selector_installation(args.native_five_mode_selector)
        resolver, session_token = build_identity_resolver(args)
        plan = build_plan(args, resolver.native_user_id)
        if args.dry_run:
            print(json.dumps(plan.as_dict(), indent=2, sort_keys=True), flush=True)
            return 0
        economy_backend, authority = build_backends(args, session_token)
        career_cloud_factory = build_career_cloud_factory(args, session_token, resolver)
        pvp_api = build_pvp_api(args, session_token)
        private_client = build_private_client(args, session_token)
        if unit_control_capability is not None and (
                args.economy_backend != "cloud" or session_token is None):
            raise BridgeError(
                "unit control capability requires an authenticated cloud bridge")
        unit_control_guard = (
            None if unit_control_capability is None
            else probe.UnitControlGuard.from_capability(
                unit_control_capability, resolver.identity,
            )
        )
    except (BridgeError, ValueError) as error:
        print(json.dumps({"event": "companion_bridge_error",
                          "error": str(error)}), file=sys.stderr, flush=True)
        return 2
    if not plan.user_storage_loopback:
        # Non-fatal: the client retries the S3 PutObject and discards failures
        # (audit 2-9-1), but the noise is worth naming once at startup.
        print(json.dumps({"event": "companion_bridge_warning",
                          "warning": "user_storage_host_not_loopback",
                          "host": plan.user_storage_host,
                          "hosts_line": f"127.0.0.1 {plan.user_storage_host}"}),
              flush=True)
    if economy_backend is None and args.economy_backend == "file":
        economy_backend = None  # native_connection_probe owns the file path
    runtime = BridgeRuntime(plan=plan, resolver=resolver,
                            economy_backend=economy_backend,
                            settlement_authority=authority,
                            pvp_api=pvp_api, private_client=private_client)
    runtime.private_mode = args.cloud_private_mode
    runtime.private_ai_opponents = args.cloud_private_ai_opponents
    runtime.private_stop_timeout = args.api_timeout + 2.0
    if lifecycle_stop is not None:
        runtime.stop = lifecycle_stop
    trace = probe.ProbeHandler._trace
    ready = _compose_ready_callback(runtime, trace, lifecycle_ready)
    try:
        probe.main(
            list(plan.probe_argv),
            identity_resolver=resolver,
            unit_control_guard=unit_control_guard,
            economy_backend=economy_backend,
            settlement_authority=authority,
            career_state_path=career_state_path,
            career_history_root=career_history_root,
            career_cloud_factory=career_cloud_factory,
            ready=ready,
            before_shutdown=lambda: _shutdown_runtime(runtime),
            stop=runtime.stop,
            pvp_enabled=(plan.mode == "pvp" or plan.public_dual_mode),
            pve_enabled=(plan.mode == "pve" and not plan.public_dual_mode),
            public_pvp_only=plan.public_dual_mode,
            cloud_coop_pve=(runtime.pvp_api is not None and plan.mode == "pve" and not plan.public_dual_mode),
        )
    except KeyboardInterrupt:  # pragma: no cover - interactive shutdown
        pass
    finally:
        _shutdown_runtime(runtime)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
