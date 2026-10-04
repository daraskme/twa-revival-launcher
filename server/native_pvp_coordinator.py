"""Public PvP and cooperative PvE coordination (one process = one human seat).

The game only ever talks to the loopback stack.  When it sends
``POST /v8/matchmake`` for PvP or enabled cloud cooperative PvE, ``NativeMatchmaking``
queue enters the ``matching`` state and this coordinator drives the Cloudflare
Worker on the player's behalf:

    join -> poll GET /v1/matchmaking -> POST /v1/battles/from-assignment
         -> PUT /v1/battles/:id/squad -> POST /v1/battles/:id/relay-ticket
         -> GET /v1/battles/:id/roster (until every human squad is uploaded)
         -> NativeMatchmaking.bind_pvp_battle(...)  (queue state ``queued``)

From there the existing companion machinery takes over unchanged: the
``AutoAnnouncer`` sends ``mm_state_changed/battle_ready``, ``/check`` returns
the frozen 1..20-human PvP or 1..10-human same-team PvE roster plus CPU fill (Worker
``battleId`` / ``battleKeyHex``), and the
relay for the battle is the BattleRelay Durable Object reached through
``native_relay_ws_bridge`` on loopback TCP 19000 (``DurableObjectRelayRunner``
below) with the seat's relay ticket. CPUs never enter Worker auth, relay, or
reward participant records.

Everything here fails closed and never crashes the game: a Worker error or a
roster timeout drops the local queue (the client then sees its normal cancel
/ timeout path) and the reason is traced without credentials.  Tickets and
battle keys are never written to the trace.
"""
from __future__ import annotations

import asyncio
import copy
import ssl
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

from battle_api import _api_client_errors
from native_custom_lobby import NativeLobbyError
from native_matchmaking import BATTLE_RULESET_MAPS, QUEUE_SECONDS
from native_battle_maps import is_native_battle_map
from native_relay_ws_bridge import DEFAULT_RETRY_DELAYS, RelayBridge
from companion.loopback_ports import bind_failure_code
from native_cloud_loadout import CloudLoadoutError, _uint64, sync_cloud_loadout

# Worker ``pollAfterMs`` is honoured inside these bounds so a bad value can
# neither hammer the Worker nor stall past the native queue window.
POLL_MIN_SECONDS = 0.25
POLL_MAX_SECONDS = 10.0
DEFAULT_POLL_SECONDS = 2.0
# The native queue expires QUEUE_SECONDS after /v8/matchmake.  The whole
# Worker exchange (join, pairing, claim, squads, roster) must finish inside it
# with room for the announce; the roster wait is the only open-ended step.
ROSTER_DEADLINE_SECONDS = 90.0
QUEUE_SAFETY_MARGIN_SECONDS = 15.0
# Re-issue the relay ticket when it would expire within this margin; the
# Worker's lifetime is 15 min (RELAY_TICKET_LIFETIME_MS) and the DO verifies
# ``exp`` at every handshake, including a CAReconn resume.
TICKET_RENEW_MARGIN_MS = 60_000
MAX_JOIN_ATTEMPTS = 3
STATES = ('idle', 'joined', 'awaiting_roster', 'prepared')
_CANONICAL_HEX = '0123456789abcdef'


class PvpCoordinatorError(Exception):
    """Stable code + HTTP status; never carries a ticket, key or body."""

    def __init__(self, code: str, status: int = 0) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


# ---------------------------------------------------------------------------
# Worker access
# ---------------------------------------------------------------------------

class WorkerPvpApi:
    """The seven Worker routes the PvP flow needs, over ``companion.api_client``.

    Errors are mapped onto :class:`PvpCoordinatorError` so the coordinator
    sees one vocabulary (``409 roster_incomplete`` is the one it polls on).
    """

    REQUIRED = ('matchmaking_join', 'matchmaking_status', 'matchmaking_cancel',
                'create_battle_from_assignment', 'put_squad', 'get_roster',
                'relay_ticket')

    def __init__(self, client: object) -> None:
        missing = [name for name in self.REQUIRED if not callable(getattr(client, name, None))]
        if missing:
            raise PvpCoordinatorError('invalid_pvp_api')
        self._client = client
        self._errors = _api_client_errors()

    def join(self, ruleset: str) -> dict:
        return self._call(lambda: self._client.matchmaking_join('pvp', ruleset))

    def sync_loadout(self, commander_id: str, item_ids: list[str]) -> None:
        if any(not callable(getattr(self._client, name, None))
               for name in ('get_loadout', 'put_loadout', 'select_commander')):
            raise PvpCoordinatorError('invalid_pvp_api')
        try:
            sync_cloud_loadout(self._client, commander_id, item_ids,
                               api_errors=self._errors)
        except CloudLoadoutError as error:
            raise PvpCoordinatorError(error.code) from None

    def join_coop(self, ruleset: str) -> dict:
        return self._call(lambda: self._client.matchmaking_join('pve', ruleset))

    def status(self) -> dict:
        return self._call(self._client.matchmaking_status)

    def cancel(self) -> dict:
        return self._call(self._client.matchmaking_cancel)

    def create_battle_from_assignment(self, assignment_id: str) -> dict:
        return self._call(lambda: self._client.create_battle_from_assignment(assignment_id))

    def put_squad(self, battle_id: str, rows: list) -> dict:
        return self._call(lambda: self._client.put_squad(battle_id, rows))

    def get_roster(self, battle_id: str) -> dict:
        return self._call(lambda: self._client.get_roster(battle_id))

    def get_active_battle(self) -> dict:
        return self._call(self._client.get_active_battle)

    def prepared_battle_terminal(self, prepared, generation) -> bool:
        reader = getattr(self._client, 'get_battle_with_admission', self._client.get_battle)
        response = self._call(lambda: reader(prepared.battle_id))
        battle = response.get('battle')
        if (not isinstance(battle, dict)
                or battle.get('battleId') != prepared.battle_id
                or battle.get('assignmentId') != prepared.assignment_id
                or type(response.get('admissionReleased')) is not bool):
            raise PvpCoordinatorError('invalid_battle_release_receipt')
        return response['admissionReleased']

    def relay_ticket(self, battle_id: str) -> dict:
        return self._call(lambda: self._client.relay_ticket(battle_id))

    def _call(self, action: Callable[[], Any]) -> Any:
        api_error, conflict, network = self._errors
        try:
            result = action()
        except conflict as error:
            raise PvpCoordinatorError(str(getattr(error, 'code', 'conflict')), 409) from None
        except api_error as error:
            status = getattr(error, 'status', 0)
            raise PvpCoordinatorError(str(getattr(error, 'code', 'error')),
                                      status if type(status) is int else 0) from None
        except network:
            raise PvpCoordinatorError('worker_unreachable', 0) from None
        if not isinstance(result, dict):
            raise PvpCoordinatorError('invalid_worker_response', 0)
        return result


# ---------------------------------------------------------------------------
# validated Worker shapes
# ---------------------------------------------------------------------------

def _canonical_uuid(value: object, code: str) -> str:
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, AttributeError, TypeError):
        raise PvpCoordinatorError(code) from None
    return value


def canonical_battle_key_hex(value: object) -> str:
    """The relay-ticket ``battleKeyHex``: lowercase hex uint64, no leading zeros."""
    if (not isinstance(value, str) or not 1 <= len(value) <= 16
            or any(char not in _CANONICAL_HEX for char in value)):
        raise PvpCoordinatorError('invalid_battle_key_hex')
    number = int(value, 16)
    if number == 0 or format(number, 'x') != value:
        raise PvpCoordinatorError('invalid_battle_key_hex')
    return value


def _roster_policy(value: object, assignment_id: str, mode: str = 'pvp') -> dict | None:
    """Validate frozen CPU-fill policy; v2+ preserve authoritative group teams."""
    if value is None:
        return None
    version = value.get('version') if isinstance(value, dict) else None
    if type(version) is not int or version not in (1, 2, 3, 4, 5):
        raise PvpCoordinatorError('invalid_roster_policy')
    expected = {
        'version': version, 'totalSeats': 20, 'seatsPerTeam': 10,
        'unitsPerSeat': 3, 'humanParticipantsOnly': True, 'cpuFill': True,
        'seed': mode + '-roster-v' + str(version) + ':' + assignment_id,
    }
    integer_keys = ('version', 'totalSeats', 'seatsPerTeam', 'unitsPerSeat')
    if (not isinstance(value, dict) or set(value) != set(expected)
            or any(type(value.get(key)) is not int for key in integer_keys)
            or type(value.get('humanParticipantsOnly')) is not bool
            or type(value.get('cpuFill')) is not bool
            or not isinstance(value.get('seed'), str)
            or value != expected):
        raise PvpCoordinatorError('invalid_roster_policy')
    return copy.deepcopy(value)


def _valid_team(team: object, seat: int, mode: str, policy: dict | None) -> bool:
    if type(team) is not int or team not in (0, 1):
        return False
    if mode == 'pve':
        return team == 0
    return policy is not None and policy['version'] in (2, 3, 4, 5) or team == seat % 2


def _participants(view: object, native_user_id: str,
                  roster_policy: dict | None = None, *,
                  loadout_required: bool = True, mode: str = 'pvp') -> list[dict]:
    """Validate frozen human seats; CPUs never enter Worker participants."""
    rows = view.get('participants') if isinstance(view, dict) else None
    if (not isinstance(rows, list)
            or (roster_policy is None and len(rows) != 2)
            or (roster_policy is not None and not 1 <= len(rows) <= (10 if mode == 'pve' else 20))):
        raise PvpCoordinatorError('invalid_pvp_participants')
    seats: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            raise PvpCoordinatorError('invalid_pvp_participants')
        user_id = row.get('userId')
        if (not isinstance(user_id, str) or not 1 <= len(user_id) <= 36
                or any(ord(char) < 32 or ord(char) > 126 for char in user_id)):
            raise PvpCoordinatorError('invalid_pvp_participants')
        seat, team, player_id = row.get('seat'), row.get('team'), row.get('playerId')
        if (type(seat) is not int or type(team) is not int or type(player_id) is not int
                or seat != len(seats) or not _valid_team(team, seat, mode, roster_policy)
                or player_id != seat + 1):
            raise PvpCoordinatorError('invalid_pvp_participants')
        loadout = row.get('loadout')
        identity = _loadout_identity(loadout) if loadout is not None else None
        if roster_policy is not None and loadout_required and identity is None:
            raise PvpCoordinatorError('invalid_pvp_loadout')
        seats.append({'user_id': user_id, 'seat': seat, 'team': team,
                      'player_id': player_id, 'rows': row.get('rows'),
                      'loadout': identity})
    seats.sort(key=lambda seat: seat['seat'])
    if ([seat['seat'] for seat in seats] != list(range(len(seats)))
            or len({seat['user_id'] for seat in seats}) != len(seats)
            or native_user_id not in {seat['user_id'] for seat in seats}):
        raise PvpCoordinatorError('invalid_pvp_participants')
    if roster_policy is not None:
        humans = [sum(seat['team'] == team for seat in seats) for team in (0, 1)]
        if any(count > 10 for count in humans):
            raise PvpCoordinatorError('invalid_pvp_participants')
        cpu = view.get('cpuSeatsByTeam')
        if (not isinstance(cpu, list) or len(cpu) != 2
                or any(type(value) is not int for value in cpu)
                or cpu != [10 - humans[0], 10 - humans[1]]):
            raise PvpCoordinatorError('invalid_cpu_seats_by_team')
    return seats


def _loadout_identity(value: object) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict) or not isinstance(value.get('units'), list) \
            or len(value['units']) != 3:
        raise PvpCoordinatorError('invalid_pvp_loadout')
    commander = value.get('commanderId')
    items = [unit.get('itemId') if isinstance(unit, dict) else None
             for unit in value['units']]
    values = [commander, *items]
    if any(not _uint64(item) for item in values):
        raise PvpCoordinatorError('invalid_pvp_loadout')
    return {'commander_id': commander, 'item_ids': items}


def pvp_battle_credentials(battle_view: object, ticket_view: object,
                           native_user_id: str) -> tuple[str, str]:
    """Return ``(battle_id, battle_key_hex)`` for the native ``/check``.

    * ``battle_id`` is the Worker ``battleId`` of ``POST /v1/battles/from-assignment``
      (identical for both participants and every retry).
    * ``battle_key`` is the relay ticket's ``battleKeyHex``: the DO manifest
      key, canonical lowercase hex, which the native client parses with
      radix 16 into the GAME_JOIN uint64.
    * the ticket's seat ``userId`` must be this process' native user id byte
      for byte, because the DO matches it against the GAME_JOIN identity slot.
    """
    if not isinstance(battle_view, dict) or not isinstance(ticket_view, dict):
        raise PvpCoordinatorError('invalid_battle_view')
    battle_id = _canonical_uuid(battle_view.get('battleId'), 'invalid_battle_id')
    if ticket_view.get('battleId') != battle_id:
        raise PvpCoordinatorError('ticket_battle_mismatch')
    if ticket_view.get('userId') not in (None, native_user_id):
        raise PvpCoordinatorError('ticket_identity_mismatch')
    return battle_id, canonical_battle_key_hex(ticket_view.get('battleKeyHex'))


def validate_relay_ticket(view: object, *, battle_id: str, seat: dict) -> dict:
    """Check one ``relay-ticket`` reply against the claimed seat."""
    if not isinstance(view, dict):
        raise PvpCoordinatorError('invalid_relay_ticket')
    ticket = view.get('ticket')
    if not isinstance(ticket, str) or not ticket or '.' not in ticket or len(ticket) > 2048:
        raise PvpCoordinatorError('invalid_relay_ticket')
    if view.get('battleId') != battle_id:
        raise PvpCoordinatorError('ticket_battle_mismatch')
    if (view.get('seat') != seat['seat'] or view.get('playerId') != seat['player_id']
            or view.get('team') != seat['team']):
        raise PvpCoordinatorError('ticket_seat_mismatch')
    expires_at = view.get('expiresAt')
    if type(expires_at) is not int or expires_at <= 0:
        raise PvpCoordinatorError('invalid_relay_ticket')
    relay_url = view.get('relayUrl')
    if not isinstance(relay_url, str) or not relay_url:
        raise PvpCoordinatorError('invalid_relay_ticket')
    return {'ticket': ticket, 'expires_at_ms': expires_at, 'relay_url': relay_url,
            'battle_key_hex': canonical_battle_key_hex(view.get('battleKeyHex'))}


def derive_relay_ws_url(api_base_url: str | None, relay_url: str) -> str:
    """``http(s)://host[/prefix]`` + ``/v1/relay/<id>`` -> ``ws(s)://host/prefix/v1/relay/<id>``."""
    if not isinstance(relay_url, str) or not relay_url:
        raise PvpCoordinatorError('invalid_relay_url')
    if relay_url.startswith(('ws://', 'wss://')):
        return relay_url
    if not isinstance(api_base_url, str) or not api_base_url:
        raise PvpCoordinatorError('invalid_api_base_url')
    parts = urlsplit(api_base_url)
    if parts.scheme not in ('http', 'https') or not parts.netloc:
        raise PvpCoordinatorError('invalid_api_base_url')
    scheme = 'wss' if parts.scheme == 'https' else 'ws'
    path = relay_url if relay_url.startswith('/') else '/' + relay_url
    return f'{scheme}://{parts.netloc}{parts.path.rstrip("/")}{path}'


def _poll_seconds(view: dict) -> float:
    value = view.get('pollAfterMs')
    if type(value) is not int or value <= 0:
        return DEFAULT_POLL_SECONDS
    return min(POLL_MAX_SECONDS, max(POLL_MIN_SECONDS, value / 1000.0))


@dataclass(frozen=True)
class PreparedPvpBattle:
    """The frozen battle this process will play; ``ticket``/key stay out of traces."""

    battle_id: str
    battle_key_hex: str
    assignment_id: str
    ruleset: str
    map_key: str
    seat: int
    team: int
    player_id: int
    user_ids: tuple[str, ...]
    opponent_user_id: str
    relay_url: str
    reward_policy: dict
    battle_expires_at: int | None = None
    mode: str = 'pvp'
    fresh_process_restart: bool = False

    def as_trace(self) -> dict:
        return {'seat': self.seat, 'team': self.team, 'player_id': self.player_id,
                'ruleset': self.ruleset, 'map': self.map_key,
                'relay_url_scheme': self.relay_url.split(':', 1)[0]}


# ---------------------------------------------------------------------------
# relay ticket renewal
# ---------------------------------------------------------------------------

class RelayTicketSource:
    """Hand the bridge a ticket that is still valid at every handshake.

    The bridge presents the ticket on every WebSocket handshake (fresh,
    CAReconn resume, bridge resume).  A ticket nearing ``expiresAt`` is
    re-issued through ``POST /v1/battles/:id/relay-ticket``; a failed renewal
    keeps the current ticket (the DO then closes with 4000 and the game falls
    back to its own CAReconn reconnect, which asks here again).
    """

    def __init__(self, api: WorkerPvpApi, battle_id: str, seat: dict, ticket: dict, *,
                 clock_ms: Callable[[], int] | None = None,
                 renew_margin_ms: int = TICKET_RENEW_MARGIN_MS,
                 fresh_process_restart: bool = False,
                 trace: Callable[[dict], None] | None = None) -> None:
        self._api = api
        self._battle_id = battle_id
        self._seat = dict(seat)
        self._ticket = ticket['ticket']
        self._expires_at_ms = ticket['expires_at_ms']
        self._battle_key_hex = ticket['battle_key_hex']
        self._clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)
        self._margin = renew_margin_ms
        self.fresh_process_restart = fresh_process_restart
        self._trace = trace
        self._lock = threading.Lock()
        self.renewals = 0
        self.failed_renewals = 0

    @property
    def expires_at_ms(self) -> int:
        return self._expires_at_ms

    @property
    def battle_id(self) -> str:
        return self._battle_id

    def current(self) -> str:
        with self._lock:
            if self._expires_at_ms - self._clock_ms() > self._margin:
                return self._ticket
            try:
                view = validate_relay_ticket(self._api.relay_ticket(self._battle_id),
                                             battle_id=self._battle_id, seat=self._seat)
                if view['battle_key_hex'] != self._battle_key_hex:
                    raise PvpCoordinatorError('ticket_key_changed')
            except PvpCoordinatorError as error:
                self.failed_renewals += 1
                _emit(self._trace, 'companion_relay_ticket_renewal_failed', reason=error.code)
                return self._ticket
            self._ticket = view['ticket']
            self._expires_at_ms = view['expires_at_ms']
            self.renewals += 1
            _emit(self._trace, 'companion_relay_ticket_renewed', renewals=self.renewals)
            return self._ticket


class TicketedRelayBridge(RelayBridge):
    """``RelayBridge`` whose ticket is read from a :class:`RelayTicketSource`."""

    def __init__(self, ws_url: str, ticket_source: RelayTicketSource, **kwargs) -> None:
        self._ticket_source = ticket_source
        super().__init__(ws_url, ticket_source.current(),
                         expected_battle_id=ticket_source.battle_id,
                         fresh_process_restart=ticket_source.fresh_process_restart, **kwargs)

    @property
    def ticket(self) -> str:  # type: ignore[override]
        return self._ticket_source.current()

    @ticket.setter
    def ticket(self, _value: str) -> None:
        # The base constructor assigns the initial ticket; the source owns it.
        pass


class DurableObjectRelayRunner:
    """Run ``native_relay_ws_bridge`` in-process on its own asyncio thread.

    The PvE relay stays a child process (its own 30-minute session cap and
    event loop, see companion_bridge.RelaySupervisor).  The WebSocket bridge
    is stdlib asyncio with no session cap of its own, and it must reach the
    live ticket source and the trace sink, so it runs here as a daemon thread
    with a private event loop.  ``stop()`` closes the listener, lets the
    current game link finish, and joins the thread.
    """

    def __init__(self, ws_url: str, ticket_source: RelayTicketSource, *,
                 host: str = '127.0.0.1', port: int = 19000,
                  ssl_context: ssl.SSLContext | None = None,
                  trace: Callable[[dict], None] | None = None,
                  on_relay_event: Callable[[dict], None] | None = None,
                  retry_delays: tuple[float, ...] = DEFAULT_RETRY_DELAYS) -> None:
        self._ws_url = ws_url
        self._ticket_source = ticket_source
        self._host = host
        self._requested_port = port
        self._ssl_context = ssl_context
        self._trace = trace
        self._on_relay_event = on_relay_event
        self._retry_delays = retry_delays
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop_event: asyncio.Event | None = None
        self._ready = threading.Event()
        self._stop_requested = threading.Event()
        self._error: BaseException | None = None
        self.port: int | None = None
        self.bridge: RelayBridge | None = None
        self.events: list[dict] = []

    def _log(self, row: dict) -> None:
        # Bridge rows already exclude the ticket and payload bytes.  This
        # callback runs inside the bridge's pump tasks, so it must never raise.
        self.events.append(row)
        try:
            fields = {key: value for key, value in row.items()
                      if key not in ('time', 'event', 'bridge_event')}
            _emit(self._trace, 'companion_relay_bridge',
                  bridge_event=str(row.get('event', ''))[:32], **fields)
        except Exception:  # pragma: no cover - tracing never fails a battle
            pass

    def start(self, timeout: float = 5.0) -> int:
        if self._thread is not None:
            raise RuntimeError('relay runner already started')
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name='companion-do-relay')
        self._thread.start()
        if not self._ready.wait(timeout):
            raise PvpCoordinatorError('relay_bridge_start_timeout')
        if self._error is not None:
            if isinstance(self._error, OSError) and bind_failure_code(self._error) is not None:
                raise self._error
            raise PvpCoordinatorError('relay_bridge_start_failed')
        assert self.port is not None
        return self.port

    def stop(self, timeout: float = 10.0) -> None:
        self._stop_requested.set()
        loop, stop_event = self._loop, self._stop_event
        if loop is not None and stop_event is not None:
            try:
                loop.call_soon_threadsafe(stop_event.set)
            except RuntimeError:
                pass
        thread = self._thread
        if thread is not None:
            thread.join(timeout)
            if thread.is_alive():
                raise PvpCoordinatorError('relay_bridge_stop_timeout')

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            loop.run_until_complete(self._serve())
        finally:
            loop.close()
            self._ready.set()

    async def _serve(self) -> None:
        self._stop_event = asyncio.Event()
        if self._stop_requested.is_set():
            self._stop_event.set()
        try:
            bridge = TicketedRelayBridge(
                self._ws_url, self._ticket_source, host=self._host, port=self._requested_port,
                ssl_context=self._ssl_context, retry_delays=self._retry_delays, log=self._log,
                on_relay_event=self._on_relay_event)
            self.port = await bridge.start()
        except BaseException as error:  # noqa: BLE001 - reported to start()
            self._error = error
            _emit(self._trace, 'companion_relay_bridge_failed', reason=type(error).__name__)
            self._ready.set()
            return
        self.bridge = bridge
        self._ready.set()
        await self._stop_event.wait()
        await bridge.stop()


# ---------------------------------------------------------------------------
# coordinator
# ---------------------------------------------------------------------------

class PvpCoordinator:
    """Drive the Worker matchmaking for the local PvP queue.

    ``step()`` performs one bounded observation and is what tests call;
    ``run()``/``start()`` loop it on a thread with the Worker's ``pollAfterMs``.
    The local ``NativeMatchmaking`` queue is the authority for "the player is
    still waiting": when it disappears (game ``/cancel``, 180 s expiry or
    ``complete_battle``) the coordinator cancels/cleans up on the Worker side.
    """

    def __init__(self, api: WorkerPvpApi, matchmaking, native_user_id: str, *,
                 api_base_url: str | None = None,
                 trace: Callable[[dict], None] | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep,
                 roster_deadline_seconds: float = ROSTER_DEADLINE_SECONDS,
                 on_prepared: Callable[[PreparedPvpBattle, RelayTicketSource], None] | None = None,
                 on_released: Callable[[PreparedPvpBattle | None, str], None] | None = None,
                 ticket_clock_ms: Callable[[], int] | None = None,
                 battle_state: object | None = None,
                 recovery_profile_source: Callable[[], dict] | None = None,
                 recovery_ready: Callable[[], bool] | None = None,
                 allow_native_test_candidate: bool = False) -> None:
        if not isinstance(native_user_id, str) or not native_user_id:
            raise ValueError('native_user_id required')
        if type(allow_native_test_candidate) is not bool:
            raise ValueError('allow_native_test_candidate must be a bool')
        self.allow_native_test_candidate = allow_native_test_candidate
        self._api = api
        self._matchmaking = matchmaking
        self._user = native_user_id
        self._api_base_url = api_base_url
        self._trace = trace
        self._clock = clock
        self._sleep = sleep
        self._roster_deadline = float(roster_deadline_seconds)
        self._on_prepared = on_prepared
        self._on_released = on_released
        self._ticket_clock_ms = ticket_clock_ms
        self._battle_state = battle_state
        self._recovery_profile_source = recovery_profile_source
        self._recovery_ready = recovery_ready or (lambda: False)
        self._recovery_checked = recovery_profile_source is None
        self._recovery_next_poll = 0.0
        self._recovery_failures = 0
        self._next_battle_release_poll = 0.0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self._phase_lock = threading.Lock()
        self._phase_prepared: PreparedPvpBattle | None = None
        self.state = 'idle'
        self.next_poll_seconds = DEFAULT_POLL_SECONDS
        self.prepared: PreparedPvpBattle | None = None
        self.ticket_source: RelayTicketSource | None = None
        self.last_error: str | None = None
        self._ruleset: str | None = None
        self._mode = 'pvp'
        self._join_attempts = 0
        self._queue_started: float | None = None
        self._roster_started: float | None = None
        self._claim: dict | None = None
        self._local_rows: list | None = None
        # The assignment id seen on the previous poll(s) but not yet claimed.
        self._pending_assignment: dict | None = None
        self._next_unstarted_party_poll = 0.0
        self._unstarted_party_error: str | None = None

    # -- one observation ----------------------------------------------------

    def step(self) -> str:
        with self._lock:
            try:
                return self._step()
            except (PvpCoordinatorError, NativeLobbyError) as error:
                retryable = getattr(self._api, 'retryable_admission_error', None)
                if (isinstance(error, PvpCoordinatorError) and callable(retryable)
                        and self.state in ('idle', 'joined') and retryable(error)):
                    self.state = 'joined'
                    self.next_poll_seconds = DEFAULT_POLL_SECONDS
                    self._emit('companion_party_admission_retry', reason=error.code)
                    return self.state
                # NativeLobbyError: the local queue refused the roster/bind
                # (opponent rows malformed, credentials reused, ...).
                self._fail(error.code)
                return self.state

    def on_relay_event(self, event: dict) -> None:
        """Advance the local result lifecycle only from the relay READY barrier."""
        # This lock protects only the immutable lease and local SQLite update;
        # it is never held over Worker I/O or relay stop/join.
        with self._phase_lock:
            if (not isinstance(event, dict)
                    or set(event) != {'event', 'battleId', 'phase', 'tick'}
                    or event.get('event') != 'battle_phase'
                    or event.get('phase') != 'ticking'
                    or type(event.get('tick')) is not int
                    or event['tick'] != 0):
                raise PvpCoordinatorError('invalid_relay_phase_event')
            prepared = self._phase_prepared
            if (prepared is None or event.get('battleId') != prepared.battle_id):
                raise PvpCoordinatorError('stale_relay_phase_event')
            if self._battle_state is None:
                raise PvpCoordinatorError('battle_state_unavailable')
            try:
                snapshot = self._battle_state.snapshot(prepared.battle_id)
                context = snapshot.get('context', {})
                pvp = context.get('pvp') if isinstance(context, dict) else None
                if (context.get('mode') != prepared.mode
                        or context.get('cloud_battle_id') != prepared.battle_id
                        or not isinstance(pvp, dict)
                        or pvp.get('assignment_id') != prepared.assignment_id
                        or snapshot.get('user_ids') != [self._user]):
                    raise PvpCoordinatorError('relay_phase_lease_mismatch')
                phase = snapshot.get('phase')
                if phase == 'enrolled':
                    self._battle_state.start_ticking(prepared.battle_id)
                elif phase not in {'ticking', 'result_reported', 'result_ready',
                                    'settled', 'delivered'}:
                    raise PvpCoordinatorError('relay_phase_before_enrollment')
            except PvpCoordinatorError:
                raise
            except Exception:
                raise PvpCoordinatorError('relay_phase_state_failed') from None

    def _step(self) -> str:
        if not self._recovery_checked and self.state == 'idle':
            if not self._recovery_ready():
                return self.state
            # The native client must first enter matchmaking itself.  A
            # startup-only XMPP connection can receive battle_ready while the
            # game is still in the hangar; its later Play is an idempotent
            # retry of the already-announced queue and cannot notify again.
            # Waiting for the local native Play intent also retains the old
            # frozen seat as the first Worker query, before any new join.
            generation = self._matchmaking.pvp_queue_generation
            if (generation is None
                    or self._matchmaking.lab_state.get('queue_state') != 'matching'):
                return self.state
            if self._clock() < self._recovery_next_poll:
                return self.state
            if self._recover_active_battle(generation) is not False:
                return self.state
        lab = self._matchmaking.lab_state
        queue_state = lab.get('queue_state')
        active = ((lab.get('game_mode') == 'pvp' or lab.get('game_mode') == 'pve' and lab.get('cloud_matchmaking') is True) and queue_state in (
            'matching', 'queued', 'battle_ready', 'notification_uncertain'))
        if not active:
            if self.state != 'idle':
                self._release('queue_cleared' if queue_state in (None, 'idle')
                              else f'queue_{queue_state}')
            self.next_poll_seconds = DEFAULT_POLL_SECONDS
            return self.state
        if self.state == 'idle':
            self._mode = lab['game_mode']
            self._ruleset = lab.get('battle_ruleset')
            if self._ruleset not in BATTLE_RULESET_MAPS:
                raise PvpCoordinatorError('invalid_ruleset')
            self._queue_started = self._clock()
            self._join_attempts = 0
            self._join()
            return self.state
        if self._queue_started is not None and (
                self._clock() - self._queue_started
                >= QUEUE_SECONDS - QUEUE_SAFETY_MARGIN_SECONDS
                and self.state != 'prepared'):
            raise PvpCoordinatorError('queue_window_exhausted')
        if self.state == 'joined':
            self._poll_status()
        elif self.state == 'awaiting_roster':
            self._poll_roster()
        else:  # prepared: wait for the local queue to clear
            if self._prepared_terminal():
                return self.state
            self.next_poll_seconds = DEFAULT_POLL_SECONDS
        return self.state

    def _recover_active_battle(self, generation) -> bool | None:
        """Re-adopt only this account's unfinished, server-frozen public seat."""
        try:
            view = self._api.get_active_battle()
        except PvpCoordinatorError as error:
            # Discovery must succeed before joining a new battle, but a
            # transport outage is not a reason to cancel the player's intent.
            if (error.code != 'worker_unreachable' and error.status != 429
                    and error.status < 500):
                raise
            self._recovery_failures += 1
            self.next_poll_seconds = min(POLL_MAX_SECONDS,
                                         DEFAULT_POLL_SECONDS * min(self._recovery_failures, 5))
            self._recovery_next_poll = self._clock() + self.next_poll_seconds
            if self._recovery_failures == 1:
                self._emit('companion_pvp_process_recovery_retry', reason=error.code)
            return None
        # A native Cancel or another Play may have replaced this queue while
        # the Worker read was in flight. Re-discover for the new generation on
        # the next step; do not consume or announce the stale result.
        if (not self._matchmaking.is_current_pvp_generation(generation)
                or self._matchmaking.lab_state.get('queue_state') != 'matching'):
            return None
        self._recovery_failures = 0
        self._recovery_next_poll = 0.0
        if not isinstance(view, dict):
            raise PvpCoordinatorError('invalid_active_battle')
        battle = view.get('battle')
        if battle is None and 'battle' in view:
            self._recovery_checked = True
            return False
        if not isinstance(battle, dict):
            raise PvpCoordinatorError('invalid_active_battle')
        expiry = battle.get('expiresAt')
        now_ms = (self._ticket_clock_ms or (lambda: time.time_ns() // 1_000_000))()
        if (battle.get('origin') != 'public' or battle.get('status') != 'created'
                or type(battle.get('winnerDecided')) is not bool
                or type(expiry) is not int or expiry <= 0
                or (view.get('settlement') is not None and not isinstance(view['settlement'], dict))):
            raise PvpCoordinatorError('invalid_active_battle')
        if (battle['winnerDecided'] or view.get('settlement') is not None
                or expiry * 1000 <= now_ms):
            # A battle can finish after the discovery query. This terminal
            # response ends startup recovery, not a new native Play request.
            self._recovery_checked = True
            self._emit('companion_pvp_process_recovery_skipped', reason='battle_terminal')
            return False
        assignment = _canonical_uuid(battle.get('assignmentId'), 'invalid_assignment_id')
        mode, ruleset = battle.get('mode'), battle.get('ruleset')
        if mode not in ('pvp', 'pve') or ruleset not in BATTLE_RULESET_MAPS:
            raise PvpCoordinatorError('invalid_active_battle')
        policy = _roster_policy(battle.get('rosterPolicy'), assignment, mode)
        seats = _participants(battle, self._user, policy, mode=mode)
        mine = next(seat for seat in seats if seat['user_id'] == self._user)
        if mine['loadout'] is None:
            raise PvpCoordinatorError('restart_loadout_unavailable')
        profile = self._recovery_profile_source()
        if not self._matchmaking.enter_party_attempt(
                profile, mode=mode, ruleset=ruleset, loadout=mine['loadout'],
                expected_generation=generation):
            return None
        self._mode, self._ruleset = mode, ruleset
        self._queue_started = self._clock()
        self._prepare_claim(battle, assignment, policy, fresh_process_restart=True)
        self._recovery_checked = True
        self._emit('companion_pvp_process_recovery_prepared', seat=mine['seat'], mode=mode, ruleset=ruleset)
        return True

    def _prepared_terminal(self) -> bool:
        prepared = self.prepared
        if prepared is None:
            return False
        if self._battle_state is not None:
            try:
                snapshot = self._battle_state.snapshot(prepared.battle_id)
            except Exception:  # State may not be allocated until native /check.
                snapshot = None
            phase = snapshot.get('phase') if isinstance(snapshot, dict) else None
            if phase in ('settled', 'delivered'):
                self._matchmaking.complete_battle(prepared.battle_id)
                self._release('battle_terminal')
                return True
        expiry = prepared.battle_expires_at
        now_ms = (self._ticket_clock_ms or
                  (lambda: time.time_ns() // 1_000_000))()
        if type(expiry) is int and now_ms >= expiry * 1000:
            self._matchmaking.abort_pvp('battle_expired')
            self._release('battle_expired')
            return True
        return self._remote_battle_terminal(prepared) or self._unstarted_party_terminal(prepared)

    def _remote_battle_terminal(self, prepared) -> bool:
        """Release only after the Worker proves this transport cannot resume."""
        terminal = getattr(self._api, 'prepared_battle_terminal', None)
        generation = self._matchmaking.pvp_queue_generation
        if not callable(terminal) or generation is None or self._clock() < self._next_battle_release_poll:
            return False
        self._next_battle_release_poll = self._clock() + 5.0
        try:
            confirmed = terminal(prepared, generation)
        except (PvpCoordinatorError, NativeLobbyError):
            # Network failures and old Workers without this receipt never
            # imply that a live or reconnectable battle has ended.
            return False
        if confirmed is not True:
            return False
        with self._phase_lock:
            if (self._phase_prepared is not prepared
                    or not self._matchmaking.abort_prepared_pvp_generation(
                        generation, prepared.battle_id)):
                return False
            self._phase_prepared = None
        self._release('battle_admission_released', generation=generation)
        return True

    def _unstarted_snapshot(self, prepared) -> bool:
        """Require readable, own battle state which has not crossed READY."""
        if self._battle_state is None:
            return False
        try:
            snapshot = self._battle_state.snapshot(prepared.battle_id)
        except Exception:
            # A missing allocation or failed DB read is not proof of a lease
            # which can be retired. Its existing absolute expiry still applies.
            return False
        if not isinstance(snapshot, dict):
            return False
        context = snapshot.get('context')
        pvp = context.get('pvp') if isinstance(context, dict) else None
        return (snapshot.get('phase') in ('allocated', 'enrolled')
                and snapshot.get('user_ids') == [self._user]
                and isinstance(context, dict)
                and context.get('mode') == prepared.mode
                and context.get('cloud_battle_id') == prepared.battle_id
                and isinstance(pvp, dict)
                and pvp.get('assignment_id') == prepared.assignment_id)

    def _unstarted_party_terminal(self, prepared) -> bool:
        terminal = getattr(self._api, 'prepared_party_terminal', None)
        if not callable(terminal) or not self._unstarted_snapshot(prepared):
            return False
        now = self._clock()
        if now < self._next_unstarted_party_poll:
            return False
        self._next_unstarted_party_poll = now + 5.0
        generation = self._matchmaking.pvp_queue_generation
        if generation is None:
            return False
        try:
            confirmed = terminal(prepared, generation)
        except (PvpCoordinatorError, NativeLobbyError) as error:
            # Authentication/network/malformed responses cannot end a prepared
            # battle. Preserve it and retry within the existing battle lease.
            if error.code != self._unstarted_party_error:
                self._emit('companion_party_release_check_failed', reason=error.code)
            self._unstarted_party_error = error.code
            return False
        self._unstarted_party_error = None
        if confirmed is not True:
            return False
        # Do not hold this lock over Worker I/O. READY may have arrived during
        # that GET; re-read under the same lock as on_relay_event before abort.
        with self._phase_lock:
            if (self._phase_prepared is not prepared
                    or not self._unstarted_snapshot(prepared)
                    or not self._matchmaking.abort_prepared_pvp_generation(
                        generation, prepared.battle_id)):
                return False
            self._phase_prepared = None
        self._release('party_unstarted_released', generation=generation)
        return True

    def _is_assignment_status(self, status: object, view: dict | None = None) -> bool:
        if status == 'native_ready':
            if (not isinstance(view, dict) or view.get('nativeBattles') is not True
                    or view.get('nativeProtocol') != 'twa-relay-v1'
                    or 'nativePvpTest' in view):
                raise PvpCoordinatorError('invalid_public_native_protocol')
            return True
        if status == 'native_test_candidate':
            if self.allow_native_test_candidate is not True:
                raise PvpCoordinatorError('native_test_candidate_disabled')
            return True
        return status == 'awaiting_gameplay_adapter'

    def _join(self) -> None:
        self._join_attempts += 1
        if self._join_attempts > MAX_JOIN_ATTEMPTS:
            raise PvpCoordinatorError('worker_queue_rejoin_exhausted')
        sync = getattr(self._api, 'sync_loadout', None)
        local = getattr(self._matchmaking, 'pvp_local_cloud_loadout', None)
        current_sync = getattr(self._api, 'sync_current_queue', None)
        if callable(current_sync):
            current_sync()
        elif callable(sync) and callable(local):
            loadout = local()
            sync(loadout['commander_id'], loadout['item_ids'])
        view = (self._api.join_coop(self._ruleset) if self._mode == 'pve' else self._api.join(self._ruleset))
        self.state = 'joined'
        self._pending_assignment = None
        self._next_unstarted_party_poll = 0.0
        self._unstarted_party_error = None
        self.next_poll_seconds = _poll_seconds(view)
        self._emit('companion_pvp_joined', attempt=self._join_attempts,
                   worker_status=str(view.get('status', ''))[:32])
        if self._is_assignment_status(view.get('status'), view):
            self._observe_assignment(view)

    def _poll_status(self) -> None:
        view = self._api.status()
        status = view.get('status')
        self.next_poll_seconds = _poll_seconds(view)
        if status == 'queued':
            self._pending_assignment = None
            return
        if status == 'idle':
            pending, self._pending_assignment = self._pending_assignment, None
            if pending is not None:
                # The partner claimed first and the Matchmaker released both
                # queue tickets (private-server/src/matchmaking.ts claim()):
                # the assignment we already saw still resolves to that battle.
                self._emit('companion_pvp_claim_after_dequeue')
                try:
                    self._claim_assignment(pending['id'],
                                           pending.get('roster_policy'),
                                           pending.get('loadouts'),
                                           pending.get('map_key'),
                                           pending.get('teams'))
                    return
                except PvpCoordinatorError as error:
                    if error.code != 'assignment_not_found':
                        raise
                    self._emit('companion_pvp_remembered_assignment_gone')
            # Assignment expiry or a Worker-side eviction: queue again while
            # the native window allows, never silently.
            self._emit('companion_pvp_worker_idle', attempt=self._join_attempts)
            self._join()
            return
        if self._is_assignment_status(status, view):
            self._observe_assignment(view)
            return
        raise PvpCoordinatorError('invalid_worker_status')

    def _observe_assignment(self, view: dict) -> None:
        """Claim only once the assignment was seen on two polls.

        The first claim releases both queue tickets on the Worker, after which
        the partner's ``GET /v1/matchmaking`` no longer shows the assignment.
        Waiting one poll interval before claiming guarantees the partner
        (polling at the same ``pollAfterMs``) observes the id at least once
        and can claim it from memory afterwards (see ``_poll_status``).
        """
        assignment = view.get('assignment')
        if not isinstance(assignment, dict):
            raise PvpCoordinatorError('invalid_assignment')
        assignment_id = _canonical_uuid(assignment.get('id'), 'invalid_assignment_id')
        if assignment.get('mode') not in (None, self._mode) or assignment.get('ruleset') not in (None, self._ruleset):
            raise PvpCoordinatorError('assignment_mode_mismatch')
        policy = _roster_policy(assignment.get('rosterPolicy'), assignment_id, self._mode)
        observed_map = assignment.get('mapKey')
        if (observed_map is not None
                and not is_native_battle_map(observed_map, self._ruleset)):
            raise PvpCoordinatorError('invalid_assignment_map')
        # A current frozen roster policy must carry the map selected by the
        # Worker.  Only legacy assignments with no policy retain the old
        # map-less fixture compatibility.
        if policy is not None and observed_map is None:
            raise PvpCoordinatorError('invalid_assignment_map')
        loadouts = None
        teams = None
        if policy is not None:
            rows = assignment.get('participants')
            if not isinstance(rows, list) or not 1 <= len(rows) <= (10 if self._mode == 'pve' else 20):
                raise PvpCoordinatorError('invalid_pvp_participants')
            teams = []
            loadouts = []
            for index, row in enumerate(rows):
                if (not isinstance(row, dict) or not _valid_team(row.get('team'), index, self._mode, policy)
                        or not isinstance(row.get('userId'), str)):
                    raise PvpCoordinatorError('invalid_pvp_participants')
                teams.append(row['team'])
                loadouts.append((row['userId'], _loadout_identity(row.get('loadout'))))
                if loadouts[-1][1] is None:
                    raise PvpCoordinatorError('invalid_pvp_loadout')
            humans = [teams.count(0), teams.count(1)]
            if any(count > 10 for count in humans):
                raise PvpCoordinatorError('invalid_pvp_participants')
            users = [user for user, _loadout in loadouts]
            if (len(set(users)) != len(users) or self._user not in users
                    or any(not 1 <= len(user) <= 36
                           or any(ord(char) < 32 or ord(char) > 126 for char in user)
                           for user in users)):
                raise PvpCoordinatorError('invalid_pvp_participants')
            validate = getattr(self._api, 'validate_party_participants', None)
            if callable(validate):
                validate(rows, policy)
            cpu = assignment.get('cpuSeatsByTeam')
            if (not isinstance(cpu, list) or len(cpu) != 2
                    or any(type(value) is not int for value in cpu)
                    or cpu != [10 - humans[0], 10 - humans[1]]):
                raise PvpCoordinatorError('invalid_cpu_seats_by_team')
        pending = self._pending_assignment
        if pending is None or pending['id'] != assignment_id:
            self._pending_assignment = {'id': assignment_id, 'observed': 1,
                                        'roster_policy': policy,
                                        'loadouts': loadouts,
                                        'map_key': observed_map, 'teams': teams}
            self._emit('companion_pvp_assignment_observed')
            return
        if pending.get('roster_policy') != policy:
            raise PvpCoordinatorError('assignment_roster_policy_changed')
        if pending.get('loadouts') != loadouts:
            raise PvpCoordinatorError('assignment_loadout_changed')
        if pending.get('map_key') != observed_map:
            raise PvpCoordinatorError('assignment_map_changed')
        if pending.get('teams') != teams:
            raise PvpCoordinatorError('assignment_teams_changed')
        pending['observed'] += 1
        self._claim_assignment(assignment_id, policy, loadouts, observed_map, teams)

    def _claim_assignment(self, assignment_id: str,
                          assignment_policy: dict | None = None,
                          assignment_loadouts: list | None = None,
                          assignment_map_key: str | None = None,
                          assignment_teams: list | None = None) -> None:
        self._pending_assignment = None
        battle = self._api.create_battle_from_assignment(assignment_id)
        self._prepare_claim(battle, assignment_id, assignment_policy, assignment_loadouts,
                            assignment_map_key, assignment_teams)

    def _prepare_claim(self, battle: dict, assignment_id: str,
                       assignment_policy: dict | None = None,
                       assignment_loadouts: list | None = None,
                       assignment_map_key: str | None = None,
                       assignment_teams: list | None = None, *,
                       fresh_process_restart: bool = False) -> None:
        battle_id = _canonical_uuid(battle.get('battleId'), 'invalid_battle_id')
        if (battle.get('mode') != self._mode or battle.get('ruleset') != self._ruleset
                or not is_native_battle_map(battle.get('mapKey'), self._ruleset)
                or (assignment_map_key is not None
                    and battle.get('mapKey') != assignment_map_key)):
            raise PvpCoordinatorError('battle_view_mismatch')
        reward_policy = battle.get('rewardPolicy')
        if not isinstance(reward_policy, dict):
            raise PvpCoordinatorError('invalid_reward_policy')
        battle_expires_at = battle.get('expiresAt')
        if type(battle_expires_at) is not int or battle_expires_at <= 0:
            raise PvpCoordinatorError('invalid_battle_expiry')
        policy = _roster_policy(battle.get('rosterPolicy'), assignment_id, self._mode)
        if policy != assignment_policy:
            raise PvpCoordinatorError('battle_roster_policy_mismatch')
        seats = _participants(battle, self._user, policy, mode=self._mode)
        if assignment_teams is not None and [seat['team'] for seat in seats] != assignment_teams:
            raise PvpCoordinatorError('battle_teams_mismatch')
        if (assignment_loadouts is not None
                and [(seat['user_id'], seat['loadout']) for seat in seats]
                    != assignment_loadouts):
            raise PvpCoordinatorError('battle_loadout_mismatch')
        mine = next(seat for seat in seats if seat['user_id'] == self._user)
        # The rows this process uploads are the exact PvE full_squad_setup
        # rows; the Worker stores them opaquely and echoes them in the roster.
        details = self._matchmaking.pvp_local_details()
        local_loadout = self._matchmaking.pvp_local_cloud_loadout()
        if mine['loadout'] is not None and mine['loadout'] != local_loadout:
            raise PvpCoordinatorError('claimed_local_loadout_mismatch')
        rows = details['full_squad_setup']
        if not fresh_process_restart:
            self._api.put_squad(battle_id, rows)
        ticket = validate_relay_ticket(self._api.relay_ticket(battle_id),
                                       battle_id=battle_id, seat=mine)
        pvp_battle_credentials(battle, {'battleId': battle_id, 'userId': self._user,
                                        'battleKeyHex': ticket['battle_key_hex']}, self._user)
        self._claim = {'assignment_id': assignment_id, 'battle_id': battle_id,
                       'seats': seats, 'mine': mine, 'reward_policy': reward_policy,
                       'ticket': ticket, 'map_key': battle['mapKey'],
                       'battle_expires_at': battle_expires_at,
                       'fresh_process_restart': fresh_process_restart,
                       'roster_policy': policy}
        self._local_rows = rows
        self._roster_started = self._clock()
        self.state = 'awaiting_roster'
        self.next_poll_seconds = POLL_MIN_SECONDS * 2
        self._emit('companion_pvp_assigned', seat=mine['seat'], team=mine['team'],
                   player_id=mine['player_id'])
        self._poll_roster()

    def _poll_roster(self) -> None:
        claim = self._claim
        assert claim is not None
        try:
            roster = self._api.get_roster(claim['battle_id'])
        except PvpCoordinatorError as error:
            if error.code != 'roster_incomplete':
                raise
            if self._clock() - (self._roster_started or 0.0) >= self._roster_deadline:
                raise PvpCoordinatorError('roster_timeout') from None
            self.next_poll_seconds = 1.0
            return
        if roster.get('battleId') != claim['battle_id']:
            raise PvpCoordinatorError('roster_battle_mismatch')
        # Current Worker roster DTOs repeat the immutable battle identity.  A
        # D1/DO retry must not let a valid-but-different map or ruleset reach
        # NativeMatchmaking after the assignment was already frozen.  This is
        # required for both the current CPU-fill and legacy two-human policy;
        # the legacy boundary only preserves its absent rosterPolicy shape.
        if roster.get('mode') != self._mode:
            raise PvpCoordinatorError('roster_mode_mismatch')
        if roster.get('ruleset') != self._ruleset:
            raise PvpCoordinatorError('roster_ruleset_mismatch')
        if roster.get('mapKey') != claim['map_key']:
            raise PvpCoordinatorError('roster_map_mismatch')
        policy = _roster_policy(roster.get('rosterPolicy'), claim['assignment_id'], self._mode)
        if policy != claim['roster_policy']:
            raise PvpCoordinatorError('roster_policy_mismatch')
        seats = _participants(roster, self._user, policy, loadout_required=False, mode=self._mode)
        if [(s['user_id'], s['seat'], s['team'], s['player_id']) for s in seats] != [
                (s['user_id'], s['seat'], s['team'], s['player_id']) for s in claim['seats']]:
            raise PvpCoordinatorError('roster_seat_mismatch')
        claimed_loadouts = {seat['user_id']: seat['loadout']
                            for seat in claim['seats']}
        for seat in seats:
            seat['loadout'] = claimed_loadouts[seat['user_id']]
        frozen: list[dict] = []
        for seat in seats:
            rows = seat['rows']
            if isinstance(rows, dict) and isinstance(rows.get('full_squad_setup'), list):
                rows = rows['full_squad_setup']
            if seat['user_id'] == self._user:
                if rows != self._local_rows:
                    raise PvpCoordinatorError('roster_local_rows_mismatch')
                details = self._matchmaking.pvp_local_details()
            else:
                details = self._matchmaking.pvp_opponent_details(rows)
                if (seat['loadout'] is not None
                        and self._matchmaking.pvp_rows_cloud_loadout(rows)
                        != seat['loadout']):
                    raise PvpCoordinatorError('opponent_loadout_mismatch')
            frozen.append({'user_id': seat['user_id'], 'seat': seat['seat'],
                           'team': seat['team'], 'player_id': seat['player_id'],
                           'details': details})
        ticket = claim['ticket']
        mine = claim['mine']
        user_ids = tuple(seat['user_id'] for seat in frozen)
        prepared = PreparedPvpBattle(
            battle_id=claim['battle_id'], battle_key_hex=ticket['battle_key_hex'],
            assignment_id=claim['assignment_id'], ruleset=self._ruleset or '',
            map_key=claim['map_key'], seat=mine['seat'], team=mine['team'],
            player_id=mine['player_id'],
            user_ids=user_ids,  # type: ignore[arg-type]
            opponent_user_id=next((
                seat['user_id'] for seat in frozen
                if seat['team'] != mine['team']), ''),
            relay_url=derive_relay_ws_url(self._api_base_url, ticket['relay_url']),
            reward_policy=copy.deepcopy(claim['reward_policy']),
            battle_expires_at=claim['battle_expires_at'], mode=self._mode,
            fresh_process_restart=claim.get('fresh_process_restart', False))
        ticket_source = RelayTicketSource(
            self._api, prepared.battle_id, mine, ticket,
            clock_ms=self._ticket_clock_ms, trace=self._trace,
            fresh_process_restart=prepared.fresh_process_restart)
        # Listen on loopback 19000 *before* the queue can announce
        # battle_ready: the game connects a few HTTP round trips after /check.
        # A relay that cannot start fails the queue closed instead of handing
        # the client an unplayable battle.
        self.prepared = prepared
        self.ticket_source = ticket_source
        if self._on_prepared is not None:
            try:
                self._on_prepared(prepared, ticket_source)
            except Exception as error:  # noqa: BLE001 - reported, then fail closed
                self._emit('companion_pvp_relay_start_failed', reason=type(error).__name__)
                raise PvpCoordinatorError('relay_bridge_start_failed') from None
        self._matchmaking.bind_pvp_battle(
            assignment_id=claim['assignment_id'], battle_id=claim['battle_id'],
            battle_key=ticket['battle_key_hex'], seats=frozen,
            reward_policy=claim['reward_policy'], roster_policy=policy,
            party_groups=roster.get('partyGroups'),
            map_key=claim['map_key'],
            battle_lifetime_seconds=max(
                0.001, (claim['battle_expires_at'] * 1000
                        - (self._ticket_clock_ms or
                           (lambda: time.time_ns() // 1_000_000))()) / 1000.0))
        with self._phase_lock:
            self._phase_prepared = prepared
        self.state = 'prepared'
        self.next_poll_seconds = DEFAULT_POLL_SECONDS
        self._emit('companion_pvp_prepared', **prepared.as_trace())

    def _fail(self, code: str) -> None:
        self.last_error = code
        self._emit('companion_pvp_failed', reason=code, state=self.state)
        try:
            self._matchmaking.abort_pvp(code)
        except Exception:  # noqa: BLE001 - the queue may already be gone
            pass
        self._release(code)

    def _release(self, reason: str, *, generation=None) -> None:
        previous, prepared = self.state, self.prepared
        with self._phase_lock:
            self._phase_prepared = None
        if previous == 'joined':
            try:
                self._api.cancel()
                self._emit('companion_pvp_worker_cancelled', reason=reason)
            except PvpCoordinatorError as error:
                self._emit('companion_pvp_worker_cancel_failed', reason=error.code)
        released = getattr(self._api, 'released', None)
        if callable(released):
            if generation is None:
                released(reason)
            else:
                released(reason, generation=generation)
        self.state = 'idle'
        self.prepared = None
        self.ticket_source = None
        self._claim = None
        self._local_rows = None
        self._pending_assignment = None
        self._queue_started = None
        self._roster_started = None
        self._join_attempts = 0
        self.next_poll_seconds = DEFAULT_POLL_SECONDS
        if previous != 'idle':
            self._emit('companion_pvp_released', reason=reason, previous_state=previous)
            if self._on_released is not None:
                try:
                    self._on_released(prepared, reason)
                except Exception as error:  # noqa: BLE001
                    self._emit('companion_pvp_release_hook_failed', reason=type(error).__name__)

    # -- supervision --------------------------------------------------------

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self.step()
            except Exception as error:  # noqa: BLE001 - never let the thread die silently
                self._emit('companion_pvp_crashed', reason=type(error).__name__)
                with self._lock:
                    self._fail('coordinator_error')
            self._stop.wait(max(POLL_MIN_SECONDS, min(POLL_MAX_SECONDS, self.next_poll_seconds)))

    def start(self) -> None:
        self._thread = threading.Thread(target=self.run, daemon=True, name='companion-pvp')
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=5.0)

    def _emit(self, event: str, **fields) -> None:
        _emit(self._trace, event, **fields)


def _emit(trace: Callable[[dict], None] | None, event: str, **fields) -> None:
    if trace is None:
        return
    try:
        trace({'event': event, **fields})
    except Exception:  # pragma: no cover - tracing never fails a battle
        pass


__all__ = [
    'DurableObjectRelayRunner',
    'POLL_MAX_SECONDS',
    'POLL_MIN_SECONDS',
    'PreparedPvpBattle',
    'PvpCoordinator',
    'PvpCoordinatorError',
    'ROSTER_DEADLINE_SECONDS',
    'RelayTicketSource',
    'TICKET_RENEW_MARGIN_MS',
    'TicketedRelayBridge',
    'WorkerPvpApi',
    'canonical_battle_key_hex',
    'derive_relay_ws_url',
    'pvp_battle_credentials',
    'validate_relay_ticket',
]
