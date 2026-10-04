"""Explicit, single-client, loopback native battle loading/tick experiment.

It validates the queue-specific battle ID, key and local roster against shared
SQLite state, confirms player 1, and echoes that client's join payload once.
The historical fixed lab fixture requires an explicit diagnostic flag. By
default no GAME_TICKING or commands are provided. ``--enable-bounded-ticks``
retains the short 50..600 step protocol diagnostic. ``--enable-natural-ticks``
instead keeps the 200ms clock running until the native peer finishes, with a
30-minute session deadline, idle I/O, packet-rate and retained-stream bounds.
Those safety bounds are not treated as normal battle completion.  An explicit
reconnect opt-in retains one session briefly, without CPU takeover. Results
and rewards are handled separately. Opaque payloads stay in bounded memory
only while needed; logs contain metadata only.

Original game.dll file offsets: BCC090 (GAME_CONFIRM), BF2D70 (client
JOIN_PAYLOAD), BCC110 (server JOIN_PAYLOADS), B774F0 (prepare session),
BF2FF0 (client READY_FOR_TICKING). See the independent static analysis.
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import socket
import struct
import sys
import time
from pathlib import Path

if not __package__:
    # The distributed interpreter ignores the script directory via ._pth.
    # Direct relay startup must still resolve its reviewed sibling modules.
    _SERVER_ROOT = Path(__file__).resolve().parent
    sys.path[:0] = [str(_SERVER_ROOT), str(_SERVER_ROOT.parent)]

from companion.loopback_ports import annotate_bind_error, bind_failure_code

if __package__:
    from .native_relay_probe import (
        GREETING, VERSION, GameJoinDecodeError, game_join_metadata,
        inner_packet, stream_chunk,
    )
else:
    from native_relay_probe import (
        GREETING, VERSION, GameJoinDecodeError, game_join_metadata,
        inner_packet, stream_chunk,
    )

if __package__:
    from .local_battle_state import (BattleStateError, DEFAULT_BATTLE_STATE_PATH,
                                     LocalBattleState)
else:
    from local_battle_state import (BattleStateError, DEFAULT_BATTLE_STATE_PATH,
                                    LocalBattleState)

LAB_BATTLE_ID = '00000000-0000-4000-8000-000000000001'
LAB_BATTLE_KEY = 1
LAB_NATIVE_USER_ID = 'player'
LOCAL_PLAYER_ID = 1
RELAY_PORT = 19000
MAX_INNER_BYTES = 4096
MAX_JOIN_PAYLOAD_BYTES = 2048  # Entire client packet, BF2D98.
MAX_CHUNK_BYTES = 16384
TICK_INTERVAL_SECONDS = 0.2
MAX_BOUNDED_TICKS = 50
MAX_CONFIGURED_TICKS = 600
OBSERVATION_CONNECTION_SECONDS = 180
MAX_OBSERVATION_PACKETS = 300
NATURAL_CONNECTION_SECONDS = 30 * 60
MIN_NATURAL_CONNECTION_SECONDS = 10 * 60
MAX_NATURAL_CONNECTION_SECONDS = 2 * 60 * 60
MAX_NATURAL_PACKETS = 100_000
NATURAL_READ_IDLE_SECONDS = 5 * 60
MAX_PENDING_COMMANDS = 32
MAX_PENDING_CIPHERTEXT_BYTES = 4096
MAX_RETAINED_SERVER_STREAM_BYTES = 4 * 1024 * 1024
MAX_RECONNECTS = 3
RECONNECT_GRACE_SECONDS = 30
TRANSPORT_DRAIN_TIMEOUT_SECONDS = 10


class BattleProbeError(ValueError):
    """A constant reason code, never packet data or exception contents."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def validate_lab_join(packet: bytes, expected_players: int = 2) -> dict:
    """Require the explicit local fixture; these checks are not authentication.

Expected player count remains an experimental input (1 or 2). The default
fixture contains one human and one CPU row, but whether the native sender
counts both must be established by the actual GAME_JOIN observation.
"""
    if type(expected_players) is not int or expected_players not in (1, 2):
        raise ValueError('expected_players must be 1 or 2')
    try:
        metadata = game_join_metadata(packet)
    except GameJoinDecodeError as exc:
        raise BattleProbeError('join_' + exc.code) from None
    if struct.unpack_from('<I', packet, 3)[0] != VERSION:
        raise BattleProbeError('join_version')
    if packet[7:44] != LAB_BATTLE_ID.encode('ascii') + b'\0':
        raise BattleProbeError('join_battle_id')
    if struct.unpack_from('<Q', packet, 44)[0] != LAB_BATTLE_KEY:
        raise BattleProbeError('join_lab_key')
    identity = LAB_NATIVE_USER_ID.encode('ascii')
    if packet[52:89] != identity + bytes(37 - len(identity)):
        raise BattleProbeError('join_native_identity')
    if packet[89] != expected_players:
        raise BattleProbeError('join_expected_players')
    if struct.unpack_from('<H', packet, 90)[0] != 200:
        raise BattleProbeError('join_normal_parameter')
    for address_offset, port_offset in ((92, 96), (98, 102)):
        if not ipaddress.IPv4Address(packet[address_offset:address_offset + 4]).is_loopback:
            raise BattleProbeError('join_endpoint_not_loopback')
        if not struct.unpack_from('<H', packet, port_offset)[0]:
            raise BattleProbeError('join_endpoint_port')
    return metadata


def _state_expected_players(battle_state: LocalBattleState, battle_id: str) -> int:
    """Read the immutable wire roster count from a battle credential.

    The native count is not the number of enrolled transports: the private
    CPU lobby has one human transport while GAME_JOIN reports two roster
    entries.  Only the count frozen by the HTTP allocator is authoritative.
    """
    try:
        expected_players = battle_state.snapshot(battle_id)['expected_players']
    except BattleStateError as error:
        raise BattleProbeError('battle_state_' + error.code) from None
    if expected_players is None:
        raise BattleProbeError('battle_state_battle_credentials_missing')
    if type(expected_players) is not int or expected_players not in (1, 2):
        raise BattleProbeError('battle_state_expected_players_unsupported')
    return expected_players


def _resolve_state_battle_id(battle_state: LocalBattleState,
                             wire_battle_id: str) -> str:
    """Resolve a native room UUID to the current immutable battle row."""
    try:
        return battle_state.resolve_wire_battle_id(wire_battle_id)
    except BattleStateError as error:
        raise BattleProbeError('battle_state_' + error.code) from None


def validate_state_join(packet: bytes, battle_state: LocalBattleState,
                        expected_players: int | None = None) -> tuple[dict, str]:
    """Authorize GAME_JOIN against the shared matchmaking allocation.

    Only redacted metadata is returned for logging.  The battle ID is returned
    separately for the internal READY transition; the battle key and native
    user identity never leave this function.
    """
    if not isinstance(battle_state, LocalBattleState):
        raise ValueError('battle_state must be LocalBattleState')
    # Keep the historical positional argument source-compatible for the
    # multiplayer adapter, but never use it to authorize a state-backed JOIN.
    # A single relay must accept both the one-entry public PvE wire roster and
    # the two-entry private human+CPU wire roster.
    if expected_players is not None and (
            type(expected_players) is not int or expected_players not in (1, 2)):
        raise ValueError('expected_players must be 1 or 2')
    try:
        metadata = game_join_metadata(packet)
    except GameJoinDecodeError as exc:
        raise BattleProbeError('join_' + exc.code) from None
    if struct.unpack_from('<I', packet, 3)[0] != VERSION:
        raise BattleProbeError('join_version')
    if not metadata['game_id_canonical_uuid']:
        raise BattleProbeError('join_battle_id')
    try:
        battle_id = packet[7:43].decode('ascii', 'strict')
    except UnicodeDecodeError:
        raise BattleProbeError('join_battle_id') from None
    battle_key = struct.unpack_from('<Q', packet, 44)[0]
    identity_slot = packet[52:89]
    end = identity_slot.find(b'\0')
    if (end <= 0 or any(identity_slot[end:])
            or not all(32 <= byte <= 126 for byte in identity_slot[:end])):
        raise BattleProbeError('join_native_identity')
    try:
        user_id = identity_slot[:end].decode('ascii', 'strict')
    except UnicodeDecodeError:
        raise BattleProbeError('join_native_identity') from None
    if struct.unpack_from('<H', packet, 90)[0] != 200:
        raise BattleProbeError('join_normal_parameter')
    for address_offset, port_offset in ((92, 96), (98, 102)):
        if not ipaddress.IPv4Address(packet[address_offset:address_offset + 4]).is_loopback:
            raise BattleProbeError('join_endpoint_not_loopback')
        if not struct.unpack_from('<H', packet, port_offset)[0]:
            raise BattleProbeError('join_endpoint_port')
    internal_battle_id = _resolve_state_battle_id(battle_state, battle_id)
    stored_expected_players = _state_expected_players(
        battle_state, internal_battle_id)
    try:
        # Authenticate the key and user against the frozen allocation before
        # comparing the packet's public count.  The packet never selects the
        # count passed to LocalBattleState.
        battle_state.validate_relay_join(
            internal_battle_id, battle_key, user_id, stored_expected_players)
    except BattleStateError as error:
        raise BattleProbeError('battle_state_' + error.code) from None
    if packet[89] != stored_expected_players:
        raise BattleProbeError('join_expected_players')
    redacted = dict(metadata)
    redacted['credentials_verified'] = True
    redacted['expected_players_source'] = 'battle_state_credentials'
    return redacted, internal_battle_id


def encode_join_payloads(entries: list[tuple[int, bytes]]) -> bytes:
    """Build one native ``GAME_JOIN_PAYLOADS`` packet for human seats.

    Each opaque client payload is encrypted with a seed which includes the
    player id assigned by ``GAME_CONFIRM``.  The relay therefore validates the
    framing but never decrypts, rewrites, or logs those bytes.  Callers must
    supply the same stable player ids they confirmed to the corresponding
    clients.  The returned packet is suitable for broadcasting byte-for-byte
    to every participant after all expected payloads have arrived.

    This is only the serialization primitive.  ``NativeBattleProbe`` remains a
    single-transport experiment until a battle coordinator owns multiple peer
    sessions and applies the required all-joined barrier.
    """
    if type(entries) is not list or not 1 <= len(entries) <= 20:
        raise BattleProbeError('join_payloads_count')
    player_ids: set[int] = set()
    validated: list[tuple[int, bytes, int]] = []
    body = bytearray(struct.pack('<I', len(entries)))
    for player_id, packet in entries:
        if type(player_id) is not int or not 1 <= player_id <= 20:
            raise BattleProbeError('join_payload_player_id')
        if player_id in player_ids:
            raise BattleProbeError('join_payload_player_id_duplicate')
        player_ids.add(player_id)
        if type(packet) is not bytes or not 9 <= len(packet) <= MAX_JOIN_PAYLOAD_BYTES:
            raise BattleProbeError('payload_packet_length')
        kind, total, payload_size = struct.unpack_from('<BHI', packet)
        if kind != 1 or total != len(packet):
            raise BattleProbeError('payload_framing')
        if payload_size != len(packet) - 7 or packet[7] != 1:
            raise BattleProbeError('payload_declared_size_or_flag')
        validated.append((player_id, packet, payload_size))
    # Native clients must see one canonical roster regardless of which peer's
    # payload reached the coordinator first.  Existing one-player echo output
    # is unchanged.
    for player_id, packet, payload_size in sorted(validated):
        body.extend(struct.pack('<II', player_id, payload_size))
        body.extend(packet[7:])
    total = len(body) + 3
    # BCC110 accepts a kind-2 packet through 0x4000 bytes.  This is wider than
    # the generic 4096-byte diagnostic helper because it carries the complete
    # roster's payloads in one frame.
    if total > MAX_CHUNK_BYTES:
        # Do not split the roster across packets because that barrier behavior
        # is unverified.
        raise BattleProbeError('join_payloads_packet_too_large')
    return struct.pack('<BH', 2, total) + body


def echo_join_payload(packet: bytes) -> bytes:
    """Build the existing one-human JOIN_PAYLOADS response."""
    return encode_join_payloads([(LOCAL_PLAYER_ID, packet)])


def echo_unticked(packet: bytes) -> bytes:
    """Native kind 6 -> kind 10 for this local one-human transport.

    The cloud relay routes the same recipient mask across authenticated human
    seats. This local diagnostic transport only owns LOCAL_PLAYER_ID.
    """
    if type(packet) is not bytes or not 8 <= len(packet) <= 4003:
        raise BattleProbeError('unticked_packet_length')
    kind, total, recipients, channel = struct.unpack_from('<BHIB', packet)
    if kind != 6 or total != len(packet):
        raise BattleProbeError('unticked_framing')
    if not recipients & (1 << LOCAL_PLAYER_ID):
        return b''
    return inner_packet(10, bytes((LOCAL_PLAYER_ID, channel)) + packet[8:])


def validate_ready_packet(packet: bytes) -> None:
    """Validate BF2FF0's header and native UTF-16-code-unit UTF/CESU-8 body.

2C11A0 counts 1..3 encoded bytes per non-NUL UTF-16 code unit. BF3028
sends that count, excluding the terminator; an empty source string is valid.
This validates the wire shape only, not the meaning of the private string.
"""
    if type(packet) is not bytes or not 3 <= len(packet) <= MAX_INNER_BYTES:
        raise BattleProbeError('ready_packet_length')
    kind, total = struct.unpack_from('<BH', packet)
    if kind != 5 or total != len(packet):
        raise BattleProbeError('ready_framing')
    try:
        value = packet[3:].decode('utf-8', errors='surrogatepass')
    except UnicodeDecodeError:
        raise BattleProbeError('ready_string_encoding') from None
    if any(ord(char) == 0 or ord(char) > 0xffff for char in value):
        raise BattleProbeError('ready_string_encoding')


class BoundedTicks:
    """Pure single-human clock/queue; it neither sends nor logs payloads.

    ``max_ticks=None`` is the natural-completion clock.  It has no artificial
    tick finish and tolerates scheduler delay by skipping catch-up ticks.  The
    owning session still applies elapsed-time, packet and memory safety bounds.
    """

    def __init__(self, max_ticks: int | None = MAX_BOUNDED_TICKS):
        if max_ticks is not None and (
                type(max_ticks) is not int or not 1 <= max_ticks <= MAX_CONFIGURED_TICKS):
            raise ValueError('max_ticks must be an integer from 1 to 600')
        self.started = False
        self.next_at = 0.0
        self.count = 0
        self.commands = []
        self.command_bytes = 0
        self.last_command_count = 0
        self.last_command_bytes = 0
        self.max_ticks = max_ticks
        self.strict_clock = max_ticks is not None

    def begin(self, packet: bytes, now: float) -> bytes:
        if self.started:
            raise BattleProbeError('duplicate_ready')
        validate_ready_packet(packet)
        self.started = True
        self.next_at = now + TICK_INTERVAL_SECONDS
        # BCC400 then BCC330. Only the real local human is marked loaded.
        return inner_packet(8, struct.pack('<I', LOCAL_PLAYER_ID)) + inner_packet(3)

    def queue_command(self, packet: bytes) -> None:
        if not self.started:
            raise BattleProbeError('command_before_ready')
        # Returning it adds one player-id byte. Keep both frames <=4096.
        if type(packet) is not bytes or not 4 <= len(packet) < MAX_INNER_BYTES:
            raise BattleProbeError('command_packet_length')
        kind, total = struct.unpack_from('<BH', packet)
        if kind != 3 or total != len(packet):
            raise BattleProbeError('command_framing')
        cipher = packet[3:]
        if len(self.commands) >= MAX_PENDING_COMMANDS:
            raise BattleProbeError('command_queue_overflow')
        if self.command_bytes + len(cipher) > MAX_PENDING_CIPHERTEXT_BYTES:
            raise BattleProbeError('command_bytes_overflow')
        self.commands.append(cipher)  # Memory-only, ordered, never decrypted.
        self.command_bytes += len(cipher)

    def resume(self, now: float) -> None:
        """Resume the lab clock without manufacturing catch-up ticks."""
        if self.started:
            self.next_at = now + TICK_INTERVAL_SECONDS

    def take_due(self, now: float) -> bytes | None:
        if not self.started or now < self.next_at:
            return None
        if self.max_ticks is not None and self.count >= self.max_ticks:
            raise BattleProbeError('tick_limit')
        if self.strict_clock and now - self.next_at >= TICK_INTERVAL_SECONDS:
            raise BattleProbeError('tick_clock_overrun')
        self.last_command_count = len(self.commands)
        self.last_command_bytes = self.command_bytes
        if not self.commands:
            packet = inner_packet(5, struct.pack('<I', 1 << LOCAL_PLAYER_ID))
        else:
            # Keep each independently framed cipher stream intact. The native
            # receiver processes these server4 packets in order from one outer
            # chunk; it assigns one implicit tick per packet.
            packet = b''.join(inner_packet(4, bytes((LOCAL_PLAYER_ID,)) + cipher)
                              for cipher in self.commands)
            self.commands.clear()
            self.command_bytes = 0
        self.count += 1
        # Never catch up with a burst after a delay.
        self.next_at = now + TICK_INTERVAL_SECONDS
        return packet


async def read_outer_chunk(reader: asyncio.StreamReader,
                           idle_timeout: float = 30) -> bytes:
    """One bounded CAReconn chunk; empty bytes denotes its credit ACK."""
    header = await asyncio.wait_for(reader.readexactly(2), idle_timeout)
    size = struct.unpack('<H', header)[0]
    if size > MAX_CHUNK_BYTES:
        raise BattleProbeError('outer_chunk_too_large')
    if size == 0:
        return b''
    return await asyncio.wait_for(reader.readexactly(size), 10)


async def drain_transport(writer: asyncio.StreamWriter, deadline: float,
                          timeout_seconds: float = TRANSPORT_DRAIN_TIMEOUT_SECONDS) -> None:
    """Bound flow control by both a short transport timeout and the session."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise BattleProbeError('session_deadline')
    await asyncio.wait_for(writer.drain(), min(timeout_seconds, remaining))


class BattleSession:
    """State retained across an explicitly enabled CAReconn transport retry."""

    def __init__(self, max_ticks: int | None,
                 connection_seconds: int = OBSERVATION_CONNECTION_SECONDS):
        self.phase = 'await_join'
        self.pending = bytearray()
        self.ticks = BoundedTicks(max_ticks)
        self.packets = 0
        self.client_stream_bytes = 0
        self.our_ack_bytes = 0
        self.server_stream = bytearray()
        self.peer_ack_bytes = 0
        self.peer_received_offset = 0
        self.identity = b''
        self.battle_id: str | None = None
        self.last_attempt = -1
        self.reconnects = 0
        self.deadline = time.monotonic() + connection_seconds
        self.disconnected_at = None
        self.drop_done = False
        self.terminal = False

    def terminate(self) -> None:
        """Make retained opaque state unreachable after the session expires."""
        self.terminal = True
        self.pending.clear()
        self.ticks.commands.clear()
        self.ticks.command_bytes = 0
        self.server_stream.clear()
        self.identity = b''


class NativeBattleProbe:
    """Single local battle session with optional bounded transport resume."""

    def __init__(self, trace: Path, *, enable_join_payload_echo: bool = False,
                 expected_players: int = 2, enable_bounded_ticks: bool = False,
                 max_bounded_ticks: int = MAX_BOUNDED_TICKS,
                 enable_natural_ticks: bool = False,
                 natural_connection_seconds: int = NATURAL_CONNECTION_SECONDS,
                 battle_state: LocalBattleState | None = None,
                 legacy_lab_credentials: bool = False,
                 enable_reconnect: bool = False,
                 drop_transport_at_tick: int | None = None):
        if enable_join_payload_echo is not True:
            raise ValueError('explicit join-payload echo opt-in required')
        if type(expected_players) is not int or expected_players not in (1, 2):
            raise ValueError('expected_players must be 1 or 2')
        if type(enable_bounded_ticks) is not bool:
            raise ValueError('enable_bounded_ticks must be an explicit boolean')
        if type(enable_natural_ticks) is not bool:
            raise ValueError('enable_natural_ticks must be an explicit boolean')
        if enable_bounded_ticks and enable_natural_ticks:
            raise ValueError('bounded and natural ticks are mutually exclusive')
        if type(max_bounded_ticks) is not int or not 1 <= max_bounded_ticks <= MAX_CONFIGURED_TICKS:
            raise ValueError('max_bounded_ticks must be an integer from 1 to 600')
        if not enable_bounded_ticks and max_bounded_ticks != MAX_BOUNDED_TICKS:
            raise ValueError('custom max_bounded_ticks requires enable_bounded_ticks')
        if (type(natural_connection_seconds) is not int or
                not MIN_NATURAL_CONNECTION_SECONDS <= natural_connection_seconds <= MAX_NATURAL_CONNECTION_SECONDS):
            raise ValueError('natural_connection_seconds must be an integer from 600 to 7200')
        if not enable_natural_ticks and natural_connection_seconds != NATURAL_CONNECTION_SECONDS:
            raise ValueError('custom natural_connection_seconds requires enable_natural_ticks')
        if battle_state is not None and not isinstance(battle_state, LocalBattleState):
            raise ValueError('battle_state must be LocalBattleState or None')
        if type(legacy_lab_credentials) is not bool:
            raise ValueError('legacy_lab_credentials must be an explicit boolean')
        if ((battle_state is None and not legacy_lab_credentials)
                or (battle_state is not None and legacy_lab_credentials)):
            raise ValueError('choose battle_state or explicit legacy lab credentials')
        if type(enable_reconnect) is not bool:
            raise ValueError('enable_reconnect must be an explicit boolean')
        if drop_transport_at_tick is not None:
            if type(drop_transport_at_tick) is not int or drop_transport_at_tick < 1:
                raise ValueError('drop_transport_at_tick must be a positive integer')
            if enable_bounded_ticks and drop_transport_at_tick >= max_bounded_ticks:
                raise ValueError('drop_transport_at_tick must precede the configured tick limit')
            if not enable_reconnect or not (enable_bounded_ticks or enable_natural_ticks):
                raise ValueError('drop_transport_at_tick requires reconnect and ticking')
        self.trace_path = Path(trace)
        self.expected_players = expected_players
        self.enable_bounded_ticks = enable_bounded_ticks
        self.enable_natural_ticks = enable_natural_ticks
        self.enable_ticks = enable_bounded_ticks or enable_natural_ticks
        self.max_bounded_ticks = max_bounded_ticks
        self.tick_limit = None if enable_natural_ticks else max_bounded_ticks
        self.connection_seconds = (natural_connection_seconds if enable_natural_ticks
                                   else OBSERVATION_CONNECTION_SECONDS)
        self.packet_limit = (MAX_NATURAL_PACKETS if enable_natural_ticks
                             else MAX_OBSERVATION_PACKETS)
        self.read_idle_seconds = (NATURAL_READ_IDLE_SECONDS if enable_natural_ticks else 30)
        self.battle_state = battle_state
        self.legacy_lab_credentials = legacy_lab_credentials
        self.enable_reconnect = enable_reconnect
        self.drop_transport_at_tick = drop_transport_at_tick
        self.claimed = False
        self.active_transport = False
        self.session = None

    def _validate_join(self, packet: bytes) -> tuple[dict, str]:
        if self.battle_state is not None:
            return validate_state_join(packet, self.battle_state)
        return validate_lab_join(packet, self.expected_players), LAB_BATTLE_ID

    def _authoritative_expected_players(self, packet: bytes) -> int | None:
        """Resolve a count only for redacted mismatch diagnostics.

        State-backed callers invoke this after ``validate_state_join`` has
        authenticated the allocation and raised ``join_expected_players``.
        Malformed packets and missing/retired credentials produce no count.
        """
        if self.battle_state is None:
            return self.expected_players
        if type(packet) is not bytes or len(packet) != 105:
            return None
        try:
            battle_id = packet[7:43].decode('ascii', 'strict')
            battle_id = _resolve_state_battle_id(self.battle_state, battle_id)
            return _state_expected_players(self.battle_state, battle_id)
        except (UnicodeDecodeError, BattleProbeError):
            return None

    def _validate_join_with_mismatch_log(self, packet: bytes) -> tuple[dict, str]:
        try:
            return self._validate_join(packet)
        except BattleProbeError as error:
            if error.code == 'join_expected_players' and len(packet) == 105:
                expected_players = self._authoritative_expected_players(packet)
                if expected_players is not None:
                    # Counts are public roster metadata.  Never log the
                    # identity, credential, packet, or a fingerprint of it.
                    self.log('expected_players_mismatch', observed=packet[89],
                             expected=expected_players,
                             expected_source=('battle_state_credentials'
                                              if self.battle_state is not None
                                              else 'legacy_fixture'))
            raise

    def _mark_battle_ticking(self, battle_id: str) -> None:
        if self.battle_state is None:
            return
        try:
            self.battle_state.start_ticking(battle_id)
        except BattleStateError as error:
            raise BattleProbeError('battle_state_' + error.code) from None

    def _retire_battle_join(self, battle_id: str | None) -> bool:
        """Persistently revoke one completed relay credential before reuse."""
        if battle_id is None or self.battle_state is None:
            return True
        try:
            self.battle_state.retire_relay_join(battle_id)
        except BattleStateError as error:
            self.log('battle_join_retirement_failed', reason=error.code)
            return False
        return True

    def _release_terminal_session(self, session: BattleSession) -> bool:
        """Release a terminal session only after its old join is revoked."""
        if self.session is not session or not session.terminal:
            return False
        if not self._retire_battle_join(session.battle_id):
            return False
        session.battle_id = None
        self.session = None
        self.log('battle_session_released', reason='terminal')
        return True

    def _release_completed_session(self) -> bool:
        """Release a detached session after HTTP persisted its final event."""
        session = self.session
        if (session is None or session.terminal or session.battle_id is None
                or self.battle_state is None):
            return False
        try:
            phase = self.battle_state.snapshot(session.battle_id)['phase']
        except BattleStateError as error:
            self.log('battle_completion_check_failed', reason=error.code)
            return False
        if phase not in {'result_reported', 'result_ready', 'settled', 'delivered'}:
            return False
        if not self._retire_battle_join(session.battle_id):
            return False
        session.terminate()
        session.battle_id = None
        self.session = None
        self.log('battle_session_released', reason='completed')
        return True

    def log(self, event: str, **fields):
        row = {'time': time.time(), 'event': event, **fields}
        with self.trace_path.open('a', encoding='utf-8') as output:
            output.write(json.dumps(row, separators=(',', ':')) + '\n')
        print(json.dumps(row), flush=True)

    def _expire_retained_session(self, session: BattleSession, detached_at: float) -> None:
        """Erase a disconnected session once its short resume window closes."""
        if (self.session is not session or session.terminal or
                session.disconnected_at != detached_at):
            return
        expires_at = min(detached_at + RECONNECT_GRACE_SECONDS, session.deadline)
        now = time.monotonic()
        if now < expires_at:
            asyncio.get_running_loop().call_later(
                expires_at - now, self._expire_retained_session, session, detached_at)
            return
        session.terminate()
        if self._release_terminal_session(session):
            self.log('resume_window_expired', tick=session.ticks.count,
                     cpu_takeover=False, gameplay_supported=False)

    async def _handle_without_resume(self, reader: asyncio.StreamReader,
                                     writer: asyncio.StreamWriter):
        phase = 'greeting'
        pending = bytearray()
        ticks = BoundedTicks(self.tick_limit)
        battle_id = None
        read_task = None
        owns_claim = False
        try:
            peer = writer.get_extra_info('peername')
            if not peer or peer[0] != '127.0.0.1':
                self.log('rejected', reason='peer_not_loopback')
                return
            if self.claimed:
                self.log('rejected', reason='single_connection_only')
                return
            # Claim synchronously before any await. Reusing a probe instance
            # cannot accidentally allocate a second participant or reconnect.
            self.claimed = True
            owns_claim = True
            self.log('connection', gameplay_supported=False)
            greeting = await asyncio.wait_for(reader.readexactly(40), 15)
            if greeting[:11] != GREETING:
                raise BattleProbeError('greeting_magic')
            if greeting[11] or struct.unpack_from('<Q', greeting, 32)[0]:
                raise BattleProbeError('resume_not_supported')
            self.log('careconn_greeting', bytes=40, reconnect=False)
            del greeting
            writer.write(bytes(17))  # First connection only, never a resume.
            version = inner_packet(13, struct.pack('<I', VERSION))
            writer.write(stream_chunk(version))
            await writer.drain()
            sent_bytes = len(version)
            peer_ack_bytes = 0
            received_bytes = 0
            our_ack_bytes = 0
            packets = 0
            phase = 'await_join'
            self.log('version_sent', version=VERSION)
            deadline = time.monotonic() + self.connection_seconds

            async def flush_due_tick():
                nonlocal sent_bytes
                now = time.monotonic()
                if not ticks.started or now < ticks.next_at:
                    return False
                if pending:
                    raise BattleProbeError('tick_incomplete_packet')
                tick_packet = ticks.take_due(now)
                writer.write(stream_chunk(tick_packet))
                sent_bytes += len(tick_packet)
                await drain_transport(writer, deadline)
                self.log('battle_tick_sent' if self.enable_natural_ticks else 'bounded_tick_sent',
                         tick=ticks.count,
                         kind=tick_packet[0], stream_bytes=len(tick_packet),
                         command_count=ticks.last_command_count,
                         command_payload_bytes=ticks.last_command_bytes,
                         local_player_id=LOCAL_PLAYER_ID,
                         command_semantics_verified=False, gameplay_supported=False)
                if ticks.max_ticks is not None and ticks.count >= ticks.max_ticks:
                    self.log('bounded_tick_limit', ticks=ticks.count,
                             normal_battle_completion=False, gameplay_supported=False)
                    return True
                return False

            while time.monotonic() < deadline and packets < self.packet_limit:
                if read_task is None:
                    read_task = asyncio.create_task(
                        read_outer_chunk(reader, self.read_idle_seconds))
                now = time.monotonic()
                timeout = max(0, deadline - now)
                if ticks.started:
                    timeout = min(timeout, max(0, ticks.next_at - now))
                done, _ = await asyncio.wait((read_task,), timeout=timeout)
                if not done:
                    if time.monotonic() >= deadline:
                        break
                    if await flush_due_tick():
                        return
                    continue
                chunk = read_task.result()
                read_task = None
                if not chunk:
                    peer_ack_bytes += 1000
                    if peer_ack_bytes > sent_bytes:
                        raise BattleProbeError('ack_beyond_sent_stream')
                    self.log('stream_ack')
                    if await flush_due_tick():
                        return
                    continue
                received_bytes += len(chunk)
                pending.extend(chunk)
                del chunk
                while received_bytes - our_ack_bytes >= 1000:
                    writer.write(b'\0\0')
                    our_ack_bytes += 1000
                await drain_transport(writer, deadline)
                while len(pending) >= 3:
                    kind, total = struct.unpack_from('<BH', pending)
                    if not 3 <= total <= MAX_INNER_BYTES:
                        raise BattleProbeError('inner_length')
                    if len(pending) < total:
                        break
                    packet = bytes(pending[:total])
                    del pending[:total]
                    packets += 1
                    if packets > self.packet_limit:
                        raise BattleProbeError('packet_limit')
                    self.log('client_packet', kind=kind, total=total, phase=phase)
                    if kind == 4:
                        if total != 3:
                            raise BattleProbeError('keepalive_length')
                    elif kind == 0:
                        if phase != 'await_join':
                            raise BattleProbeError('join_order')
                        metadata, battle_id = self._validate_join_with_mismatch_log(packet)
                        self.log('battle_join_validated', **metadata,
                                 credential_source=('sqlite' if self.battle_state is not None
                                                    else 'legacy_fixture'))
                        confirmation = inner_packet(0, struct.pack('<I', LOCAL_PLAYER_ID))
                        writer.write(stream_chunk(confirmation))
                        await writer.drain()
                        sent_bytes += len(confirmation)
                        phase = 'await_payload'
                        self.log('game_confirm_sent', local_player_id=LOCAL_PLAYER_ID,
                                 gameplay_supported=False)
                    elif kind == 1:
                        if phase != 'await_payload':
                            raise BattleProbeError('payload_order')
                        echo = echo_join_payload(packet)
                        writer.write(stream_chunk(echo))
                        await writer.drain()
                        sent_bytes += len(echo)
                        phase = 'payload_echoed'
                        self.log('join_payload_echoed', payload_bytes=len(packet) - 8,
                                 local_player_id=LOCAL_PLAYER_ID, participants_echoed=1,
                                 game_ticking_sent=False, gameplay_supported=False)
                        del echo
                    elif kind in (3, 5, 6, 7):
                        if phase not in ('payload_echoed', 'ticking'):
                            raise BattleProbeError('post_payload_order')
                        if kind == 5:
                            if self.enable_ticks:
                                start_packets = ticks.begin(packet, time.monotonic())
                                self._mark_battle_ticking(battle_id)
                            self.log('ready_for_ticking_observed', payload_bytes=total - 3,
                                     payload_schema_verified=self.enable_ticks,
                                     game_ticking_sent=False,
                                     gameplay_supported=False)
                            if self.enable_ticks:
                                writer.write(stream_chunk(start_packets))
                                sent_bytes += len(start_packets)
                                await writer.drain()
                                del start_packets
                                phase = 'ticking'
                                self.log('natural_ticking_started' if self.enable_natural_ticks
                                         else 'bounded_ticking_started',
                                         local_player_id=LOCAL_PLAYER_ID,
                                         interval_ms=200, max_ticks=ticks.max_ticks,
                                         session_seconds=self.connection_seconds,
                                         game_ticking_sent=True, gameplay_supported=False)
                        elif self.enable_ticks and kind == 3:
                            ticks.queue_command(packet)
                            self.log('command_queued', payload_bytes=total - 3,
                                     pending_count=len(ticks.commands),
                                     pending_payload_bytes=ticks.command_bytes,
                                     command_semantics_verified=False, persisted=False)
                        elif self.enable_ticks and kind == 6:
                            if phase != 'ticking':
                                raise BattleProbeError('unticked_before_ticking')
                            outgoing = echo_unticked(packet)
                            if outgoing:
                                writer.write(stream_chunk(outgoing))
                                sent_bytes += len(outgoing)
                                await writer.drain()
                        elif self.enable_ticks and kind == 7:
                            if (total - 3) % 4:
                                raise BattleProbeError('checksum_packet_length')
                            self.log('tick_checksums_observed', count=(total - 3) // 4,
                                     compared=False, gameplay_supported=False)
                        else:
                            self.log('post_payload_packet_observed', kind=kind, total=total,
                                     forwarded=False)
                    else:
                        raise BattleProbeError('unsupported_client_kind')
                    del packet
                if len(pending) >= MAX_INNER_BYTES:
                    raise BattleProbeError('pending_limit')
                if await flush_due_tick():
                    return
            self.log('natural_safety_limit' if self.enable_natural_ticks else 'observation_limit',
                     phase=phase, gameplay_supported=False,
                     normal_battle_completion=False)
        except BattleProbeError as exc:
            self.log('rejected', reason=exc.code, phase=phase)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError) as exc:
            self.log('connection_end', reason=type(exc).__name__, phase=phase)
        finally:
            pending.clear()
            ticks.commands.clear()
            ticks.command_bytes = 0
            if read_task is not None:
                read_task.cancel()
                await asyncio.gather(read_task, return_exceptions=True)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            if owns_claim and self._retire_battle_join(battle_id):
                self.claimed = False
                self.log('battle_session_released', reason='terminal')

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        if not self.enable_reconnect:
            await self._handle_without_resume(reader, writer)
            return
        await self._handle_with_resume(reader, writer)

    async def _handle_with_resume(self, reader: asyncio.StreamReader,
                                  writer: asyncio.StreamWriter):
        """Run one transport while retaining the validated local session."""
        read_task = None
        owns_transport = False
        attached = False
        session = None
        try:
            peer = writer.get_extra_info('peername')
            if not peer or peer[0] != '127.0.0.1':
                self.log('rejected', reason='peer_not_loopback')
                return
            if self.active_transport:
                self.log('rejected', reason='transport_already_active')
                return
            # asyncio callbacks do not pre-empt between these assignments.
            self.active_transport = True
            owns_transport = True
            greeting = await asyncio.wait_for(reader.readexactly(40), 15)
            if greeting[:11] != GREETING:
                raise BattleProbeError('greeting_magic')
            reconnect = bool(greeting[11])
            identity = greeting[12:28]
            attempt = struct.unpack_from('<I', greeting, 28)[0]
            received_offset = struct.unpack_from('<Q', greeting, 32)[0]
            del greeting

            # A final HTTP event is the durable completion boundary.  It is
            # safe to discard the detached transport at that point and accept
            # the next dynamically allocated battle without restarting relay.
            if self.session is not None and self.session.terminal:
                self._release_terminal_session(self.session)
            if self.session is not None:
                self._release_completed_session()

            if self.session is None:
                if reconnect or received_offset:
                    raise BattleProbeError('resume_without_session')
                session = BattleSession(self.tick_limit, self.connection_seconds)
                session.identity = identity
                session.last_attempt = attempt
                self.session = session
                self.claimed = True
                attached = True
                self.log('connection', gameplay_supported=False,
                         transport_resume_enabled=True)
                self.log('careconn_greeting', bytes=40, reconnect=False)
                writer.write(bytes(17))
                version = inner_packet(13, struct.pack('<I', VERSION))
                session.server_stream.extend(version)
                writer.write(stream_chunk(version))
                await drain_transport(writer, session.deadline)
                self.log('version_sent', version=VERSION)
            else:
                session = self.session
                if session.terminal:
                    raise BattleProbeError('session_complete')
                if not reconnect:
                    raise BattleProbeError('resume_flag_required')
                if identity != session.identity:
                    raise BattleProbeError('resume_identity_mismatch')
                if attempt <= session.last_attempt:
                    raise BattleProbeError('resume_attempt_stale')
                if session.reconnects >= MAX_RECONNECTS:
                    raise BattleProbeError('resume_limit')
                now = time.monotonic()
                if (session.disconnected_at is None or
                        now - session.disconnected_at > RECONNECT_GRACE_SECONDS or
                        now >= session.deadline):
                    session.terminate()
                    raise BattleProbeError('resume_grace_expired')
                if not session.peer_ack_bytes <= received_offset <= len(session.server_stream):
                    raise BattleProbeError('resume_offset_out_of_range')
                session.last_attempt = attempt
                session.reconnects += 1
                session.peer_received_offset = max(session.peer_received_offset,
                                                   received_offset)
                session.disconnected_at = None
                attached = True
                # The native reply and greeting reset both ACK-credit bases to
                # exact offsets. Continuing at old rounded blocks can credit
                # more bytes than the game sent and stall its unsigned window.
                session.our_ack_bytes = session.client_stream_bytes
                session.peer_ack_bytes = received_offset
                # Offset 1 acknowledges every client stream byte retained by
                # this process. Offset 9 preserves the initial local value 0.
                writer.write(struct.pack('<BQQ', 0, session.client_stream_bytes, 0))
                replayed = len(session.server_stream) - received_offset
                for start in range(received_offset, len(session.server_stream), MAX_CHUNK_BYTES):
                    writer.write(stream_chunk(bytes(
                        session.server_stream[start:start + MAX_CHUNK_BYTES])))
                await drain_transport(writer, session.deadline)
                # Replay flow control can block. Start the next tick only after
                # it has completed so a slow reconnect cannot create catch-up.
                session.ticks.resume(time.monotonic())
                self.log('careconn_greeting', bytes=40, reconnect=True)
                self.log('transport_resumed', reconnect=session.reconnects,
                         replayed_stream_bytes=replayed,
                         client_stream_ack=session.client_stream_bytes,
                         tick=session.ticks.count,
                         cpu_takeover=False, gameplay_supported=False)
            del identity

            async def send_new_stream(payload: bytes) -> None:
                if len(session.server_stream) + len(payload) > MAX_RETAINED_SERVER_STREAM_BYTES:
                    raise BattleProbeError('server_stream_retention_limit')
                received = max(session.peer_ack_bytes, session.peer_received_offset)
                if len(session.server_stream) + len(payload) - received > 25000:
                    raise BattleProbeError('server_stream_window')
                session.server_stream.extend(payload)
                writer.write(stream_chunk(payload))
                await drain_transport(writer, session.deadline)

            async def flush_due_tick():
                now = time.monotonic()
                if not session.ticks.started or now < session.ticks.next_at:
                    return None
                if session.pending:
                    raise BattleProbeError('tick_incomplete_packet')
                tick_packet = session.ticks.take_due(now)
                await send_new_stream(tick_packet)
                self.log('battle_tick_sent' if self.enable_natural_ticks else 'bounded_tick_sent',
                         tick=session.ticks.count,
                         kind=tick_packet[0], stream_bytes=len(tick_packet),
                         command_count=session.ticks.last_command_count,
                         command_payload_bytes=session.ticks.last_command_bytes,
                         local_player_id=LOCAL_PLAYER_ID,
                         command_semantics_verified=False, gameplay_supported=False)
                if (self.drop_transport_at_tick == session.ticks.count and
                        not session.drop_done):
                    session.drop_done = True
                    self.log('transport_drop_injected', tick=session.ticks.count,
                             session_retained=True, cpu_takeover=False)
                    return 'drop'
                if (session.ticks.max_ticks is not None and
                        session.ticks.count >= session.ticks.max_ticks):
                    session.terminate()
                    self.log('bounded_tick_limit', ticks=session.ticks.count,
                             normal_battle_completion=False, gameplay_supported=False)
                    return 'limit'
                return None

            while (time.monotonic() < session.deadline and
                   session.packets < self.packet_limit):
                if read_task is None:
                    read_task = asyncio.create_task(
                        read_outer_chunk(reader, self.read_idle_seconds))
                now = time.monotonic()
                timeout = max(0, session.deadline - now)
                if session.ticks.started:
                    timeout = min(timeout, max(0, session.ticks.next_at - now))
                done, _ = await asyncio.wait((read_task,), timeout=timeout)
                if not done:
                    if time.monotonic() >= session.deadline:
                        break
                    if await flush_due_tick():
                        return
                    continue
                chunk = read_task.result()
                read_task = None
                if not chunk:
                    session.peer_ack_bytes += 1000
                    if session.peer_ack_bytes > len(session.server_stream):
                        raise BattleProbeError('ack_beyond_sent_stream')
                    session.peer_received_offset = max(session.peer_received_offset,
                                                       session.peer_ack_bytes)
                    self.log('stream_ack')
                    if await flush_due_tick():
                        return
                    continue
                session.client_stream_bytes += len(chunk)
                session.pending.extend(chunk)
                del chunk
                while session.client_stream_bytes - session.our_ack_bytes >= 1000:
                    writer.write(b'\0\0')
                    session.our_ack_bytes += 1000
                await drain_transport(writer, session.deadline)
                while len(session.pending) >= 3:
                    kind, total = struct.unpack_from('<BH', session.pending)
                    if not 3 <= total <= MAX_INNER_BYTES:
                        raise BattleProbeError('inner_length')
                    if len(session.pending) < total:
                        break
                    packet = bytes(session.pending[:total])
                    del session.pending[:total]
                    session.packets += 1
                    if session.packets > self.packet_limit:
                        raise BattleProbeError('packet_limit')
                    self.log('client_packet', kind=kind, total=total,
                             phase=session.phase)
                    if kind == 4:
                        if total != 3:
                            raise BattleProbeError('keepalive_length')
                    elif kind == 0:
                        if session.phase != 'await_join':
                            raise BattleProbeError('join_order')
                        metadata, session.battle_id = \
                            self._validate_join_with_mismatch_log(packet)
                        self.log('battle_join_validated', **metadata,
                                 credential_source=('sqlite' if self.battle_state is not None
                                                    else 'legacy_fixture'))
                        confirmation = inner_packet(0, struct.pack('<I', LOCAL_PLAYER_ID))
                        await send_new_stream(confirmation)
                        session.phase = 'await_payload'
                        self.log('game_confirm_sent', local_player_id=LOCAL_PLAYER_ID,
                                 gameplay_supported=False)
                    elif kind == 1:
                        if session.phase != 'await_payload':
                            raise BattleProbeError('payload_order')
                        echo = echo_join_payload(packet)
                        await send_new_stream(echo)
                        session.phase = 'payload_echoed'
                        self.log('join_payload_echoed', payload_bytes=len(packet) - 8,
                                 local_player_id=LOCAL_PLAYER_ID, participants_echoed=1,
                                 game_ticking_sent=False, gameplay_supported=False)
                        del echo
                    elif kind in (3, 5, 6, 7):
                        if session.phase not in ('payload_echoed', 'ticking'):
                            raise BattleProbeError('post_payload_order')
                        if kind == 5:
                            if self.enable_ticks:
                                start_packets = session.ticks.begin(packet, time.monotonic())
                                self._mark_battle_ticking(session.battle_id)
                            self.log('ready_for_ticking_observed', payload_bytes=total - 3,
                                     payload_schema_verified=self.enable_ticks,
                                     game_ticking_sent=False,
                                     gameplay_supported=False)
                            if self.enable_ticks:
                                await send_new_stream(start_packets)
                                del start_packets
                                session.phase = 'ticking'
                                self.log('natural_ticking_started' if self.enable_natural_ticks
                                         else 'bounded_ticking_started',
                                         local_player_id=LOCAL_PLAYER_ID,
                                         interval_ms=200, max_ticks=session.ticks.max_ticks,
                                         session_seconds=self.connection_seconds,
                                         game_ticking_sent=True, gameplay_supported=False)
                        elif self.enable_ticks and kind == 3:
                            session.ticks.queue_command(packet)
                            self.log('command_queued', payload_bytes=total - 3,
                                     pending_count=len(session.ticks.commands),
                                     pending_payload_bytes=session.ticks.command_bytes,
                                     command_semantics_verified=False, persisted=False)
                        elif self.enable_ticks and kind == 6:
                            if session.phase != 'ticking':
                                raise BattleProbeError('unticked_before_ticking')
                            outgoing = echo_unticked(packet)
                            if outgoing:
                                await send_new_stream(outgoing)
                        elif self.enable_ticks and kind == 7:
                            if (total - 3) % 4:
                                raise BattleProbeError('checksum_packet_length')
                            self.log('tick_checksums_observed', count=(total - 3) // 4,
                                     compared=False, gameplay_supported=False)
                        else:
                            self.log('post_payload_packet_observed', kind=kind, total=total,
                                     forwarded=False)
                    else:
                        raise BattleProbeError('unsupported_client_kind')
                    del packet
                if len(session.pending) >= MAX_INNER_BYTES:
                    raise BattleProbeError('pending_limit')
                if await flush_due_tick():
                    return
            session.terminate()
            self.log('natural_safety_limit' if self.enable_natural_ticks else 'observation_limit',
                     phase=session.phase, gameplay_supported=False,
                     normal_battle_completion=False)
        except BattleProbeError as exc:
            if attached and session is not None:
                session.terminate()
            self.log('rejected', reason=exc.code,
                     phase=session.phase if attached else 'greeting')
        except (asyncio.IncompleteReadError, asyncio.TimeoutError,
                ConnectionError, OSError) as exc:
            self.log('connection_end', reason=type(exc).__name__,
                     phase=session.phase if attached else 'greeting',
                     resume_available=bool(attached and session is not None and
                                           not session.terminal))
        finally:
            if read_task is not None:
                read_task.cancel()
                await asyncio.gather(read_task, return_exceptions=True)
            if attached and session is not None:
                if not session.terminal and time.monotonic() < session.deadline:
                    detached_at = time.monotonic()
                    session.disconnected_at = detached_at
                    self.log('transport_detached', reconnect_grace_seconds=RECONNECT_GRACE_SECONDS,
                             tick=session.ticks.count, cpu_takeover=False)
                    expires_at = min(detached_at + RECONNECT_GRACE_SECONDS,
                                     session.deadline)
                    asyncio.get_running_loop().call_later(
                        max(0, expires_at - detached_at),
                        self._expire_retained_session, session, detached_at)
                else:
                    session.terminate()
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            if session is not None and session.terminal:
                self._release_terminal_session(session)
            if owns_transport:
                self.active_transport = False


async def serve(trace: Path, *, enable_join_payload_echo: bool, expected_players: int,
                 enable_bounded_ticks: bool = False,
                 max_bounded_ticks: int = MAX_BOUNDED_TICKS,
                 enable_natural_ticks: bool = False,
                 natural_connection_seconds: int = NATURAL_CONNECTION_SECONDS,
                 battle_state_path: Path | None = None,
                 legacy_lab_credentials: bool = False,
                 enable_reconnect: bool = False,
                 drop_transport_at_tick: int | None = None):
    battle_state = (LocalBattleState(battle_state_path)
                    if battle_state_path is not None else None)
    try:
        probe = NativeBattleProbe(trace, enable_join_payload_echo=enable_join_payload_echo,
                                  expected_players=expected_players,
                                  enable_bounded_ticks=enable_bounded_ticks,
                                  max_bounded_ticks=max_bounded_ticks,
                                  enable_natural_ticks=enable_natural_ticks,
                                  natural_connection_seconds=natural_connection_seconds,
                                  battle_state=battle_state,
                                  legacy_lab_credentials=legacy_lab_credentials,
                                  enable_reconnect=enable_reconnect,
                                  drop_transport_at_tick=drop_transport_at_tick)
        trace.parent.mkdir(parents=True, exist_ok=True)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            try:
                listener.bind(('127.0.0.1', RELAY_PORT))
                listener.listen()
            except OSError as error:
                annotate_bind_error(error, transport='tcp', family='ipv4', port=RELAY_PORT)
                probe.log('bind_error', host='127.0.0.1', port=RELAY_PORT,
                          code=bind_failure_code(error))
                raise
            listener.setblocking(False)
            server = await asyncio.start_server(probe.handle, sock=listener)
        except BaseException:
            listener.close()
            raise
        probe.log('ready', host='127.0.0.1', port=RELAY_PORT,
                  expected_players=(None if battle_state is not None else expected_players),
                  expected_players_source=('battle_state_credentials'
                                           if battle_state is not None
                                           else 'legacy_fixture'),
                  bounded_ticks_opt_in=enable_bounded_ticks,
                  max_bounded_ticks=max_bounded_ticks if enable_bounded_ticks else None,
                  natural_ticks_opt_in=enable_natural_ticks,
                  natural_session_seconds=(natural_connection_seconds
                                           if enable_natural_ticks else None),
                  battle_state_enabled=battle_state is not None,
                  legacy_lab_credentials=legacy_lab_credentials,
                  client_packet_limit=(MAX_NATURAL_PACKETS if enable_natural_ticks
                                       else MAX_OBSERVATION_PACKETS),
                  transport_resume_enabled=enable_reconnect,
                  max_reconnects=MAX_RECONNECTS if enable_reconnect else None,
                  reconnect_grace_seconds=RECONNECT_GRACE_SECONDS if enable_reconnect else None,
                  injected_drop_tick=drop_transport_at_tick,
                  one_session=True, game_ticking_sent=False, gameplay_supported=False)
        async with server:
            await server.serve_forever()
    finally:
        if battle_state is not None:
            battle_state.close()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--enable-join-payload-echo', action='store_true', required=True)
    ticking = parser.add_mutually_exclusive_group()
    ticking.add_argument('--enable-bounded-ticks', action='store_true',
                         help='after real READY, run bounded 200ms diagnostic ticks')
    ticking.add_argument('--enable-natural-ticks', action='store_true',
                         help='after real READY, tick until native disconnect or safety deadline')
    parser.add_argument('--max-bounded-ticks', type=int, default=None, metavar='1..600',
                        help='explicit tick limit (default 50); requires --enable-bounded-ticks')
    parser.add_argument('--natural-session-seconds', type=int,
                        default=NATURAL_CONNECTION_SECONDS, metavar='600..7200',
                        help='safety deadline; custom value requires --enable-natural-ticks')
    parser.add_argument('--battle-state', type=Path, default=None,
                        help='SQLite lifecycle (defaults to local state in natural mode)')
    parser.add_argument('--legacy-lab-credentials', action='store_true',
                        help='explicit diagnostic only: accept the fixed historical lab ID/key')
    parser.add_argument('--enable-reconnect', action='store_true',
                        help='retain one validated loopback session for up to three retries')
    parser.add_argument('--drop-transport-at-tick', type=int, default=None, metavar='N',
                        help='lab-only one-time disconnect; requires reconnect and bounded ticks')
    parser.add_argument('--expected-players', type=int, choices=(1, 2), default=1,
                        help='fixed count for --legacy-lab-credentials only; '
                             'SQLite-backed joins use each battle credential')
    parser.add_argument('--trace', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.max_bounded_ticks is not None and not args.enable_bounded_ticks:
        parser.error('--max-bounded-ticks requires --enable-bounded-ticks')
    if args.max_bounded_ticks is not None and not 1 <= args.max_bounded_ticks <= MAX_CONFIGURED_TICKS:
        parser.error('--max-bounded-ticks must be from 1 to 600')
    if args.max_bounded_ticks is None:
        args.max_bounded_ticks = MAX_BOUNDED_TICKS
    if (args.enable_natural_ticks and args.battle_state is None
            and not args.legacy_lab_credentials):
        args.battle_state = DEFAULT_BATTLE_STATE_PATH
    if args.battle_state is not None and args.legacy_lab_credentials:
        parser.error('--battle-state and --legacy-lab-credentials are mutually exclusive')
    if args.battle_state is None and not args.legacy_lab_credentials:
        parser.error('choose --battle-state or explicit --legacy-lab-credentials')
    if not args.enable_natural_ticks and args.natural_session_seconds != NATURAL_CONNECTION_SECONDS:
        parser.error('--natural-session-seconds requires --enable-natural-ticks')
    if not MIN_NATURAL_CONNECTION_SECONDS <= args.natural_session_seconds <= MAX_NATURAL_CONNECTION_SECONDS:
        parser.error('--natural-session-seconds must be from 600 to 7200')
    if args.drop_transport_at_tick is not None:
        if not args.enable_reconnect or not (args.enable_bounded_ticks or args.enable_natural_ticks):
            parser.error('--drop-transport-at-tick requires reconnect and ticking')
        if args.drop_transport_at_tick < 1:
            parser.error('--drop-transport-at-tick must be positive')
        if (args.enable_bounded_ticks and
                args.drop_transport_at_tick >= args.max_bounded_ticks):
            parser.error('--drop-transport-at-tick must precede the configured tick limit')
    return args


def main():
    args = parse_args()
    try:
        asyncio.run(serve(args.trace, enable_join_payload_echo=args.enable_join_payload_echo,
                          expected_players=args.expected_players,
                          enable_bounded_ticks=args.enable_bounded_ticks,
                          max_bounded_ticks=args.max_bounded_ticks,
                          enable_natural_ticks=args.enable_natural_ticks,
                          natural_connection_seconds=args.natural_session_seconds,
                          battle_state_path=args.battle_state,
                          legacy_lab_credentials=args.legacy_lab_credentials,
                          enable_reconnect=args.enable_reconnect,
                          drop_transport_at_tick=args.drop_transport_at_tick))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
