"""Loopback-only CAReconn/command-relay diagnostic listener.

Evidence: original game.dll FO C56B30 (40-byte greeting), C56C06 (17-byte
reply), C573F0/C5AC50 (u16 outer stream chunks), BCC760/B80F8F (VERSION 27),
BF2E30/B46F0B (105-byte GAME_JOIN). GAME_JOIN is observed, never confirmed.
No battle simulation, match allocation, AI control, or public authentication.
Do not publish this port or use zero-token probe replies for a real session.
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import re
import struct
import time
from pathlib import Path

GREETING = b'CAReconn01\0'
VERSION = 27
GAME_JOIN_BYTES = 105
_CANONICAL_UUID = re.compile(rb'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')


class GameJoinDecodeError(ValueError):
    """A framing error with a constant reason code, never packet contents."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def game_join_metadata(packet: bytes) -> dict[str, bool | int]:
    """Return only redacted observations of one complete native inner packet.

    Framing/type/length are strict. Semantic checks are diagnostic, not an
    authorization policy: identities and roster/endpoint ownership are not
    verified, and no value from either opaque field is returned. Unknown
    versions, UUID spelling, flags and destinations do not start gameplay.

    BF2E30 places opaque bytes at +44 (8) and +52 (37). The custom caller
    B703B6/B704EC/B46EC7 suggests these are numeric battle key and native user
    id, respectively, contrary to an earlier tentative layout description.
    Do not require the second field to be a decimal key: "player" is valid
    local identity text. Its decimal-uint64 flag only tests that hypothesis.
    """
    if type(packet) is not bytes:
        raise GameJoinDecodeError('input_type')
    if len(packet) != GAME_JOIN_BYTES:
        raise GameJoinDecodeError('packet_length')
    kind, total = struct.unpack_from('<BH', packet)
    if kind != 0:
        raise GameJoinDecodeError('message_kind')
    if total != GAME_JOIN_BYTES:
        raise GameJoinDecodeError('declared_length')

    def text_flags(slot: bytes, prefix: str) -> dict[str, bool | int]:
        end = slot.find(b'\0')
        value = slot if end == -1 else slot[:end]
        return {
            prefix + '_bytes': len(value),
            prefix + '_nul_terminated': end != -1,
            prefix + '_ascii': all(byte < 128 for byte in value),
            prefix + '_printable_ascii': all(32 <= byte <= 126 for byte in value),
            prefix + '_zero_padding': end != -1 and not any(slot[end:]),
        }

    game_id = packet[7:44]
    secondary = packet[52:89]
    end = secondary.find(b'\0')
    # The field is at most 37 bytes, so the temporary integer conversion is
    # bounded. Its value is deliberately neither returned nor logged.
    candidate = secondary[:end] if end != -1 else b''
    decimal_uint64 = bool(candidate) and all(48 <= b <= 57 for b in candidate)
    if decimal_uint64:
        decimal_uint64 = int(candidate) <= (1 << 64) - 1
    expected_players = packet[89]
    return {
        'framing_valid': True,
        'protocol_version_supported': struct.unpack_from('<I', packet, 3)[0] == VERSION,
        **text_flags(game_id, 'game_id'),
        'game_id_canonical_uuid': game_id[36] == 0 and _CANONICAL_UUID.fullmatch(game_id[:36]) is not None,
        'opaque_identity_bytes': 8,
        **text_flags(secondary, 'secondary_text'),
        'secondary_text_decimal_uint64': decimal_uint64,
        'expected_players': expected_players,
        # 1..20 is this TWA lobby lab's roster range, not authentication or a
        # claim that every native game mode uses this same limit.
        'expected_players_in_lab_range': 1 <= expected_players <= 20,
        'normal_parameter_200': struct.unpack_from('<H', packet, 90)[0] == 200,
        'casa_ipv4_loopback': ipaddress.IPv4Address(packet[92:96]).is_loopback,
        'casa_port_nonzero': struct.unpack_from('<H', packet, 96)[0] != 0,
        'carpg_ipv4_loopback': ipaddress.IPv4Address(packet[98:102]).is_loopback,
        'carpg_port_nonzero': struct.unpack_from('<H', packet, 102)[0] != 0,
        'credentials_verified': False,
        'game_confirm_sent': False,
        'gameplay_supported': False,
    }


def inner_packet(message_id: int, payload: bytes = b'') -> bytes:
    if not 0 <= message_id <= 255 or len(payload) + 3 > 4096:
        raise ValueError('invalid inner packet')
    return struct.pack('<BH', message_id, len(payload) + 3) + payload


def stream_chunk(payload: bytes) -> bytes:
    if not 0 < len(payload) <= 65535:
        raise ValueError('invalid stream chunk')
    return struct.pack('<H', len(payload)) + payload


class RelayProbe:
    def __init__(self, trace: Path, *, passive: bool = False):
        self.trace_path = trace
        self.passive = passive
        self.next_id = 0
        self.active = 0

    def log(self, event: str, **fields):
        row = {'time': time.time(), 'event': event, **fields}
        with self.trace_path.open('a', encoding='utf-8') as output:
            output.write(json.dumps(row, separators=(',', ':')) + '\n')
        print(json.dumps(row), flush=True)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.next_id += 1
        connection = self.next_id
        self.active += 1
        self.log('connection', connection=connection)
        try:
            if self.active > 8:
                self.log('connection_limit', connection=connection)
                return
            greeting = await asyncio.wait_for(reader.readexactly(40), timeout=15)
            if not greeting.startswith(GREETING):
                self.log('unrecognized_greeting', connection=connection, bytes=len(greeting))
                return
            # Caller fields at 12..19 and random fields at 20..27 may identify
            # a session. Retain only their widths, never their values.
            self.log('careconn_greeting', connection=connection, bytes=40,
                     reconnect=bool(greeting[11]),
                     caller_parameters_bytes=8, random_session_bytes=8,
                     attempt=struct.unpack_from('<I', greeting, 28)[0],
                     received_offset=struct.unpack_from('<Q', greeting, 32)[0])
            if self.passive:
                return
            if greeting[11] or struct.unpack_from('<Q', greeting, 32)[0]:
                self.log('resume_not_supported', connection=connection)
                return
            # Diagnostic fresh-session response only: accepted, initial offset 0, token 0.
            writer.write(bytes(17))
            writer.write(stream_chunk(inner_packet(13, struct.pack('<I', VERSION))))
            await writer.drain()
            self.log('version_sent', connection=connection, version=VERSION)
            pending = bytearray()
            received = 0
            acknowledged = 0
            packets = 0
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline and packets < 300:
                header = await asyncio.wait_for(reader.readexactly(2), timeout=30)
                size = struct.unpack('<H', header)[0]
                if size == 0:
                    self.log('stream_ack', connection=connection)
                    continue
                chunk = await asyncio.wait_for(reader.readexactly(size), timeout=10)
                received += size
                pending.extend(chunk)
                # CAReconn acknowledges each complete 1000-byte stream block.
                while received - acknowledged >= 1000:
                    writer.write(b'\0\0')
                    acknowledged += 1000
                await writer.drain()
                while len(pending) >= 3 and packets < 300:
                    kind, total = struct.unpack_from('<BH', pending)
                    if total < 3 or total > 4096:
                        self.log('invalid_inner_length', connection=connection, kind=kind, total=total)
                        return
                    if kind == 0 and total != GAME_JOIN_BYTES:
                        self.log('invalid_game_join', connection=connection, reason='declared_length', total=total)
                        return
                    if len(pending) < total:
                        break
                    # Frame metadata only: unknown payloads may contain native tickets.
                    self.log('client_packet', connection=connection, kind=kind, total=total)
                    if kind == 0:
                        try:
                            metadata = game_join_metadata(bytes(pending[:total]))
                        except GameJoinDecodeError as exc:
                            self.log('invalid_game_join', connection=connection, reason=exc.code)
                            return
                        self.log('game_join_observed', connection=connection, **metadata)
                        # No GAME_CONFIRM, GAME_JOIN_PAYLOADS, ticking, or
                        # endpoint contact: this remains a diagnostic sink.
                    del pending[:total]
                    packets += 1
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError) as exc:
            self.log('connection_end', connection=connection, reason=type(exc).__name__)
        finally:
            self.active -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


class PingEcho(asyncio.DatagramProtocol):
    """Native latency probe: 4-byte timestamp, UDP port 55563 (FO BE382F)."""
    def __init__(self, probe: RelayProbe, delay_ms: int = 0):
        self.probe = probe
        self.delay_ms = delay_ms
        self.count = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        if len(data) != 4 or addr[0] != '127.0.0.1':
            return
        if self.delay_ms:
            asyncio.get_running_loop().call_later(self.delay_ms / 1000, self.transport.sendto, data, addr)
        else:
            self.transport.sendto(data, addr)
        self.count += 1
        if self.count <= 10 or self.count % 100 == 0:
            self.probe.log('udp_ping_echo', bytes=4, count=self.count, peer_port=addr[1])


async def serve(port: int, ping_port: int, trace: Path, passive: bool, ping_delay_ms: int = 0):
    trace.parent.mkdir(parents=True, exist_ok=True)
    probe = RelayProbe(trace, passive=passive)
    server = await asyncio.start_server(probe.handle, '127.0.0.1', port)
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: PingEcho(probe, ping_delay_ms), local_addr=('127.0.0.1', ping_port))
    probe.log('ready', host='127.0.0.1', port=port, ping_port=ping_port, passive=passive, ping_delay_ms=ping_delay_ms)
    try:
        async with server:
            await server.serve_forever()
    finally:
        transport.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=19000)
    parser.add_argument('--ping-port', type=int, default=55563)
    parser.add_argument('--ping-delay-ms', type=int, default=0, help='Diagnostic echo delay, not a real network measurement')
    parser.add_argument('--trace', type=Path, required=True)
    parser.add_argument('--passive', action='store_true')
    args = parser.parse_args()
    if not all(1 <= p <= 65535 for p in (args.port, args.ping_port)):
        parser.error('port must be 1..65535')
    if not 0 <= args.ping_delay_ms <= 1000:
        parser.error('ping delay must be 0..1000 ms')
    asyncio.run(serve(args.port, args.ping_port, args.trace.resolve(), args.passive, args.ping_delay_ms))


if __name__ == '__main__':
    main()
