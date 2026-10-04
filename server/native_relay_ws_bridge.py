"""Loopback TCP 19000 <-> BattleRelay Durable Object WebSocket bridge.

The native game connects to ``127.0.0.1:19000`` exactly as it did for the
proven single-player relay.  This bridge accepts that connection, opens an
outbound WebSocket (RFC 6455, implemented here with the standard library only)
to the Cloudflare BattleRelay Durable Object and forwards bytes both ways
while preserving the game's outer chunk boundaries.  It never parses inner
packets, never decrypts payloads and never logs payload bytes or the ticket.

Bridge -> relay frames:
  1. text  {"ticket": ..., "resumeOffset": N, "greeting": true|false, "clientOffset": M}
  2. greeting=true : one binary frame with the game's 40-byte CAReconn greeting
  3. afterwards one binary frame per outer chunk (<u16le len><payload>, len 0 = ACK)
Relay -> bridge frames are raw bytes to write to the game socket (17-byte
greeting reply, outer chunks, 2-byte ACKs); text frames are diagnostics.

Recovery paths:
  * WebSocket drop while the game socket stays open: reconnect with
    greeting=false and resumeOffset = server stream bytes already delivered to
    the game; the relay answers {"event":"resumed","clientReceived":K} and the
    bridge re-sends its retained client stream from K.  Bounded retries; when
    they are exhausted the game socket is closed so the game performs its own
    proven CAReconn reconnect.
  * Game socket drop: the WebSocket is closed with 1000 "game_closed"; the
    next game connection (a CAReconn reconnect) opens a new WebSocket whose
    handshake carries the greeting's received offset.
Relay close codes 4000..4002 and 1000 are terminal: the game socket is closed
and no retry happens.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Awaitable, Callable

_SOURCE_ROOT = Path(__file__).resolve().parents[1]
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.append(str(_SOURCE_ROOT))
from companion.loopback_ports import annotate_bind_error

GREETING_MAGIC = b'CAReconn01\0'
GREETING_BYTES = 40
GREETING_REPLY_BYTES = 17
MAX_CHUNK_BYTES = 16384
CA_RECONN_ACK_BLOCK_BYTES = 1000
DEFAULT_LISTEN_HOST = '127.0.0.1'
DEFAULT_LISTEN_PORT = 19000
WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
MAX_WS_FRAME_BYTES = 1 << 20
MAX_HTTP_HEADER_BYTES = 16384
CLOSE_NORMAL = 1000
CLOSE_REJECTED = 4000
CLOSE_ENDED = 4001
CLOSE_SUPERSEDED = 4002
TERMINAL_CLOSE_CODES = frozenset({CLOSE_NORMAL, CLOSE_REJECTED, CLOSE_ENDED, CLOSE_SUPERSEDED})
MAX_RETAINED_CLIENT_BYTES = 64 * 1024
DEFAULT_RETRY_DELAYS = (0.25, 0.5, 1.0, 2.0, 4.0)
GREETING_TIMEOUT_SECONDS = 15
CHUNK_BODY_TIMEOUT_SECONDS = 10
WS_CONNECT_TIMEOUT_SECONDS = 10
RESUME_EVENT_TIMEOUT_SECONDS = 10

OP_CONTINUATION = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA


class BridgeError(Exception):
    """Constant reason code; never carries payload bytes or the ticket."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


# ---------------------------------------------------------------------------
# RFC 6455 framing (shared by the client below and by test fake servers)
# ---------------------------------------------------------------------------

def websocket_accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + WS_GUID).encode('ascii')).digest()).decode('ascii')


def encode_frame(opcode: int, payload: bytes, *, mask: bool, fin: bool = True) -> bytes:
    if not 0 <= opcode <= 0xF:
        raise BridgeError('ws_opcode')
    if opcode >= 0x8 and (len(payload) > 125 or not fin):
        raise BridgeError('ws_control_frame')
    header = bytearray([(0x80 if fin else 0) | opcode])
    length = len(payload)
    mask_bit = 0x80 if mask else 0
    if length <= 125:
        header.append(mask_bit | length)
    elif length <= 0xFFFF:
        header.append(mask_bit | 126)
        header.extend(struct.pack('>H', length))
    else:
        header.append(mask_bit | 127)
        header.extend(struct.pack('>Q', length))
    if not mask:
        return bytes(header) + payload
    key = os.urandom(4)
    header.extend(key)
    masked = bytearray(payload)
    for index in range(len(masked)):
        masked[index] ^= key[index & 3]
    return bytes(header) + bytes(masked)


async def read_frame(reader: asyncio.StreamReader, *, require_mask: bool,
                     max_bytes: int = MAX_WS_FRAME_BYTES) -> tuple[bool, int, bytes]:
    """Read one frame; returns (fin, opcode, unmasked payload)."""
    first, second = await reader.readexactly(2)
    fin = bool(first & 0x80)
    if first & 0x70:
        raise BridgeError('ws_reserved_bits')
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    if masked != require_mask:
        raise BridgeError('ws_mask_bit')
    length = second & 0x7F
    if length == 126:
        length = struct.unpack('>H', await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack('>Q', await reader.readexactly(8))[0]
    if length > max_bytes:
        raise BridgeError('ws_frame_too_large')
    key = await reader.readexactly(4) if masked else b''
    payload = await reader.readexactly(length) if length else b''
    if masked:
        data = bytearray(payload)
        for index in range(len(data)):
            data[index] ^= key[index & 3]
        payload = bytes(data)
    return fin, opcode, payload


class WebSocketClient:
    """Minimal RFC 6455 client: masked frames, ping/pong, close handshake."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.closed = False
        self._send_lock = asyncio.Lock()

    @classmethod
    async def connect(cls, url: str, *, ssl_context: ssl.SSLContext | None = None,
                      timeout: float = WS_CONNECT_TIMEOUT_SECONDS,
                      extra_headers: dict[str, str] | None = None) -> 'WebSocketClient':
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ('ws', 'wss') or not parts.hostname:
            raise BridgeError('ws_url')
        secure = parts.scheme == 'wss'
        port = parts.port or (443 if secure else 80)
        path = (parts.path or '/') + (('?' + parts.query) if parts.query else '')
        if secure and ssl_context is None:
            ssl_context = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(asyncio.open_connection(
            parts.hostname, port, ssl=ssl_context if secure else None,
            server_hostname=parts.hostname if secure else None), timeout)
        try:
            key = base64.b64encode(os.urandom(16)).decode('ascii')
            host = parts.hostname if port in (80, 443) else f'{parts.hostname}:{port}'
            lines = [f'GET {path} HTTP/1.1', f'Host: {host}', 'Upgrade: websocket', 'Connection: Upgrade',
                     f'Sec-WebSocket-Key: {key}', 'Sec-WebSocket-Version: 13']
            for name, value in (extra_headers or {}).items():
                lines.append(f'{name}: {value}')
            writer.write(('\r\n'.join(lines) + '\r\n\r\n').encode('ascii'))
            await asyncio.wait_for(writer.drain(), timeout)
            status_line, headers = await asyncio.wait_for(read_http_head(reader), timeout)
            if not status_line.startswith('HTTP/1.1 101'):
                raise BridgeError('ws_handshake_status')
            if headers.get('upgrade', '').lower() != 'websocket':
                raise BridgeError('ws_handshake_upgrade')
            if headers.get('sec-websocket-accept') != websocket_accept(key):
                raise BridgeError('ws_handshake_accept')
        except BaseException:
            writer.close()
            raise
        return cls(reader, writer)

    async def _send(self, opcode: int, payload: bytes) -> None:
        if self.closed:
            raise BridgeError('ws_closed')
        async with self._send_lock:
            self.writer.write(encode_frame(opcode, payload, mask=True))
            await self.writer.drain()

    async def send_text(self, text: str) -> None:
        await self._send(OP_TEXT, text.encode('utf-8'))

    async def send_binary(self, data: bytes) -> None:
        await self._send(OP_BINARY, data)

    async def receive(self) -> tuple[str, object]:
        """Return ('text', str), ('binary', bytes) or ('close', (code, reason)); pings are answered."""
        fragments: list[bytes] = []
        fragment_opcode: int | None = None
        while True:
            fin, opcode, payload = await read_frame(self.reader, require_mask=False)
            if opcode == OP_PING:
                await self._send(OP_PONG, payload)
                continue
            if opcode == OP_PONG:
                continue
            if opcode == OP_CLOSE:
                code = struct.unpack('>H', payload[:2])[0] if len(payload) >= 2 else 1005
                reason = payload[2:].decode('utf-8', 'replace') if len(payload) > 2 else ''
                self.closed = True
                try:
                    async with self._send_lock:
                        self.writer.write(encode_frame(OP_CLOSE, payload[:2], mask=True))
                        await asyncio.wait_for(self.writer.drain(), 2)
                except (OSError, asyncio.TimeoutError, ConnectionError):
                    pass
                return 'close', (code, reason)
            if opcode in (OP_TEXT, OP_BINARY):
                if fragment_opcode is not None:
                    raise BridgeError('ws_fragment_interleaved')
                if fin:
                    return ('text', payload.decode('utf-8')) if opcode == OP_TEXT else ('binary', payload)
                fragment_opcode = opcode
                fragments = [payload]
                continue
            if opcode == OP_CONTINUATION:
                if fragment_opcode is None:
                    raise BridgeError('ws_fragment_unexpected')
                fragments.append(payload)
                if sum(len(part) for part in fragments) > MAX_WS_FRAME_BYTES:
                    raise BridgeError('ws_frame_too_large')
                if fin:
                    data = b''.join(fragments)
                    kind = fragment_opcode
                    fragment_opcode = None
                    fragments = []
                    return ('text', data.decode('utf-8')) if kind == OP_TEXT else ('binary', data)
                continue
            raise BridgeError('ws_opcode')

    async def close(self, code: int = CLOSE_NORMAL, reason: str = '') -> None:
        if not self.closed:
            self.closed = True
            try:
                async with self._send_lock:
                    self.writer.write(encode_frame(OP_CLOSE, struct.pack('>H', code) + reason.encode('utf-8')[:123], mask=True))
                    await asyncio.wait_for(self.writer.drain(), 2)
            except (OSError, asyncio.TimeoutError, ConnectionError):
                pass
        self.writer.close()
        try:
            await asyncio.wait_for(self.writer.wait_closed(), 2)
        except (OSError, asyncio.TimeoutError, ConnectionError):
            pass

    def abort(self) -> None:
        self.closed = True
        self.writer.transport.abort()


async def read_http_head(reader: asyncio.StreamReader) -> tuple[str, dict[str, str]]:
    """Read one HTTP request/status line plus headers (lower-cased names)."""
    raw = bytearray()
    while not raw.endswith(b'\r\n\r\n'):
        if len(raw) > MAX_HTTP_HEADER_BYTES:
            raise BridgeError('http_head_too_large')
        chunk = await reader.read(1)
        if not chunk:
            raise BridgeError('http_head_eof')
        raw.extend(chunk)
    lines = raw.decode('latin-1').split('\r\n')
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ':' in line:
            name, value = line.split(':', 1)
            headers[name.strip().lower()] = value.strip()
    return lines[0], headers


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------

ConnectFactory = Callable[[str], Awaitable[WebSocketClient]]


class _GameLink:
    """One accepted game TCP connection and its (possibly re-established) WebSocket."""

    def __init__(self, bridge: 'RelayBridge', reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.bridge = bridge
        self.reader = reader
        self.writer = writer
        self.ws: WebSocketClient | None = None
        self.send_lock = asyncio.Lock()
        self.server_offset = 0       # server stream payload bytes written to the game socket
        self.client_sent = 0         # client stream payload bytes forwarded (absolute)
        self.client_acked = 0        # client stream bytes the relay acknowledged (absolute)
        self.retained: list[tuple[int, bytes]] = []  # (absolute start, payload) not yet acknowledged
        self.retained_bytes = 0
        self.expect_reply = False
        self.ws_generation = 0
        self.resuming = False
        self.done = asyncio.Event()
        self.closing = False
        self.terminal_reason: str | None = None
        self.pump_task: asyncio.Task | None = None
        self.resume_task: asyncio.Task | None = None

    # -- lifecycle ---------------------------------------------------------

    async def run(self) -> None:
        try:
            greeting = await asyncio.wait_for(self.reader.readexactly(GREETING_BYTES), GREETING_TIMEOUT_SECONDS)
            if not greeting.startswith(GREETING_MAGIC):
                raise BridgeError('greeting_magic')
            reconnect = bool(greeting[11])
            received_offset = struct.unpack_from('<Q', greeting, 32)[0]
            self.server_offset = received_offset
            self.bridge.log('careconn_greeting', reconnect=reconnect, received_offset=received_offset)
            ws = await self.bridge.connect_ws()
            handshake = {
                'ticket': self.bridge.ticket, 'resumeOffset': received_offset, 'greeting': True, 'clientOffset': 0,
            }
            if self.bridge.fresh_process_restart and not reconnect and received_offset == 0:
                handshake['restart'] = True
            await ws.send_text(json.dumps(handshake, separators=(',', ':')))
            await ws.send_binary(greeting)
            self.expect_reply = True
            self.ws = ws
            self.pump_task = asyncio.create_task(self._pump_ws_to_tcp(ws, self.ws_generation))
            await self._pump_tcp_to_ws()
        except BridgeError as error:
            self.terminal_reason = error.code
            self.bridge.log('rejected', reason=error.code)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError) as error:
            self.terminal_reason = self.terminal_reason or type(error).__name__
            self.bridge.log('game_connection_end', reason=type(error).__name__)
        finally:
            await self._finish()

    @property
    def is_closing(self) -> bool:
        return self.closing or self.done.is_set() or self.reader.at_eof()

    async def _finish(self) -> None:
        self.closing = True
        if self.resume_task is not None and self.resume_task is not asyncio.current_task():
            self.resume_task.cancel()
            await asyncio.gather(self.resume_task, return_exceptions=True)
        if self.pump_task is not None and self.pump_task is not asyncio.current_task():
            self.pump_task.cancel()
            await asyncio.gather(self.pump_task, return_exceptions=True)
        ws, self.ws = self.ws, None
        if ws is not None:
            await ws.close(CLOSE_NORMAL, 'game_closed')
        self.retained.clear()
        self.retained_bytes = 0
        self.writer.close()
        try:
            await asyncio.wait_for(self.writer.wait_closed(), 2)
        except (OSError, asyncio.TimeoutError, ConnectionError):
            pass
        self.done.set()
        self.bridge.log('link_closed', reason=self.terminal_reason or 'game_closed',
                        server_offset=self.server_offset, client_sent=self.client_sent)

    # -- game -> relay -----------------------------------------------------

    async def _pump_tcp_to_ws(self) -> None:
        while True:
            header = await self.reader.readexactly(2)
            size = struct.unpack('<H', header)[0]
            if size > MAX_CHUNK_BYTES:
                raise BridgeError('outer_chunk_too_large')
            payload = await asyncio.wait_for(self.reader.readexactly(size), CHUNK_BODY_TIMEOUT_SECONDS) if size else b''
            frame = header + payload
            if size:
                self.retained.append((self.client_sent, payload))
                self.retained_bytes += size
                self.client_sent += size
                if self.retained_bytes > MAX_RETAINED_CLIENT_BYTES:
                    raise BridgeError('retained_client_stream_limit')
            async with self.send_lock:
                ws = self.ws
                if ws is None:
                    continue  # reconnecting: the resume routine re-sends from the retained stream
                try:
                    await ws.send_binary(frame)
                except (BridgeError, ConnectionError, OSError):
                    self._ws_lost(ws, 'send_failed')

    # -- relay -> game -----------------------------------------------------

    async def _pump_ws_to_tcp(self, ws: WebSocketClient, generation: int) -> None:
        try:
            while True:
                kind, value = await ws.receive()
                if kind == 'binary':
                    data = value  # type: ignore[assignment]
                    assert isinstance(data, bytes)
                    if self.expect_reply:
                        if len(data) != GREETING_REPLY_BYTES:
                            raise BridgeError('greeting_reply_length')
                        self.expect_reply = False
                        client_stream_bytes = struct.unpack_from('<Q', data, 1)[0]
                        self._rebase_client_stream(client_stream_bytes)
                    elif len(data) == 2 and data == b'\0\0':
                        self.client_acked += CA_RECONN_ACK_BLOCK_BYTES
                        self._prune_retained()
                    elif len(data) >= 3:
                        self.server_offset += len(data) - 2
                    else:
                        raise BridgeError('relay_frame_shape')
                    self.writer.write(data)
                    await self.writer.drain()
                elif kind == 'text':
                    self._note_event(value)  # type: ignore[arg-type]
                else:
                    code, reason = value  # type: ignore[misc]
                    if code in TERMINAL_CLOSE_CODES:
                        self.terminal_reason = f'relay_close_{code}'
                        self.bridge.log('relay_closed', code=code, reason=str(reason)[:64], terminal=True)
                        self.writer.close()
                        return
                    self.bridge.log('relay_closed', code=code, terminal=False)
                    self._ws_lost(ws, f'close_{code}')
                    return
        except asyncio.CancelledError:
            raise
        except BridgeError as error:
            self.terminal_reason = error.code
            self.bridge.log('rejected', reason=error.code)
            self.writer.close()
        except (asyncio.IncompleteReadError, ConnectionError, OSError) as error:
            if generation == self.ws_generation and self.ws is ws:
                self._ws_lost(ws, type(error).__name__)

    def _note_event(self, text: str) -> None:
        try:
            event = json.loads(text)
        except ValueError:
            raise BridgeError('relay_text_invalid')
        if isinstance(event, dict) and isinstance(event.get('event'), str):
            self.bridge.log('relay_event', name=event['event'][:32], phase=str(event.get('phase', ''))[:16])
            if event['event'] == 'battle_phase':
                if (set(event) != {'event', 'battleId', 'phase', 'tick'}
                        or not isinstance(event.get('battleId'), str)
                        or not event['battleId']
                        or event.get('phase') != 'ticking'
                        or type(event.get('tick')) is not int
                        or event['tick'] != 0
                        or (self.bridge.expected_battle_id is not None
                            and event['battleId'] != self.bridge.expected_battle_id)):
                    raise BridgeError('relay_control_invalid')
                callback = self.bridge.on_relay_event
                if callback is not None:
                    try:
                        callback(dict(event))
                    except Exception:
                        raise BridgeError('relay_event_callback_failed') from None

    def _rebase_client_stream(self, client_stream_bytes: int) -> None:
        """The 17-byte reply says how many client bytes the relay holds; count from there."""
        self.client_sent = client_stream_bytes
        self.client_acked = client_stream_bytes
        self.retained.clear()
        self.retained_bytes = 0

    def _prune_retained(self) -> None:
        while self.retained and self.retained[0][0] + len(self.retained[0][1]) <= self.client_acked:
            _start, payload = self.retained.pop(0)
            self.retained_bytes -= len(payload)

    # -- WebSocket loss and resume ----------------------------------------

    def _ws_lost(self, ws: WebSocketClient, reason: str) -> None:
        if self.ws is not ws:
            return
        self.ws = None
        self.ws_generation += 1
        ws.abort()
        self.bridge.log('relay_connection_lost', reason=reason, server_offset=self.server_offset,
                        client_sent=self.client_sent, retained_bytes=self.retained_bytes)
        if self.resume_task is None or self.resume_task.done():
            self.resume_task = asyncio.create_task(self._resume())

    async def _resume(self) -> None:
        for attempt, delay in enumerate(self.bridge.retry_delays, 1):
            await asyncio.sleep(delay)
            try:
                ws = await self.bridge.connect_ws()
            except (BridgeError, ConnectionError, OSError, asyncio.TimeoutError) as error:
                self.bridge.log('relay_reconnect_failed', attempt=attempt, reason=type(error).__name__)
                continue
            try:
                async with self.send_lock:
                    await ws.send_text(json.dumps({
                        'ticket': self.bridge.ticket, 'resumeOffset': self.server_offset,
                        'greeting': False, 'clientOffset': self.client_sent,
                    }, separators=(',', ':')))
                    resumed = await asyncio.wait_for(self._await_resumed(ws), RESUME_EVENT_TIMEOUT_SECONDS)
                    if resumed is None:
                        return  # terminal close from the relay: the game socket is closing
                    client_received = resumed
                    # Everything below the relay's count must still be retained here;
                    # otherwise client bytes were lost for good and the game must CAReconn.
                    lowest = self.retained[0][0] if self.retained else self.client_sent
                    if client_received < lowest:
                        raise BridgeError('resume_client_gap')
                    resent = 0
                    for start, payload in self.retained:
                        end = start + len(payload)
                        if end <= client_received:
                            continue
                        tail = payload[max(0, client_received - start):]
                        await ws.send_binary(struct.pack('<H', len(tail)) + tail)
                        resent += len(tail)
                    self.ws = ws
                    self.ws_generation += 1
                    self.pump_task = asyncio.create_task(self._pump_ws_to_tcp(ws, self.ws_generation))
                self.bridge.log('relay_resumed', attempt=attempt, server_offset=self.server_offset,
                                client_received=client_received, resent_bytes=resent)
                return
            except BridgeError as error:
                self.bridge.log('relay_reconnect_rejected', attempt=attempt, reason=error.code)
                self.terminal_reason = error.code
                await ws.close(CLOSE_NORMAL, 'bridge_abort')
                self.writer.close()
                return
            except (ConnectionError, OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as error:
                self.bridge.log('relay_reconnect_failed', attempt=attempt, reason=type(error).__name__)
                ws.abort()
                continue
        self.terminal_reason = 'relay_retries_exhausted'
        self.bridge.log('relay_retries_exhausted', attempts=len(self.bridge.retry_delays))
        # Close the game socket: the game then performs its proven CAReconn reconnect.
        self.writer.close()

    async def _await_resumed(self, ws: WebSocketClient) -> int | None:
        while True:
            kind, value = await ws.receive()
            if kind == 'text':
                event = json.loads(value)  # type: ignore[arg-type]
                if isinstance(event, dict) and event.get('event') == 'resumed':
                    received = event.get('clientReceived')
                    if type(received) is not int or received < 0 or received > self.client_sent:
                        raise BridgeError('resume_client_offset')
                    self.bridge.log('relay_event', name='resumed', phase=str(event.get('phase', ''))[:16])
                    return received
                self._note_event(value)  # type: ignore[arg-type]
                continue
            if kind == 'close':
                code, _reason = value  # type: ignore[misc]
                if code in TERMINAL_CLOSE_CODES:
                    self.terminal_reason = f'relay_close_{code}'
                    self.bridge.log('relay_closed', code=code, terminal=True)
                    self.writer.close()
                    return None
                raise ConnectionError(f'relay_close_{code}')
            raise BridgeError('resume_unexpected_binary')


class RelayBridge:
    """Accepts the game's loopback connection and bridges it to the relay DO."""

    def __init__(self, ws_url: str, ticket: str, *, host: str = DEFAULT_LISTEN_HOST,
                 port: int = DEFAULT_LISTEN_PORT, ssl_context: ssl.SSLContext | None = None,
                 retry_delays: tuple[float, ...] = DEFAULT_RETRY_DELAYS,
                  ws_connect: ConnectFactory | None = None,
                  log: Callable[..., None] | None = None,
                  on_relay_event: Callable[[dict], None] | None = None,
                  expected_battle_id: str | None = None,
                  fresh_process_restart: bool = False):
        if type(ticket) is not str or not ticket or '.' not in ticket:
            raise ValueError('ticket must be a signed relay ticket string')
        if host not in ('127.0.0.1', '::1', 'localhost'):
            raise ValueError('the bridge only listens on loopback')
        if not 0 <= port <= 65535:
            raise ValueError('port must be 0..65535')
        if expected_battle_id is not None and (
                not isinstance(expected_battle_id, str) or not expected_battle_id):
            raise ValueError('expected_battle_id must be a non-empty string')
        if on_relay_event is not None and expected_battle_id is None:
            raise ValueError('relay event callback requires expected_battle_id')
        self.ws_url = ws_url
        self.ticket = ticket
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.retry_delays = tuple(retry_delays)
        self._ws_connect = ws_connect
        self._log = log
        self.on_relay_event = on_relay_event
        self.expected_battle_id = expected_battle_id
        if type(fresh_process_restart) is not bool:
            raise ValueError('fresh_process_restart must be a bool')
        self.fresh_process_restart = fresh_process_restart
        self.server: asyncio.base_events.Server | None = None
        self.link: _GameLink | None = None
        self.connections = 0
        self.rejected_concurrent = 0

    def log(self, event: str, **fields) -> None:
        row = {'time': time.time(), 'event': event, **fields}
        if self._log is not None:
            self._log(row)
        else:
            print(json.dumps(row, separators=(',', ':')), flush=True)

    async def connect_ws(self) -> WebSocketClient:
        if self._ws_connect is not None:
            return await self._ws_connect(self.ws_url)
        return await WebSocketClient.connect(self.ws_url, ssl_context=self.ssl_context)

    async def start(self) -> int:
        if self.host in ('127.0.0.1', '::1'):
            family = socket.AF_INET6 if self.host == '::1' else socket.AF_INET
            listener = socket.socket(family, socket.SOCK_STREAM)
            try:
                if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                if family == socket.AF_INET6:
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                try:
                    listener.bind((self.host, self.port))
                    listener.listen()
                except OSError as error:
                    raise annotate_bind_error(
                        error, transport='tcp',
                        family='ipv6' if family == socket.AF_INET6 else 'ipv4',
                        port=self.port)
                listener.setblocking(False)
                self.server = await asyncio.start_server(self._accept, sock=listener)
            except BaseException:
                listener.close()
                raise
        else:
            # `localhost` is a development-only alias with OS-dependent family.
            self.server = await asyncio.start_server(self._accept, self.host, self.port)
        self.port = self.server.sockets[0].getsockname()[1]
        self.log('ready', host=self.host, port=self.port)
        return self.port

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
        link = self.link
        if link is not None:
            link.writer.close()
            await asyncio.wait_for(link.done.wait(), 5)
        if self.server is not None:
            try:
                await asyncio.wait_for(self.server.wait_closed(), 3)
            except asyncio.TimeoutError:
                pass

    async def wait_closed(self) -> None:
        if self.link is not None:
            await self.link.done.wait()

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info('peername')
        if not peer or peer[0] not in ('127.0.0.1', '::1'):
            writer.close()
            return
        link = self.link
        if link is not None and not link.done.is_set():
            if not link.is_closing:
                # The game keeps one relay connection; a CAReconn reconnect
                # only arrives after the previous socket died.
                self.rejected_concurrent += 1
                self.log('rejected', reason='concurrent_game_connection')
                writer.close()
                return
            # The game reconnects ~20 ms after a drop (proven in the lab):
            # let the old link finish closing its WebSocket, then continue.
            try:
                await asyncio.wait_for(link.done.wait(), 5)
            except asyncio.TimeoutError:
                self.log('rejected', reason='previous_link_stuck')
                writer.close()
                return
        self.connections += 1
        link = _GameLink(self, reader, writer)
        self.link = link
        self.log('game_connection', number=self.connections)
        await link.run()


def build_ssl_context(*, insecure: bool = False, ca_file: str | None = None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=ca_file)
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--ws-url', required=True, help='wss://<worker>/v1/relay/<battleId>')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--ticket-file', type=Path, help='file containing the relay ticket (kept out of argv)')
    source.add_argument('--ticket-env', help='environment variable holding the relay ticket')
    parser.add_argument('--host', default=DEFAULT_LISTEN_HOST)
    parser.add_argument('--port', type=int, default=DEFAULT_LISTEN_PORT)
    parser.add_argument('--ca-file', default=None, help='extra CA bundle for wss')
    parser.add_argument('--insecure-tls', action='store_true', help='LOCAL TESTING ONLY: skip certificate verification')
    parser.add_argument('--trace', type=Path, default=None, help='append metadata-only JSON lines here')
    args = parser.parse_args(argv)
    if args.host not in ('127.0.0.1', '::1', 'localhost'):
        parser.error('the bridge only listens on loopback')
    if not 1 <= args.port <= 65535:
        parser.error('port must be 1..65535')
    return args


async def serve(args: argparse.Namespace) -> None:
    if args.ticket_file is not None:
        ticket = args.ticket_file.read_text('utf-8').strip()
    else:
        ticket = os.environ.get(args.ticket_env, '').strip()
    if not ticket:
        raise SystemExit('relay ticket missing')
    trace = None
    if args.trace is not None:
        args.trace.parent.mkdir(parents=True, exist_ok=True)
        trace = args.trace.open('a', encoding='utf-8')

    def log(row: dict) -> None:
        line = json.dumps(row, separators=(',', ':'))
        if trace is not None:
            trace.write(line + '\n')
            trace.flush()
        print(line, flush=True)

    context = None
    if args.ws_url.startswith('wss://'):
        context = build_ssl_context(insecure=args.insecure_tls, ca_file=args.ca_file)
    bridge = RelayBridge(args.ws_url, ticket, host=args.host, port=args.port, ssl_context=context, log=log)
    await bridge.start()
    try:
        await bridge.server.serve_forever()
    finally:
        await bridge.stop()
        if trace is not None:
            trace.close()


def main() -> None:
    args = parse_args()
    try:
        asyncio.run(serve(args))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
