"""Loopback-only, single-fake-player XMPP hub for a native connection probe.

This accepts offline SASL without verifying credentials; it is NOT production
authentication. Never expose these listeners through a tunnel or public route.
No game/profile/battle is started here. Only an explicit send_custom_starting()
call emits the native cg_starting notification, and delivery is not a battle ack.
Custom room notifications target only the native twa_notifications resource;
other bound streams retain their ordinary IQ, presence and pubsub responses.

trace receives one metadata-only dict, or is a Path for append-only JSONL. No
stanza, SASL response, hostname, IQ ID, UUID, or exception message is logged.
"""
from __future__ import annotations

import codecs
import copy
import ipaddress
import json
import re
import select
import socket
import ssl
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from xml.sax.saxutils import escape, quoteattr

from f2p_fake import PLAYER, active_native_user_id
from native_private_cpu_notifications import (
    CpuNotificationDeliveryUncertain,
    build_cpu_loadout_changed,
    build_cpu_member_joined,
    build_cpu_member_removed,
    build_cpu_ready_changed,
    build_human_loadout_changed,
    build_human_member_joined,
    build_human_member_removed,
    build_human_ready_changed,
    build_private_settings_changed,
)
from xmpp_stub import _digest_challenge, _iq_body, _open_stream, _tls_context

_SASL = "urn:ietf:params:xml:ns:xmpp-sasl"
_BIND = "urn:ietf:params:xml:ns:xmpp-bind"
_SESSION = "urn:ietf:params:xml:ns:xmpp-session"
_TLS = "urn:ietf:params:xml:ns:xmpp-tls"
_PUBSUB = "http://jabber.org/protocol/pubsub"
_LOOPBACK = frozenset(("127.0.0.1", "::1"))
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_TAG = re.compile(r"<(/?)([A-Za-z_][A-Za-z0-9_.:-]*)\b")
_STANZAS = frozenset(("stream:stream", "starttls", "auth", "response", "iq", "presence", "message"))
_MAX_LOADOUT_ROWS = 512
_MAX_LOADOUT_BYTES = 32768
_UINT64_MAX = (1 << 64) - 1
_NOTIFICATION_RESOURCE = "twa_notifications"
_DIAGNOSTIC_IQ_NAMESPACES = (
    'jabber:iq:auth', _BIND, _SESSION, 'jabber:iq:roster', 'jabber:iq:search',
    'vcard-temp', 'http://jabber.org/protocol/disco#info',
    'http://jabber.org/protocol/disco#items', _PUBSUB, 'jabber:iq:privacy',
    'urn:xmpp:blocking', 'urn:xmpp:ping',
)
_DIAGNOSTIC_ERROR_TYPES = frozenset((
    'ValueError', 'TypeError', 'KeyError', 'OSError', 'NetworkError',
    'ApiError', 'AuthError', 'ConflictError', 'MaintenanceError',
))


def _local_user() -> str:
    """The JID localpart of the one player this hub serves.

    The native XMPP client authenticates offline, so the localpart is a value
    this server chooses, not a client claim.  It follows the identity bound
    into ``f2p_fake`` so the JID, the profile ``user_id`` and the matchmaking
    roster can never disagree.
    """
    return active_native_user_id()


class XmppDeliveryUncertain(OSError):
    """A normal matchmaking send failed after delivery became uncertain."""

    def __init__(self):
        # Never include the socket error, JID or partially written stanza.
        super().__init__('native_matchmaking_delivery_uncertain')


def _game_id(value: str) -> str:
    if not isinstance(value, str) or not _UUID.fullmatch(value):
        raise ValueError("game_id must be a canonical UUID string")
    return str(uuid.UUID(value))


def _loadout_json(details: dict) -> str:
    """Validate the wire shape; ownership/faction checks belong to the caller."""
    required = {"commander_tier", "full_squad_setup"}
    if type(details) is not dict or not required <= details.keys() \
            or details.keys() - required - {"new_player", "premium"}:
        raise ValueError("invalid_loadout_fields")
    tier, rows = details["commander_tier"], details["full_squad_setup"]
    if type(tier) is not int or not 1 <= tier <= 10:
        raise ValueError("invalid_loadout_commander_tier")
    if type(rows) is not list or not 1 <= len(rows) <= _MAX_LOADOUT_ROWS:
        raise ValueError("invalid_loadout_rows")
    validated = []
    for row in rows:
        if type(row) is not list or len(row) != 4:
            raise ValueError("invalid_loadout_row")
        values = row.copy()
        if any(type(value) is not int or not 0 <= value <= _UINT64_MAX for value in values) \
                or values[1] == 0 or values[2] == 0:
            raise ValueError("invalid_loadout_uint64")
        validated.append(values)
    payload = {"commander_tier": tier, "full_squad_setup": validated}
    for key in ("new_player", "premium"):
        if key in details:
            value = details[key]
            if type(value) is not bool:
                raise ValueError("invalid_loadout_boolean")
            payload[key] = value
    # Python ints serialize as exact JSON integer literals, including >2**63.
    text = json.dumps(payload, separators=(",", ":"), allow_nan=False)
    if len(text.encode("utf-8")) > _MAX_LOADOUT_BYTES:
        raise ValueError("loadout_body_limit")
    return text


def _tag_end(text: str) -> int:
    quoted = ""
    for index, char in enumerate(text):
        if quoted:
            if char == quoted:
                quoted = ""
        elif char in "'\"":
            quoted = char
        elif char == ">":
            return index
    return -1


def _take_frame(text: str) -> tuple[str, str]:
    """Consume the first complete top-level stanza, preserving TCP order."""
    text = text.lstrip()
    if text.startswith("<?xml"):
        end = text.find("?>")
        if end < 0:
            return "", text
        text = text[end + 2:].lstrip()
    if not text:
        return "", ""
    if "<!" in text:
        raise ValueError("xml_declaration_not_supported")
    match = _TAG.match(text)
    if not match:
        if text == "<":
            return "", text
        # A tag name can be split across TCP reads.
        if re.fullmatch(r"</?[A-Za-z_:.-]*", text):
            return "", text
        raise ValueError("invalid_stanza")
    closing, name = match.groups()
    end = _tag_end(text)
    if end < 0:
        return "", text
    if name not in _STANZAS or (closing and name != "stream:stream"):
        raise ValueError("unsupported_stanza")
    if name == "stream:stream" or text[:end].rstrip().endswith("/"):
        return text[:end + 1], text[end + 1:]
    close = re.search(rf"</{re.escape(name)}\s*>", text[end + 1:])
    if not close:
        return "", text
    stop = end + 1 + close.end()
    return text[:stop], text[stop:]


def _attribute(element: ET.Element, name: str, default: str = "", maximum: int = 512) -> str:
    value = element.get(name, default)
    if len(value) > maximum:
        raise ValueError("attribute_limit")
    return value


def _iq_result(element: ET.Element, inner: str = "") -> str:
    identifier = quoteattr(_attribute(element, "id", "revival"))
    destination = _attribute(element, "to")
    origin = f" from={quoteattr(destination)}" if destination else ""
    return f"<iq type='result' id={identifier}{origin}>{inner}</iq>"


def _pubsub_event(host: str, node: str, jid: str) -> str:
    return (f"<message from={quoteattr('pubsub.' + host)} to={quoteattr(jid)} type='headline'>"
            "<event xmlns='http://jabber.org/protocol/pubsub#event'>"
            f"<items node={quoteattr(node)}><item id='1'><status>ok</status></item></items>"
            "</event></message>")


@dataclass(eq=False)
class _Client:
    number: int
    sock: socket.socket
    send_lock: threading.RLock = field(default_factory=threading.RLock)
    host: str = "127.0.0.1"
    authed: bool = False
    bound_jid: str | None = None
    resource: str = "twa"
    tls_done: bool = False
    digest_sent: bool = False
    closed: bool = False
    social_snapshot: dict | None = None
    diagnostic_iq_counts: dict = field(default_factory=dict, repr=False)


class NativeXmppProbe:
    def __init__(self, trace: Callable[[dict], None] | Path, *, max_clients: int = 8,
                 max_buffer_bytes: int = 65536, idle_timeout: float = 60.0):
        if not callable(trace) and not isinstance(trace, Path):
            raise TypeError("trace must be a callable or Path")
        if type(max_clients) is not int or not 1 <= max_clients <= 32:
            raise ValueError("max_clients must be 1..32")
        if type(max_buffer_bytes) is not int or not 128 <= max_buffer_bytes <= 65536:
            raise ValueError("max_buffer_bytes must be 128..65536")
        if not isinstance(idle_timeout, (int, float)) or not 0.1 <= idle_timeout <= 600:
            raise ValueError("idle_timeout must be 0.1..600 seconds")
        self.social = None
        self.social_party = None
        self._trace_target = trace
        self._trace_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._lifecycle_lock = threading.Lock()
        self._pending_lock = threading.Lock()
        self._pending_flush_lock = threading.Lock()
        self._stopping = threading.Event()
        self._stopping.set()
        self._listeners: list[socket.socket] = []
        self._clients: dict[int, _Client] = {}
        self._pending_custom_starts: set[str] = set()
        self._threads: set[threading.Thread] = set()
        self._next_id = 0
        self.max_clients = max_clients
        self.max_buffer_bytes = max_buffer_bytes
        self.idle_timeout = idle_timeout

    def _trace(self, event: str, **metadata: int | bool | str) -> None:
        row = {"time": time.time(), "event": event, **metadata}
        # A trace sink failure must not leak an exception containing user input.
        try:
            with self._trace_lock:
                if callable(self._trace_target):
                    self._trace_target(row)
                else:
                    self._trace_target.parent.mkdir(parents=True, exist_ok=True)
                    with self._trace_target.open("a", encoding="utf-8") as handle:
                        handle.write(json.dumps(row, separators=(",", ":")) + "\n")
        except Exception:
            pass

    @property
    def addresses(self) -> tuple[tuple[str, int], ...]:
        with self._state_lock:
            return tuple((sock.getsockname()[0], sock.getsockname()[1]) for sock in self._listeners)

    @property
    def bound_client_count(self) -> int:
        with self._state_lock:
            clients = tuple(self._clients.values())
        count = 0
        for client in clients:
            with client.send_lock:
                count += bool(client.bound_jid and not client.closed)
        return count

    @property
    def notification_client_count(self) -> int:
        """Streams that would actually receive a notification.

        ``bound_client_count`` also counts the chat connection, so it is not
        proof that a notification target exists (server/NATIVE_CONNECTION.md).
        This uses exactly ``_broadcast``'s eligibility test, so the companion
        can wait for a real ``twa_notifications`` stream before announcing.
        """
        with self._state_lock:
            clients = tuple(self._clients.values())
        count = 0
        for client in clients:
            with client.send_lock:
                count += bool(client.bound_jid and not client.closed
                              and client.resource == _NOTIFICATION_RESOURCE)
        return count

    def start(self, ports: tuple[int, ...] = (5222, 5223), *,
              hosts: tuple[str, ...] = ("127.0.0.1", "::1")) -> tuple[tuple[str, int], ...]:
        ports, hosts = tuple(ports), tuple(hosts)
        if not 1 <= len(ports) <= 4 or any(type(port) is not int or not 0 <= port <= 65535 for port in ports):
            raise ValueError("ports must contain 1..4 TCP ports in 0..65535")
        if not hosts or len(set(hosts)) != len(hosts) or any(host not in _LOOPBACK for host in hosts):
            raise ValueError("only literal loopback listeners are permitted")
        with self._lifecycle_lock:
            with self._state_lock:
                if self._listeners or any(thread.is_alive() for thread in self._threads):
                    raise RuntimeError("probe already started or still stopping")
            pending: list[tuple[socket.socket, bool]] = []
            try:
                for port in ports:
                    for host in hosts:
                        family = socket.AF_INET6 if host == "::1" else socket.AF_INET
                        listener = socket.socket(family, socket.SOCK_STREAM)
                        pending.append((listener, port == 5223))
                        # Do not steal a live Windows service's listening port.
                        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                        else:
                            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        if family == socket.AF_INET6:
                            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                        listener.bind((host, port))
                        listener.listen(self.max_clients)
                        listener.settimeout(0.2)
            except Exception:
                for listener, _ in pending:
                    listener.close()
                self._trace("xmpp_bind_failed")
                raise
            self._stopping.clear()
            with self._state_lock:
                self._listeners = [listener for listener, _ in pending]
                for listener, implicit_tls in pending:
                    thread = threading.Thread(target=self._accept, args=(listener, implicit_tls), daemon=True)
                    self._threads.add(thread)
                    thread.start()
            self._trace("xmpp_ready", listeners=len(pending), ready=True)
            return self.addresses

    def stop(self) -> None:
        with self._lifecycle_lock:
            self._stopping.set()
            with self._pending_lock:
                pending_count = len(self._pending_custom_starts)
                self._pending_custom_starts.clear()
            with self._state_lock:
                listeners, self._listeners = self._listeners, []
                clients = tuple(self._clients.values())
            for listener in listeners:
                listener.close()
            for client in clients:
                self._close(client)
            with self._state_lock:
                threads = tuple(self._threads)
            deadline = time.monotonic() + 3
            for thread in threads:
                if thread is not threading.current_thread():
                    thread.join(max(0, deadline - time.monotonic()))
            if pending_count:
                self._trace('xmpp_custom_start_cancelled', pending=pending_count,
                            reason='probe_stopped')
            self._trace("xmpp_stopped", ready=False)

    def _accept(self, listener: socket.socket, implicit_tls: bool) -> None:
        try:
            while not self._stopping.is_set():
                try:
                    sock, address = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with self._state_lock:
                    rejected = (self._stopping.is_set() or len(self._clients) >= self.max_clients or
                                not ipaddress.ip_address(address[0]).is_loopback)
                    if not rejected:
                        self._next_id += 1
                        client = _Client(self._next_id, sock)
                        self._clients[client.number] = client
                        thread = threading.Thread(target=self._handle, args=(client, implicit_tls), daemon=True)
                        self._threads.add(thread)
                        thread.start()
                if rejected:
                    sock.close()
                    self._trace("xmpp_connection_rejected")
        finally:
            with self._state_lock:
                self._threads.discard(threading.current_thread())

    def _close(self, client: _Client) -> None:
        with client.send_lock:
            if client.closed:
                return
            client.closed = True
            client.bound_jid = None
            client.resource = "twa"
            try:
                client.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client.sock.close()
        with self._state_lock:
            self._clients.pop(client.number, None)
        self._trace("xmpp_closed", connection=client.number, ready=False)

    def _send(self, client: _Client, text: str) -> None:
        data = text.encode("utf-8")
        if len(data) > 65536:
            raise ValueError("send_limit")
        with client.send_lock:
            if client.closed or self._stopping.is_set():
                raise OSError("probe_closed")
            client.sock.sendall(data)
        self._trace("xmpp_sent", connection=client.number, bytes=len(data))

    def _upgrade_tls(self, client: _Client) -> None:
        with client.send_lock:
            if client.closed or self._stopping.is_set():
                raise OSError("probe_closed")
            client.bound_jid = None
            client.resource = "twa"
            client.authed = False
            client.digest_sent = False
            client.sock = _tls_context().wrap_socket(client.sock, server_side=True, do_handshake_on_connect=False)
        client.sock.do_handshake()
        client.tls_done = True
        self._trace("xmpp_tls", connection=client.number, ready=True)

    def _receive(self, client: _Client) -> bytes:
        # SSLSocket read/write share one TLS state machine. Wait outside the
        # lock so a quiet client cannot delay a battle-ready notification.
        with client.send_lock:
            if client.closed:
                return b""
            buffered = isinstance(client.sock, ssl.SSLSocket) and client.sock.pending() > 0
        if not buffered and not select.select([client.sock], [], [], 0.2)[0]:
            raise socket.timeout()
        with client.send_lock:
            if client.closed:
                return b""
            return client.sock.recv(8192)

    def _handle(self, client: _Client, implicit_tls: bool) -> None:
        self._trace("xmpp_connected", connection=client.number, ready=False)
        try:
            client.sock.settimeout(min(2.0, self.idle_timeout))
            if implicit_tls or client.sock.recv(1, socket.MSG_PEEK) == b"\x16":
                self._upgrade_tls(client)
            decoder = codecs.getincrementaldecoder("utf-8")("strict")
            buffer = ""
            total_bytes = stanzas = 0
            last_received = time.monotonic()
            while not self._stopping.is_set() and not client.closed:
                try:
                    raw = self._receive(client)
                except socket.timeout:
                    if time.monotonic() - last_received >= self.idle_timeout:
                        self._trace("xmpp_idle_limit", connection=client.number)
                        break
                    continue
                if not raw:
                    self._trace("xmpp_peer_eof", connection=client.number)
                    break
                last_received = time.monotonic()
                total_bytes += len(raw)
                self._trace("xmpp_received", connection=client.number, bytes=len(raw))
                buffer += decoder.decode(raw)
                if len(buffer.encode("utf-8")) > self.max_buffer_bytes or total_bytes > 4 * 1024 * 1024:
                    self._trace("xmpp_buffer_limit", connection=client.number)
                    break
                while True:
                    stanza, buffer = _take_frame(buffer)
                    if not stanza:
                        break
                    stanzas += 1
                    if stanzas > 4096:
                        self._trace("xmpp_stanza_limit", connection=client.number)
                        return
                    if not self._stanza(client, stanza):
                        return
        except (OSError, ValueError, ET.ParseError, UnicodeError):
            self._trace("xmpp_protocol_end", connection=client.number)
        finally:
            self._close(client)
            with self._state_lock:
                self._threads.discard(threading.current_thread())

    def _stanza(self, client: _Client, stanza: str) -> bool:
        if stanza.startswith("</stream:stream"):
            self._send(client, "</stream:stream>")
            return False
        if stanza.startswith("<stream:stream"):
            stream = ET.fromstring(stanza[:-1] + "/>")
            host = _attribute(stream, "to", "127.0.0.1", 253)
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,253}", host):
                raise ValueError("invalid_stream_host")
            client.host = host
            self._send(client, _open_stream(host, client.authed, not client.tls_done))
            return True
        element = ET.fromstring(stanza)
        kind = element.tag.rsplit("}", 1)[-1]
        if element.tag == "{" + _TLS + "}starttls":
            if client.tls_done:
                raise ValueError("tls_already_active")
            self._send(client, "<proceed xmlns='" + _TLS + "'/>")
            self._upgrade_tls(client)
        elif element.tag == "{" + _SASL + "}auth":
            mechanism = _attribute(element, "mechanism", maximum=32)
            with client.send_lock:
                client.bound_jid = None
                client.resource = "twa"
            if mechanism == "DIGEST-MD5" and not client.digest_sent:
                client.digest_sent = True
                self._send(client, "<challenge xmlns='" + _SASL + "'>" + _digest_challenge(client.host) + "</challenge>")
            elif mechanism in ("PLAIN", "ANONYMOUS", "DIGEST-MD5"):
                client.authed = True
                self._send(client, "<success xmlns='" + _SASL + "'/>")
                self._trace("xmpp_offline_auth", connection=client.number)
            else:
                raise ValueError("unsupported_sasl_mechanism")
        elif element.tag == "{" + _SASL + "}response":
            if not client.digest_sent:
                raise ValueError("unexpected_sasl_response")
            client.authed = True
            self._send(client, "<success xmlns='" + _SASL + "'/>")
            self._trace("xmpp_offline_auth", connection=client.number)
        elif kind == "iq":
            self._iq(client, element)
        elif kind == "presence":
            if self.social is not None and client.bound_jid:
                try:
                    if self.social.presence(element):
                        return True
                except Exception:
                    self._send(client, "<presence type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>")
                    return True
            jid = quoteattr(client.bound_jid or _local_user() + "@" + client.host + "/twa")
            self._send(client, f"<presence from={jid} to={jid}/>")
        return True

    def _trace_iq(self, client: _Client, element: ET.Element, *, error=None) -> None:
        """Fixed labels only, at most two rows per classification per stream.

        Unknown namespace/type/exception names collapse to 'other'; attribute
        names, IDs, JIDs, values and stanza text never enter the trace. Search
        has its own count so earlier discovery/roster traffic cannot hide it.
        """
        tags = {node.tag for node in element.iter()}
        namespace = next((space for space in _DIAGNOSTIC_IQ_NAMESPACES
                          if any(tag.startswith('{' + space + '}') for tag in tags)), 'other')
        kind = element.get('type')
        kind = kind if kind in ('get', 'set', 'result', 'error') else 'other'
        error_type = None if error is None else type(error).__name__
        if error_type is not None and error_type not in _DIAGNOSTIC_ERROR_TYPES:
            error_type = 'other'
        event = 'xmpp_iq_parsed' if error is None else 'xmpp_social_iq_failed'
        key = (event, namespace, kind, error_type)
        with client.send_lock:
            count = client.diagnostic_iq_counts.get(key, 0)
            if count >= 2:
                return
            client.diagnostic_iq_counts[key] = count + 1
            bound = bool(client.bound_jid and not client.closed)
        metadata = {'connection': client.number, 'kind': 'iq', 'type': kind,
                    'namespace': namespace, 'bound': bound,
                    'social_attached': self.social is not None,
                    'frame_parsed': True, 'occurrence': count + 1}
        if error_type is not None:
            metadata['error_type'] = error_type
        self._trace(event, **metadata)

    def _iq(self, client: _Client, element: ET.Element) -> None:
        self._trace_iq(client, element)
        if self.social is not None and client.bound_jid:
            try:
                if element.get('type') == 'get' and element.find('{jabber:iq:roster}query') is not None:
                    self._social_roster_result(client, element)
                    return
                inner = self.social.iq(element, client.host)
                if inner is not None:
                    self._send(client, _iq_result(element, inner))
                    return
            except Exception as error:
                self._trace_iq(client, element, error=error)
                self._send(client, "<iq type='error' id=" + quoteattr(_attribute(element, "id", "revival")) + "><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")
                return
        tags = {child.tag for child in element.iter()}
        if "{jabber:iq:auth}query" in tags:
            if element.get("type") == "get":
                self._send(client, _iq_result(element, "<query xmlns='jabber:iq:auth'><username/><password/><resource/></query>"))
            elif element.get("type") == "set":
                client.authed = True
                self._bind(client, element, legacy=True)
            else:
                self._send(client, _iq_result(element))
        elif "{" + _BIND + "}bind" in tags:
            if not client.authed:
                raise ValueError("bind_before_offline_auth")
            self._bind(client, element)
        elif "{" + _SESSION + "}session" in tags:
            self._send(client, _iq_result(element))
        elif any(tag.startswith("{" + _PUBSUB + "}") for tag in tags):
            node = next((_attribute(child, "node") for child in element.iter() if child.get("node") is not None), "news")
            inner = ("<pubsub xmlns='" + _PUBSUB + "'>"
                     f"<subscription node={quoteattr(node)} jid={quoteattr(_local_user())} subscription='subscribed'/>"
                     f"<items node={quoteattr(node)}/></pubsub>")
            self._send(client, _iq_result(element, inner))
            if "{" + _PUBSUB + "}subscribe" in tags:
                jid = client.bound_jid or _local_user() + "@" + client.host + "/twa"
                self._send(client, _pubsub_event(client.host, node, jid))
                if node != "caprofile.xmpp.twa":
                    self._send(client, _pubsub_event(client.host, "caprofile.xmpp.twa", jid))
        else:
            # Pass only a known fixed namespace into the legacy helper, never
            # stanza text that could select its unescaped pubsub interpolation.
            fixed = ("jabber:iq:roster", "jabber:iq:privacy", "urn:xmpp:blocking", "vcard-temp",
                     "http://jabber.org/protocol/disco#info", "http://jabber.org/protocol/disco#items")
            namespace = next((space for space in fixed if any(tag.startswith("{" + space + "}") for tag in tags)), "")
            self._send(client, _iq_result(element, _iq_body(namespace) if namespace else ""))

    def publish_social(self, before: dict, after: dict) -> None:
        """Publish only this local user's authenticated friends and requests."""
        with self._state_lock:
            clients = tuple(self._clients.values())
        for client in clients:
            if not client.bound_jid or client.closed:
                continue
            try:
                self._send_social(client, before, after)
            except OSError:
                self._trace('xmpp_social_delivery_failed', connection=client.number)
                self._close(client)

    def _send_social(self, client: _Client, before: dict, after: dict) -> None:
        # API callbacks may arrive in a different order from their responses.
        # Serialize per native stream, without holding NativeSocial's state lock.
        with client.send_lock:
            previous = client.social_snapshot
            if previous is not None:
                old_revision, revision = previous.get('revision'), after.get('revision')
                if type(old_revision) is int and (type(revision) is not int or revision < old_revision):
                    return
                before = previous
            self._send_social_ordered(client, before, after)
            client.social_snapshot = copy.deepcopy(after)

    def _social_roster_result(self, client: _Client, element: ET.Element) -> None:
        # Presence sent during bind may precede the client's initial roster
        # load. Replay it after the roster result, even if the graph is unchanged.
        # Snapshot reads do not call the API or a publisher while send_lock is held.
        from native_social import NativeSocial
        with client.send_lock:
            state = self.social.snapshot()
            previous = client.social_snapshot
            if previous is not None:
                old_revision, revision = previous.get('revision'), state.get('revision')
                if type(old_revision) is int and (type(revision) is not int or revision < old_revision):
                    state = copy.deepcopy(previous)
            items = (NativeSocial._roster_item(row, client.host, subscription)
                     for row, subscription in NativeSocial.roster_entries(state).values())
            body = "<query xmlns='jabber:iq:roster'>" + ''.join(items) + '</query>'
            self._send(client, _iq_result(element, body))
            self._send_social_presence(client, previous or {}, state, force=True)
            client.social_snapshot = copy.deepcopy(state)

    def _send_social_ordered(self, client: _Client, before: dict, after: dict) -> None:
        from native_social import NativeSocial
        old_entries = NativeSocial.roster_entries(before)
        entries = NativeSocial.roster_entries(after)
        destination = quoteattr(client.bound_jid)
        for user in old_entries.keys() - entries.keys():
            item = NativeSocial._roster_item(old_entries[user][0], client.host, 'remove')
            self._send(client, "<iq type='set' id=" + quoteattr('social-' + uuid.uuid4().hex) + " to=" + destination + "><query xmlns='jabber:iq:roster'>" + item + "</query></iq>")
        for user, (row, subscription) in entries.items():
            if old_entries.get(user) == (row, subscription):
                continue
            item = NativeSocial._roster_item(row, client.host, subscription)
            self._send(client, "<iq type='set' id=" + quoteattr('social-' + uuid.uuid4().hex) + " to=" + destination + "><query xmlns='jabber:iq:roster'>" + item + "</query></iq>")
        self._send_social_presence(client, before, after)

    def _send_social_presence(self, client: _Client, before: dict, after: dict, *, force: bool = False) -> None:
        old_friends = {row['id']: row for row in before.get('friends', [])}
        friends = {row['id']: row for row in after.get('friends', [])}
        destination = quoteattr(client.bound_jid)
        for user in old_friends.keys() - friends.keys():
            self._send(client, '<presence type="unavailable" from=' + quoteattr(user + '@' + client.host) + ' to=' + destination + '/>')
        for user, row in friends.items():
            if not force and old_friends.get(user) == row:
                continue
            jid = quoteattr(user + '@' + client.host)
            native_status = {'online': '', 'in_party': 'in_party',
                             'matchmaking': 'in_mm', 'in_battle': 'in_battle'}
            offline = row.get('status') not in native_status
            self._send(client, '<presence' + (' type="unavailable"' if offline else '') + ' from=' + jid + ' to=' + destination + '><status>' + native_status.get(row.get('status'), '') + '</status></presence>')

    def _bind(self, client: _Client, element: ET.Element, legacy: bool = False) -> None:
        namespace, container_tag = ("jabber:iq:auth", "query") if legacy else (_BIND, "bind")
        containers = element.findall("{" + namespace + "}" + container_tag)
        if len(containers) != 1:
            raise ValueError("invalid_bind_container")
        resources = containers[0].findall("{" + namespace + "}resource")
        if len(resources) > 1 or resources and len(resources[0]):
            raise ValueError("invalid_bind_resource")
        resource = resources[0].text if resources else None
        resource = resource or "twa"
        if len(resource) > 128 or len(resource.encode("utf-8")) > 256 \
                or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in resource):
            raise ValueError("invalid_bind_resource")
        jid = _local_user() + "@" + client.host + "/" + resource
        body = "" if legacy else "<bind xmlns='" + _BIND + "'><jid>" + escape(jid) + "</jid></bind>"
        with client.send_lock:
            self._send(client, _iq_result(element, body))
            client.resource = resource
            client.bound_jid = jid
        channel = "notifications" if resource == _NOTIFICATION_RESOURCE else "other"
        self._trace("xmpp_bound", connection=client.number, ready=True, channel=channel)
        if self.social is not None:
            self._send_social(client, {}, self.social.snapshot())
        if resource == _NOTIFICATION_RESOURCE:
            self._flush_pending_custom_starts()
            if self.social_party is not None:
                try:
                    self.social_party.resync()
                except Exception as error:
                    self._trace('xmpp_social_party_resync_failed',
                                error_type=type(error).__name__)

    def send_social_party(self, event: str, inner: str) -> int:
        allowed = {'party_invite', 'reconnected_to_party', 'party_invite_revoked',
                   'party_member_added', 'new_party_leader', 'party_member_removed',
                   'party_member_status_changed'}
        if event not in allowed or not isinstance(inner, str) or len(inner) > 65536:
            raise ValueError('invalid_social_party_notification')
        try:
            root = ET.fromstring(inner)
        except ET.ParseError:
            raise ValueError('invalid_social_party_notification') from None
        if root.tag != '{http://arenatw.co.uk/xmpp}' + event:
            raise ValueError('invalid_social_party_notification')
        # Stock checks the exact full sender; adding a resource also fails.
        return self._broadcast(inner, 'xmpp_social_' + event,
                               sender='camm.xmpp.twa', strict_delivery=True)

    def _broadcast(self, inner: str, event: str, *, sender: str = 'cacugs.xmpp.twa',
                   strict_delivery: bool = False, **metadata: bool) -> int:
        if sender not in ('cacugs.xmpp.twa', 'camm.xmpp.twa'):
            raise ValueError('unsupported native notification sender')
        with self._state_lock:
            clients = tuple(self._clients.values())
        sent = 0
        uncertain = False
        for client in clients:
            try:
                with client.send_lock:
                    if client.closed or not client.bound_jid or client.resource != _NOTIFICATION_RESOURCE:
                        continue
                    message = ("<message from=" + quoteattr(sender) + " to=" + quoteattr(client.bound_jid) + " type='normal'>"
                               + inner + "</message>")
                    self._send(client, message)
                sent += 1
            except OSError:
                # sendall may have written part or all of the stanza before
                # failing. Normal matchmaking must not mistake that for an
                # absent notification stream and blindly retry its start.
                uncertain = True
                self._close(client)
        if strict_delivery and uncertain:
            self._trace('xmpp_matchmaking_delivery_uncertain', clients=sent)
            raise XmppDeliveryUncertain() from None
        self._trace(event, clients=sent, **metadata)
        return sent

    def send_matchmaking_state(self, state: str) -> int:
        """Ordinary Play state, from CAMM and only to twa_notifications.

        The battle_ready state asks the native client to fetch /check. The
        caller must commit a complete, verified battle response before sending
        it. This notification alone is not proof that a battle can be played.
        Zero means no eligible stream; a send failure raises the safe
        XmppDeliveryUncertain even if another stream was sent successfully.
        """
        if state not in ('ready', 'waiting', 'in_mm', 'requeue', 'battle_ready', 'failed', 'cancelled'):
            raise ValueError('unsupported native matchmaking state')
        inner = ("<mm_state_changed xmlns='http://arenatw.co.uk/xmpp'><new_state>" + state +
                 "</new_state></mm_state_changed>")
        return self._broadcast(inner, 'xmpp_matchmaking_state', sender='camm.xmpp.twa',
                               strict_delivery=True,
                               battle_ready=state == 'battle_ready')

    def send_custom_starting(self, game_id: str) -> int:
        inner = ("<cg_starting xmlns='http://arenatw.co.uk/xmpp'><cg_id>" + escape(_game_id(game_id)) +
                 "</cg_id></cg_starting>")
        return self._broadcast(inner, "xmpp_custom_starting")

    def _flush_pending_custom_starts(self) -> int:
        """Deliver each queued start once to a bound notification stream."""
        delivered = 0
        with self._pending_flush_lock:
            while not self._stopping.is_set():
                with self._pending_lock:
                    game_id = next(iter(self._pending_custom_starts), None)
                if game_id is None:
                    break
                recipients = self.send_custom_starting(game_id)
                if recipients <= 0:
                    break
                with self._pending_lock:
                    self._pending_custom_starts.discard(game_id)
                delivered += recipients
                self._trace('xmpp_custom_start_dequeued', clients=recipients)
        return delivered

    def send_or_queue_custom_starting(self, game_id: str) -> int:
        """Accept a start while the native notification resource is rebinding.

        Entering custom battle can replace ``twa_notifications`` a few seconds
        after ``/start_game``.  The validated room ID remains in a small
        in-memory outbox and is flushed when that resource binds again.  The
        return value is one accepted delivery job, not a live socket count.
        """
        game_id = _game_id(game_id)
        if self._stopping.is_set():
            return 0
        with self._pending_lock:
            already_queued = game_id in self._pending_custom_starts
            self._pending_custom_starts.add(game_id)
        delivered = self._flush_pending_custom_starts()
        with self._pending_lock:
            pending = game_id in self._pending_custom_starts
        if pending and not already_queued:
            self._trace('xmpp_custom_start_queued', pending=1)
        return 1 if delivered or pending or already_queued else 0

    def cancel_queued_custom_starting(self, game_id: str) -> bool:
        """Cancel an undelivered start when its room is left or unreadied."""
        game_id = _game_id(game_id)
        # Serialize with dequeue+send. After this returns True no concurrent
        # bind thread can still emit the cancelled cg_starting stanza.
        with self._pending_flush_lock:
            with self._pending_lock:
                existed = game_id in self._pending_custom_starts
                self._pending_custom_starts.discard(game_id)
        if existed:
            self._trace('xmpp_custom_start_cancelled', pending=1,
                        reason='lobby_state_changed')
        return existed

    def send_player_ready(self, game_id: str, ready: bool) -> int:
        game_id = _game_id(game_id)
        if type(ready) is not bool:
            raise ValueError("ready must be bool")
        state = "ready" if ready else "not_ready"
        inner = ("<player_state_changed xmlns='http://arenatw.co.uk/xmpp'><cg_id>" + escape(game_id) +
                 "</cg_id><player_id>" + escape(_local_user()) + "</player_id><new_state>" + state +
                 "</new_state></player_state_changed>")
        return self._broadcast(inner, "xmpp_player_ready", ready=ready)

    def send_player_loadout(self, game_id: str, details: dict) -> int:
        """Notify an already verified local owned squad, without starting play.

        The native loadout branch requires JSON text directly under <loadout>;
        new_state/new_team would select different branches and are omitted.
        No profile_matchmaking_details wrapper or arbitrary fields are sent.
        """
        game_id = _game_id(game_id)
        text = _loadout_json(details)
        inner = ("<player_state_changed xmlns='http://arenatw.co.uk/xmpp'><cg_id>" + escape(game_id) +
                 "</cg_id><player_id>" + escape(_local_user()) + "</player_id><loadout>" + escape(text) +
                 "</loadout></player_state_changed>")
        return self._broadcast(inner, "xmpp_player_loadout")

    def send_cpu_member_removed(self, game_id: str, removed_player: str) -> int:
        """Publish the statically identified custom-game removal payload."""
        inner = build_cpu_member_removed(game_id, removed_player)
        return self._broadcast_cpu(inner, "xmpp_cpu_member_removed")

    def send_cpu_member_joined(self, game_id: str, player: dict) -> int:
        """Publish one trusted server-built CPU row to the native roster."""
        inner = build_cpu_member_joined(game_id, player)
        return self._broadcast_cpu(inner, "xmpp_cpu_member_joined")

    def send_cpu_ready(self, game_id: str, player_id: str) -> int:
        """Mark a late-joined trusted CPU ready using the native state branch."""
        inner = build_cpu_ready_changed(game_id, player_id)
        return self._broadcast_cpu(inner, "xmpp_cpu_ready")

    def send_cpu_loadout(self, game_id: str, player_id: str,
                         details: dict) -> int:
        """Refresh a trusted CPU row after the human battle tier changes."""
        inner = build_cpu_loadout_changed(game_id, player_id, details)
        return self._broadcast_cpu(inner, "xmpp_cpu_loadout")

    def send_private_human_joined(self, game_id: str, player: dict) -> int:
        return self._broadcast_private_human(
            build_human_member_joined(game_id, player),
            "xmpp_private_human_joined")

    def send_private_human_removed(self, game_id: str, player_id: str) -> int:
        return self._broadcast_private_human(
            build_human_member_removed(game_id, player_id),
            "xmpp_private_human_removed")

    def send_private_human_loadout(self, game_id: str, player_id: str,
                                   details: dict) -> int:
        return self._broadcast_private_human(
            build_human_loadout_changed(game_id, player_id, details),
            "xmpp_private_human_loadout")

    def send_private_human_ready(self, game_id: str, player_id: str,
                                 ready: bool) -> int:
        return self._broadcast_private_human(
            build_human_ready_changed(game_id, player_id, ready),
            "xmpp_private_human_ready")

    def _broadcast_private_human(self, inner: str, event: str) -> int:
        """Strict delivery boundary for validated private human mutations."""
        try:
            return self._broadcast(inner, event, strict_delivery=True)
        except XmppDeliveryUncertain:
            raise CpuNotificationDeliveryUncertain() from None

    def send_private_settings_changed(self, game_id: str, settings: dict) -> int:
        return self._broadcast_private_human(
            build_private_settings_changed(game_id, settings),
            "xmpp_private_settings_changed")

    def _broadcast_cpu(self, inner: str, event: str) -> int:
        """Never retry a CPU mutation after socket delivery became uncertain."""
        try:
            return self._broadcast(inner, event, strict_delivery=True)
        except XmppDeliveryUncertain:
            raise CpuNotificationDeliveryUncertain() from None
