"""Accept gloox C2S so hangar can leave the profile spinner."""
from __future__ import annotations

import base64
import re
import socket
import ssl
import threading
from pathlib import Path

from f2p_fake import PLAYER

PORTS = (5222, 5223)
CERT = Path(__file__).resolve().parent / "certs" / "cert.pem"
KEY = Path(__file__).resolve().parent / "certs" / "key.pem"
ID_RE = re.compile(r"""\bid=['"]([^'"]+)['"]""")
TO_RE = re.compile(r"""\bto=['"]([^'"]+)['"]""")
NODE_RE = re.compile(r"""\bnode=['"]([^'"]+)['"]""")


def _digest_challenge(host: str) -> str:
    return base64.b64encode(
        f'nonce="revival",realm="{host}",qop="auth",charset=utf-8,algorithm=md5-sess'.encode(
            "ascii"
        )
    ).decode("ascii")


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except ValueError:
        pass
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    ctx.load_cert_chain(str(CERT), str(KEY))
    return ctx


def _send(sock: socket.socket, text: str) -> None:
    sock.sendall(text.encode("utf-8"))


def _iq_id(chunk: str) -> str:
    match = ID_RE.search(chunk)
    return match.group(1) if match else "revival"


def _host(chunk: str) -> str:
    match = TO_RE.search(chunk)
    return match.group(1) if match else "127.0.0.1"


def _iq_result(chunk: str, inner: str = "") -> str:
    dest = TO_RE.search(chunk)
    from_attr = f" from='{dest.group(1)}'" if dest else ""
    if inner:
        return f"<iq type='result' id='{_iq_id(chunk)}'{from_attr}>{inner}</iq>"
    return f"<iq type='result' id='{_iq_id(chunk)}'{from_attr}/>"


def _take_stanza(buf: str) -> tuple[str, str]:
    low = buf.lower()
    stream = low.find("<stream:stream")
    if stream >= 0:
        gt = buf.find(">", stream)
        if gt >= 0:
            return buf[stream : gt + 1], buf[gt + 1 :]
        return "", buf
    for tag in (
        "starttls",
        "response",
        "auth",
        "iq",
        "presence",
        "message",
        "/stream:stream",
    ):
        open_at = low.find(f"<{tag}")
        if open_at < 0:
            continue
        close_tag = tag.lstrip("/")
        close = low.find(f"</{close_tag}>", open_at)
        if close >= 0:
            end = close + len(close_tag) + 3
            return buf[open_at:end], buf[end:]
        gt = buf.find(">", open_at)
        if gt >= 0 and (buf[gt - 1] == "/" or tag.startswith("/")):
            return buf[open_at : gt + 1], buf[gt + 1 :]
    return "", buf


def _features(authed: bool, offer_tls: bool) -> str:
    if authed:
        return (
            "<stream:features>"
            "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>"
            "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>"
            "</stream:features>"
        )
    parts = ["<stream:features>"]
    if offer_tls:
        parts.append(
            "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>"
        )
    else:
        parts.append(
            "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
            "<mechanism>DIGEST-MD5</mechanism>"
            "<mechanism>PLAIN</mechanism>"
            "<mechanism>ANONYMOUS</mechanism>"
            "</mechanisms>"
            "<auth xmlns='http://jabber.org/features/iq-auth'/>"
        )
    parts.append("</stream:features>")
    return "".join(parts)


def _open_stream(host: str, authed: bool, offer_tls: bool) -> str:
    return (
        "<?xml version='1.0'?>"
        f"<stream:stream from='{host}' id='revival' xml:lang='en' "
        "xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' "
        f"version='1.0'>{_features(authed, offer_tls)}"
    )


def _wrap_tls(sock: socket.socket, addr: tuple[str, int]) -> socket.socket:
    print(f"xmpp starttls {addr}", flush=True)
    return _tls_context().wrap_socket(sock, server_side=True)


def _iq_body(chunk: str) -> str:
    low = chunk.lower()
    if "jabber:iq:roster" in low:
        return "<query xmlns='jabber:iq:roster'/>"
    if "jabber:iq:privacy" in low:
        return "<query xmlns='jabber:iq:privacy'/>"
    if "urn:xmpp:blocking" in low:
        return "<blocklist xmlns='urn:xmpp:blocking'/>"
    if "vcard-temp" in low:
        return (
            "<vCard xmlns='vcard-temp'>"
            f"<FN>{PLAYER}</FN><NICKNAME>{PLAYER}</NICKNAME>"
            "</vCard>"
        )
    if "disco#info" in low:
        return (
            "<query xmlns='http://jabber.org/protocol/disco#info'>"
            "<identity category='pubsub' type='service' name='revival'/>"
            "<feature var='http://jabber.org/protocol/pubsub'/>"
            "<feature var='http://jabber.org/protocol/pubsub#subscribe'/>"
            "<feature var='http://jabber.org/protocol/disco#info'/>"
            "<feature var='http://jabber.org/protocol/disco#items'/>"
            "</query>"
        )
    if "disco#items" in low:
        return "<query xmlns='http://jabber.org/protocol/disco#items'/>"
    if "http://jabber.org/protocol/pubsub" in low:
        match = NODE_RE.search(chunk)
        node = match.group(1) if match else "news"
        return (
            "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
            f"<subscription node='{node}' jid='{PLAYER}' subscription='subscribed'/>"
            f"<items node='{node}'/>"
            "</pubsub>"
        )
    return ""


def _pubsub_event(host: str, node: str) -> str:
    return (
        f"<message from='pubsub.{host}' to='{PLAYER}@{host}/twa' type='headline'>"
        "<event xmlns='http://jabber.org/protocol/pubsub#event'>"
        f"<items node='{node}'>"
        "<item id='1'><status>ok</status></item>"
        "</items></event></message>"
    )


def _handle(sock: socket.socket, addr: tuple[str, int], implicit_tls: bool) -> None:
    local = sock.getsockname()
    print(f"xmpp connect {addr} local={local}", flush=True)
    host = "127.0.0.1"
    authed = False
    tls_done = implicit_tls
    digest_sent = False
    buf = ""
    try:
        sock.settimeout(60)
        if implicit_tls or (sock.recv(1, socket.MSG_PEEK) == b"\x16"):
            sock = _wrap_tls(sock, addr)
            tls_done = True
        while True:
            raw = sock.recv(8192)
            if not raw:
                break
            print(f"xmpp recv {addr} {raw[:240]!r}", flush=True)
            buf += raw.decode("utf-8", "replace")
            while True:
                stanza, rest = _take_stanza(buf)
                if not stanza:
                    break
                buf = rest
                low = stanza.lower()
                if "<stream:stream" in low:
                    host = _host(stanza)
                    _send(sock, _open_stream(host, authed, not tls_done))
                    continue
                if "</stream:stream" in low:
                    _send(sock, "</stream:stream>")
                    return
                if "starttls" in low and "xmpp-tls" in low:
                    _send(sock, "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
                    sock = _wrap_tls(sock, addr)
                    tls_done = True
                    authed = False
                    continue
                if "<response" in low and "xmpp-sasl" in low:
                    authed = True
                    _send(sock, "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")
                    continue
                if "digest-md5" in low and "<auth" in low and not digest_sent:
                    digest_sent = True
                    _send(
                        sock,
                        "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                        f"{_digest_challenge(host)}</challenge>",
                    )
                    continue
                if "urn:ietf:params:xml:ns:xmpp-sasl" in low and "<auth" in low:
                    authed = True
                    _send(sock, "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")
                    continue
                if "jabber:iq:auth" in low and "type='get'" in low:
                    _send(
                        sock,
                        _iq_result(
                            stanza,
                            "<query xmlns='jabber:iq:auth'>"
                            "<username/><password/><resource/>"
                            "</query>",
                        ),
                    )
                    continue
                if "jabber:iq:auth" in low and "type='set'" in low:
                    authed = True
                    _send(sock, _iq_result(stanza))
                    continue
                if "urn:ietf:params:xml:ns:xmpp-bind" in low:
                    _send(
                        sock,
                        _iq_result(
                            stanza,
                            "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
                            f"<jid>{PLAYER}@{host}/twa</jid></bind>",
                        ),
                    )
                    continue
                if "urn:ietf:params:xml:ns:xmpp-session" in low:
                    _send(sock, _iq_result(stanza))
                    continue
                if "<iq" in low:
                    _send(sock, _iq_result(stanza, _iq_body(stanza)))
                    if "pubsub" in low and "subscribe" in low:
                        node_match = NODE_RE.search(stanza)
                        node = node_match.group(1) if node_match else "news"
                        _send(sock, _pubsub_event(host, node))
                        if node != "caprofile.xmpp.twa":
                            _send(sock, _pubsub_event(host, "caprofile.xmpp.twa"))
                    continue
                if "<presence" in low:
                    _send(
                        sock,
                        f"<presence from='{PLAYER}@{host}/twa' "
                        f"to='{PLAYER}@{host}/twa'/>",
                    )
                    continue
            if len(buf) > 65536:
                buf = ""
    except OSError as exc:
        print(f"xmpp drop {addr}: {exc}", flush=True)
    finally:
        try:
            sock.close()
        except OSError:
            pass
        print(f"xmpp closed {addr}", flush=True)


def _accept(port: int, host: str = "0.0.0.0") -> None:
    implicit_tls = port == 5223
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    srv = socket.socket(family, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    srv.bind((host, port))
    srv.listen(16)
    print(f"Revival XMPP listening on {host}:{port} tls={implicit_tls}")
    while True:
        sock, addr = srv.accept()
        threading.Thread(
            target=_handle, args=(sock, addr, implicit_tls), daemon=True
        ).start()


def start(hosts: tuple[str, ...] = ("0.0.0.0", "::")) -> None:
    """Keep legacy defaults; callers may explicitly restrict both loopbacks."""
    hosts = tuple(hosts)
    if not hosts or len(set(hosts)) != len(hosts) or any(
            host not in ("0.0.0.0", "::", "127.0.0.1", "::1") for host in hosts):
        raise ValueError("unsupported XMPP bind hosts")

    def listen(port: int, host: str) -> None:
        # Bind happens inside the worker, so catch unavailable IPv6 here.
        try:
            _accept(port, host)
        except OSError as exc:
            print(f"XMPP {host}:{port} skipped: {exc}", flush=True)

    for port in PORTS:
        for host in hosts:
            threading.Thread(target=listen, args=(port, host), daemon=True).start()
