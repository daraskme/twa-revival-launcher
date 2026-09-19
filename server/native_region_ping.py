"""Local native region discovery only: four-byte UDP echo, never gameplay.

The owned native helper redirects the client's fixed ping to IPv4 port 19063,
outside Windows' dynamic-port range. Echo the four-byte timestamp unchanged;
do not manufacture a latency or decode identities.
This unauthenticated helper must never be exposed beyond loopback.
"""
from __future__ import annotations

import errno
import ipaddress
import socket
import threading


def local_server_list() -> dict:
    """The fixed, native-tested native_probe.example.json response."""
    return {
        "timestamp": 1787760241000,
        "response": {
            "relay_server_list": [{"host": "127.0.0.1", "region": "local"}],
            "game_modes": [{"name": "pvp", "max_party_size": 1,
                            "min_tier": 1, "max_tier": 10}],
        },
    }


def _valid_ping(data: bytes, peer: tuple[str, int]) -> bool:
    if len(data) != 4:
        return False
    try:
        return ipaddress.IPv4Address(peer[0]).is_loopback
    except (ValueError, IndexError):
        return False


class NativeRegionPing:
    """A single stoppable IPv4 loopback listener; port zero supports tests."""

    def __init__(self, port: int = 19063, *, on_first_echo=None) -> None:
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("invalid local region UDP port")
        self.port = port
        self._on_first_echo = on_first_echo
        self._echo_reported = False
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> tuple[str, int]:
        if self._socket is not None:
            raise RuntimeError("local region ping is already started")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # A second local process must not silently share or steal this port.
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind(("127.0.0.1", self.port))
            sock.settimeout(0.2)
            self._stop.clear()
            self._echo_reported = False
            self._socket = sock
            self._thread = threading.Thread(target=self._serve, args=(sock,),
                                            name="native-region-ping", daemon=True)
            self._thread.start()
            return sock.getsockname()
        except BaseException:
            sock.close()
            self._socket = None
            self._thread = None
            raise

    def _serve(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                # Five bytes distinguish a valid four-byte ping from truncated
                # oversized datagrams. Windows raises WSAEMSGSIZE instead.
                data, peer = sock.recvfrom(5)
            except socket.timeout:
                continue
            except OSError as exc:
                if self._stop.is_set():
                    return
                if exc.errno == errno.EMSGSIZE or getattr(exc, "winerror", None) == 10040:
                    continue
                # Windows can report a previous echo's ICMP Port Unreachable
                # here after that client closes; other clients must still work.
                if exc.errno == errno.ECONNRESET or getattr(exc, "winerror", None) == 10054:
                    continue
                raise
            if not self._stop.is_set() and _valid_ping(data, peer):
                try:
                    sock.sendto(data, peer)
                    if not self._echo_reported:
                        self._echo_reported = True
                        if self._on_first_echo is not None:
                            self._on_first_echo()
                except OSError:
                    if self._stop.is_set():
                        return
                    raise

    def stop(self) -> None:
        self._stop.set()
        sock, self._socket = self._socket, None
        if sock is not None:
            sock.close()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=1)
