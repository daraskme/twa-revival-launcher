"""Bounded diagnostics and preflight for the native client's local listeners.

Preflight never contacts a listener or stops its owner. Actual servers must
still bind exclusively and report failures: availability can change after
the temporary probe closes. No session material is included in these errors.
"""
from __future__ import annotations

import re
import socket


def annotate_bind_error(error: OSError, *, transport: str, family: str,
                        port: int) -> OSError:
    if (not isinstance(error, OSError) or transport not in ('tcp', 'udp')
            or family not in ('ipv4', 'ipv6')
            or type(port) is not int or not 0 <= port <= 65535):
        raise ValueError('invalid loopback bind metadata')
    error.twa_bind_transport = transport
    error.twa_bind_family = family
    error.twa_bind_port = port
    return error


def bind_failure_code(error: BaseException) -> str | None:
    if not isinstance(error, OSError):
        return None
    transport = getattr(error, 'twa_bind_transport', None)
    family = getattr(error, 'twa_bind_family', None)
    port = getattr(error, 'twa_bind_port', None)
    if (transport not in ('tcp', 'udp') or family not in ('ipv4', 'ipv6')
            or type(port) is not int or not 1 <= port <= 65535):
        return None
    code = f'loopback_bind_failed:{transport}:{family}:{port}'
    winerror = getattr(error, 'winerror', None)
    number = winerror if type(winerror) is int else getattr(error, 'errno', None)
    if type(number) is int and 0 <= number <= 0xffffffff:
        code += f':{"winerror" if type(winerror) is int else "errno"}_{number}'
    return code


def parse_bind_failure_code(value: object) -> dict | None:
    if not isinstance(value, str) or len(value) > 96:
        return None
    match = re.fullmatch(
        r'loopback_bind_failed:(tcp|udp):(ipv4|ipv6):([0-9]{1,5})'
        r'(?::(winerror|errno)_([0-9]{1,10}))?', value)
    if match is None:
        return None
    transport, family, port_text, kind, number_text = match.groups()
    port = int(port_text)
    number = int(number_text) if number_text is not None else None
    if not 1 <= port <= 65535 or (number is not None and number > 0xffffffff):
        return None
    return {'bind_transport': transport, 'bind_family': family,
            'bind_port': port,
            'windows_error': number if kind == 'winerror' else None}


def check_loopback_ports(surfaces: dict) -> None:
    """Check each required TCP/UDP address, closing all sockets on any failure.

    Only loopback addresses are used. Hold every probe until the complete set
    is checked, so duplicate configuration also fails instead of seeming free.
    Do not set SO_REUSEADDR: on Windows that can steal another app's listener.
    """
    if set(surfaces) != {'http', 'xmpp', 'region_udp', 'relay_tcp'}:
        raise ValueError('invalid bridge surfaces')
    endpoints = []
    for service in ('http', 'xmpp'):
        ports = surfaces[service]
        if not isinstance(ports, (tuple, list)) or not 1 <= len(ports) <= 4:
            raise ValueError('invalid bridge ports')
        for port in ports:
            endpoints.extend((('tcp', 'ipv4', port), ('tcp', 'ipv6', port)))
    endpoints.extend((('tcp', 'ipv4', surfaces['relay_tcp']),
                      ('udp', 'ipv4', surfaces['region_udp'])))
    if any(type(port) is not int or not 1 <= port <= 65535
           for _, _, port in endpoints):
        raise ValueError('invalid bridge port')
    sockets = []
    try:
        for transport, family, port in endpoints:
            sock = socket.socket(socket.AF_INET6 if family == 'ipv6' else socket.AF_INET,
                                 socket.SOCK_STREAM if transport == 'tcp' else socket.SOCK_DGRAM)
            sockets.append(sock)
            try:
                if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                if family == 'ipv6':
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind(('::1' if family == 'ipv6' else '127.0.0.1', port))
                if transport == 'tcp':
                    sock.listen(1)
            except OSError as error:
                annotate_bind_error(error, transport=transport, family=family, port=port)
                raise
    finally:
        for sock in reversed(sockets):
            sock.close()
