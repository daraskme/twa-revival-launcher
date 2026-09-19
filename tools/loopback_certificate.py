"""Loopback support for the native stack: its TLS key and *.localhost names.

create() generates an ephemeral Windows RSA key, never using a certificate
store. PowerShell's framework crypto generates/signs; Python only serializes
exported RSA parameters as PKCS#1. Nothing is installed into the OS trust store.

Arena builds its service hosts as revival-<service>.localhost and resolves them
through the OS resolver, which Windows does not answer for *.localhost by
itself (only some routers' DNS does). The name helpers check that those names
reach loopback and, only after the player consents and approves UAC, append a
marked 127.0.0.1 block to the hosts file from an elevated helper. Importing
this module never reads or writes the hosts file.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import threading
import time

SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
try {
  $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=localhost', $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
  $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
  $san.AddDnsName('localhost')
  $san.AddDnsName('*.localhost')
  $san.AddDnsName('revival-casag.localhost')
  $san.AddDnsName('revival-camm.localhost')
  $san.AddDnsName('revival-casa.localhost')
  $san.AddIpAddress([System.Net.IPAddress]::Parse('127.0.0.1'))
  $san.AddIpAddress([System.Net.IPAddress]::Parse('::1'))
  $req.CertificateExtensions.Add($san.Build())
  $cert = $req.CreateSelfSigned([System.DateTimeOffset]::UtcNow.AddDays(-1), [System.DateTimeOffset]::UtcNow.AddYears(5))
  try {
    $p = $rsa.ExportParameters($true)
    $values = @($p.Modulus, $p.Exponent, $p.D, $p.P, $p.Q, $p.DP, $p.DQ, $p.InverseQ) | ForEach-Object { [Convert]::ToBase64String($_) }
    @{cert=[Convert]::ToBase64String($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)); parameters=$values} | ConvertTo-Json -Compress
  } finally { $cert.Dispose() }
} finally { $rsa.Dispose() }
'''


def _der(tag, value):
    size = len(value)
    length = bytes([size]) if size < 128 else size.to_bytes((size.bit_length()+7)//8, 'big')
    if size >= 128:
        length = bytes([0x80 | len(length)]) + length
    return bytes([tag]) + length + value


def _pem(kind, data):
    encoded = base64.b64encode(data).decode('ascii')
    return (f'-----BEGIN {kind}-----\n' + '\n'.join(encoded[i:i+64] for i in range(0, len(encoded), 64))
            + f'\n-----END {kind}-----\n').encode('ascii')


def create(directory):
    directory = Path(directory)
    if os.name != 'nt' or directory.exists():
        raise RuntimeError('certificate creation requires a fresh Windows directory')
    executable = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    result = subprocess.run([str(executable), '-NoProfile', '-NonInteractive', '-Command', SCRIPT],
        capture_output=True, timeout=45, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise RuntimeError('local certificate generation failed')
    value = json.loads(result.stdout.decode('utf-8-sig'))
    if len(value['parameters']) != 8:
        raise RuntimeError('local certificate generation failed')
    integers = [b'\x00']
    for encoded in value['parameters']:
        number = base64.b64decode(encoded, validate=True).lstrip(b'\x00') or b'\x00'
        integers.append(b'\x00' + number if number[0] & 0x80 else number)
    key = _pem('RSA PRIVATE KEY', _der(0x30, b''.join(_der(2, n) for n in integers)))
    certificate = _pem('CERTIFICATE', base64.b64decode(value['cert'], validate=True))
    directory.mkdir(parents=True)
    (directory / 'key.pem').write_bytes(key)
    (directory / 'cert.pem').write_bytes(certificate)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(directory / 'cert.pem', directory / 'key.pem')


# The services game.dll resolves through its "%s-%s.%s" stack-service-domain
# builder (confirmed in engine logs); stack "revival" and domain "localhost"
# come from server/f2p_fake.py STACK.
LOOPBACK_SERVICES = ('casag', 'camm', 'causer', 'caprofile', 'carpg', 'calb', 'casa', 'xmpp',
                     'capromo', 'cacugs', 'casteampayment', 'camuc')
LOOPBACK_HOSTS: tuple[str, ...] = tuple(f'revival-{s}.localhost' for s in LOOPBACK_SERVICES)
HOSTS_BLOCK_BEGIN = '# BEGIN TWA Revival loopback names'
HOSTS_BLOCK_END = '# END TWA Revival loopback names'
_HOSTS_BLOCK_NOTE = ("# Added with the player's consent so Arena can reach its local services;"
                     " delete this block to remove.")
_HOSTS_MAX_BYTES = 32 * 1024 * 1024  # kept bytes; large blocklist hosts files still fit


def loopback_host_resolves(host, *, resolve=socket.getaddrinfo) -> bool:
    # Every answer must be loopback, and one IPv4: casa/carpg/xmpp use gethostbyname.
    try:
        addresses = [ipaddress.ip_address(info[4][0].split('%')[0])
                     for info in resolve(host, 443, 0, socket.SOCK_STREAM)]
    except (OSError, UnicodeError, ValueError):
        return False
    return (bool(addresses) and all(address.is_loopback for address in addresses)
            and any(address.version == 4 for address in addresses))


def unresolved_loopback_hosts(hosts=LOOPBACK_HOSTS, *, resolve=socket.getaddrinfo,
                              timeout=20.0) -> tuple[str, ...]:
    """Names that do not reach loopback, in input order; empty means ready.

    getaddrinfo has no timeout and a slow NXDOMAIN can take seconds per name,
    so all names are checked at once under one deadline. Daemon threads let a
    hung lookup be abandoned; a pool's workers would block interpreter exit.
    """
    hosts = tuple(hosts)
    resolved = [False] * len(hosts)

    def check(index):
        resolved[index] = loopback_host_resolves(hosts[index], resolve=resolve)

    threads = [threading.Thread(target=check, args=(index,), name='loopback-dns', daemon=True)
               for index in range(len(hosts))]
    deadline = time.monotonic() + timeout
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))
    # A lookup still running at the deadline counts as unresolved.
    finished = [not thread.is_alive() for thread in threads]
    return tuple(host for host, done, ok in zip(hosts, finished, resolved) if not (done and ok))


def merged_hosts_bytes(existing: bytes) -> bytes:
    """Hosts bytes with earlier marked blocks replaced by one fresh block at the end.

    All other bytes are kept exactly. Content this line-based edit cannot keep
    intact (UTF-16, NUL, over _HOSTS_MAX_BYTES outside the block, an unterminated
    block) is refused, not guessed.
    """
    if b'\0' in existing or existing.startswith((b'\xff\xfe', b'\xfe\xff')):
        raise ValueError('unsupported hosts file content')
    newline = b'\r\n' if b'\r\n' in existing else b'\n' if b'\n' in existing else b'\r\n'
    bom = b'\xef\xbb\xbf' if existing.startswith(b'\xef\xbb\xbf') else b''
    begin, end = HOSTS_BLOCK_BEGIN.encode('ascii'), HOSTS_BLOCK_END.encode('ascii')
    kept, inside = [], False
    for line in re.findall(rb'[^\n]*\n|[^\n]+', existing[len(bom):]):
        marker = line.strip()
        if marker.startswith(begin):
            if inside:
                raise ValueError('unterminated TWA hosts block')
            inside = True
        elif not inside:
            kept.append(line)
        elif marker.startswith(end):
            inside = False
    if inside:
        raise ValueError('unterminated TWA hosts block')
    body = b''.join(kept)
    if body and not body.endswith(b'\n'):
        body += newline
    # Capped after normalizing, so every merged result merges again unchanged.
    if len(body) > _HOSTS_MAX_BYTES:
        raise ValueError('unsupported hosts file content')
    block = (HOSTS_BLOCK_BEGIN, _HOSTS_BLOCK_NOTE,
             *(f'127.0.0.1 {host}' for host in LOOPBACK_HOSTS), HOSTS_BLOCK_END)
    return bom + body + b''.join(line.encode('ascii') + newline for line in block)


def hosts_file_path() -> Path:
    # Ask the API: %SystemRoot% is environment input the caller controls.
    if os.name != 'nt':
        raise OSError('the hosts file is only managed on Windows')
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    get_system_directory = kernel32.GetSystemDirectoryW
    get_system_directory.argtypes = (wintypes.LPWSTR, wintypes.UINT)
    get_system_directory.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    size = get_system_directory(buffer, len(buffer))
    if not 0 < size < len(buffer):
        raise OSError(f'cannot locate the Windows system directory (winerror={ctypes.get_last_error()})')
    return Path(buffer.value) / 'drivers' / 'etc' / 'hosts'


def write_loopback_hosts(path: Path | None = None) -> bool:
    """Add or refresh the marked block; False when the file already has it.

    Written in place because replacing the file would drop its ACL/attributes.
    PermissionError (read-only attribute, access denied) propagates; content
    the merge will not edit raises ValueError.
    """
    path = hosts_file_path() if path is None else Path(path)
    limit = _HOSTS_MAX_BYTES + 64 * 1024  # the kept bytes plus an earlier block
    try:
        with open(path, 'rb') as stream:
            existing = stream.read(limit + 1)
    except FileNotFoundError:
        existing = None
    if existing is not None and len(existing) > limit:
        raise ValueError('unsupported hosts file content')
    merged = merged_hosts_bytes(existing or b'')
    if merged == existing:
        return False
    with open(path, 'xb' if existing is None else 'r+b') as stream:
        stream.seek(0)
        stream.write(merged)
        stream.truncate()
        stream.flush()
        os.fsync(stream.fileno())
    with open(path, 'rb') as stream:
        if stream.read(len(merged) + 1) != merged:
            raise OSError('hosts file did not keep the written content')
    return True


def flush_dns_cache() -> bool:
    # Best effort: drop a cached negative answer so the new names apply at once.
    try:
        import ctypes
        flush = ctypes.WinDLL('dnsapi').DnsFlushResolverCache
        flush.argtypes = ()
        flush.restype = ctypes.c_int
        return bool(flush())
    except Exception:
        return False


def repair_loopback_hosts_main() -> int:
    """Elevated entry point: fixed work, no argv/stdin/environment input.

    Over-the-shoulder UAC runs this as another account, so nothing per-user
    (companion state, diagnostics under that account's LOCALAPPDATA) is used.
    """
    try:
        write_loopback_hosts()
    except PermissionError:
        return 3
    except ValueError:  # content it will not edit safely
        return 4
    except Exception:
        return 5
    flush_dns_cache()
    return 0


def request_elevated_repair(root: Path, *, owner_hwnd: int = 0, timeout: float = 180.0,
                            _verb: str = 'runas', _parameters: str | None = None) -> str:
    """Run repair_loopback_hosts_main elevated once the player agreed; blocks.

    Returns ok, permission, unsupported (hosts content the helper will not
    edit), cancelled (UAC declined), timeout or failed; the caller re-verifies
    resolution itself. _verb/_parameters exist only so tests can start a
    harmless unelevated process.
    """
    if os.name != 'nt':
        return 'failed'
    import ctypes
    from ctypes import wintypes

    class ShellExecuteInfo(ctypes.Structure):
        _fields_ = [('cbSize', wintypes.DWORD), ('fMask', wintypes.ULONG), ('hwnd', wintypes.HWND),
                    ('lpVerb', wintypes.LPCWSTR), ('lpFile', wintypes.LPCWSTR),
                    ('lpParameters', wintypes.LPCWSTR), ('lpDirectory', wintypes.LPCWSTR),
                    ('nShow', ctypes.c_int), ('hInstApp', wintypes.HINSTANCE),
                    ('lpIDList', ctypes.c_void_p), ('lpClass', wintypes.LPCWSTR),
                    ('hkeyClass', wintypes.HKEY), ('dwHotKey', wintypes.DWORD),
                    ('hIconOrMonitor', wintypes.HANDLE), ('hProcess', wintypes.HANDLE)]

    root = Path(root)
    python = root / 'runtime/python.exe'
    if not python.is_file():
        python = Path(sys.executable)
    parameters = _parameters if _parameters is not None else subprocess.list2cmdline(
        ['-B', '-E', '-s', str(root / 'tools/player_launcher.py'), '--repair-loopback-hosts'])
    shell32 = ctypes.WinDLL('shell32', use_last_error=True)
    execute = shell32.ShellExecuteExW
    execute.argtypes = (ctypes.POINTER(ShellExecuteInfo),)
    execute.restype = wintypes.BOOL
    ole32 = ctypes.WinDLL('ole32', use_last_error=True)
    ole32.CoInitializeEx.argtypes = (ctypes.c_void_p, wintypes.DWORD)
    ole32.CoInitializeEx.restype = ctypes.c_long
    ole32.CoUninitialize.argtypes = ()
    ole32.CoUninitialize.restype = None
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    # NOCLOSEPROCESS | NOASYNC | FLAG_NO_UI; SW_HIDE: the helper has no window.
    info = ShellExecuteInfo(cbSize=ctypes.sizeof(ShellExecuteInfo), fMask=0x40 | 0x100 | 0x400,
                            hwnd=owner_hwnd, lpVerb=_verb, lpFile=str(python),
                            lpParameters=parameters, lpDirectory=str(root), nShow=0)
    # ShellExecuteEx may delegate to COM shell extensions, so COM must be up
    # on this thread (APARTMENTTHREADED | DISABLE_OLE1DDE, as documented).
    initialized = ole32.CoInitializeEx(None, 0x2 | 0x4) >= 0
    try:
        if not execute(ctypes.byref(info)):
            return 'cancelled' if ctypes.get_last_error() == 1223 else 'failed'
    finally:
        if initialized:
            ole32.CoUninitialize()
    if not info.hProcess:
        return 'failed'
    try:
        state = kernel32.WaitForSingleObject(info.hProcess, min(max(int(timeout * 1000), 0), 0xFFFFFFFE))
        if state == 0x00000102:
            return 'timeout'
        code = wintypes.DWORD()
        if state != 0 or not kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code)):
            return 'failed'
        return {0: 'ok', 3: 'permission', 4: 'unsupported'}.get(code.value, 'failed')
    finally:
        kernel32.CloseHandle(info.hProcess)
