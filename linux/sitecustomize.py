"""Wine/Proton compatibility layer for the TWA Revival launcher.

Copied by linux/twa-proton.sh into the bundled runtime's
``runtime/Lib/site-packages`` folder. The embedded CPython's ``python311._pth``
enables ``import site``, so every launcher process (GUI, workers, bridge, Frida
helper, update runner) imports this module before any launcher code runs.

It lives in the runtime on purpose: signed launcher updates replace every
``.py`` file under companion/, server/ and tools/, but never touch runtime/.
Patching those files directly would be undone by the next update, or would
block updates ("same-version launcher contents differ").

On real Windows this module does nothing. Under Wine it only replaces steps
that need Windows components Proton does not ship:

* ``tools.loopback_certificate.create`` runs PowerShell to generate the
  loopback TLS key. Proton has no PowerShell, so installation always failed at
  the "applying" phase. Here the same certificate (CN=localhost, the same SAN
  names/addresses, 5 years) is generated in pure Python.
* The hosts-file fix edits the Wine prefix's hosts file, which Wine ignores:
  name lookups go to the Linux resolver. The fix is reported as not possible,
  so the launcher shows the lines to add to /etc/hosts instead.
* A fresh installation only copies the files listed in the core manifest, so
  this module copies itself into the new installation's runtime.
* Arena never signals ``WaitForInputIdle`` under Wine, so the launcher gave
  up after 30 seconds and closed the running game. A visible Arena window
  also counts as ready, and the first start may take up to 120 seconds.
* Every launch replaced Arena's preferences.script.txt with the template
  (its "damaged file" check matches every valid file), so in-game settings
  never survived a restart. A valid saved file is now kept, including the
  window size, position and fullscreen choice the launcher used to reset.
* ``os.startfile`` on a folder opens the Linux file manager (winebrowser)
  instead of Wine's own explorer window.
"""
from __future__ import annotations

import os
import sys


def _running_under_wine() -> bool:
    if os.name != 'nt':
        return False
    try:
        import ctypes
        return hasattr(ctypes.WinDLL('ntdll'), 'wine_get_version')
    except Exception:
        return False


# --- Pure-Python self-signed loopback certificate -----------------------------

_SAN_DNS = ('localhost', '*.localhost', 'revival-casag.localhost',
            'revival-camm.localhost', 'revival-casa.localhost')
_SAN_IP = (bytes((127, 0, 0, 1)), bytes(15) + b'\x01')
_SMALL_PRIMES = tuple(p for p in range(3, 2000, 2) if all(p % d for d in range(3, int(p ** 0.5) + 1, 2)))


def _der(tag: int, value: bytes) -> bytes:
    size = len(value)
    if size < 128:
        return bytes((tag, size)) + value
    length = size.to_bytes((size.bit_length() + 7) // 8, 'big')
    return bytes((tag, 0x80 | len(length))) + length + value


def _int(value: int) -> bytes:
    return _der(0x02, value.to_bytes(value.bit_length() // 8 + 1, 'big'))


def _oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split('.')]
    body = bytes((40 * parts[0] + parts[1],))
    for part in parts[2:]:
        chunk = [part & 0x7f]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7f))
            part >>= 7
        body += bytes(reversed(chunk))
    return _der(0x06, body)


def _seq(*items: bytes) -> bytes:
    return _der(0x30, b''.join(items))


def _time(moment) -> bytes:
    if moment.year < 2050:
        return _der(0x17, moment.strftime('%y%m%d%H%M%SZ').encode('ascii'))
    return _der(0x18, moment.strftime('%Y%m%d%H%M%SZ').encode('ascii'))


def _probable_prime(n: int, rounds: int = 40) -> bool:
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    import secrets
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(rounds):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int, e: int) -> int:
    import secrets
    while True:
        # Top two bits set so p*q has exactly 2*bits bits; odd.
        candidate = secrets.randbits(bits) | (3 << (bits - 2)) | 1
        if (candidate - 1) % e and _probable_prime(candidate):
            return candidate


def _rsa_key(bits: int = 2048):
    e = 65537
    while True:
        p, q = _prime(bits // 2, e), _prime(bits // 2, e)
        if p == q:
            continue
        if p < q:
            p, q = q, p
        n = p * q
        if n.bit_length() != bits:
            continue
        d = pow(e, -1, (p - 1) * (q - 1))
        return n, e, d, p, q, d % (p - 1), d % (q - 1), pow(q, -1, p)


def _certificate_and_key():
    import datetime
    import hashlib
    import secrets
    n, e, d, p, q, dp, dq, qinv = _rsa_key()
    sha256_rsa = _seq(_oid('1.2.840.113549.1.1.11'), b'\x05\x00')
    name = _seq(_der(0x31, _seq(_oid('2.5.4.3'), _der(0x0c, b'localhost'))))
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    try:
        not_after = now.replace(year=now.year + 5)
    except ValueError:  # 29 February
        not_after = now.replace(year=now.year + 5, day=28)
    public_key = _seq(_seq(_oid('1.2.840.113549.1.1.1'), b'\x05\x00'),
                      _der(0x03, b'\x00' + _seq(_int(n), _int(e))))
    san = _seq(*(_der(0x82, host.encode('ascii')) for host in _SAN_DNS),
               *(_der(0x87, address) for address in _SAN_IP))
    extensions = _der(0xa3, _seq(_seq(_oid('2.5.29.17'), _der(0x04, san))))
    tbs = _seq(_der(0xa0, _int(2)), _int(secrets.randbits(127) | 1 << 126), sha256_rsa, name,
               _seq(_time(now - datetime.timedelta(days=1)), _time(not_after)), name,
               public_key, extensions)
    # EMSA-PKCS1-v1_5 with a SHA-256 DigestInfo, signed through the CRT.
    digest_info = bytes.fromhex('3031300d060960864801650304020105000420') + hashlib.sha256(tbs).digest()
    size = (n.bit_length() + 7) // 8
    encoded = int.from_bytes(b'\x00\x01' + b'\xff' * (size - len(digest_info) - 3) + b'\x00' + digest_info, 'big')
    m1, m2 = pow(encoded, dp, p), pow(encoded, dq, q)
    signature = m2 + q * ((qinv * (m1 - m2)) % p)
    if pow(signature, e, n) != encoded:
        raise RuntimeError('local certificate generation failed')
    certificate = _seq(tbs, sha256_rsa, _der(0x03, b'\x00' + signature.to_bytes(size, 'big')))
    key = _seq(*(_int(value) for value in (0, n, e, d, p, q, dp, dq, qinv)))
    return certificate, key


def _patch_loopback_certificate(module) -> None:
    from pathlib import Path

    def create(directory):
        """Same contract as the original: fresh directory, key.pem + cert.pem, verified."""
        import ssl
        directory = Path(directory)
        if directory.exists():
            raise RuntimeError('certificate creation requires a fresh Windows directory')
        certificate, key = _certificate_and_key()
        directory.mkdir(parents=True)
        (directory / 'key.pem').write_bytes(module._pem('RSA PRIVATE KEY', key))
        (directory / 'cert.pem').write_bytes(module._pem('CERTIFICATE', certificate))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(directory / 'cert.pem', directory / 'key.pem')

    def hosts_file_path():
        # Wine resolves names with the Linux resolver, which reads /etc/hosts.
        return Path(r'Z:\etc\hosts')

    def request_elevated_repair(root, **_):
        # The prefix's hosts file is ignored by Wine and /etc/hosts needs root:
        # report failure so the launcher saves the lines for a manual edit.
        return 'failed'

    module.create = create
    module.hosts_file_path = hosts_file_path
    module.request_elevated_repair = request_elevated_repair


# --- Carry this layer into a new installation ---------------------------------

def _install_self(root) -> None:
    from pathlib import Path
    import shutil
    source = Path(__file__).resolve()
    target = Path(root) / 'runtime' / 'Lib' / 'site-packages' / 'sitecustomize.py'
    if target.parent.is_dir() and source != target.resolve():
        shutil.copyfile(source, target)


def _patch_install_player(module) -> None:
    original = module.install

    def install(source, original_dir, destination, *args, **kwargs):
        result = original(source, original_dir, destination, *args, **kwargs)
        _install_self(destination)
        return result

    module.install = install


# --- Arena readiness ------------------------------------------------------------

def _has_visible_window(pid: int) -> bool:
    import ctypes
    from ctypes import wintypes
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    user32.GetWindowThreadProcessId.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.DWORD))
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.IsWindowVisible.argtypes = (wintypes.HWND,)
    user32.IsWindowVisible.restype = wintypes.BOOL
    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def visit(hwnd, _):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid and user32.IsWindowVisible(hwnd):
            found.append(hwnd)
            return False
        return True

    user32.EnumWindows(visit, 0)
    return bool(found)


def _patch_native_launch(module) -> None:
    """Under Wine, Arena runs normally but never signals WaitForInputIdle.

    The launcher only waits so the Frida helper attaches once Arena's UI
    exists; a visible top-level window of the process means the same. The
    first start under DXVK can also take longer than Windows' 30 seconds.
    """
    import time
    process_class = module._Win32Process
    original = process_class.wait_input_idle

    def wait_input_idle(self, timeout: float) -> None:
        deadline = time.monotonic() + max(timeout, 120.0)
        while True:
            try:
                original(self, min(2.0, max(0.1, deadline - time.monotonic())))
                return
            except module.NativeLaunchError:
                if self.poll() is not None or time.monotonic() >= deadline:
                    raise
                if _has_visible_window(self.pid):
                    return

    process_class.wait_input_idle = wait_input_idle


# --- Keep Arena's saved settings --------------------------------------------------

def _patch_launch_preparation(module) -> None:
    """Keep the player's preferences.script.txt instead of resetting it every launch.

    ``_build_preferences`` falls back to the template unless
    ``text.count("x_res") == 1``, but every valid file contains that substring
    four times (the key, its comment, and ``fix_res``), so graphics, sound and
    advisor settings were replaced by the template on every launch. A file
    that the launcher's own checks accept is handed in as the fallback.

    The launcher also resets the window to at most 1600x900, windowed, at the
    primary monitor's corner on every launch, so the resolution chosen in the
    game never stuck. The saved size, position and fullscreen choice are put
    back, capped to the primary monitor and re-centred if the saved window
    would not fit on it.
    """
    import re
    original = module._build_preferences

    def saved_window(text):
        def value(key, pattern):
            found = re.findall(rf'^[ \t]*{key}[ \t]+({pattern});', text, re.M)
            return found[0] if len(found) == 1 else None
        numbers = [value(key, r'-?\d+') for key in ('x_res', 'y_res', 'x_pos', 'y_pos')]
        fullscreen = value('gfx_fullscreen', 'true|false')
        if None in numbers or fullscreen is None:
            return None
        return [int(number) for number in numbers] + [fullscreen == 'true']

    def _build_preferences(current, template, monitor, *args, **kwargs):
        window = None
        if current is not None:
            text = module._read_pref_text(current)
            keys = [line.split(' ', 1)[0].rstrip(';') for line in text.splitlines()]
            if text.strip() and not module._preferences_corrupt(text) and keys.count('x_res') == 1:
                template = text
                window = saved_window(text)
        result = original(current, template, monitor, *args, **kwargs)
        if window is None or window[0] <= 0 or window[1] <= 0:
            return result
        width, height = min(window[0], monitor['w']), min(window[1], monitor['h'])
        x, y = window[2], window[3]
        if not (monitor['x'] <= x <= monitor['x'] + monitor['w'] - width
                and monitor['y'] <= y <= monitor['y'] + monitor['h'] - height):
            x = monitor['x'] + (monitor['w'] - width) // 2
            y = monitor['y'] + (monitor['h'] - height) // 2
        text = module._read_pref_text(result)
        for key, setting in (('x_res', width), ('y_res', height), ('x_pos', x), ('y_pos', y),
                             ('gfx_fullscreen', window[4])):
            text = module._set_preference(text, key, setting)
        return b'\xff\xfe' + text.encode('utf-16-le')

    module._build_preferences = _build_preferences


# --- Folders open in the Linux file manager -----------------------------------

def _patch_startfile() -> None:
    original = getattr(os, 'startfile', None)
    if original is None:
        return

    def startfile(path, *args, **kwargs):
        if not args and not kwargs and os.path.isdir(path):
            import subprocess
            try:
                subprocess.Popen(['winebrowser', os.fspath(path)], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return
            except OSError:
                pass
        return original(path, *args, **kwargs)

    os.startfile = startfile


# --- Import hook --------------------------------------------------------------

_MODULE_PATCHES = {
    'tools.loopback_certificate': _patch_loopback_certificate,
    'tools.install_player': _patch_install_player,
    'companion.native_launch': _patch_native_launch,
    'companion.launch_preparation': _patch_launch_preparation,
}


def _install_import_hook() -> None:
    import importlib.abc

    class _PatchingFinder(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path, target=None):
            patch = _MODULE_PATCHES.get(name)
            if patch is None:
                return None
            for finder in sys.meta_path:
                if finder is self or not hasattr(finder, 'find_spec'):
                    continue
                spec = finder.find_spec(name, path, target)
                if spec is not None:
                    break
            else:
                return None
            loader = spec.loader
            exec_module = getattr(loader, 'exec_module', None)
            if exec_module is None:
                return spec

            def exec_and_patch(module):
                exec_module(module)
                patch(module)

            loader.exec_module = exec_and_patch
            return spec

    sys.meta_path.insert(0, _PatchingFinder())


if _running_under_wine():
    _install_import_hook()
    _patch_startfile()
