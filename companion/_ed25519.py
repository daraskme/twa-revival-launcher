"""Pure-Python Ed25519 (RFC 8032), reference-implementation style.

Neither `cryptography` nor `pynacl` is installed in this environment (checked
2026-09-02), so update manifests are verified with this instead. It follows
the well-known reference construction from the RFC 8032 announcement: plain
Python big integers over the Edwards curve, no dependencies beyond hashlib.

Production code (companion/manifest.py) only ever calls verify(). sign() and
generate_keypair() exist because tests and dev-key generation need to
produce real signatures/keys to verify against -- they are not on any
runtime path that ships to players.

Correctness is pinned by companion/tests/test_ed25519.py against the
official RFC 8032 ยง7.1 TEST 1 / TEST 2 vectors.
"""
from __future__ import annotations

import hashlib

_B = 256
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493


def _h(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _expmod(base: int, exp: int, mod: int) -> int:
    if exp == 0:
        return 1
    t = _expmod(base, exp // 2, mod) ** 2 % mod
    if exp & 1:
        t = (t * base) % mod
    return t


def _inv(x: int) -> int:
    return _expmod(x, _Q - 2, _Q)


_D = -121665 * _inv(121666) % _Q
_I = _expmod(2, (_Q - 1) // 4, _Q)


def _x_recover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = _expmod(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = 4 * _inv(5)
_BX = _x_recover(_BY)
_BASE = (_BX % _Q, _BY % _Q)


def _edwards(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p
    x2, y2 = q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2)
    return (x3 % _Q, y3 % _Q)


def _scalarmult(p: tuple[int, int], e: int) -> tuple[int, int]:
    if e == 0:
        return (0, 1)
    q = _scalarmult(p, e // 2)
    q = _edwards(q, q)
    if e & 1:
        q = _edwards(q, p)
    return q


def _encode_int(y: int) -> bytes:
    return y.to_bytes(_B // 8, "little")


def _encode_point(p: tuple[int, int]) -> bytes:
    x, y = p
    result = bytearray(y.to_bytes(_B // 8, "little"))
    if x & 1:
        result[-1] |= 0x80
    return bytes(result)


def _bit(data: bytes, i: int) -> int:
    return (data[i // 8] >> (i % 8)) & 1


def _clamped_scalar(seed_hash: bytes) -> int:
    return 2 ** (_B - 2) + sum(2**i * _bit(seed_hash, i) for i in range(3, _B - 2))


def _hint(data: bytes) -> int:
    return int.from_bytes(_h(data), "little")


def _is_on_curve(p: tuple[int, int]) -> bool:
    x, y = p
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _Q == 0


def _decode_int(data: bytes) -> int:
    return int.from_bytes(data, "little")


def _decode_point(data: bytes) -> tuple[int, int]:
    y = int.from_bytes(data, "little") & ((1 << (_B - 1)) - 1)
    x = _x_recover(y)
    if x & 1 != _bit(data, _B - 1):
        x = _Q - x
    p = (x, y)
    if not _is_on_curve(p):
        raise ValueError("decoding point that is not on the curve")
    return p


def generate_keypair(seed: bytes) -> tuple[bytes, bytes]:
    """Derive (public_key_32, seed_32) from a 32-byte Ed25519 seed.

    Dev/test key generation only -- see module docstring.
    """
    if len(seed) != 32:
        raise ValueError("seed must be exactly 32 bytes")
    h = _h(seed)
    a = _clamped_scalar(h)
    public_key = _encode_point(_scalarmult(_BASE, a))
    return public_key, seed


def sign(seed: bytes, message: bytes) -> bytes:
    """Sign message with a 32-byte seed, returning a 64-byte signature.

    Dev/test key generation only -- see module docstring.
    """
    if len(seed) != 32:
        raise ValueError("seed must be exactly 32 bytes")
    public_key, _ = generate_keypair(seed)
    h = _h(seed)
    r = _hint(h[_B // 8 : _B // 4] + message)
    big_r = _scalarmult(_BASE, r)
    a = _clamped_scalar(h)
    s = (r + _hint(_encode_point(big_r) + public_key + message) * a) % _L
    return _encode_point(big_r) + _encode_int(s)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a 64-byte Ed25519 signature. Never raises -- fails closed.

    This is the only function production code (companion/manifest.py) calls.
    """
    if len(public_key) != _B // 8 or len(signature) != _B // 4:
        return False
    try:
        r_enc = signature[: _B // 8]
        s_enc = signature[_B // 8 : _B // 4]
        big_r = _decode_point(r_enc)
        a = _decode_point(public_key)
        s = _decode_int(s_enc)
        if s >= _L:
            return False
        h = _hint(_encode_point(big_r) + public_key + message)
        v1 = _scalarmult(_BASE, s)
        v2 = _edwards(big_r, _scalarmult(a, h))
        return v1 == v2
    except (ValueError, ZeroDivisionError, IndexError):
        # Any malformed point/scalar decodes to "not a valid signature",
        # never a crash -- callers must be able to trust a bool result.
        return False
