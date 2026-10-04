"""Write Arena PFH5 packs (encrypted index, plaintext bodies)."""
from __future__ import annotations

import struct
from pathlib import Path

try:
    from .unpack_pfh5 import INDEX_KEY, SIZE_KEY, HAS_BIG_HEADER, HAS_ENCRYPTED_INDEX, HAS_INDEX_WITH_TIMESTAMPS
except ImportError:  # Direct execution from the tools directory.
    from unpack_pfh5 import INDEX_KEY, SIZE_KEY, HAS_BIG_HEADER, HAS_ENCRYPTED_INDEX, HAS_INDEX_WITH_TIMESTAMPS

RELEASE_FLAGS = 0x181  # big header + encrypted index + release type


def encrypt_index_length(item_index: int, size: int) -> int:
    return ((~item_index) & 0xFFFFFFFF) ^ size ^ SIZE_KEY


def encrypt_index_name(size: int, name: bytes) -> bytes:
    inv = (~size) & 0xFF
    payload = name + b"\x00"
    out = bytearray()
    for i, b in enumerate(payload):
        out.append(b ^ inv ^ INDEX_KEY[i % 64])
    return bytes(out)


def build_pack(
    files: list[tuple[str, bytes]],
    flags: int = RELEASE_FLAGS,
    signature: bytes | None = None,
) -> bytes:
    bitmask = flags & ~0xF
    header_size = 0x30 if bitmask & HAS_BIG_HEADER else 0x1C
    index = bytearray()
    bodies = bytearray()
    n = len(files)
    for i, (path, data) in enumerate(files):
        item_index = n - 1 - i
        size = len(data)
        index += struct.pack("<I", encrypt_index_length(item_index, size))
        if bitmask & HAS_INDEX_WITH_TIMESTAMPS:
            index += struct.pack("<I", 0)
        name = path.replace("/", "\\").encode("ascii")
        index += encrypt_index_name(size, name)
        bodies += data
        if bitmask & 0x10:  # HAS_ENCRYPTED_CONTENT
            pad = (-len(bodies)) & 7
            bodies += b"\x00" * pad

    sig = signature if signature is not None else (b"\x00" * 256)
    if len(sig) != 256:
        raise ValueError("signature must be 256 bytes")

    file_index_size = len(index)
    content_size = len(bodies)
    total = header_size + file_index_size + content_size + 256
    sig_offset = total - 256

    header = bytearray(header_size)
    header[0:4] = b"PFH5"
    struct.pack_into("<I", header, 4, flags)
    if header_size >= 0x1C:
        struct.pack_into("<I", header, 0x08, 0)  # dependency count
        struct.pack_into("<I", header, 0x0C, 0)  # dependency size
        struct.pack_into("<I", header, 0x10, n)
        struct.pack_into("<I", header, 0x14, file_index_size)
        struct.pack_into("<I", header, 0x18, 0)  # timestamp
        struct.pack_into("<I", header, 0x1C, 1)  # extra
    if header_size >= 0x30:
        struct.pack_into("<I", header, 0x20, 0)
        struct.pack_into("<I", header, 0x24, 256)
        struct.pack_into("<I", header, 0x28, sig_offset)
        struct.pack_into("<I", header, 0x2C, 0)

    return bytes(header) + bytes(index) + bytes(bodies) + sig
