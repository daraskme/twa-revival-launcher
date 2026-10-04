"""Parse Arena PFH5 packs. Index is encrypted; file bodies are plaintext."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

HAS_ENCRYPTED_CONTENT = 0x10
HAS_INDEX_WITH_TIMESTAMPS = 0x40
HAS_ENCRYPTED_INDEX = 0x80
HAS_BIG_HEADER = 0x100

SIZE_KEY = 0xE10B73F4
INDEX_KEY = b"#:AhppdV-!PEfz&}[]Nv?6w4guU%dF5.fq:n*-qGuhBJJBm&?2tPy!geW/+k#pG?"


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def decrypt_index_length(item_index: int, size_cipher: int) -> int:
    return ((~item_index) & 0xFFFFFFFF) ^ size_cipher ^ SIZE_KEY


def decrypt_index_name(size: int, cipher: bytes) -> bytes:
    inv = (~size) & 0xFF
    out = bytearray()
    for i, b in enumerate(cipher):
        plain = b ^ inv ^ INDEX_KEY[i % 64]
        if plain == 0:
            break
        out.append(plain)
    return bytes(out)


@dataclass
class PackFile:
    path: str
    size: int
    start: int
    timestamp: int | None = None


def parse_pack(data: bytes) -> list[PackFile]:
    if data[:4] != b"PFH5":
        raise ValueError("not PFH5")
    flags = u32(data, 4)
    bitmask = flags & ~0xF
    header_size = 0x30 if bitmask & HAS_BIG_HEADER else 0x1C
    pack_index_size = u32(data, 0x0C)
    file_count = u32(data, 0x10)
    file_index_size = u32(data, 0x14)
    index_start = header_size + pack_index_size
    content_start = index_start + file_index_size
    cur = index_start
    files: list[PackFile] = []
    off = content_start
    for n in range(file_count):
        item_index = file_count - 1 - n
        size = decrypt_index_length(item_index, u32(data, cur))
        cur += 4
        timestamp = None
        if bitmask & HAS_INDEX_WITH_TIMESTAMPS:
            timestamp = u32(data, cur)
            cur += 4
        name = decrypt_index_name(size, data[cur:])
        cur += len(name) + 1
        files.append(PackFile(name.decode("ascii", "replace"), size, off, timestamp))
        off += size
        if bitmask & HAS_ENCRYPTED_CONTENT:
            off = (off + 7) & ~7
    return files


def extract_file(data: bytes, entry: PackFile) -> bytes:
    return data[entry.start : entry.start + entry.size]


def read_pack_index(pack_path: Path) -> bytes:
    with pack_path.open("rb") as handle:
        head = handle.read(0x30)
        flags = u32(head, 4)
        bitmask = flags & ~0xF
        header_size = 0x30 if bitmask & HAS_BIG_HEADER else 0x1C
        pack_index_size = u32(head, 0x0C)
        file_index_size = u32(head, 0x14)
        handle.seek(0)
        return handle.read(header_size + pack_index_size + file_index_size)


def extract_named(pack_path: Path, inner_path: str) -> bytes:
    index = read_pack_index(pack_path)
    want = inner_path.replace("/", "\\").lower()
    for entry in parse_pack(index):
        if entry.path.replace("/", "\\").lower() == want:
            with pack_path.open("rb") as handle:
                handle.seek(entry.start)
                return handle.read(entry.size)
    raise FileNotFoundError(inner_path)
