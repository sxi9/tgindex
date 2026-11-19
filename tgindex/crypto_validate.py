"""Checksum validators. These are what separate an entity from a false positive."""
from __future__ import annotations

import hashlib

_MASK = (1 << 64) - 1
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_R = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]


def _rol(v: int, n: int) -> int:
    n %= 64
    return ((v << n) | (v >> (64 - n))) & _MASK if n else v


def _keccak_f(A):
    for rnd in range(24):
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                A[x][y] ^= D[x]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rol(A[x][y], _R[x][y])
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y] & _MASK)
        A[0][0] ^= _RC[rnd]
    return A


def keccak256(data: bytes) -> bytes:
    """Original Keccak padding (0x01), not NIST SHA3 (0x06). Ethereum uses this."""
    rate = 136
    A = [[0] * 5 for _ in range(5)]
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80

    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:i * 8 + 8], "little")
            A[i % 5][i // 5] ^= lane
        A = _keccak_f(A)

    out = bytearray()
    for i in range(4):
        out += A[i % 5][i // 5].to_bytes(8, "little")
    return bytes(out[:32])


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_MAP = {c: i for i, c in enumerate(_B58)}


def b58check(addr: str) -> bool:
    """Base58Check: last 4 bytes are sha256(sha256(payload))[:4]."""
    num = 0
    for ch in addr:
        v = _B58_MAP.get(ch)
        if v is None:
            return False
        num = num * 58 + v
    pad = len(addr) - len(addr.lstrip("1"))
    raw = b"\x00" * pad + (num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b"")
    if len(raw) < 5:
        return False
    body, checksum = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] == checksum


_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_MAP = {c: i for i, c in enumerate(_BECH32)}


def _bech32_polymod(values) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def bech32_valid(addr: str) -> bool:
    """BIP-173 (bech32, v0 / bc1q) and BIP-350 (bech32m, v1+ / bc1p)."""
    if not (8 <= len(addr) <= 90):
        return False
    if addr.lower() != addr and addr.upper() != addr:
        return False
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr):
        return False
    hrp, data_part = addr[:pos], addr[pos + 1:]
    try:
        data = [_BECH32_MAP[c] for c in data_part]
    except KeyError:
        return False
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    const = _bech32_polymod(expanded + data)
    if data[0] == 0:
        return const == 1          # bech32
    return const == 0x2BC830A3     # bech32m


def eip55_ok(addr: str) -> bool:
    """All-one-case addresses carry no checksum; mixed case must match EIP-55."""
    body = addr[2:]
    if body == body.lower() or body == body.upper():
        return True
    digest = keccak256(body.lower().encode()).hex()
    for ch, h in zip(body, digest):
        if ch.isalpha() and ch.isupper() != (int(h, 16) >= 8):
            return False
    return True


def luhn_ok(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_ok(iban: str) -> bool:
    s = iban.replace(" ", "").upper()
    if not (15 <= len(s) <= 34) or not s[:2].isalpha() or not s[2:4].isdigit():
        return False
    rearranged = s[4:] + s[:4]
    converted = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    if not converted.isdigit():
        return False
    return int(converted) % 97 == 1
