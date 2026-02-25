"""Minimal bech32/bech32m encoding for SegWit addresses.

Reference: BIP-173 (bech32) and BIP-350 (bech32m).
Only includes encode/decode for witness v0 (P2WPKH dgb1q...) addresses.
"""

from __future__ import annotations

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1


def _bech32_polymod(values: list[int]) -> int:
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ BECH32_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _bech32_verify_checksum(hrp: str, data: list[int]) -> bool:
    return _bech32_polymod(_bech32_hrp_expand(hrp) + data) == BECH32_CONST


def _convertbits(data: bytes | list[int], frombits: int, tobits: int, pad: bool = True) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return []
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return []
    return ret


def encode_segwit_address(hrp: str, witver: int, witprog: bytes) -> str | None:
    conv = _convertbits(witprog, 8, 5)
    if conv is None or len(conv) == 0:
        return None
    data = [witver] + conv
    checksum = _bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum)


def decode_segwit_address(hrp: str, addr: str) -> tuple[int | None, bytes | None]:
    if addr.lower() != addr and addr.upper() != addr:
        return None, None
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        return None, None
    if not all(x in CHARSET for x in addr[pos + 1 :]):
        return None, None
    hrp_got = addr[:pos]
    if hrp_got != hrp:
        return None, None
    data = [CHARSET.find(x) for x in addr[pos + 1 :]]
    if not _bech32_verify_checksum(hrp_got, data):
        return None, None
    decoded = data[:-6]
    if len(decoded) < 1:
        return None, None
    witver = decoded[0]
    witprog = _convertbits(decoded[1:], 5, 8, False)
    if witprog is None or len(witprog) < 2 or len(witprog) > 40:
        return None, None
    if witver == 0 and len(witprog) not in (20, 32):
        return None, None
    return witver, bytes(witprog)
