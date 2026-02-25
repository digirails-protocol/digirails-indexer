"""OP_RETURN decoding and sender address extraction."""

from __future__ import annotations

import hashlib
from enum import IntEnum
from typing import Any

from dr_indexer.bech32 import encode_segwit_address

# DR protocol constants
DR_MAGIC = b"\x44\x52"  # "DR"
DR_HEADER_SIZE = 5
DR_VERSION = 0x01
DR_TEST_FLAG = 0x80


class SubProtocol(IntEnum):
    DR_CORE = 0x00
    DR_PAY = 0x01
    DR_REP = 0x02


class PayMessageType(IntEnum):
    SERVICE_DECLARATION = 0x01
    PAYMENT_MEMO = 0x02


class CoreMessageType(IntEnum):
    IDENTITY_DECLARATION = 0x01
    IDENTITY_TRANSFER = 0x02


class RepMessageType(IntEnum):
    ATTESTATION = 0x01


SERVICE_CATEGORIES: dict[int, str] = {
    0x0001: "LLM Inference",
    0x0002: "Image Generation",
    0x0003: "Code Execution",
    0x0004: "Data Retrieval / Feeds",
    0x0005: "Embedding / Vector Search",
    0x0006: "Media Processing",
    0x0007: "Translation / Localization",
    0x0008: "General Compute",
    0x0009: "Storage",
    0x000A: "Relay / Proxy",
    0x000B: "Web Search / Live Information",
    0x000C: "Web Scraping / Extraction",
    0x000D: "Document Parsing",
    0x000E: "Data Enrichment",
    0x000F: "Fact Verification",
    0x0010: "Agent Task Delegation",
    0x0011: "Knowledge Graph",
    0x0012: "Compliance / Regulatory",
}

ZERO_HASH = "0" * 64


def hash160(data: bytes) -> bytes:
    sha = hashlib.sha256(data).digest()
    return hashlib.new("ripemd160", sha).digest()


def decode_header(
    data: bytes,
) -> tuple[int, SubProtocol, int, bytes, bool] | None:
    """Decode 5-byte DR header.

    Returns (version, sub_protocol, message_type, payload, is_test) or None.
    """
    if len(data) < DR_HEADER_SIZE:
        return None
    if data[:2] != DR_MAGIC:
        return None
    raw_version = data[2]
    is_test = bool(raw_version & DR_TEST_FLAG)
    version = raw_version & 0x7F
    try:
        sub_protocol = SubProtocol(data[3])
    except ValueError:
        return None
    message_type = data[4]
    payload = data[DR_HEADER_SIZE:]
    return (version, sub_protocol, message_type, payload, is_test)


def extract_opreturn(tx: dict[str, Any]) -> bytes | None:
    """Extract OP_RETURN payload bytes from a decoded transaction."""
    for vout in tx.get("vout", []):
        spk = vout.get("scriptPubKey", {})
        if spk.get("type") == "nulldata" or spk.get("asm", "").startswith("OP_RETURN"):
            hex_data = spk.get("hex", "")
            if not hex_data.startswith("6a"):
                return None
            rest = hex_data[2:]
            if len(rest) < 2:
                return None
            length_byte = int(rest[:2], 16)
            if length_byte <= 75:
                payload_hex = rest[2:]
            elif length_byte == 0x4C:
                payload_hex = rest[4:]
            else:
                payload_hex = rest[2:]
            try:
                return bytes.fromhex(payload_hex)
            except ValueError:
                return None
    return None


def get_sender_address(tx: dict[str, Any], hrp: str = "dgb") -> str | None:
    """Extract sender address from the first input of a transaction.

    Tries: (1) prevout address field, (2) SegWit witness pubkey derivation.
    """
    vin = tx.get("vin", [])
    if not vin:
        return None
    first = vin[0]
    if "coinbase" in first:
        return None

    # Method 1: prevout (available in getrawtransaction verbose)
    prevout = first.get("prevout", {})
    spk = prevout.get("scriptPubKey", {})
    addr = spk.get("address")
    if addr:
        return addr
    addrs = spk.get("addresses", [])
    if addrs:
        return addrs[0]

    # Method 2: derive from SegWit witness pubkey
    witness = first.get("txinwitness", [])
    if len(witness) >= 2:
        try:
            pubkey_bytes = bytes.fromhex(witness[1])
            if len(pubkey_bytes) == 33:
                keyhash = hash160(pubkey_bytes)
                return encode_segwit_address(hrp, 0, keyhash)
        except (ValueError, IndexError):
            pass

    return None


def decode_service_declaration(payload: bytes) -> dict[str, Any] | None:
    """Decode service declaration payload (after 5-byte header).

    Format: category (2B) + capability_flags (2B) + manifest_hash (32B) + [domain (variable)]
    """
    if len(payload) < 36:
        return None
    category = int.from_bytes(payload[0:2], "big")
    flags = int.from_bytes(payload[2:4], "big")
    manifest_hash = payload[4:36].hex()

    # Optional domain field (v0.3.0+)
    manifest_domain = ""
    if len(payload) > 36:
        try:
            manifest_domain = payload[36:].decode("utf-8")
        except UnicodeDecodeError:
            pass

    return {
        "category": category,
        "category_name": SERVICE_CATEGORIES.get(category, f"Unknown (0x{category:04X})"),
        "capability_flags": flags,
        "manifest_hash": manifest_hash,
        "manifest_domain": manifest_domain,
        "is_withdrawal": manifest_hash == ZERO_HASH,
    }


def decode_payment_memo(payload: bytes) -> dict[str, Any] | None:
    """Decode payment memo payload (after 5-byte header).

    Format: invoice_id (16B) + service_ref (0-59B)
    """
    if len(payload) < 16:
        return None
    invoice_id = payload[:16].hex()
    service_ref = payload[16:].hex() if len(payload) > 16 else ""
    return {
        "invoice_id": invoice_id,
        "service_ref": service_ref,
    }


def decode_attestation(payload: bytes) -> dict[str, Any] | None:
    """Decode reputation attestation payload (after 5-byte header).

    Format: target_address_hash (20B) + score (1B) + nonce (4B) = 25B
    """
    if len(payload) < 25:
        return None
    target_hash = payload[:20].hex()
    score = payload[20]
    nonce = int.from_bytes(payload[21:25], "big")
    return {
        "target_address_hash": target_hash,
        "score": score,
        "nonce": nonce,
    }


def decode_identity_declaration(payload: bytes) -> dict[str, Any]:
    """Decode identity declaration payload (after 5-byte header).

    Format: label (UTF-8, 0-75B)
    """
    try:
        label = payload.decode("utf-8")
    except UnicodeDecodeError:
        label = payload.hex()
    return {"label": label}
