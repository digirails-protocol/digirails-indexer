"""Block scanner — historical sync and real-time monitoring."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from typing import Any

import aiohttp

from dr_indexer.config import Config
from dr_indexer.db import Database
from dr_indexer.decoder import (
    CoreMessageType,
    PayMessageType,
    RepMessageType,
    SubProtocol,
    decode_attestation,
    decode_header,
    decode_identity_declaration,
    decode_payment_memo,
    decode_service_declaration,
    extract_opreturn,
    get_sender_address,
)

log = logging.getLogger(__name__)


class RpcClient:
    """Minimal async JSON-RPC client for DGB Core."""

    def __init__(self, url: str, user: str = "", password: str = ""):
        self._url = url
        self._auth: aiohttp.BasicAuth | None = None
        if user and password:
            self._auth = aiohttp.BasicAuth(user, password)
        self._session: aiohttp.ClientSession | None = None
        self._req_id = 0

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(auth=self._auth)
        return self._session

    async def call(self, method: str, params: list[Any] | None = None) -> Any:
        self._req_id += 1
        payload = {
            "jsonrpc": "1.0",
            "id": self._req_id,
            "method": method,
            "params": params or [],
        }
        session = await self._get_session()
        async with session.post(
            self._url,
            json=payload,
            headers={"Content-Type": "application/json"},
        ) as resp:
            data = await resp.json(content_type=None)
            if data.get("error"):
                raise RuntimeError(f"RPC error: {data['error']}")
            return data["result"]

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()


async def process_transaction(
    db: Database,
    tx: dict[str, Any],
    block_height: int,
    tx_index: int,
    block_time: int,
) -> bool:
    """Process a single transaction. Returns True if it contained DR data."""
    opreturn = extract_opreturn(tx)
    if opreturn is None:
        return False

    header = decode_header(opreturn)
    if header is None:
        return False

    version, sub_protocol, msg_type, payload, is_test = header
    txid = tx["txid"]
    sender = get_sender_address(tx) or "unknown"

    if sub_protocol == SubProtocol.DR_PAY:
        if msg_type == PayMessageType.SERVICE_DECLARATION:
            decl = decode_service_declaration(payload)
            if decl is None:
                log.warning("Malformed service declaration in %s", txid)
                return False
            await db.insert_declaration(
                txid=txid,
                block_height=block_height,
                tx_index=tx_index,
                sender_address=sender,
                category=decl["category"],
                capability_flags=decl["capability_flags"],
                manifest_hash=decl["manifest_hash"],
                manifest_domain=decl.get("manifest_domain", ""),
                is_withdrawal=decl["is_withdrawal"],
                is_test=is_test,
                version=version,
                block_time=block_time,
            )
            action = "withdrawal" if decl["is_withdrawal"] else "declaration"
            log.info(
                "Service %s: %s cat=0x%04X block=%d tx=%s",
                action, sender, decl["category"], block_height, txid[:16],
            )
            return True

        elif msg_type == PayMessageType.PAYMENT_MEMO:
            memo = decode_payment_memo(payload)
            if memo is None:
                log.warning("Malformed payment memo in %s", txid)
                return False
            await db.insert_payment_memo(
                txid=txid,
                block_height=block_height,
                tx_index=tx_index,
                sender_address=sender,
                invoice_id=memo["invoice_id"],
                service_ref=memo["service_ref"],
                is_test=is_test,
                version=version,
                block_time=block_time,
            )
            log.info("Payment memo: %s block=%d tx=%s", sender, block_height, txid[:16])
            return True

    elif sub_protocol == SubProtocol.DR_CORE:
        if msg_type == CoreMessageType.IDENTITY_DECLARATION:
            ident = decode_identity_declaration(payload)
            await db.insert_identity_declaration(
                txid=txid,
                block_height=block_height,
                tx_index=tx_index,
                sender_address=sender,
                label=ident["label"],
                is_test=is_test,
                version=version,
                block_time=block_time,
            )
            log.info("Identity declaration: %s label=%r block=%d", sender, ident["label"], block_height)
            return True

    elif sub_protocol == SubProtocol.DR_REP:
        if msg_type == RepMessageType.ATTESTATION:
            att = decode_attestation(payload)
            if att is None:
                log.warning("Malformed attestation in %s", txid)
                return False
            await db.insert_attestation(
                txid=txid,
                block_height=block_height,
                tx_index=tx_index,
                sender_address=sender,
                target_address_hash=att["target_address_hash"],
                score=att["score"],
                nonce=att["nonce"],
                is_test=is_test,
                version=version,
                block_time=block_time,
            )
            log.info("Attestation: %s → %s score=%d block=%d", sender, att["target_address_hash"][:16], att["score"], block_height)
            return True

    return False


async def sync_historical(
    db: Database,
    rpc: RpcClient,
    start_height: int,
) -> None:
    """Scan blocks from start_height to chain tip."""
    chain_height = await rpc.call("getblockcount")
    indexed_height = await db.get_indexed_height()
    effective_start = max(start_height, indexed_height + 1)

    if effective_start > chain_height:
        log.info("Already up to date at height %d", chain_height)
        return

    total = chain_height - effective_start + 1
    log.info("Historical sync: blocks %d to %d (%d blocks)", effective_start, chain_height, total)

    dr_count = 0
    for i, height in enumerate(range(effective_start, chain_height + 1)):
        bhash = await rpc.call("getblockhash", [height])
        block = await rpc.call("getblock", [bhash, 2])
        block_time = block.get("time", 0)

        for tx_idx, tx in enumerate(block.get("tx", [])):
            if tx_idx == 0:
                continue  # Skip coinbase
            found = await process_transaction(db, tx, height, tx_idx, block_time)
            if found:
                dr_count += 1

        await db.set_indexed_height(height)

        if (i + 1) % 1000 == 0:
            log.info(
                "  %d/%d blocks scanned (%d DR transactions found)",
                i + 1, total, dr_count,
            )

    log.info("Historical sync complete: %d DR transactions in %d blocks", dr_count, total)


async def poll_new_blocks(
    db: Database,
    rpc: RpcClient,
    poll_interval: float = 15.0,
) -> None:
    """Poll for new blocks and process them. Runs indefinitely."""
    log.info("Starting block poller (interval=%.0fs)", poll_interval)
    while True:
        try:
            chain_height = await rpc.call("getblockcount")
            indexed_height = await db.get_indexed_height()

            if chain_height > indexed_height:
                for height in range(indexed_height + 1, chain_height + 1):
                    bhash = await rpc.call("getblockhash", [height])
                    block = await rpc.call("getblock", [bhash, 2])
                    block_time = block.get("time", 0)

                    for tx_idx, tx in enumerate(block.get("tx", [])):
                        if tx_idx == 0:
                            continue
                        await process_transaction(db, tx, height, tx_idx, block_time)

                    await db.set_indexed_height(height)

                if chain_height - indexed_height > 1:
                    log.info("Caught up to block %d", chain_height)

        except Exception:
            log.exception("Error polling blocks")

        await asyncio.sleep(poll_interval)
