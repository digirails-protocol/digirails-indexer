"""Discovery Query Protocol REST API (spec §9.5)."""

from __future__ import annotations

import logging
import time
from typing import Any

from aiohttp import web

from dr_indexer.config import Config
from dr_indexer.db import Database
from dr_indexer.decoder import SERVICE_CATEGORIES
from dr_indexer.scanner import RpcClient
from dr_indexer.trust import build_trust_object

log = logging.getLogger(__name__)

PROTOCOL_VERSION = "0.3.0"


def create_app(db: Database, config: Config, rpc: RpcClient) -> web.Application:
    app = web.Application(middlewares=[cors_middleware])
    app["db"] = db
    app["config"] = config
    app["rpc"] = rpc

    app.router.add_get("/health", handle_health)
    app.router.add_get("/v1/services", handle_services)
    app.router.add_get("/v1/agents/{address}", handle_agent)
    app.router.add_get("/v1/status", handle_status)
    app.router.add_get("/v1/declarations", handle_declarations)
    app.router.add_get("/v1/payments", handle_payments)
    app.router.add_get("/v1/attestations", handle_attestations)
    app.router.add_get("/v1/blocks/recent", handle_recent_blocks)

    return app


@web.middleware
async def cors_middleware(request: web.Request, handler: Any) -> web.StreamResponse:
    if request.method == "OPTIONS":
        resp = web.Response()
    else:
        resp = await handler(request)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp


async def handle_health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


async def handle_services(request: web.Request) -> web.Response:
    """GET /v1/services — Service search (spec §9.5.1)."""
    db: Database = request.app["db"]
    config: Config = request.app["config"]
    rpc: RpcClient = request.app["rpc"]

    # Parse query parameters
    category_str = request.query.get("category")
    category: int | None = None
    if category_str:
        try:
            category = int(category_str, 16) if category_str.startswith("0x") else int(category_str)
        except ValueError:
            return web.json_response({"error": "Invalid category"}, status=400)

    min_trust = int(request.query.get("min_trust", "0"))
    currency = request.query.get("currency")
    status = request.query.get("status", "active")
    limit = min(int(request.query.get("limit", "20")), 100)
    offset = int(request.query.get("offset", "0"))
    include_unrated = request.query.get("include_unrated", "true").lower() == "true"

    if status not in ("active", "new", "demoted", "all"):
        return web.json_response({"error": "Invalid status"}, status=400)

    # Get chain height for trust computation
    try:
        chain_height = await rpc.call("getblockcount")
    except Exception:
        chain_height = 0

    # Query authoritative declarations
    declarations = await db.get_authoritative_declarations(
        category=category,
        status=status,
    )

    # Build results with trust scores
    results = []
    for decl in declarations:
        trust = build_trust_object(decl, chain_height)

        if trust["composite_score"] < min_trust:
            continue

        if not include_unrated and trust["reputation"]["attestation_count"] == 0:
            # Only skip if min_reputation or include_unrated=false specifically set
            if request.query.get("include_unrated") == "false":
                continue

        # Get agent label from identity declarations
        label = ""
        agent_data = await db.get_agent(decl["sender_address"])
        if agent_data and agent_data.get("identity"):
            label = agent_data["identity"].get("label", "")

        cat_code = decl["category"]
        validation_status = decl.get("validation_status", "new")

        result = {
            "address": decl["sender_address"],
            "label": label,
            "category": f"0x{cat_code:04X}",
            "category_name": SERVICE_CATEGORIES.get(cat_code, f"Unknown"),
            "manifest_url": decl.get("manifest_url"),
            "manifest_hash": decl["manifest_hash"],
            "manifest_verified": bool(decl.get("manifest_valid")),
            "declaration_txid": decl["txid"],
            "declaration_block": decl["block_height"],
            "trust": trust,
            "status": validation_status if validation_status else "new",
            "last_seen_active": decl.get("last_checked_at"),
        }
        results.append(result)

    # Sort by composite trust score descending
    results.sort(key=lambda r: r["trust"]["composite_score"], reverse=True)

    # Pagination
    total = len(results)
    results = results[offset : offset + limit]

    return web.json_response({
        "protocol": "drpay",
        "version": PROTOCOL_VERSION,
        "type": "discovery_response",
        "indexer": config.indexer_url,
        "total": total,
        "results": results,
    })


async def handle_agent(request: web.Request) -> web.Response:
    """GET /v1/agents/{address} — Agent lookup (spec §9.5.2)."""
    db: Database = request.app["db"]
    config: Config = request.app["config"]
    rpc: RpcClient = request.app["rpc"]
    address = request.match_info["address"]

    agent = await db.get_agent(address)
    if agent is None:
        return web.json_response(
            {"error": f"Agent {address} not found"}, status=404,
        )

    try:
        chain_height = await rpc.call("getblockcount")
    except Exception:
        chain_height = 0

    # Build services list with trust
    services = []
    for decl in agent.get("declarations", []):
        trust = build_trust_object(
            decl, chain_height,
            attestations=agent.get("attestations"),
            tx_count=agent.get("transaction_count", 0),
        )
        cat_code = decl["category"]
        services.append({
            "category": f"0x{cat_code:04X}",
            "category_name": SERVICE_CATEGORIES.get(cat_code, "Unknown"),
            "manifest_url": decl.get("manifest_url"),
            "manifest_hash": decl["manifest_hash"],
            "manifest_verified": bool(decl.get("manifest_valid")),
            "declaration_txid": decl["txid"],
            "declaration_block": decl["block_height"],
            "trust": trust,
            "status": decl.get("validation_status", "new"),
        })

    identity = agent.get("identity")
    response = {
        "protocol": "drpay",
        "version": PROTOCOL_VERSION,
        "type": "agent_profile",
        "indexer": config.indexer_url,
        "address": address,
        "label": identity.get("label", "") if identity else "",
        "services": services,
        "transaction_count": agent.get("transaction_count", 0),
        "attestation_count": len(agent.get("attestations", [])),
    }

    return web.json_response(response)


async def handle_status(request: web.Request) -> web.Response:
    """GET /v1/status — Indexer metadata (spec §9.5.3)."""
    db: Database = request.app["db"]
    config: Config = request.app["config"]
    rpc: RpcClient = request.app["rpc"]

    try:
        chain_height = await rpc.call("getblockcount")
    except Exception:
        chain_height = 0

    indexed_height = await db.get_indexed_height()
    stats = await db.get_stats()

    return web.json_response({
        "protocol": "drpay",
        "version": PROTOCOL_VERSION,
        "type": "indexer_status",
        "indexer": config.indexer_url,
        "chain_height": chain_height,
        "indexed_height": indexed_height,
        "total_agents": stats.get("total_agents", 0),
        "total_services": stats.get("total_services", 0),
        "total_declarations": stats.get("total_declarations", 0),
        "total_payment_memos": stats.get("total_payment_memos", 0),
        "total_attestations": stats.get("total_attestations", 0),
        "manifest_check_interval_seconds": config.manifest_check_interval,
        "supported_query_params": [
            "category", "min_trust", "min_reputation", "currency",
            "verified_only", "include_unrated", "status",
        ],
    })


async def handle_declarations(request: web.Request) -> web.Response:
    """GET /v1/declarations — Chronological declaration feed."""
    db: Database = request.app["db"]
    config: Config = request.app["config"]

    limit = min(int(request.query.get("limit", "50")), 100)
    offset = int(request.query.get("offset", "0"))

    rows, total = await db.get_recent_declarations(limit=limit, offset=offset)

    results = []
    for row in rows:
        cat_code = row["category"]
        results.append({
            "txid": row["txid"],
            "block_height": row["block_height"],
            "block_time": row["block_time"],
            "sender_address": row["sender_address"],
            "sender_label": row.get("sender_label") or "",
            "category": f"0x{cat_code:04X}",
            "category_name": SERVICE_CATEGORIES.get(cat_code, "Unknown"),
            "manifest_hash": row["manifest_hash"],
            "manifest_domain": row.get("manifest_domain", ""),
            "is_withdrawal": bool(row["is_withdrawal"]),
            "is_test": bool(row["is_test"]),
            "version": row["version"],
        })

    return web.json_response({
        "protocol": "drpay",
        "version": PROTOCOL_VERSION,
        "type": "declaration_feed",
        "indexer": config.indexer_url,
        "total": total,
        "results": results,
    })


async def handle_payments(request: web.Request) -> web.Response:
    """GET /v1/payments — Chronological payment memo feed."""
    db: Database = request.app["db"]
    config: Config = request.app["config"]

    limit = min(int(request.query.get("limit", "50")), 100)
    offset = int(request.query.get("offset", "0"))

    rows, total = await db.get_recent_payments(limit=limit, offset=offset)

    results = []
    for row in rows:
        results.append({
            "txid": row["txid"],
            "block_height": row["block_height"],
            "block_time": row["block_time"],
            "sender_address": row["sender_address"],
            "sender_label": row.get("sender_label") or "",
            "invoice_id": row.get("invoice_id", ""),
            "service_ref": row.get("service_ref", ""),
            "is_test": bool(row["is_test"]),
            "version": row["version"],
        })

    return web.json_response({
        "protocol": "drpay",
        "version": PROTOCOL_VERSION,
        "type": "payment_feed",
        "indexer": config.indexer_url,
        "total": total,
        "results": results,
    })


async def handle_attestations(request: web.Request) -> web.Response:
    """GET /v1/attestations — Chronological attestation feed."""
    db: Database = request.app["db"]
    config: Config = request.app["config"]

    limit = min(int(request.query.get("limit", "50")), 100)
    offset = int(request.query.get("offset", "0"))

    rows, total = await db.get_recent_attestations(limit=limit, offset=offset)

    results = []
    for row in rows:
        results.append({
            "txid": row["txid"],
            "block_height": row["block_height"],
            "block_time": row["block_time"],
            "sender_address": row["sender_address"],
            "sender_label": row.get("sender_label") or "",
            "target_address_hash": row["target_address_hash"],
            "score": row["score"],
            "nonce": row["nonce"],
            "is_test": bool(row["is_test"]),
            "version": row["version"],
        })

    return web.json_response({
        "protocol": "drpay",
        "version": PROTOCOL_VERSION,
        "type": "attestation_feed",
        "indexer": config.indexer_url,
        "total": total,
        "results": results,
    })


async def handle_recent_blocks(request: web.Request) -> web.Response:
    """GET /v1/blocks/recent — Recent blocks with DR protocol activity."""
    db: Database = request.app["db"]
    config: Config = request.app["config"]
    rpc: RpcClient = request.app["rpc"]

    limit = min(int(request.query.get("limit", "20")), 50)

    try:
        chain_height = await rpc.call("getblockcount")
    except Exception:
        chain_height = 0

    blocks = await db.get_recent_blocks(limit=limit)

    return web.json_response({
        "protocol": "drpay",
        "version": PROTOCOL_VERSION,
        "type": "block_activity",
        "indexer": config.indexer_url,
        "chain_height": chain_height,
        "blocks": blocks,
    })
