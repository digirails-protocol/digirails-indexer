"""DigiRails indexer entry point."""

from __future__ import annotations

import asyncio
import logging
import signal
import sys

from aiohttp import web

from dr_indexer.api import create_app
from dr_indexer.config import Config
from dr_indexer.db import Database
from dr_indexer.scanner import RpcClient, poll_new_blocks, sync_historical
from dr_indexer.validator import run_validation_cycle, staleness_loop

log = logging.getLogger("dr_indexer")


async def run(config: Config) -> None:
    # Initialize database
    db = Database(config.db_path)
    await db.open()
    log.info("Database opened: %s", config.db_path)

    # Initialize RPC
    rpc = RpcClient(config.rpc_url, config.rpc_user, config.rpc_pass)
    try:
        height = await rpc.call("getblockcount")
        log.info("Connected to DGB Core at %s (height=%d)", config.rpc_url, height)
    except Exception as e:
        log.error("Cannot connect to DGB Core at %s: %s", config.rpc_url, e)
        await db.close()
        return

    # Historical sync
    log.info("Starting historical sync from block %d...", config.start_block)
    await sync_historical(db, rpc, config.start_block)

    # Initial manifest validation
    log.info("Running initial manifest validation...")
    await run_validation_cycle(db, config)

    # Start background tasks
    poller_task = asyncio.create_task(poll_new_blocks(db, rpc))
    staleness_task = asyncio.create_task(staleness_loop(db, config))

    # Start API server
    app = create_app(db, config, rpc)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, config.api_host, config.api_port)
    await site.start()
    log.info("API server listening on %s:%d", config.api_host, config.api_port)

    # Wait for shutdown
    stop = asyncio.Event()

    def on_signal() -> None:
        log.info("Shutdown signal received")
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, on_signal)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass

    try:
        await stop.wait()
    except KeyboardInterrupt:
        pass

    # Cleanup
    log.info("Shutting down...")
    poller_task.cancel()
    staleness_task.cancel()
    await runner.cleanup()
    await rpc.close()
    await db.close()
    log.info("Shutdown complete")


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    config = Config.from_env()
    log.info("DigiRails Indexer v0.1.0")
    log.info("RPC: %s", config.rpc_url)
    log.info("DB: %s", config.db_path)
    log.info("API: %s:%d", config.api_host, config.api_port)

    try:
        asyncio.run(run(config))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
