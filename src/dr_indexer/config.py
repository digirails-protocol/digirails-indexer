"""Indexer configuration from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Config:
    rpc_url: str = "http://127.0.0.1:14022/"
    rpc_user: str = ""
    rpc_pass: str = ""
    db_path: str = "./indexer.db"
    api_host: str = "127.0.0.1"
    api_port: int = 8090
    zmq_url: str = "tcp://127.0.0.1:28332"
    manifest_check_interval: int = 3600
    start_block: int = 23_013_000
    seed_manifest_urls: list[str] = field(default_factory=list)
    indexer_url: str = "https://indexer.digirails.org"

    @classmethod
    def from_env(cls) -> Config:
        seeds = os.environ.get("DR_SEED_MANIFEST_URLS", "")
        return cls(
            rpc_url=os.environ.get("DR_RPC_URL", cls.rpc_url),
            rpc_user=os.environ.get("DR_RPC_USER", ""),
            rpc_pass=os.environ.get("DR_RPC_PASS", ""),
            db_path=os.environ.get("DR_DB_PATH", cls.db_path),
            api_host=os.environ.get("DR_API_HOST", cls.api_host),
            api_port=int(os.environ.get("DR_API_PORT", str(cls.api_port))),
            zmq_url=os.environ.get("DR_ZMQ_URL", cls.zmq_url),
            manifest_check_interval=int(
                os.environ.get("DR_MANIFEST_CHECK_INTERVAL", str(cls.manifest_check_interval))
            ),
            start_block=int(os.environ.get("DR_START_BLOCK", str(cls.start_block))),
            seed_manifest_urls=[u.strip() for u in seeds.split(",") if u.strip()],
            indexer_url=os.environ.get("DR_INDEXER_URL", cls.indexer_url),
        )
