"""SQLite database layer for the indexer."""

from __future__ import annotations

import time
from typing import Any

import aiosqlite

SCHEMA = """
CREATE TABLE IF NOT EXISTS declarations (
    txid TEXT PRIMARY KEY,
    block_height INTEGER NOT NULL,
    tx_index INTEGER NOT NULL,
    sender_address TEXT NOT NULL,
    category INTEGER NOT NULL,
    capability_flags INTEGER NOT NULL,
    manifest_hash TEXT NOT NULL,
    manifest_domain TEXT NOT NULL DEFAULT '',
    is_withdrawal INTEGER NOT NULL DEFAULT 0,
    is_test INTEGER NOT NULL DEFAULT 0,
    version INTEGER NOT NULL DEFAULT 1,
    block_time INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS payment_memos (
    txid TEXT PRIMARY KEY,
    block_height INTEGER NOT NULL,
    tx_index INTEGER NOT NULL,
    sender_address TEXT NOT NULL,
    invoice_id TEXT,
    service_ref TEXT,
    is_test INTEGER NOT NULL DEFAULT 0,
    version INTEGER NOT NULL DEFAULT 1,
    block_time INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS attestations (
    txid TEXT PRIMARY KEY,
    block_height INTEGER NOT NULL,
    tx_index INTEGER NOT NULL,
    sender_address TEXT NOT NULL,
    target_address_hash TEXT NOT NULL,
    score INTEGER NOT NULL,
    nonce INTEGER NOT NULL,
    is_test INTEGER NOT NULL DEFAULT 0,
    version INTEGER NOT NULL DEFAULT 1,
    block_time INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_declarations (
    txid TEXT PRIMARY KEY,
    block_height INTEGER NOT NULL,
    tx_index INTEGER NOT NULL,
    sender_address TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    is_test INTEGER NOT NULL DEFAULT 0,
    version INTEGER NOT NULL DEFAULT 1,
    block_time INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS manifest_checks (
    sender_address TEXT NOT NULL,
    category INTEGER NOT NULL,
    manifest_url TEXT,
    manifest_hash_expected TEXT NOT NULL,
    manifest_hash_actual TEXT,
    manifest_valid INTEGER,
    endpoint_responsive INTEGER,
    dns_verified INTEGER,
    tls_valid INTEGER,
    last_checked_at INTEGER,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'new',
    PRIMARY KEY (sender_address, category)
);

CREATE TABLE IF NOT EXISTS indexer_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_decl_address_cat ON declarations(sender_address, category);
CREATE INDEX IF NOT EXISTS idx_decl_block ON declarations(block_height);
CREATE INDEX IF NOT EXISTS idx_memo_address ON payment_memos(sender_address);
CREATE INDEX IF NOT EXISTS idx_attest_target ON attestations(target_address_hash);
CREATE INDEX IF NOT EXISTS idx_attest_sender ON attestations(sender_address);
CREATE INDEX IF NOT EXISTS idx_identity_address ON identity_declarations(sender_address);
"""


class Database:
    def __init__(self, path: str):
        self._path = path
        self._db: aiosqlite.Connection | None = None

    async def open(self) -> None:
        self._db = await aiosqlite.connect(self._path)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(SCHEMA)
        await self._migrate()
        await self._db.commit()

    async def _migrate(self) -> None:
        """Run schema migrations for existing databases."""
        # v0.3.0: add manifest_domain column to declarations
        async with self.db.execute("PRAGMA table_info(declarations)") as cur:
            cols = {row[1] for row in await cur.fetchall()}
        if "manifest_domain" not in cols:
            await self.db.execute(
                "ALTER TABLE declarations ADD COLUMN manifest_domain TEXT NOT NULL DEFAULT ''"
            )

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    @property
    def db(self) -> aiosqlite.Connection:
        assert self._db is not None, "Database not opened"
        return self._db

    # --- State ---

    async def get_state(self, key: str, default: str = "") -> str:
        async with self.db.execute(
            "SELECT value FROM indexer_state WHERE key = ?", (key,)
        ) as cur:
            row = await cur.fetchone()
            return row["value"] if row else default

    async def set_state(self, key: str, value: str) -> None:
        await self.db.execute(
            "INSERT OR REPLACE INTO indexer_state (key, value) VALUES (?, ?)",
            (key, value),
        )
        await self.db.commit()

    async def get_indexed_height(self) -> int:
        return int(await self.get_state("indexed_height", "0"))

    async def set_indexed_height(self, height: int) -> None:
        await self.set_state("indexed_height", str(height))

    # --- Declarations ---

    async def insert_declaration(
        self,
        txid: str,
        block_height: int,
        tx_index: int,
        sender_address: str,
        category: int,
        capability_flags: int,
        manifest_hash: str,
        manifest_domain: str,
        is_withdrawal: bool,
        is_test: bool,
        version: int,
        block_time: int,
    ) -> None:
        await self.db.execute(
            """INSERT OR IGNORE INTO declarations
            (txid, block_height, tx_index, sender_address, category,
             capability_flags, manifest_hash, manifest_domain,
             is_withdrawal, is_test, version, block_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                txid, block_height, tx_index, sender_address, category,
                capability_flags, manifest_hash, manifest_domain,
                int(is_withdrawal), int(is_test), version, block_time,
            ),
        )
        await self.db.commit()

        # Upsert manifest_checks entry for non-withdrawals
        if not is_withdrawal:
            # Construct manifest URL from on-chain domain if available
            manifest_url = (
                f"https://{manifest_domain}/.well-known/digirails.json"
                if manifest_domain else None
            )
            await self.db.execute(
                """INSERT INTO manifest_checks
                (sender_address, category, manifest_hash_expected, manifest_url, status)
                VALUES (?, ?, ?, ?, 'new')
                ON CONFLICT(sender_address, category) DO UPDATE SET
                    manifest_hash_expected = excluded.manifest_hash_expected,
                    manifest_url = COALESCE(excluded.manifest_url, manifest_checks.manifest_url),
                    manifest_valid = NULL,
                    consecutive_failures = 0,
                    status = 'new'""",
                (sender_address, category, manifest_hash, manifest_url),
            )
            await self.db.commit()

    # --- Payment Memos ---

    async def insert_payment_memo(
        self,
        txid: str,
        block_height: int,
        tx_index: int,
        sender_address: str,
        invoice_id: str,
        service_ref: str,
        is_test: bool,
        version: int,
        block_time: int,
    ) -> None:
        await self.db.execute(
            """INSERT OR IGNORE INTO payment_memos
            (txid, block_height, tx_index, sender_address,
             invoice_id, service_ref, is_test, version, block_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                txid, block_height, tx_index, sender_address,
                invoice_id, service_ref, int(is_test), version, block_time,
            ),
        )
        await self.db.commit()

    # --- Attestations ---

    async def insert_attestation(
        self,
        txid: str,
        block_height: int,
        tx_index: int,
        sender_address: str,
        target_address_hash: str,
        score: int,
        nonce: int,
        is_test: bool,
        version: int,
        block_time: int,
    ) -> None:
        await self.db.execute(
            """INSERT OR IGNORE INTO attestations
            (txid, block_height, tx_index, sender_address,
             target_address_hash, score, nonce, is_test, version, block_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                txid, block_height, tx_index, sender_address,
                target_address_hash, score, nonce, int(is_test), version, block_time,
            ),
        )
        await self.db.commit()

    # --- Identity Declarations ---

    async def insert_identity_declaration(
        self,
        txid: str,
        block_height: int,
        tx_index: int,
        sender_address: str,
        label: str,
        is_test: bool,
        version: int,
        block_time: int,
    ) -> None:
        await self.db.execute(
            """INSERT OR IGNORE INTO identity_declarations
            (txid, block_height, tx_index, sender_address,
             label, is_test, version, block_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                txid, block_height, tx_index, sender_address,
                label, int(is_test), version, block_time,
            ),
        )
        await self.db.commit()

    # --- Queries ---

    async def get_authoritative_declarations(
        self,
        category: int | None = None,
        status: str = "active",
        include_test: bool = False,
    ) -> list[dict[str, Any]]:
        """Get the latest declaration per (address, category), excluding withdrawals.

        Supersession: highest (block_height, tx_index) wins.
        """
        query = """
            SELECT d.*, mc.status as validation_status,
                   mc.manifest_url, mc.manifest_valid, mc.endpoint_responsive,
                   mc.dns_verified, mc.tls_valid, mc.last_checked_at
            FROM declarations d
            INNER JOIN (
                SELECT sender_address, category,
                       MAX(block_height * 1000000 + tx_index) as max_pos
                FROM declarations
                GROUP BY sender_address, category
            ) latest
            ON d.sender_address = latest.sender_address
               AND d.category = latest.category
               AND (d.block_height * 1000000 + d.tx_index) = latest.max_pos
            LEFT JOIN manifest_checks mc
            ON d.sender_address = mc.sender_address AND d.category = mc.category
            WHERE d.is_withdrawal = 0
        """
        params: list[Any] = []

        if not include_test:
            query += " AND d.is_test = 0"

        if category is not None:
            query += " AND d.category = ?"
            params.append(category)

        if status == "active":
            query += " AND (mc.status IS NULL OR mc.status != 'demoted')"
        elif status == "new":
            query += " AND mc.status = 'new'"
        elif status == "demoted":
            query += " AND mc.status = 'demoted'"

        query += " ORDER BY d.block_height DESC"

        async with self.db.execute(query, params) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def get_agent(self, address: str) -> dict[str, Any] | None:
        """Get full profile for an agent address."""
        # Get identity
        async with self.db.execute(
            """SELECT * FROM identity_declarations
            WHERE sender_address = ?
            ORDER BY block_height DESC, tx_index DESC LIMIT 1""",
            (address,),
        ) as cur:
            identity = await cur.fetchone()

        # Get all declarations (authoritative only)
        async with self.db.execute(
            """SELECT d.*, mc.status as validation_status,
                      mc.manifest_url, mc.manifest_valid, mc.endpoint_responsive,
                      mc.dns_verified, mc.tls_valid, mc.last_checked_at
            FROM declarations d
            INNER JOIN (
                SELECT sender_address, category,
                       MAX(block_height * 1000000 + tx_index) as max_pos
                FROM declarations
                WHERE sender_address = ?
                GROUP BY sender_address, category
            ) latest
            ON d.sender_address = latest.sender_address
               AND d.category = latest.category
               AND (d.block_height * 1000000 + d.tx_index) = latest.max_pos
            LEFT JOIN manifest_checks mc
            ON d.sender_address = mc.sender_address AND d.category = mc.category
            WHERE d.is_withdrawal = 0""",
            (address,),
        ) as cur:
            declarations = [dict(r) for r in await cur.fetchall()]

        if not declarations and not identity:
            return None

        # Get attestations about this agent
        async with self.db.execute(
            """SELECT * FROM attestations
            WHERE target_address_hash IN (
                SELECT DISTINCT target_address_hash FROM attestations
            )
            ORDER BY block_height DESC""",
        ) as cur:
            all_attestations = [dict(r) for r in await cur.fetchall()]

        # Count payment memos involving this address
        async with self.db.execute(
            "SELECT COUNT(*) as cnt FROM payment_memos WHERE sender_address = ?",
            (address,),
        ) as cur:
            row = await cur.fetchone()
            tx_count = row["cnt"] if row else 0

        return {
            "address": address,
            "identity": dict(identity) if identity else None,
            "declarations": declarations,
            "attestations": all_attestations,
            "transaction_count": tx_count,
        }

    async def get_stats(self) -> dict[str, int]:
        """Get aggregate stats for the indexer status endpoint."""
        stats: dict[str, int] = {}
        for table, key in [
            ("declarations", "total_declarations"),
            ("payment_memos", "total_payment_memos"),
            ("attestations", "total_attestations"),
            ("identity_declarations", "total_identity_declarations"),
        ]:
            async with self.db.execute(f"SELECT COUNT(*) as cnt FROM {table}") as cur:
                row = await cur.fetchone()
                stats[key] = row["cnt"] if row else 0

        # Count unique agent addresses (across declarations)
        async with self.db.execute(
            "SELECT COUNT(DISTINCT sender_address) as cnt FROM declarations WHERE is_withdrawal = 0"
        ) as cur:
            row = await cur.fetchone()
            stats["total_agents"] = row["cnt"] if row else 0

        # Count active services (authoritative, non-withdrawn)
        auth_decls = await self.get_authoritative_declarations(status="all")
        stats["total_services"] = len(auth_decls)

        return stats

    # --- Manifest checks ---

    async def get_checks_needing_validation(self) -> list[dict[str, Any]]:
        """Get manifest checks that need re-validation."""
        async with self.db.execute(
            """SELECT mc.*, d.block_height as declaration_block
            FROM manifest_checks mc
            JOIN declarations d ON mc.sender_address = d.sender_address
                AND mc.category = d.category
            WHERE mc.last_checked_at IS NULL
               OR mc.last_checked_at < ?
            ORDER BY mc.last_checked_at ASC NULLS FIRST""",
            (int(time.time()) - 3600,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def update_manifest_check(
        self,
        sender_address: str,
        category: int,
        manifest_url: str | None,
        manifest_hash_actual: str | None,
        manifest_valid: bool | None,
        endpoint_responsive: bool | None,
        dns_verified: bool | None,
        tls_valid: bool | None,
        status: str,
        consecutive_failures: int,
    ) -> None:
        await self.db.execute(
            """UPDATE manifest_checks SET
                manifest_url = COALESCE(?, manifest_url),
                manifest_hash_actual = ?,
                manifest_valid = ?,
                endpoint_responsive = ?,
                dns_verified = ?,
                tls_valid = ?,
                last_checked_at = ?,
                status = ?,
                consecutive_failures = ?
            WHERE sender_address = ? AND category = ?""",
            (
                manifest_url, manifest_hash_actual,
                int(manifest_valid) if manifest_valid is not None else None,
                int(endpoint_responsive) if endpoint_responsive is not None else None,
                int(dns_verified) if dns_verified is not None else None,
                int(tls_valid) if tls_valid is not None else None,
                int(time.time()), status, consecutive_failures,
                sender_address, category,
            ),
        )
        await self.db.commit()
