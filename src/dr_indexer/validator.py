"""Manifest validation and staleness monitoring (spec §9.4)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import ssl
import time
from typing import Any
from urllib.parse import urlparse

import aiohttp

from dr_indexer.config import Config
from dr_indexer.db import Database

log = logging.getLogger(__name__)


async def validate_manifest(
    session: aiohttp.ClientSession,
    manifest_url: str,
    expected_hash: str,
) -> dict[str, Any]:
    """Fetch and validate a manifest against its expected hash.

    Returns validation results dict.
    """
    result: dict[str, Any] = {
        "manifest_hash_actual": None,
        "manifest_valid": False,
        "endpoint_responsive": False,
        "tls_valid": False,
        "manifest_data": None,
    }

    try:
        async with session.get(manifest_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                log.warning("Manifest fetch failed: %s returned %d", manifest_url, resp.status)
                return result

            body = await resp.text()
            result["tls_valid"] = manifest_url.startswith("https://")

            # Validate JSON
            try:
                manifest_data = json.loads(body)
            except json.JSONDecodeError:
                log.warning("Manifest is not valid JSON: %s", manifest_url)
                return result

            # Compute hash of the manifest body
            actual_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
            result["manifest_hash_actual"] = actual_hash
            result["manifest_data"] = manifest_data

            # Compare hashes
            if actual_hash == expected_hash:
                result["manifest_valid"] = True
            else:
                log.warning(
                    "Manifest hash mismatch for %s: expected=%s actual=%s",
                    manifest_url, expected_hash[:16], actual_hash[:16],
                )

            # Probe service endpoints from manifest
            services = manifest_data.get("services", [])
            if services:
                endpoint = services[0].get("endpoint", "")
                if endpoint:
                    result["endpoint_responsive"] = await probe_endpoint(session, endpoint)

    except asyncio.TimeoutError:
        log.warning("Manifest fetch timed out: %s", manifest_url)
    except aiohttp.ClientError as e:
        log.warning("Manifest fetch error for %s: %s", manifest_url, e)
    except Exception:
        log.exception("Unexpected error validating manifest: %s", manifest_url)

    return result


async def probe_endpoint(
    session: aiohttp.ClientSession,
    endpoint: str,
) -> bool:
    """Probe a service endpoint to verify it speaks DR-Pay.

    Sends a deliberately invalid request and checks for a DR-Pay error response.
    """
    try:
        async with session.post(
            endpoint,
            json={"protocol": "drpay", "type": "payment_request", "probe": True},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            # Any response (even 400) from the endpoint means it's responsive
            if resp.status in (200, 400, 405):
                return True
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass
    return False


async def verify_dns(domain: str, address: str) -> bool:
    """Verify that address is authorized for domain via _digirails TXT records.

    Walks up the DNS hierarchy per spec §4.4.2:
      1. Query _digirails.<domain> for TXT records
      2. If address found, return True
      3. Strip leftmost label and repeat
      4. Stop after checking the registered domain (2 labels)
    """
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        check_domain = ".".join(labels[i:])
        if len(check_domain.split(".")) < 2:
            break
        txt_name = f"_digirails.{check_domain}"
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "TXT", txt_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            for line in stdout.decode().strip().splitlines():
                value = line.strip().strip('"')
                if value == address:
                    return True
        except FileNotFoundError:
            log.warning("dig not found — DNS verification unavailable")
            return False
        except asyncio.TimeoutError:
            log.debug("DNS lookup timed out for %s", txt_name)
        except Exception:
            log.debug("DNS lookup failed for %s", txt_name, exc_info=True)
    return False


async def discover_manifest_url_from_seeds(
    session: aiohttp.ClientSession,
    seed_urls: list[str],
    address: str,
) -> str | None:
    """Try to discover manifest URL for an address from seed manifest URLs."""
    for url in seed_urls:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    continue
                data = await resp.json(content_type=None)
                if data.get("address") == address:
                    # This manifest belongs to the address
                    discovery = data.get("discovery", {})
                    return discovery.get("manifest_url", url)
        except Exception:
            continue
    return None


async def run_validation_cycle(
    db: Database,
    config: Config,
) -> None:
    """Run one cycle of manifest validation for all registered services."""
    checks = await db.get_checks_needing_validation()
    if not checks:
        return

    log.info("Validating %d manifest(s)", len(checks))

    async with aiohttp.ClientSession() as session:
        for check in checks:
            address = check["sender_address"]
            category = check["category"]
            expected_hash = check["manifest_hash_expected"]
            manifest_url = check.get("manifest_url")
            failures = check.get("consecutive_failures", 0)

            # Fallback: discover manifest URL from seed URLs if not set
            if not manifest_url and config.seed_manifest_urls:
                manifest_url = await discover_manifest_url_from_seeds(
                    session, config.seed_manifest_urls, address,
                )

            if not manifest_url:
                log.debug("No manifest URL for %s cat=0x%04X, skipping", address, category)
                continue

            result = await validate_manifest(session, manifest_url, expected_hash)

            # DNS verification (spec §4.4)
            dns_verified = False
            domain = urlparse(manifest_url).hostname if manifest_url else None
            if domain:
                dns_verified = await verify_dns(domain, address)

            # Determine status per demotion rules (spec §9.4.2)
            if result["manifest_valid"] and result["endpoint_responsive"]:
                status = "active"
                failures = 0
            else:
                failures += 1
                if not result["manifest_valid"] and result["manifest_hash_actual"] is not None:
                    # Hash mismatch → immediate demotion
                    status = "demoted"
                elif failures >= 3:
                    # 3 consecutive failures → demotion
                    status = "demoted"
                elif failures >= 2 and not result["endpoint_responsive"]:
                    # 2 endpoint failures → demotion
                    status = "demoted"
                else:
                    status = check.get("status", "new")

            await db.update_manifest_check(
                sender_address=address,
                category=category,
                manifest_url=manifest_url,
                manifest_hash_actual=result["manifest_hash_actual"],
                manifest_valid=result["manifest_valid"],
                endpoint_responsive=result["endpoint_responsive"],
                dns_verified=dns_verified,
                tls_valid=result["tls_valid"],
                status=status,
                consecutive_failures=failures,
            )

            if status == "demoted":
                log.warning(
                    "Demoted %s cat=0x%04X (failures=%d)", address, category, failures,
                )
            elif status == "active":
                log.info("Validated %s cat=0x%04X: active", address, category)


async def staleness_loop(
    db: Database,
    config: Config,
) -> None:
    """Periodically re-validate manifests."""
    log.info(
        "Starting staleness monitor (interval=%ds)", config.manifest_check_interval,
    )
    while True:
        try:
            await run_validation_cycle(db, config)
        except Exception:
            log.exception("Error in validation cycle")
        await asyncio.sleep(config.manifest_check_interval)
