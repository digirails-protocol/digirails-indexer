"""Composite trust score computation (spec §9.4.3)."""

from __future__ import annotations

import time
from typing import Any

# Blocks per day at ~15s block time
BLOCKS_PER_DAY = 5760

# Mechanical signal weights (0-255 scale)
W_MANIFEST_VALID = 80
W_ENDPOINT_RESPONSIVE = 40
W_DNS_VERIFIED = 60
W_DECLARATION_AGE = 30
W_TLS_VALID = 10

# Reputation signal weights
W_REP_SCORE = 60
W_REP_DIVERSITY = 40
W_REP_VOLUME = 15

# Maximum declaration age bonus (in days)
MAX_AGE_DAYS = 30


def compute_mechanical_score(
    manifest_valid: bool | None,
    endpoint_responsive: bool | None,
    dns_verified: bool | None,
    tls_valid: bool | None,
    declaration_age_blocks: int,
) -> int:
    """Compute mechanical trust score component (0-255)."""
    score = 0
    total_weight = W_MANIFEST_VALID + W_ENDPOINT_RESPONSIVE + W_DNS_VERIFIED + W_DECLARATION_AGE + W_TLS_VALID

    if manifest_valid:
        score += W_MANIFEST_VALID
    if endpoint_responsive:
        score += W_ENDPOINT_RESPONSIVE
    if dns_verified:
        score += W_DNS_VERIFIED
    if tls_valid:
        score += W_TLS_VALID

    # Declaration age: linear scale up to MAX_AGE_DAYS
    age_days = declaration_age_blocks / BLOCKS_PER_DAY
    age_factor = min(age_days / MAX_AGE_DAYS, 1.0)
    score += int(W_DECLARATION_AGE * age_factor)

    # Normalize to 0-255
    return min(int(score / total_weight * 255), 255)


def compute_reputation_score(
    attestation_score: float | None,
    unique_attestors: int,
    transaction_count: int,
) -> int | None:
    """Compute reputation score component (0-255). Returns None if no attestations."""
    if attestation_score is None or unique_attestors == 0:
        return None

    total_weight = W_REP_SCORE + W_REP_DIVERSITY + W_REP_VOLUME
    score = 0

    # Attestation score (already 0-255)
    score += int(W_REP_SCORE * attestation_score / 255)

    # Diversity: diminishing returns, caps at 20 unique attestors
    diversity_factor = min(unique_attestors / 20, 1.0)
    score += int(W_REP_DIVERSITY * diversity_factor)

    # Volume: diminishing returns, caps at 100 transactions
    volume_factor = min(transaction_count / 100, 1.0)
    score += int(W_REP_VOLUME * volume_factor)

    return min(int(score / total_weight * 255), 255)


def compute_composite_score(
    mechanical: int,
    reputation: int | None,
) -> int:
    """Combine mechanical and reputation into composite (0-255).

    During bootstrap (no reputation data), mechanical score dominates.
    As reputation data grows, it blends in.
    """
    if reputation is None:
        return mechanical

    # Blend: 40% mechanical + 60% reputation (when reputation exists)
    return min(int(mechanical * 0.4 + reputation * 0.6), 255)


def build_trust_object(
    declaration: dict[str, Any],
    chain_height: int,
    attestations: list[dict[str, Any]] | None = None,
    tx_count: int = 0,
) -> dict[str, Any]:
    """Build the trust object for API responses."""
    manifest_valid = bool(declaration.get("manifest_valid"))
    endpoint_responsive = bool(declaration.get("endpoint_responsive"))
    dns_verified = bool(declaration.get("dns_verified"))
    tls_valid = bool(declaration.get("tls_valid"))
    decl_block = declaration.get("block_height", chain_height)
    age_blocks = max(chain_height - decl_block, 0)

    mech_score = compute_mechanical_score(
        manifest_valid, endpoint_responsive, dns_verified, tls_valid, age_blocks,
    )

    # Reputation from attestations
    rep_score_val = None
    att_count = 0
    unique_att = 0
    if attestations:
        att_count = len(attestations)
        unique_att = len({a["sender_address"] for a in attestations})
        if att_count > 0:
            avg = sum(a["score"] for a in attestations) / att_count
            rep_score_val = avg

    rep_score = compute_reputation_score(rep_score_val, unique_att, tx_count)
    composite = compute_composite_score(mech_score, rep_score)

    return {
        "composite_score": composite,
        "reputation": {
            "score": rep_score,
            "attestation_count": att_count,
            "unique_attestors": unique_att,
            "transaction_count": tx_count,
        },
        "mechanical": {
            "manifest_valid": manifest_valid,
            "endpoint_responsive": endpoint_responsive,
            "dns_verified": dns_verified,
            "declaration_age_blocks": age_blocks,
            "tls_valid": tls_valid,
        },
    }
