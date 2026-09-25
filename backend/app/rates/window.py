# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Rolling request/token window used to detect model-extraction floods."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.audit.writer import AuditWriter, ProfileUsage
from app.config import RateLimitConfig
from app.policies.engine import PolicyResult

BILLABLE_DECISIONS = frozenset({"allow", "warn", "redact"})

EXTRACTION_RATE_POLICY_ID = "extraction-rate"
EXTRACTION_RATE_REASON = "extraction-rate"


@dataclass(frozen=True)
class RateLimitCheck:
    exceeded: bool
    result: PolicyResult | None = None
    usage: ProfileUsage | None = None
    since: datetime | None = None


def window_start(
    window_seconds: int,
    now: datetime | None = None,
) -> datetime:
    """UTC start of the rolling window ending at ``now``."""
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    else:
        current = current.astimezone(UTC)
    seconds = max(1, int(window_seconds))
    return current - timedelta(seconds=seconds)


def check_extraction_rate(
    *,
    audit_writer: AuditWriter,
    config: RateLimitConfig,
    user_id: str | None,
    projected_tokens: int = 0,
    now: datetime | None = None,
) -> RateLimitCheck:
    """Block when billable volume in the rolling window exceeds a configured cap.

    Counts ``allow`` / ``warn`` / ``redact`` rows. Token caps include the
    projected tokens for the current request. When ``user_id`` is missing the
    cap applies to the whole gateway if ``apply_without_profile`` is true.
    """
    if not config.enabled:
        return RateLimitCheck(exceeded=False)
    if not _has_any_cap(config):
        return RateLimitCheck(exceeded=False)
    if user_id is None and not config.apply_without_profile:
        return RateLimitCheck(exceeded=False)

    since = window_start(config.window_seconds, now)
    usage = audit_writer.usage_for_scope(
        since=since,
        user_id=user_id,
        decisions=BILLABLE_DECISIONS,
    )

    if config.max_requests is not None and usage.request_count >= config.max_requests:
        return _block(usage, since)

    if config.max_tokens is not None and _exceeds_cap(
        usage.total_tokens,
        max(0, projected_tokens),
        config.max_tokens,
    ):
        return _block(usage, since)

    return RateLimitCheck(exceeded=False, usage=usage, since=since)


def _block(usage: ProfileUsage, since: datetime) -> RateLimitCheck:
    return RateLimitCheck(
        exceeded=True,
        result=PolicyResult(
            action="block",
            policy_id=EXTRACTION_RATE_POLICY_ID,
            reason=EXTRACTION_RATE_REASON,
        ),
        usage=usage,
        since=since,
    )


def _exceeds_cap(used: float, projected: float, limit: float) -> bool:
    if used >= limit:
        return True
    return projected > 0 and (used + projected) > limit


def _has_any_cap(config: RateLimitConfig) -> bool:
    return config.max_requests is not None or config.max_tokens is not None
