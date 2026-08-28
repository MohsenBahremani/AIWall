# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Closed audit ``reason`` vocabulary for SIEM and detection contracts."""

from __future__ import annotations

import re

AUDIT_SCHEMA = "aiwall.audit.v1"

EXACT_AUDIT_REASONS = frozenset(
    {
        "proxied",
        "secret-detected",
        "private-key-detected",
        "secret-redacted",
        "category-blocked",
        "cost-threshold",
        "cost-budget",
        "length-threshold",
        "role-policy",
        "daily-limit",
        "policy-matched",
        "policy_warn",
        "approval-denied",
        "approval-timeout",
        "dangerous-shell-command",
        "upstream_unreachable",
        "upstream_error",
    }
)

AUDIT_REASON_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^shell risk \d+ \([a-z]+\)$"),
    re.compile(r"^sensitive-file-access:[a-z0-9_-]+$"),
)


def is_valid_audit_reason(reason: str | None) -> bool:
    if reason is None:
        return True
    text = reason.strip()
    if not text:
        return True
    if text in EXACT_AUDIT_REASONS:
        return True
    return any(pattern.fullmatch(text) for pattern in AUDIT_REASON_PATTERNS)


def assert_valid_audit_reason(reason: str | None) -> None:
    if not is_valid_audit_reason(reason):
        raise ValueError(f"audit reason {reason!r} is not in the closed vocabulary")
