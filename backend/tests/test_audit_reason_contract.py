# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Audit reason contract — closed vocabulary enforced for SIEM consumers."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.audit.reasons import (
    AUDIT_REASON_PATTERNS,
    AUDIT_SCHEMA,
    EXACT_AUDIT_REASONS,
    assert_valid_audit_reason,
    is_valid_audit_reason,
)
from app.policies.engine import PolicyResult, _match_reason

DETECTIONS_CONTRACT = (
    Path(__file__).resolve().parents[3] / "AIWall-detections" / "validation" / "audit_reasons.json"
)
SAMPLE_JSONL = (
    Path(__file__).resolve().parents[3]
    / "AIWall-detections"
    / "validation"
    / "samples"
    / "aiwall.audit.v1.sample.jsonl"
)


def test_match_reason_never_emits_raw_condition_text() -> None:
    cases = [
        "input.contains_secret",
        "estimated_cost > 1.00",
        "input.length > 5000",
        "input.category == 'sexual'",
        "user.role == 'child'",
        "input.contains_private_key",
    ]
    for when in cases:
        reason = _match_reason(when)
        assert ">" not in reason
        assert "==" not in reason
        assert is_valid_audit_reason(reason)


@pytest.mark.parametrize(
    ("when", "expected"),
    [
        ("input.contains_secret", "secret-detected"),
        ("input.contains_private_key", "private-key-detected"),
        ("input.category == 'sexual'", "category-blocked"),
        ("estimated_cost > 1.00", "cost-threshold"),
        ("input.length > 5000", "length-threshold"),
        ("user.role == 'child'", "role-policy"),
        ("custom.flag == true", "policy-matched"),
    ],
)
def test_policy_match_reasons_are_contract_members(when: str, expected: str) -> None:
    assert _match_reason(when) == expected
    assert is_valid_audit_reason(expected)


def test_dynamic_guardrail_reasons_match_patterns() -> None:
    assert is_valid_audit_reason("shell risk 55 (medium)")
    assert is_valid_audit_reason("sensitive-file-access:ssh-private-key")
    assert not is_valid_audit_reason("estimated_cost > 1.00")


def test_guardrail_production_reasons_are_valid() -> None:
    from app.agents.guardrails import evaluate_shell_guardrails
    from app.config import AgentGuardrailsConfig, ShellGuardrailConfig

    config = AgentGuardrailsConfig(
        enabled=True,
        shell=ShellGuardrailConfig(
            warn_above=40,
            block_above=70,
            require_approval_above=90,
        ),
    )
    body = b'{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"bash","arguments":"{\\"command\\":\\"sudo rm -rf /\\"}"}}]}]}'
    warn = evaluate_shell_guardrails(body, config)
    assert warn is not None
    assert is_valid_audit_reason(warn.reason)

    block_body = b'{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"bash","arguments":"{\\"command\\":\\"rm -rf /\\"}"}}]}]}'
    block = evaluate_shell_guardrails(block_body, config)
    assert block is not None
    assert is_valid_audit_reason(block.reason)


def test_detections_contract_matches_core_module() -> None:
    if not DETECTIONS_CONTRACT.is_file():
        pytest.skip("AIWall-detections sibling repo not present")
    payload = json.loads(DETECTIONS_CONTRACT.read_text(encoding="utf-8"))
    assert payload["schema"] == AUDIT_SCHEMA
    assert frozenset(payload["exact"]) == EXACT_AUDIT_REASONS
    patterns = tuple(re.compile(item) for item in payload["patterns"])
    assert [p.pattern for p in patterns] == [p.pattern for p in AUDIT_REASON_PATTERNS]


def test_sample_corpus_reasons_obey_contract() -> None:
    if not SAMPLE_JSONL.is_file():
        pytest.skip("detection sample corpus not present")
    for line_no, line in enumerate(SAMPLE_JSONL.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        event = json.loads(line)
        reason = event.get("reason")
        assert is_valid_audit_reason(reason), f"line {line_no}: {reason!r}"


def test_assert_valid_audit_reason_raises_on_violation() -> None:
    with pytest.raises(ValueError, match="closed vocabulary"):
        assert_valid_audit_reason("estimated_cost > 99")


def test_budget_and_daily_limit_reasons() -> None:
    from app.budgets import BUDGET_REASON
    from app.profiles.limits import DAILY_LIMIT_REASON

    assert is_valid_audit_reason(BUDGET_REASON)
    assert is_valid_audit_reason(DAILY_LIMIT_REASON)


def test_proxy_block_reasons_from_policy_result() -> None:
    for reason in (
        "secret-detected",
        "cost-threshold",
        "approval-denied",
        "approval-timeout",
        "dangerous-shell-command",
    ):
        result = PolicyResult(action="block", policy_id="demo", reason=reason)
        assert is_valid_audit_reason(result.reason)
