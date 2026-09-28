# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Helpers for building audit events from proxy traffic."""

from __future__ import annotations

import json
import time
import uuid
from contextlib import contextmanager

from app.agents.extract import extract_agent_actions_from_body
from app.audit.writer import AuditEvent, AuditWriter
from app.config import AIWallConfig, ScannerConfig
from app.scanners.secrets import redact_request_body, redact_response_body


def new_request_id() -> str:
    return str(uuid.uuid4())


def measure_input_length(body: bytes) -> int:
    if not body:
        return 0
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return len(body)

    messages = payload.get("messages")
    if not isinstance(messages, list):
        return len(body)

    total = 0
    for message in messages:
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str):
            total += len(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    total += len(part["text"])
    return total or len(body)


def extract_prompt_text(body: bytes) -> str | None:
    if not body:
        return None
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return None

    messages = payload.get("messages")
    if not isinstance(messages, list):
        return None

    parts: list[str] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str):
            parts.append(content)
    return "\n".join(parts) if parts else None


def privacy_safe_prompt_text(
    body: bytes | None,
    scanner_config: ScannerConfig | None = None,
) -> str | None:
    """Extract prompt text with any detected secrets already masked."""
    if not body:
        return None
    redacted = redact_request_body(body, scanner_config)
    return extract_prompt_text(redacted.body)


@contextmanager
def request_timer():
    start = time.perf_counter()
    yield lambda: (time.perf_counter() - start) * 1000.0


def log_proxy_event(
    audit_writer: AuditWriter,
    config: AIWallConfig,
    *,
    request_id: str,
    provider_name: str,
    model: str,
    decision: str,
    reason: str | None,
    input_length: int,
    output_length: int,
    latency_ms: float,
    body: bytes | None = None,
    response_text: str | None = None,
    policy_id: str | None = None,
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
    total_tokens: int | None = None,
    estimated_cost: float | None = None,
    redaction_count: int = 0,
    rule_ids: tuple[str, ...] = (),
    user_id: str | None = None,
    categories: frozenset[str] | tuple[str, ...] = (),
) -> None:
    raw_prompt = None
    if config.logging.log_raw_prompts and body:
        # Always mask secrets before persisting — never store raw credential values.
        raw_prompt = privacy_safe_prompt_text(body, config.scanners)

    raw_response = None
    if config.logging.log_raw_prompts and response_text:
        redacted = redact_response_body(
            response_text.encode("utf-8"),
            config.scanners,
        )
        raw_response = redacted.body.decode("utf-8", errors="replace")
    matched_rule_ids = ",".join(rule_ids) if rule_ids else None
    categories_value = ",".join(sorted(categories)) if categories else None

    audit_row = audit_writer.write(
        AuditEvent(
            request_id=request_id,
            user_id=user_id,
            provider=provider_name,
            model=model,
            decision=decision,
            reason=reason,
            input_length=input_length,
            output_length=output_length,
            latency_ms=latency_ms,
            policy_id=policy_id,
            matched_rule_ids=matched_rule_ids,
            categories=categories_value,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            estimated_cost=estimated_cost,
            redaction_count=redaction_count,
            raw_prompt=raw_prompt,
            raw_response=raw_response,
        )
    )
    agent_actions = extract_agent_actions_from_body(body)
    if agent_actions:
        audit_writer.write_agent_actions(
            request_id=request_id,
            audit_event_id=audit_row.id,
            actions=agent_actions,
        )
