# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Stable NDJSON (JSON Lines) audit export for SIEM / detections (Phase 6.1)."""

from __future__ import annotations

import json
from typing import Any

from app.audit.models import AuditEventRow
from app.reports.export import EventExport, row_to_export_dict

# Frozen schema id — bump only with a documented breaking change.
AUDIT_SCHEMA_ID = "aiwall.audit.v1"


def _split_csv_field(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def row_to_audit_v1(row: AuditEventRow) -> dict[str, Any]:
    """Map an audit row to the frozen ``aiwall.audit.v1`` event object.

    Omits ``raw_prompt`` / ``raw_response``. Rule ids and categories are lists.
    """
    base = row_to_export_dict(row)
    return {
        "schema": AUDIT_SCHEMA_ID,
        "id": base["id"],
        "timestamp": base["timestamp"],
        "request_id": base["request_id"],
        "user_id": base["user_id"],
        "provider": base["provider"],
        "model": base["model"],
        "decision": base["decision"],
        "reason": base["reason"],
        "policy_id": base["policy_id"],
        "matched_rule_ids": _split_csv_field(base.get("matched_rule_ids")),
        "categories": _split_csv_field(base.get("categories")),
        "input_length": base["input_length"],
        "output_length": base["output_length"],
        "prompt_tokens": base["prompt_tokens"],
        "completion_tokens": base["completion_tokens"],
        "total_tokens": base["total_tokens"],
        "estimated_cost": base["estimated_cost"],
        "redaction_count": base["redaction_count"],
        "latency_ms": base["latency_ms"],
    }


def event_dict_to_audit_v1(event: dict[str, Any]) -> dict[str, Any]:
    """Normalize a dashboard export event dict into ``aiwall.audit.v1``."""
    rule_ids = event.get("matched_rule_ids")
    if isinstance(rule_ids, str):
        rule_ids = _split_csv_field(rule_ids)
    elif rule_ids is None:
        rule_ids = []
    else:
        rule_ids = list(rule_ids)

    categories = event.get("categories")
    if isinstance(categories, str):
        categories = _split_csv_field(categories)
    elif categories is None:
        categories = []
    else:
        categories = list(categories)

    return {
        "schema": AUDIT_SCHEMA_ID,
        "id": event.get("id"),
        "timestamp": event.get("timestamp"),
        "request_id": event.get("request_id"),
        "user_id": event.get("user_id"),
        "provider": event.get("provider"),
        "model": event.get("model"),
        "decision": event.get("decision"),
        "reason": event.get("reason"),
        "policy_id": event.get("policy_id"),
        "matched_rule_ids": rule_ids,
        "categories": categories,
        "input_length": event.get("input_length"),
        "output_length": event.get("output_length"),
        "prompt_tokens": event.get("prompt_tokens"),
        "completion_tokens": event.get("completion_tokens"),
        "total_tokens": event.get("total_tokens"),
        "estimated_cost": event.get("estimated_cost"),
        "redaction_count": event.get("redaction_count"),
        "latency_ms": event.get("latency_ms"),
    }


def export_to_jsonl(report: EventExport) -> str:
    """One ``aiwall.audit.v1`` JSON object per line (NDJSON)."""
    lines = [
        json.dumps(event_dict_to_audit_v1(event), sort_keys=False, separators=(",", ":"))
        for event in report.events
    ]
    if not lines:
        return ""
    return "\n".join(lines) + "\n"
