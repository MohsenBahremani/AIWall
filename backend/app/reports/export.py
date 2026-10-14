# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""CSV/JSON export of filtered audit events plus a summary."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

from app.audit.models import AuditEventRow
from app.audit.writer import AuditWriter

DEFAULT_EXPORT_LIMIT = 10_000

EXPORT_EVENT_FIELDS = (
    "id",
    "timestamp",
    "request_id",
    "user_id",
    "org",
    "provider",
    "model",
    "decision",
    "reason",
    "policy_id",
    "matched_rule_ids",
    "categories",
    "input_length",
    "output_length",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "estimated_cost",
    "redaction_count",
    "latency_ms",
)


@dataclass(frozen=True)
class ExportFilters:
    decision: str | None = None
    provider: str | None = None
    model: str | None = None
    profile: str | None = None
    window_hours: int = 24

    def query_params(self) -> dict[str, str]:
        params: dict[str, str] = {"window_hours": str(self.window_hours)}
        if self.decision:
            params["decision"] = self.decision
        if self.provider:
            params["provider"] = self.provider
        if self.model:
            params["model"] = self.model
        if self.profile:
            params["profile"] = self.profile
        return params

    def query_string(self) -> str:
        return urlencode(self.query_params())


@dataclass(frozen=True)
class ExportSummary:
    total: int = 0
    decision_counts: dict[str, int] = field(default_factory=dict)
    total_estimated_cost: float = 0.0
    total_tokens: int = 0
    exported_events: int = 0
    truncated: bool = False


@dataclass(frozen=True)
class EventExport:
    exported_at: datetime
    filters: ExportFilters
    summary: ExportSummary
    events: tuple[dict[str, Any], ...]


def row_to_export_dict(row: AuditEventRow) -> dict[str, Any]:
    timestamp = row.timestamp
    if timestamp is not None and timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return {
        "id": row.id,
        "timestamp": timestamp.isoformat() if timestamp else None,
        "request_id": row.request_id,
        "user_id": row.user_id,
        "org": row.org,
        "provider": row.provider,
        "model": row.model,
        "decision": row.decision,
        "reason": row.reason,
        "policy_id": row.policy_id,
        "matched_rule_ids": row.matched_rule_ids,
        "categories": row.categories,
        "input_length": row.input_length,
        "output_length": row.output_length,
        "prompt_tokens": row.prompt_tokens,
        "completion_tokens": row.completion_tokens,
        "total_tokens": row.total_tokens,
        "estimated_cost": row.estimated_cost,
        "redaction_count": row.redaction_count,
        "latency_ms": row.latency_ms,
    }


def build_event_export(
    audit_writer: AuditWriter,
    filters: ExportFilters,
    *,
    limit: int = DEFAULT_EXPORT_LIMIT,
    now: datetime | None = None,
) -> EventExport:
    if limit < 1:
        raise ValueError("limit must be >= 1")

    exported_at = now or datetime.now(UTC)
    since = None
    if filters.window_hours > 0:
        since = exported_at - timedelta(hours=filters.window_hours)

    page = audit_writer.search_events(
        limit=limit,
        offset=0,
        decision=filters.decision or None,
        provider=filters.provider or None,
        model=filters.model or None,
        user_id=filters.profile or None,
        since=since,
    )
    events = tuple(row_to_export_dict(row) for row in page.events)
    truncated = page.total > len(events)

    if truncated:
        agg = audit_writer.summarize_events(
            decision=filters.decision or None,
            provider=filters.provider or None,
            model=filters.model or None,
            user_id=filters.profile or None,
            since=since,
        )
        decision_counts = dict(agg.decision_counts)
        total_cost = agg.total_estimated_cost
        total_tokens = agg.total_tokens
        summary_total = agg.total
    else:
        decision_counts = {}
        total_cost = 0.0
        total_tokens = 0
        for event in events:
            decision = str(event.get("decision") or "unknown")
            decision_counts[decision] = decision_counts.get(decision, 0) + 1
            cost = event.get("estimated_cost")
            if isinstance(cost, (int, float)):
                total_cost += float(cost)
            tokens = event.get("total_tokens")
            if isinstance(tokens, int):
                total_tokens += tokens
        summary_total = page.total

    return EventExport(
        exported_at=exported_at,
        filters=filters,
        summary=ExportSummary(
            total=summary_total,
            decision_counts=decision_counts,
            total_estimated_cost=round(total_cost, 8),
            total_tokens=total_tokens,
            exported_events=len(events),
            truncated=truncated,
        ),
        events=events,
    )


def export_to_json(report: EventExport, *, indent: int = 2) -> str:
    payload = {
        "exported_at": report.exported_at.isoformat(),
        "filters": asdict(report.filters),
        "summary": asdict(report.summary),
        "events": list(report.events),
    }
    return json.dumps(payload, indent=indent, sort_keys=False) + "\n"


def export_to_csv(report: EventExport) -> str:
    """Two-section CSV: summary/filter key-value rows, blank line, then event table."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["section", "key", "value"])
    writer.writerow(["summary", "exported_at", report.exported_at.isoformat()])
    writer.writerow(["summary", "total", report.summary.total])
    writer.writerow(["summary", "exported_events", report.summary.exported_events])
    writer.writerow(["summary", "truncated", str(report.summary.truncated).lower()])
    writer.writerow(["summary", "total_estimated_cost", report.summary.total_estimated_cost])
    writer.writerow(["summary", "total_tokens", report.summary.total_tokens])
    for decision, count in sorted(report.summary.decision_counts.items()):
        writer.writerow(["summary", f"decision.{decision}", count])
    for key, value in report.filters.query_params().items():
        writer.writerow(["filter", key, value])
    writer.writerow([])
    writer.writerow(list(EXPORT_EVENT_FIELDS))
    for event in report.events:
        writer.writerow([event.get(field_name) for field_name in EXPORT_EVENT_FIELDS])
    return buffer.getvalue()
