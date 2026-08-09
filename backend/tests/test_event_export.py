# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
import csv
import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine

from app.audit.writer import AuditEvent, AuditWriter
from app.reports.audit_jsonl import AUDIT_SCHEMA_ID, export_to_jsonl
from app.reports.export import (
    ExportFilters,
    build_event_export,
    export_to_csv,
    export_to_json,
)
from app.storage.database import init_db
from tests.conftest import write_test_config

pytest.importorskip("jinja2")


def _writer(tmp_path: Path) -> AuditWriter:
    engine = create_engine(f"sqlite:///{(tmp_path / 'export.db').as_posix()}")
    init_db(engine)
    return AuditWriter(engine)


def _event(
    *,
    request_id: str,
    decision: str = "allow",
    provider: str = "openai",
    model: str = "gpt-4o-mini",
    estimated_cost: float | None = 0.01,
    total_tokens: int | None = 10,
    timestamp: datetime | None = None,
) -> AuditEvent:
    return AuditEvent(
        request_id=request_id,
        provider=provider,
        model=model,
        decision=decision,
        reason="proxied",
        input_length=10,
        output_length=5,
        latency_ms=1.0,
        estimated_cost=estimated_cost,
        total_tokens=total_tokens,
        timestamp=timestamp or datetime.now(UTC),
    )


def test_build_event_export_includes_summary_and_filters(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    now = datetime(2026, 8, 3, 15, 0, tzinfo=UTC)
    writer.write(
        _event(request_id="a", decision="block", estimated_cost=0.0, timestamp=now)
    )
    writer.write(
        _event(request_id="b", decision="allow", estimated_cost=0.02, timestamp=now)
    )
    writer.write(
        _event(
            request_id="old",
            decision="block",
            timestamp=now - timedelta(hours=48),
        )
    )

    report = build_event_export(
        writer,
        ExportFilters(decision="block", window_hours=24),
        now=now,
    )

    assert report.summary.total == 1
    assert report.summary.decision_counts == {"block": 1}
    assert report.summary.exported_events == 1
    assert report.summary.truncated is False
    assert report.events[0]["request_id"] == "a"
    assert "raw_prompt" not in report.events[0]

    payload = json.loads(export_to_json(report))
    assert payload["filters"]["decision"] == "block"
    assert payload["summary"]["total"] == 1
    assert len(payload["events"]) == 1

    csv_text = export_to_csv(report)
    assert "section,key,value" in csv_text
    assert "decision.block" in csv_text
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    assert rows[0] == ["section", "key", "value"]
    assert any(row[:2] == ["summary", "total"] and row[2] == "1" for row in rows)
    assert "request_id" in rows[-2] or "request_id" in rows[-1] or any(
        "request_id" in row for row in rows
    )


def test_build_event_export_truncated_uses_db_summary(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    now = datetime.now(UTC)
    for index in range(5):
        writer.write(
            _event(
                request_id=f"r{index}",
                decision="allow" if index % 2 == 0 else "block",
                timestamp=now,
            )
        )

    report = build_event_export(
        writer,
        ExportFilters(window_hours=24),
        limit=2,
        now=now,
    )
    assert report.summary.truncated is True
    assert report.summary.exported_events == 2
    assert report.summary.total == 5
    assert report.summary.decision_counts["allow"] == 3
    assert report.summary.decision_counts["block"] == 2


def test_export_to_jsonl_is_ndjson_audit_v1(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    now = datetime(2026, 8, 8, 12, 0, tzinfo=UTC)
    writer.write(
        AuditEvent(
            request_id="sec-1",
            provider="openai",
            model="gpt-4o-mini",
            decision="block",
            reason="secret-detected",
            input_length=40,
            output_length=0,
            latency_ms=2.0,
            policy_id="block-secrets",
            matched_rule_ids="aws-access-key,github-token",
            categories="secret",
            timestamp=now,
        )
    )
    writer.write(
        _event(request_id="ok-1", decision="allow", timestamp=now)
    )

    report = build_event_export(writer, ExportFilters(window_hours=24), now=now)
    text = export_to_jsonl(report)
    lines = [line for line in text.splitlines() if line.strip()]
    assert len(lines) == 2
    events = [json.loads(line) for line in lines]
    assert all(event["schema"] == AUDIT_SCHEMA_ID for event in events)
    blocked = next(event for event in events if event["request_id"] == "sec-1")
    assert blocked["matched_rule_ids"] == ["aws-access-key", "github-token"]
    assert blocked["categories"] == ["secret"]
    assert "raw_prompt" not in blocked
    allowed = next(event for event in events if event["request_id"] == "ok-1")
    assert allowed["matched_rule_ids"] == []


@pytest.mark.asyncio
async def test_events_export_endpoints_respect_filters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    upstream_mock_handler,
) -> None:
    from app.main import create_app

    monkeypatch.setenv("OPENAI_API_KEY", "upstream-openai-key")
    config_path = write_test_config(
        tmp_path,
        """  - name: block-long-input
    when: input.length > 5
    action: block""",
    )
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_mock_handler))
    app = create_app(config_path=config_path, http_client=http_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        blocked = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hello world this is long"}],
            },
        )
        allowed = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hi"}],
            },
        )
        assert blocked.status_code == 403
        assert allowed.status_code == 200

        page = await client.get("/events", params={"decision": "block"})
        json_resp = await client.get(
            "/events/export.json",
            params={"decision": "block", "window_hours": 24},
        )
        csv_resp = await client.get(
            "/events/export.csv",
            params={"decision": "block", "window_hours": 24},
        )
        jsonl_resp = await client.get(
            "/events/export.jsonl",
            params={"decision": "block", "window_hours": 24},
        )

    assert page.status_code == 200
    assert "/events/export.json?" in page.text
    assert "/events/export.csv?" in page.text

    assert json_resp.status_code == 200
    assert "attachment" in json_resp.headers.get("content-disposition", "")
    payload = json_resp.json()
    assert payload["filters"]["decision"] == "block"
    assert payload["summary"]["total"] == 1
    assert payload["summary"]["decision_counts"]["block"] == 1
    assert len(payload["events"]) == 1
    assert payload["events"][0]["decision"] == "block"
    assert "raw_prompt" not in payload["events"][0]

    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers.get("content-type", "")
    assert "attachment" in csv_resp.headers.get("content-disposition", "")
    assert "decision.block" in csv_resp.text
    assert "block-long-input" in csv_resp.text

    assert jsonl_resp.status_code == 200
    assert "ndjson" in jsonl_resp.headers.get("content-type", "")
    assert "attachment" in jsonl_resp.headers.get("content-disposition", "")
    jsonl_lines = [line for line in jsonl_resp.text.splitlines() if line.strip()]
    assert len(jsonl_lines) == 1
    event = json.loads(jsonl_lines[0])
    assert event["schema"] == AUDIT_SCHEMA_ID
    assert event["decision"] == "block"
    assert "raw_prompt" not in event

    await http_client.aclose()
