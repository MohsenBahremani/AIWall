# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine

from app.audit.writer import AuditEvent, AuditWriter
from app.storage.database import init_db


def _make_writer(tmp_path) -> AuditWriter:
    db_path = tmp_path / "summary.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}", connect_args={"check_same_thread": False})
    init_db(engine)
    return AuditWriter(engine)


def _event(decision: str, cost: float | None, timestamp: datetime) -> AuditEvent:
    return AuditEvent(
        request_id=f"req-{decision}-{timestamp.timestamp()}",
        provider="openai",
        model="gpt-4o-mini",
        decision=decision,
        reason="proxied",
        input_length=10,
        output_length=20,
        latency_ms=5.0,
        estimated_cost=cost,
        timestamp=timestamp,
    )


def test_summary_counts_and_cost_within_window(tmp_path) -> None:
    writer = _make_writer(tmp_path)
    now = datetime.now(UTC)

    writer.write(_event("allow", 0.001, now))
    writer.write(_event("allow", 0.002, now))
    writer.write(_event("warn", 0.003, now))
    writer.write(_event("block", None, now))

    summary = writer.summary(window_hours=24)

    assert summary.total == 4
    assert summary.allow == 2
    assert summary.warn == 1
    assert summary.block == 1
    assert abs(summary.total_estimated_cost - 0.006) < 1e-9


def test_summary_excludes_events_outside_window(tmp_path) -> None:
    writer = _make_writer(tmp_path)
    now = datetime.now(UTC)

    writer.write(_event("allow", 0.005, now))
    writer.write(_event("allow", 0.005, now - timedelta(hours=48)))

    summary = writer.summary(window_hours=24)

    assert summary.total == 1
    assert summary.allow == 1
    assert abs(summary.total_estimated_cost - 0.005) < 1e-9


def test_list_recent_filters_by_decision_and_provider(tmp_path) -> None:
    writer = _make_writer(tmp_path)
    now = datetime.now(UTC)

    writer.write(_event("allow", 0.001, now))
    writer.write(_event("allow", 0.002, now))
    writer.write(
        AuditEvent(
            request_id="req-warn",
            provider="ollama",
            model="llama3.2:1b",
            decision="warn",
            reason="proxied",
            input_length=10,
            output_length=20,
            latency_ms=5.0,
            timestamp=now,
        )
    )

    assert len(writer.list_recent(decision="allow")) == 2
    assert len(writer.list_recent(decision="warn")) == 1
    assert len(writer.list_recent(provider="ollama")) == 1
    assert len(writer.list_recent(decision="allow", provider="openai")) == 2
    assert writer.list_providers() == ["ollama", "openai"]
