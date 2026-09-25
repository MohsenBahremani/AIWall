# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Rolling-window extraction-rate checker (Phase 6.14)."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine

from app.audit.reasons import is_valid_audit_reason
from app.audit.writer import AuditEvent, AuditWriter
from app.config import RateLimitConfig
from app.rates.window import (
    EXTRACTION_RATE_REASON,
    check_extraction_rate,
    window_start,
)
from app.storage.database import init_db


def _writer(tmp_path: Path) -> AuditWriter:
    engine = create_engine(f"sqlite:///{(tmp_path / 'audit.db').as_posix()}")
    init_db(engine)
    return AuditWriter(engine)


def _allow(
    writer: AuditWriter,
    *,
    request_id: str,
    user_id: str | None,
    when: datetime,
    tokens: int = 10,
) -> None:
    writer.write(
        AuditEvent(
            request_id=request_id,
            provider="openai",
            model="gpt-4o-mini",
            decision="allow",
            reason="proxied",
            input_length=20,
            output_length=10,
            latency_ms=1.0,
            user_id=user_id,
            total_tokens=tokens,
            timestamp=when,
        )
    )


def test_window_start_is_rolling_not_calendar() -> None:
    now = datetime(2026, 9, 25, 12, 5, 0, tzinfo=UTC)
    assert window_start(300, now) == datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)


def test_disabled_config_never_blocks(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    now = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)
    _allow(writer, request_id="a1", user_id="1", when=now - timedelta(seconds=10))
    result = check_extraction_rate(
        audit_writer=writer,
        config=RateLimitConfig(enabled=False, max_requests=1),
        user_id="1",
        now=now,
    )
    assert result.exceeded is False


def test_request_cap_blocks_inside_window(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    now = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)
    _allow(writer, request_id="a1", user_id="7", when=now - timedelta(seconds=30))
    _allow(writer, request_id="a2", user_id="7", when=now - timedelta(seconds=10))
    config = RateLimitConfig(enabled=True, window_seconds=300, max_requests=2)
    blocked = check_extraction_rate(
        audit_writer=writer,
        config=config,
        user_id="7",
        now=now,
    )
    assert blocked.exceeded is True
    assert blocked.result is not None
    assert blocked.result.reason == EXTRACTION_RATE_REASON
    assert is_valid_audit_reason(blocked.result.reason)


def test_events_outside_window_do_not_count(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    now = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)
    _allow(writer, request_id="old", user_id="7", when=now - timedelta(seconds=400))
    config = RateLimitConfig(enabled=True, window_seconds=300, max_requests=1)
    result = check_extraction_rate(
        audit_writer=writer,
        config=config,
        user_id="7",
        now=now,
    )
    assert result.exceeded is False


def test_token_cap_includes_projected_request(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    now = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)
    _allow(writer, request_id="a1", user_id="3", when=now - timedelta(seconds=5), tokens=80)
    config = RateLimitConfig(enabled=True, window_seconds=60, max_tokens=100)
    blocked = check_extraction_rate(
        audit_writer=writer,
        config=config,
        user_id="3",
        projected_tokens=30,
        now=now,
    )
    assert blocked.exceeded is True


def test_anonymous_scope_when_apply_without_profile(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    now = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)
    _allow(writer, request_id="g1", user_id=None, when=now - timedelta(seconds=5))
    _allow(writer, request_id="g2", user_id=None, when=now - timedelta(seconds=4))
    config = RateLimitConfig(
        enabled=True,
        window_seconds=60,
        max_requests=2,
        apply_without_profile=True,
    )
    blocked = check_extraction_rate(
        audit_writer=writer,
        config=config,
        user_id=None,
        now=now,
    )
    assert blocked.exceeded is True
