# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine

from app.audit.writer import AuditEvent, AuditWriter
from app.profiles.limits import check_daily_limits, utc_day_start
from app.profiles.store import ProfileStore
from app.storage.database import init_db
from tests.conftest import write_test_config


def test_utc_day_start_resets_at_midnight() -> None:
    noon = datetime(2026, 7, 19, 12, 30, 0, tzinfo=UTC)
    assert utc_day_start(noon) == datetime(2026, 7, 19, 0, 0, 0, tzinfo=UTC)


def test_usage_for_user_aggregates_billable_events(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'audit.db').as_posix()}")
    init_db(engine)
    writer = AuditWriter(engine)
    since = utc_day_start()

    writer.write(
        AuditEvent(
            request_id="a1",
            provider="openai",
            model="gpt-4o-mini",
            decision="allow",
            reason="proxied",
            input_length=10,
            output_length=5,
            latency_ms=1.0,
            user_id="1",
            total_tokens=100,
            estimated_cost=0.01,
            timestamp=since + timedelta(hours=1),
        )
    )
    writer.write(
        AuditEvent(
            request_id="a2",
            provider="openai",
            model="gpt-4o-mini",
            decision="block",
            reason="proxied",
            input_length=10,
            output_length=0,
            latency_ms=1.0,
            user_id="1",
            total_tokens=50,
            estimated_cost=0.5,
            timestamp=since + timedelta(hours=2),
        )
    )
    writer.write(
        AuditEvent(
            request_id="a3",
            provider="openai",
            model="gpt-4o-mini",
            decision="allow",
            reason="proxied",
            input_length=10,
            output_length=5,
            latency_ms=1.0,
            user_id="1",
            total_tokens=40,
            estimated_cost=0.02,
            timestamp=since - timedelta(hours=1),
        )
    )

    usage = writer.usage_for_user(
        "1",
        since=since,
        decisions=frozenset({"allow", "warn", "redact"}),
    )
    assert usage.request_count == 1
    assert usage.total_tokens == 100
    assert usage.estimated_cost == pytest.approx(0.01)


def test_check_daily_limits_blocks_when_request_cap_reached(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'limits.db').as_posix()}")
    init_db(engine)
    store = ProfileStore(engine)
    writer = AuditWriter(engine)
    profile = store.create(name="Kid", role="child", daily_request_limit=1)
    since = utc_day_start()
    writer.write(
        AuditEvent(
            request_id="r1",
            provider="openai",
            model="gpt-4o-mini",
            decision="allow",
            reason="proxied",
            input_length=1,
            output_length=1,
            latency_ms=1.0,
            user_id=str(profile.id),
            timestamp=since + timedelta(minutes=5),
        )
    )

    blocked = check_daily_limits(
        profile_store=store,
        audit_writer=writer,
        profile_id=profile.id,
    )
    assert blocked.exceeded is True
    assert blocked.result is not None
    assert blocked.result.reason == "daily-limit"
    assert blocked.result.policy_id == "daily-limit"

    # Prior-day usage does not count toward today's cap.
    allowed = check_daily_limits(
        profile_store=store,
        audit_writer=writer,
        profile_id=profile.id,
        now=since + timedelta(days=1, hours=1),
    )
    assert allowed.exceeded is False


def test_check_daily_limits_blocks_token_and_cost_caps(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'caps.db').as_posix()}")
    init_db(engine)
    store = ProfileStore(engine)
    writer = AuditWriter(engine)
    profile = store.create(
        name="Budget",
        role="adult",
        daily_token_limit=100,
        daily_cost_limit=0.05,
    )
    since = utc_day_start()
    writer.write(
        AuditEvent(
            request_id="t1",
            provider="openai",
            model="gpt-4o-mini",
            decision="allow",
            reason="proxied",
            input_length=1,
            output_length=1,
            latency_ms=1.0,
            user_id=str(profile.id),
            total_tokens=90,
            estimated_cost=0.04,
            timestamp=since + timedelta(minutes=1),
        )
    )

    token_block = check_daily_limits(
        profile_store=store,
        audit_writer=writer,
        profile_id=profile.id,
        projected_tokens=20,
    )
    assert token_block.exceeded is True

    cost_block = check_daily_limits(
        profile_store=store,
        audit_writer=writer,
        profile_id=profile.id,
        projected_cost=0.02,
    )
    assert cost_block.exceeded is True

    under = check_daily_limits(
        profile_store=store,
        audit_writer=writer,
        profile_id=profile.id,
        projected_tokens=5,
        projected_cost=0.005,
    )
    assert under.exceeded is False


@pytest.mark.asyncio
async def test_proxy_blocks_when_daily_request_limit_reached(
    tmp_path,
    monkeypatch,
    upstream_mock_handler,
) -> None:
    from app.main import create_app

    monkeypatch.setenv("OPENAI_API_KEY", "upstream-openai-key")
    config_path = write_test_config(
        tmp_path,
        policies_block="",
        extra_yaml="""
gateway_auth:
  enabled: true
  api_key_env: AIWALL_API_KEY
""".strip(),
    )

    mock_transport = httpx.MockTransport(upstream_mock_handler)
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client)

    profile = app.state.profile_store.create(
        name="Limited",
        role="child",
        daily_request_limit=1,
    )
    key = app.state.profile_store.issue_api_key(profile.id)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        first = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hello"}],
            },
            headers={"Authorization": f"Bearer {key}"},
        )
        second = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hello again"}],
            },
            headers={"Authorization": f"Bearer {key}"},
        )

    assert first.status_code == 200
    assert second.status_code == 403
    body = second.json()["error"]
    assert body["reason"] == "daily-limit"
    assert body["policy"] == "daily-limit"
    await http_client.aclose()
