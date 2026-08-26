# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine

from app.audit.writer import AuditEvent, AuditWriter
from app.storage.database import init_db
from tests.conftest import write_test_config

pytest.importorskip("jinja2")


def _writer(tmp_path: Path) -> AuditWriter:
    engine = create_engine(f"sqlite:///{(tmp_path / 'explorer.db').as_posix()}")
    init_db(engine)
    return AuditWriter(engine)


def _event(
    *,
    request_id: str,
    decision: str = "allow",
    provider: str = "openai",
    model: str = "gpt-4o-mini",
    user_id: str | None = None,
    policy_id: str | None = None,
    reason: str | None = "proxied",
    timestamp: datetime | None = None,
) -> AuditEvent:
    return AuditEvent(
        request_id=request_id,
        provider=provider,
        model=model,
        decision=decision,
        reason=reason,
        input_length=10,
        output_length=5,
        latency_ms=1.0,
        user_id=user_id,
        policy_id=policy_id,
        timestamp=timestamp or datetime.now(UTC),
    )


def test_search_events_filters_and_paginates(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    now = datetime(2026, 7, 26, 18, 0, tzinfo=UTC)

    writer.write(
        _event(
            request_id="1",
            decision="block",
            model="gpt-4o-mini",
            user_id="1",
            policy_id="block-secrets",
            reason="secret-detected",
            timestamp=now - timedelta(hours=1),
        )
    )
    writer.write(
        _event(
            request_id="2",
            decision="allow",
            provider="ollama",
            model="llama3.2",
            timestamp=now - timedelta(hours=2),
        )
    )
    writer.write(
        _event(
            request_id="3",
            decision="block",
            model="gpt-4o",
            user_id="2",
            policy_id="block-long-input",
            reason="length-threshold",
            timestamp=now - timedelta(hours=3),
        )
    )
    writer.write(
        _event(
            request_id="old",
            decision="block",
            timestamp=now - timedelta(hours=48),
            policy_id="block-secrets",
        )
    )

    blocked = writer.search_events(decision="block", since=now - timedelta(hours=24))
    assert blocked.total == 2
    assert {event.request_id for event in blocked.events} == {"1", "3"}

    by_model = writer.search_events(model="llama3.2")
    assert by_model.total == 1
    assert by_model.events[0].provider == "ollama"

    by_profile = writer.search_events(user_id="1")
    assert by_profile.total == 1
    assert by_profile.events[0].policy_id == "block-secrets"

    page1 = writer.search_events(limit=1, offset=0, since=now - timedelta(hours=24))
    page2 = writer.search_events(limit=1, offset=1, since=now - timedelta(hours=24))
    assert page1.total == 3
    assert page1.has_next is True
    assert page2.events[0].request_id != page1.events[0].request_id
    assert writer.list_models() == ["gpt-4o", "gpt-4o-mini", "llama3.2"]


@pytest.mark.asyncio
async def test_event_explorer_page_filters_and_detail(
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

    profile = app.state.profile_store.create(name="ExplorerKid", role="child")
    key = app.state.profile_store.issue_api_key(profile.id)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        blocked = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hello world this is long"}],
            },
            headers={"Authorization": f"Bearer {key}"},
        )
        assert blocked.status_code == 403

        page = await client.get("/events")
        filtered = await client.get(
            "/events",
            params={
                "decision": "block",
                "provider": "openai",
                "model": "gpt-4o-mini",
                "profile": str(profile.id),
                "window_hours": 24,
            },
        )
        partial = await client.get(
            "/partials/event-explorer",
            params={"decision": "block", "limit": 1, "offset": 0},
        )
        empty = await client.get("/events", params={"decision": "warn"})

        rows = app.state.audit_writer.list_recent(limit=1, decision="block")
        detail = await client.get(f"/partials/events/{rows[0].id}/detail")

    assert page.status_code == 200
    assert "Event log" in page.text
    assert "block-long-input" in page.text
    assert "ExplorerKid" in page.text

    assert filtered.status_code == 200
    assert "block-long-input" in filtered.text
    assert "secret-detected" not in filtered.text

    assert partial.status_code == 200
    assert "<html" not in partial.text.lower()
    assert "badge-block" in partial.text

    assert empty.status_code == 200
    assert "No events match" in empty.text

    assert detail.status_code == 200
    assert "block-long-input" in detail.text
    assert "Reason" in detail.text
    # Reasons are normalized; raw condition text never reaches the dashboard.
    assert "length-threshold" in detail.text
    assert "input.length" not in detail.text
    await http_client.aclose()
