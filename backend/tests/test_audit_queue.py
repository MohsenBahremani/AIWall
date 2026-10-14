# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Queued audit writes and logging.store=none."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine

from app.audit.writer import AuditEvent, AuditWriter
from app.main import create_app
from app.storage.database import init_db
from tests.conftest import write_test_prices


def _event(request_id: str) -> AuditEvent:
    return AuditEvent(
        request_id=request_id,
        provider="openai",
        model="gpt-4o-mini",
        decision="allow",
        reason="proxied",
        input_length=4,
        output_length=2,
        latency_ms=1.0,
    )


def test_log_proxy_event_copies_org(tmp_path: Path) -> None:
    from app.audit.helpers import log_proxy_event
    from app.config import AIWallConfig, LoggingConfig

    engine = create_engine(f"sqlite:///{(tmp_path / 'label.db').as_posix()}")
    init_db(engine)
    writer = AuditWriter(engine)
    config = AIWallConfig(logging=LoggingConfig(org="homelab"))
    log_proxy_event(
        writer,
        config,
        request_id="proxy-org",
        provider_name="openai",
        model="gpt-4o-mini",
        decision="allow",
        reason="proxied",
        input_length=4,
        output_length=2,
        latency_ms=1.0,
    )
    assert writer.list_recent(limit=1)[0].org == "homelab"


def test_queued_record_stores_org(tmp_path: Path) -> None:
    engine = create_engine(
        f"sqlite:///{(tmp_path / 'org.db').as_posix()}",
        connect_args={"check_same_thread": False},
    )
    init_db(engine)
    writer = AuditWriter(engine, queue_writes=True)
    writer.record(
        AuditEvent(
            request_id="org-1",
            provider="openai",
            model="gpt-4o-mini",
            decision="allow",
            reason="proxied",
            input_length=4,
            output_length=2,
            latency_ms=1.0,
            org="homelab",
        )
    )
    rows = writer.list_recent(limit=1)
    writer.close()
    assert rows[0].org == "homelab"


def test_queued_record_is_visible_on_read(tmp_path: Path) -> None:
    engine = create_engine(
        f"sqlite:///{(tmp_path / 'queue.db').as_posix()}",
        connect_args={"check_same_thread": False},
    )
    init_db(engine)
    writer = AuditWriter(engine, queue_writes=True)
    writer.record(_event("queued-1"))
    rows = writer.list_recent(limit=1)
    writer.close()
    assert len(rows) == 1
    assert rows[0].request_id == "queued-1"
    assert rows[0].decision == "allow"


def test_disabled_persistence_drops_events(tmp_path: Path) -> None:
    engine = create_engine(
        f"sqlite:///{(tmp_path / 'drop.db').as_posix()}",
        connect_args={"check_same_thread": False},
    )
    init_db(engine)
    writer = AuditWriter(engine, persist=False)
    writer.record(_event("dropped"))
    assert writer.list_recent(limit=5) == []


@pytest.mark.asyncio
async def test_store_none_proxies_without_an_audit_file(tmp_path: Path) -> None:
    config_path = tmp_path / "aiwall.yaml"
    config_path.write_text(
        """
server:
  host: 127.0.0.1
  port: 9090
providers:
  - name: openai
    type: openai-compatible
    base_url: https://api.openai.com/v1
    api_key_env: OPENAI_API_KEY
    models: ["gpt-*"]
policies: []
logging:
  store: none
  log_raw_prompts: false
""".strip(),
        encoding="utf-8",
    )
    write_test_prices(config_path)
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={
                    "id": "chat-1",
                    "choices": [{"message": {"role": "assistant", "content": "hello"}}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                },
            )
        )
    )
    app = create_app(config_path=config_path, http_client=http_client)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
        )

    assert response.status_code == 200
    assert app.state.audit_writer.list_recent(limit=5) == []
    assert list(tmp_path.glob("*.db")) == []
    await http_client.aclose()
