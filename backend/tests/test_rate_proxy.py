# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Proxy enforcement for extraction-rate (Phase 6.14)."""

from __future__ import annotations

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import write_test_config


@pytest.mark.asyncio
async def test_proxy_blocks_when_extraction_rate_exceeded(
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
rate_limits:
  enabled: true
  window_seconds: 300
  max_requests: 1
  apply_without_profile: true
""".strip(),
    )

    mock_transport = httpx.MockTransport(upstream_mock_handler)
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        first = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hello"}],
            },
        )
        second = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hello again"}],
            },
        )

    assert first.status_code == 200
    assert second.status_code == 403
    body = second.json()["error"]
    assert body["reason"] == "extraction-rate"
    assert body["policy"] == "extraction-rate"
    await http_client.aclose()
