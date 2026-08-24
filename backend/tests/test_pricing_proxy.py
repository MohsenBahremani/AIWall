# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import write_test_config, write_test_prices


@pytest.mark.asyncio
async def test_unknown_model_records_null_estimated_cost(tmp_path, upstream_mock_handler) -> None:
    import httpx

    from app.main import create_app

    config_path = write_test_config(tmp_path, "")
    write_test_prices(config_path)

    mock_transport = httpx.MockTransport(upstream_mock_handler)
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "llama3.2:1b",
                "messages": [{"role": "user", "content": "hello"}],
            },
        )

    assert response.status_code == 200
    rows = app.state.audit_writer.list_recent(limit=1)
    assert rows[0].model == "llama3.2:1b"
    assert rows[0].estimated_cost is None
    await http_client.aclose()


@pytest.mark.asyncio
async def test_cost_warn_policy_fires_from_request_estimate(
    tmp_path, upstream_mock_handler
) -> None:
    import httpx

    from app.main import create_app

    config_path = write_test_config(
        tmp_path,
        """  - name: warn-large-cost
    when: estimated_cost > 0.001
    action: warn""",
    )

    mock_transport = httpx.MockTransport(upstream_mock_handler)
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 100000,
            },
        )

    assert response.status_code == 200
    rows = app.state.audit_writer.list_recent(limit=1)
    assert rows[0].decision == "warn"
    assert rows[0].policy_id == "warn-large-cost"
    assert rows[0].reason == "cost-threshold"
    await http_client.aclose()


@pytest.mark.asyncio
async def test_cost_block_policy_emits_cost_threshold_reason(
    tmp_path, upstream_mock_handler
) -> None:
    import httpx

    from app.main import create_app

    config_path = write_test_config(
        tmp_path,
        """  - name: block-high-cost
    when: estimated_cost > 0.001
    action: block""",
    )

    mock_transport = httpx.MockTransport(upstream_mock_handler)
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 100000,
            },
        )
        export = await client.get("/events/export.jsonl?window_hours=1")

    assert response.status_code == 403
    payload = response.json()
    assert payload["error"]["reason"] == "cost-threshold"
    assert payload["error"]["policy"] == "block-high-cost"
    assert '"reason":"cost-threshold"' in export.text
    assert "estimated_cost >" not in export.text
    await http_client.aclose()


@pytest.mark.asyncio
async def test_streaming_records_tokens_and_cost(tmp_path, upstream_mock_handler) -> None:
    import httpx

    from app.main import create_app

    config_path = write_test_config(tmp_path, "")

    mock_transport = httpx.MockTransport(upstream_mock_handler)
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hello"}],
                "stream": True,
            },
        )

    assert response.status_code == 200
    assert b"data: [DONE]" in response.content
    rows = app.state.audit_writer.list_recent(limit=1)
    row = rows[0]
    assert row.prompt_tokens is not None
    assert row.completion_tokens is not None
    assert row.total_tokens == row.prompt_tokens + row.completion_tokens
    assert row.estimated_cost is not None
    await http_client.aclose()
