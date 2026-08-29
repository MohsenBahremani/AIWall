# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import write_test_config


def _auth_config(tmp_path) -> str:
    return write_test_config(
        tmp_path,
        "",
        extra_yaml="""
gateway_auth:
  enabled: true
  api_key_env: AIWALL_API_KEY
""",
    )


@pytest.mark.asyncio
async def test_gateway_auth_rejects_missing_key(tmp_path, monkeypatch) -> None:
    from app.main import create_app

    monkeypatch.setenv("AIWALL_API_KEY", "aiwall-secret")
    config_path = _auth_config(tmp_path)
    mock_transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
        )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or missing AIWall API key"
    await http_client.aclose()


@pytest.mark.asyncio
async def test_gateway_auth_rejects_invalid_key(tmp_path, monkeypatch) -> None:
    from app.main import create_app

    monkeypatch.setenv("AIWALL_API_KEY", "aiwall-secret")
    config_path = _auth_config(tmp_path)
    mock_transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
            headers={"Authorization": "Bearer wrong-key"},
        )

    assert response.status_code == 401
    await http_client.aclose()


@pytest.mark.asyncio
async def test_gateway_auth_allows_valid_key_and_uses_upstream_key(
    tmp_path,
    monkeypatch,
    upstream_mock_handler,
) -> None:
    from app.main import create_app

    monkeypatch.setenv("AIWALL_API_KEY", "aiwall-secret")
    monkeypatch.setenv("OPENAI_API_KEY", "upstream-openai-key")
    config_path = _auth_config(tmp_path)

    upstream_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return upstream_mock_handler(request)

    mock_transport = httpx.MockTransport(handler)
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
            headers={"Authorization": "Bearer aiwall-secret"},
        )

    assert response.status_code == 200
    assert len(upstream_requests) == 1
    assert upstream_requests[0].headers["authorization"] == "Bearer upstream-openai-key"
    await http_client.aclose()


@pytest.mark.asyncio
async def test_models_requires_gateway_auth_when_enabled(tmp_path, monkeypatch) -> None:
    from app.main import create_app

    monkeypatch.setenv("AIWALL_API_KEY", "aiwall-secret")
    config_path = _auth_config(tmp_path)
    mock_transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        denied = await client.get("/v1/models")
        allowed = await client.get("/v1/models", headers={"Authorization": "Bearer aiwall-secret"})

    assert denied.status_code == 401
    assert allowed.status_code == 200
    await http_client.aclose()


@pytest.mark.asyncio
async def test_unauthenticated_caller_spends_owner_provider_key_when_gateway_auth_off(
    tmp_path,
    monkeypatch,
    upstream_mock_handler,
) -> None:
    from app.main import create_app

    monkeypatch.setenv("OPENAI_API_KEY", "owner-upstream-key")
    config_path = write_test_config(tmp_path, "")

    upstream_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return upstream_mock_handler(request)

    mock_transport = httpx.MockTransport(handler)
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
        )

    assert response.status_code == 200
    assert len(upstream_requests) == 1
    assert upstream_requests[0].headers["authorization"] == "Bearer owner-upstream-key"
    await http_client.aclose()
