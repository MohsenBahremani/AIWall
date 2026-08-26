# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Tests for app.dotenv_loader and provider upstream auth preference."""

from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.config import ProviderConfig
from app.dotenv_loader import load_dotenv, reset_dotenv_cache_for_tests
from app.providers.adapters import build_upstream_headers
from tests.conftest import write_test_config


def test_load_dotenv_into_os_environ(tmp_path: Path, monkeypatch) -> None:
    reset_dotenv_cache_for_tests()
    env_file = tmp_path / ".env"
    env_file.write_text("CURSOR_API_KEY=crsr_from_file\nOPENAI_API_KEY=sk-from-file\n")
    monkeypatch.delenv("CURSOR_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    try:
        loaded = load_dotenv(env_file)
        assert loaded == env_file.resolve()
        assert os.environ["CURSOR_API_KEY"] == "crsr_from_file"
        assert os.environ["OPENAI_API_KEY"] == "sk-from-file"
    finally:
        os.environ.pop("CURSOR_API_KEY", None)
        os.environ.pop("OPENAI_API_KEY", None)


def test_load_dotenv_does_not_override_existing(tmp_path: Path, monkeypatch) -> None:
    reset_dotenv_cache_for_tests()
    env_file = tmp_path / ".env"
    env_file.write_text("OPENAI_API_KEY=from-file\n")
    monkeypatch.setenv("OPENAI_API_KEY", "from-shell")

    load_dotenv(env_file)
    assert os.environ["OPENAI_API_KEY"] == "from-shell"


def test_provider_api_key_env_wins_over_client_authorization(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-provider")
    provider = ProviderConfig(
        name="openai",
        type="openai-compatible",
        base_url="https://api.openai.com/v1",
        api_key_env="OPENAI_API_KEY",
        models=["gpt-*"],
    )
    headers = build_upstream_headers(
        provider,
        {"Authorization": "Bearer crsr_client_should_not_win"},
    )
    assert headers["Authorization"] == "Bearer sk-provider"


def test_client_authorization_used_when_api_key_env_missing(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = ProviderConfig(
        name="openai",
        type="openai-compatible",
        base_url="https://api.openai.com/v1",
        api_key_env="OPENAI_API_KEY",
        models=["gpt-*"],
    )
    headers = build_upstream_headers(
        provider,
        {"Authorization": "Bearer client-passthrough"},
    )
    assert headers["Authorization"] == "Bearer client-passthrough"


def test_client_authorization_used_when_no_api_key_env() -> None:
    provider = ProviderConfig(
        name="openai",
        type="openai-compatible",
        base_url="https://api.openai.com/v1",
        models=["gpt-*"],
    )
    headers = build_upstream_headers(
        provider,
        {"Authorization": "Bearer client-only"},
    )
    assert headers["Authorization"] == "Bearer client-only"


def test_client_authorization_wins_when_prefer_provider_key_false(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-provider")
    provider = ProviderConfig(
        name="openai",
        type="openai-compatible",
        base_url="https://api.openai.com/v1",
        api_key_env="OPENAI_API_KEY",
        models=["gpt-*"],
    )
    headers = build_upstream_headers(
        provider,
        {"Authorization": "Bearer client-passthrough"},
        prefer_provider_key=False,
    )
    assert headers["Authorization"] == "Bearer client-passthrough"


@pytest.mark.asyncio
async def test_models_list_honors_prefer_provider_key_false(tmp_path, monkeypatch) -> None:
    from app.main import create_app

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    config_path = write_test_config(
        tmp_path,
        "",
        extra_yaml="""
upstream_auth:
  prefer_provider_key: false
""".strip(),
    )

    upstream_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(
            200,
            json={"object": "list", "data": [{"id": "gpt-4o-mini", "object": "model"}]},
        )

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = create_app(config_path=config_path, http_client=http_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/v1/models",
            headers={"Authorization": "Bearer client-models-key"},
        )

    assert response.status_code == 200
    openai_requests = [r for r in upstream_requests if "openai.com" in str(r.url)]
    assert len(openai_requests) == 1
    assert openai_requests[0].headers["authorization"] == "Bearer client-models-key"
    await http_client.aclose()


@pytest.mark.asyncio
async def test_chat_proxy_honors_prefer_provider_key_false(tmp_path, monkeypatch) -> None:
    from app.main import create_app

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    config_path = write_test_config(
        tmp_path,
        "",
        extra_yaml="""
upstream_auth:
  prefer_provider_key: false
""".strip(),
    )

    upstream_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"total_tokens": 1},
            },
        )

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = create_app(config_path=config_path, http_client=http_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer client-chat-key"},
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hi"}],
            },
        )

    assert response.status_code == 200
    assert len(upstream_requests) == 1
    assert upstream_requests[0].headers["authorization"] == "Bearer client-chat-key"
    await http_client.aclose()
