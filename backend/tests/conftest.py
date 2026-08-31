# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
import os
from pathlib import Path

os.environ.setdefault("AIWALL_SKIP_DOTENV", "1")
os.environ.setdefault("AIWALL_SKIP_APP_BOOT", "1")

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import create_app


@pytest.fixture(autouse=True)
def _skip_repo_dotenv(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the developer's real .env out of unit tests."""
    monkeypatch.setenv("AIWALL_SKIP_DOTENV", "1")


def write_test_prices(config_path: Path) -> Path:
    prices_path = config_path.parent / "prices.yaml"
    prices_path.write_text(
        """
models:
  openai:
    gpt-4o-mini:
      input_per_million: 0.15
      output_per_million: 0.60
""".strip()
    )
    return prices_path


def write_test_config(
    tmp_path: Path,
    policies_block: str = "",
    extra_yaml: str = "",
) -> Path:
    db_path = tmp_path / "aiwall.db"
    config_path = tmp_path / "aiwall.yaml"
    block = policies_block.strip("\n")
    if block.strip():
        policies_yaml = f"policies:\n{block}"
    else:
        policies_yaml = "policies: []"
    extra = extra_yaml.strip("\n")
    extra_section = f"\n{extra}" if extra else ""
    config_path.write_text(
        f"""
server:
  host: 127.0.0.1
  port: 9090
providers:
  - name: openai
    type: openai-compatible
    base_url: https://api.openai.com/v1
    api_key_env: OPENAI_API_KEY
    models: ["gpt-*"]
  - name: ollama
    type: ollama
    base_url: http://localhost:11434
    models: ["llama*"]
{policies_yaml}
logging:
  store: sqlite:///{db_path.as_posix()}
  log_raw_prompts: false{extra_section}
""".strip()
    )
    write_test_prices(config_path)
    return config_path


@pytest.fixture
def example_config(tmp_path: Path) -> Path:
    return write_test_config(
        tmp_path,
        """  - name: block-secrets
    when: input.contains_secret
    action: block""",
    )


@pytest.fixture
async def client(example_config: Path):
    mock_transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=example_config, http_client=http_client)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as test_client:
        yield test_client
    await http_client.aclose()


@pytest.fixture
def upstream_requests() -> list[httpx.Request]:
    return []


@pytest.fixture
def upstream_mock_handler(upstream_requests):
    import json

    def handler(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)

        if request.method == "GET" and request.url.path.endswith("/models"):
            return httpx.Response(
                200,
                json={
                    "object": "list",
                    "data": [{"id": "gpt-4o-mini", "object": "model"}],
                },
            )
        if request.method == "GET" and request.url.path.endswith("/api/tags"):
            return httpx.Response(
                200,
                json={"models": [{"name": "llama3.2:1b"}]},
            )

        body = json.loads(request.content.decode())
        if body.get("stream"):
            return httpx.Response(
                200,
                content=b'data: {"id":"stream-1","choices":[{"delta":{"content":"hi"}}]}\n\ndata: [DONE]\n\n',
                headers={"content-type": "text/event-stream"},
            )

        return httpx.Response(
            200,
            json={
                "id": "chat-1",
                "object": "chat.completion",
                "choices": [{"message": {"role": "assistant", "content": "hello"}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
            },
        )

    return handler


@pytest.fixture
async def proxy_app(example_config, upstream_mock_handler):
    mock_transport = httpx.MockTransport(upstream_mock_handler)
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=example_config, http_client=http_client)
    yield app
    await http_client.aclose()


@pytest.fixture
async def proxy_client(proxy_app):
    transport = ASGITransport(app=proxy_app)
    async with AsyncClient(transport=transport, base_url="http://test") as test_client:
        yield test_client


@pytest.fixture
async def proxy_client_no_provider(tmp_path):
    db_path = tmp_path / "empty.db"
    config_path = tmp_path / "aiwall.yaml"
    config_path.write_text(
        f"""
server:
  port: 8080
providers: []
policies: []
logging:
  store: sqlite:///{db_path.as_posix()}
""".strip()
    )
    mock_transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as test_client:
        yield test_client
    await http_client.aclose()
