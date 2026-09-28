# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Output DLP: scan model replies for secrets (SE-03)."""

from __future__ import annotations

import json

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import create_app
from app.scanners.secrets import extract_completion_text, scan_response_body
from tests.conftest import write_test_config
from tests.test_secret_scanner import _random_aws_key


def test_extract_completion_text_from_chat_json() -> None:
    body = json.dumps(
        {"choices": [{"message": {"role": "assistant", "content": "hello AKIA"}}]}
    ).encode()
    assert extract_completion_text(body) == "hello AKIA"


def test_extract_completion_text_from_sse() -> None:
    sse = (
        b'data: {"choices":[{"delta":{"content":"AKIA"}}]}\n\n'
        b'data: {"choices":[{"delta":{"content":"REST"}}]}\n\n'
        b"data: [DONE]\n\n"
    )
    assert extract_completion_text(sse) == "AKIAREST"


@pytest.mark.asyncio
async def test_secret_in_model_reply_is_blocked(tmp_path) -> None:
    aws_key = _random_aws_key()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "chat-1",
                "object": "chat.completion",
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": f"sure, the key is {aws_key}",
                        }
                    }
                ],
                "usage": {"prompt_tokens": 5, "completion_tokens": 8, "total_tokens": 13},
            },
        )

    config_path = write_test_config(
        tmp_path,
        """  - name: block-output-secrets
    when: output.contains_secret
    action: block""",
    )
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = create_app(config_path=config_path, http_client=http_client)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "say hello"}],
            },
        )

    assert response.status_code == 403
    error = response.json()["error"]
    assert error["policy"] == "block-output-secrets"
    assert error["reason"] == "output-secret-detected"
    assert error["rule_ids"] == ["aws-access-key"]
    assert aws_key not in response.text

    rows = app.state.audit_writer.list_recent(limit=1)
    assert rows[0].decision == "block"
    assert rows[0].reason == "output-secret-detected"
    assert rows[0].policy_id == "block-output-secrets"
    await http_client.aclose()


@pytest.mark.asyncio
async def test_output_secret_allowed_without_policy(tmp_path) -> None:
    aws_key = _random_aws_key()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"role": "assistant", "content": aws_key}}],
            },
        )

    config_path = write_test_config(tmp_path, policies_block="")
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = create_app(config_path=config_path, http_client=http_client)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "say hello"}],
            },
        )

    assert response.status_code == 200
    assert aws_key in response.text
    await http_client.aclose()


@pytest.mark.asyncio
async def test_output_secret_redacted(tmp_path) -> None:
    aws_key = _random_aws_key()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {"message": {"role": "assistant", "content": f"key {aws_key}"}}
                ],
            },
        )

    config_path = write_test_config(
        tmp_path,
        """  - name: redact-output-secrets
    when: output.contains_secret
    action: redact""",
    )
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = create_app(config_path=config_path, http_client=http_client)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "say hello"}],
            },
        )

    assert response.status_code == 200
    assert aws_key not in response.text
    assert "[REDACTED:aws-access-key]" in response.text
    rows = app.state.audit_writer.list_recent(limit=1)
    assert rows[0].decision == "redact"
    assert rows[0].reason == "output-secret-detected"
    await http_client.aclose()


@pytest.mark.asyncio
async def test_stream_output_secret_is_blocked(tmp_path) -> None:
    aws_key = _random_aws_key()
    sse = (
        f'data: {{"choices":[{{"delta":{{"content":"{aws_key}"}}}}]}}\n\n'
        "data: [DONE]\n\n"
    ).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=sse,
            headers={"content-type": "text/event-stream"},
        )

    config_path = write_test_config(
        tmp_path,
        """  - name: block-output-secrets
    when: output.contains_secret
    action: block""",
    )
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = create_app(config_path=config_path, http_client=http_client)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "stream": True,
                "messages": [{"role": "user", "content": "say hello"}],
            },
        )

    assert response.status_code == 403
    assert response.json()["error"]["reason"] == "output-secret-detected"
    assert aws_key not in response.text
    assert scan_response_body(sse).contains_secret is True
    await http_client.aclose()
