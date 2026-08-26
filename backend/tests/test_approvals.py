# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
import asyncio
import json

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.agents.approval_summary import summarize_agent_actions
from app.alerts import RecordingNotifier
from app.alerts.base import TRIGGER_APPROVAL_REQUIRED
from tests.conftest import write_test_config


def _critical_shell_payload() -> dict:
    return {
        "model": "gpt-4o-mini",
        "messages": [
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "call_root",
                        "type": "function",
                        "function": {
                            "name": "bash",
                            "arguments": '{"command":"rm -rf /"}',
                        },
                    }
                ],
            }
        ],
    }


GUARDRAILS_YAML = """
agent_guardrails:
  enabled: true
  approval_timeout_seconds: 30
  shell:
    warn_above: 40
    block_above: 70
    require_approval_above: 90
""".strip()


@pytest.mark.asyncio
async def test_approve_releases_held_request(
    tmp_path,
    monkeypatch,
    upstream_mock_handler,
) -> None:
    from app.main import create_app

    monkeypatch.setenv("OPENAI_API_KEY", "upstream-openai-key")
    config_path = write_test_config(
        tmp_path,
        policies_block="",
        extra_yaml=GUARDRAILS_YAML,
    )
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_mock_handler))
    app = create_app(config_path=config_path, http_client=http_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:

        async def hold() -> httpx.Response:
            return await client.post(
                "/v1/chat/completions",
                json=_critical_shell_payload(),
            )

        held = asyncio.create_task(hold())
        approval_id: int | None = None
        for _ in range(50):
            listed = await client.get("/approvals")
            assert listed.status_code == 200
            items = listed.json()["approvals"]
            if items:
                approval_id = int(items[0]["id"])
                break
            await asyncio.sleep(0.05)

        assert approval_id is not None
        decided = await client.post(f"/approvals/{approval_id}/approve?decided_by=tester")
        assert decided.status_code == 200
        assert decided.json()["status"] == "approved"

        response = await asyncio.wait_for(held, timeout=5.0)
        assert response.status_code == 200

    await http_client.aclose()


@pytest.mark.asyncio
async def test_deny_blocks_held_request(
    tmp_path,
    monkeypatch,
    upstream_mock_handler,
) -> None:
    from app.main import create_app

    monkeypatch.setenv("OPENAI_API_KEY", "upstream-openai-key")
    config_path = write_test_config(
        tmp_path,
        policies_block="",
        extra_yaml=GUARDRAILS_YAML,
    )
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_mock_handler))
    app = create_app(config_path=config_path, http_client=http_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        held = asyncio.create_task(
            client.post("/v1/chat/completions", json=_critical_shell_payload())
        )
        approval_id: int | None = None
        for _ in range(50):
            listed = await client.get("/approvals")
            items = listed.json()["approvals"]
            if items:
                approval_id = int(items[0]["id"])
                break
            await asyncio.sleep(0.05)

        assert approval_id is not None
        denied = await client.post(f"/approvals/{approval_id}/deny?decided_by=tester")
        assert denied.status_code == 200
        assert denied.json()["status"] == "denied"

        response = await asyncio.wait_for(held, timeout=5.0)
        assert response.status_code == 403
        body = response.json()["error"]
        assert body["code"] == "approval_required"
        assert body["reason"] == "approval-denied"
        assert body["approval_id"] == approval_id
        assert response.headers.get("x-aiwall-approval-id") == str(approval_id)

    await http_client.aclose()


@pytest.mark.asyncio
async def test_approval_timeout_blocks_request(
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
agent_guardrails:
  enabled: true
  approval_timeout_seconds: 1
  shell:
    warn_above: 40
    block_above: 70
    require_approval_above: 90
""".strip(),
    )
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_mock_handler))
    app = create_app(config_path=config_path, http_client=http_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/chat/completions",
            json=_critical_shell_payload(),
            timeout=5.0,
        )
        assert response.status_code == 403
        body = response.json()["error"]
        assert body["code"] == "approval_required"
        assert body["reason"] == "approval-timeout"
        assert "approval_id" in body

        detail = await client.get(f"/approvals/{body['approval_id']}")
        assert detail.status_code == 200
        assert detail.json()["status"] == "timed_out"

    await http_client.aclose()


@pytest.mark.asyncio
async def test_approval_required_emits_alert(
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
agent_guardrails:
  enabled: true
  approval_timeout_seconds: 1
  shell:
    warn_above: 40
    block_above: 70
    require_approval_above: 90
alerts:
  - channel: stub
    on: [approval_required]
""".strip(),
    )
    recorder = RecordingNotifier()
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_mock_handler))
    app = create_app(
        config_path=config_path,
        http_client=http_client,
        recording_notifier=recorder,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/chat/completions",
            json=_critical_shell_payload(),
            timeout=5.0,
        )
        assert response.status_code == 403

    assert any(event.trigger == TRIGGER_APPROVAL_REQUIRED for event in recorder.events)
    await http_client.aclose()


def test_summarize_agent_actions_includes_shell() -> None:
    body = json.dumps(_critical_shell_payload()).encode()
    summary = summarize_agent_actions(body)
    assert "rm -rf /" in summary


@pytest.mark.asyncio
async def test_list_approvals_history_status(
    tmp_path,
    monkeypatch,
    upstream_mock_handler,
) -> None:
    from app.main import create_app

    monkeypatch.setenv("OPENAI_API_KEY", "upstream-openai-key")
    config_path = write_test_config(tmp_path, policies_block="", extra_yaml=GUARDRAILS_YAML)
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_mock_handler))
    app = create_app(config_path=config_path, http_client=http_client)
    created = app.state.approval_store.create(
        request_id="hist-1",
        policy_id="agent-shell",
        reason="require_approval",
        summary="held",
        provider="openai",
        model="gpt-4o-mini",
    )
    app.state.approval_store.approve(created.id, decided_by="tester")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        pending = await client.get("/approvals?status=pending")
        assert pending.json()["approvals"] == []
        history = await client.get("/approvals?status=approved")
        ids = [row["id"] for row in history.json()["approvals"]]
        assert created.id in ids
    await http_client.aclose()


@pytest.mark.asyncio
async def test_approve_requires_gateway_auth_when_enabled(tmp_path, monkeypatch) -> None:
    from app.main import create_app

    monkeypatch.setenv("AIWALL_API_KEY", "aiwall-secret")
    config_path = write_test_config(
        tmp_path,
        "",
        extra_yaml="""
gateway_auth:
  enabled: true
  api_key_env: AIWALL_API_KEY
""".strip(),
    )
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))
    )
    app = create_app(config_path=config_path, http_client=http_client)
    pending = app.state.approval_store.create(
        request_id="auth-1",
        policy_id="agent-shell",
        reason="require_approval",
        summary="held",
        provider="openai",
        model="gpt-4o-mini",
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        denied = await client.post(f"/approvals/{pending.id}/approve")
        assert denied.status_code == 401
        allowed = await client.post(
            f"/approvals/{pending.id}/approve",
            headers={"Authorization": "Bearer aiwall-secret"},
        )
        assert allowed.status_code == 200
    await http_client.aclose()
