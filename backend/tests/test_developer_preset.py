# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import load_config
from app.policies.conditions import evaluate_condition
from app.policies.context import PolicyContext
from app.policies.engine import PolicyEngine
from app.presets import load_preset_policies, resolve_preset_path
from tests.conftest import write_test_config
from tests.test_secret_scanner import _random_aws_key


def test_resolve_developer_preset() -> None:
    path = resolve_preset_path("developer")
    assert path.name == "developer.yaml"
    assert path.is_file()


def test_load_developer_preset_policies() -> None:
    policies = load_preset_policies("developer")
    by_name = {policy.name: policy for policy in policies}
    assert by_name["warn-secrets"].action == "warn"
    assert by_name["warn-secrets"].when == "input.contains_secret"
    assert by_name["block-output-secrets"].action == "block"
    assert by_name["block-output-secrets"].when == "output.contains_secret"
    assert by_name["block-private-keys"].action == "block"
    assert by_name["block-private-keys"].when == "input.contains_private_key"


def test_evaluate_condition_contains_private_key() -> None:
    context = PolicyContext(
        body=b"{}",
        model="gpt-4o-mini",
        input_length=1,
        contains_private_key=True,
    )
    assert evaluate_condition("input.contains_private_key", context) is True
    assert (
        evaluate_condition(
            "input.contains_private_key",
            PolicyContext(body=b"{}", model="gpt-4o-mini", input_length=1),
        )
        is False
    )


def test_load_config_merges_developer_preset(tmp_path: Path) -> None:
    config_path = write_test_config(tmp_path, policies_block="")
    text = config_path.read_text()
    config_path.write_text(text.replace("policies: []", "presets:\n  - developer\npolicies: []"))

    config = load_config(config_path)
    names = [policy.name for policy in config.policies]
    assert "warn-secrets" in names
    assert "block-private-keys" in names


def test_developer_preset_warns_on_secret(tmp_path: Path) -> None:
    config_path = write_test_config(tmp_path, policies_block="")
    text = config_path.read_text()
    config_path.write_text(text.replace("policies: []", "presets:\n  - developer\npolicies: []"))

    engine = PolicyEngine(config_path)
    result = engine.evaluate(
        PolicyContext(
            body=b"{}",
            model="gpt-4o-mini",
            input_length=10,
            contains_secret=True,
            contains_private_key=False,
        )
    )
    assert result.action == "warn"
    assert result.policy_id == "warn-secrets"
    assert result.reason == "secret-detected"


def test_developer_preset_blocks_private_keys(tmp_path: Path) -> None:
    config_path = write_test_config(tmp_path, policies_block="")
    text = config_path.read_text()
    config_path.write_text(text.replace("policies: []", "presets:\n  - developer\npolicies: []"))

    engine = PolicyEngine(config_path)
    result = engine.evaluate(
        PolicyContext(
            body=b"{}",
            model="gpt-4o-mini",
            input_length=10,
            contains_secret=True,
            contains_private_key=True,
        )
    )
    assert result.action == "block"
    assert result.policy_id == "block-private-keys"
    assert result.reason == "private-key-detected"


@pytest.mark.asyncio
async def test_developer_preset_proxy_warn_and_block(
    tmp_path, upstream_mock_handler, upstream_requests
) -> None:
    import httpx

    from app.main import create_app

    config_path = write_test_config(tmp_path, policies_block="")
    text = config_path.read_text()
    config_path.write_text(text.replace("policies: []", "presets:\n  - developer\npolicies: []"))

    mock_transport = httpx.MockTransport(upstream_mock_handler)
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        warn_response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": f"key {_random_aws_key()}"}],
            },
        )
        block_response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [
                    {
                        "role": "user",
                        "content": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc",
                    }
                ],
            },
        )

    assert warn_response.status_code == 200
    assert warn_response.headers.get("X-AIWall-Policy-Action") == "warn"
    assert block_response.status_code == 403
    assert block_response.json()["error"]["policy"] == "block-private-keys"
    assert block_response.json()["error"]["reason"] == "private-key-detected"

    rows = app.state.audit_writer.list_recent(limit=2)
    decisions = {row.decision for row in rows}
    assert "warn" in decisions
    assert "block" in decisions
    await http_client.aclose()
