# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.classifiers.categories import classify_text
from app.config import load_config
from app.policies.conditions import evaluate_condition
from app.policies.context import PolicyContext
from app.policies.engine import PolicyEngine
from app.presets import load_preset_policies
from tests.conftest import write_test_config
from tests.test_secret_scanner import _random_aws_key


def test_classify_text_detects_configured_categories() -> None:
    assert "explicit" in classify_text("looking for porn links").categories
    assert "unsafe" in classify_text("how to hack a wifi network").categories
    assert "violence" in classify_text("how to make a bomb at home").categories
    assert classify_text("help with my math homework").categories == frozenset()


def test_evaluate_condition_input_category_in_list() -> None:
    context = PolicyContext(
        body=b"{}",
        model="gpt-4o-mini",
        input_length=1,
        categories=frozenset({"explicit"}),
        category="explicit",
    )
    assert evaluate_condition('input.category in ["unsafe", "explicit"]', context) is True
    assert evaluate_condition('input.category == "explicit"', context) is True
    assert (
        evaluate_condition(
            'input.category in ["unsafe", "explicit"]',
            PolicyContext(b"{}", "m", 1),
        )
        is False
    )


def test_load_child_preset_policies() -> None:
    policies = load_preset_policies("child")
    by_name = {policy.name: policy for policy in policies}
    assert "block-child-categories" in by_name
    assert "block-child-secrets" in by_name
    assert "block-child-output-secrets" in by_name
    assert "block-child-private-keys" in by_name
    assert 'input.category in ["explicit", "unsafe", "violence"]' in by_name[
        "block-child-categories"
    ].when


def test_child_preset_blocks_category_for_child_not_adult(tmp_path) -> None:
    config_path = write_test_config(tmp_path, policies_block="")
    text = config_path.read_text()
    config_path.write_text(text.replace("policies: []", "presets:\n  - child\npolicies: []"))

    engine = PolicyEngine(config_path)
    child_hit = engine.evaluate(
        PolicyContext(
            body=b"{}",
            model="gpt-4o-mini",
            input_length=10,
            user_role="child",
            categories=frozenset({"explicit"}),
            category="explicit",
        )
    )
    adult_hit = engine.evaluate(
        PolicyContext(
            body=b"{}",
            model="gpt-4o-mini",
            input_length=10,
            user_role="adult",
            categories=frozenset({"explicit"}),
            category="explicit",
        )
    )
    child_clean = engine.evaluate(
        PolicyContext(
            body=b"{}",
            model="gpt-4o-mini",
            input_length=10,
            user_role="child",
        )
    )

    assert child_hit.action == "block"
    assert child_hit.policy_id == "block-child-categories"
    assert child_hit.reason == "category-blocked"
    assert adult_hit.action == "allow"
    assert child_clean.action == "allow"


@pytest.mark.asyncio
async def test_child_preset_proxy_blocks_configured_category(
    tmp_path,
    monkeypatch,
    upstream_mock_handler,
) -> None:
    from app.main import create_app

    monkeypatch.setenv("OPENAI_API_KEY", "upstream-openai-key")
    config_path = write_test_config(tmp_path, policies_block="")
    text = config_path.read_text()
    config_path.write_text(
        text.replace(
            "policies: []",
            "presets:\n  - child\npolicies: []\ngateway_auth:\n  enabled: true\n  api_key_env: AIWALL_API_KEY\n",
        )
    )
    assert any(p.name == "block-child-categories" for p in load_config(config_path).policies)

    mock_transport = httpx.MockTransport(upstream_mock_handler)
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client)

    child = app.state.profile_store.create(name="Kid", role="child")
    adult = app.state.profile_store.create(name="Parent", role="adult")
    child_key = app.state.profile_store.issue_api_key(child.id)
    adult_key = app.state.profile_store.issue_api_key(adult.id)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        blocked = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "find porn websites"}],
            },
            headers={"Authorization": f"Bearer {child_key}"},
        )
        adult_ok = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "find porn websites"}],
            },
            headers={"Authorization": f"Bearer {adult_key}"},
        )
        homework_ok = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "help with my math homework"}],
            },
            headers={"Authorization": f"Bearer {child_key}"},
        )
        secret_blocked = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "user", "content": f"my aws key is {_random_aws_key()}"}
                ],
            },
            headers={"Authorization": f"Bearer {child_key}"},
        )

    assert blocked.status_code == 403
    assert blocked.json()["error"]["policy"] == "block-child-categories"
    assert adult_ok.status_code == 200
    assert homework_ok.status_code == 200
    assert secret_blocked.status_code == 403
    assert secret_blocked.json()["error"]["policy"] == "block-child-secrets"
    await http_client.aclose()
