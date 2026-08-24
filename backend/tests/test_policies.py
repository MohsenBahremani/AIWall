# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
from app.config import load_config
from app.policies.conditions import evaluate_condition
from app.policies.context import PolicyContext
from app.policies.engine import PolicyEngine
from tests.conftest import write_test_config


def test_evaluate_condition_input_length() -> None:
    context = PolicyContext(body=b"{}", model="gpt-4o-mini", input_length=50)
    assert evaluate_condition("input.length > 10", context) is True
    assert evaluate_condition("input.length > 100", context) is False


def test_evaluate_condition_contains_secret() -> None:
    context = PolicyContext(body=b"{}", model="gpt-4o-mini", input_length=1, contains_secret=True)
    assert evaluate_condition("input.contains_secret", context) is True


def test_policy_engine_blocks_matching_policy(tmp_path) -> None:
    config_path = write_test_config(
        tmp_path,
        """  - name: block-long-input
    when: input.length > 5
    action: block""",
    )
    engine = PolicyEngine(config_path)
    result = engine.evaluate(
        PolicyContext(body=b"hello world", model="gpt-4o-mini", input_length=11)
    )
    assert result.action == "block"
    assert result.policy_id == "block-long-input"


def test_policy_engine_warns_without_blocking(tmp_path) -> None:
    config_path = write_test_config(
        tmp_path,
        """  - name: warn-long-input
    when: input.length > 5
    action: warn""",
    )
    engine = PolicyEngine(config_path)
    result = engine.evaluate(
        PolicyContext(body=b"hello world", model="gpt-4o-mini", input_length=11)
    )
    assert result.action == "warn"


def test_policy_engine_redacts_matching_policy(tmp_path) -> None:
    config_path = write_test_config(
        tmp_path,
        """  - name: redact-secrets
    when: input.contains_secret
    action: redact""",
    )
    engine = PolicyEngine(config_path)
    result = engine.evaluate(
        PolicyContext(
            body=b"{}",
            model="gpt-4o-mini",
            input_length=1,
            contains_secret=True,
        )
    )
    assert result.action == "redact"
    assert result.policy_id == "redact-secrets"
    assert result.reason == "secret-detected"


def test_policy_engine_block_beats_redact(tmp_path) -> None:
    config_path = write_test_config(
        tmp_path,
        """  - name: redact-secrets
    when: input.contains_secret
    action: redact
  - name: block-secrets
    when: input.contains_secret
    action: block""",
    )
    engine = PolicyEngine(config_path)
    result = engine.evaluate(
        PolicyContext(
            body=b"{}",
            model="gpt-4o-mini",
            input_length=1,
            contains_secret=True,
        )
    )
    assert result.action == "block"
    assert result.policy_id == "block-secrets"


def test_policy_engine_cost_policy_reason_is_stable(tmp_path) -> None:
    config_path = write_test_config(
        tmp_path,
        """  - name: block-high-cost
    when: estimated_cost > 1.00
    action: block""",
    )
    engine = PolicyEngine(config_path)
    result = engine.evaluate(
        PolicyContext(
            body=b"{}",
            model="gpt-4o",
            input_length=9000,
            estimated_cost=1.25,
        )
    )
    assert result.action == "block"
    assert result.policy_id == "block-high-cost"
    assert result.reason == "cost-threshold"


def test_policy_engine_length_policy_reason_is_stable(tmp_path) -> None:
    config_path = write_test_config(
        tmp_path,
        """  - name: warn-long-input
    when: input.length > 5
    action: warn""",
    )
    engine = PolicyEngine(config_path)
    result = engine.evaluate(
        PolicyContext(body=b"hello world", model="gpt-4o-mini", input_length=11)
    )
    assert result.reason == "length-threshold"


def test_policy_engine_never_leaks_raw_condition_text(tmp_path) -> None:
    """Audit reasons are a closed vocabulary; SIEM rules match on them."""
    config_path = write_test_config(
        tmp_path,
        """  - name: block-costly-child
    when: user.role == "child" and estimated_cost > 0.50
    action: block""",
    )
    engine = PolicyEngine(config_path)
    result = engine.evaluate(
        PolicyContext(
            body=b"{}",
            model="gpt-4o",
            input_length=10,
            estimated_cost=0.75,
            user_role="child",
        )
    )
    assert result.action == "block"
    assert result.reason == "cost-threshold"
    assert "estimated_cost" not in (result.reason or "")


def test_policy_engine_hot_reload(tmp_path) -> None:
    config_path = write_test_config(tmp_path, "")
    engine = PolicyEngine(config_path)
    allow_context = PolicyContext(body=b"hi", model="gpt-4o-mini", input_length=2)
    assert engine.evaluate(allow_context).action == "allow"

    config_path.write_text(
        write_test_config(
            tmp_path,
            """  - name: block-any-input
    when: input.length > 1
    action: block""",
        ).read_text()
    )
    assert engine.evaluate(allow_context).action == "block"


def test_policy_engine_caches_config_until_mtime_changes(tmp_path, monkeypatch) -> None:
    config_path = write_test_config(
        tmp_path,
        """  - name: block-long-input
    when: input.length > 5
    action: block""",
    )
    engine = PolicyEngine(config_path)
    context = PolicyContext(body=b"hello world", model="gpt-4o-mini", input_length=11)
    load_calls = {"count": 0}
    original_load_config = load_config

    def counting_load_config(path):
        load_calls["count"] += 1
        return original_load_config(path)

    monkeypatch.setattr("app.policies.engine.load_config", counting_load_config)

    assert engine.evaluate(context).action == "block"
    assert engine.evaluate(context).action == "block"
    assert load_calls["count"] == 1

    config_path.write_text(config_path.read_text() + "\n")
    assert engine.evaluate(context).action == "block"
    assert load_calls["count"] == 2
