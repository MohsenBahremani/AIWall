# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Extra secret-rule extension tests (Phase 8.6 community hook)."""

from __future__ import annotations

from pathlib import Path

from app.scanners.custom_rules import (
    custom_scanner_rules_path,
    load_custom_secret_rules,
    save_custom_rule_records,
    validate_custom_rule,
)
from app.scanners.registry import SecretRuleDef, SecretRuleRegistry
from app.scanners.secrets import SecretScanner


def test_extra_rules_detect_custom_secret() -> None:
    rule = SecretRuleDef(
        rule_id="acme-token",
        pattern=r"\b(acme_[A-Za-z0-9]{16,})\b",
        description="Acme token",
        source="custom",
    )
    scanner = SecretScanner(extra_rules=[rule])
    sample = "please use acme_abcdefghijklmnop"
    result = scanner.scan(sample)
    assert result.contains_secret is True
    assert any(m.rule_id == "acme-token" for m in result.matches)


def test_custom_rules_yaml_roundtrip(tmp_path: Path) -> None:
    config = tmp_path / "aiwall.yaml"
    config.write_text("server:\n  port: 1\n", encoding="utf-8")
    path = custom_scanner_rules_path(config)
    record = validate_custom_rule(
        rule_id="acme-token",
        pattern=r"\b(acme_[A-Za-z0-9]{16,})\b",
        description="Acme",
    )
    save_custom_rule_records(path, [record])
    loaded = load_custom_secret_rules(path)
    assert len(loaded) == 1
    assert loaded[0].rule_id == "acme-token"
    scanner = SecretScanner(extra_rules=loaded)
    assert scanner.scan("acme_abcdefghijklmnop").contains_secret is True


def test_secret_rule_registry_validates_regex() -> None:
    registry = SecretRuleRegistry()
    registry.register(
        SecretRuleDef(
            rule_id="ok-rule",
            pattern=r"\b(OK)\b",
            description="ok",
        )
    )
    assert registry.rules()[0].rule_id == "ok-rule"
