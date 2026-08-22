# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Extension types for plugin / custom secret detectors."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SecretRuleDef:
    """A regex secret detector that can be registered by plugins or custom UI."""

    rule_id: str
    pattern: str
    description: str
    default_min_length: int | None = None
    source: str = "extension"  # builtin | premium | custom

    def compile(self) -> re.Pattern[str]:
        return re.compile(self.pattern)


class SecretRuleRegistry:
    """Collects extra secret rules from plugins before the app finishes starting."""

    def __init__(self) -> None:
        self._rules: list[SecretRuleDef] = []

    def register(self, rule: SecretRuleDef) -> None:
        rule_id = rule.rule_id.strip()
        if not rule_id:
            raise ValueError("rule_id is required")
        # Validate regex early so bad plugins fail at load time.
        rule.compile()
        self._rules.append(
            SecretRuleDef(
                rule_id=rule_id,
                pattern=rule.pattern,
                description=rule.description,
                default_min_length=rule.default_min_length,
                source=rule.source,
            )
        )

    def register_many(self, rules: list[SecretRuleDef] | tuple[SecretRuleDef, ...]) -> None:
        for rule in rules:
            self.register(rule)

    def rules(self) -> tuple[SecretRuleDef, ...]:
        return tuple(self._rules)
