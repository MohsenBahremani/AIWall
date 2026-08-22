# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Policy evaluation engine with hot reload from aiwall.yaml."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.config import AIWallConfig, load_config
from app.policies.conditions import evaluate_condition
from app.policies.context import PolicyContext
from app.policies.overrides import policy_overrides_path
from app.presets.selection import preset_selection_path


@dataclass(frozen=True)
class PolicyResult:
    action: str
    policy_id: str | None = None
    reason: str | None = None
    rule_ids: tuple[str, ...] = ()


def _match_reason(when: str) -> str:
    expression = when.strip()
    if expression == "input.contains_secret":
        return "secret-detected"
    if expression == "input.contains_private_key":
        return "private-key-detected"
    if "input.category" in expression:
        return "category-blocked"
    if "user.role" in expression:
        return "role-policy"
    return when


class PolicyEngine:
    def __init__(self, config_path: Path):
        self._config_path = config_path
        self._cached_mtime: float | None = None
        self._cached_overrides_mtime: float | None = None
        self._cached_selection_mtime: float | None = None
        self._cached_config: AIWallConfig | None = None

    def invalidate(self) -> None:
        """Drop cached config so the next evaluate/reload reads from disk."""
        self._cached_mtime = None
        self._cached_overrides_mtime = None
        self._cached_selection_mtime = None
        self._cached_config = None

    def _source_mtimes(self) -> tuple[float | None, float | None, float | None]:
        config_mtime = (
            self._config_path.stat().st_mtime if self._config_path.exists() else None
        )
        overrides = policy_overrides_path(self._config_path)
        overrides_mtime = overrides.stat().st_mtime if overrides.exists() else None
        selection = preset_selection_path(self._config_path)
        selection_mtime = selection.stat().st_mtime if selection.exists() else None
        return config_mtime, overrides_mtime, selection_mtime

    def reload(self) -> AIWallConfig:
        if not self._config_path.exists():
            self._cached_mtime = None
            self._cached_overrides_mtime = None
            self._cached_selection_mtime = None
            self._cached_config = AIWallConfig()
            return self._cached_config

        config_mtime, overrides_mtime, selection_mtime = self._source_mtimes()
        if (
            self._cached_config is not None
            and self._cached_mtime == config_mtime
            and self._cached_overrides_mtime == overrides_mtime
            and self._cached_selection_mtime == selection_mtime
        ):
            return self._cached_config

        config = load_config(self._config_path)
        self._cached_mtime = config_mtime
        self._cached_overrides_mtime = overrides_mtime
        self._cached_selection_mtime = selection_mtime
        self._cached_config = config
        return config

    def evaluate(self, context: PolicyContext) -> PolicyResult:
        config = self.reload()
        block_match: PolicyResult | None = None
        redact_match: PolicyResult | None = None
        warn_match: PolicyResult | None = None

        for policy in config.policies:
            if not policy.enabled:
                continue
            try:
                matched = evaluate_condition(policy.when, context)
            except ValueError:
                continue

            if not matched:
                continue

            if policy.action == "block":
                block_match = PolicyResult(
                    action="block",
                    policy_id=policy.name,
                    reason=_match_reason(policy.when),
                )
                break
            if policy.action == "redact" and redact_match is None:
                redact_match = PolicyResult(
                    action="redact",
                    policy_id=policy.name,
                    reason=_match_reason(policy.when),
                )
            if policy.action == "warn" and warn_match is None:
                warn_match = PolicyResult(
                    action="warn",
                    policy_id=policy.name,
                    reason=_match_reason(policy.when),
                )

        if block_match is not None:
            return block_match
        if redact_match is not None:
            return redact_match
        if warn_match is not None:
            return warn_match
        return PolicyResult(action="allow", reason="policy_allow")
