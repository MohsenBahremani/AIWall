# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Budget checker registry tests (Phase 8.9 community hook)."""

from __future__ import annotations

from app.budgets import (
    BudgetCheckContext,
    BudgetCheckerRegistry,
    BudgetDecision,
    run_budget_checkers,
)


class _StubChecker:
    def __init__(self, decision: BudgetDecision | None):
        self._decision = decision

    def check(self, context: BudgetCheckContext) -> BudgetDecision | None:
        return self._decision


def test_run_budget_checkers_prefers_block_over_warn() -> None:
    warn = BudgetDecision(action="warn")
    block = BudgetDecision(action="block")
    ctx = BudgetCheckContext(
        profile_id=1,
        user_id="1",
        provider="openai",
        model="gpt-4o-mini",
        projected_tokens=10,
        projected_cost=0.01,
    )
    decision = run_budget_checkers(
        [_StubChecker(warn), _StubChecker(block)],
        ctx,
    )
    assert decision is not None
    assert decision.action == "block"


def test_budget_checker_registry_build() -> None:
    registry = BudgetCheckerRegistry()
    registry.register(lambda: _StubChecker(BudgetDecision(action="warn")))
    checkers = registry.build()
    assert len(checkers) == 1
