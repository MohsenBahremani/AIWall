# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Plugin budget checkers consulted before proxying a request."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from app.policies.engine import PolicyResult

BUDGET_POLICY_ID = "cost-budget"
BUDGET_REASON = "cost-budget"


@dataclass(frozen=True, slots=True)
class BudgetCheckContext:
    profile_id: int | None
    user_id: str | None
    provider: str
    model: str
    projected_tokens: int
    projected_cost: float


@dataclass(frozen=True, slots=True)
class BudgetDecision:
    action: str  # warn | block
    policy_id: str = BUDGET_POLICY_ID
    reason: str = BUDGET_REASON
    message: str | None = None

    def as_policy_result(self) -> PolicyResult:
        return PolicyResult(
            action=self.action,
            policy_id=self.policy_id,
            reason=self.reason,
        )


@runtime_checkable
class BudgetChecker(Protocol):
    def check(self, context: BudgetCheckContext) -> BudgetDecision | None: ...


BudgetCheckerFactory = Callable[[], BudgetChecker]


class BudgetCheckerRegistry:
    def __init__(self) -> None:
        self._factories: list[BudgetCheckerFactory] = []

    def register(self, factory: BudgetCheckerFactory) -> None:
        self._factories.append(factory)

    def build(self) -> tuple[BudgetChecker, ...]:
        return tuple(factory() for factory in self._factories)


def run_budget_checkers(
    checkers: Sequence[BudgetChecker] | None,
    context: BudgetCheckContext,
) -> BudgetDecision | None:
    """Return the first blocking decision, else the first warn, else None."""
    if not checkers:
        return None
    warn: BudgetDecision | None = None
    for checker in checkers:
        try:
            decision = checker.check(context)
        except Exception:
            continue
        if decision is None:
            continue
        if decision.action == "block":
            return decision
        if decision.action == "warn" and warn is None:
            warn = decision
    return warn
