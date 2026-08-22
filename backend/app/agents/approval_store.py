# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Persist and decide pending agent-action approvals."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.engine import Engine

from app.agents.approval_models import (
    APPROVAL_APPROVED,
    APPROVAL_DENIED,
    APPROVAL_PENDING,
    APPROVAL_STATUSES,
    APPROVAL_TIMED_OUT,
    PendingApprovalRow,
)
from app.storage.database import session_factory


@dataclass(frozen=True)
class PendingApproval:
    id: int
    request_id: str
    status: str
    policy_id: str | None
    reason: str | None
    rule_ids: tuple[str, ...]
    summary: str
    provider: str
    model: str
    user_id: str | None
    created_at: datetime
    decided_at: datetime | None
    decided_by: str | None


class ApprovalError(ValueError):
    """Invalid approval state transition."""


def _parse_rule_ids(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ()
    return tuple(part for part in raw.split(",") if part)


def _to_dataclass(row: PendingApprovalRow) -> PendingApproval:
    return PendingApproval(
        id=row.id,
        request_id=row.request_id,
        status=row.status,
        policy_id=row.policy_id,
        reason=row.reason,
        rule_ids=_parse_rule_ids(row.rule_ids),
        summary=row.summary or "",
        provider=row.provider,
        model=row.model,
        user_id=row.user_id,
        created_at=row.created_at,
        decided_at=row.decided_at,
        decided_by=row.decided_by,
    )


class ApprovalStore:
    def __init__(self, engine: Engine):
        self._engine = engine
        self._session_factory = session_factory(engine)

    def create(
        self,
        *,
        request_id: str,
        policy_id: str | None,
        reason: str | None,
        rule_ids: tuple[str, ...] = (),
        summary: str,
        provider: str,
        model: str,
        user_id: str | None = None,
    ) -> PendingApproval:
        row = PendingApprovalRow(
            request_id=request_id,
            status=APPROVAL_PENDING,
            policy_id=policy_id,
            reason=reason,
            rule_ids=",".join(rule_ids) if rule_ids else None,
            summary=summary,
            provider=provider,
            model=model,
            user_id=user_id,
        )
        with self._session_factory() as session:
            session.add(row)
            session.commit()
            session.refresh(row)
            return _to_dataclass(row)

    def get(self, approval_id: int) -> PendingApproval | None:
        with self._session_factory() as session:
            row = session.get(PendingApprovalRow, approval_id)
            return _to_dataclass(row) if row is not None else None

    def list_pending(self, *, limit: int = 50) -> list[PendingApproval]:
        return self.list(status=APPROVAL_PENDING, limit=limit)

    def list(
        self,
        *,
        status: str | None = APPROVAL_PENDING,
        user_id: str | None = None,
        limit: int = 50,
    ) -> list[PendingApproval]:
        """List approvals, newest first. ``status=None`` returns all statuses."""
        if limit < 1:
            raise ValueError("limit must be >= 1")
        if status is not None and status not in APPROVAL_STATUSES:
            raise ValueError(f"Invalid approval status: {status}")
        with self._session_factory() as session:
            stmt = (
                select(PendingApprovalRow)
                .order_by(PendingApprovalRow.id.desc())
                .limit(limit)
            )
            if status is not None:
                stmt = stmt.where(PendingApprovalRow.status == status)
            if user_id is not None:
                stmt = stmt.where(PendingApprovalRow.user_id == user_id)
            return [_to_dataclass(row) for row in session.scalars(stmt).all()]

    def decide(
        self,
        approval_id: int,
        *,
        status: str,
        decided_by: str | None = None,
    ) -> PendingApproval:
        if status not in {APPROVAL_APPROVED, APPROVAL_DENIED, APPROVAL_TIMED_OUT}:
            raise ApprovalError(f"Invalid decision status: {status}")
        with self._session_factory() as session:
            row = session.get(PendingApprovalRow, approval_id)
            if row is None:
                raise ApprovalError(f"Approval {approval_id} not found")
            if row.status != APPROVAL_PENDING:
                raise ApprovalError(
                    f"Approval {approval_id} is already {row.status}"
                )
            row.status = status
            row.decided_at = datetime.now(UTC)
            row.decided_by = decided_by
            session.commit()
            session.refresh(row)
            return _to_dataclass(row)

    def approve(self, approval_id: int, *, decided_by: str | None = None) -> PendingApproval:
        return self.decide(approval_id, status=APPROVAL_APPROVED, decided_by=decided_by)

    def deny(self, approval_id: int, *, decided_by: str | None = None) -> PendingApproval:
        return self.decide(approval_id, status=APPROVAL_DENIED, decided_by=decided_by)

    def timeout(self, approval_id: int) -> PendingApproval:
        return self.decide(approval_id, status=APPROVAL_TIMED_OUT, decided_by="system")
