# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""HTTP API for listing and deciding pending approvals."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from app.agents.approval_models import APPROVAL_APPROVED, APPROVAL_DENIED
from app.agents.approval_store import ApprovalError, PendingApproval


def _approval_payload(item: PendingApproval) -> dict[str, object]:
    return {
        "id": item.id,
        "request_id": item.request_id,
        "status": item.status,
        "policy_id": item.policy_id,
        "reason": item.reason,
        "rule_ids": list(item.rule_ids),
        "summary": item.summary,
        "provider": item.provider,
        "model": item.model,
        "user_id": item.user_id,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "decided_at": item.decided_at.isoformat() if item.decided_at else None,
        "decided_by": item.decided_by,
    }


def create_approvals_router() -> APIRouter:
    router = APIRouter(prefix="/approvals", tags=["approvals"])

    @router.get("")
    async def list_approvals(
        request: Request,
        status: str | None = Query(default="pending"),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, object]:
        store = getattr(request.app.state, "approval_store", None)
        if store is None:
            raise HTTPException(status_code=503, detail="Approval store unavailable")
        if status == "pending" or status is None:
            items = store.list_pending(limit=limit)
        elif status == "all":
            items = store.list(status=None, limit=limit)
        elif status in {"approved", "denied", "timed_out"}:
            items = store.list(status=status, limit=limit)
        else:
            raise HTTPException(
                status_code=400,
                detail="status must be pending, approved, denied, timed_out, or all",
            )
        return {"approvals": [_approval_payload(item) for item in items]}

    @router.get("/{approval_id}")
    async def get_approval(request: Request, approval_id: int) -> dict[str, object]:
        store = getattr(request.app.state, "approval_store", None)
        if store is None:
            raise HTTPException(status_code=503, detail="Approval store unavailable")
        item = store.get(approval_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Approval not found")
        return _approval_payload(item)

    @router.post("/{approval_id}/approve")
    async def approve_approval(
        request: Request,
        approval_id: int,
        decided_by: str | None = Query(default=None),
    ) -> JSONResponse:
        return _decide(request, approval_id, APPROVAL_APPROVED, decided_by)

    @router.post("/{approval_id}/deny")
    async def deny_approval(
        request: Request,
        approval_id: int,
        decided_by: str | None = Query(default=None),
    ) -> JSONResponse:
        return _decide(request, approval_id, APPROVAL_DENIED, decided_by)

    def _decide(
        request: Request,
        approval_id: int,
        status: str,
        decided_by: str | None,
    ) -> JSONResponse:
        store = getattr(request.app.state, "approval_store", None)
        broker = getattr(request.app.state, "approval_broker", None)
        if store is None or broker is None:
            raise HTTPException(status_code=503, detail="Approval system unavailable")
        try:
            if status == APPROVAL_APPROVED:
                item = store.approve(approval_id, decided_by=decided_by)
            else:
                item = store.deny(approval_id, decided_by=decided_by)
        except ApprovalError as exc:
            message = str(exc)
            code = 404 if "not found" in message else 409
            raise HTTPException(status_code=code, detail=message) from exc

        broker.resolve(approval_id, status)
        return JSONResponse(content=_approval_payload(item))

    return router
