# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""OpenAI-compatible proxy routes."""

from __future__ import annotations

from fastapi import APIRouter, Request

from app.auth.gateway import (
    strip_client_authorization,
    validate_gateway_auth,
)
from app.proxy.chat import ChatCompletionProxy, _filter_forward_headers, _should_strip_client_auth
from app.proxy.models import list_models

router = APIRouter(prefix="/v1", tags=["openai-compatible"])


@router.get("/models")
async def models(request: Request) -> dict[str, object]:
    identity = validate_gateway_auth(
        request.app.state.config,
        request,
        getattr(request.app.state, "profile_store", None),
    )
    request.state.gateway_identity = identity
    incoming = _filter_forward_headers(request.headers)
    if _should_strip_client_auth(request.app.state.config, identity):
        incoming = strip_client_authorization(incoming)
    return await list_models(
        request.app.state.config,
        request.app.state.http_client,
        request.app.state.cost_estimator,
        incoming_headers=incoming,
    )


@router.post("/chat/completions")
async def chat_completions(request: Request):
    identity = validate_gateway_auth(
        request.app.state.config,
        request,
        getattr(request.app.state, "profile_store", None),
    )
    request.state.gateway_identity = identity
    proxy = ChatCompletionProxy(
        request.app.state.config,
        request.app.state.http_client,
        request.app.state.audit_writer,
        request.app.state.policy_engine,
        request.app.state.cost_estimator,
        getattr(request.app.state, "profile_store", None),
        getattr(request.app.state, "alert_dispatcher", None),
        getattr(request.app.state, "approval_store", None),
        getattr(request.app.state, "approval_broker", None),
        getattr(request.app.state, "secret_extra_rules", ()),
        getattr(request.app.state, "budget_checkers", ()),
    )
    return await proxy.forward(request)
