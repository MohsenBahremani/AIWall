# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Forward chat completion requests to upstream providers."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Mapping

import httpx
from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from app.agents.approval_broker import ApprovalBroker
from app.agents.approval_models import APPROVAL_APPROVED, APPROVAL_DENIED, APPROVAL_PENDING
from app.agents.approval_store import ApprovalStore
from app.agents.approval_summary import summarize_agent_actions
from app.agents.guardrails import evaluate_agent_guardrails, merge_policy_results
from app.alerts.base import TRIGGER_APPROVAL_REQUIRED, AlertEvent
from app.alerts.dispatcher import (
    AlertDispatcher,
    triggers_for_block,
    triggers_for_provider_error,
    triggers_for_warn,
)
from app.audit.helpers import log_proxy_event, measure_input_length, new_request_id
from app.audit.writer import AuditWriter
from app.auth.gateway import GatewayIdentity, gateway_auth_enabled, strip_client_authorization
from app.budgets import BudgetCheckContext, BudgetChecker, run_budget_checkers
from app.classifiers.categories import CategoryResult, classify_request_body
from app.config import AIWallConfig
from app.policies.context import PolicyContext
from app.policies.engine import PolicyEngine, PolicyResult
from app.policies.responses import policy_blocked_response, privacy_safe_headers
from app.presets import has_private_key_rule
from app.profiles.limits import check_daily_limits
from app.profiles.store import ProfileStore
from app.providers.adapters import build_chat_completions_url, build_upstream_headers
from app.providers.router import extract_model_from_body, select_provider
from app.proxy.tokens import (
    estimate_request_token_usage,
    extract_stream_token_usage,
    extract_token_usage,
)
from app.scanners.secrets import ScanResult, redact_request_body, scan_request_body

FORWARD_REQUEST_HEADERS = {
    "authorization",
    "content-type",
    "openai-organization",
    "openai-project",
}


def _request_is_streaming(body: bytes) -> bool:
    if not body:
        return False
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return False
    return bool(payload.get("stream"))


def _filter_forward_headers(headers: Mapping[str, str]) -> dict[str, str]:
    forwarded: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in FORWARD_REQUEST_HEADERS:
            forwarded[key] = value
    return forwarded


def _audit_decision(policy_result: PolicyResult, upstream_ok: bool = True) -> str:
    if policy_result.action == "redact" and upstream_ok:
        return "redact"
    if policy_result.action == "warn":
        return "warn"
    if not upstream_ok:
        return "error"
    return "allow"


def _audit_reason(policy_result: PolicyResult, upstream_reason: str | None = None) -> str:
    if policy_result.action == "redact":
        return policy_result.reason or "secret-redacted"
    if policy_result.action == "warn":
        return policy_result.reason or "policy_warn"
    return upstream_reason or "proxied"


def _policy_id_for_audit(policy_result: PolicyResult) -> str | None:
    if policy_result.action in {"warn", "redact", "block"}:
        return policy_result.policy_id
    return None


def _with_rule_ids(result: PolicyResult, scan_result: ScanResult) -> PolicyResult:
    if not scan_result.matches:
        return result
    rule_ids = tuple(match.rule_id for match in scan_result.matches)
    return PolicyResult(
        action=result.action,
        policy_id=result.policy_id,
        reason=result.reason,
        rule_ids=rule_ids,
    )


def _identity_from_request(request: Request) -> GatewayIdentity:
    identity = getattr(request.state, "gateway_identity", None)
    if isinstance(identity, GatewayIdentity):
        return identity
    return GatewayIdentity()


def _should_strip_client_auth(config: AIWallConfig, identity: GatewayIdentity) -> bool:
    # Strip AIWall keys so they never reach upstream providers.
    return gateway_auth_enabled(config) or identity.profile_id is not None


class ChatCompletionProxy:
    def __init__(
        self,
        config: AIWallConfig,
        http_client: httpx.AsyncClient,
        audit_writer: AuditWriter,
        policy_engine: PolicyEngine,
        cost_estimator,
        profile_store: ProfileStore | None = None,
        alert_dispatcher: AlertDispatcher | None = None,
        approval_store: ApprovalStore | None = None,
        approval_broker: ApprovalBroker | None = None,
        secret_extra_rules: tuple | list | None = None,
        budget_checkers: tuple[BudgetChecker, ...] | list[BudgetChecker] | None = None,
    ):
        self._config = config
        self._http_client = http_client
        self._audit_writer = audit_writer
        self._policy_engine = policy_engine
        self._cost_estimator = cost_estimator
        self._profile_store = profile_store
        self._alert_dispatcher = alert_dispatcher
        self._approval_store = approval_store
        self._approval_broker = approval_broker
        self._secret_extra_rules = secret_extra_rules or ()
        self._budget_checkers = tuple(budget_checkers or ())

    async def _emit_block_alerts(
        self,
        *,
        request_id: str,
        policy_result: PolicyResult,
    ) -> None:
        if self._alert_dispatcher is None or self._alert_dispatcher.channel_count == 0:
            return
        triggers = triggers_for_block(
            reason=policy_result.reason,
            policy_id=policy_result.policy_id,
            rule_ids=policy_result.rule_ids,
        )
        policy_name = policy_result.policy_id or "unknown"
        reason = policy_result.reason or "blocked"
        for trigger in triggers:
            await self._alert_dispatcher.dispatch(
                AlertEvent(
                    trigger=trigger,
                    title=f"AIWall {trigger.replace('_', ' ')}",
                    message=f"Policy {policy_name} blocked a request ({reason}).",
                    request_id=request_id,
                    policy_id=policy_result.policy_id,
                    reason=policy_result.reason,
                    rule_ids=policy_result.rule_ids,
                )
            )

    async def _emit_warn_alerts(
        self,
        *,
        request_id: str,
        policy_result: PolicyResult,
    ) -> None:
        if self._alert_dispatcher is None or self._alert_dispatcher.channel_count == 0:
            return
        triggers = triggers_for_warn(
            reason=policy_result.reason,
            policy_id=policy_result.policy_id,
        )
        policy_name = policy_result.policy_id or "unknown"
        reason = policy_result.reason or "warn"
        for trigger in triggers:
            await self._alert_dispatcher.dispatch(
                AlertEvent(
                    trigger=trigger,
                    title=f"AIWall {trigger.replace('_', ' ')}",
                    message=f"Policy {policy_name} warned on a request ({reason}).",
                    request_id=request_id,
                    policy_id=policy_result.policy_id,
                    reason=policy_result.reason,
                    rule_ids=policy_result.rule_ids,
                )
            )

    async def _emit_approval_alert(
        self,
        *,
        request_id: str,
        approval_id: int,
        policy_result: PolicyResult,
        summary: str,
    ) -> None:
        if self._alert_dispatcher is None or self._alert_dispatcher.channel_count == 0:
            return
        await self._alert_dispatcher.dispatch(
            AlertEvent(
                trigger=TRIGGER_APPROVAL_REQUIRED,
                title="AIWall approval required",
                message=(
                    f"Approval #{approval_id} pending: {summary} "
                    f"(policy {policy_result.policy_id or 'unknown'})."
                ),
                request_id=request_id,
                policy_id=policy_result.policy_id,
                reason=policy_result.reason,
                rule_ids=policy_result.rule_ids,
                metadata={"approval_id": str(approval_id)},
            )
        )

    async def _await_approval(
        self,
        *,
        request_id: str,
        policy_result: PolicyResult,
        provider_name: str,
        model: str,
        user_id: str | None,
        body: bytes,
        timeout_seconds: int,
    ) -> tuple[str, int]:
        """Create a pending approval, notify, and wait for a decision.

        Returns ``(decision, approval_id)`` where decision is approved/denied/timed_out.
        """
        if self._approval_store is None or self._approval_broker is None:
            return APPROVAL_DENIED, 0

        summary = summarize_agent_actions(body)
        pending = self._approval_store.create(
            request_id=request_id,
            policy_id=policy_result.policy_id,
            reason=policy_result.reason,
            rule_ids=policy_result.rule_ids,
            summary=summary,
            provider=provider_name,
            model=model,
            user_id=user_id,
        )
        await self._emit_approval_alert(
            request_id=request_id,
            approval_id=pending.id,
            policy_result=policy_result,
            summary=summary,
        )
        future = self._approval_broker.register(pending.id)
        # Approve/deny may race between create and register; honor store state.
        current = self._approval_store.get(pending.id)
        if current is not None and current.status != APPROVAL_PENDING:
            self._approval_broker.resolve(pending.id, current.status)
            return current.status, pending.id
        try:
            decision = await asyncio.wait_for(
                asyncio.shield(future),
                timeout=max(1, timeout_seconds),
            )
            return str(decision), pending.id
        except TimeoutError:
            self._approval_broker.discard(pending.id)
            try:
                self._approval_store.timeout(pending.id)
            except Exception:
                pass
            return "timed_out", pending.id
        except asyncio.CancelledError:
            self._approval_broker.discard(pending.id)
            raise

    async def _emit_provider_error_alerts(
        self,
        *,
        request_id: str,
        provider_name: str,
        model: str,
        reason: str,
        status_code: int | None = None,
    ) -> None:
        if self._alert_dispatcher is None or self._alert_dispatcher.channel_count == 0:
            return
        detail = reason
        if status_code is not None:
            detail = f"{reason} (HTTP {status_code})"
        for trigger in triggers_for_provider_error():
            await self._alert_dispatcher.dispatch(
                AlertEvent(
                    trigger=trigger,
                    title="AIWall provider error",
                    message=f"Provider {provider_name} failed for model {model}: {detail}.",
                    request_id=request_id,
                    reason=reason,
                    metadata={
                        "provider": provider_name,
                        "model": model,
                        **({"status_code": str(status_code)} if status_code is not None else {}),
                    },
                )
            )

    def _evaluate_policy(
        self,
        body: bytes,
        provider_name: str,
        model: str,
        input_length: int,
        *,
        user_role: str | None = None,
        user_id: str | None = None,
        category_result: CategoryResult | None = None,
    ) -> PolicyResult:
        scan_result = scan_request_body(
            body,
            self._config.scanners,
            extra_rules=self._secret_extra_rules,
        )
        if category_result is None:
            category_result = classify_request_body(body)
        projected_usage = estimate_request_token_usage(body)
        cost_estimate = self._cost_estimator.estimate(provider_name, model, projected_usage)
        rule_ids = tuple(match.rule_id for match in scan_result.matches)
        context = PolicyContext(
            body=body,
            model=model,
            input_length=input_length,
            contains_secret=scan_result.contains_secret,
            contains_private_key=has_private_key_rule(rule_ids),
            estimated_cost=cost_estimate.estimated_cost if cost_estimate else 0.0,
            user_role=user_role,
            user_id=user_id,
            categories=category_result.categories,
            category=category_result.primary,
        )
        result = self._policy_engine.evaluate(context)
        result = _with_rule_ids(result, scan_result)
        fresh_config = self._policy_engine.reload()
        agent_result = evaluate_agent_guardrails(
            body,
            fresh_config.agent_guardrails,
        )
        return merge_policy_results(result, agent_result)

    async def forward(self, request: Request) -> Response | StreamingResponse | JSONResponse:
        body = await request.body()
        model = extract_model_from_body(body)
        provider = select_provider(self._config, model)
        upstream_url = build_chat_completions_url(provider)
        identity = _identity_from_request(request)
        user_id = identity.user_id
        incoming_headers = _filter_forward_headers(request.headers)
        if _should_strip_client_auth(self._config, identity):
            incoming_headers = strip_client_authorization(incoming_headers)
        upstream_headers = build_upstream_headers(provider, incoming_headers)
        request_id = new_request_id()
        input_length = measure_input_length(body)
        started = time.perf_counter()
        category_result = classify_request_body(body)
        categories = category_result.categories
        policy_result = self._evaluate_policy(
            body,
            provider.name,
            model,
            input_length,
            user_role=identity.role,
            user_id=user_id,
            category_result=category_result,
        )

        if policy_result.action == "block":
            latency_ms = (time.perf_counter() - started) * 1000.0
            log_proxy_event(
                self._audit_writer,
                self._config,
                request_id=request_id,
                provider_name=provider.name,
                model=model,
                decision="block",
                reason=policy_result.reason,
                input_length=input_length,
                output_length=0,
                latency_ms=latency_ms,
                body=body,
                policy_id=policy_result.policy_id,
                rule_ids=policy_result.rule_ids,
                user_id=user_id,
                categories=categories,
            )
            await self._emit_block_alerts(
                request_id=request_id,
                policy_result=policy_result,
            )
            return policy_blocked_response(policy_result)

        if policy_result.action == "require_approval":
            fresh = self._policy_engine.reload()
            timeout_seconds = fresh.agent_guardrails.approval_timeout_seconds
            decision, approval_id = await self._await_approval(
                request_id=request_id,
                policy_result=policy_result,
                provider_name=provider.name,
                model=model,
                user_id=user_id,
                body=body,
                timeout_seconds=timeout_seconds,
            )
            if decision != APPROVAL_APPROVED:
                deny_reason = (
                    "approval-denied"
                    if decision == APPROVAL_DENIED
                    else "approval-timeout"
                )
                latency_ms = (time.perf_counter() - started) * 1000.0
                log_proxy_event(
                    self._audit_writer,
                    self._config,
                    request_id=request_id,
                    provider_name=provider.name,
                    model=model,
                    decision="block",
                    reason=deny_reason,
                    input_length=input_length,
                    output_length=0,
                    latency_ms=latency_ms,
                    body=body,
                    policy_id=policy_result.policy_id,
                    rule_ids=policy_result.rule_ids,
                    user_id=user_id,
                    categories=categories,
                )
                await self._emit_block_alerts(
                    request_id=request_id,
                    policy_result=PolicyResult(
                        action="block",
                        policy_id=policy_result.policy_id,
                        reason=deny_reason,
                        rule_ids=policy_result.rule_ids,
                    ),
                )
                return policy_blocked_response(
                    PolicyResult(
                        action="require_approval",
                        policy_id=policy_result.policy_id,
                        reason=deny_reason,
                        rule_ids=policy_result.rule_ids,
                    ),
                    approval_id=approval_id or None,
                )
            # Approved: continue proxying as a normal allow.

        if self._profile_store is not None and identity.profile_id is not None:
            projected_usage = estimate_request_token_usage(body)
            cost_estimate = self._cost_estimator.estimate(
                provider.name, model, projected_usage
            )
            limit_check = check_daily_limits(
                profile_store=self._profile_store,
                audit_writer=self._audit_writer,
                profile_id=identity.profile_id,
                projected_tokens=projected_usage.total_tokens,
                projected_cost=cost_estimate.estimated_cost if cost_estimate else 0.0,
            )
            if limit_check.exceeded and limit_check.result is not None:
                latency_ms = (time.perf_counter() - started) * 1000.0
                log_proxy_event(
                    self._audit_writer,
                    self._config,
                    request_id=request_id,
                    provider_name=provider.name,
                    model=model,
                    decision="block",
                    reason=limit_check.result.reason,
                    input_length=input_length,
                    output_length=0,
                    latency_ms=latency_ms,
                    body=body,
                    policy_id=limit_check.result.policy_id,
                    user_id=user_id,
                    categories=categories,
                )
                await self._emit_block_alerts(
                    request_id=request_id,
                    policy_result=limit_check.result,
                )
                return policy_blocked_response(limit_check.result)

        projected_usage = estimate_request_token_usage(body)
        cost_estimate = self._cost_estimator.estimate(provider.name, model, projected_usage)
        budget_decision = run_budget_checkers(
            self._budget_checkers,
            BudgetCheckContext(
                profile_id=identity.profile_id,
                user_id=user_id,
                provider=provider.name,
                model=model,
                projected_tokens=projected_usage.total_tokens,
                projected_cost=(
                    cost_estimate.estimated_cost if cost_estimate else 0.0
                ),
            ),
        )
        if budget_decision is not None and budget_decision.action == "block":
            block_result = budget_decision.as_policy_result()
            latency_ms = (time.perf_counter() - started) * 1000.0
            log_proxy_event(
                self._audit_writer,
                self._config,
                request_id=request_id,
                provider_name=provider.name,
                model=model,
                decision="block",
                reason=block_result.reason,
                input_length=input_length,
                output_length=0,
                latency_ms=latency_ms,
                body=body,
                policy_id=block_result.policy_id,
                user_id=user_id,
                categories=categories,
            )
            await self._emit_block_alerts(
                request_id=request_id,
                policy_result=block_result,
            )
            return policy_blocked_response(block_result)
        if (
            budget_decision is not None
            and budget_decision.action == "warn"
            and policy_result.action == "allow"
        ):
            policy_result = budget_decision.as_policy_result()
            await self._emit_warn_alerts(
                request_id=request_id,
                policy_result=policy_result,
            )

        forward_body = body
        redaction_count = 0
        if policy_result.action == "redact":
            redaction = redact_request_body(
                body,
                self._config.scanners,
                extra_rules=self._secret_extra_rules,
            )
            forward_body = redaction.body
            redaction_count = redaction.redaction_count
            if redaction.rule_ids and not policy_result.rule_ids:
                policy_result = PolicyResult(
                    action=policy_result.action,
                    policy_id=policy_result.policy_id,
                    reason=policy_result.reason,
                    rule_ids=redaction.rule_ids,
                )

        response_headers = privacy_safe_headers(policy_result)

        if _request_is_streaming(forward_body):
            return await self._forward_stream(
                request_id=request_id,
                provider_name=provider.name,
                model=model,
                body=forward_body,
                input_length=input_length,
                upstream_url=upstream_url,
                upstream_headers=upstream_headers,
                started=started,
                policy_result=policy_result,
                redaction_count=redaction_count,
                extra_headers=response_headers,
                user_id=user_id,
                categories=categories,
            )

        try:
            upstream_response = await self._http_client.post(
                upstream_url,
                content=forward_body,
                headers=upstream_headers,
            )
        except httpx.RequestError as exc:
            latency_ms = (time.perf_counter() - started) * 1000.0
            log_proxy_event(
                self._audit_writer,
                self._config,
                request_id=request_id,
                provider_name=provider.name,
                model=model,
                decision="error",
                reason="upstream_unreachable",
                input_length=input_length,
                output_length=0,
                latency_ms=latency_ms,
                body=forward_body,
                policy_id=_policy_id_for_audit(policy_result),
                redaction_count=redaction_count,
                rule_ids=policy_result.rule_ids,
                user_id=user_id,
                categories=categories,
            )
            await self._emit_provider_error_alerts(
                request_id=request_id,
                provider_name=provider.name,
                model=model,
                reason="upstream_unreachable",
            )
            raise HTTPException(
                status_code=502,
                detail=f"Upstream provider unreachable at {upstream_url}: {exc}",
            ) from exc

        latency_ms = (time.perf_counter() - started) * 1000.0
        output_length = len(upstream_response.content)
        upstream_ok = upstream_response.status_code < 400
        decision = _audit_decision(policy_result, upstream_ok=upstream_ok)
        reason = _audit_reason(
            policy_result,
            "proxied" if upstream_ok else "upstream_error",
        )
        token_usage = (
            extract_token_usage(forward_body, upstream_response.content) if upstream_ok else None
        )
        cost_estimate = None
        if token_usage is not None:
            cost_estimate = self._cost_estimator.estimate(provider.name, model, token_usage)

        log_proxy_event(
            self._audit_writer,
            self._config,
            request_id=request_id,
            provider_name=provider.name,
            model=model,
            decision=decision,
            reason=reason,
            input_length=input_length,
            output_length=output_length,
            latency_ms=latency_ms,
            body=forward_body,
            response_text=upstream_response.text if upstream_ok else None,
            policy_id=_policy_id_for_audit(policy_result),
            prompt_tokens=token_usage.prompt_tokens if token_usage else None,
            completion_tokens=token_usage.completion_tokens if token_usage else None,
            total_tokens=token_usage.total_tokens if token_usage else None,
            estimated_cost=cost_estimate.estimated_cost if cost_estimate else None,
            redaction_count=redaction_count,
            rule_ids=policy_result.rule_ids,
            user_id=user_id,
            categories=categories,
        )

        if not upstream_ok and upstream_response.status_code >= 500:
            await self._emit_provider_error_alerts(
                request_id=request_id,
                provider_name=provider.name,
                model=model,
                reason="upstream_error",
                status_code=upstream_response.status_code,
            )

        return Response(
            content=upstream_response.content,
            status_code=upstream_response.status_code,
            media_type=upstream_response.headers.get("content-type", "application/json"),
            headers=response_headers or None,
        )

    async def _forward_stream(
        self,
        *,
        request_id: str,
        provider_name: str,
        model: str,
        body: bytes,
        input_length: int,
        upstream_url: str,
        upstream_headers: dict[str, str],
        started: float,
        policy_result: PolicyResult,
        redaction_count: int = 0,
        extra_headers: dict[str, str] | None = None,
        user_id: str | None = None,
        categories: frozenset[str] = frozenset(),
    ) -> StreamingResponse | Response:
        upstream_request = self._http_client.build_request(
            "POST",
            upstream_url,
            content=body,
            headers=upstream_headers,
        )

        try:
            upstream_response = await self._http_client.send(upstream_request, stream=True)
        except httpx.RequestError as exc:
            latency_ms = (time.perf_counter() - started) * 1000.0
            log_proxy_event(
                self._audit_writer,
                self._config,
                request_id=request_id,
                provider_name=provider_name,
                model=model,
                decision="error",
                reason="upstream_unreachable",
                input_length=input_length,
                output_length=0,
                latency_ms=latency_ms,
                body=body,
                policy_id=_policy_id_for_audit(policy_result),
                redaction_count=redaction_count,
                rule_ids=policy_result.rule_ids,
                user_id=user_id,
                categories=categories,
            )
            await self._emit_provider_error_alerts(
                request_id=request_id,
                provider_name=provider_name,
                model=model,
                reason="upstream_unreachable",
            )
            raise HTTPException(
                status_code=502,
                detail=f"Upstream provider unreachable at {upstream_url}: {exc}",
            ) from exc

        if upstream_response.status_code >= 400:
            error_body = await upstream_response.aread()
            latency_ms = (time.perf_counter() - started) * 1000.0
            log_proxy_event(
                self._audit_writer,
                self._config,
                request_id=request_id,
                provider_name=provider_name,
                model=model,
                decision="error",
                reason="upstream_error",
                input_length=input_length,
                output_length=len(error_body),
                latency_ms=latency_ms,
                body=body,
                policy_id=_policy_id_for_audit(policy_result),
                redaction_count=redaction_count,
                rule_ids=policy_result.rule_ids,
                user_id=user_id,
                categories=categories,
            )
            if upstream_response.status_code >= 500:
                await self._emit_provider_error_alerts(
                    request_id=request_id,
                    provider_name=provider_name,
                    model=model,
                    reason="upstream_error",
                    status_code=upstream_response.status_code,
                )
            await upstream_response.aclose()
            return Response(
                content=error_body,
                status_code=upstream_response.status_code,
                media_type=upstream_response.headers.get("content-type", "application/json"),
                headers=extra_headers or None,
            )

        output_chunks: list[bytes] = []

        async def stream_body() -> AsyncIterator[bytes]:
            try:
                async for chunk in upstream_response.aiter_bytes():
                    output_chunks.append(chunk)
                    yield chunk
            finally:
                await upstream_response.aclose()
                latency_ms = (time.perf_counter() - started) * 1000.0
                output_bytes = b"".join(output_chunks)
                output_length = len(output_bytes)
                token_usage = extract_stream_token_usage(
                    body, output_bytes.decode("utf-8", errors="replace")
                )
                cost_estimate = self._cost_estimator.estimate(provider_name, model, token_usage)
                log_proxy_event(
                    self._audit_writer,
                    self._config,
                    request_id=request_id,
                    provider_name=provider_name,
                    model=model,
                    decision=_audit_decision(policy_result),
                    reason=_audit_reason(policy_result),
                    input_length=input_length,
                    output_length=output_length,
                    latency_ms=latency_ms,
                    body=body,
                    response_text=output_bytes.decode("utf-8", errors="replace"),
                    policy_id=_policy_id_for_audit(policy_result),
                    prompt_tokens=token_usage.prompt_tokens,
                    completion_tokens=token_usage.completion_tokens,
                    total_tokens=token_usage.total_tokens,
                    estimated_cost=cost_estimate.estimated_cost if cost_estimate else None,
                    redaction_count=redaction_count,
                    rule_ids=policy_result.rule_ids,
                    user_id=user_id,
                    categories=categories,
                )

        return StreamingResponse(
            stream_body(),
            status_code=upstream_response.status_code,
            media_type=upstream_response.headers.get("content-type", "text/event-stream"),
            headers=extra_headers or None,
        )
