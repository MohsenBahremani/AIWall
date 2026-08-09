# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Web control panel routes (server-rendered, no frontend build step)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.agents.approval_models import APPROVAL_APPROVED, APPROVAL_DENIED
from app.agents.approval_store import ApprovalError
from app.agents.types import KNOWN_ACTION_TYPES
from app.policies.overrides import set_policy_enabled
from app.reports.audit_jsonl import export_to_jsonl
from app.reports.export import (
    DEFAULT_EXPORT_LIMIT,
    ExportFilters,
    build_event_export,
    export_to_csv,
    export_to_json,
)
from app.reports.weekly import build_weekly_report, render_markdown
from app.settings.overrides import update_logging_settings
from app.web.privacy import event_detail_context

WEB_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"

DEFAULT_EVENT_LIMIT = 50
DEFAULT_AGENT_ACTION_LIMIT = 50
DEFAULT_SUMMARY_WINDOW_HOURS = 24
DEFAULT_TREND_BUCKET_HOURS = 1
DEFAULT_EXPLORER_PAGE_SIZE = 25
EXPLORER_WINDOW_OPTIONS = (24, 72, 168, 0)  # 0 = all time
DEFAULT_PROMPT_PAGE_SIZE = 25


def build_templates() -> Jinja2Templates:
    def ui_flags(request: Request) -> dict[str, object]:
        config = request.app.state.policy_engine.reload()
        return {"log_raw_prompts_enabled": bool(config.logging.log_raw_prompts)}

    templates = Jinja2Templates(
        directory=str(TEMPLATES_DIR),
        context_processors=[ui_flags],
    )

    def bar_height(value: float, maximum: float, *, min_px: int = 2, max_px: int = 120) -> int:
        if maximum <= 0 or value <= 0:
            return min_px if value > 0 else 0
        ratio = min(float(value) / float(maximum), 1.0)
        return max(min_px, int(round(ratio * max_px)))

    templates.env.globals["bar_height"] = bar_height
    return templates


def create_web_router(templates: Jinja2Templates) -> APIRouter:
    router = APIRouter()

    def _load_events(
        audit_writer,
        *,
        decision: str | None,
        provider: str | None,
    ):
        normalized_decision = decision or None
        normalized_provider = provider or None
        events = audit_writer.list_recent(
            limit=DEFAULT_EVENT_LIMIT,
            decision=normalized_decision,
            provider=normalized_provider,
        )
        providers = audit_writer.list_providers()
        return events, providers, normalized_decision, normalized_provider

    @router.get("/", response_class=HTMLResponse)
    async def dashboard(
        request: Request,
        decision: str | None = None,
        provider: str | None = None,
    ) -> HTMLResponse:
        audit_writer = request.app.state.audit_writer
        events, providers, selected_decision, selected_provider = _load_events(
            audit_writer,
            decision=decision,
            provider=provider,
        )
        summary = audit_writer.summary(window_hours=DEFAULT_SUMMARY_WINDOW_HOURS)
        trends = audit_writer.usage_timeseries(
            window_hours=DEFAULT_SUMMARY_WINDOW_HOURS,
            bucket_hours=DEFAULT_TREND_BUCKET_HOURS,
        )
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                "events": events,
                "event_limit": DEFAULT_EVENT_LIMIT,
                "summary": summary,
                "trends": trends,
                "providers": providers,
                "selected_decision": selected_decision,
                "selected_provider": selected_provider,
            },
        )

    @router.get("/partials/events", response_class=HTMLResponse)
    async def events_partial(
        request: Request,
        decision: str | None = None,
        provider: str | None = None,
    ) -> HTMLResponse:
        audit_writer = request.app.state.audit_writer
        events, providers, selected_decision, selected_provider = _load_events(
            audit_writer,
            decision=decision,
            provider=provider,
        )
        return templates.TemplateResponse(
            request,
            "partials/events_table.html",
            {
                "events": events,
                "providers": providers,
                "selected_decision": selected_decision,
                "selected_provider": selected_provider,
            },
        )

    @router.get("/partials/events/{event_id}/detail", response_class=HTMLResponse)
    async def event_detail_partial(request: Request, event_id: int) -> HTMLResponse:
        audit_writer = request.app.state.audit_writer
        event = audit_writer.get_by_id(event_id)
        if event is None:
            raise HTTPException(status_code=404, detail="Event not found")
        return templates.TemplateResponse(
            request,
            "partials/event_detail.html",
            event_detail_context(event),
        )

    def _load_event_explorer(
        request: Request,
        *,
        decision: str | None,
        provider: str | None,
        model: str | None,
        profile: str | None,
        window_hours: int,
        offset: int,
        limit: int,
    ) -> dict[str, object]:
        audit_writer = request.app.state.audit_writer
        profile_store = getattr(request.app.state, "profile_store", None)
        profiles = profile_store.list() if profile_store is not None else []
        profile_names = {str(p.id): p.name for p in profiles}
        selected_profile = profile if profile in profile_names else None

        since = None
        if window_hours > 0:
            since = datetime.now(UTC) - timedelta(hours=window_hours)

        page = audit_writer.search_events(
            limit=limit,
            offset=max(0, offset),
            decision=decision or None,
            provider=provider or None,
            model=model or None,
            user_id=selected_profile,
            since=since,
        )
        export_filters = ExportFilters(
            decision=decision or None,
            provider=provider or None,
            model=model or None,
            profile=selected_profile,
            window_hours=window_hours,
        )
        return {
            "page": page,
            "events": page.events,
            "providers": audit_writer.list_providers(),
            "models": audit_writer.list_models(provider=provider or None),
            "profiles": profiles,
            "profile_names": profile_names,
            "selected_decision": decision or None,
            "selected_provider": provider or None,
            "selected_model": model or None,
            "selected_profile": selected_profile,
            "window_hours": window_hours,
            "window_options": EXPLORER_WINDOW_OPTIONS,
            "page_size": limit,
            "export_query": export_filters.query_string(),
        }

    @router.get("/events", response_class=HTMLResponse)
    async def events_explorer(
        request: Request,
        decision: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        profile: str | None = None,
        window_hours: int = 24,
        offset: int = 0,
        limit: int = DEFAULT_EXPLORER_PAGE_SIZE,
    ) -> HTMLResponse:
        page_size = limit if limit >= 1 else DEFAULT_EXPLORER_PAGE_SIZE
        return templates.TemplateResponse(
            request,
            "events.html",
            _load_event_explorer(
                request,
                decision=decision,
                provider=provider,
                model=model,
                profile=profile,
                window_hours=window_hours,
                offset=offset,
                limit=page_size,
            ),
        )

    @router.get("/partials/event-explorer", response_class=HTMLResponse)
    async def events_explorer_partial(
        request: Request,
        decision: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        profile: str | None = None,
        window_hours: int = 24,
        offset: int = 0,
        limit: int = DEFAULT_EXPLORER_PAGE_SIZE,
    ) -> HTMLResponse:
        page_size = limit if limit >= 1 else DEFAULT_EXPLORER_PAGE_SIZE
        return templates.TemplateResponse(
            request,
            "partials/event_explorer_table.html",
            _load_event_explorer(
                request,
                decision=decision,
                provider=provider,
                model=model,
                profile=profile,
                window_hours=window_hours,
                offset=offset,
                limit=page_size,
            ),
        )

    @router.get("/events/export.json")
    async def events_export_json(
        request: Request,
        decision: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        profile: str | None = None,
        window_hours: int = 24,
    ) -> Response:
        report = _build_filtered_export(
            request,
            decision=decision,
            provider=provider,
            model=model,
            profile=profile,
            window_hours=window_hours,
        )
        body = export_to_json(report)
        filename = f"aiwall-events-{report.exported_at.strftime('%Y%m%d-%H%M%S')}.json"
        return Response(
            content=body,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @router.get("/events/export.csv")
    async def events_export_csv(
        request: Request,
        decision: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        profile: str | None = None,
        window_hours: int = 24,
    ) -> Response:
        report = _build_filtered_export(
            request,
            decision=decision,
            provider=provider,
            model=model,
            profile=profile,
            window_hours=window_hours,
        )
        body = export_to_csv(report)
        filename = f"aiwall-events-{report.exported_at.strftime('%Y%m%d-%H%M%S')}.csv"
        return Response(
            content=body,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @router.get("/events/export.jsonl")
    async def events_export_jsonl(
        request: Request,
        decision: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        profile: str | None = None,
        window_hours: int = 24,
    ) -> Response:
        """Stable SIEM feed: one ``aiwall.audit.v1`` object per line."""
        report = _build_filtered_export(
            request,
            decision=decision,
            provider=provider,
            model=model,
            profile=profile,
            window_hours=window_hours,
        )
        body = export_to_jsonl(report)
        filename = f"aiwall-audit-{report.exported_at.strftime('%Y%m%d-%H%M%S')}.jsonl"
        return Response(
            content=body,
            media_type="application/x-ndjson; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    def _build_filtered_export(
        request: Request,
        *,
        decision: str | None,
        provider: str | None,
        model: str | None,
        profile: str | None,
        window_hours: int,
    ):
        audit_writer = request.app.state.audit_writer
        profile_store = getattr(request.app.state, "profile_store", None)
        profiles = profile_store.list() if profile_store is not None else []
        profile_names = {str(p.id): p.name for p in profiles}
        selected_profile = profile if profile in profile_names else None
        filters = ExportFilters(
            decision=decision or None,
            provider=provider or None,
            model=model or None,
            profile=selected_profile,
            window_hours=window_hours,
        )
        return build_event_export(audit_writer, filters, limit=DEFAULT_EXPORT_LIMIT)

    def _load_blocked(request: Request, profile: str | None):
        audit_writer = request.app.state.audit_writer
        profile_store = getattr(request.app.state, "profile_store", None)
        profiles = profile_store.list() if profile_store is not None else []
        profile_names = {str(p.id): p.name for p in profiles}
        selected_profile = profile if profile in profile_names else None
        events = audit_writer.list_recent(
            limit=DEFAULT_EVENT_LIMIT,
            decision="block",
            user_id=selected_profile,
        )
        return {
            "events": events,
            "event_limit": DEFAULT_EVENT_LIMIT,
            "profiles": profiles,
            "profile_names": profile_names,
            "selected_profile": selected_profile,
        }

    @router.get("/blocked", response_class=HTMLResponse)
    async def blocked_review(request: Request, profile: str | None = None) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "blocked.html",
            _load_blocked(request, profile),
        )

    @router.get("/partials/blocked", response_class=HTMLResponse)
    async def blocked_partial(request: Request, profile: str | None = None) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "partials/blocked_table.html",
            _load_blocked(request, profile),
        )

    @router.get("/reports/weekly")
    async def weekly_report(
        request: Request,
        format: str | None = None,
    ) -> Response:
        profile_store = getattr(request.app.state, "profile_store", None)
        if profile_store is None:
            raise HTTPException(status_code=503, detail="Profile store unavailable")
        report = build_weekly_report(request.app.state.audit_writer, profile_store)
        fmt = (format or "").lower()
        if fmt in {"md", "markdown", "text"}:
            return PlainTextResponse(
                render_markdown(report),
                media_type="text/markdown; charset=utf-8",
            )
        return templates.TemplateResponse(
            request,
            "reports_weekly.html",
            {"report": report},
        )

    @router.get("/usage", response_class=HTMLResponse)
    async def model_usage_page(
        request: Request,
        window_hours: int = DEFAULT_SUMMARY_WINDOW_HOURS,
    ) -> HTMLResponse:
        hours = window_hours if window_hours >= 1 else DEFAULT_SUMMARY_WINDOW_HOURS
        report = request.app.state.audit_writer.model_usage(window_hours=hours)
        return templates.TemplateResponse(
            request,
            "usage.html",
            {
                "report": report,
                "window_hours": hours,
                "window_options": (24, 72, 168),
            },
        )

    def _policies_context(request: Request) -> dict[str, object]:
        engine = request.app.state.policy_engine
        config = engine.reload()
        stats = request.app.state.audit_writer.policy_hit_stats()
        return {
            "policies": config.policies,
            "policy_stats": stats,
        }

    @router.get("/policies", response_class=HTMLResponse)
    async def policies_page(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "policies.html",
            _policies_context(request),
        )

    @router.get("/partials/policies", response_class=HTMLResponse)
    async def policies_partial(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "partials/policies_table.html",
            _policies_context(request),
        )

    @router.post("/policies/{policy_name}/enabled")
    async def set_policy_enabled_route(
        request: Request,
        policy_name: str,
        enabled: bool = Query(...),
    ) -> Response:
        engine = request.app.state.policy_engine
        config = engine.reload()
        known = {policy.name for policy in config.policies}
        if policy_name not in known:
            raise HTTPException(status_code=404, detail="Policy not found")

        set_policy_enabled(request.app.state.config_path, policy_name, enabled)
        engine.invalidate()
        # Keep app.state.config in sync for healthz / other readers.
        request.app.state.config = engine.reload()

        if request.headers.get("hx-request") == "true":
            return templates.TemplateResponse(
                request,
                "partials/policies_table.html",
                _policies_context(request),
            )
        return RedirectResponse(url="/policies", status_code=303)

    def _settings_context(
        request: Request,
        *,
        message: str | None = None,
        purged: int | None = None,
    ) -> dict[str, object]:
        config = request.app.state.policy_engine.reload()
        request.app.state.config = config
        return {
            "providers": config.providers,
            "log_raw_prompts": config.logging.log_raw_prompts,
            "retention_days": config.logging.retention_days,
            "message": message,
            "purged": purged,
        }

    def _reload_runtime_config(request: Request):
        engine = request.app.state.policy_engine
        engine.invalidate()
        config = engine.reload()
        request.app.state.config = config
        return config

    @router.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "settings.html",
            _settings_context(request),
        )

    @router.get("/partials/settings", response_class=HTMLResponse)
    async def settings_partial(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "partials/settings_body.html",
            _settings_context(request),
        )

    @router.post("/settings/logging/raw-prompts")
    async def settings_raw_prompts(
        request: Request,
        enabled: bool = Query(...),
    ) -> Response:
        update_logging_settings(
            request.app.state.config_path,
            log_raw_prompts=enabled,
        )
        _reload_runtime_config(request)
        if request.headers.get("hx-request") == "true":
            return templates.TemplateResponse(
                request,
                "partials/settings_body.html",
                _settings_context(
                    request,
                    message=(
                        "Raw prompt logging enabled."
                        if enabled
                        else "Raw prompt logging disabled."
                    ),
                ),
            )
        return RedirectResponse(url="/settings", status_code=303)

    @router.post("/settings/logging/retention")
    async def settings_retention(
        request: Request,
        days: int = Query(...),
    ) -> Response:
        if days < 1:
            raise HTTPException(status_code=400, detail="retention days must be >= 1")
        update_logging_settings(
            request.app.state.config_path,
            retention_days=days,
        )
        config = _reload_runtime_config(request)
        purged = request.app.state.audit_writer.purge_expired_events(
            config.logging.retention_days
        )
        if request.headers.get("hx-request") == "true":
            return templates.TemplateResponse(
                request,
                "partials/settings_body.html",
                _settings_context(
                    request,
                    message=f"Retention set to {days} days.",
                    purged=purged,
                ),
            )
        return RedirectResponse(url="/settings", status_code=303)

    def _require_prompt_logging(request: Request) -> None:
        config = request.app.state.policy_engine.reload()
        request.app.state.config = config
        if not config.logging.log_raw_prompts:
            raise HTTPException(
                status_code=404,
                detail="Prompt log viewer requires logging.log_raw_prompts: true",
            )

    def _load_prompt_logs(
        request: Request,
        *,
        offset: int,
        limit: int,
    ) -> dict[str, object]:
        page = request.app.state.audit_writer.search_events(
            limit=limit,
            offset=max(0, offset),
            has_raw_prompt=True,
        )
        profile_store = getattr(request.app.state, "profile_store", None)
        profiles = profile_store.list() if profile_store is not None else []
        profile_names = {str(p.id): p.name for p in profiles}
        return {
            "page": page,
            "events": page.events,
            "profile_names": profile_names,
            "page_size": limit,
        }

    @router.get("/prompts", response_class=HTMLResponse)
    async def prompt_log_viewer(
        request: Request,
        offset: int = 0,
        limit: int = DEFAULT_PROMPT_PAGE_SIZE,
    ) -> HTMLResponse:
        _require_prompt_logging(request)
        page_size = limit if limit >= 1 else DEFAULT_PROMPT_PAGE_SIZE
        return templates.TemplateResponse(
            request,
            "prompts.html",
            _load_prompt_logs(request, offset=offset, limit=page_size),
        )

    @router.get("/partials/prompts", response_class=HTMLResponse)
    async def prompt_log_partial(
        request: Request,
        offset: int = 0,
        limit: int = DEFAULT_PROMPT_PAGE_SIZE,
    ) -> HTMLResponse:
        _require_prompt_logging(request)
        page_size = limit if limit >= 1 else DEFAULT_PROMPT_PAGE_SIZE
        return templates.TemplateResponse(
            request,
            "partials/prompts_table.html",
            _load_prompt_logs(request, offset=offset, limit=page_size),
        )

    @router.get("/partials/prompts/{event_id}/detail", response_class=HTMLResponse)
    async def prompt_detail_partial(request: Request, event_id: int) -> HTMLResponse:
        _require_prompt_logging(request)
        event = request.app.state.audit_writer.get_by_id(event_id)
        if event is None or not event.raw_prompt:
            raise HTTPException(status_code=404, detail="Prompt not found")
        return templates.TemplateResponse(
            request,
            "partials/event_detail.html",
            event_detail_context(event, show_raw=True),
        )

    def _approvals_context(request: Request) -> dict[str, object]:
        store = getattr(request.app.state, "approval_store", None)
        approvals = store.list_pending(limit=100) if store is not None else []
        return {"approvals": approvals}

    def _agent_actions_context(
        request: Request,
        *,
        action_type: str | None,
    ) -> dict[str, object]:
        selected = action_type if action_type in KNOWN_ACTION_TYPES else None
        actions = request.app.state.audit_writer.list_agent_actions(
            action_type=selected,
            limit=DEFAULT_AGENT_ACTION_LIMIT,
        )
        return {
            "actions": actions,
            "action_types": sorted(KNOWN_ACTION_TYPES),
            "selected_action_type": selected,
            "action_limit": DEFAULT_AGENT_ACTION_LIMIT,
        }

    def _decide_approval(
        request: Request,
        approval_id: int,
        *,
        status: str,
        decided_by: str | None,
    ) -> None:
        store = getattr(request.app.state, "approval_store", None)
        broker = getattr(request.app.state, "approval_broker", None)
        if store is None or broker is None:
            raise HTTPException(status_code=503, detail="Approval system unavailable")
        try:
            if status == APPROVAL_APPROVED:
                store.approve(approval_id, decided_by=decided_by)
            else:
                store.deny(approval_id, decided_by=decided_by)
        except ApprovalError as exc:
            message = str(exc)
            code = 404 if "not found" in message else 409
            raise HTTPException(status_code=code, detail=message) from exc
        broker.resolve(approval_id, status)

    @router.get("/agents", response_class=HTMLResponse)
    async def agents_page(
        request: Request,
        action_type: str | None = None,
    ) -> HTMLResponse:
        context = {
            **_approvals_context(request),
            **_agent_actions_context(request, action_type=action_type),
        }
        return templates.TemplateResponse(request, "agents.html", context)

    @router.get("/partials/approvals", response_class=HTMLResponse)
    async def approvals_partial(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "partials/approvals_table.html",
            _approvals_context(request),
        )

    @router.get("/partials/agent-actions", response_class=HTMLResponse)
    async def agent_actions_partial(
        request: Request,
        action_type: str | None = None,
    ) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "partials/agent_actions_table.html",
            _agent_actions_context(request, action_type=action_type),
        )

    @router.post("/agents/approvals/{approval_id}/approve")
    async def agents_approve(
        request: Request,
        approval_id: int,
        decided_by: str | None = Query(default="dashboard"),
    ) -> Response:
        _decide_approval(
            request,
            approval_id,
            status=APPROVAL_APPROVED,
            decided_by=decided_by,
        )
        if request.headers.get("hx-request") == "true":
            return templates.TemplateResponse(
                request,
                "partials/approvals_table.html",
                _approvals_context(request),
            )
        return RedirectResponse(url="/agents", status_code=303)

    @router.post("/agents/approvals/{approval_id}/deny")
    async def agents_deny(
        request: Request,
        approval_id: int,
        decided_by: str | None = Query(default="dashboard"),
    ) -> Response:
        _decide_approval(
            request,
            approval_id,
            status=APPROVAL_DENIED,
            decided_by=decided_by,
        )
        if request.headers.get("hx-request") == "true":
            return templates.TemplateResponse(
                request,
                "partials/approvals_table.html",
                _approvals_context(request),
            )
        return RedirectResponse(url="/agents", status_code=303)

    return router


def register_web(app: FastAPI) -> None:
    """Mount the dashboard. Requires Jinja2; callers should guard the import."""
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(create_web_router(build_templates()))
