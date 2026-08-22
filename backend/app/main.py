# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""AIWall FastAPI application factory."""

from __future__ import annotations

import importlib.util
import logging
from collections.abc import Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI

from app import __version__
from app.agents.approval_broker import ApprovalBroker
from app.agents.approval_store import ApprovalStore
from app.agents.routes import create_approvals_router
from app.alerts import RecordingNotifier, build_alert_dispatcher
from app.alerts.heartbeat import HeartbeatMonitor
from app.audit.writer import AuditWriter
from app.config import AIWallConfig, load_config, resolve_config_path
from app.plugins.base import AIWallPlugin
from app.plugins.loader import (
    collect_alert_notifiers,
    collect_secret_rules,
    discover_plugins,
    register_plugins,
)
from app.policies.engine import PolicyEngine
from app.profiles.store import ProfileStore
from app.proxy.pricing import CostEstimator, resolve_prices_path
from app.proxy.routes import router as proxy_router
from app.storage.database import create_engine_from_config, init_db

logger = logging.getLogger(__name__)
DEFAULT_TIMEOUT = httpx.Timeout(60.0, connect=10.0, read=300.0, write=60.0, pool=10.0)


def _init_storage(
    config: AIWallConfig,
) -> tuple[Any, AuditWriter, ProfileStore, ApprovalStore]:
    engine = create_engine_from_config(config)
    init_db(engine)
    return engine, AuditWriter(engine), ProfileStore(engine), ApprovalStore(engine)


def create_app(
    config_path: Path | str | None = None,
    http_client: httpx.AsyncClient | None = None,
    *,
    recording_notifier: RecordingNotifier | None = None,
    plugins: Sequence[AIWallPlugin] | None = None,
) -> FastAPI:
    resolved_path = resolve_config_path(config_path)
    config = load_config(resolved_path)
    engine, audit_writer, profile_store, approval_store = _init_storage(config)
    prices_path = resolve_prices_path(resolved_path, config.pricing.file)
    cost_estimator = CostEstimator(prices_path)
    resolved_plugins = list(plugins) if plugins is not None else discover_plugins()
    alert_notifiers = collect_alert_notifiers(resolved_plugins, config=config)
    plugin_secret_rules = collect_secret_rules(resolved_plugins, config=config)
    alert_dispatcher = build_alert_dispatcher(
        config,
        http_client=http_client,
        recording_notifier=recording_notifier,
        extra_notifiers=alert_notifiers,
    )
    approval_broker = ApprovalBroker()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.config = load_config(resolved_path)
        try:
            deleted = audit_writer.purge_expired_events(
                app.state.config.logging.retention_days
            )
            if deleted:
                logger.info("Purged %s audit events older than retention", deleted)
        except Exception:
            logger.exception("Audit retention purge failed on startup")
        heartbeat: HeartbeatMonitor | None = None
        try:
            if http_client is not None:
                heartbeat = HeartbeatMonitor(
                    config=app.state.config,
                    http_client=http_client,
                    alert_dispatcher=app.state.alert_dispatcher,
                )
                app.state.heartbeat = heartbeat
                heartbeat.start()
                yield
            else:
                async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
                    app.state.http_client = client
                    heartbeat = HeartbeatMonitor(
                        config=app.state.config,
                        http_client=client,
                        alert_dispatcher=app.state.alert_dispatcher,
                    )
                    app.state.heartbeat = heartbeat
                    heartbeat.start()
                    yield
        finally:
            if heartbeat is not None:
                await heartbeat.stop()
            engine.dispose()

    app = FastAPI(
        title="AIWall",
        description="Self-hosted AI security gateway.",
        version=__version__,
        lifespan=lifespan,
    )
    app.state.config_path = resolved_path
    app.state.config = config
    app.state.engine = engine
    app.state.audit_writer = audit_writer
    app.state.profile_store = profile_store
    app.state.policy_engine = PolicyEngine(resolved_path)
    app.state.cost_estimator = cost_estimator
    app.state.alert_dispatcher = alert_dispatcher
    app.state.approval_store = approval_store
    app.state.approval_broker = approval_broker
    app.state.secret_extra_rules = plugin_secret_rules
    app.state.plugin_secret_rules = plugin_secret_rules
    if recording_notifier is not None:
        app.state.recording_notifier = recording_notifier
    if http_client is not None:
        app.state.http_client = http_client

    _configure_cors(app, config)

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        config: AIWallConfig = app.state.config
        payload: dict[str, Any] = {
            "status": "ok",
            "version": __version__,
            "service": "aiwall",
            "config_path": str(app.state.config_path),
            "providers": len(config.providers),
            "policies": len(config.policies),
            "profiles": len(app.state.profile_store.list()),
            "heartbeat_enabled": config.heartbeat.enabled,
            "pending_approvals": len(app.state.approval_store.list_pending(limit=200)),
        }
        heartbeat = getattr(app.state, "heartbeat", None)
        if isinstance(heartbeat, HeartbeatMonitor):
            payload["unhealthy_providers"] = sorted(heartbeat.unhealthy_providers)
        plugin_meta = getattr(app.state, "plugins", None)
        if plugin_meta:
            payload["plugins"] = [
                {
                    "name": item.name,
                    "version": item.version,
                    "edition": item.edition,
                }
                for item in plugin_meta
            ]
        return payload

    app.include_router(proxy_router)
    app.include_router(create_approvals_router())
    _register_web(app)
    register_plugins(app, config, resolved_plugins)
    return app


def _configure_cors(app: FastAPI, config: AIWallConfig) -> None:
    if not config.cors.enabled or not config.cors.allow_origins:
        return
    from fastapi.middleware.cors import CORSMiddleware

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(config.cors.allow_origins),
        allow_credentials=False,
        allow_methods=list(config.cors.allow_methods),
        allow_headers=list(config.cors.allow_headers),
    )


def _register_web(app: FastAPI) -> None:
    """Mount the Jinja2 control panel if Jinja2 is installed."""
    if importlib.util.find_spec("jinja2") is None:
        return
    from app.web.routes import register_web

    register_web(app)


app = create_app()
