# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Discover and register setuptools entry-point plugins."""

from __future__ import annotations

import logging
from importlib.metadata import entry_points
from typing import TYPE_CHECKING

from app.plugins.base import AIWallPlugin, PluginInfo

if TYPE_CHECKING:
    from fastapi import FastAPI

    from app.alerts.registry import AlertNotifierRegistry
    from app.config import AIWallConfig
    from app.scanners.registry import SecretRuleDef

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "aiwall.plugins"


def _iter_entry_points():
    try:
        return entry_points(group=ENTRY_POINT_GROUP)
    except TypeError:
        # Python < 3.10 fallback (not expected for AIWall, but defensive)
        return entry_points().get(ENTRY_POINT_GROUP, ())


def discover_plugins() -> list[AIWallPlugin]:
    """Load all plugins registered under ``aiwall.plugins`` entry points."""
    plugins: list[AIWallPlugin] = []
    for ep in sorted(_iter_entry_points(), key=lambda item: item.name):
        try:
            loaded = ep.load()
        except Exception:
            logger.exception("Failed to import plugin entry point %r", ep.name)
            continue
        try:
            plugin = loaded() if callable(loaded) else loaded
        except Exception:
            logger.exception("Failed to instantiate plugin entry point %r", ep.name)
            continue
        if not isinstance(plugin, AIWallPlugin):
            logger.error(
                "Plugin entry point %r returned %r; expected AIWallPlugin",
                ep.name,
                type(plugin),
            )
            continue
        plugins.append(plugin)
        logger.info(
            "Loaded plugin %s v%s (%s)",
            plugin.info.name,
            plugin.info.version,
            plugin.info.edition,
        )
    return plugins


def register_plugins(
    app: FastAPI,
    config: AIWallConfig,
    plugins: list[AIWallPlugin],
) -> list[PluginInfo]:
    """Register plugins on the app and return loaded metadata."""
    loaded: list[PluginInfo] = []
    for plugin in plugins:
        plugin.register(app, config=config)
        loaded.append(plugin.info)
    app.state.plugins = loaded
    return loaded


def collect_alert_notifiers(
    plugins: list[AIWallPlugin],
    *,
    config: AIWallConfig,
) -> AlertNotifierRegistry:
    """Ask plugins to register custom alert channel factories."""
    from app.alerts.registry import AlertNotifierRegistry

    registry = AlertNotifierRegistry()
    for plugin in plugins:
        hook = getattr(plugin, "register_alert_notifiers", None)
        if not callable(hook):
            continue
        try:
            hook(registry, config=config)
        except Exception:
            logger.exception(
                "Plugin %s failed register_alert_notifiers",
                getattr(getattr(plugin, "info", None), "name", plugin),
            )
    return registry


def collect_secret_rules(
    plugins: list[AIWallPlugin],
    *,
    config: AIWallConfig,
) -> tuple[SecretRuleDef, ...]:
    """Ask plugins to register premium / extra secret detectors."""
    from app.scanners.registry import SecretRuleRegistry

    registry = SecretRuleRegistry()
    for plugin in plugins:
        hook = getattr(plugin, "register_secret_rules", None)
        if not callable(hook):
            continue
        try:
            hook(registry, config=config)
        except Exception:
            logger.exception(
                "Plugin %s failed register_secret_rules",
                getattr(getattr(plugin, "info", None), "name", plugin),
            )
    return registry.rules()


def collect_budget_checkers(
    plugins: list[AIWallPlugin],
    *,
    config: AIWallConfig,
) -> tuple:
    """Ask plugins to register cost-budget checkers."""
    from app.budgets import BudgetCheckerRegistry

    registry = BudgetCheckerRegistry()
    for plugin in plugins:
        hook = getattr(plugin, "register_budget_checkers", None)
        if not callable(hook):
            continue
        try:
            hook(registry, config=config)
        except Exception:
            logger.exception(
                "Plugin %s failed register_budget_checkers",
                getattr(getattr(plugin, "info", None), "name", plugin),
            )
    return registry.build()
