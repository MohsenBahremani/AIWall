# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Proprietary feature plugins (Phase 8.1)."""

from app.plugins.base import AIWallPlugin, PluginInfo
from app.plugins.loader import discover_plugins, register_plugins

__all__ = [
    "AIWallPlugin",
    "PluginInfo",
    "discover_plugins",
    "register_plugins",
]
