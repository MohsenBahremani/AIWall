# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Registry for plugin-provided alert notifier channels."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx

    from app.alerts.base import Notifier
    from app.alerts.stub import RecordingNotifier
    from app.config import AlertChannelConfig


NotifierFactory = Callable[["AlertChannelConfig", "NotifierBuildContext"], "Notifier | None"]


@dataclass(frozen=True, slots=True)
class NotifierBuildContext:
    http_client: httpx.AsyncClient | None = None
    recording_notifier: RecordingNotifier | None = None


class AlertNotifierRegistry:
    """Maps custom ``alerts[].channel`` names to notifier factories from plugins."""

    def __init__(self) -> None:
        self._factories: dict[str, NotifierFactory] = {}

    def register(self, channel: str, factory: NotifierFactory) -> None:
        name = channel.strip().lower()
        if not name:
            raise ValueError("channel name must not be empty")
        self._factories[name] = factory

    def build(
        self,
        channel: str,
        entry: AlertChannelConfig,
        ctx: NotifierBuildContext,
    ) -> Notifier | None:
        factory = self._factories.get(channel.strip().lower())
        if factory is None:
            return None
        return factory(entry, ctx)
