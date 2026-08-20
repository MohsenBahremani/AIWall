# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Example plugin package for dev/tests (not a commercial Pro/Enterprise build)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, FastAPI


@dataclass(frozen=True, slots=True)
class PluginInfo:
    name: str
    version: str
    edition: str = "extension"


class StubPlugin:
    """Minimal plugin used to validate entry-point loading in tests."""

    @property
    def info(self) -> PluginInfo:
        return PluginInfo(name="aiwall-plugin-stub", version="0.0.1", edition="extension")

    def register(self, app: FastAPI, *, config: Any) -> None:
        router = APIRouter(prefix="/plugins/stub", tags=["plugins"])

        @router.get("/health")
        async def stub_health() -> dict[str, str]:
            return {"status": "ok", "plugin": self.info.name}

        app.include_router(router)


def plugin_factory() -> StubPlugin:
    return StubPlugin()
