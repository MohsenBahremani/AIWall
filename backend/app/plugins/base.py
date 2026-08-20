# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Plugin contract for AIWall Pro / Enterprise extensions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from fastapi import FastAPI

    from app.config import AIWallConfig


@dataclass(frozen=True, slots=True)
class PluginInfo:
    """Metadata surfaced in /healthz and logs."""

    name: str
    version: str
    edition: str = "extension"


@runtime_checkable
class AIWallPlugin(Protocol):
    """Entry-point plugin loaded from separate Pro/Enterprise packages."""

    @property
    def info(self) -> PluginInfo: ...

    def register(self, app: FastAPI, *, config: AIWallConfig) -> None:
        """Mount routes, hooks, or services on the core FastAPI app."""
