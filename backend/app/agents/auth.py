# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Auth helpers for agent approval decisions."""

from __future__ import annotations

from fastapi import Request

from app.auth.gateway import GatewayIdentity, authenticate_gateway, gateway_auth_enabled
from app.config import AIWallConfig
from app.profiles.store import ProfileStore


def require_approval_auth(
    config: AIWallConfig,
    request: Request,
    profile_store: ProfileStore | None = None,
) -> GatewayIdentity | None:
    """When gateway auth is on, require a valid admin or profile API key."""
    if not gateway_auth_enabled(config):
        return None
    return authenticate_gateway(config, request, profile_store)
