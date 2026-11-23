# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Optional gateway API key validation and profile identity resolution."""

from __future__ import annotations

import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass

from fastapi import HTTPException, Request

from app.config import AIWallConfig
from app.orgs.directory import membership_for_profile
from app.profiles.store import ProfileStore, hash_api_key


@dataclass(frozen=True)
class GatewayIdentity:
    """Resolved caller identity for audit attribution and organization scope."""

    user_id: str | None = None
    profile_id: int | None = None
    profile_name: str | None = None
    role: str | None = None
    is_gateway_admin: bool = False
    organization_slug: str | None = None
    team_slug: str | None = None
    org_role: str | None = None


def _extract_bearer_token(headers: Mapping[str, str]) -> str | None:
    authorization = headers.get("authorization") or headers.get("Authorization")
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token.strip()


def gateway_auth_enabled(config: AIWallConfig) -> bool:
    return config.gateway_auth.enabled


def resolve_profile_from_api_key(
    profile_store: ProfileStore | None,
    api_key: str,
    config: AIWallConfig | None = None,
) -> GatewayIdentity | None:
    if profile_store is None or not api_key:
        return None
    profile = profile_store.get_by_api_key_hash(hash_api_key(api_key))
    if profile is None or not profile.enabled:
        return None
    membership = membership_for_profile(config, profile.name) if config is not None else None
    return GatewayIdentity(
        user_id=str(profile.id),
        profile_id=profile.id,
        profile_name=profile.name,
        role=profile.role,
        organization_slug=None if membership is None else membership.organization_slug,
        team_slug=None if membership is None else membership.team_slug,
        org_role=None if membership is None else membership.role,
    )


def authenticate_gateway(
    config: AIWallConfig,
    request: Request,
    profile_store: ProfileStore | None = None,
) -> GatewayIdentity:
    """Validate the client Bearer token and resolve optional profile identity.

    When ``gateway_auth.enabled`` is false, requests are allowed without a key.
    A matching profile key still attributes the request to that profile.

    When enabled, the Bearer must match ``AIWALL_API_KEY`` (admin) or an
    enabled profile's issued API key.
    """
    provided_key = _extract_bearer_token(request.headers)

    if not config.gateway_auth.enabled:
        if provided_key:
            identity = resolve_profile_from_api_key(profile_store, provided_key, config)
            if identity is not None:
                return identity
        return GatewayIdentity()

    if not provided_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing AIWall API key",
        )

    expected_key = os.environ.get(config.gateway_auth.api_key_env)
    if expected_key and secrets.compare_digest(provided_key, expected_key):
        return GatewayIdentity(is_gateway_admin=True)

    identity = resolve_profile_from_api_key(profile_store, provided_key, config)
    if identity is not None:
        return identity

    raise HTTPException(
        status_code=401,
        detail="Invalid or missing AIWall API key",
    )


def validate_gateway_auth(
    config: AIWallConfig,
    request: Request,
    profile_store: ProfileStore | None = None,
) -> GatewayIdentity:
    """Backward-compatible entry point used by proxy routes."""
    return authenticate_gateway(config, request, profile_store)


def strip_client_authorization(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: value
        for key, value in headers.items()
        if key.lower() != "authorization"
    }
