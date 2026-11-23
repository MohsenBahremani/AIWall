# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Authorization-code login against an OpenID Connect issuer."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

import httpx

from app.config import AIWallConfig, OidcConfig
from app.orgs.directory import Membership, membership_for_profile
from app.profiles.store import ProfileStore


async def discover(client: httpx.AsyncClient, issuer: str) -> dict[str, str]:
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    response = await client.get(url)
    response.raise_for_status()
    document = response.json()
    try:
        return {
            "authorization_endpoint": document["authorization_endpoint"],
            "token_endpoint": document["token_endpoint"],
            "userinfo_endpoint": document["userinfo_endpoint"],
        }
    except (KeyError, TypeError) as exc:
        raise ValueError("OIDC discovery document is missing an endpoint") from exc


def authorize_url(
    authorization_endpoint: str,
    oidc: OidcConfig,
    *,
    redirect_uri: str,
    state: str,
) -> str:
    query = urlencode(
        {
            "response_type": "code",
            "client_id": oidc.client_id,
            "redirect_uri": redirect_uri,
            "scope": oidc.scopes,
            "state": state,
        }
    )
    separator = "&" if "?" in authorization_endpoint else "?"
    return f"{authorization_endpoint}{separator}{query}"


async def fetch_userinfo(
    client: httpx.AsyncClient,
    metadata: dict[str, str],
    oidc: OidcConfig,
    *,
    code: str,
    redirect_uri: str,
    client_secret: str,
) -> dict[str, Any]:
    token_response = await client.post(
        metadata["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": oidc.client_id,
            "client_secret": client_secret,
        },
    )
    token_response.raise_for_status()
    token = token_response.json()
    access_token = token.get("access_token") if isinstance(token, dict) else None
    if not isinstance(access_token, str) or not access_token:
        raise ValueError("OIDC token response has no access_token")
    userinfo = await client.get(
        metadata["userinfo_endpoint"],
        headers={"Authorization": f"Bearer {access_token}"},
    )
    userinfo.raise_for_status()
    claims = userinfo.json()
    if not isinstance(claims, dict):
        raise ValueError("OIDC userinfo is not an object")
    return claims


def match_member(
    config: AIWallConfig,
    profile_store: ProfileStore,
    claims: dict[str, Any],
) -> tuple[str, Membership] | None:
    """Pick the first claim that names an enabled profile in an organization."""
    seen: set[str] = set()
    for name in _candidate_names(claims):
        if name in seen:
            continue
        seen.add(name)
        profile = profile_store.get_by_name(name)
        if profile is None or not profile.enabled:
            continue
        membership = membership_for_profile(config, profile.name)
        if membership is not None:
            return profile.name, membership
    return None


def _candidate_names(claims: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for key in ("preferred_username", "email", "sub"):
        value = claims.get(key)
        if isinstance(value, str) and value.strip():
            names.append(value.strip())
    email = claims.get("email")
    if isinstance(email, str) and "@" in email:
        names.append(email.split("@", 1)[0].strip())
    return names
