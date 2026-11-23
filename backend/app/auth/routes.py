# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""SSO login routes. Disabled issuers answer 404."""

from __future__ import annotations

import os
import secrets

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from app.auth.oidc import authorize_url, discover, fetch_userinfo, match_member
from app.auth.session import COOKIE_NAME, STATE_COOKIE, read_session, sign_session
from app.config import AIWallConfig

router = APIRouter()


def _oidc_or_404(config: AIWallConfig):
    oidc = config.sso.oidc
    if not oidc.enabled:
        raise HTTPException(status_code=404, detail="OIDC is not enabled")
    return oidc


def _secret(env_name: str) -> str:
    value = os.environ.get(env_name, "").strip()
    if not value:
        raise HTTPException(status_code=503, detail=f"{env_name} is not set")
    return value


def _redirect_uri(request: Request, path: str) -> str:
    return str(request.base_url).rstrip("/") + path


@router.get("/auth/oidc/login")
async def oidc_login(request: Request) -> RedirectResponse:
    config: AIWallConfig = request.app.state.config
    oidc = _oidc_or_404(config)
    _secret(config.sso.session_secret_env)
    client: httpx.AsyncClient = request.app.state.http_client
    metadata = await discover(client, oidc.issuer)
    state = secrets.token_urlsafe(24)
    target = authorize_url(
        metadata["authorization_endpoint"],
        oidc,
        redirect_uri=_redirect_uri(request, oidc.redirect_path),
        state=state,
    )
    response = RedirectResponse(target, status_code=302)
    response.set_cookie(STATE_COOKIE, state, max_age=600, httponly=True, samesite="lax")
    return response


@router.get("/auth/oidc/callback")
async def oidc_callback(
    request: Request,
    code: str = "",
    state: str = "",
) -> RedirectResponse:
    config: AIWallConfig = request.app.state.config
    oidc = _oidc_or_404(config)
    session_secret = _secret(config.sso.session_secret_env)
    expected = request.cookies.get(STATE_COOKIE, "")
    if not code or not state or not expected or not secrets.compare_digest(expected, state):
        raise HTTPException(status_code=400, detail="OIDC state does not match")
    client: httpx.AsyncClient = request.app.state.http_client
    metadata = await discover(client, oidc.issuer)
    claims = await fetch_userinfo(
        client,
        metadata,
        oidc,
        code=code,
        redirect_uri=_redirect_uri(request, oidc.redirect_path),
        client_secret=_secret(oidc.client_secret_env),
    )
    matched = match_member(config, request.app.state.profile_store, claims)
    if matched is None:
        raise HTTPException(status_code=403, detail="No organization member matches this login")
    profile_name, membership = matched
    token = sign_session(session_secret, profile_name, membership.organization_slug)
    response = RedirectResponse("/", status_code=302)
    response.set_cookie(COOKIE_NAME, token, max_age=8 * 60 * 60, httponly=True, samesite="lax")
    response.delete_cookie(STATE_COOKIE)
    return response


@router.get("/auth/session")
async def current_session(request: Request) -> JSONResponse:
    config: AIWallConfig = request.app.state.config
    secret = os.environ.get(config.sso.session_secret_env, "").strip()
    token = request.cookies.get(COOKIE_NAME, "")
    if not secret or not token:
        raise HTTPException(status_code=401, detail="Not signed in")
    claims = read_session(secret, token)
    if claims is None:
        raise HTTPException(status_code=401, detail="Not signed in")
    return JSONResponse(
        {"profile": claims.profile, "organization": claims.organization_slug}
    )
