# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""OIDC login maps a verified userinfo claim onto an organization member."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.auth.session import read_session, sign_session
from app.main import create_app
from app.profiles.store import ProfileStore
from tests.conftest import write_test_config

_SSO = """
organizations:
  - slug: acme
    name: Acme
    members:
      - profile: ada
        role: admin
sso:
  oidc:
    enabled: true
    issuer: https://idp.example.test/realms/acme
    client_id: aiwall
    client_secret_env: OIDC_CLIENT_SECRET
"""


def _handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path.endswith("/.well-known/openid-configuration"):
        return httpx.Response(
            200,
            json={
                "authorization_endpoint": "https://idp.example.test/authorize",
                "token_endpoint": "https://idp.example.test/token",
                "userinfo_endpoint": "https://idp.example.test/userinfo",
            },
        )
    if path.endswith("/token"):
        return httpx.Response(200, json={"access_token": "idp-access"})
    if path.endswith("/userinfo"):
        return httpx.Response(200, json={"email": "ada@acme.test", "sub": "subject-1"})
    return httpx.Response(404)


@pytest.mark.asyncio
async def test_oidc_login_sets_a_session_for_the_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AIWALL_SESSION_SECRET", "test-session-secret")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("AIWALL_SKIP_DOTENV", "1")
    config_path = write_test_config(tmp_path, extra_yaml=_SSO)
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
    app = create_app(config_path=config_path, http_client=http_client, plugins=[])
    store: ProfileStore = app.state.profile_store
    store.create(name="ada")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        login = await client.get("/auth/oidc/login", follow_redirects=False)
        assert login.status_code == 302
        assert login.headers["location"].startswith("https://idp.example.test/authorize?")
        state = login.cookies["aiwall_oidc_state"]
        callback = await client.get(
            "/auth/oidc/callback",
            params={"code": "auth-code", "state": state},
            follow_redirects=False,
        )
        assert callback.status_code == 302
        assert callback.headers["location"] == "/"
        session = await client.get("/auth/session")
    assert session.status_code == 200
    assert session.json() == {"profile": "ada", "organization": "acme"}
    await http_client.aclose()


@pytest.mark.asyncio
async def test_oidc_is_hidden_when_disabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AIWALL_SKIP_DOTENV", "1")
    config_path = write_test_config(tmp_path)
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
    app = create_app(config_path=config_path, http_client=http_client, plugins=[])
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/auth/oidc/login")
    assert response.status_code == 404
    await http_client.aclose()


def test_tampered_session_cookie_is_rejected() -> None:
    token = sign_session("secret", "ada", "acme", now=1_700_000_000)
    assert read_session("secret", token, now=1_700_000_000) is not None
    flipped = token[:-1] + ("a" if token[-1] != "a" else "b")
    assert read_session("secret", flipped, now=1_700_000_000) is None
