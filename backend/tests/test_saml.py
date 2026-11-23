# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""SAML login accepts a signed assertion and rejects an unsigned one."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import create_app
from app.profiles.store import ProfileStore
from tests.conftest import write_test_config

_IDP = "https://idp.example.test"


def _identity():
    pytest.importorskip("signxml")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return key_pem, cert_pem


def _signed_assertion(key_pem: bytes, cert_pem: str, name_id: str) -> str:
    from lxml import etree
    from signxml import XMLSigner

    ns = "urn:oasis:names:tc:SAML:2.0:assertion"
    xml = (
        f'<saml:Assertion xmlns:saml="{ns}" ID="_assertion">'
        f"<saml:Issuer>{_IDP}</saml:Issuer>"
        f"<saml:Subject><saml:NameID>{name_id}</saml:NameID></saml:Subject>"
        "</saml:Assertion>"
    )
    signed = XMLSigner().sign(etree.fromstring(xml.encode()), key=key_pem, cert=cert_pem)
    return base64.b64encode(etree.tostring(signed)).decode()


def _config(tmp_path: Path, cert_pem: str) -> Path:
    indented = "\n".join(f"      {line}" for line in cert_pem.strip().splitlines())
    extra = f"""
organizations:
  - slug: acme
    name: Acme
    members:
      - profile: ada
        role: admin
sso:
  saml:
    enabled: true
    idp_entity_id: {_IDP}
    sso_url: {_IDP}/sso
    sp_entity_id: aiwall
    idp_cert: |
{indented}
"""
    return write_test_config(tmp_path, extra_yaml=extra)


@pytest.mark.asyncio
async def test_signed_assertion_sets_a_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_pem, cert_pem = _identity()
    monkeypatch.setenv("AIWALL_SESSION_SECRET", "test-session-secret")
    monkeypatch.setenv("AIWALL_SKIP_DOTENV", "1")
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200)))
    app = create_app(config_path=_config(tmp_path, cert_pem), http_client=http_client, plugins=[])
    store: ProfileStore = app.state.profile_store
    store.create(name="ada")
    encoded = _signed_assertion(key_pem, cert_pem, "ada")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        posted = await client.post(
            "/auth/saml/acs",
            content=urlencode({"SAMLResponse": encoded}),
            headers={"content-type": "application/x-www-form-urlencoded"},
            follow_redirects=False,
        )
        assert posted.status_code == 302
        session = await client.get("/auth/session")
    assert session.status_code == 200
    assert session.json() == {"profile": "ada", "organization": "acme"}
    await http_client.aclose()


@pytest.mark.asyncio
async def test_unsigned_assertion_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("signxml")
    _key_pem, cert_pem = _identity()
    monkeypatch.setenv("AIWALL_SESSION_SECRET", "test-session-secret")
    monkeypatch.setenv("AIWALL_SKIP_DOTENV", "1")
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200)))
    app = create_app(config_path=_config(tmp_path, cert_pem), http_client=http_client, plugins=[])
    ns = "urn:oasis:names:tc:SAML:2.0:assertion"
    unsigned = (
        f'<saml:Assertion xmlns:saml="{ns}" ID="_assertion">'
        f"<saml:Issuer>{_IDP}</saml:Issuer>"
        "<saml:Subject><saml:NameID>ada</saml:NameID></saml:Subject>"
        "</saml:Assertion>"
    )
    encoded = base64.b64encode(unsigned.encode()).decode()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        posted = await client.post(
            "/auth/saml/acs",
            content=urlencode({"SAMLResponse": encoded}),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
    assert posted.status_code == 400
    await http_client.aclose()


@pytest.mark.asyncio
async def test_saml_login_redirects_to_the_idp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AIWALL_SESSION_SECRET", "test-session-secret")
    monkeypatch.setenv("AIWALL_SKIP_DOTENV", "1")
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200)))
    app = create_app(
        config_path=_config(tmp_path, "placeholder-cert"),
        http_client=http_client,
        plugins=[],
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/auth/saml/login", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"].startswith(f"{_IDP}/sso?SAMLRequest=")
    await http_client.aclose()
