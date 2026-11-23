# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""SAML login. The assertion is accepted only when the IdP certificate signs it."""

from __future__ import annotations

import base64
import secrets
import zlib
from datetime import UTC, datetime
from urllib.parse import urlencode
from xml.sax.saxutils import escape

_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
_PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol"


def authn_redirect(sso_url: str, sp_entity_id: str, acs_url: str) -> str:
    instant = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    request_id = "_" + secrets.token_hex(16)
    xml = (
        f'<samlp:AuthnRequest xmlns:samlp="{_PROTOCOL_NS}" '
        f'xmlns:saml="{_ASSERTION_NS}" '
        f'ID="{request_id}" Version="2.0" IssueInstant="{instant}" '
        f'Destination="{escape(sso_url)}" '
        f'AssertionConsumerServiceURL="{escape(acs_url)}">'
        f"<saml:Issuer>{escape(sp_entity_id)}</saml:Issuer>"
        "</samlp:AuthnRequest>"
    )
    compressed = zlib.compress(xml.encode())[2:-4]
    encoded = base64.b64encode(compressed).decode()
    joiner = "&" if "?" in sso_url else "?"
    return sso_url + joiner + urlencode({"SAMLRequest": encoded})


def name_id_from_response(xml: bytes, *, cert_pem: str, idp_entity_id: str) -> str:
    """Return the NameID from a response signed by cert_pem. Anything else raises."""
    if not cert_pem.strip():
        raise ValueError("SAML IdP certificate is not configured")
    try:
        from lxml import etree
        from signxml import XMLVerifier
    except ImportError as exc:
        raise RuntimeError("SAML support is not installed") from exc
    try:
        signed_root = etree.fromstring(xml)
    except etree.XMLSyntaxError as exc:
        raise ValueError("SAML response is not XML") from exc
    try:
        verified = XMLVerifier().verify(signed_root, x509_cert=cert_pem)
    except Exception as exc:
        raise ValueError("SAML signature is not valid") from exc
    signed = verified.signed_xml
    issuer = signed.find(f".//{{{_ASSERTION_NS}}}Issuer")
    if issuer is None or (issuer.text or "").strip() != idp_entity_id:
        raise ValueError("SAML issuer does not match")
    _reject_expired(signed)
    name = signed.find(f".//{{{_ASSERTION_NS}}}NameID")
    if name is None or not (name.text or "").strip():
        raise ValueError("SAML response has no NameID")
    return name.text.strip()


def _reject_expired(signed) -> None:
    conditions = signed.find(f".//{{{_ASSERTION_NS}}}Conditions")
    if conditions is None:
        return
    until = conditions.get("NotOnOrAfter")
    if not until:
        return
    text = until.replace("Z", "+00:00")
    try:
        when = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("SAML NotOnOrAfter is not a time") from exc
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    if when <= datetime.now(UTC):
        raise ValueError("SAML assertion has expired")
