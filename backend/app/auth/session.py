# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""HMAC-signed browser session for SSO logins."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass

COOKIE_NAME = "aiwall_session"
STATE_COOKIE = "aiwall_oidc_state"
DEFAULT_TTL_SECONDS = 8 * 60 * 60


@dataclass(frozen=True)
class SessionClaims:
    profile: str
    organization_slug: str | None
    expires_at: int


def sign_session(
    secret: str,
    profile: str,
    organization_slug: str | None,
    *,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: int | None = None,
) -> str:
    issued = int(time.time() if now is None else now)
    payload = {
        "p": profile,
        "o": organization_slug,
        "e": issued + ttl_seconds,
    }
    return _seal(secret, payload)


def read_session(secret: str, token: str, *, now: int | None = None) -> SessionClaims | None:
    payload = _open(secret, token)
    if payload is None:
        return None
    try:
        expires_at = int(payload["e"])
        profile = str(payload["p"])
    except (KeyError, TypeError, ValueError):
        return None
    current = int(time.time() if now is None else now)
    if not profile or expires_at < current:
        return None
    org = payload.get("o")
    return SessionClaims(
        profile=profile,
        organization_slug=str(org) if org else None,
        expires_at=expires_at,
    )


def _seal(secret: str, payload: dict[str, object]) -> str:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    encoded = base64.urlsafe_b64encode(body).decode().rstrip("=")
    signature = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def _open(secret: str, token: str) -> dict[str, object] | None:
    encoded, separator, signature = token.partition(".")
    if not separator or not encoded or not signature:
        return None
    expected = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return None
    padded = encoded + "=" * (-len(encoded) % 4)
    try:
        raw = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict):
        return None
    return raw
