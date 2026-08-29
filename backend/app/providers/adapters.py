# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Provider-type adapters for upstream chat completion requests."""

from __future__ import annotations

import os
from urllib.parse import urljoin

from fastapi import HTTPException

from app.config import ProviderConfig

OPENAI_COMPATIBLE = "openai-compatible"
OLLAMA = "ollama"


def build_chat_completions_url(provider: ProviderConfig) -> str:
    base_url = provider.base_url.rstrip("/")

    if provider.type == OPENAI_COMPATIBLE:
        return urljoin(f"{base_url}/", "chat/completions")

    if provider.type == OLLAMA:
        return f"{base_url}/v1/chat/completions"

    raise HTTPException(
        status_code=503,
        detail=f"Unsupported provider type: {provider.type}",
    )


def build_upstream_headers(
    provider: ProviderConfig,
    incoming_headers: dict[str, str],
    *,
    prefer_provider_key: bool = True,
) -> dict[str, str]:
    """Build headers for the upstream provider.

    When ``prefer_provider_key`` is true (default), use the provider's
    ``api_key_env`` value from the process environment when set. Otherwise
    prefer the client's ``Authorization`` header and only fall back to the
    provider key when the client did not send one.
    """
    headers = {"Content-Type": "application/json"}

    authorization = incoming_headers.get("authorization") or incoming_headers.get(
        "Authorization"
    )

    provider_key = ""
    if provider.api_key_env:
        provider_key = (os.environ.get(provider.api_key_env) or "").strip()

    if not prefer_provider_key and authorization:
        headers["Authorization"] = authorization
        return headers

    if provider_key:
        headers["Authorization"] = f"Bearer {provider_key}"
        return headers

    if authorization:
        headers["Authorization"] = authorization

    return headers
