# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Route requests to providers based on model name patterns."""

from __future__ import annotations

import fnmatch
import json

from fastapi import HTTPException

from app.config import AIWallConfig, ProviderConfig


def model_matches_pattern(model: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(model, pattern)


def provider_matches_model(provider: ProviderConfig, model: str) -> bool:
    if not provider.models:
        return False
    return any(model_matches_pattern(model, pattern) for pattern in provider.models)


def try_select_provider(config: AIWallConfig, model: str) -> ProviderConfig | None:
    for provider in config.providers:
        if provider_matches_model(provider, model):
            return provider
    return None


def select_provider(config: AIWallConfig, model: str) -> ProviderConfig:
    if not config.providers:
        raise HTTPException(
            status_code=503,
            detail="No providers configured",
        )

    provider = try_select_provider(config, model)
    if provider is None:
        raise HTTPException(
            status_code=404,
            detail=f"No provider configured for model: {model}",
        )
    return provider


def extract_model_from_body(body: bytes) -> str:
    if not body:
        raise HTTPException(status_code=400, detail="Missing required field: model")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON request body") from exc

    model = payload.get("model")
    if not isinstance(model, str) or not model.strip():
        raise HTTPException(status_code=400, detail="Missing required field: model")

    return model
