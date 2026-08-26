# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Aggregate model listings from configured providers."""

from __future__ import annotations

import json
import time
from urllib.parse import urljoin

import httpx

from app.config import AIWallConfig, ProviderConfig
from app.providers.adapters import OLLAMA, OPENAI_COMPATIBLE, build_upstream_headers
from app.providers.router import provider_matches_model
from app.proxy.pricing import CostEstimator


def build_models_list_url(provider: ProviderConfig) -> str | None:
    base_url = provider.base_url.rstrip("/")
    if provider.type == OPENAI_COMPATIBLE:
        return urljoin(f"{base_url}/", "models")
    if provider.type == OLLAMA:
        return f"{base_url}/api/tags"
    return None


def _parse_openai_models(body: bytes) -> list[str]:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if not isinstance(data, list):
        return []
    models: list[str] = []
    for item in data:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            models.append(item["id"])
    return models


def _parse_ollama_models(body: bytes) -> list[str]:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []
    models = payload.get("models")
    if not isinstance(models, list):
        return []
    names: list[str] = []
    for item in models:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            names.append(item["name"])
    return names


def _fallback_model_ids(provider: ProviderConfig, cost_estimator: CostEstimator) -> list[str]:
    return cost_estimator.list_models(provider.name)


async def _fetch_provider_model_ids(
    provider: ProviderConfig,
    http_client: httpx.AsyncClient,
    *,
    incoming_headers: dict[str, str] | None = None,
    prefer_provider_key: bool = True,
) -> list[str]:
    url = build_models_list_url(provider)
    if url is None:
        return []

    headers = build_upstream_headers(
        provider,
        incoming_headers or {},
        prefer_provider_key=prefer_provider_key,
    )
    try:
        response = await http_client.get(url, headers=headers)
    except httpx.RequestError:
        return []

    if response.status_code >= 400:
        return []

    if provider.type == OPENAI_COMPATIBLE:
        return _parse_openai_models(response.content)
    if provider.type == OLLAMA:
        return _parse_ollama_models(response.content)
    return []


def _openai_model_entry(model_id: str, owned_by: str) -> dict[str, str | int]:
    return {
        "id": model_id,
        "object": "model",
        "created": int(time.time()),
        "owned_by": owned_by,
    }


async def list_models(
    config: AIWallConfig,
    http_client: httpx.AsyncClient,
    cost_estimator: CostEstimator,
    *,
    incoming_headers: dict[str, str] | None = None,
) -> dict[str, object]:
    entries: list[dict[str, str | int]] = []
    seen: set[str] = set()
    prefer_provider_key = config.upstream_auth.prefer_provider_key

    for provider in config.providers:
        candidate_ids = await _fetch_provider_model_ids(
            provider,
            http_client,
            incoming_headers=incoming_headers,
            prefer_provider_key=prefer_provider_key,
        )
        if not candidate_ids:
            candidate_ids = _fallback_model_ids(provider, cost_estimator)

        for model_id in candidate_ids:
            if model_id in seen or not provider_matches_model(provider, model_id):
                continue
            seen.add(model_id)
            entries.append(_openai_model_entry(model_id, provider.name))

    entries.sort(key=lambda item: str(item["id"]))
    return {"object": "list", "data": entries}
