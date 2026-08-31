# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
import pytest
from fastapi import HTTPException

from app.config import AIWallConfig, ProviderConfig
from app.providers.adapters import build_chat_completions_url
from app.providers.router import extract_model_from_body, select_provider, try_select_provider


def test_select_provider_routes_openai_model() -> None:
    config = AIWallConfig(
        providers=[
            ProviderConfig(
                name="openai",
                type="openai-compatible",
                base_url="https://api.openai.com/v1",
                models=["gpt-*"],
            ),
            ProviderConfig(
                name="ollama",
                type="ollama",
                base_url="http://localhost:11434",
                models=["llama*"],
            ),
        ]
    )

    provider = select_provider(config, "gpt-4o-mini")
    assert provider.name == "openai"


def test_select_provider_routes_ollama_model() -> None:
    config = AIWallConfig(
        providers=[
            ProviderConfig(
                name="openai",
                type="openai-compatible",
                base_url="https://api.openai.com/v1",
                models=["gpt-*"],
            ),
            ProviderConfig(
                name="ollama",
                type="ollama",
                base_url="http://localhost:11434",
                models=["llama*"],
            ),
        ]
    )

    provider = select_provider(config, "llama3.2:1b")
    assert provider.name == "ollama"


def test_try_select_provider_unknown_model_returns_none() -> None:
    config = AIWallConfig(
        providers=[
            ProviderConfig(
                name="openai",
                type="openai-compatible",
                base_url="https://api.openai.com/v1",
                models=["gpt-*"],
            )
        ]
    )

    assert try_select_provider(config, "unknown-model") is None


def test_select_provider_unknown_model() -> None:
    config = AIWallConfig(
        providers=[
            ProviderConfig(
                name="openai",
                type="openai-compatible",
                base_url="https://api.openai.com/v1",
                models=["gpt-*"],
            )
        ]
    )

    with pytest.raises(HTTPException) as exc_info:
        select_provider(config, "unknown-model")

    assert exc_info.value.status_code == 404


def test_build_chat_completions_url_for_ollama() -> None:
    provider = ProviderConfig(
        name="ollama",
        type="ollama",
        base_url="http://ollama:11434",
        models=["llama*"],
    )

    assert build_chat_completions_url(provider) == "http://ollama:11434/v1/chat/completions"


def test_build_chat_completions_url_for_openai_compatible() -> None:
    provider = ProviderConfig(
        name="openai",
        type="openai-compatible",
        base_url="https://api.openai.com/v1",
        models=["gpt-*"],
    )

    assert build_chat_completions_url(provider) == "https://api.openai.com/v1/chat/completions"


def test_extract_model_from_body() -> None:
    body = b'{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
    assert extract_model_from_body(body) == "gpt-4o-mini"
