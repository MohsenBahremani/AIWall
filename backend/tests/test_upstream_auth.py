# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Tests for app.dotenv_loader and provider upstream auth preference."""

from __future__ import annotations

import os
from pathlib import Path

from app.config import ProviderConfig
from app.dotenv_loader import load_dotenv, reset_dotenv_cache_for_tests
from app.providers.adapters import build_upstream_headers


def test_load_dotenv_into_os_environ(tmp_path: Path, monkeypatch) -> None:
    reset_dotenv_cache_for_tests()
    env_file = tmp_path / ".env"
    env_file.write_text("CURSOR_API_KEY=crsr_from_file\nOPENAI_API_KEY=sk-from-file\n")
    monkeypatch.delenv("CURSOR_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    try:
        loaded = load_dotenv(env_file)
        assert loaded == env_file.resolve()
        assert os.environ["CURSOR_API_KEY"] == "crsr_from_file"
        assert os.environ["OPENAI_API_KEY"] == "sk-from-file"
    finally:
        os.environ.pop("CURSOR_API_KEY", None)
        os.environ.pop("OPENAI_API_KEY", None)


def test_load_dotenv_does_not_override_existing(tmp_path: Path, monkeypatch) -> None:
    reset_dotenv_cache_for_tests()
    env_file = tmp_path / ".env"
    env_file.write_text("OPENAI_API_KEY=from-file\n")
    monkeypatch.setenv("OPENAI_API_KEY", "from-shell")

    load_dotenv(env_file)
    assert os.environ["OPENAI_API_KEY"] == "from-shell"


def test_provider_api_key_env_wins_over_client_authorization(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-provider")
    provider = ProviderConfig(
        name="openai",
        type="openai-compatible",
        base_url="https://api.openai.com/v1",
        api_key_env="OPENAI_API_KEY",
        models=["gpt-*"],
    )
    headers = build_upstream_headers(
        provider,
        {"Authorization": "Bearer crsr_client_should_not_win"},
    )
    assert headers["Authorization"] == "Bearer sk-provider"


def test_client_authorization_used_when_api_key_env_missing(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = ProviderConfig(
        name="openai",
        type="openai-compatible",
        base_url="https://api.openai.com/v1",
        api_key_env="OPENAI_API_KEY",
        models=["gpt-*"],
    )
    headers = build_upstream_headers(
        provider,
        {"Authorization": "Bearer client-passthrough"},
    )
    assert headers["Authorization"] == "Bearer client-passthrough"


def test_client_authorization_used_when_no_api_key_env() -> None:
    provider = ProviderConfig(
        name="openai",
        type="openai-compatible",
        base_url="https://api.openai.com/v1",
        models=["gpt-*"],
    )
    headers = build_upstream_headers(
        provider,
        {"Authorization": "Bearer client-only"},
    )
    assert headers["Authorization"] == "Bearer client-only"


def test_client_authorization_wins_when_prefer_provider_key_false(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-provider")
    provider = ProviderConfig(
        name="openai",
        type="openai-compatible",
        base_url="https://api.openai.com/v1",
        api_key_env="OPENAI_API_KEY",
        models=["gpt-*"],
    )
    headers = build_upstream_headers(
        provider,
        {"Authorization": "Bearer client-passthrough"},
        prefer_provider_key=False,
    )
    assert headers["Authorization"] == "Bearer client-passthrough"
