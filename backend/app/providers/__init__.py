# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Provider routing and upstream adapters."""

from app.providers.adapters import (
    OLLAMA,
    OPENAI_COMPATIBLE,
    build_chat_completions_url,
    build_upstream_headers,
)
from app.providers.router import extract_model_from_body, select_provider, try_select_provider

__all__ = [
    "OLLAMA",
    "OPENAI_COMPATIBLE",
    "build_chat_completions_url",
    "build_upstream_headers",
    "extract_model_from_body",
    "select_provider",
    "try_select_provider",
]
