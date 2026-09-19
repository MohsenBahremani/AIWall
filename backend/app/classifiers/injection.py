# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Keyword detectors for prompt injection and jailbreak probes."""

from __future__ import annotations

import re
from dataclasses import dataclass

# Instruction-override / role-hijack probes (AML.T0051 / PI-01).
_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b"),
    re.compile(r"(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b"),
    re.compile(r"(?i)\bforget\s+(?:all\s+)?(?:your|the)\s+(?:previous\s+)?instructions?\b"),
    re.compile(r"(?i)\boverride\s+(?:your|the)\s+(?:system\s+)?prompt\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+(?:dan|evil|unrestricted|jailbroken)\b"),
    re.compile(r"(?i)\bnew\s+instructions?\s*:\s*"),
)

# Jailbreak persona + meta-prompt extraction (AML.T0054 / AML.T0056 / PI-03).
_JAILBREAK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bdan\b"),
    re.compile(r"(?i)\bdo\s+anything\s+now\b"),
    re.compile(r"(?i)\bjailbreak\b"),
    re.compile(r"(?i)\bdeveloper\s+mode\s+(?:enabled|activated)\b"),
    re.compile(r"(?i)\boutput\s+(?:your|the)\s+(?:full\s+)?system\s+prompt\b"),
    re.compile(
        r"(?i)\breveal\s+(?:your|the)\s+(?:hidden\s+)?(?:system\s+)?(?:prompt|instructions?)\b"
    ),
    re.compile(r"(?i)\bhidden\s+tool\s+schemas?\b"),
    re.compile(r"(?i)\bverbatim\b.*\b(?:system\s+prompt|tool\s+schemas?)\b"),
)


@dataclass(frozen=True)
class InjectionResult:
    contains_injection: bool = False
    contains_jailbreak: bool = False

    @property
    def detected(self) -> bool:
        return self.contains_injection or self.contains_jailbreak


def classify_injection_text(text: str) -> InjectionResult:
    if not text or not text.strip():
        return InjectionResult()
    contains_injection = any(pattern.search(text) for pattern in _INJECTION_PATTERNS)
    contains_jailbreak = any(pattern.search(text) for pattern in _JAILBREAK_PATTERNS)
    return InjectionResult(
        contains_injection=contains_injection,
        contains_jailbreak=contains_jailbreak,
    )


def classify_injection_request_body(body: bytes) -> InjectionResult:
    from app.audit.helpers import extract_prompt_text

    text = extract_prompt_text(body)
    if text is None and body:
        text = body.decode("utf-8", errors="replace")
    return classify_injection_text(text or "")
