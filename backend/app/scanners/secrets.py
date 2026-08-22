# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Regex-based secret detection for prompts and request bodies."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from app.config import RuleScannerConfig, ScannerConfig
from app.scanners.allowlist import AllowlistChecker
from app.scanners.dotenv import detect_dotenv_block
from app.scanners.entropy import contains_high_entropy_string, find_high_entropy_tokens
from app.scanners.registry import SecretRuleDef


@dataclass(frozen=True)
class SecretMatch:
    rule_id: str
    description: str
    count: int | None = None


@dataclass(frozen=True)
class ScanResult:
    contains_secret: bool
    matches: tuple[SecretMatch, ...] = ()


@dataclass(frozen=True)
class RedactionResult:
    text: str
    redaction_count: int
    rule_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class BodyRedactionResult:
    body: bytes
    redaction_count: int
    rule_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class _SecretRule:
    rule_id: str
    pattern: re.Pattern[str]
    description: str
    default_min_length: int | None = None


@dataclass(frozen=True)
class _RedactionSpan:
    start: int
    end: int
    rule_id: str


_SECRET_RULES = (
    _SecretRule("aws-access-key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "AWS access key ID"),
    _SecretRule(
        "github-token",
        re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,})\b"),
        "GitHub token",
    ),
    _SecretRule(
        "github-fine-grained-token",
        re.compile(r"\b(github_pat_[A-Za-z0-9_]{20,})\b"),
        "GitHub fine-grained token",
    ),
    _SecretRule(
        "slack-token",
        re.compile(r"\b(xox[abprsb]-[0-9A-Za-z-]{10,})\b"),
        "Slack token",
    ),
    _SecretRule(
        "stripe-secret-key",
        re.compile(r"\b(sk_(?:live|test)_[0-9a-zA-Z]{16,})\b"),
        "Stripe secret key",
    ),
    _SecretRule(
        "stripe-restricted-key",
        re.compile(r"\b(rk_(?:live|test)_[0-9a-zA-Z]{16,})\b"),
        "Stripe restricted key",
    ),
    _SecretRule(
        "google-api-key",
        re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        "Google API key",
    ),
    _SecretRule(
        "azure-storage-key",
        re.compile(r"(?i)((?:AccountKey|SharedAccessKey)=['\"]?[A-Za-z0-9+/=]{40,})"),
        "Azure storage access key",
    ),
    _SecretRule(
        "gcp-service-account",
        re.compile(r'"type"\s*:\s*"service_account"'),
        "GCP service account JSON",
    ),
    _SecretRule(
        "database-url",
        re.compile(
            r"(?i)((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)"
            r"://[^\s:@/]+:[^\s@/]+@)"
        ),
        "Database connection URL with credentials",
    ),
    _SecretRule(
        "ssh-private-key",
        re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )PRIVATE KEY-----"),
        "SSH private key",
    ),
    _SecretRule(
        "pkcs8-private-key",
        re.compile(r"-----BEGIN PRIVATE KEY-----"),
        "PKCS#8 private key",
    ),
    _SecretRule(
        "encrypted-private-key",
        re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----"),
        "Encrypted private key",
    ),
    _SecretRule(
        "jwt",
        re.compile(
            r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"
        ),
        "JSON Web Token",
    ),
    _SecretRule(
        "generic-api-key",
        re.compile(
            r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*"
            r"['\"]?([A-Za-z0-9_\-]{8,})"
        ),
        "Generic API key assignment",
        16,
    ),
)

_HEURISTIC_RULES: tuple[tuple[str, str], ...] = (
    ("dotenv-secret", "Pasted .env / credential file"),
    ("high-entropy", "High-entropy secret-like string"),
)


def supported_rule_ids() -> tuple[str, ...]:
    """Stable rule ids for every detector, including heuristics."""
    return tuple(rule.rule_id for rule in _SECRET_RULES) + tuple(
        rule_id for rule_id, _ in _HEURISTIC_RULES
    )


def rule_catalog() -> tuple[tuple[str, str], ...]:
    """(rule_id, description) pairs for docs and UI."""
    regex_rules = tuple((rule.rule_id, rule.description) for rule in _SECRET_RULES)
    return regex_rules + _HEURISTIC_RULES


def _mask_for_rule(rule_id: str) -> str:
    return f"[REDACTED:{rule_id}]"


def _compile_extra_rules(
    extra_rules: tuple[SecretRuleDef, ...] | list[SecretRuleDef] | None,
) -> tuple[_SecretRule, ...]:
    if not extra_rules:
        return ()
    compiled: list[_SecretRule] = []
    for rule in extra_rules:
        try:
            pattern = rule.compile()
        except re.error:
            continue
        compiled.append(
            _SecretRule(
                rule_id=rule.rule_id,
                pattern=pattern,
                description=rule.description,
                default_min_length=rule.default_min_length,
            )
        )
    return tuple(compiled)


class SecretScanner:
    def __init__(
        self,
        config: ScannerConfig | None = None,
        *,
        extra_rules: tuple[SecretRuleDef, ...] | list[SecretRuleDef] | None = None,
    ):
        self._config = config or ScannerConfig()
        self._allowlist = AllowlistChecker(
            ignore_examples=self._config.ignore_examples,
            allowlist=self._config.allowlist,
        )
        self._extra_rules = _compile_extra_rules(extra_rules)

    @property
    def _all_regex_rules(self) -> tuple[_SecretRule, ...]:
        return _SECRET_RULES + self._extra_rules

    def _rule_config(self, rule_id: str) -> RuleScannerConfig:
        return self._config.rules.get(rule_id, RuleScannerConfig())

    def _rule_enabled(self, rule_id: str) -> bool:
        return self._rule_config(rule_id).enabled

    def _effective_min_length(self, rule: _SecretRule) -> int | None:
        override = self._rule_config(rule.rule_id).min_length
        if override is not None:
            return override
        return rule.default_min_length

    def _match_value(self, match: re.Match[str]) -> str:
        if match.lastindex:
            return match.group(1)
        return match.group(0)

    def _match_span(self, match: re.Match[str]) -> tuple[int, int]:
        if match.lastindex:
            return match.span(1)
        return match.span(0)

    def _is_valid_match(self, rule: _SecretRule, matched: str) -> bool:
        min_length = self._effective_min_length(rule)
        if min_length is not None and len(matched) < min_length:
            return False
        return not self._allowlist.is_allowed(matched)

    def _collect_spans(self, text: str) -> list[_RedactionSpan]:
        spans: list[_RedactionSpan] = []
        for rule in self._all_regex_rules:
            if not self._rule_enabled(rule.rule_id):
                continue
            for match in rule.pattern.finditer(text):
                matched = self._match_value(match)
                if not self._is_valid_match(rule, matched):
                    continue
                start, end = self._match_span(match)
                spans.append(_RedactionSpan(start=start, end=end, rule_id=rule.rule_id))

        dotenv = self._config.dotenv
        if dotenv.enabled and self._rule_enabled("dotenv-secret"):
            detection = detect_dotenv_block(
                text,
                min_lines=dotenv.min_lines,
                min_value_length=dotenv.min_value_length,
                pasted_file_min_lines=dotenv.pasted_file_min_lines,
            )
            for line in detection.lines:
                if self._allowlist.is_allowed(line.value):
                    continue
                spans.append(
                    _RedactionSpan(
                        start=line.start,
                        end=line.end,
                        rule_id="dotenv-secret",
                    )
                )

        entropy = self._config.entropy
        if entropy.enabled and self._rule_enabled("high-entropy"):
            for token in find_high_entropy_tokens(
                text,
                min_length=entropy.min_length,
                threshold=entropy.threshold,
                is_allowed=self._allowlist.is_allowed,
            ):
                start = 0
                while True:
                    index = text.find(token, start)
                    if index < 0:
                        break
                    spans.append(
                        _RedactionSpan(
                            start=index,
                            end=index + len(token),
                            rule_id="high-entropy",
                        )
                    )
                    start = index + len(token)

        return spans

    @staticmethod
    def _apply_spans(text: str, spans: list[_RedactionSpan]) -> RedactionResult:
        if not spans:
            return RedactionResult(text=text, redaction_count=0)

        ordered = sorted(spans, key=lambda span: (span.start, -(span.end - span.start)))
        selected: list[_RedactionSpan] = []
        covered_until = -1
        for span in ordered:
            if span.start < covered_until:
                continue
            selected.append(span)
            covered_until = span.end

        redacted = text
        rule_ids: list[str] = []
        for span in sorted(selected, key=lambda item: item.start, reverse=True):
            redacted = redacted[: span.start] + _mask_for_rule(span.rule_id) + redacted[span.end :]
            rule_ids.append(span.rule_id)

        # rule_ids were appended in reverse order of appearance; restore document order
        rule_ids.reverse()
        return RedactionResult(
            text=redacted,
            redaction_count=len(selected),
            rule_ids=tuple(rule_ids),
        )

    def scan(self, text: str) -> ScanResult:
        if not text:
            return ScanResult(contains_secret=False)

        matches: list[SecretMatch] = []
        for rule in self._all_regex_rules:
            if not self._rule_enabled(rule.rule_id):
                continue
            for match in rule.pattern.finditer(text):
                matched = self._match_value(match)
                if not self._is_valid_match(rule, matched):
                    continue
                matches.append(SecretMatch(rule_id=rule.rule_id, description=rule.description))
                break

        dotenv = self._config.dotenv
        if dotenv.enabled and self._rule_enabled("dotenv-secret"):
            detection = detect_dotenv_block(
                text,
                min_lines=dotenv.min_lines,
                min_value_length=dotenv.min_value_length,
                pasted_file_min_lines=dotenv.pasted_file_min_lines,
            )
            if detection.detected:
                allowed_lines = [
                    line
                    for line in detection.lines
                    if not self._allowlist.is_allowed(line.value)
                ]
                if allowed_lines:
                    count = len(allowed_lines)
                    matches.append(
                        SecretMatch(
                            rule_id="dotenv-secret",
                            description=f"Pasted .env / credential file ({count} assignments)",
                            count=count,
                        )
                    )

        entropy = self._config.entropy
        if entropy.enabled and self._rule_enabled("high-entropy"):
            if contains_high_entropy_string(
                text,
                min_length=entropy.min_length,
                threshold=entropy.threshold,
                is_allowed=self._allowlist.is_allowed,
            ):
                matches.append(
                    SecretMatch(
                        rule_id="high-entropy",
                        description="High-entropy secret-like string",
                    )
                )

        return ScanResult(contains_secret=bool(matches), matches=tuple(matches))

    def redact(self, text: str) -> RedactionResult:
        if not text:
            return RedactionResult(text=text, redaction_count=0)
        return self._apply_spans(text, self._collect_spans(text))


def scan_request_body(
    body: bytes,
    scanner_config: ScannerConfig | None = None,
    *,
    extra_rules: tuple[SecretRuleDef, ...] | list[SecretRuleDef] | None = None,
) -> ScanResult:
    from app.audit.helpers import extract_prompt_text

    text = extract_prompt_text(body)
    if text is None and body:
        text = body.decode("utf-8", errors="replace")
    return SecretScanner(scanner_config, extra_rules=extra_rules).scan(text or "")


def redact_request_body(
    body: bytes,
    scanner_config: ScannerConfig | None = None,
    *,
    extra_rules: tuple[SecretRuleDef, ...] | list[SecretRuleDef] | None = None,
) -> BodyRedactionResult:
    scanner = SecretScanner(scanner_config, extra_rules=extra_rules)
    if not body:
        return BodyRedactionResult(body=body, redaction_count=0)

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        result = scanner.redact(body.decode("utf-8", errors="replace"))
        return BodyRedactionResult(
            body=result.text.encode("utf-8"),
            redaction_count=result.redaction_count,
            rule_ids=result.rule_ids,
        )

    if not isinstance(payload, dict):
        return BodyRedactionResult(body=body, redaction_count=0)

    messages = payload.get("messages")
    if not isinstance(messages, list):
        return BodyRedactionResult(body=body, redaction_count=0)

    total_count = 0
    all_rule_ids: list[str] = []
    changed = False
    for message in messages:
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str):
            result = scanner.redact(content)
            if result.redaction_count:
                message["content"] = result.text
                total_count += result.redaction_count
                all_rule_ids.extend(result.rule_ids)
                changed = True
        elif isinstance(content, list):
            for part in content:
                if not isinstance(part, dict):
                    continue
                text = part.get("text")
                if not isinstance(text, str):
                    continue
                result = scanner.redact(text)
                if result.redaction_count:
                    part["text"] = result.text
                    total_count += result.redaction_count
                    all_rule_ids.extend(result.rule_ids)
                    changed = True

    if not changed:
        return BodyRedactionResult(body=body, redaction_count=0)

    return BodyRedactionResult(
        body=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        redaction_count=total_count,
        rule_ids=tuple(all_rule_ids),
    )
