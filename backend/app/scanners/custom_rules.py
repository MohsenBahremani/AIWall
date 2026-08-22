# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Persist custom secret scanner rules (GUI / Pro editor)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.scanners.registry import SecretRuleDef

OVERRIDES_FILENAME = "custom-scanner-rules.yaml"


@dataclass(frozen=True)
class CustomRuleRecord:
    rule_id: str
    pattern: str
    description: str
    enabled: bool = True
    min_length: int | None = None


class CustomRuleError(ValueError):
    pass


def custom_scanner_rules_path(config_path: Path) -> Path:
    data_dir = config_path.parent / "data"
    if data_dir.is_dir():
        return data_dir / OVERRIDES_FILENAME
    return config_path.parent / OVERRIDES_FILENAME


def _parse_records(raw: Any) -> list[CustomRuleRecord]:
    if not isinstance(raw, dict):
        return []
    entries = raw.get("rules")
    if not isinstance(entries, list):
        return []
    records: list[CustomRuleRecord] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        rule_id = str(entry.get("id") or entry.get("rule_id") or "").strip()
        pattern = str(entry.get("pattern") or "").strip()
        description = str(entry.get("description") or rule_id).strip() or rule_id
        if not rule_id or not pattern:
            continue
        enabled = entry.get("enabled", True)
        min_length = entry.get("min_length")
        try:
            default_min = int(min_length) if min_length is not None else None
        except (TypeError, ValueError):
            default_min = None
        records.append(
            CustomRuleRecord(
                rule_id=rule_id,
                pattern=pattern,
                description=description,
                enabled=bool(enabled),
                min_length=default_min,
            )
        )
    return records


def load_custom_rule_records(path: Path) -> list[CustomRuleRecord]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        raw: Any = yaml.safe_load(handle) or {}
    return _parse_records(raw)


def load_custom_secret_rules(path: Path) -> tuple[SecretRuleDef, ...]:
    """Return enabled custom rules as scanner defs (invalid regexes skipped)."""
    rules: list[SecretRuleDef] = []
    for record in load_custom_rule_records(path):
        if not record.enabled:
            continue
        try:
            re.compile(record.pattern)
        except re.error:
            continue
        rules.append(
            SecretRuleDef(
                rule_id=record.rule_id,
                pattern=record.pattern,
                description=record.description,
                default_min_length=record.min_length,
                source="custom",
            )
        )
    return tuple(rules)


def save_custom_rule_records(path: Path, records: list[CustomRuleRecord]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "rules": [
            {
                "id": r.rule_id,
                "pattern": r.pattern,
                "description": r.description,
                "enabled": r.enabled,
                **({"min_length": r.min_length} if r.min_length is not None else {}),
            }
            for r in records
        ]
    }
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(payload, handle, default_flow_style=False, sort_keys=False)
    tmp_path.replace(path)
    return path


def validate_custom_rule(
    *,
    rule_id: str,
    pattern: str,
    description: str = "",
    min_length: int | None = None,
    reserved_ids: frozenset[str] | set[str] = frozenset(),
) -> CustomRuleRecord:
    cleaned_id = rule_id.strip()
    cleaned_pattern = pattern.strip()
    cleaned_desc = (description or cleaned_id).strip() or cleaned_id
    if not cleaned_id:
        raise CustomRuleError("rule id is required")
    if not re.fullmatch(r"[a-z][a-z0-9_-]{1,63}", cleaned_id):
        raise CustomRuleError(
            "rule id must be lowercase, start with a letter, and use [a-z0-9_-]"
        )
    if cleaned_id in reserved_ids:
        raise CustomRuleError(f"rule id {cleaned_id!r} conflicts with a built-in detector")
    if not cleaned_pattern:
        raise CustomRuleError("pattern is required")
    try:
        re.compile(cleaned_pattern)
    except re.error as exc:
        raise CustomRuleError(f"invalid regex: {exc}") from exc
    if min_length is not None and min_length < 1:
        raise CustomRuleError("min_length must be >= 1")
    return CustomRuleRecord(
        rule_id=cleaned_id,
        pattern=cleaned_pattern,
        description=cleaned_desc,
        enabled=True,
        min_length=min_length,
    )
