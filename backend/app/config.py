# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Load and validate AIWall configuration from aiwall.yaml."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

DEFAULT_CONFIG_PATH = Path("aiwall.yaml")
CONFIG_ENV_VAR = "AIWALL_CONFIG"


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080


class ProviderConfig(BaseModel):
    name: str
    type: str
    base_url: str
    api_key_env: str | None = None
    models: list[str] = Field(default_factory=list)


class PolicyConfig(BaseModel):
    name: str
    when: str
    action: str
    enabled: bool = True


class LoggingConfig(BaseModel):
    store: str = "sqlite:///data/aiwall.db"
    log_raw_prompts: bool = False
    retention_days: int = 90


class PricingConfig(BaseModel):
    file: str = "prices.yaml"


class GatewayAuthConfig(BaseModel):
    enabled: bool = False
    api_key_env: str = "AIWALL_API_KEY"


class UpstreamAuthConfig(BaseModel):
    """Which credential wins when both a provider env key and client Authorization exist."""

    prefer_provider_key: bool = True


class AlertChannelConfig(BaseModel):
    """One alert destination. Channel-specific fields are used by later phases."""

    channel: str
    on: list[str] = Field(default_factory=list)
    enabled: bool = True
    bot_token_env: str | None = None
    chat_id: str | None = None
    url: str | None = None
    topic: str | None = None
    server: str | None = None


class HeartbeatConfig(BaseModel):
    """Periodic upstream provider probes (fires ``provider_error`` on outage)."""

    enabled: bool = False
    interval_seconds: int = 60


class ShellGuardrailConfig(BaseModel):
    """Risk-score thresholds for shell agent actions (inclusive)."""

    # Defaults: warn at medium, block at high, require approval at critical.
    warn_above: int = 40
    block_above: int = 70
    require_approval_above: int = 90


class FileGuardrailConfig(BaseModel):
    """Policy action when a sensitive file path is referenced."""

    # block | warn | require_approval
    action: str = "block"


class AgentGuardrailsConfig(BaseModel):
    """Phase 5 agent tool/command guardrails."""

    enabled: bool = False
    shell: ShellGuardrailConfig = Field(default_factory=ShellGuardrailConfig)
    file: FileGuardrailConfig = Field(default_factory=FileGuardrailConfig)
    # How long a require_approval request waits before timing out (seconds).
    approval_timeout_seconds: int = 60


class CorsConfig(BaseModel):
    """Browser CORS for Open WebUI Direct Connections and similar clients."""

    enabled: bool = False
    allow_origins: list[str] = Field(default_factory=list)
    allow_methods: list[str] = Field(
        default_factory=lambda: ["GET", "POST", "OPTIONS"]
    )
    allow_headers: list[str] = Field(
        default_factory=lambda: ["Authorization", "Content-Type", "OpenAI-Organization"]
    )


class EntropyScannerConfig(BaseModel):
    enabled: bool = True
    min_length: int = 20
    threshold: float = 4.5


class DotenvScannerConfig(BaseModel):
    enabled: bool = True
    min_lines: int = 2
    min_value_length: int = 8
    pasted_file_min_lines: int = 5


class RuleScannerConfig(BaseModel):
    enabled: bool = True
    min_length: int | None = None


class ScannerAllowlistConfig(BaseModel):
    literals: list[str] = Field(default_factory=list)
    patterns: list[str] = Field(default_factory=list)


class ScannerConfig(BaseModel):
    entropy: EntropyScannerConfig = Field(default_factory=EntropyScannerConfig)
    dotenv: DotenvScannerConfig = Field(default_factory=DotenvScannerConfig)
    ignore_examples: bool = True
    allowlist: ScannerAllowlistConfig = Field(default_factory=ScannerAllowlistConfig)
    rules: dict[str, RuleScannerConfig] = Field(default_factory=dict)


class AIWallConfig(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    providers: list[ProviderConfig] = Field(default_factory=list)
    presets: list[str] = Field(default_factory=list)
    policies: list[PolicyConfig] = Field(default_factory=list)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    pricing: PricingConfig = Field(default_factory=PricingConfig)
    gateway_auth: GatewayAuthConfig = Field(default_factory=GatewayAuthConfig)
    upstream_auth: UpstreamAuthConfig = Field(default_factory=UpstreamAuthConfig)
    alerts: list[AlertChannelConfig] = Field(default_factory=list)
    heartbeat: HeartbeatConfig = Field(default_factory=HeartbeatConfig)
    agent_guardrails: AgentGuardrailsConfig = Field(default_factory=AgentGuardrailsConfig)
    cors: CorsConfig = Field(default_factory=CorsConfig)
    scanners: ScannerConfig = Field(default_factory=ScannerConfig)


def resolve_config_path(path: Path | str | None = None) -> Path:
    if path is not None:
        return Path(path)
    env_path = os.environ.get(CONFIG_ENV_VAR)
    if env_path:
        return Path(env_path)
    return DEFAULT_CONFIG_PATH


def load_config(path: Path | str | None = None) -> AIWallConfig:
    config_path = resolve_config_path(path)
    if not config_path.exists():
        return AIWallConfig()

    with config_path.open(encoding="utf-8") as config_file:
        raw: Any = yaml.safe_load(config_file) or {}

    _normalize_yaml_alert_keys(raw)
    _normalize_yaml_null_dicts(raw)

    config = AIWallConfig.model_validate(raw)
    from app.presets.selection import load_preset_selection, preset_selection_path

    selection = load_preset_selection(preset_selection_path(config_path))
    if selection:
        merged_names = list(dict.fromkeys([*config.presets, *selection]))
        config = config.model_copy(update={"presets": merged_names})
    if config.presets:
        from app.presets import merge_preset_policies

        merged_policies = merge_preset_policies(
            config.presets,
            config.policies,
            config_dir=config_path.parent,
        )
        config = config.model_copy(update={"policies": merged_policies})

    from app.policies.overrides import (
        apply_policy_overrides,
        load_policy_overrides,
        policy_overrides_path,
    )
    from app.settings.overrides import (
        apply_settings_overrides,
        load_settings_overrides,
        settings_overrides_path,
    )

    overrides = load_policy_overrides(policy_overrides_path(config_path))
    if overrides:
        config = config.model_copy(
            update={"policies": apply_policy_overrides(config.policies, overrides)}
        )
    settings_overrides = load_settings_overrides(settings_overrides_path(config_path))
    if settings_overrides:
        config = apply_settings_overrides(config, settings_overrides)
    return config


def _normalize_yaml_null_dicts(raw: Any) -> None:
    """PyYAML maps comment-only mappings like ``rules:`` to ``null``."""
    if not isinstance(raw, dict):
        return
    scanners = raw.get("scanners")
    if not isinstance(scanners, dict):
        return
    if scanners.get("rules") is None:
        scanners["rules"] = {}


def _normalize_yaml_alert_keys(raw: Any) -> None:
    """PyYAML maps the unquoted key ``on`` to boolean ``True`` (YAML 1.1)."""
    if not isinstance(raw, dict):
        return
    alerts = raw.get("alerts")
    if not isinstance(alerts, list):
        return
    for entry in alerts:
        if not isinstance(entry, dict):
            continue
        if True in entry and "on" not in entry:
            entry["on"] = entry.pop(True)
        if "triggers" in entry and "on" not in entry:
            entry["on"] = entry.pop("triggers")


def reload_config(app_config_path: Path | str | None) -> AIWallConfig:
    """Reload configuration from disk. Used by future hot-reload paths."""
    return load_config(app_config_path)
