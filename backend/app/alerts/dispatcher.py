# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Dispatch alert events to configured channel notifiers."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from app.alerts.base import (
    KNOWN_TRIGGERS,
    TRIGGER_COST_THRESHOLD,
    TRIGGER_DAILY_LIMIT,
    TRIGGER_POLICY_BLOCKED,
    TRIGGER_PROVIDER_ERROR,
    TRIGGER_SECRET_BLOCKED,
    AlertEvent,
    Notifier,
)
from app.alerts.ntfy import DEFAULT_NTFY_SERVER, NtfyNotifier
from app.alerts.registry import AlertNotifierRegistry, NotifierBuildContext
from app.alerts.stub import RecordingNotifier
from app.alerts.telegram import TelegramNotifier
from app.alerts.webhook import WebhookNotifier
from app.config import AIWallConfig, AlertChannelConfig

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _BoundChannel:
    name: str
    triggers: frozenset[str]
    notifier: Notifier


class AlertDispatcher:
    def __init__(self, channels: list[_BoundChannel] | None = None):
        self._channels = list(channels or [])

    @property
    def channel_count(self) -> int:
        return len(self._channels)

    async def dispatch(self, event: AlertEvent) -> None:
        for channel in self._channels:
            if event.trigger not in channel.triggers:
                continue
            try:
                await channel.notifier.send(event)
            except Exception:
                logger.exception(
                    "Alert channel %s failed for trigger %s",
                    channel.name,
                    event.trigger,
                )


def build_alert_dispatcher(
    config: AIWallConfig,
    *,
    http_client=None,
    recording_notifier: RecordingNotifier | None = None,
    extra_notifiers: AlertNotifierRegistry | None = None,
) -> AlertDispatcher:
    """Build a dispatcher from ``alerts:`` config.

    ``channel: stub`` uses an in-memory recorder (tests / dry-run).
    ``channel: telegram`` sends via the Bot API using ``bot_token_env`` + ``chat_id``.
    ``channel: webhook`` POSTs JSON to ``url`` (Discord / Slack / Home Assistant).
    ``channel: ntfy`` publishes to ``server``/``topic`` (defaults to ntfy.sh).
    Additional channels may be registered by plugins via ``extra_notifiers``.
    """
    ctx = NotifierBuildContext(
        http_client=http_client,
        recording_notifier=recording_notifier,
    )
    channels: list[_BoundChannel] = []
    for index, entry in enumerate(config.alerts):
        if not entry.enabled:
            continue
        triggers = _normalize_triggers(entry.on)
        if not triggers:
            logger.warning("Alert channel %s has no valid triggers; skipping", entry.channel)
            continue
        try:
            notifier = _build_notifier(
                entry,
                ctx=ctx,
                extra_notifiers=extra_notifiers,
            )
        except ValueError as exc:
            logger.warning(
                "Alert channel %r misconfigured (index %s): %s",
                entry.channel,
                index,
                exc,
            )
            continue
        if notifier is None:
            logger.warning(
                "Alert channel %r is not implemented yet; skipping (index %s)",
                entry.channel,
                index,
            )
            continue
        channels.append(
            _BoundChannel(
                name=f"{entry.channel}:{index}",
                triggers=triggers,
                notifier=notifier,
            )
        )
    return AlertDispatcher(channels)


def _normalize_triggers(values: list[str]) -> frozenset[str]:
    normalized: set[str] = set()
    for value in values:
        name = value.strip()
        if name in KNOWN_TRIGGERS:
            normalized.add(name)
        else:
            logger.warning("Unknown alert trigger %r; ignoring", value)
    return frozenset(normalized)


def _build_notifier(
    entry: AlertChannelConfig,
    *,
    ctx: NotifierBuildContext,
    extra_notifiers: AlertNotifierRegistry | None = None,
) -> Notifier | None:
    channel = entry.channel.strip().lower()
    if channel == "stub":
        return (
            ctx.recording_notifier
            if ctx.recording_notifier is not None
            else RecordingNotifier()
        )
    if channel == "telegram":
        if not entry.bot_token_env or not entry.chat_id:
            raise ValueError("telegram channel requires bot_token_env and chat_id")
        return TelegramNotifier.from_env(
            bot_token_env=entry.bot_token_env,
            chat_id=entry.chat_id,
            http_client=ctx.http_client,
        )
    if channel == "webhook":
        if not entry.url:
            raise ValueError("webhook channel requires url")
        return WebhookNotifier(url=entry.url, http_client=ctx.http_client)
    if channel == "ntfy":
        if not entry.topic:
            raise ValueError("ntfy channel requires topic")
        return NtfyNotifier(
            topic=entry.topic,
            server=entry.server or DEFAULT_NTFY_SERVER,
            http_client=ctx.http_client,
        )
    if extra_notifiers is not None:
        custom = extra_notifiers.build(channel, entry, ctx)
        if custom is not None:
            return custom
    return None


def triggers_for_block(
    *,
    reason: str | None,
    policy_id: str | None,
    rule_ids: tuple[str, ...] = (),
) -> list[str]:
    """Map a blocked proxy decision to alert trigger names."""
    triggers = [TRIGGER_POLICY_BLOCKED]
    if reason == "secret-detected" or policy_id in {
        "block-secrets",
        "block-child-secrets",
        "block-child-private-keys",
    }:
        triggers.insert(0, TRIGGER_SECRET_BLOCKED)
    elif reason == "private-key-detected":
        triggers.insert(0, TRIGGER_SECRET_BLOCKED)
    if reason == "daily-limit" or policy_id == "daily-limit":
        triggers.append(TRIGGER_DAILY_LIMIT)
    if reason == "cost-budget" or policy_id == "cost-budget":
        triggers.append(TRIGGER_COST_THRESHOLD)
        triggers.append(TRIGGER_DAILY_LIMIT)
    secret_like = any(
        marker in rule_id
        for rule_id in rule_ids
        for marker in ("key", "token", "secret")
    )
    if rule_ids and secret_like and TRIGGER_SECRET_BLOCKED not in triggers:
        triggers.insert(0, TRIGGER_SECRET_BLOCKED)
    return triggers


def triggers_for_warn(*, reason: str | None, policy_id: str | None) -> list[str]:
    if reason and "cost" in reason.lower():
        return [TRIGGER_COST_THRESHOLD]
    if policy_id and "cost" in policy_id.lower():
        return [TRIGGER_COST_THRESHOLD]
    if reason == "cost-budget" or policy_id == "cost-budget":
        return [TRIGGER_COST_THRESHOLD]
    return []


def triggers_for_provider_error() -> list[str]:
    return [TRIGGER_PROVIDER_ERROR]
