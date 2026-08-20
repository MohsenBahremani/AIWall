# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.alerts import (
    AlertEvent,
    RecordingNotifier,
    build_alert_dispatcher,
)
from app.alerts.base import TRIGGER_POLICY_BLOCKED, TRIGGER_SECRET_BLOCKED
from app.alerts.dispatcher import triggers_for_block
from app.config import AIWallConfig, AlertChannelConfig, load_config
from tests.conftest import write_test_config
from tests.test_secret_scanner import _random_aws_key


def test_triggers_for_block_secret() -> None:
    triggers = triggers_for_block(
        reason="secret-detected",
        policy_id="block-secrets",
        rule_ids=("aws-access-key",),
    )
    assert triggers[0] == TRIGGER_SECRET_BLOCKED
    assert TRIGGER_POLICY_BLOCKED in triggers


@pytest.mark.asyncio
async def test_dispatcher_sends_to_stub_for_matching_trigger() -> None:
    recorder = RecordingNotifier()
    config = AIWallConfig(
        alerts=[
            AlertChannelConfig(
                channel="stub",
                on=["secret_blocked"],
            ),
            AlertChannelConfig(
                channel="stub",
                on=["policy_blocked"],
                enabled=False,
            ),
        ]
    )
    dispatcher = build_alert_dispatcher(config, recording_notifier=recorder)

    await dispatcher.dispatch(
        AlertEvent(
            trigger=TRIGGER_SECRET_BLOCKED,
            title="secret",
            message="blocked",
            policy_id="block-secrets",
            reason="secret-detected",
        )
    )
    await dispatcher.dispatch(
        AlertEvent(
            trigger=TRIGGER_POLICY_BLOCKED,
            title="policy",
            message="blocked",
        )
    )

    assert len(recorder.events) == 1
    assert recorder.events[0].trigger == TRIGGER_SECRET_BLOCKED


@pytest.mark.asyncio
async def test_blocked_secret_dispatches_to_stub_notifier(
    tmp_path,
    monkeypatch,
    upstream_mock_handler,
) -> None:
    from app.main import create_app

    monkeypatch.setenv("OPENAI_API_KEY", "upstream-openai-key")
    config_path = write_test_config(
        tmp_path,
        """  - name: block-secrets
    when: input.contains_secret
    action: block""",
        extra_yaml="""
alerts:
  - channel: stub
    on: [secret_blocked, policy_blocked]
""".strip(),
    )
    assert any(a.channel == "stub" for a in load_config(config_path).alerts)

    recorder = RecordingNotifier()
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_mock_handler))
    app = create_app(
        config_path=config_path,
        http_client=http_client,
        recording_notifier=recorder,
    )

    secret = _random_aws_key()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": f"key {secret}"}],
            },
        )

    assert response.status_code == 403
    triggers = {event.trigger for event in recorder.events}
    assert TRIGGER_SECRET_BLOCKED in triggers
    assert TRIGGER_POLICY_BLOCKED in triggers
    assert any(event.policy_id == "block-secrets" for event in recorder.events)
    assert any(event.reason == "secret-detected" for event in recorder.events)
    assert secret not in str(recorder.events)
    await http_client.aclose()


def test_build_alert_dispatcher_supports_plugin_channel() -> None:
    from app.alerts.registry import AlertNotifierRegistry

    registry = AlertNotifierRegistry()
    recorder = RecordingNotifier()
    registry.register("custom", lambda _entry, _ctx: recorder)
    config = AIWallConfig(
        alerts=[AlertChannelConfig(channel="custom", on=["secret_blocked"])]
    )
    dispatcher = build_alert_dispatcher(config, extra_notifiers=registry)
    assert dispatcher.channel_count == 1
