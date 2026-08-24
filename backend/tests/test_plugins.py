#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Plugin architecture tests (Phase 8.1)."""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator, Sequence
from pathlib import Path

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

ROOT = Path(__file__).resolve().parents[2]
STUB_ROOT = ROOT / "packages" / "aiwall_plugin_stub"
if str(STUB_ROOT) not in sys.path:
    sys.path.insert(0, str(STUB_ROOT))


@pytest.fixture
def stub_plugin():
    from aiwall_plugin_stub import plugin_factory

    return plugin_factory()


async def _app_client(
    example_config: Path,
    plugins: Sequence | None = None,
) -> AsyncIterator[AsyncClient]:
    mock_transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))
    http_client = httpx.AsyncClient(transport=mock_transport)
    from app.main import create_app

    kwargs = {"config_path": example_config, "http_client": http_client}
    if plugins is not None:
        kwargs["plugins"] = plugins
    app = create_app(**kwargs)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as test_client:
        yield test_client
    await http_client.aclose()


@pytest.mark.asyncio
async def test_core_runs_without_plugins(example_config):
    async for client in _app_client(example_config, plugins=[]):
        health = await client.get("/healthz")
        assert health.status_code == 200
        body = health.json()
        assert body["status"] == "ok"
        assert "plugins" not in body
        stub = await client.get("/plugins/stub/health")
        assert stub.status_code == 404


@pytest.mark.asyncio
async def test_plugin_registers_when_passed_explicitly(example_config, stub_plugin):
    async for client in _app_client(example_config, plugins=[stub_plugin]):
        health = await client.get("/healthz")
        assert health.status_code == 200
        plugins = health.json()["plugins"]
        assert len(plugins) == 1
        assert plugins[0]["name"] == "aiwall-plugin-stub"
        assert plugins[0]["edition"] == "extension"

        stub = await client.get("/plugins/stub/health")
        assert stub.status_code == 200
        assert stub.json()["plugin"] == "aiwall-plugin-stub"


@pytest.mark.asyncio
async def test_discover_plugins_via_entry_point(example_config, monkeypatch):
    from aiwall_plugin_stub import plugin_factory

    from app.main import create_app

    monkeypatch.setattr(
        "app.main.discover_plugins",
        lambda: [plugin_factory()],
    )

    mock_transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=example_config, http_client=http_client)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        health = await client.get("/healthz")
        assert health.status_code == 200
        assert health.json()["plugins"][0]["name"] == "aiwall-plugin-stub"

        stub = await client.get("/plugins/stub/health")
        assert stub.status_code == 200
    await http_client.aclose()


def test_core_package_declares_no_plugin_entry_points():
    """Community core must not register plugins; Pro/stub may exist in a lab venv."""
    from importlib.metadata import PackageNotFoundError, distribution

    from app.plugins.loader import ENTRY_POINT_GROUP

    try:
        dist = distribution("aiwall")
    except PackageNotFoundError:
        pytest.skip("aiwall package metadata not available")

    core_eps = [ep for ep in dist.entry_points if ep.group == ENTRY_POINT_GROUP]
    assert core_eps == [], f"core package must not declare {ENTRY_POINT_GROUP}: {core_eps}"
