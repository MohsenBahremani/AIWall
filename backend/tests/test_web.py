# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
import pytest
from httpx import ASGITransport, AsyncClient

pytest.importorskip("jinja2")


@pytest.mark.asyncio
async def test_dashboard_hides_pro_nav_without_plugins(tmp_path) -> None:
    import httpx

    from app.main import create_app
    from tests.conftest import write_test_config

    config_path = write_test_config(tmp_path, "")
    mock_transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client, plugins=[])

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")

    assert response.status_code == 200
    assert 'href="/pro/profiles"' not in response.text
    assert 'class="nav-pro"' not in response.text
    await http_client.aclose()


@pytest.mark.asyncio
async def test_dashboard_shows_pro_nav_when_pro_plugin_loaded(tmp_path) -> None:
    import httpx

    from app.main import create_app
    from app.plugins.base import PluginInfo
    from tests.conftest import write_test_config

    class _ProStub:
        @property
        def info(self) -> PluginInfo:
            return PluginInfo(name="aiwall-pro", version="0.1.0", edition="pro")

        def register(self, app, *, config) -> None:
            return None

    config_path = write_test_config(tmp_path, "")
    mock_transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client, plugins=[_ProStub()])

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")

    assert response.status_code == 200
    assert 'href="/pro/profiles"' in response.text
    assert 'nav-pro-slot' in response.text
    assert 'nav-dropdown-trigger nav-pro' in response.text
    await http_client.aclose()


@pytest.mark.asyncio
async def test_dashboard_renders_empty_state(tmp_path) -> None:
    import httpx

    from app.main import create_app
    from tests.conftest import write_test_config

    config_path = write_test_config(tmp_path, "")
    mock_transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Recent events" in response.text
    assert "No events yet" in response.text
    await http_client.aclose()


@pytest.mark.asyncio
async def test_dashboard_lists_recent_events(tmp_path, upstream_mock_handler) -> None:
    import httpx

    from app.main import create_app
    from tests.conftest import write_test_config

    config_path = write_test_config(tmp_path, "")
    mock_transport = httpx.MockTransport(upstream_mock_handler)
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        proxied = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hello"}],
            },
        )
        assert proxied.status_code == 200

        response = await client.get("/")

    assert response.status_code == 200
    assert "gpt-4o-mini" in response.text
    assert "badge-allow" in response.text
    # summary panel (1.8b)
    assert "Requests" in response.text
    assert "Allowed" in response.text
    assert "Est. cost" in response.text
    await http_client.aclose()


@pytest.mark.asyncio
async def test_dashboard_secret_event_detail_shows_rule_id_not_secret(
    tmp_path, upstream_mock_handler
) -> None:
    import httpx

    from app.main import create_app
    from tests.conftest import write_test_config
    from tests.test_secret_scanner import _random_aws_key

    config_path = write_test_config(
        tmp_path,
        """  - name: block-secrets
    when: input.contains_secret
    action: block""",
    )
    mock_transport = httpx.MockTransport(upstream_mock_handler)
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client)

    secret = _random_aws_key()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        blocked = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": f"my aws key is {secret}"}],
            },
        )
        assert blocked.status_code == 403

        dashboard = await client.get("/")
        assert dashboard.status_code == 200
        assert "aws-access-key" in dashboard.text
        assert "secret-detected" in dashboard.text
        assert secret not in dashboard.text
        assert "rule-chip" in dashboard.text

        rows = app.state.audit_writer.list_recent(limit=1)
        event_id = rows[0].id
        detail = await client.get(f"/partials/events/{event_id}/detail")

    assert detail.status_code == 200
    assert "aws-access-key" in detail.text
    assert "secret-detected" in detail.text
    assert "block-secrets" in detail.text
    assert "Secret values are never shown" in detail.text
    assert secret not in detail.text
    assert "raw_prompt" not in detail.text
    await http_client.aclose()


@pytest.mark.asyncio
async def test_events_partial_filters_without_full_page(tmp_path, upstream_mock_handler) -> None:
    import httpx

    from app.main import create_app
    from tests.conftest import write_test_config

    config_path = write_test_config(
        tmp_path,
        """  - name: warn-large-cost
    when: estimated_cost > 0.001
    action: warn""",
    )
    mock_transport = httpx.MockTransport(upstream_mock_handler)
    http_client = httpx.AsyncClient(transport=mock_transport)
    app = create_app(config_path=config_path, http_client=http_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        allow_response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hello"}],
            },
        )
        assert allow_response.status_code == 200

        warn_response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 100000,
            },
        )
        assert warn_response.status_code == 200

        partial = await client.get("/partials/events", params={"decision": "warn"})

    assert partial.status_code == 200
    assert "text/html" in partial.headers["content-type"]
    assert "<html" not in partial.text.lower()
    assert "badge-warn" in partial.text
    assert "badge-allow" not in partial.text
    assert 'hx-get="/partials/events"' not in partial.text
    await http_client.aclose()
