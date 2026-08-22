# Plugin architecture (Phase 8.1)

AIWall Community (Apache-2.0) stays a single open core. **Commercial Pro/Enterprise** features ship as **separate private packages** that register through Python [entry points](https://packaging.python.org/en/latest/specifications/entry-points/). None of that paid code belongs in this public repo.

## Contract

Group name: **`aiwall.plugins`**

Each entry point loads a factory callable (or instance) implementing `AIWallPlugin`:

| Member | Purpose |
|---|---|
| `info` | `PluginInfo(name, version, edition)` — listed on `/healthz` |
| `register(app, *, config)` | Mount routes, services, or hooks on the core FastAPI app |
| `register_alert_notifiers(registry, *, config)` *(optional)* | Register custom `alerts[].channel` notifier factories |
| `register_secret_rules(registry, *, config)` *(optional)* | Register extra secret detectors (`SecretRuleDef`) |

Core code lives in `backend/app/plugins/` (`base.py`, `loader.py`). The app factory calls `discover_plugins()` unless tests pass an explicit `plugins=` list to `create_app()`.

### Custom alert channels

Plugins may register additional alert channel types (Pro uses `push`):

```python
def register_alert_notifiers(self, registry, *, config):
    registry.register("push", lambda entry, ctx: MyNotifier(http_client=ctx.http_client))
```

Then reference the channel in `aiwall.yaml`:

```yaml
alerts:
  - channel: push
    on: [secret_blocked, approval_required]
```

### Extra secret detectors

Plugins may register additional regex detectors (Pro ships a premium pack + custom UI):

```python
def register_secret_rules(self, registry, *, config):
    from app.scanners.registry import SecretRuleDef
    registry.register(SecretRuleDef(
        rule_id="openai-api-key",
        pattern=r"\\b(sk-[A-Za-z0-9]{20,})\\b",
        description="OpenAI API key",
        source="premium",
    ))
```

Custom rules persisted by the Pro editor live in `custom-scanner-rules.yaml` next to the config (or under `data/`).

## Commercial packaging (private repo)

1. Create a **separate** private repo or wheel (never commit license-gated code here).
2. Add an entry point in that package’s `pyproject.toml`:

```toml
[project.entry-points."aiwall.plugins"]
pro = "aiwall_pro:plugin_factory"
```

3. Install alongside Community:

```bash
pip install aiwall aiwall-pro   # commercial wheel from your private release
```

4. Restart AIWall — `/healthz` includes `"plugins": [{"name": "...", "version": "...", "edition": "pro"}]`.

## Dev / test stub (public repo only)

`packages/aiwall_plugin_stub/` is an Apache-2.0 **test harness** — not Pro product code. It proves entry points work and exposes `GET /plugins/stub/health` when loaded.

```bash
cd packages/aiwall_plugin_stub
pip install -e .
pytest backend/tests/test_plugins.py -q
```

Or pass the plugin explicitly in tests:

```python
from aiwall_plugin_stub import plugin_factory
create_app(..., plugins=[plugin_factory()])
```

## Open-core rules

- Community must run with **zero** plugins installed.
- Do not add paid-only logic to `backend/app/` — only the plugin loader and protocol.
- Never move a shipped Community feature behind a plugin.

See also: long-term plan Section 20 (licensing) and Phase 8 task 8.1.
