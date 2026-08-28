# AIWall Architecture

This document describes the Community architecture as currently shipped.

## Overview

AIWall is a self-hosted AI security gateway. Client applications send OpenAI-compatible requests to AIWall; AIWall evaluates policies, scans for secrets, logs the decision, and forwards allowed traffic to upstream providers (OpenAI-compatible APIs, Ollama, etc.).

```text
Client (curl, Cursor, Open WebUI, script)
    |
    v
AIWall (FastAPI)
    |
    +-- Policy Engine      allow / warn / block / redact
    +-- Secret Scanner     regex on request body
    +-- Agent Guardrails   shell risk, sensitive files, approvals
    +-- Cost Estimator     prices.yaml + token usage
    +-- Provider Router    model -> provider
    +-- Audit Logger       SQLite
    +-- Web Dashboard      Jinja2 + HTMX at /
    |
    v
Upstream provider (OpenAI, Ollama, ...)
```

## Request flow

1. **Ingress** — `POST /v1/chat/completions` receives the request body and headers (including `Authorization` when present).
2. **Gateway auth** — optional: validate shared `AIWALL_API_KEY` or a per-profile key; profile keys set audit `user_id`.
3. **Model extraction** — the `model` field is parsed from the JSON body.
4. **Provider selection** — the first configured provider whose `models` patterns match the requested model is chosen (`fnmatch` globs such as `gpt-*`, `llama*`).
5. **Category classification** — keyword classifiers derive `input.category` and `input.categories` for family policies.
6. **Policy evaluation** — one bundled step (`ChatProxy._evaluate_policy`) that runs in this order:
   1. **Secret scan** — regex and entropy rules run on message content; results feed `input.contains_secret` and `input.contains_private_key`.
   2. **Cost estimate (pre-forward)** — prompt tokens and `max_tokens` hints estimate cost for `estimated_cost` conditions.
   3. **Policy engine** — policies from `aiwall.yaml` are evaluated in order against the assembled context:
      - `block` on first match stops the request (HTTP 403).
      - `redact` masks matched secrets in the request body, then continues.
      - `warn` is recorded but the request continues.
      - otherwise the request is allowed.
   4. **Agent guardrails** (optional) — tool/shell/file actions are classified; shell risk and sensitive paths can warn, block, or hold for approval. The guardrail verdict is merged with the policy verdict, strictest wins. See [agent-guardrails.md](agent-guardrails.md).
7. **Approval hold** — a `require_approval` verdict parks the request until an operator approves or denies it, or the timeout expires.
8. **Daily limits** — for requests carrying a profile key, projected tokens and cost are checked against that profile's daily allowance; exceeding it blocks with reason `daily-limit`.
9. **Budget checkers** — registered plugins (Pro cost budgets) see the projected tokens and cost and may block or warn with reason `cost-budget`. See [plugins.md](plugins.md).
10. **Redaction** — on a `redact` verdict, matched secrets in the outbound body are masked before forwarding.
11. **Forward** — non-streaming: full upstream response; streaming: SSE chunks passed through to the client.
12. **Audit** — every request writes a row to SQLite (`decision`, `reason`, tokens, estimated cost, latency, redaction count, `user_id`). Agent tool actions are stored in `agent_actions` when present.

Blocked requests never reach the upstream provider. Redacted requests reach the provider with secrets masked.

## Components

| Package | Role |
|---|---|
| `app/proxy/` | OpenAI-compatible forwarding, token/cost accounting |
| `app/policies/` | YAML policy engine with hot reload on each request |
| `app/scanners/` | Regex and entropy-based secret detection |
| `app/classifiers/` | Keyword content-category classification for family policies |
| `app/auth/` | Gateway auth: shared admin key and per-profile API keys |
| `app/profiles/` | Family/user profile model, CRUD storage, and per-profile daily limits |
| `app/presets/` | Bundled policy packs and the additive `preset-selection.yaml` merge |
| `app/settings/` | Runtime setting overrides written from the dashboard (`settings-overrides.yaml`) |
| `app/budgets/` | Budget-checker registry consulted before forwarding (plugin-supplied) |
| `app/providers/` | Provider adapters and model-based routing |
| `app/audit/` | SQLite audit event model and writer |
| `app/agents/` | Agent action model, tool classification, shell risk scoring, sensitive-file monitoring, approval hold/release, dashboard views (Phase 5) |
| `app/storage/` | Database engine and schema migrations |
| `app/reports/` | Family usage reports (weekly per-profile summary) |
| `app/alerts/` | Pluggable alert dispatcher and channel notifiers |
| `app/web/` | Server-rendered dashboard (Jinja2 + HTMX) |
| `app/plugins/` | Entry-point loader for Pro/Enterprise extensions (Phase 8.1) |
| `deploy/examples/` | Docker Compose templates (default + Open WebUI family stack) |
| `app/config.py` | Pydantic models for `aiwall.yaml` |

## Exposed endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/v1/chat/completions` | POST | OpenAI-compatible proxy (streaming and non-streaming) |
| `/v1/models` | GET | Models from configured providers (OpenAI list shape) |
| `/healthz` | GET | Liveness, version, `config_path`, provider/policy/profile counts, `heartbeat_enabled`, `pending_approvals`, `unhealthy_providers`, plus `plugins` for any loaded entry-point plugin |
| `/` | GET | Dashboard — summary cards, usage trends, and recent events |
| `/events` | GET | Event log explorer — filters, pagination, detail |
| `/events/export.json` | GET | Download filtered events + summary as JSON (same query filters as `/events`) |
| `/events/export.csv` | GET | Download filtered events + summary as CSV (same query filters as `/events`) |
| `/events/export.jsonl` | GET | Stable SIEM feed — one `aiwall.audit.v1` object per line (see [audit-export.md](audit-export.md)) |
| `/settings` | GET | Settings — providers (read-only), retention, raw-prompt opt-in |
| `/settings/logging/raw-prompts` | POST | Toggle `logging.log_raw_prompts` via `settings-overrides.yaml` |
| `/settings/logging/retention` | POST | Set `logging.retention_days` and purge expired audit rows |
| `/prompts` | GET | Prompt log viewer (404 unless `logging.log_raw_prompts: true`) |
| `/partials/event-explorer` | GET | HTMX fragment for the event explorer table |
| `/partials/prompts` | GET | HTMX fragment for the prompt log table |
| `/usage` | GET | Model usage — tokens, cost, latency, volume per model/provider |
| `/policies` | GET | Policy management — enable/disable toggles (hot reload) |
| `/policies/{name}/enabled` | POST | Set a policy's `enabled` flag via `policy-overrides.yaml` |
| `/agents` | GET | Agent action log + pending approvals (approve/deny) |
| `/agents/approvals/{id}/approve` | POST | Approve a held agent action from the GUI |
| `/agents/approvals/{id}/deny` | POST | Deny a held agent action from the GUI |
| `/approvals` | GET | JSON approval list; `?status=pending\|approved\|denied\|timed_out\|all` (default `pending`) and `?limit=1..200` (default 50) |
| `/approvals/{id}` | GET | JSON detail for a single approval |
| `/approvals/{id}/approve` | POST | JSON approve (releases held proxy request) |
| `/approvals/{id}/deny` | POST | JSON deny (blocks held proxy request) |
| `/blocked` | GET | Blocked-event review, filterable per profile (`?profile=<id>`) |
| `/reports/weekly` | GET | Weekly family report (HTML; `?format=md` for Markdown) |
| `/partials/events` | GET | HTMX fragment for filtered event table |
| `/partials/blocked` | GET | HTMX fragment for the blocked-event table |
| `/partials/approvals` | GET | HTMX fragment for pending approvals |
| `/partials/agent-actions` | GET | HTMX fragment for the agent action log |
| `/partials/events/{id}/detail` | GET | HTMX fragment for privacy-safe event detail (rule ids, reason) |
| `/partials/policies` | GET | HTMX fragment for the policy table |
| `/partials/settings` | GET | HTMX fragment for the settings panel |
| `/partials/prompts/{event_id}/detail` | GET | HTMX fragment for a single prompt-log entry |
| `/static/*` | GET | Dashboard CSS |

Clients should set their OpenAI base URL to:

```text
http://<aiwall-host>:8080/v1
```

## Streaming (SSE)

- Request bodies are read fully before forwarding so input policies and secret scanning run on the complete prompt.
- Streaming responses pass SSE chunks through to the client.
- Token usage for streams is computed from SSE `delta.content` chunks or a trailing `usage` object when the provider sends one.
- Audit rows for streams are written when the response finishes.

## Data storage

- **Audit events** — SQLite at the path configured in `logging.store` (default `sqlite:///data/aiwall.db`).
- **Agent actions** — `agent_actions` rows linked by `request_id` / `audit_event_id`. Tool/function calls in chat requests are detected and classified as `tool_call`, `shell`, or `file_access`, with `action_target` set to the tool name, command, or path.
- **Pending approvals** — `pending_approvals` rows for held `require_approval` requests; operators decide via `/agents` (GUI) or `/approvals` (JSON API).
- **Configuration** — `aiwall.yaml` on disk; re-read by the policy engine on each evaluation.
- **Pricing** — `prices.yaml` beside the config file (or path set in `pricing.file`).

Raw prompts and responses are **not** stored unless `logging.log_raw_prompts: true`. When enabled, any detected secrets are masked as `[REDACTED:<rule_id>]` before persistence. Block responses list matched `rule_ids` and never echo the raw secret.

Secret detector inventory and the positive/negative test corpus are documented in [secret-scanning.md](secret-scanning.md).

Pro/Enterprise extensions load via setuptools entry points — see [plugins.md](plugins.md).

## Deployment

| Mode | How |
|---|---|
| Docker Compose | `deploy/docker-compose.yml` — recommended |
| Local dev | `./scripts/dev.sh` with Python venv |
| Demo | `./scripts/demo.sh` against a running instance |

The Docker image runs as a non-root `aiwall` user, serves uvicorn on port 8080 (configurable via `AIWALL_PORT`), and bundles a default Docker-oriented config at `/app/aiwall.yaml`.

## Technology stack

- Python 3.12
- FastAPI + uvicorn
- httpx (async upstream proxy)
- SQLAlchemy + SQLite
- Jinja2 + HTMX (dashboard)
- Docker / Docker Compose

## Related repositories

| Repo | Purpose |
|---|---|
| [AIWall-detections](https://github.com/MohsenBahremani/AIWall-detections) | SIEM rules and dashboards |
| [AIWall-redteam](https://github.com/MohsenBahremani/AIWall-redteam) | Adversarial test payloads |
