# AIWall

Self-hosted AI security gateway for homelabs, developers, and teams.

AIWall sits between your apps and AI providers. You get visibility, policy enforcement, secret scanning, audit logging, and cost tracking — on your own hardware, without renting someone else's cloud.

> AIWall is to AI traffic what Firewalla is to home networks.

## Where things stand

The Community gateway is in good shape for day-to-day use: OpenAI-compatible proxy, policies, secret scanning, family profiles, the control panel, alerts, and agent tool guardrails (shell/file risk + approve/deny).

Still in progress:

- Detection packs (Wazuh, Sigma, Grafana) in [AIWall-detections](https://github.com/MohsenBah/AIWall-detections) — audit JSONL schema (`aiwall.audit.v1`) is frozen first
- Red-team payloads and regression checks in [AIWall-redteam](https://github.com/MohsenBah/AIWall-redteam)

## What AIWall does

- Proxies AI API traffic — drop-in OpenAI-compatible endpoint for clients, scripts, and coding tools (Cursor, Claude Code, Continue.dev)
- Scans for secrets — API keys, tokens, SSH keys, pasted `.env` content, before they hit a provider
- Enforces policies — allow, warn, block, or redact; toggle from the GUI
- Guards agent tools — scores shell commands, flags sensitive file access, holds risky actions for approve/deny
- Control panel — dashboard, event log, usage, cost, policies, agent approvals
- Alerts — Telegram, webhook, or ntfy when something risky is blocked (or held for approval)
- Audit log — privacy-preserving by default; raw prompts only if you opt in
- Cost tracking — tokens and estimated spend by provider and model

## What AIWall does not do

AIWall only sees traffic from clients you control — anything with a configurable base URL, or that you self-host. It cannot watch commercial chatbot apps on phones (ChatGPT, Character.AI, Gemini): those pin TLS and give you no endpoint to point here. For on-device app limits, use Screen Time, Family Link, or MDM.

## Family use (self-hosted)

If you run your own AI stack, give household members profiles: a child on Open WebUI (or similar) routed through AIWall gets per-profile policies, daily limits, and usage summaries. You control the client, so no traffic interception is needed.

Details: [docs/family-mode.md](docs/family-mode.md). Compose stack: [docs/open-webui.md](docs/open-webui.md).

## Editions

| Edition | License | Audience |
|---|---|---|
| **AIWall Community** | Apache-2.0 (this repo) | Homelab users, developers, self-hosters |
| **AIWall Pro** | Commercial | Power users, small teams, consultants |
| **AIWall Enterprise** | Commercial | Regulated orgs, security teams |

Community is meant to be useful on its own. Pro and Enterprise ship as separate modules.

## Related repositories

| Repository | Purpose |
|---|---|
| [AIWall](https://github.com/MohsenBah/AIWall) | Core gateway — proxy, policies, control panel |
| [AIWall-detections](https://github.com/MohsenBah/AIWall-detections) | Wazuh / Sigma / Grafana / SIEM content |
| [AIWall-redteam](https://github.com/MohsenBah/AIWall-redteam) | Attack payloads and mitigation checks |

## Quick start (~15 minutes)

Get AIWall running, proxy a request, trigger a secret block, and see it on the dashboard.

### 1. Start AIWall (Docker)

```bash
git clone https://github.com/MohsenBah/AIWall.git
cd AIWall
docker compose -f deploy/docker-compose.yml up --build -d
curl http://127.0.0.1:8080/healthz
```

Optional local Ollama for `llama*` models:

```bash
docker compose -f deploy/docker-compose.yml --profile ollama up --build -d
```

Copy `deploy/.env.example` to `.env` for `OPENAI_API_KEY`, `AIWALL_PORT`, and other secrets.

### 2. Run the demo

```bash
./scripts/demo.sh
```

Sends one normal request and one secret-leak request, then prints recent audit rows. The secret request should return **HTTP 403** with `policy_blocked`.

For a successful **allow** row, set `OPENAI_API_KEY` or use the Ollama profile.

### 3. Open the dashboard

[http://127.0.0.1:8080/](http://127.0.0.1:8080/) — summary cards and a filterable event log.

![AIWall dashboard](docs/screenshots/dashboard.svg)

After the demo you should see at least one **block** with reason `secret-detected`.

### 4. Point a client at AIWall

Base URL:

```text
http://127.0.0.1:8080/v1
```

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'
```

In Cursor / Continue.dev / similar tools, set the OpenAI base URL to that same `/v1` endpoint.

### Local development (no Docker)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp aiwall.yaml.example aiwall.yaml   # optional
cp prices.yaml.example prices.yaml   # optional
./scripts/dev.sh
```

In another terminal:

```bash
curl http://127.0.0.1:8080/healthz
./scripts/demo.sh
```

Audit DB defaults to `data/aiwall.db`.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `AIWALL_CONFIG` | `aiwall.yaml` (local) / `/app/aiwall.yaml` (Docker) | Config file path |
| `AIWALL_PORT` | `8080` | Proxy + dashboard port |
| `OPENAI_API_KEY` | _(unset)_ | Upstream OpenAI-compatible key |
| `AIWALL_API_KEY` | _(unset)_ | Client key when `gateway_auth.enabled: true` |
| `OLLAMA_PORT` | `11434` | Host port with `--profile ollama` |

Providers and policies live in `deploy/examples/aiwall.docker.yaml` (Docker) or `aiwall.yaml` (local). Docker keeps audit data in the `aiwall_data` volume.

## Architecture

```text
AI Application (script, coding tool, Open WebUI, ...)
    |
    v
AIWall Proxy  (/v1/chat/completions, /healthz, dashboard at /)
    |
    +-- Policy Engine
    +-- Secret Scanner
    +-- Agent Guardrails
    +-- Cost Estimator
    +-- Provider Router
    +-- Audit Logger ----> Control panel + alerts
    |
    v
AI Provider (OpenAI-compatible, Ollama, ...)
```

Stack: Python 3.12, FastAPI, SQLite, Jinja2 + HTMX, Docker.

## Configuration

Point clients at:

```text
http://aiwall-host:8080/v1
```

Tune providers and policies in `aiwall.yaml`. Deeper reading:

- [docs/configuration.md](docs/configuration.md) — schema
- [docs/secret-scanning.md](docs/secret-scanning.md) — detectors
- [docs/agent-guardrails.md](docs/agent-guardrails.md) — tool / shell / file guardrails
- [docs/audit-export.md](docs/audit-export.md) — SIEM JSONL (`aiwall.audit.v1`)
- [docs/architecture.md](docs/architecture.md) — request flow

## Contributing

Issues and PRs are welcome. External contributions use a Developer Certificate of Origin (DCO) sign-off — no CLA.

## License

[Apache License 2.0](LICENSE)

## Background

AIWall grew out of work on [MedSecLab](https://github.com/MohsenBah/MedSecLab), a simulated healthcare AI security lab. This repo turns those ideas into something you can run at home or at work.
