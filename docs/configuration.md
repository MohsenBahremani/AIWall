# AIWall Configuration

AIWall reads a single YAML file (`aiwall.yaml` by default). Override the path with the `AIWALL_CONFIG` environment variable.

## File locations

| Environment | Default config path |
|---|---|
| Local dev | `./aiwall.yaml` (copy from `aiwall.yaml.example`) |
| Docker | `/app/aiwall.yaml` (mount or edit `deploy/examples/aiwall.docker.yaml`) |

Pricing defaults to `prices.yaml` in the same directory as the config file. Copy `prices.yaml.example` to get started.

## Full example

```yaml
server:
  host: 0.0.0.0
  port: 8080

providers:
  - name: ollama
    type: ollama
    base_url: http://127.0.0.1:11434   # Docker Compose: http://ollama:11434
    models: ["llama*", "mistral*", "qwen*"]

  # - name: openai
  #   type: openai-compatible
  #   base_url: https://api.openai.com/v1
  #   api_key_env: OPENAI_API_KEY
  #   models: ["gpt-*", "o1*", "o3*", "o4*"]
  #
  # - name: anthropic
  #   type: openai-compatible
  #   base_url: https://openrouter.ai/api/v1
  #   api_key_env: OPENROUTER_API_KEY
  #   models: ["claude-*", "anthropic/*"]
  #
  # - name: cursor
  #   type: openai-compatible
  #   base_url: https://api.openai.com/v1
  #   api_key_env: CURSOR_API_KEY
  #   models: ["composer-*", "cursor-*"]

policies:
  - name: block-secrets
    when: input.contains_secret
    action: block

  - name: warn-large-cost
    when: estimated_cost > 1.00
    action: warn

logging:
  store: sqlite:///data/aiwall.db
  log_raw_prompts: false
  retention_days: 90

pricing:
  file: prices.yaml

gateway_auth:
  enabled: false
  api_key_env: AIWALL_API_KEY
```

`aiwall.yaml.example` ships with Ollama enabled and OpenAI / Anthropic (via OpenRouter) / Cursor providers commented out — uncomment the ones you use and set the matching key in `.env`.

## Schema reference

### `server`

| Field | Type | Default | Description |
|---|---|---|---|
| `host` | string | `0.0.0.0` | Bind address (uvicorn uses `0.0.0.0` in Docker/dev scripts) |
| `port` | integer | `8080` | Config file port hint; runtime port is set by `AIWALL_PORT` / uvicorn |

### `providers` (list)

Each provider entry:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Identifier used in audit logs and pricing |
| `type` | string | yes | `openai-compatible` or `ollama` |
| `base_url` | string | yes | Upstream API base URL |
| `api_key_env` | string | no | **Name** of the environment variable holding the upstream API key (e.g. `OPENAI_API_KEY`). AIWall loads repo-root `.env` at startup. Do not paste the secret into YAML. When set and present, this key is used for upstream calls and wins over any client `Authorization` header. |
| `models` | list of strings | no | `fnmatch` patterns; first matching provider wins |

**Provider types**

| `type` | Upstream URL built as |
|---|---|
| `openai-compatible` | `{base_url}/chat/completions` |
| `ollama` | `{base_url}/v1/chat/completions` |

**Model routing** — request `model` is matched against each provider's `models` list in file order. Example: `gpt-4o-mini` matches `gpt-*` on the `openai` provider.

### `presets` (list of strings)

Named policy packs merged before explicit `policies`. Shipped presets:

| Name | Behavior |
|---|---|
| `developer` | Warn on `input.contains_secret`; block on `input.contains_private_key` |
| `child` | For `user.role == "child"`: block `explicit`/`unsafe`/`violence` categories; hard-block secrets and private keys |

Community also merges an additive `preset-selection.yaml` (beside the config or under `data/`) whenever the file is present, so presets can be toggled without editing `aiwall.yaml`. Names from that file are appended to `presets`, and the policy engine reloads when its mtime changes.

With **AIWall Pro** installed, additional packs (`home`, `school`, `work`) are available and `/pro/presets` writes that same `preset-selection.yaml` for you.

```yaml
presets:
  - developer
```

Preset files live in `presets/` (and are also packaged under `app/presets/`). Explicit policies with the same `name` override the preset entry.

### `policies` (list)

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | string | yes | Policy ID in audit logs and block responses |
| `when` | string | yes | Condition expression (see below) |
| `action` | string | yes | `allow`, `warn`, `block`, or `redact` |
| `enabled` | boolean | `true` | Skip when `false` |

The control panel at `/policies` can toggle `enabled` without editing `aiwall.yaml`. Toggles are written to `policy-overrides.yaml` (beside the config, or under `data/` when that directory exists) and hot-reloaded on the next request.

**Evaluation order**

1. Enabled policies are scanned in file order (presets first, then explicit policies).
2. First matching `block` stops immediately (HTTP 403).
3. First matching `redact` is remembered; secrets are masked and the request continues.
4. First matching `warn` is remembered; request continues.
5. Precedence is `block` > `redact` > `warn` > `allow`.

**Supported `when` expressions**

| Expression | Meaning |
|---|---|
| `input.contains_secret` | Secret scanner found a match in the request |
| `input.contains_private_key` | Matched rule is an SSH/PKCS#8/encrypted private key |
| `user.role == "child"` | Authenticated profile role equals `child` (also `!=`) |
| `input.category == "explicit"` | Prompt classified into a content category |
| `input.category in ["unsafe", "explicit"]` | Prompt matches any listed category |
| `input.length > N` | Total message character length (comparison operators: `>`, `<`, `>=`, `<=`, `==`) |
| `estimated_cost > N` | Pre-request cost estimate from tokens + `prices.yaml` |

Combine atoms with `and`, for example:

```yaml
when: user.role == "child" and input.category in ["explicit", "unsafe"]
```

`user.role` is set from the profile that owns the Bearer API key. Requests without a profile identity (shared admin key or no auth) have no role, so role conditions do not match.

Built-in categories (keyword classifier): `explicit`, `violence`, `unsafe`.

Every proxied request is classified regardless of policy outcome, and matched categories are stored on the audit row (`categories`, comma-separated). `AuditWriter.category_summary(since=..., user_id=...)` aggregates per-profile per-category counts for reports and the dashboard.

Named presets:

| Preset | Purpose |
|---|---|
| `developer` | Warn on secrets; block private keys |
| `child` | Block risky categories for children; hard-block secrets/private keys for child roles |

Examples:

```yaml
when: input.contains_secret
when: input.length > 50000
when: estimated_cost > 0.50
```

Cost-based policies use a pre-forward estimate (prompt tokens + `max_tokens` / `max_completion_tokens` hint). Actual cost is recorded in the audit log after the response.

### `logging`

| Field | Type | Default | Description |
|---|---|---|---|
| `store` | string | `sqlite:///data/aiwall.db` | SQLite database URL |
| `log_raw_prompts` | boolean | `false` | Store prompt/response text in audit rows (opt-in). Detected secrets are always masked as `[REDACTED:<rule_id>]` before storage. When `true`, the `/prompts` viewer is available and shows a privacy warning banner. Can also be toggled from the Settings page (`settings-overrides.yaml`). |
| `retention_days` | integer | `90` | Delete audit events older than this many days (purged on startup and when retention is saved in Settings). |

### `pricing`

| Field | Type | Default | Description |
|---|---|---|---|
| `file` | string | `prices.yaml` | Path relative to the config file directory |

### `scanners`

| Field | Type | Default | Description |
|---|---|---|---|
| `ignore_examples` | boolean | `true` | Skip known documentation placeholders (e.g. `AKIAIOSFODNN7EXAMPLE`, repetitive `sk_test_` samples) |
| `entropy.enabled` | boolean | `true` | Detect high-entropy base64/hex-like strings |
| `entropy.min_length` | integer | `20` | Minimum candidate token length |
| `entropy.threshold` | float | `4.5` | Shannon entropy threshold (bits per character) |
| `dotenv.enabled` | boolean | `true` | Detect pasted `.env` bodies and credential dumps |
| `dotenv.min_lines` | integer | `2` | Minimum dotenv-style `KEY=value` lines to treat as a block |
| `dotenv.min_value_length` | integer | `8` | Minimum value length for dotenv/assignment lines |
| `dotenv.pasted_file_min_lines` | integer | `5` | Minimum assignment lines for large pasted config dumps |
| `allowlist.literals` | list of strings | `[]` | Exact matched values to ignore |
| `allowlist.patterns` | list of strings | `[]` | Regex patterns; matched secret substrings that match are ignored |
| `rules.<rule_id>.enabled` | boolean | `true` | Enable or disable a specific detector (including `high-entropy`) |
| `rules.<rule_id>.min_length` | integer | rule default | Minimum matched substring length before flagging |

When regex rules do not match, entropy detection flags long random-looking tokens (unknown API key formats). Disable or raise `threshold` if you see false positives.

**False-positive tuning:** set `ignore_examples: true` (default) for docs/tutorials, add project-specific `allowlist` entries, or disable noisy rules under `rules`. The test suite measures false-positive rate on `backend/tests/fixtures/scanner_corpus_negative.txt` and expects ≤ 5% on that corpus.

## `prices.yaml`

```yaml
models:
  openai:
    gpt-4o-mini:
      input_per_million: 0.15
      output_per_million: 0.60
    gpt-4o:
      input_per_million: 2.50
      output_per_million: 10.00
```

Costs are USD per million tokens. Unknown models return `null` estimated cost in audit logs.

### `gateway_auth`

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `false` | Require a client API key before proxying `/v1/*` routes |
| `api_key_env` | string | `AIWALL_API_KEY` | Environment variable holding the expected client key |

When enabled, clients must send `Authorization: Bearer <key>` where `<key>` is either:

- the shared admin key from `AIWALL_API_KEY`, or
- a per-profile key issued via `ProfileStore.issue_api_key()` (prefix `aiwall_pk_`)

The gateway validates the key and does **not** forward it upstream; provider keys still come from each provider's `api_key_env` (e.g. `OPENAI_API_KEY`).

Profile keys are stored as SHA-256 hashes only. A successful profile-authenticated request sets audit `user_id` to the profile id.

Leave disabled for trusted localhost / homelab networks. Enable when exposing AIWall beyond your LAN. Even with auth disabled, presenting a valid profile key still attributes the request to that profile.

**Spend exposure:** With `gateway_auth.enabled: false` and a provider `api_key_env` set, anyone who can reach the port can spend your upstream credits — AIWall substitutes the owner's provider key for every request. Enable gateway auth (or profile keys) on shared hosts. The default upstream behavior uses the provider env key when present; see `upstream_auth` to prefer client-supplied keys instead.

### `upstream_auth`

| Field | Type | Default | Description |
|---|---|---|---|
| `prefer_provider_key` | boolean | `true` | When true, use the provider's `api_key_env` for upstream calls when set. When false, forward the client's `Authorization` header when present and only fall back to the provider key if the client sent none. |

Homelab default (`true`) prevents IDE or demo client keys from clobbering the real upstream credential. Set `false` only when AIWall is a deliberate BYOK relay and clients supply their own provider keys.

### Daily usage limits

Profiles may set optional daily caps:

| Field | Unit | Behavior |
|---|---|---|
| `daily_request_limit` | count | Block after this many billable requests today |
| `daily_token_limit` | tokens | Block when today's tokens (plus projected request) would exceed the cap |
| `daily_cost_limit` | USD | Block when today's estimated cost (plus projected request) would exceed the cap |

`None` / unset means no cap. Billable decisions are `allow`, `warn`, and `redact` (policy blocks and upstream errors do not consume the request quota).

The reset window is the **UTC calendar day** (midnight UTC). Over-limit requests return HTTP 403 with `error.reason` / `error.policy` set to `daily-limit`.

### `cors`

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `false` | Emit CORS headers for browser clients (e.g. Open WebUI Direct Connections) |
| `allow_origins` | string[] | `[]` | Allowed `Origin` values (must be non-empty when enabled) |
| `allow_methods` | string[] | `GET`, `POST`, `OPTIONS` | Allowed methods |
| `allow_headers` | string[] | `Authorization`, `Content-Type`, … | Allowed request headers |

Example for the family Open WebUI stack on port 3000:

```yaml
cors:
  enabled: true
  allow_origins:
    - "http://localhost:3000"
    - "http://127.0.0.1:3000"
```

See [Open WebUI reference](open-webui.md) for the full mapping walkthrough.

### `alerts` (list)

Pluggable notifiers for notable events. Each entry selects a channel and the triggers it listens for.

| Field | Type | Default | Description |
|---|---|---|---|
| `channel` | string | yes | `stub`, `telegram`, `webhook`, `ntfy` |
| `on` | string[] | `[]` | Triggers: `secret_blocked`, `policy_blocked`, `cost_threshold`, `daily_limit`, `provider_error`, `approval_required` |
| `enabled` | boolean | `true` | Skip the channel when `false` |
| `bot_token_env` | string | — | Env var holding the Telegram bot token (`telegram` channel) |
| `chat_id` | string | — | Telegram chat or group id (`telegram` channel) |
| `url` | string | — | Destination URL for `webhook` POSTs (`http://` or `https://`) |
| `topic` | string | — | ntfy topic name (`ntfy` channel) |
| `server` | string | `https://ntfy.sh` | ntfy server base URL (`ntfy` channel; self-host or public) |

```yaml
alerts:
  - channel: stub
    "on": [secret_blocked, policy_blocked]
  - channel: telegram
    bot_token_env: TELEGRAM_BOT_TOKEN
    chat_id: "123456789"
    "on": [secret_blocked, policy_blocked, daily_limit]
  - channel: webhook
    url: https://ha.local/api/webhook/aiwall
    "on": [secret_blocked, policy_blocked]
  - channel: ntfy
    topic: aiwall-alerts
    # server: https://ntfy.home.local   # optional; defaults to https://ntfy.sh
    "on": [secret_blocked, policy_blocked]
```

(Unquoted `on:` is treated as a YAML boolean; quote it or use `triggers:` as an alias.)

Blocked secret leaks emit `secret_blocked` (and `policy_blocked`). Alert payloads never include raw secret values. The Telegram channel POSTs to `https://api.telegram.org/bot<token>/sendMessage`.

Webhook channels POST JSON with structured fields (`source`, `trigger`, `title`, `message`, `policy_id`, `reason`, `rule_ids`, `request_id`, `metadata`) plus Slack-compatible `text` and Discord-compatible `content` strings so Discord, Slack, and Home Assistant incoming webhooks can consume the same payload.

The ntfy channel POSTs plain text to `{server}/{topic}` with `Title`, `Tags`, and `Priority` headers (secret blocks use high priority).

For SIEM-side routing by Wazuh rule id or Loki query name (after `GET /events/export.jsonl`), see [AIWall-detections alert routing](https://github.com/MohsenBahremani/AIWall-detections/blob/main/docs/alert-routing.md).

`provider_error` fires when an upstream provider is unreachable or returns HTTP 5xx during a proxied request, and when optional heartbeat probes first detect an outage (see `heartbeat` below). Point a channel at `provider_error` to get notified of provider downtime.

`approval_required` fires when an agent action is held for human approval (Phase 5.6).

`cost_threshold` fires for both cost mechanisms: a `when: estimated_cost > …` policy in `aiwall.yaml` (reason `cost-threshold`) and a plugin budget block or warn (reason `cost-budget`). See "Cost budgets" below.

### `heartbeat`

Optional background probes of configured providers. On the first failure for a provider, AIWall emits `provider_error` (no repeat alerts while that provider stays unhealthy). Monitor AIWall itself for gateway-down via `GET /healthz` (returns `status: ok` while the process is up; includes `unhealthy_providers` when heartbeat has run).

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `false` | Start the background probe loop |
| `interval_seconds` | integer | `60` | Seconds between probe rounds (minimum effective interval is 5) |

```yaml
heartbeat:
  enabled: true
  interval_seconds: 60

alerts:
  - channel: ntfy
    topic: aiwall-alerts
    "on": [provider_error, secret_blocked]
```

### `agent_guardrails`

Optional shell-command guardrails for agent tool calls. When enabled, AIWall scores shell actions and applies the first matching band (highest severity wins):

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `false` | Enforce shell and file guardrails |
| `approval_timeout_seconds` | integer | `60` | How long a held `require_approval` request waits before timing out |
| `shell.warn_above` | integer | `40` | Warn when risk score ≥ this value |
| `shell.block_above` | integer | `70` | Block when risk score ≥ this value |
| `shell.require_approval_above` | integer | `90` | Hold the request for human approval when risk score ≥ this value |
| `file.action` | string | `block` | Action for sensitive file paths: `block`, `warn`, or `require_approval` |

```yaml
agent_guardrails:
  enabled: true
  approval_timeout_seconds: 60
  shell:
    warn_above: 40
    block_above: 70
    require_approval_above: 90
  file:
    action: block
```

Example: `ls` is low risk (allowed); `rm -rf /tmp/x` is high (blocked); `rm -rf /` is critical and is **held** until an operator approves or denies it (or the timeout fires). File tools that touch `.env`, SSH keys, cloud credential files, kubeconfigs, or similar paths are flagged with reason `sensitive-file-access:<rule_id>`.

Operator guide: [agent-guardrails.md](agent-guardrails.md).

### Approvals API (Phase 5.6)

When a request action is `require_approval`, the proxy creates a pending approval, emits an `approval_required` alert (if configured), and waits.

| Method | Path | Description |
|---|---|---|
| `GET` | `/approvals` | List approvals; see query params below |
| `GET` | `/approvals/{id}` | Fetch one approval (any status) |
| `POST` | `/approvals/{id}/approve` | Approve and release the held request |
| `POST` | `/approvals/{id}/deny` | Deny and return HTTP 403 to the client |

`GET /approvals` query params:

| Param | Values | Default | Description |
|---|---|---|---|
| `status` | `pending`, `approved`, `denied`, `timed_out`, `all` | `pending` | Filter by decision state; anything else returns HTTP 400 |
| `limit` | `1`–`200` | `50` | Maximum rows returned |

Use `status=all` (or a specific decided status) to read approval history rather than just the open queue.

Optional query param `decided_by` on approve/deny records who decided. Denied and timed-out responses include `approval_id` in the JSON body and `X-AIWall-Approval-Id` header.

Operators can also approve or deny from the control panel at `/agents`, which lists pending approvals and the recent agent action log.

### Cost budgets

AIWall has two independent ways to stop expensive requests, and they write different audit reasons.

| Mechanism | Configured in | `policy_id` / `reason` |
|---|---|---|
| Per-request cost ceiling | A `policies` entry with `when: estimated_cost > 1.00` | Your policy `name` / `cost-threshold` |
| Rolling budget (day/week/month) | A plugin budget checker, e.g. AIWall Pro's `/pro/budgets` | `cost-budget` / `cost-budget` |

The per-request ceiling is evaluated by the policy engine alongside every other policy. Rolling budgets run later, just before the request is forwarded, and see the projected tokens and cost for the request plus the spend already recorded for that profile or provider. A budget checker can return `block` (HTTP 403) or `warn` (request proceeds, audited as a warn).

Community ships the registry but no checkers, so rolling budgets are inert until a plugin registers one via `register_budget_checkers` — see [plugins.md](plugins.md).

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `AIWALL_CONFIG` | `aiwall.yaml` | Path to configuration file |
| `AIWALL_PORT` | `8080` | HTTP listen port |
| `OPENAI_API_KEY` | _(unset)_ | Used when a provider sets `api_key_env: OPENAI_API_KEY` |
| `OPENROUTER_API_KEY` | _(unset)_ | Used when a provider sets `api_key_env: OPENROUTER_API_KEY` (Claude via OpenRouter) |
| `CURSOR_API_KEY` | _(unset)_ | Used when a provider sets `api_key_env: CURSOR_API_KEY` |
| `AIWALL_API_KEY` | _(unset)_ | Shared admin client key when `gateway_auth.enabled: true` (profile keys also accepted) |
| `AIWALL_DEMO_MODEL` | _(auto)_ | Model id for `scripts/demo.sh` (overrides auto-detect) |
| `AIWALL_OLLAMA_MODEL` | `llama3.2:1b` | Demo fallback when Ollama is detected |
| `AIWALL_OPENAI_MODEL` | `gpt-4o-mini` | Demo fallback for cloud providers |
| `TELEGRAM_BOT_TOKEN` | _(unset)_ | Bot token when an alert channel sets `bot_token_env: TELEGRAM_BOT_TOKEN` |
| `OLLAMA_PORT` | `11434` | Host port for Ollama in Docker Compose (`--profile ollama`) |

Copy `deploy/.env.example` to `.env` at the repo root. `scripts/dev.sh` and `scripts/demo.sh` load it via `scripts/load_dotenv.sh` without overriding variables already exported in your shell.

Provider-specific keys are read from the environment variable named in `api_key_env`.

## Secret scanner

The built-in scanner runs on request message content. Rules include:

| Rule ID | Detects |
|---|---|
| `aws-access-key` | AWS access key IDs (`AKIA…`) |
| `github-token` | GitHub personal/access tokens |
| `github-fine-grained-token` | GitHub fine-grained tokens |
| `slack-token` | Slack bot/user tokens (`xox…`) |
| `stripe-secret-key` | Stripe secret keys (`sk_live_`, `sk_test_`) |
| `stripe-restricted-key` | Stripe restricted keys (`rk_live_`, `rk_test_`) |
| `google-api-key` | Google API keys (`AIza…`) |
| `azure-storage-key` | Azure storage account keys |
| `gcp-service-account` | GCP service account JSON |
| `database-url` | Database URLs with embedded credentials |
| `ssh-private-key` | PEM SSH private keys |
| `pkcs8-private-key` | PKCS#8 private keys |
| `encrypted-private-key` | Encrypted PEM private keys |
| `jwt` | JSON Web Token shape |
| `generic-api-key` | `api_key=…`, `secret_key=…`, etc. |
| `dotenv-secret` | Pasted `.env` bodies / credential dumps (includes assignment `count`) |
| `high-entropy` | Long high-entropy base64/hex-like strings |

Wire into policy with `when: input.contains_secret` and `action: block` (or `redact` / `warn`).

`action: redact` masks matched secrets in message content as `[REDACTED:<rule_id>]` before forwarding. The audit row uses `decision: redact` and stores `redaction_count`.

### Block / warn privacy

Blocked secret responses are structured and never echo the raw credential:

```json
{
  "error": {
    "message": "Request blocked by AIWall policy: block-secrets",
    "type": "policy_blocked",
    "code": "policy_blocked",
    "policy": "block-secrets",
    "reason": "secret-detected",
    "rule_ids": ["aws-access-key"]
  }
}
```

Warn and redact responses continue to the provider and add privacy-safe headers:

| Header | Meaning |
|---|---|
| `X-AIWall-Policy-Action` | `warn` or `redact` |
| `X-AIWall-Rule-Ids` | Comma-separated matched rule ids |

Audit rows store `matched_rule_ids` (no raw secret values).

### Tuning false positives

- **`ignore_examples`** (default `true`) — skips AWS doc keys, `EXAMPLE` placeholders, and repetitive `sk_test_` / `xoxb-` tutorial values.
- **`allowlist.literals` / `allowlist.patterns`** — project-specific values or regexes to ignore.
- **`rules.<rule_id>`** — disable a detector or raise `min_length` for noisy rules like `generic-api-key`.

The negative corpus at `backend/tests/fixtures/scanner_corpus_negative.txt` is checked in CI; the suite expects a false-positive rate ≤ 5%.

## Client setup

Point any OpenAI-compatible client to AIWall:

```text
Base URL:  http://127.0.0.1:8080/v1
API key:   your upstream key (or `AIWALL_API_KEY` when gateway auth is enabled)
```

Example:

```bash
curl http://127.0.0.1:8080/v1/models
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'
```

## Docker notes

- Bind-mount your config: `./my-aiwall.yaml:/app/aiwall.yaml:ro`
- Audit DB persists in the `aiwall_data` volume at `/app/data/aiwall.db`
- Use `http://ollama:11434` for Ollama when running the `ollama` Compose profile
- See `deploy/.env.example` for port and secret templates
- Family / Open WebUI stack: `deploy/examples/docker-compose.open-webui.yml` + [open-webui.md](open-webui.md)

## See also

- [Family mode](family-mode.md) — profiles, keys, limits, parent review
- [Open WebUI](open-webui.md) — reference Compose + user → key mapping
- [Architecture](architecture.md) — request flow and components
- [Secret scanning](secret-scanning.md) — detectors, privacy, and test corpus
- [README](../README.md) — quick start
- `aiwall.yaml.example` — local development template
- `presets/developer.yaml` — developer guardrail policy pack
- `deploy/examples/aiwall.docker.yaml` — Docker Compose template
- `deploy/examples/docker-compose.open-webui.yml` — Open WebUI + AIWall family stack
