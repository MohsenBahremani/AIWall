# Family mode

Family mode is for **self-hosted chat** you control (Open WebUI, scripts, coding tools). Each household member gets an AIWall **profile** and API key. Policies, daily limits, and audit rows follow that key — not Open WebUI's own user database.

Out of scope: commercial phone apps (ChatGPT, Character.AI, etc.). Those pin TLS and expose no configurable base URL, so AIWall cannot see their traffic — use Screen Time, Family Link, or MDM for on-device limits.

## Concepts

| Concept | Meaning |
|---|---|
| **Profile** | Named identity with a role (`adult`, `child`, `developer`, `guest`) and optional daily caps |
| **Profile API key** | `aiwall_pk_…` Bearer token; only a SHA-256 hash is stored |
| **Admin key** | Shared `AIWALL_API_KEY` when `gateway_auth.enabled: true` (bootstrap / admin; no profile role) |
| **Role** | Exposed to policies as `user.role` |
| **Daily limits** | Optional per-profile caps on requests, tokens, or estimated cost (UTC day) |

## Enable family policies

```yaml
presets:
  - child          # category + secret blocks when user.role == "child"
  - developer      # warn on secrets; block private keys (all roles matching when)

gateway_auth:
  enabled: true
  api_key_env: AIWALL_API_KEY
```

Reference Docker config: `deploy/examples/aiwall.family.yaml`.

### Child preset behavior

When the request is authenticated as a **child** profile:

| Policy | When | Action |
|---|---|---|
| `block-child-categories` | category in `explicit`, `unsafe`, `violence` | block |
| `block-child-secrets` | secret detected | block |
| `block-child-private-keys` | private key detected | block |

Adult / guest / developer profiles are not matched by those `user.role == "child"` rules. Category classification still runs and is stored on the audit row for reports.

### Roles in custom policies

```yaml
policies:
  - name: bedtime-child-block
    when: user.role == "child" and input.length > 8000
    action: block
```

Supported role comparisons: `user.role == "…"` and `user.role != "…"`, combinable with `and`.

## Create a profile and key

```bash
python scripts/issue_profile_key.py \
  --db sqlite:///data/aiwall.db \
  --name Kid \
  --role child \
  --daily-request-limit 40 \
  --daily-token-limit 100000 \
  --daily-cost-limit 1.5
```

In Docker (family stack):

```bash
docker compose -f deploy/examples/docker-compose.open-webui.yml exec aiwall \
  python /app/scripts/issue_profile_key.py \
  --db sqlite:///data/aiwall.db \
  --name Kid \
  --role child \
  --daily-request-limit 40
```

The script prints the plaintext key **once**. Put that key in the chat client's Authorization header (or Open WebUI Direct Connection). Rotating the key invalidates the previous one.

### Daily limit fields

| Field | Unit | Enforcement |
|---|---|---|
| `daily_request_limit` | count | Block when today's billable requests (`allow` / `warn` / `redact`) already meet the cap |
| `daily_token_limit` | tokens | Block when prior tokens are at the cap, or this request's projected tokens would exceed it |
| `daily_cost_limit` | USD | Same pattern using estimated cost |

Unset / `null` means no cap. Window resets at **UTC midnight**. Over-limit responses use `error.reason` / `error.policy` = `daily-limit`.

Admin-key and unauthenticated traffic are not limited (no profile).

## Client setup

```text
Base URL:  http://127.0.0.1:8080/v1
API key:   aiwall_pk_…   (profile key)
```

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer $PROFILE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'
```

Open WebUI walkthrough (Direct Connections, Compose): [open-webui.md](open-webui.md).

## Parent review surfaces

| URL | Purpose |
|---|---|
| `/` | Live dashboard (all events) |
| `/blocked?profile=<id>` | Blocked events for one profile |
| `/reports/weekly` | Per-profile weekly usage / blocks / cost (HTML) |
| `/reports/weekly?format=md` | Same report as Markdown |

Category tags on audit events feed the weekly report and `AuditWriter.category_summary()`.

## What parents can expect

1. Create a child profile and issue a key.
2. Point the child's chat account at AIWall with that key.
3. Risky categories and secrets are blocked for that role; usage can be capped per day.
4. Blocked events and weekly reports attribute traffic to the profile.

## Tests

The suite covers profile CRUD, key auth + audit `user_id`, role DSL, child preset, daily limits, category tagging, blocked review, weekly reports, and an end-to-end family-mode flow in `backend/tests/test_family_mode.py`.

## See also

- [open-webui.md](open-webui.md) — reference Compose + user → key mapping
- [configuration.md](configuration.md) — gateway auth, CORS, presets, limits
- [architecture.md](architecture.md) — request path and endpoints
- `presets/child.yaml` — child policy pack
- `scripts/issue_profile_key.py` — profile / key helper
