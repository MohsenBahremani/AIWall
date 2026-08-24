# Agent guardrails

AIWall inspects OpenAI-compatible chat requests for **agent tool calls** (shell
commands, file access, and generic tools). When `agent_guardrails` is enabled,
risky actions can be warned, blocked, or held for human approval.

## How it works

1. Tool / function-call payloads are extracted from the request body.
2. Each call is classified as `tool_call`, `shell`, or `file_access`.
3. Shell targets are scored by the command risk engine.
4. File targets are checked against sensitive-path patterns.
5. The most severe guardrail result is merged with YAML policies and applied:
   - `warn` — forward; audit as warn
   - `block` — HTTP 403 immediately
   - `require_approval` — hold until approve / deny / timeout

Actions are also written to the `agent_actions` audit table for review on
`/agents`.

## Enable

```yaml
agent_guardrails:
  enabled: true
  approval_timeout_seconds: 60
  shell:
    warn_above: 40
    block_above: 70
    require_approval_above: 90
  file:
    action: block   # block | warn | require_approval
```

Guardrails are **off by default**. Full field reference:
[configuration.md](configuration.md#agent_guardrails).

## Shell risk scoring

`score_shell_command` returns a score `0–100` and a level:

| Level | Score |
|---|---|
| `low` | 0–39 |
| `medium` | 40–69 |
| `high` | 70–89 |
| `critical` | 90–100 |

Thresholds in config are inclusive (`score >= N`). Evaluation order is
`require_approval` → `block` → `warn`, so the highest matching band wins.

### Examples (defaults)

| Command | Typical score | Default action |
|---|---|---|
| `ls`, `pwd`, `cat …` | ~5 (low) | allow |
| Unknown / unrecognized | ~35 (low) | allow |
| `sudo …` | ~55 (medium) | warn |
| `rm -rf /tmp/workdir` | ~85 (high) | block |
| `rm -rf /` or `curl … \| bash` | ~90–100 (critical) | require approval |

### Notable shell rules

| Rule ID | What it catches |
|---|---|
| `rm-rf-root` | Recursive force delete of `/`, `/home`, `/etc`, etc. |
| `rm-rf` | Recursive force delete of other paths |
| `curl-pipe-shell` | `curl`/`wget` piped into `sh`/`bash` |
| `mkfs` / `dd-device` / `wipefs` | Disk format / raw device wipe |
| `fork-bomb` | Classic bash fork bomb |
| `shutdown-reboot` | `shutdown`, `reboot`, `poweroff`, `halt` |
| `kill-init` | Signals to PID 1 / init |
| `chmod-777-recursive` | Recursive world-writable mode |
| `sudo` | Elevated privileges |
| `safe-read-only` | Common informational commands (`ls`, `grep`, …) |

## Sensitive file access

File-access tools (for example `read_file` with a path argument) are matched
against path patterns. Hits use reason `sensitive-file-access:<rule_id>`.

| Rule ID | Paths |
|---|---|
| `dotenv-file` | `.env`, `.env.*`, `*.env` |
| `aws-credentials` | `.aws/credentials`, `.aws/config` |
| `gcp-service-account` | `*service*account*.json`, `*-key.json` |
| `ssh-private-key` | `.ssh/id_rsa`, `id_ed25519`, … |
| `private-key-file` | `*.pem`, `*.p12`, `*private*key*` |
| `kubeconfig` | `.kube/config`, `kubeconfig*` |
| `docker-config` | `.docker/config.json` |
| `secrets-store` | `secrets.yaml`, `credentials.json`, … |
| `prod-config` | production-named config files |
| `etc-shadow` | `/etc/shadow`, `/etc/gshadow` |
| `netrc-npmrc` | `.netrc`, `.npmrc`, `.pypirc` |
| `git-credentials` | `.git-credentials` |

`file.action` applies to any sensitive hit (`block` by default).

## Approval workflow

When the effective action is `require_approval`:

1. AIWall creates a `pending_approvals` row and optionally emits an
   `approval_required` alert.
2. The client request **waits** (up to `approval_timeout_seconds`, default 60).
3. An operator decides:
   - **Approve** — request continues to the upstream provider
   - **Deny** — client gets HTTP 403 (`approval-denied`) with `approval_id`
   - **Timeout** — client gets HTTP 403 (`approval-timeout`)

### Decide from the GUI

Open **Agents** (`/agents`):

- Pending approvals table with **Approve** / **Deny**
- Agent action log (filter by `tool_call` / `shell` / `file_access`)

### Decide via JSON API

| Method | Path |
|---|---|
| `GET` | `/approvals?status=pending` |
| `GET` | `/approvals/{id}` |
| `POST` | `/approvals/{id}/approve` |
| `POST` | `/approvals/{id}/deny` |

`status` also accepts `approved`, `denied`, `timed_out`, and `all` for reading
history, with `limit` (1–200, default 50) controlling how many rows come back.

Optional query param on approve/deny: `decided_by`. Denied / timed-out responses
include `approval_id` and header `X-AIWall-Approval-Id`.

## Alerts

Subscribe a channel to `approval_required` to be notified when a request is
held:

```yaml
alerts:
  - channel: ntfy
    topic: aiwall-alerts
    "on": [approval_required, secret_blocked]
```

## Audit and dashboard

| Store | Contents |
|---|---|
| `agent_actions` | Classified tool/shell/file actions per `request_id` |
| `pending_approvals` | Held approval state (`pending` / `approved` / `denied` / `timed_out`) |
| Audit events | Proxy decisions (`allow` / `warn` / `block` / …) including deny/timeout reasons |

Control panel entry points: `/agents`, plus the usual event log at `/events`.

## Tests

The suite covers scoring, policy bands, sensitive files, hold/approve/deny, and
the GUI:

| Module | Focus |
|---|---|
| `backend/tests/test_command_risk.py` | `rm -rf /` critical; `ls` low |
| `backend/tests/test_shell_guardrails.py` | warn / block / require-approval bands |
| `backend/tests/test_sensitive_files.py` | path patterns and proxy blocks |
| `backend/tests/test_approvals.py` | hold, approve, deny, timeout, alert |
| `backend/tests/test_agents_dashboard.py` | GUI approve/deny releases or blocks |
| `backend/tests/test_agent_actions.py` | extraction + persistence |

```bash
.venv/bin/pytest backend/tests/test_command_risk.py \
  backend/tests/test_shell_guardrails.py \
  backend/tests/test_sensitive_files.py \
  backend/tests/test_approvals.py \
  backend/tests/test_agents_dashboard.py \
  backend/tests/test_agent_actions.py -q
```

## Related docs

- [configuration.md](configuration.md#agent_guardrails) — YAML schema
- [architecture.md](architecture.md) — package layout and HTTP routes
- [secret-scanning.md](secret-scanning.md) — prompt secret detectors (separate from agent tools)
