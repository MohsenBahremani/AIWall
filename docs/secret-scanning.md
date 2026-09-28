# Secret scanning

AIWall scans outbound chat prompts before they reach a provider, and can scan
**model replies** after the provider responds. Matches feed
`input.contains_secret` / `input.contains_private_key` / `output.contains_secret`
policies and appear in audit rows and the dashboard as privacy-safe `rule_id`
values — never as raw secret strings.

## How it works

1. Message content is extracted from OpenAI-compatible chat payloads (prompts)
   or from completion JSON / SSE deltas (replies).
2. Detectors run in this order:
   - Signature / regex rules
   - `.env` / pasted-config heuristics (`dotenv-secret`)
   - High-entropy token detection (`high-entropy`)
3. Allowlists and documentation-placeholder filters remove known safe values.
4. Policy actions decide what happens next: `warn`, `block`, or `redact`.

## Supported detections

| Rule ID | Description | Category |
|---|---|---|
| `aws-access-key` | AWS access key IDs (`AKIA…`) | Cloud |
| `github-token` | GitHub classic tokens (`ghp_`, `gho_`, …) | SCM |
| `github-fine-grained-token` | GitHub fine-grained PATs (`github_pat_…`) | SCM |
| `slack-token` | Slack tokens (`xoxb-`, `xoxp-`, …) | SaaS |
| `stripe-secret-key` | Stripe secret keys (`sk_live_`, `sk_test_`) | Payments |
| `stripe-restricted-key` | Stripe restricted keys (`rk_live_`, `rk_test_`) | Payments |
| `google-api-key` | Google API keys (`AIza…`) | Cloud |
| `azure-storage-key` | Azure storage account / SAS keys | Cloud |
| `gcp-service-account` | GCP service account JSON (`"type": "service_account"`) | Cloud |
| `database-url` | Database URLs with embedded credentials | Infra |
| `ssh-private-key` | PEM SSH private keys (RSA/OPENSSH/EC/DSA) | Crypto |
| `pkcs8-private-key` | PKCS#8 private keys | Crypto |
| `encrypted-private-key` | Encrypted PEM private keys | Crypto |
| `jwt` | JWT-shaped bearer tokens | Auth |
| `generic-api-key` | `api_key=` / `secret_key=` / `access_token=` assignments | Generic |
| `dotenv-secret` | Pasted `.env` bodies and credential dumps (includes `count`) | Config |
| `high-entropy` | Long high-entropy base64/hex-like strings | Heuristic |

Private-key rules (`ssh-private-key`, `pkcs8-private-key`, `encrypted-private-key`)
also set `input.contains_private_key` for the developer preset.

## Policy actions

| Action | Behavior |
|---|---|
| `warn` | Forward the request; audit as `warn`; add `X-AIWall-Rule-Ids` |
| `block` | HTTP 403 with `rule_ids` in the JSON error body |
| `redact` | Mask matches as `[REDACTED:<rule_id>]`, then forward |

Example developer preset (`presets/developer.yaml`):

```yaml
presets:
  - developer
```

That pack warns on secrets and hard-blocks private keys.

## Configuration

See [configuration.md](configuration.md) for the full `scanners` schema. Common knobs:

```yaml
scanners:
  ignore_examples: true
  entropy:
    enabled: true
    min_length: 20
    threshold: 4.5
  dotenv:
    enabled: true
    min_lines: 2
    min_value_length: 8
    pasted_file_min_lines: 5
  allowlist:
    literals: []
    patterns: []
  rules:
    jwt:
      enabled: false
    generic-api-key:
      min_length: 24
```

## Privacy

- Blocked responses list `rule_ids` only.
- Audit `matched_rule_ids` stores rule ids, never raw credentials.
- When `log_raw_prompts: true`, prompts are masked with `[REDACTED:<rule_id>]` before storage.
- The dashboard event detail shows rule ids and reason; secret values are never rendered.

## Test corpus

| Corpus | Path | Purpose |
|---|---|---|
| Positive | `backend/tests/fixtures/scanner_corpus_positive.py` | One runtime-built sample per `rule_id` |
| Negative | `backend/tests/fixtures/scanner_corpus_negative.txt` | Benign prompts; FP rate must stay ≤ 5% |

CI runs `backend/tests/test_secret_corpus.py`, which asserts:

1. Every `supported_rule_ids()` entry has a positive sample that triggers it.
2. The negative corpus false-positive rate stays within the threshold.

Positive samples are assembled at runtime so the repository does not contain
strings that trip GitHub push protection.

## Related docs

- [configuration.md](configuration.md) — YAML schema and tuning
- [architecture.md](architecture.md) — request flow
- `presets/developer.yaml` — developer guardrail pack
