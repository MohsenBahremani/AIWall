# Audit export (JSON Lines)

Stable NDJSON schema for SIEM and [AIWall-detections](https://github.com/MohsenBahremani/AIWall-detections) (Phase 6.1).

## Schema id

`aiwall.audit.v1`

One JSON object per line (NDJSON / JSON Lines). No envelope, no summary row.
Raw prompts and responses are never included.

## Download

```http
GET /events/export.jsonl?window_hours=24
```

Same filters as the event explorer: `decision`, `provider`, `model`, `profile`, `window_hours`
(`window_hours=0` means all time).

Content-Type: `application/x-ndjson`.

Dashboard bulk export (`/events/export.json` / `.csv`) remains available for operators;
use **`.jsonl`** for log shipping and detection packs.

## Fields

| Field | Type | Notes |
|---|---|---|
| `schema` | string | Always `aiwall.audit.v1` |
| `id` | integer | SQLite audit row id |
| `timestamp` | string | ISO-8601 UTC |
| `request_id` | string | Per-request correlation id |
| `user_id` | string \| null | Profile id when gateway auth / profile keys are used |
| `provider` | string | Selected upstream provider name |
| `model` | string | Requested model |
| `decision` | string | `allow`, `warn`, `block`, `redact`, `error`, … |
| `reason` | string \| null | Closed vocabulary — see "Reason values" below |
| `policy_id` | string \| null | Policy name when a policy decided the outcome |
| `matched_rule_ids` | string[] | Scanner / guardrail rule ids (empty if none) |
| `categories` | string[] | Content categories (empty if none) |
| `input_length` | integer | Request body size (bytes) |
| `output_length` | integer | Response body size (bytes) |
| `prompt_tokens` | integer \| null | |
| `completion_tokens` | integer \| null | |
| `total_tokens` | integer \| null | |
| `estimated_cost` | number \| null | USD estimate from `prices.yaml` |
| `redaction_count` | integer | Secrets masked when action is `redact` |
| `latency_ms` | number | End-to-end proxy latency |

## Reason values

`reason` is a stable, closed vocabulary so SIEM rules can match on it directly. Raw policy condition text is never emitted.

Canonical list (exact values + dynamic patterns): [`backend/app/audit/reasons.py`](../backend/app/audit/reasons.py) in core, mirrored as [`AIWall-detections/validation/audit_reasons.json`](https://github.com/MohsenBahremani/AIWall-detections/blob/main/validation/audit_reasons.json). CI in both repos asserts new reasons update the contract before merge.

| Reason | Emitted when |
|---|---|
| `proxied` | Request was allowed and forwarded |
| `secret-detected` | A policy on `input.contains_secret` matched |
| `private-key-detected` | A policy on `input.contains_private_key` matched |
| `secret-redacted` | Secrets were masked and the request continued |
| `category-blocked` | A policy on `input.category` matched |
| `cost-threshold` | A policy on `estimated_cost` matched (per-request ceiling) |
| `cost-budget` | A plugin budget checker blocked or warned (rolling day/week/month spend) |
| `length-threshold` | A policy on `input.length` matched |
| `role-policy` | A policy scoped only by `user.role` matched |
| `daily-limit` | A profile hit its configured daily request/token/cost cap |
| `policy-matched` | Fallback for a matched policy whose condition maps to none of the above |
| `approval-denied` | An agent action was held and then denied (or timed out) |
| `shell risk <score> (<band>)` | Agent shell guardrail warn/block; score and band vary |
| `sensitive-file-access:<rule_id>` | Agent touched a path matching a sensitive-file rule |
| `upstream_unreachable` | Provider could not be reached; `decision` is `error` |

The two cost reasons are distinct on purpose: `cost-threshold` is a single expensive request, `cost-budget` is cumulative spend. Detection rules that care about "cost blocked" should match both.

## Example line

```json
{"schema":"aiwall.audit.v1","id":1,"timestamp":"2026-08-08T16:00:00+00:00","request_id":"req-demo","user_id":null,"provider":"openai","model":"gpt-4o-mini","decision":"block","reason":"secret-detected","policy_id":"block-secrets","matched_rule_ids":["aws-access-key"],"categories":[],"input_length":120,"output_length":0,"prompt_tokens":null,"completion_tokens":null,"total_tokens":null,"estimated_cost":null,"redaction_count":0,"latency_ms":3.2}
```

## Compatibility

- Additive fields may appear in a future `aiwall.audit.v2` (new schema id).
- Consumers should ignore unknown fields.
- Detection content: [AIWall-detections `docs/data-sources.md`](https://github.com/MohsenBahremani/AIWall-detections/blob/main/docs/data-sources.md).
