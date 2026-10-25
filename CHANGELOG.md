# Changelog

All notable changes to AIWall Community are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/). Versions align with `backend/app/__init__.py`.

## [Unreleased]

## [0.2.1] - 2026-10-24

### Added

- Optional `logging.org` label on `aiwall.audit.v1`. The field is omitted when unset.
- Proxy audit writes are queued and committed off the request path.
- `logging.store: none` skips the audit file for lab runs. Profiles and approvals stay in memory.

### Changed

- Streaming output-secret block policies scan SSE as it arrives and stop before the secret reaches the client. HTTP 403 is still returned when the secret appears before any safe text is released.

### Compatibility

- Audit export schema: `aiwall.audit.v1` (unchanged).
- Detection packs targeting this release: AIWall-detections `0.2.1`. The pack still accepts Community `>= 0.2.0`.

## [0.2.0] - 2026-10-11

### Added

- Cross-repo docs drift guard: relative-link checks and detections Wazuh rule-range alignment (`backend/tests/test_doc_drift.py`).
- Prompt-injection / jailbreak keyword classifiers with policy conditions `input.contains_injection` / `input.contains_jailbreak` and audit reasons `injection-detected` / `jailbreak-detected`.
- Closed audit reason `extraction-rate` and rolling-window usage checker (`app/rates`) for model-extraction / high-volume query floods (AML.T0024).
- Proxy enforcement of `rate_limits` (request/token caps over a sliding window) before upstream forward.
- Output DLP: policy condition `output.contains_secret` scans model replies (non-stream and buffered stream) and emits `output-secret-detected`.
- Jailbreak classifier now matches safety-bypass framing such as “safety rules do not apply” (PI-02) without requiring a child category policy.
- Pro navigation dropdown in the Community top bar, shown when `aiwall-pro` is loaded.
- `register_preset_dirs` plugin hook, invoked before `load_config` so plugin preset packs resolve.
- Documentation ownership map (`docs/doc-ownership.md`) with version-alignment tests.
- Local proxy overhead benchmark harness and results (`docs/benchmarks.md`).

### Changed

- `aiwall.yaml.example` and the configuration guide now include output-secret, injection, and jailbreak block policies, matching the Docker examples.
- Policy evaluation now runs before provider routing, so secret blocks no longer depend on upstream model availability.
- Tests honour `AIWALL_SKIP_APP_BOOT` to avoid importing the developer config during collection.

### Fixed

- Hardened approval endpoints, audit reason handling, and upstream auth for model listing.

### Compatibility

- Audit export schema: `aiwall.audit.v1` (unchanged from 0.1.0).
- Detection packs targeting this release: AIWall-detections `0.2.0`.

## [0.1.0] - 2026-08-27

### Added

- OpenAI-compatible proxy with Ollama support, policy engine, secret scanning, and audit logging.
- Family mode, agent guardrails, control panel, and plugin hooks for Pro extensions.
- Stable audit `reason` vocabulary with CI contract test (`app/audit/reasons.py`).
- Configurable upstream credential precedence via `upstream_auth.prefer_provider_key`.

### Compatibility

- Audit export schema: `aiwall.audit.v1`
- Detection packs targeting this release: AIWall-detections `0.1.0`
