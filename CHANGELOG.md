# Changelog

All notable changes to AIWall Community are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/). Versions align with `backend/app/__init__.py`.

## [Unreleased]

### Added

- Cross-repo docs drift guard: relative-link checks and detections Wazuh rule-range alignment (`backend/tests/test_doc_drift.py`).
- Prompt-injection / jailbreak keyword classifiers with policy conditions `input.contains_injection` / `input.contains_jailbreak` and audit reasons `injection-detected` / `jailbreak-detected`.
- Pro navigation dropdown in the Community top bar, shown when `aiwall-pro` is loaded.
- `register_preset_dirs` plugin hook, invoked before `load_config` so plugin preset packs resolve.
- Documentation ownership map (`docs/doc-ownership.md`) with version-alignment tests.
- Local proxy overhead benchmark harness and results (`docs/benchmarks.md`).

### Changed

- Policy evaluation now runs before provider routing, so secret blocks no longer depend on upstream model availability.
- Tests honour `AIWALL_SKIP_APP_BOOT` to avoid importing the developer config during collection.

### Fixed

- Hardened approval endpoints, audit reason handling, and upstream auth for model listing.

## [0.1.0] - 2026-08-27

### Added

- OpenAI-compatible proxy with Ollama support, policy engine, secret scanning, and audit logging.
- Family mode, agent guardrails, control panel, and plugin hooks for Pro extensions.
- Stable audit `reason` vocabulary with CI contract test (`app/audit/reasons.py`).
- Configurable upstream credential precedence via `upstream_auth.prefer_provider_key`.

### Compatibility

- Audit export schema: `aiwall.audit.v1`
- Detection packs targeting this release: AIWall-detections `0.1.0`
