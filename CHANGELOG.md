# Changelog

All notable changes to AIWall Community are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/). Versions align with `backend/app/__init__.py`.

## [0.1.0] - 2026-08-27

### Added

- OpenAI-compatible proxy with Ollama support, policy engine, secret scanning, and audit logging.
- Family mode, agent guardrails, control panel, and plugin hooks for Pro extensions.
- Stable audit `reason` vocabulary with CI contract test (`app/audit/reasons.py`).
- Configurable upstream credential precedence via `upstream_auth.prefer_provider_key`.

### Compatibility

- Audit export schema: `aiwall.audit.v1`
- Detection packs targeting this release: AIWall-detections `0.1.0`
