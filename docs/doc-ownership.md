# Documentation ownership

Single source of truth for cross-repo facts. When a claim appears elsewhere, link here instead of copying.

| Fact | Owning file |
|---|---|
| Audit export schema and `reason` vocabulary | [`docs/audit-export.md`](audit-export.md) + [`backend/app/audit/reasons.py`](../backend/app/audit/reasons.py) |
| Gateway auth and spend exposure | [`docs/configuration.md`](configuration.md) (`gateway_auth`, `upstream_auth`) |
| Plugin hooks and budget registry | [`docs/plugins.md`](plugins.md) |
| Family mode and profile keys | [`docs/family-mode.md`](family-mode.md) |
| Detection sample corpus and reason contract mirror | [AIWall-detections `validation/audit_reasons.json`](https://github.com/MohsenBahremani/AIWall-detections/blob/main/validation/audit_reasons.json) |
| Core ↔ detection pack compatibility | [AIWall-detections `validation/compatibility.json`](https://github.com/MohsenBahremani/AIWall-detections/blob/main/validation/compatibility.json) |
| Release history | [`CHANGELOG.md`](../CHANGELOG.md) |
| Package version | [`pyproject.toml`](../pyproject.toml) and [`backend/app/__init__.py`](../backend/app/__init__.py) |
| Pro plugin version | [AIWall-pro `pyproject.toml`](https://github.com/MohsenBahremani/AIWall-pro/blob/main/pyproject.toml) and `plugin.info.version` |

CI checks version alignment via `backend/tests/test_doc_drift.py`.
