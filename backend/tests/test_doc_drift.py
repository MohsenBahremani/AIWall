# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Guard against version and schema doc drift."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
DETECTIONS = REPO.parent / "AIWall-detections"


def test_package_version_matches_runtime() -> None:
    init_text = (BACKEND / "app" / "__init__.py").read_text(encoding="utf-8")
    runtime = re.search(r'__version__\s*=\s*"([^"]+)"', init_text)
    assert runtime is not None
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    packaged = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    assert packaged is not None
    assert runtime.group(1) == packaged.group(1)


def test_changelog_documents_current_version() -> None:
    version = (BACKEND / "app" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', version)
    assert match is not None
    changelog = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"[{match.group(1)}]" in changelog


def test_audit_export_doc_names_schema() -> None:
    doc = (REPO / "docs" / "audit-export.md").read_text(encoding="utf-8")
    assert "aiwall.audit.v1" in doc
    assert "backend/app/audit/reasons.py" in doc


def test_detections_compatibility_matches_schema() -> None:
    if not DETECTIONS.is_dir():
        pytest.skip("AIWall-detections sibling repo not present")
    payload = json.loads(
        (DETECTIONS / "validation" / "compatibility.json").read_text(encoding="utf-8")
    )
    assert payload["audit_schema"] == "aiwall.audit.v1"
    assert payload["core_min_version"] == "0.1.0"
