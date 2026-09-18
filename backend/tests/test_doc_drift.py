# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Guard against version, schema, and cross-repo docs drift."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
WORKSPACE = REPO.parent
DETECTIONS = WORKSPACE / "AIWall-detections"
REDTEAM = WORKSPACE / "AIWall-redteam"
PRO = WORKSPACE / "AIWall-pro"

_MD_LINK = re.compile(r"\[([^\]]*)\]\(([^)]+)\)")
_WAZUH_RULE_ID = re.compile(r'rule id="(1072\d{2})"')
_ROADMAP_RANGE = re.compile(r"rules\s+(1072\d{2})\s*[–-]\s*(1072\d{2})", re.IGNORECASE)


def _iter_relative_md_links(markdown: str) -> list[str]:
    links: list[str] = []
    for _label, target in _MD_LINK.findall(markdown):
        href = target.strip()
        if not href or href.startswith(("#", "http://", "https://", "mailto:")):
            continue
        path_part = href.split("#", 1)[0].split("?", 1)[0]
        if path_part:
            links.append(path_part)
    return links


def _assert_relative_links_resolve(doc_path: Path, repo_root: Path) -> None:
    text = doc_path.read_text(encoding="utf-8")
    for rel in _iter_relative_md_links(text):
        resolved = (doc_path.parent / rel).resolve()
        assert resolved.exists(), f"{doc_path.relative_to(repo_root)}: broken link -> {rel}"


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


def test_core_readme_relative_links_resolve() -> None:
    _assert_relative_links_resolve(REPO / "README.md", REPO)


def test_core_docs_relative_links_resolve() -> None:
    for path in sorted((REPO / "docs").rglob("*.md")):
        _assert_relative_links_resolve(path, REPO)


def test_detections_compatibility_matches_schema() -> None:
    if not DETECTIONS.is_dir():
        pytest.skip("AIWall-detections sibling repo not present")
    payload = json.loads(
        (DETECTIONS / "validation" / "compatibility.json").read_text(encoding="utf-8")
    )
    assert payload["audit_schema"] == "aiwall.audit.v1"
    assert payload["core_min_version"] == "0.1.0"


def test_detections_roadmap_rule_range_matches_wazuh() -> None:
    if not DETECTIONS.is_dir():
        pytest.skip("AIWall-detections sibling repo not present")
    rules_xml = (DETECTIONS / "wazuh" / "rules" / "aiwall_rules.xml").read_text(
        encoding="utf-8"
    )
    rule_ids = sorted(int(match) for match in _WAZUH_RULE_ID.findall(rules_xml))
    assert rule_ids, "expected AIWall Wazuh alert rules"
    alert_ids = [rule_id for rule_id in rule_ids if rule_id >= 107210]
    roadmap = (DETECTIONS / "docs" / "detection-roadmap.md").read_text(encoding="utf-8")
    range_match = _ROADMAP_RANGE.search(roadmap)
    assert range_match is not None, "detection-roadmap.md must state Wazuh rule range"
    low, high = int(range_match.group(1)), int(range_match.group(2))
    assert low == min(alert_ids)
    assert high == max(alert_ids)


def test_sibling_readme_relative_links_resolve() -> None:
    checked = 0
    for sibling in (DETECTIONS, REDTEAM, PRO):
        readme = sibling / "README.md"
        if not readme.is_file():
            continue
        _assert_relative_links_resolve(readme, sibling)
        checked += 1
    if checked == 0:
        pytest.skip("no sibling repo READMEs present")


def test_doc_ownership_lists_required_owners() -> None:
    ownership = (REPO / "docs" / "doc-ownership.md").read_text(encoding="utf-8")
    for required in (
        "docs/audit-export.md",
        "backend/app/audit/reasons.py",
        "CHANGELOG.md",
        "validation/compatibility.json",
    ):
        assert required in ownership
