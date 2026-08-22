# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Preset discovery and GUI selection (Phase 8.7 community hooks)."""

from __future__ import annotations

from pathlib import Path

from app.config import load_config
from app.presets import (
    clear_extra_preset_dirs,
    list_available_presets,
    load_preset_policies,
    register_preset_dir,
)
from app.presets.selection import (
    load_preset_selection,
    preset_selection_path,
    save_preset_selection,
)


def test_register_preset_dir_loads_extra_pack(tmp_path: Path) -> None:
    clear_extra_preset_dirs()
    pack = tmp_path / "extra"
    pack.mkdir()
    (pack / "home.yaml").write_text(
        """
policies:
  - name: home-block-secrets
    when: input.contains_secret
    action: block
""".strip(),
        encoding="utf-8",
    )
    register_preset_dir(pack)
    try:
        assert "home" in list_available_presets()
        policies = load_preset_policies("home")
        assert policies[0].name == "home-block-secrets"
    finally:
        clear_extra_preset_dirs()


def test_preset_selection_merges_into_config(tmp_path: Path) -> None:
    clear_extra_preset_dirs()
    config = tmp_path / "aiwall.yaml"
    config.write_text(
        """
server:
  port: 8080
presets:
  - developer
policies: []
""".strip(),
        encoding="utf-8",
    )
    save_preset_selection(preset_selection_path(config), ["child"])
    loaded = load_config(config)
    assert loaded.presets == ["developer", "child"]
    assert any(p.name == "warn-secrets" for p in loaded.policies)
    assert any(p.name == "block-child-categories" for p in loaded.policies)


def test_load_preset_selection_missing_is_none(tmp_path: Path) -> None:
    path = preset_selection_path(tmp_path / "aiwall.yaml")
    assert load_preset_selection(path) is None
