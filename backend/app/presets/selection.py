# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""GUI / Pro-managed preset selection (additive to aiwall.yaml presets)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

SELECTION_FILENAME = "preset-selection.yaml"


def preset_selection_path(config_path: Path) -> Path:
    data_dir = config_path.parent / "data"
    if data_dir.is_dir():
        return data_dir / SELECTION_FILENAME
    return config_path.parent / SELECTION_FILENAME


def load_preset_selection(path: Path) -> list[str] | None:
    """Return selected preset names, or ``None`` if the file is absent."""
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as handle:
        raw: Any = yaml.safe_load(handle) or {}
    if not isinstance(raw, dict):
        return []
    values = raw.get("presets")
    if not isinstance(values, list):
        return []
    names: list[str] = []
    for item in values:
        if isinstance(item, str) and item.strip():
            names.append(item.strip())
    return names


def save_preset_selection(path: Path, presets: list[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    cleaned = list(dict.fromkeys(name.strip() for name in presets if name.strip()))
    payload = {"presets": cleaned}
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(payload, handle, default_flow_style=False, sort_keys=False)
    tmp_path.replace(path)
    return path
