# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path

from app.config import load_config


def test_load_config_from_yaml(example_config: Path) -> None:
    config = load_config(example_config)

    assert config.server.host == "127.0.0.1"
    assert config.server.port == 9090
    assert len(config.providers) == 2
    assert config.providers[0].name == "openai"
    assert config.providers[1].name == "ollama"
    assert len(config.policies) == 1
    assert config.logging.log_raw_prompts is False


def test_load_config_defaults_when_missing(tmp_path: Path) -> None:
    config = load_config(tmp_path / "missing.yaml")

    assert config.server.port == 8080
    assert config.providers == []
    assert config.policies == []


def test_load_config_coerces_null_scanner_rules(tmp_path: Path) -> None:
    config_path = tmp_path / "aiwall.yaml"
    config_path.write_text(
        """
scanners:
  rules:
    # comment-only block parses as null in PyYAML
""".strip()
    )
    config = load_config(config_path)
    assert config.scanners.rules == {}
