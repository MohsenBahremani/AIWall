# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Smoke tests for scripts/load_dotenv.sh."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOAD_DOTENV = ROOT / "scripts" / "load_dotenv.sh"


def _run_loader(env_file: Path, extra_env: dict[str, str] | None = None) -> dict[str, str]:
    # Start from a clean env so a polluted parent process cannot mask .env values.
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "AIWALL_ENV_FILE": str(env_file),
    }
    if extra_env:
        env.update(extra_env)
    # Print selected keys after sourcing so we can assert without polluting the
    # pytest process itself.
    script = f"""
set -euo pipefail
source "{LOAD_DOTENV}"
printf 'AIWALL_DEMO_MODEL=%s\\n' "${{AIWALL_DEMO_MODEL-}}"
printf 'AIWALL_OLLAMA_MODEL=%s\\n' "${{AIWALL_OLLAMA_MODEL-}}"
printf 'OPENAI_API_KEY=%s\\n' "${{OPENAI_API_KEY-}}"
"""
    result = subprocess.run(
        ["bash", "-c", script],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        cwd=str(ROOT),
    )
    assert result.returncode == 0, result.stderr
    out: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            out[key] = value
    return out


def test_load_dotenv_reads_model_vars(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# comment\n"
        "AIWALL_DEMO_MODEL=composer-2.5\n"
        "AIWALL_OLLAMA_MODEL='llama3.2:1b'\n"
        'OPENAI_API_KEY="sk-test"\n'
    )
    values = _run_loader(env_file)
    assert values["AIWALL_DEMO_MODEL"] == "composer-2.5"
    assert values["AIWALL_OLLAMA_MODEL"] == "llama3.2:1b"
    assert values["OPENAI_API_KEY"] == "sk-test"


def test_load_dotenv_does_not_override_existing(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("AIWALL_DEMO_MODEL=from-file\n")
    values = _run_loader(env_file, extra_env={"AIWALL_DEMO_MODEL": "from-shell"})
    assert values["AIWALL_DEMO_MODEL"] == "from-shell"
