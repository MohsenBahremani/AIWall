# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Load a repo-root ``.env`` into ``os.environ`` (no third-party dependency).

Values already present in the process environment are never overwritten, so
explicit exports and systemd ``Environment=`` win over the file.
"""

from __future__ import annotations

import os
from pathlib import Path

_LOADED: set[Path] = set()


def find_dotenv(
    *,
    start: Path | None = None,
    explicit: str | None = None,
) -> Path | None:
    """Locate ``.env``: ``AIWALL_ENV_FILE``, then walk up from ``start``/cwd."""
    if explicit:
        path = Path(explicit).expanduser()
        return path if path.is_file() else None
    env_override = os.environ.get("AIWALL_ENV_FILE")
    if env_override:
        path = Path(env_override).expanduser()
        return path if path.is_file() else None

    cursor = (start or Path.cwd()).resolve()
    for candidate in (cursor, *cursor.parents):
        path = candidate / ".env"
        if path.is_file():
            return path
        # Stop at filesystem root / when we leave a plausible project tree.
        if (candidate / "pyproject.toml").is_file() or (candidate / "aiwall.yaml").is_file():
            # Prefer the project dir even if .env is missing.
            break
    # Also check beside the configured aiwall.yaml when AIWALL_CONFIG is set.
    config = os.environ.get("AIWALL_CONFIG")
    if config:
        sibling = Path(config).expanduser().resolve().parent / ".env"
        if sibling.is_file():
            return sibling
    return None


def load_dotenv(
    path: Path | str | None = None,
    *,
    override: bool = False,
) -> Path | None:
    """Parse KEY=VALUE lines into ``os.environ``. Returns the path loaded, if any."""
    env_path = Path(path).expanduser() if path else find_dotenv()
    if env_path is None or not env_path.is_file():
        return None
    resolved = env_path.resolve()
    if resolved in _LOADED and not override:
        return resolved

    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key or not key.replace("_", "").isalnum() or key[0].isdigit():
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if not override and key in os.environ:
            continue
        os.environ[key] = value

    _LOADED.add(resolved)
    return resolved


def reset_dotenv_cache_for_tests() -> None:
    """Test helper: allow the same path to be loaded again."""
    _LOADED.clear()
