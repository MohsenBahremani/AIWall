# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""SQLite database engine and session management."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.audit.models import Base
from app.config import AIWallConfig


def sqlite_path_from_store(store_url: str) -> Path:
    if not store_url.startswith("sqlite:///"):
        raise ValueError(f"Invalid SQLite store URL: {store_url}")
    path_part = store_url.removeprefix("sqlite:///")
    return Path(path_part)


def audit_persistence_enabled(config: AIWallConfig) -> bool:
    return config.logging.store != "none"


def create_engine_from_config(config: AIWallConfig) -> Engine:
    store_url = config.logging.store
    if store_url == "none":
        # One shared connection so in-memory profiles/approvals stay visible.
        # Audit rows are not written when persistence is off.
        return create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    if not store_url.startswith("sqlite:"):
        raise ValueError(
            f"logging.store must be a sqlite URL or 'none': {store_url}"
        )

    db_path = sqlite_path_from_store(store_url)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(
        store_url,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

    return engine


def init_db(engine: Engine) -> None:
    # Import models so create_all registers every table on Base.metadata.
    from app.agents import approval_models as _approval_models  # noqa: F401
    from app.agents import models as _agent_models  # noqa: F401
    from app.profiles import models as _profile_models  # noqa: F401

    Base.metadata.create_all(engine)
    _migrate_audit_schema(engine)
    _ensure_profiles_table(engine)
    _ensure_agent_actions_table(engine)
    _ensure_pending_approvals_table(engine)


def _migrate_audit_schema(engine: Engine) -> None:
    columns = {
        "prompt_tokens": "INTEGER",
        "completion_tokens": "INTEGER",
        "total_tokens": "INTEGER",
        "redaction_count": "INTEGER DEFAULT 0",
        "matched_rule_ids": "TEXT",
        "categories": "TEXT",
    }
    with engine.connect() as conn:
        existing = {row[1] for row in conn.execute(text("PRAGMA table_info(audit_events)"))}
        for name, col_type in columns.items():
            if name not in existing:
                conn.execute(text(f"ALTER TABLE audit_events ADD COLUMN {name} {col_type}"))
        conn.commit()


def _ensure_profiles_table(engine: Engine) -> None:
    """Create profiles table on existing databases that predate Phase 3.1."""
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
        tables = {row[0] for row in rows}
        if "profiles" in tables:
            return
    Base.metadata.create_all(engine, tables=[Base.metadata.tables["profiles"]])


def _ensure_agent_actions_table(engine: Engine) -> None:
    """Create agent_actions table on existing databases that predate Phase 5.1."""
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
        tables = {row[0] for row in rows}
        if "agent_actions" in tables:
            return
    Base.metadata.create_all(engine, tables=[Base.metadata.tables["agent_actions"]])


def _ensure_pending_approvals_table(engine: Engine) -> None:
    """Create pending_approvals table on existing databases that predate Phase 5.6."""
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
        tables = {row[0] for row in rows}
        if "pending_approvals" in tables:
            return
    Base.metadata.create_all(engine, tables=[Base.metadata.tables["pending_approvals"]])


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)
