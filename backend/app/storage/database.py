# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Database engine and session management.

SQLite is the default. PostgreSQL is selected with a ``postgresql+psycopg://``
store URL (``postgresql://`` and ``postgres://`` are accepted and use psycopg).
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, event, inspect, text
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
    if store_url.startswith("sqlite:"):
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
    if _is_postgres(store_url):
        return create_engine(_postgres_url(store_url), pool_pre_ping=True)
    raise ValueError(
        "logging.store must be a sqlite URL, a postgresql URL, or 'none': "
        f"{store_url}"
    )


def _is_postgres(store_url: str) -> bool:
    return store_url.startswith(("postgresql://", "postgresql+", "postgres://"))


def _postgres_url(store_url: str) -> str:
    """Use the psycopg v3 dialect unless the URL already names one."""
    if store_url.startswith("postgresql+"):
        return store_url
    if store_url.startswith("postgres://"):
        return "postgresql+psycopg://" + store_url.removeprefix("postgres://")
    return "postgresql+psycopg://" + store_url.removeprefix("postgresql://")


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


def _column_names(engine: Engine, table: str) -> set[str]:
    inspector = inspect(engine)
    if not inspector.has_table(table):
        return set()
    return {column["name"] for column in inspector.get_columns(table)}


def _migrate_audit_schema(engine: Engine) -> None:
    columns = {
        "prompt_tokens": "INTEGER",
        "completion_tokens": "INTEGER",
        "total_tokens": "INTEGER",
        "redaction_count": "INTEGER DEFAULT 0",
        "matched_rule_ids": "TEXT",
        "categories": "TEXT",
        "org": "TEXT",
        "organization_slug": "TEXT",
    }
    existing = _column_names(engine, "audit_events")
    if not existing:
        return
    with engine.begin() as conn:
        for name, col_type in columns.items():
            if name not in existing:
                conn.execute(text(f"ALTER TABLE audit_events ADD COLUMN {name} {col_type}"))


def _ensure_table(engine: Engine, name: str) -> None:
    if inspect(engine).has_table(name):
        return
    Base.metadata.create_all(engine, tables=[Base.metadata.tables[name]])


def _ensure_profiles_table(engine: Engine) -> None:
    """Create profiles table on existing databases that predate Phase 3.1."""
    _ensure_table(engine, "profiles")


def _ensure_agent_actions_table(engine: Engine) -> None:
    """Create agent_actions table on existing databases that predate Phase 5.1."""
    _ensure_table(engine, "agent_actions")


def _ensure_pending_approvals_table(engine: Engine) -> None:
    """Create pending_approvals table on existing databases that predate Phase 5.6."""
    _ensure_table(engine, "pending_approvals")


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)
