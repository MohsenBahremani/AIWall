# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""PostgreSQL store URL and dialect-neutral audit insert."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text

from app.audit.writer import AuditEvent, AuditWriter, audit_insert_sql
from app.config import AIWallConfig, LoggingConfig
from app.storage.database import (
    _migrate_audit_schema,
    create_engine_from_config,
    init_db,
)


def test_sqlite_migration_adds_a_missing_column(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'old.db').as_posix()}")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE audit_events (id INTEGER PRIMARY KEY)"))
    _migrate_audit_schema(engine)
    names = {column["name"] for column in inspect(engine).get_columns("audit_events")}
    assert "org" in names
    assert "prompt_tokens" in names


def test_unknown_store_is_rejected() -> None:
    config = AIWallConfig(logging=LoggingConfig(store="mysql://localhost/aiwall"))
    with pytest.raises(ValueError, match="logging.store"):
        create_engine_from_config(config)


def test_postgres_url_selects_the_postgres_dialect() -> None:
    pytest.importorskip("psycopg")
    config = AIWallConfig(
        logging=LoggingConfig(store="postgresql://aiwall:aiwall@127.0.0.1:5432/aiwall")
    )
    engine = create_engine_from_config(config)
    try:
        assert engine.dialect.name == "postgresql"
        assert engine.url.drivername == "postgresql+psycopg"
    finally:
        engine.dispose()


def test_audit_insert_sql_uses_the_dialect_marker() -> None:
    qmark = audit_insert_sql("qmark")
    assert qmark.count("?") == 23
    assert "%s" not in qmark
    pyformat = audit_insert_sql("pyformat")
    assert pyformat.count("%s") == 23
    assert "?" not in pyformat


def test_postgres_init_db_creates_the_audit_table() -> None:
    url = "postgresql+psycopg://aiwall:aiwall@127.0.0.1:54329/aiwall"
    pytest.importorskip("psycopg")
    engine = create_engine(url, connect_args={"connect_timeout": 2})
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        engine.dispose()
        pytest.skip("PostgreSQL is not listening on 127.0.0.1:54329")
    try:
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE IF EXISTS pending_approvals"))
            conn.execute(text("DROP TABLE IF EXISTS agent_actions"))
            conn.execute(text("DROP TABLE IF EXISTS profiles"))
            conn.execute(text("DROP TABLE IF EXISTS audit_events"))
        init_db(engine)
        assert inspect(engine).has_table("audit_events")
        assert inspect(engine).has_table("profiles")
        writer = AuditWriter(engine, queue_writes=True)
        writer.record(
            AuditEvent(
                request_id="pg-1",
                provider="openai",
                model="gpt-4o-mini",
                decision="block",
                reason="injection-detected",
                input_length=12,
                output_length=0,
                latency_ms=1.5,
            )
        )
        rows = writer.list_recent(limit=1)
        writer.close()
        assert rows[0].request_id == "pg-1"
        assert rows[0].reason == "injection-detected"
    finally:
        engine.dispose()
