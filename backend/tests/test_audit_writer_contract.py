# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Audit writer rejects reasons outside the closed vocabulary."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine

from app.audit.writer import AuditEvent, AuditWriter
from app.storage.database import init_db


def test_writer_rejects_invalid_reason() -> None:
    engine = create_engine("sqlite:///:memory:")
    init_db(engine)
    writer = AuditWriter(engine)
    with pytest.raises(ValueError, match="closed vocabulary"):
        writer.write(
            AuditEvent(
                request_id="bad",
                provider="openai",
                model="gpt-4o-mini",
                decision="block",
                reason="estimated_cost > 9.99",
                input_length=1,
                output_length=0,
                latency_ms=1.0,
            )
        )
