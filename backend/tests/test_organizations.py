# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Organizations isolate policies and audit rows."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine

from app.audit.writer import AuditEvent, AuditWriter
from app.auth.gateway import resolve_profile_from_api_key
from app.config import AIWallConfig, load_config
from app.policies.context import PolicyContext
from app.policies.engine import PolicyEngine
from app.profiles.store import ProfileStore, hash_api_key
from app.storage.database import init_db
from tests.conftest import write_test_config

_ORGS = """
organizations:
  - slug: acme
    name: Acme
    teams:
      - slug: security
        name: Security
    members:
      - profile: ada
        team: security
        role: admin
  - slug: beta
    name: Beta
    members:
      - profile: bob
        role: member
"""


def test_a_profile_cannot_belong_to_two_organizations() -> None:
    with pytest.raises(ValidationError, match="more than one organization"):
        AIWallConfig.model_validate(
            {
                "organizations": [
                    {"slug": "acme", "name": "Acme", "members": [{"profile": "ada"}]},
                    {"slug": "beta", "name": "Beta", "members": [{"profile": "ada"}]},
                ]
            }
        )


def test_org_policy_does_not_apply_to_another_org(tmp_path: Path) -> None:
    config_path = write_test_config(
        tmp_path,
        """  - name: acme-secrets
    when: input.contains_secret
    action: block
    org: acme
  - name: everyone-injection
    when: input.contains_injection
    action: block""",
        extra_yaml=_ORGS,
    )
    engine = PolicyEngine(config_path)
    secret = PolicyContext(
        body=b"{}",
        model="gpt-4o-mini",
        input_length=4,
        contains_secret=True,
    )
    assert engine.evaluate(secret).action == "allow"
    assert (
        engine.evaluate(
            PolicyContext(
                body=b"{}",
                model="gpt-4o-mini",
                input_length=4,
                contains_secret=True,
                organization_slug="acme",
            )
        ).action
        == "block"
    )
    assert (
        engine.evaluate(
            PolicyContext(
                body=b"{}",
                model="gpt-4o-mini",
                input_length=4,
                contains_secret=True,
                organization_slug="beta",
            )
        ).action
        == "allow"
    )
    injected = PolicyContext(
        body=b"{}",
        model="gpt-4o-mini",
        input_length=4,
        contains_injection=True,
        organization_slug="beta",
    )
    assert engine.evaluate(injected).policy_id == "everyone-injection"


def test_audit_rows_are_filtered_by_organization(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'orgs.db').as_posix()}")
    init_db(engine)
    writer = AuditWriter(engine)

    def _row(request_id: str, organization_slug: str | None) -> None:
        writer.record(
            AuditEvent(
                request_id=request_id,
                provider="openai",
                model="gpt-4o-mini",
                decision="block",
                reason="secret-detected",
                input_length=3,
                output_length=0,
                latency_ms=1.0,
                organization_slug=organization_slug,
            )
        )

    _row("acme-1", "acme")
    _row("beta-1", "beta")
    acme = writer.search_events(organization_slug="acme")
    assert [event.request_id for event in acme.events] == ["acme-1"]
    assert writer.search_events().total == 2


def test_profile_key_carries_its_organization(tmp_path: Path) -> None:
    config_path = write_test_config(tmp_path, extra_yaml=_ORGS)
    config = load_config(config_path)
    db = create_engine(f"sqlite:///{(tmp_path / 'profiles.db').as_posix()}")
    init_db(db)
    store = ProfileStore(db)
    store.create(name="ada", api_key_hash=hash_api_key("ada-key"))
    identity = resolve_profile_from_api_key(store, "ada-key", config)
    assert identity is not None
    assert identity.organization_slug == "acme"
    assert identity.team_slug == "security"
    assert identity.org_role == "admin"
