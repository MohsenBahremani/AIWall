# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Resolve which organization a profile belongs to, and which policies apply."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass

from app.config import AIWallConfig, PolicyConfig

current_organization: ContextVar[str | None] = ContextVar(
    "aiwall_organization",
    default=None,
)


@dataclass(frozen=True)
class Membership:
    organization_slug: str
    organization_name: str
    team_slug: str | None
    role: str


def membership_for_profile(config: AIWallConfig, profile_name: str | None) -> Membership | None:
    if not profile_name:
        return None
    for org in config.organizations:
        for member in org.members:
            if member.profile == profile_name:
                return Membership(
                    organization_slug=org.slug,
                    organization_name=org.name,
                    team_slug=member.team,
                    role=member.role,
                )
    return None


def policy_applies(policy: PolicyConfig, organization_slug: str | None) -> bool:
    """Policies with no org apply to every caller. An org policy applies only there."""
    if not policy.org:
        return True
    return policy.org == organization_slug
