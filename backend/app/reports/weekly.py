# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Weekly family usage report (per-profile summary)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from app.audit.writer import AuditWriter
from app.profiles.store import ProfileStore

DEFAULT_WINDOW_DAYS = 7


@dataclass(frozen=True)
class ProfileWeeklySummary:
    profile_id: int
    name: str
    role: str
    request_count: int
    block_count: int
    warn_count: int
    total_tokens: int
    estimated_cost: float
    categories: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class WeeklyFamilyReport:
    window_start: datetime
    window_end: datetime
    profiles: tuple[ProfileWeeklySummary, ...]

    @property
    def total_requests(self) -> int:
        return sum(p.request_count for p in self.profiles)

    @property
    def total_blocks(self) -> int:
        return sum(p.block_count for p in self.profiles)

    @property
    def total_estimated_cost(self) -> float:
        return sum(p.estimated_cost for p in self.profiles)


def build_weekly_report(
    audit_writer: AuditWriter,
    profile_store: ProfileStore,
    *,
    now: datetime | None = None,
    days: int = DEFAULT_WINDOW_DAYS,
) -> WeeklyFamilyReport:
    """Build a per-profile summary for the last ``days`` (UTC)."""
    if days < 1:
        raise ValueError("days must be >= 1")

    window_end = now or datetime.now(UTC)
    if window_end.tzinfo is None:
        window_end = window_end.replace(tzinfo=UTC)
    else:
        window_end = window_end.astimezone(UTC)
    window_start = window_end - timedelta(days=days)
    window_until = window_end + timedelta(microseconds=1)

    category_by_user = audit_writer.category_summary(
        since=window_start,
        until=window_until,
    )
    summaries: list[ProfileWeeklySummary] = []

    for profile in profile_store.list():
        user_id = str(profile.id)
        decisions = audit_writer.decision_counts_for_user(
            user_id, since=window_start, until=window_until
        )
        usage = audit_writer.usage_for_user(
            user_id, since=window_start, until=window_until
        )
        categories = dict(sorted((category_by_user.get(user_id) or {}).items()))
        summaries.append(
            ProfileWeeklySummary(
                profile_id=profile.id,
                name=profile.name,
                role=profile.role,
                request_count=sum(decisions.values()),
                block_count=decisions.get("block", 0),
                warn_count=decisions.get("warn", 0),
                total_tokens=usage.total_tokens,
                estimated_cost=usage.estimated_cost,
                categories=categories,
            )
        )

    return WeeklyFamilyReport(
        window_start=window_start,
        window_end=window_end,
        profiles=tuple(summaries),
    )


def render_markdown(report: WeeklyFamilyReport) -> str:
    """Render the weekly family report as Markdown."""
    start = report.window_start.strftime("%Y-%m-%d %H:%M UTC")
    end = report.window_end.strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Weekly family report",
        "",
        f"Window: **{start}** → **{end}**",
        "",
        f"- Profiles: {len(report.profiles)}",
        f"- Total requests: {report.total_requests}",
        f"- Total blocks: {report.total_blocks}",
        f"- Total estimated cost: ${report.total_estimated_cost:.6f}",
        "",
    ]

    if not report.profiles:
        lines.append("_No profiles configured._")
        lines.append("")
        return "\n".join(lines)

    for profile in report.profiles:
        lines.extend(
            [
                f"## {profile.name} ({profile.role})",
                "",
                f"- Requests: {profile.request_count}",
                f"- Blocks: {profile.block_count}",
                f"- Warns: {profile.warn_count}",
                f"- Tokens: {profile.total_tokens}",
                f"- Estimated cost: ${profile.estimated_cost:.6f}",
            ]
        )
        if profile.categories:
            lines.append("- Categories:")
            for category, count in profile.categories.items():
                lines.append(f"  - `{category}`: {count}")
        else:
            lines.append("- Categories: none")
        lines.append("")

    return "\n".join(lines)
