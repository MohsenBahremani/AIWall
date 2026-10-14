# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Persist audit events to SQLite."""

from __future__ import annotations

import logging
import queue
import threading
from collections.abc import Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy.engine import Engine

from app.agents.models import AgentActionRow
from app.agents.types import AgentAction
from app.audit.models import AuditEventRow
from app.audit.reasons import assert_valid_audit_reason
from app.storage.database import session_factory

logger = logging.getLogger(__name__)
_STOP = object()
_BATCH_LIMIT = 32


@dataclass(frozen=True)
class AuditEvent:
    request_id: str
    provider: str
    model: str
    decision: str
    reason: str | None
    input_length: int
    output_length: int
    latency_ms: float
    user_id: str | None = None
    app_id: str | None = None
    estimated_cost: float | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    policy_id: str | None = None
    matched_rule_ids: str | None = None
    categories: str | None = None
    redaction_count: int = 0
    raw_prompt: str | None = None
    raw_response: str | None = None
    timestamp: datetime | None = None


@dataclass(frozen=True)
class AuditSummary:
    window_hours: int
    total: int = 0
    decision_counts: dict[str, int] = field(default_factory=dict)
    total_estimated_cost: float = 0.0

    @property
    def allow(self) -> int:
        return self.decision_counts.get("allow", 0)

    @property
    def warn(self) -> int:
        return self.decision_counts.get("warn", 0)

    @property
    def block(self) -> int:
        return self.decision_counts.get("block", 0)

    @property
    def redact(self) -> int:
        return self.decision_counts.get("redact", 0)

    @property
    def error(self) -> int:
        return self.decision_counts.get("error", 0)


@dataclass(frozen=True)
class FilteredEventSummary:
    total: int = 0
    decision_counts: dict[str, int] = field(default_factory=dict)
    total_estimated_cost: float = 0.0
    total_tokens: int = 0


@dataclass(frozen=True)
class ProfileUsage:
    request_count: int = 0
    total_tokens: int = 0
    estimated_cost: float = 0.0


@dataclass(frozen=True)
class UsageBucket:
    start: datetime
    request_count: int = 0
    estimated_cost: float = 0.0


@dataclass(frozen=True)
class UsageTimeseries:
    window_hours: int
    bucket_hours: int
    buckets: tuple[UsageBucket, ...] = ()

    @property
    def max_requests(self) -> int:
        return max((bucket.request_count for bucket in self.buckets), default=0)

    @property
    def max_cost(self) -> float:
        return max((bucket.estimated_cost for bucket in self.buckets), default=0.0)

    @property
    def total_requests(self) -> int:
        return sum(bucket.request_count for bucket in self.buckets)

    @property
    def total_estimated_cost(self) -> float:
        return sum(bucket.estimated_cost for bucket in self.buckets)


@dataclass(frozen=True)
class ModelUsageRow:
    provider: str
    model: str
    request_count: int = 0
    total_tokens: int = 0
    estimated_cost: float = 0.0
    avg_latency_ms: float = 0.0


@dataclass(frozen=True)
class ModelUsageReport:
    window_hours: int
    rows: tuple[ModelUsageRow, ...] = ()

    @property
    def total_requests(self) -> int:
        return sum(row.request_count for row in self.rows)

    @property
    def total_tokens(self) -> int:
        return sum(row.total_tokens for row in self.rows)

    @property
    def total_estimated_cost(self) -> float:
        return sum(row.estimated_cost for row in self.rows)


@dataclass(frozen=True)
class PolicyHitStats:
    policy_id: str
    hit_count: int = 0
    last_triggered: datetime | None = None


@dataclass(frozen=True)
class EventPage:
    events: tuple[AuditEventRow, ...]
    total: int
    limit: int
    offset: int

    @property
    def page(self) -> int:
        if self.limit <= 0:
            return 1
        return (self.offset // self.limit) + 1

    @property
    def total_pages(self) -> int:
        if self.limit <= 0:
            return 1
        return max(1, (self.total + self.limit - 1) // self.limit)

    @property
    def has_prev(self) -> bool:
        return self.offset > 0

    @property
    def has_next(self) -> bool:
        return self.offset + self.limit < self.total

    @property
    def prev_offset(self) -> int:
        return max(0, self.offset - self.limit)

    @property
    def next_offset(self) -> int:
        return self.offset + self.limit


class AuditWriter:
    def __init__(
        self,
        engine: Engine,
        *,
        persist: bool = True,
        queue_writes: bool = False,
    ):
        self._engine = engine
        self._session_factory = session_factory(engine)
        self._persist = persist
        self._queue: queue.Queue[tuple[AuditEvent, tuple[AgentAction, ...]] | object] | None = None
        self._worker: threading.Thread | None = None
        if persist and queue_writes:
            self._queue = queue.Queue()
            self._worker = threading.Thread(
                target=self._worker_loop,
                name="aiwall-audit",
                daemon=True,
            )
            self._worker.start()

    def record(
        self,
        event: AuditEvent,
        actions: Sequence[AgentAction] = (),
    ) -> None:
        """Persist an audit row without blocking the caller on SQLite.

        Direct ``write`` stays synchronous for tests and maintenance. The proxy
        uses this so request handlers return while a background thread commits.
        """
        assert_valid_audit_reason(event.reason)
        if not self._persist:
            return
        action_tuple = tuple(actions)
        if self._queue is None:
            row = self.write(event)
            if action_tuple:
                self.write_agent_actions(
                    request_id=event.request_id,
                    actions=action_tuple,
                    audit_event_id=row.id,
                    timestamp=event.timestamp,
                )
            return
        self._queue.put((event, action_tuple))

    def flush(self) -> None:
        """Wait until queued proxy events are committed."""
        if self._queue is None:
            return
        self._queue.join()

    def close(self) -> None:
        if self._queue is None or self._worker is None:
            return
        self._queue.put(_STOP)
        self._worker.join(timeout=5)
        self._queue = None
        self._worker = None

    @contextmanager
    def _read_session(self):
        self.flush()
        with self._session_factory() as session:
            yield session

    def _worker_loop(self) -> None:
        assert self._queue is not None
        while True:
            item = self._queue.get()
            if item is _STOP:
                self._queue.task_done()
                return
            batch: list[tuple[AuditEvent, tuple[AgentAction, ...]]] = [item]
            stop = False
            while len(batch) < _BATCH_LIMIT:
                try:
                    nxt = self._queue.get_nowait()
                except queue.Empty:
                    break
                if nxt is _STOP:
                    stop = True
                    self._queue.task_done()
                    break
                batch.append(nxt)  # type: ignore[arg-type]
            try:
                self._write_batch(batch)
            except Exception:
                logger.exception("audit batch failed")
            finally:
                for _ in batch:
                    self._queue.task_done()
            if stop:
                return

    def _write_batch(
        self,
        batch: Sequence[tuple[AuditEvent, tuple[AgentAction, ...]]],
    ) -> None:
        if any(actions for _event, actions in batch):
            self._write_batch_orm(batch)
            return
        sql = (
            "INSERT INTO audit_events ("
            "timestamp, request_id, user_id, app_id, provider, model, decision, reason, "
            "input_length, output_length, estimated_cost, prompt_tokens, completion_tokens, "
            "total_tokens, policy_id, matched_rule_ids, categories, redaction_count, "
            "latency_ms, raw_prompt, raw_response"
            ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        )
        rows = [self._event_params(event) for event, _actions in batch]
        connection = self._engine.raw_connection()
        try:
            cursor = connection.cursor()
            cursor.executemany(sql, rows)
            connection.commit()
        finally:
            connection.close()

    def _event_params(self, event: AuditEvent) -> tuple[object, ...]:
        when = event.timestamp or datetime.now(UTC)
        if when.tzinfo is not None:
            when = when.astimezone(UTC).replace(tzinfo=None)
        # Match SQLAlchemy's SQLite DateTime text so range queries still hit.
        stored_timestamp = when.strftime("%Y-%m-%d %H:%M:%S.%f")
        return (
            stored_timestamp,
            event.request_id,
            event.user_id,
            event.app_id,
            event.provider,
            event.model,
            event.decision,
            event.reason,
            event.input_length,
            event.output_length,
            event.estimated_cost,
            event.prompt_tokens,
            event.completion_tokens,
            event.total_tokens,
            event.policy_id,
            event.matched_rule_ids,
            event.categories,
            event.redaction_count,
            event.latency_ms,
            event.raw_prompt,
            event.raw_response,
        )

    def _write_batch_orm(
        self,
        batch: Sequence[tuple[AuditEvent, tuple[AgentAction, ...]]],
    ) -> None:
        with self._session_factory() as session:
            for event, actions in batch:
                row = self._build_row(event)
                session.add(row)
                session.flush()
                when = event.timestamp or row.timestamp
                for action in actions:
                    session.add(
                        AgentActionRow(
                            timestamp=when,
                            request_id=event.request_id,
                            audit_event_id=row.id,
                            action_type=action.action_type,
                            action_target=action.action_target,
                            tool_name=action.tool_name,
                            arguments_preview=action.arguments_preview,
                            tool_call_id=action.tool_call_id,
                        )
                    )
            session.commit()

    def _build_row(self, event: AuditEvent) -> AuditEventRow:
        assert_valid_audit_reason(event.reason)
        return AuditEventRow(
            timestamp=event.timestamp or datetime.now(UTC),
            request_id=event.request_id,
            user_id=event.user_id,
            app_id=event.app_id,
            provider=event.provider,
            model=event.model,
            decision=event.decision,
            reason=event.reason,
            input_length=event.input_length,
            output_length=event.output_length,
            estimated_cost=event.estimated_cost,
            prompt_tokens=event.prompt_tokens,
            completion_tokens=event.completion_tokens,
            total_tokens=event.total_tokens,
            policy_id=event.policy_id,
            matched_rule_ids=event.matched_rule_ids,
            categories=event.categories,
            redaction_count=event.redaction_count,
            latency_ms=event.latency_ms,
            raw_prompt=event.raw_prompt,
            raw_response=event.raw_response,
        )

    def write(self, event: AuditEvent) -> AuditEventRow:
        row = self._build_row(event)
        if not self._persist:
            return row
        with self._session_factory() as session:
            session.add(row)
            session.commit()
            session.refresh(row)
            return row

    def write_agent_actions(
        self,
        *,
        request_id: str,
        actions: tuple[AgentAction, ...] | list[AgentAction],
        audit_event_id: int | None = None,
        timestamp: datetime | None = None,
    ) -> list[AgentActionRow]:
        """Persist agent/tool actions linked to a proxy request."""
        if not actions:
            return []
        when = timestamp or datetime.now(UTC)
        rows: list[AgentActionRow] = []
        with self._session_factory() as session:
            for action in actions:
                row = AgentActionRow(
                    timestamp=when,
                    request_id=request_id,
                    audit_event_id=audit_event_id,
                    action_type=action.action_type,
                    action_target=action.action_target,
                    tool_name=action.tool_name,
                    arguments_preview=action.arguments_preview,
                    tool_call_id=action.tool_call_id,
                )
                session.add(row)
                rows.append(row)
            session.commit()
            for row in rows:
                session.refresh(row)
            return list(rows)

    def list_agent_actions(
        self,
        *,
        request_id: str | None = None,
        action_type: str | None = None,
        limit: int = 100,
    ) -> list[AgentActionRow]:
        from sqlalchemy import select

        if limit < 1:
            raise ValueError("limit must be >= 1")
        with self._read_session() as session:
            stmt = select(AgentActionRow).order_by(AgentActionRow.id.desc()).limit(limit)
            if request_id:
                stmt = stmt.where(AgentActionRow.request_id == request_id)
            if action_type:
                stmt = stmt.where(AgentActionRow.action_type == action_type)
            return list(session.scalars(stmt).all())

    def list_recent(
        self,
        limit: int = 100,
        *,
        decision: str | None = None,
        provider: str | None = None,
        user_id: str | None = None,
    ) -> list[AuditEventRow]:
        page = self.search_events(
            limit=limit,
            offset=0,
            decision=decision,
            provider=provider,
            user_id=user_id,
        )
        return list(page.events)

    def search_events(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        decision: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        user_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        has_raw_prompt: bool = False,
    ) -> EventPage:
        """Filter and paginate audit events (newest first)."""
        from sqlalchemy import func, select

        if limit < 1:
            raise ValueError("limit must be >= 1")
        if offset < 0:
            raise ValueError("offset must be >= 0")

        filters = []
        if decision:
            filters.append(AuditEventRow.decision == decision)
        if provider:
            filters.append(AuditEventRow.provider == provider)
        if model:
            filters.append(AuditEventRow.model == model)
        if user_id:
            filters.append(AuditEventRow.user_id == user_id)
        if since is not None:
            filters.append(AuditEventRow.timestamp >= since)
        if until is not None:
            filters.append(AuditEventRow.timestamp < until)
        if has_raw_prompt:
            filters.append(AuditEventRow.raw_prompt.is_not(None))

        with self._read_session() as session:
            count_stmt = select(func.count()).select_from(AuditEventRow)
            if filters:
                count_stmt = count_stmt.where(*filters)
            total = int(session.execute(count_stmt).scalar_one() or 0)

            stmt = select(AuditEventRow).order_by(AuditEventRow.id.desc())
            if filters:
                stmt = stmt.where(*filters)
            stmt = stmt.offset(offset).limit(limit)
            events = tuple(session.scalars(stmt).all())

        return EventPage(events=events, total=total, limit=limit, offset=offset)

    def summarize_events(
        self,
        *,
        decision: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        user_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> FilteredEventSummary:
        """Aggregate totals for the same filters used by ``search_events``."""
        from sqlalchemy import func, select

        filters = []
        if decision:
            filters.append(AuditEventRow.decision == decision)
        if provider:
            filters.append(AuditEventRow.provider == provider)
        if model:
            filters.append(AuditEventRow.model == model)
        if user_id:
            filters.append(AuditEventRow.user_id == user_id)
        if since is not None:
            filters.append(AuditEventRow.timestamp >= since)
        if until is not None:
            filters.append(AuditEventRow.timestamp < until)

        with self._read_session() as session:
            count_stmt = select(AuditEventRow.decision, func.count())
            if filters:
                count_stmt = count_stmt.where(*filters)
            count_stmt = count_stmt.group_by(AuditEventRow.decision)
            decision_counts = {
                decision_name: int(count)
                for decision_name, count in session.execute(count_stmt)
            }

            cost_stmt = select(func.coalesce(func.sum(AuditEventRow.estimated_cost), 0.0))
            tokens_stmt = select(func.coalesce(func.sum(AuditEventRow.total_tokens), 0))
            if filters:
                cost_stmt = cost_stmt.where(*filters)
                tokens_stmt = tokens_stmt.where(*filters)
            total_cost = float(session.execute(cost_stmt).scalar_one() or 0.0)
            total_tokens = int(session.execute(tokens_stmt).scalar_one() or 0)

        return FilteredEventSummary(
            total=sum(decision_counts.values()),
            decision_counts=decision_counts,
            total_estimated_cost=total_cost,
            total_tokens=total_tokens,
        )

    def purge_expired_events(
        self,
        retention_days: int,
        *,
        now: datetime | None = None,
    ) -> int:
        """Delete audit rows older than ``retention_days``. Returns deleted count."""
        from sqlalchemy import delete, func, select

        if retention_days < 1:
            raise ValueError("retention_days must be >= 1")
        cutoff = (now or datetime.now(UTC)) - timedelta(days=retention_days)
        with self._read_session() as session:
            count_stmt = select(func.count()).select_from(AuditEventRow).where(
                AuditEventRow.timestamp < cutoff
            )
            to_delete = int(session.execute(count_stmt).scalar_one() or 0)
            if to_delete:
                session.execute(
                    delete(AuditEventRow).where(AuditEventRow.timestamp < cutoff)
                )
                session.commit()
            return to_delete

    def get_by_id(self, event_id: int) -> AuditEventRow | None:
        from sqlalchemy import select

        with self._read_session() as session:
            stmt = select(AuditEventRow).where(AuditEventRow.id == event_id)
            return session.scalars(stmt).first()

    def list_providers(self) -> list[str]:
        from sqlalchemy import select

        with self._read_session() as session:
            stmt = select(AuditEventRow.provider).distinct().order_by(AuditEventRow.provider)
            return list(session.scalars(stmt).all())

    def list_models(self, *, provider: str | None = None) -> list[str]:
        from sqlalchemy import select

        with self._read_session() as session:
            stmt = select(AuditEventRow.model).distinct().order_by(AuditEventRow.model)
            if provider:
                stmt = stmt.where(AuditEventRow.provider == provider)
            return list(session.scalars(stmt).all())

    def summary(self, window_hours: int = 24) -> AuditSummary:
        from sqlalchemy import func, select

        since = datetime.now(UTC) - timedelta(hours=window_hours)
        with self._read_session() as session:
            count_stmt = (
                select(AuditEventRow.decision, func.count())
                .where(AuditEventRow.timestamp >= since)
                .group_by(AuditEventRow.decision)
            )
            decision_counts = {decision: count for decision, count in session.execute(count_stmt)}

            cost_stmt = select(func.coalesce(func.sum(AuditEventRow.estimated_cost), 0.0)).where(
                AuditEventRow.timestamp >= since
            )
            total_cost = session.execute(cost_stmt).scalar_one()

        return AuditSummary(
            window_hours=window_hours,
            total=sum(decision_counts.values()),
            decision_counts=decision_counts,
            total_estimated_cost=float(total_cost or 0.0),
        )

    def usage_timeseries(
        self,
        *,
        window_hours: int = 24,
        bucket_hours: int = 1,
        now: datetime | None = None,
    ) -> UsageTimeseries:
        """Return request and cost totals in fixed UTC buckets over a rolling window.

        Empty buckets are included so charts render a continuous series.
        """
        from sqlalchemy import select

        if window_hours < 1:
            raise ValueError("window_hours must be >= 1")
        if bucket_hours < 1:
            raise ValueError("bucket_hours must be >= 1")
        if window_hours % bucket_hours != 0:
            raise ValueError("window_hours must be divisible by bucket_hours")

        window_end = now or datetime.now(UTC)
        if window_end.tzinfo is None:
            window_end = window_end.replace(tzinfo=UTC)
        else:
            window_end = window_end.astimezone(UTC)

        # Align the last bucket to the current bucket boundary (UTC).
        bucket_seconds = bucket_hours * 3600
        end_epoch = int(window_end.timestamp())
        last_bucket_epoch = end_epoch - (end_epoch % bucket_seconds)
        last_bucket_start = datetime.fromtimestamp(last_bucket_epoch, tz=UTC)
        bucket_count = window_hours // bucket_hours
        first_bucket_start = last_bucket_start - timedelta(
            hours=bucket_hours * (bucket_count - 1)
        )
        since = first_bucket_start

        with self._read_session() as session:
            stmt = select(
                AuditEventRow.timestamp,
                AuditEventRow.estimated_cost,
            ).where(AuditEventRow.timestamp >= since)
            rows = session.execute(stmt).all()

        totals: dict[datetime, list[float]] = {
            first_bucket_start
            + timedelta(hours=bucket_hours * index): [0.0, 0.0]
            for index in range(bucket_count)
        }

        for timestamp, estimated_cost in rows:
            if timestamp is None:
                continue
            if timestamp.tzinfo is None:
                ts = timestamp.replace(tzinfo=UTC)
            else:
                ts = timestamp.astimezone(UTC)
            if ts < since:
                continue
            offset = int((ts - first_bucket_start).total_seconds() // bucket_seconds)
            if offset < 0 or offset >= bucket_count:
                continue
            bucket_start = first_bucket_start + timedelta(hours=bucket_hours * offset)
            totals[bucket_start][0] += 1
            totals[bucket_start][1] += float(estimated_cost or 0.0)

        buckets = tuple(
            UsageBucket(
                start=start,
                request_count=int(values[0]),
                estimated_cost=float(values[1]),
            )
            for start, values in sorted(totals.items())
        )
        return UsageTimeseries(
            window_hours=window_hours,
            bucket_hours=bucket_hours,
            buckets=buckets,
        )

    def model_usage(
        self,
        *,
        window_hours: int = 24,
        now: datetime | None = None,
    ) -> ModelUsageReport:
        """Aggregate volume, tokens, cost, and latency per provider/model."""
        from sqlalchemy import func, select

        if window_hours < 1:
            raise ValueError("window_hours must be >= 1")

        window_end = now or datetime.now(UTC)
        if window_end.tzinfo is None:
            window_end = window_end.replace(tzinfo=UTC)
        else:
            window_end = window_end.astimezone(UTC)
        since = window_end - timedelta(hours=window_hours)

        with self._read_session() as session:
            stmt = (
                select(
                    AuditEventRow.provider,
                    AuditEventRow.model,
                    func.count().label("request_count"),
                    func.coalesce(func.sum(AuditEventRow.total_tokens), 0).label(
                        "total_tokens"
                    ),
                    func.coalesce(func.sum(AuditEventRow.estimated_cost), 0.0).label(
                        "estimated_cost"
                    ),
                    func.coalesce(func.avg(AuditEventRow.latency_ms), 0.0).label(
                        "avg_latency_ms"
                    ),
                )
                .where(AuditEventRow.timestamp >= since)
                .group_by(AuditEventRow.provider, AuditEventRow.model)
                .order_by(
                    func.coalesce(func.sum(AuditEventRow.estimated_cost), 0.0).desc(),
                    func.count().desc(),
                    AuditEventRow.provider,
                    AuditEventRow.model,
                )
            )
            results = session.execute(stmt).all()

        rows = tuple(
            ModelUsageRow(
                provider=row.provider,
                model=row.model,
                request_count=int(row.request_count),
                total_tokens=int(row.total_tokens or 0),
                estimated_cost=float(row.estimated_cost or 0.0),
                avg_latency_ms=float(row.avg_latency_ms or 0.0),
            )
            for row in results
        )
        return ModelUsageReport(window_hours=window_hours, rows=rows)

    def policy_hit_stats(self) -> dict[str, PolicyHitStats]:
        """Hit counts and last-triggered timestamps keyed by ``policy_id``."""
        from sqlalchemy import func, select

        with self._read_session() as session:
            stmt = (
                select(
                    AuditEventRow.policy_id,
                    func.count().label("hit_count"),
                    func.max(AuditEventRow.timestamp).label("last_triggered"),
                )
                .where(AuditEventRow.policy_id.is_not(None))
                .group_by(AuditEventRow.policy_id)
            )
            results = session.execute(stmt).all()

        stats: dict[str, PolicyHitStats] = {}
        for policy_id, hit_count, last_triggered in results:
            if not policy_id:
                continue
            triggered = last_triggered
            if triggered is not None and triggered.tzinfo is None:
                triggered = triggered.replace(tzinfo=UTC)
            stats[policy_id] = PolicyHitStats(
                policy_id=policy_id,
                hit_count=int(hit_count),
                last_triggered=triggered,
            )
        return stats

    def usage_for_user(
        self,
        user_id: str,
        *,
        since: datetime,
        until: datetime | None = None,
        decisions: frozenset[str] | set[str] | None = None,
        provider: str | None = None,
    ) -> ProfileUsage:
        """Aggregate billable usage for a profile since ``since`` (UTC)."""
        return self.usage_for_scope(
            since=since,
            until=until,
            user_id=user_id,
            provider=provider,
            decisions=decisions,
        )

    def usage_for_scope(
        self,
        *,
        since: datetime,
        until: datetime | None = None,
        user_id: str | None = None,
        provider: str | None = None,
        decisions: frozenset[str] | set[str] | None = None,
    ) -> ProfileUsage:
        """Aggregate usage for an optional profile and/or provider scope."""
        from sqlalchemy import func, select

        with self._read_session() as session:
            filters = [AuditEventRow.timestamp >= since]
            if until is not None:
                filters.append(AuditEventRow.timestamp < until)
            if user_id is not None:
                filters.append(AuditEventRow.user_id == user_id)
            if provider is not None:
                filters.append(AuditEventRow.provider == provider)
            if decisions is not None:
                filters.append(AuditEventRow.decision.in_(tuple(decisions)))

            count_stmt = select(func.count()).select_from(AuditEventRow).where(*filters)
            request_count = int(session.execute(count_stmt).scalar_one() or 0)

            tokens_stmt = select(
                func.coalesce(func.sum(AuditEventRow.total_tokens), 0)
            ).where(*filters)
            total_tokens = int(session.execute(tokens_stmt).scalar_one() or 0)

            cost_stmt = select(
                func.coalesce(func.sum(AuditEventRow.estimated_cost), 0.0)
            ).where(*filters)
            estimated_cost = float(session.execute(cost_stmt).scalar_one() or 0.0)

        return ProfileUsage(
            request_count=request_count,
            total_tokens=total_tokens,
            estimated_cost=estimated_cost,
        )

    def decision_counts_for_user(
        self,
        user_id: str,
        *,
        since: datetime,
        until: datetime | None = None,
    ) -> dict[str, int]:
        """Per-decision event counts for a profile since ``since`` (UTC)."""
        from sqlalchemy import func, select

        filters = [
            AuditEventRow.user_id == user_id,
            AuditEventRow.timestamp >= since,
        ]
        if until is not None:
            filters.append(AuditEventRow.timestamp < until)

        with self._read_session() as session:
            stmt = (
                select(AuditEventRow.decision, func.count())
                .where(*filters)
                .group_by(AuditEventRow.decision)
            )
            return {decision: int(count) for decision, count in session.execute(stmt)}

    def category_summary(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        user_id: str | None = None,
    ) -> dict[str | None, dict[str, int]]:
        """Per-profile counts of category-tagged events: ``{user_id: {category: count}}``.

        Events tagged with multiple categories (comma-joined) count once per category.
        """
        from sqlalchemy import select

        with self._read_session() as session:
            stmt = select(AuditEventRow.user_id, AuditEventRow.categories).where(
                AuditEventRow.categories.is_not(None)
            )
            if since is not None:
                stmt = stmt.where(AuditEventRow.timestamp >= since)
            if until is not None:
                stmt = stmt.where(AuditEventRow.timestamp < until)
            if user_id is not None:
                stmt = stmt.where(AuditEventRow.user_id == user_id)
            rows = session.execute(stmt).all()

        summary: dict[str | None, dict[str, int]] = {}
        for event_user_id, categories in rows:
            for category in (categories or "").split(","):
                name = category.strip()
                if not name:
                    continue
                per_user = summary.setdefault(event_user_id, {})
                per_user[name] = per_user.get(name, 0) + 1
        return summary
