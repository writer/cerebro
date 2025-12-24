"""Time series analytics for tracking security metrics over time."""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Float, String, func, text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from cerebro.core.database import Base
from cerebro.core.database_types import JSONType

from .sql_dialect import get_dialect_name, hours_between_expr

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Types of security metrics to track."""

    FINDING_COUNT = "finding_count"
    CRITICAL_FINDING_COUNT = "critical_finding_count"
    FINDING_SEVERITY_DISTRIBUTION = "finding_severity_distribution"
    FINDING_STATUS_DISTRIBUTION = "finding_status_distribution"
    MEAN_TIME_TO_REMEDIATION = "mean_time_to_remediation"
    SLA_BREACH_COUNT = "sla_breach_count"
    RULE_EFFECTIVENESS = "rule_effectiveness"
    PROVIDER_COVERAGE = "provider_coverage"
    IDENTITY_RISK_SCORE = "identity_risk_score"
    COMPLIANCE_SCORE = "compliance_score"
    OVERALL_RISK_SCORE = "overall_risk_score"


class AggregationPeriod(Enum):
    """Time periods for metric aggregation."""

    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


@dataclass
class TrendData:
    """Trend data for a specific metric."""

    metric_type: str
    current_value: float
    previous_value: float
    change_absolute: float
    change_percentage: float
    trend_direction: str  # "up", "down", "stable"
    confidence: float
    data_points: list[dict[str, Any]]


@dataclass
class MetricSnapshot:
    """Point-in-time snapshot of a security metric."""

    timestamp: datetime
    metric_type: str
    value: float
    metadata: dict[str, Any]


class SecurityMetricSnapshot(Base):
    """Database model for security metric snapshots."""

    __tablename__ = "security_metric_snapshots"

    snapshot_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)

    # Metric identification
    metric_type: Mapped[str] = mapped_column(String(100), nullable=False)
    metric_category: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # findings, compliance, identity, etc.

    # Time and aggregation
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    aggregation_period: Mapped[str] = mapped_column(String(20), nullable=False)

    # Metric values
    value: Mapped[float] = mapped_column(Float, nullable=False)
    previous_value: Mapped[float | None] = mapped_column(Float)

    # Breakdown data
    breakdown_data: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    metric_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSONType)

    # Tracking
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )


class TimeSeriesCollector:
    """Collects and stores time series security metrics."""

    def __init__(self, db_session: AsyncSession):
        """Initialize time series collector."""
        self.db = db_session

    async def collect_finding_metrics(self, org_id: UUID) -> list[MetricSnapshot]:
        """Collect comprehensive finding metrics."""
        snapshots = []
        now = datetime.utcnow()

        # Total finding count
        total_count = await self._get_finding_count(org_id)
        snapshots.append(
            MetricSnapshot(
                timestamp=now,
                metric_type=MetricType.FINDING_COUNT.value,
                value=float(total_count),
                metadata={"category": "findings"},
            )
        )

        # Severity distribution
        severity_dist = await self._get_severity_distribution(org_id)
        snapshots.append(
            MetricSnapshot(
                timestamp=now,
                metric_type=MetricType.FINDING_SEVERITY_DISTRIBUTION.value,
                value=severity_dist.get("critical", 0),
                metadata={
                    "category": "findings",
                    "distribution": severity_dist,
                    "critical_count": severity_dist.get("critical", 0),
                    "high_count": severity_dist.get("high", 0),
                },
            )
        )

        critical_count = severity_dist.get("critical", 0)
        snapshots.append(
            MetricSnapshot(
                timestamp=now,
                metric_type=MetricType.CRITICAL_FINDING_COUNT.value,
                value=float(critical_count),
                metadata={"category": "findings", "severity": "critical"},
            )
        )

        # Status distribution
        status_dist = await self._get_status_distribution(org_id)
        snapshots.append(
            MetricSnapshot(
                timestamp=now,
                metric_type=MetricType.FINDING_STATUS_DISTRIBUTION.value,
                value=status_dist.get("open", 0),
                metadata={"category": "findings", "distribution": status_dist},
            )
        )

        # Mean time to remediation
        mttr = await self._calculate_mttr(org_id)
        snapshots.append(
            MetricSnapshot(
                timestamp=now,
                metric_type=MetricType.MEAN_TIME_TO_REMEDIATION.value,
                value=mttr,
                metadata={"category": "findings", "unit": "hours"},
            )
        )

        # SLA breach count
        sla_breaches = await self._count_sla_breaches(org_id)
        snapshots.append(
            MetricSnapshot(
                timestamp=now,
                metric_type=MetricType.SLA_BREACH_COUNT.value,
                value=float(sla_breaches),
                metadata={
                    "category": "compliance",
                    "sla_critical_days": 7,
                    "sla_high_days": 14,
                    "sla_medium_days": 30,
                },
            )
        )

        return snapshots

    async def store_snapshot(
        self,
        org_id: UUID,
        snapshot: MetricSnapshot,
        aggregation_period: AggregationPeriod = AggregationPeriod.DAILY,
    ) -> SecurityMetricSnapshot:
        """Store a metric snapshot in the database."""

        db_snapshot = SecurityMetricSnapshot(
            org_id=org_id,
            metric_type=snapshot.metric_type,
            metric_category=snapshot.metadata.get("category", "general"),
            captured_at=snapshot.timestamp,
            aggregation_period=aggregation_period.value,
            value=snapshot.value,
            breakdown_data=snapshot.metadata,
            metric_metadata=snapshot.metadata,
        )

        self.db.add(db_snapshot)
        await self.db.commit()
        await self.db.refresh(db_snapshot)

        return db_snapshot

    async def _get_finding_count(self, org_id: UUID) -> int:
        """Get total finding count."""
        result = await self.db.execute(
            text(
                """
                SELECT COUNT(*)
                FROM findings
                WHERE org_id = :org_id
                """
            ),
            {"org_id": org_id},
        )
        return int(result.scalar() or 0)

    async def _get_severity_distribution(self, org_id: UUID) -> dict[str, int]:
        """Get finding severity distribution."""
        result = await self.db.execute(
            text(
                """
                SELECT severity, COUNT(*)
                FROM findings
                WHERE org_id = :org_id
                GROUP BY severity
                """
            ),
            {"org_id": org_id},
        )
        return {str(severity): int(count) for severity, count in result.fetchall()}

    async def _get_status_distribution(self, org_id: UUID) -> dict[str, int]:
        """Get finding status distribution."""
        result = await self.db.execute(
            text(
                """
                SELECT status, COUNT(*)
                FROM findings
                WHERE org_id = :org_id
                GROUP BY status
                """
            ),
            {"org_id": org_id},
        )
        return {str(status): int(count) for status, count in result.fetchall()}

    async def _calculate_mttr(self, org_id: UUID) -> float:
        """Calculate mean time to remediation in hours."""
        # Get resolved findings from last 90 days
        since_date = datetime.utcnow() - timedelta(days=90)

        dialect = get_dialect_name(self.db)
        resolved_timestamp_expr = (
            "CASE "
            "WHEN status = 'fixed' THEN last_seen "
            "WHEN status = 'accepted_risk' THEN last_seen "
            "ELSE NULL "
            "END"
        )
        duration_hours_expr = hours_between_expr(
            start_expr="first_seen",
            end_expr=resolved_timestamp_expr,
            dialect=dialect,
        )

        # Query for resolved findings with time difference
        query = text(
            f"""
            SELECT AVG({duration_hours_expr}) as mttr_hours
            FROM findings
            WHERE org_id = :org_id
                AND status IN ('fixed', 'accepted_risk')
                AND first_seen >= :since_date
                AND last_seen IS NOT NULL
            """
        )

        result = await self.db.execute(
            query, {"org_id": org_id, "since_date": since_date}
        )

        mttr = result.scalar()
        return float(mttr) if mttr else 0.0

    async def _count_sla_breaches(self, org_id: UUID) -> int:
        """Count findings that breach SLA deadlines."""
        now = datetime.utcnow()

        # SLA thresholds by severity
        sla_thresholds = {
            "critical": 7,  # 7 days
            "high": 14,  # 14 days
            "medium": 30,  # 30 days
            "low": 90,  # 90 days
        }

        breach_count = 0

        for severity, days in sla_thresholds.items():
            threshold_date = now - timedelta(days=days)

            result = await self.db.execute(
                text(
                    """
                    SELECT COUNT(*)
                    FROM findings
                    WHERE org_id = :org_id
                      AND severity = :severity
                      AND status = 'open'
                      AND first_seen <= :threshold_date
                    """
                ),
                {
                    "org_id": org_id,
                    "severity": severity,
                    "threshold_date": threshold_date,
                },
            )

            breach_count += int(result.scalar() or 0)

        return breach_count


async def store_snapshot_to_warehouse(
    db_session: Any,
    org_id: UUID,
    snapshot: MetricSnapshot,
    *,
    aggregation_period: AggregationPeriod = AggregationPeriod.DAILY,
) -> str:
    """Store a metric snapshot in Snowflake.

    The Snowflake warehouse is accessed via a sync SQLAlchemy session wrapper,
    so we avoid ORM models (which use Postgres-specific UUID types) and instead
    insert directly into the warehouse table.
    """

    dialect = get_dialect_name(db_session)
    if dialect != "snowflake":
        raise ValueError("store_snapshot_to_warehouse requires a Snowflake session")

    snapshot_id = str(uuid4())
    payload = snapshot.metadata or {}
    payload_json = json.dumps(payload, default=str)

    await db_session.execute(
        text(
            """
            INSERT INTO security_metric_snapshots (
                snapshot_id,
                org_id,
                metric_type,
                metric_category,
                captured_at,
                aggregation_period,
                value,
                previous_value,
                breakdown_data,
                metadata,
                metric_metadata,
                created_at
            ) VALUES (
                :snapshot_id,
                :org_id,
                :metric_type,
                :metric_category,
                :captured_at,
                :aggregation_period,
                :value,
                :previous_value,
                PARSE_JSON(:breakdown_data),
                PARSE_JSON(:metadata),
                PARSE_JSON(:metric_metadata),
                CURRENT_TIMESTAMP()
            )
            """
        ),
        {
            "snapshot_id": snapshot_id,
            "org_id": str(org_id),
            "metric_type": snapshot.metric_type,
            "metric_category": str(payload.get("category") or "general"),
            "captured_at": snapshot.timestamp,
            "aggregation_period": aggregation_period.value,
            "value": float(snapshot.value),
            "previous_value": None,
            "breakdown_data": payload_json,
            "metadata": payload_json,
            "metric_metadata": payload_json,
        },
    )

    commit = getattr(db_session, "commit", None)
    if callable(commit):
        await commit()

    return snapshot_id


class TrendAnalyzer:
    """Analyzes trends in security metrics over time."""

    def __init__(self, db_session: Any):
        """Initialize trend analyzer."""
        self.db = db_session

    def _org_param(self, org_id: UUID) -> object:
        dialect = get_dialect_name(self.db)
        if dialect == "snowflake":
            return str(org_id)
        return org_id

    async def analyze_metric_trend(
        self,
        org_id: UUID,
        metric_type: MetricType,
        days_back: int = 30,
        aggregation_period: AggregationPeriod = AggregationPeriod.DAILY,
    ) -> TrendData:
        """Analyze trend for a specific metric."""

        # Get historical data
        since_date = datetime.utcnow() - timedelta(days=days_back)

        result = await self.db.execute(
            text(
                """
                SELECT captured_at, value, breakdown_data
                FROM security_metric_snapshots
                WHERE org_id = :org_id
                    AND metric_type = :metric_type
                    AND aggregation_period = :aggregation_period
                    AND captured_at >= :since_date
                ORDER BY captured_at
                """
            ),
            {
                "org_id": self._org_param(org_id),
                "metric_type": metric_type.value,
                "aggregation_period": aggregation_period.value,
                "since_date": since_date,
            },
        )

        rows = list(result.mappings().all())

        if len(rows) < 2:
            # Not enough data for trend analysis
            return TrendData(
                metric_type=metric_type.value,
                current_value=float(rows[0]["value"]) if rows else 0.0,
                previous_value=0.0,
                change_absolute=0.0,
                change_percentage=0.0,
                trend_direction="stable",
                confidence=0.0,
                data_points=[],
            )

        # Calculate trend
        current_value = float(rows[-1]["value"])
        previous_value = (
            float(rows[-2]["value"]) if len(rows) > 1 else float(rows[0]["value"])
        )

        change_absolute = current_value - previous_value
        change_percentage = (
            (change_absolute / previous_value * 100) if previous_value > 0 else 0.0
        )

        # Determine trend direction
        if abs(change_percentage) < 5.0:  # Less than 5% change
            trend_direction = "stable"
        elif change_percentage > 0:
            trend_direction = "up"
        else:
            trend_direction = "down"

        # Calculate confidence based on data consistency
        confidence = min(
            1.0, len(rows) / 30.0
        )  # Higher confidence with more data points

        # Prepare data points for sparkline
        data_points = [
            {
                "timestamp": row["captured_at"].isoformat(),
                "value": float(row["value"]),
                "metadata": row.get("breakdown_data"),
            }
            for row in rows
        ]

        return TrendData(
            metric_type=metric_type.value,
            current_value=current_value,
            previous_value=previous_value,
            change_absolute=change_absolute,
            change_percentage=change_percentage,
            trend_direction=trend_direction,
            confidence=confidence,
            data_points=data_points,
        )

    async def generate_sparkline_data(
        self, org_id: UUID, metric_type: MetricType, days_back: int = 7
    ) -> list[float]:
        """Generate sparkline data for the last N days."""

        since_date = datetime.utcnow() - timedelta(days=days_back)

        result = await self.db.execute(
            text(
                """
                SELECT value
                FROM security_metric_snapshots
                WHERE org_id = :org_id
                    AND metric_type = :metric_type
                    AND captured_at >= :since_date
                ORDER BY captured_at
                """
            ),
            {
                "org_id": self._org_param(org_id),
                "metric_type": metric_type.value,
                "since_date": since_date,
            },
        )
        return [float(row[0]) for row in result.fetchall()]

    async def detect_anomalies(
        self, org_id: UUID, metric_type: MetricType, sensitivity: float = 2.0
    ) -> list[dict[str, Any]]:
        """Detect anomalies in metric trends using statistical analysis."""

        # Get last 30 days of data
        since_date = datetime.utcnow() - timedelta(days=30)

        result = await self.db.execute(
            text(
                """
                SELECT captured_at, value
                FROM security_metric_snapshots
                WHERE org_id = :org_id
                    AND metric_type = :metric_type
                    AND captured_at >= :since_date
                ORDER BY captured_at
                """
            ),
            {
                "org_id": self._org_param(org_id),
                "metric_type": metric_type.value,
                "since_date": since_date,
            },
        )
        rows = list(result.mappings().all())

        if len(rows) < 7:  # Need at least a week of data
            return []

        # Calculate baseline statistics
        values = [
            float(row["value"]) for row in rows[:-3]
        ]  # Exclude last 3 days from baseline
        if not values:
            return []

        mean_value = sum(values) / len(values)
        variance = sum((x - mean_value) ** 2 for x in values) / len(values)
        std_dev = variance**0.5

        # Check last 3 days for anomalies
        anomalies = []
        threshold = sensitivity * std_dev

        for row in rows[-3:]:
            deviation = abs(float(row["value"]) - mean_value)
            if deviation > threshold:
                anomalies.append(
                    {
                        "timestamp": row["captured_at"].isoformat(),
                        "value": float(row["value"]),
                        "expected_range": [
                            mean_value - threshold,
                            mean_value + threshold,
                        ],
                        "deviation": deviation,
                        "severity": "high" if deviation > threshold * 1.5 else "medium",
                    }
                )

        return anomalies

    async def generate_metric_summary(self, org_id: UUID) -> dict[str, Any]:
        """Generate comprehensive metric summary with trends."""

        summary = {}

        # Core metrics with trends
        for metric_type in [
            MetricType.FINDING_COUNT,
            MetricType.MEAN_TIME_TO_REMEDIATION,
            MetricType.SLA_BREACH_COUNT,
        ]:
            trend = await self.analyze_metric_trend(org_id, metric_type, days_back=7)
            sparkline = await self.generate_sparkline_data(
                org_id, metric_type, days_back=7
            )

            summary[metric_type.value] = {
                "current_value": trend.current_value,
                "change_percentage": trend.change_percentage,
                "trend_direction": trend.trend_direction,
                "sparkline": sparkline,
                "confidence": trend.confidence,
            }

        return summary


class SecurityTrendCollector:
    """Automated collector that runs periodically to capture metrics."""

    def __init__(self, db_session: AsyncSession):
        """Initialize security trend collector."""
        self.db = db_session
        self.time_series = TimeSeriesCollector(db_session)

    async def collect_daily_metrics(self, org_id: UUID) -> int:
        """Collect daily security metrics for an organization."""

        logger.info(f"Starting daily metric collection for org {org_id}")

        # Collect finding metrics
        finding_snapshots = await self.time_series.collect_finding_metrics(org_id)

        # Store all snapshots
        stored_count = 0
        for snapshot in finding_snapshots:
            await self.time_series.store_snapshot(
                org_id=org_id,
                snapshot=snapshot,
                aggregation_period=AggregationPeriod.DAILY,
            )
            stored_count += 1

        logger.info(f"Stored {stored_count} metric snapshots for org {org_id}")
        return stored_count

    async def collect_hourly_metrics(self, org_id: UUID) -> int:
        """Collect hourly security metrics for real-time monitoring."""

        # Focus on critical metrics that need hourly tracking
        snapshots = []
        now = datetime.utcnow()

        # Critical finding count (for immediate response)
        critical_query = text(
            """
            SELECT COUNT(*) FROM findings
            WHERE org_id = :org_id AND severity = 'critical' AND status = 'open'
        """
        )
        result = await self.db.execute(critical_query, {"org_id": org_id})
        critical_count = result.scalar() or 0

        snapshots.append(
            MetricSnapshot(
                timestamp=now,
                metric_type=MetricType.CRITICAL_FINDING_COUNT.value,
                value=float(critical_count),
                metadata={"category": "findings", "severity": "critical"},
            )
        )

        # Store hourly snapshots
        stored_count = 0
        for snapshot in snapshots:
            await self.time_series.store_snapshot(
                org_id=org_id,
                snapshot=snapshot,
                aggregation_period=AggregationPeriod.HOURLY,
            )
            stored_count += 1

        return stored_count
