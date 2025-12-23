"""
Identity Anomaly Detection for Cerebro Security System.

Implements ML-based behavioral analysis to detect anomalous identity activities
across multiple providers using unsupervised learning techniques.
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from ..core.database import async_session_factory
from ..core.models import Principal, IamEdge, AuditEvent
from ..query.bootstrap import get_query_engine

logger = logging.getLogger(__name__)


class AnomalyType(Enum):
    """Types of identity anomalies that can be detected."""

    LOGIN_PATTERN = "login_pattern"
    PERMISSION_ESCALATION = "permission_escalation"
    ACCESS_TIME = "access_time"
    GEOGRAPHIC = "geographic"
    RESOURCE_ACCESS = "resource_access"
    VELOCITY = "velocity"
    CROSS_PROVIDER = "cross_provider"


class RiskLevel(Enum):
    """Risk levels for detected anomalies."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AnomalyResult:
    """Result of anomaly detection analysis."""

    principal_id: str
    anomaly_type: AnomalyType
    risk_level: RiskLevel
    score: float
    confidence: float
    description: str
    details: Dict[str, Any]
    detected_at: datetime
    baseline_period: Tuple[datetime, datetime]
    affected_resources: List[str]
    recommended_actions: List[str]


@dataclass
class BehavioralBaseline:
    """Behavioral baseline for a principal."""

    principal_id: str
    provider: str
    typical_login_hours: List[int]
    typical_access_patterns: Dict[str, float]
    permission_levels: Dict[str, int]
    resource_access_frequency: Dict[str, float]
    geographic_locations: List[str]
    baseline_period: Tuple[datetime, datetime]
    last_updated: datetime


class IdentityAnomalyDetector:
    """
    ML-based identity anomaly detection system.

    Detects unusual patterns in user behavior across multiple security providers
    using unsupervised machine learning techniques.
    """

    def __init__(self, lookback_days: int = 30):
        self.lookback_days = lookback_days
        self.query_engine = get_query_engine()
        self.baselines: Dict[str, BehavioralBaseline] = {}

        # ML models
        self.isolation_forest = IsolationForest(
            contamination=0.1, random_state=42, n_estimators=100  # Expect 10% anomalies
        )
        self.scaler = StandardScaler()
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)

    async def analyze_identity_anomalies(
        self, org_id: str, principal_id: Optional[str] = None
    ) -> List[AnomalyResult]:
        """
        Analyze identity anomalies for an organization or specific principal.

        Args:
            org_id: Organization ID to analyze
            principal_id: Optional specific principal to analyze

        Returns:
            List of detected anomalies
        """
        logger.info(f"Starting identity anomaly analysis for org {org_id}")

        try:
            # Establish baselines for all principals
            await self._establish_baselines(org_id, principal_id)

            # Collect behavioral data
            behavioral_data = await self._collect_behavioral_data(org_id, principal_id)

            if not behavioral_data:
                logger.warning("No behavioral data found for analysis")
                return []

            # Run anomaly detection algorithms
            anomalies = []

            # 1. Login pattern anomalies
            login_anomalies = await self._detect_login_anomalies(behavioral_data)
            anomalies.extend(login_anomalies)

            # 2. Permission escalation anomalies
            permission_anomalies = await self._detect_permission_anomalies(
                behavioral_data
            )
            anomalies.extend(permission_anomalies)

            # 3. Access time anomalies
            time_anomalies = await self._detect_access_time_anomalies(behavioral_data)
            anomalies.extend(time_anomalies)

            # 4. Resource access anomalies
            resource_anomalies = await self._detect_resource_access_anomalies(
                behavioral_data
            )
            anomalies.extend(resource_anomalies)

            # 5. Velocity anomalies (rapid successive actions)
            velocity_anomalies = await self._detect_velocity_anomalies(behavioral_data)
            anomalies.extend(velocity_anomalies)

            # 6. Cross-provider correlation anomalies
            cross_provider_anomalies = await self._detect_cross_provider_anomalies(
                behavioral_data
            )
            anomalies.extend(cross_provider_anomalies)

            # Sort by risk level and score
            anomalies.sort(key=lambda x: (x.risk_level.value, x.score), reverse=True)

            logger.info(f"Detected {len(anomalies)} identity anomalies")
            return anomalies

        except Exception as e:
            logger.error(f"Error in identity anomaly analysis: {e}")
            raise

    async def _establish_baselines(
        self, org_id: str, principal_id: Optional[str] = None
    ):
        """Establish behavioral baselines for principals."""
        async with async_session_factory() as db:
            # Get all principals for the organization
            stmt = select(Principal).where(Principal.org_id == org_id)
            if principal_id:
                stmt = stmt.where(Principal.principal_id == principal_id)

            principals = list(await db.scalars(stmt))

            for principal in principals:
                baseline = await self._calculate_baseline(db, principal)
                self.baselines[principal.principal_id] = baseline

    async def _calculate_baseline(
        self, db: AsyncSession, principal: Principal
    ) -> BehavioralBaseline:
        """Calculate behavioral baseline for a specific principal."""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=self.lookback_days)

        # Query login patterns using SQL engine
        login_data = await self._get_login_patterns(
            principal.principal_id, start_date, end_date
        )

        # Query permission patterns
        permission_data = await self._get_permission_patterns(
            db, principal, start_date, end_date
        )

        # Query resource access patterns
        resource_data = await self._get_resource_access_patterns(
            db, principal, start_date, end_date
        )

        return BehavioralBaseline(
            principal_id=principal.principal_id,
            provider=principal.provider,
            typical_login_hours=self._extract_typical_hours(login_data),
            typical_access_patterns=self._extract_access_patterns(login_data),
            permission_levels=self._extract_permission_levels(permission_data),
            resource_access_frequency=self._extract_resource_frequencies(resource_data),
            geographic_locations=self._extract_locations(login_data),
            baseline_period=(start_date, end_date),
            last_updated=datetime.now(),
        )

    async def _get_login_patterns(
        self, principal_id: str, start_date: datetime, end_date: datetime
    ) -> List[Dict[str, Any]]:
        """Get login patterns using SQL query engine."""
        try:
            # Query Okta user login data
            result = await self.query_engine.execute_query(
                f"""
                SELECT username, last_login, status, metadata
                FROM okta_user
                WHERE user_id = '{principal_id}'
                  AND last_login >= '{start_date.isoformat()}'
                  AND last_login <= '{end_date.isoformat()}'
            """
            )

            return result.rows

        except Exception as e:
            logger.warning(f"Could not get login patterns for {principal_id}: {e}")
            return []

    async def _get_permission_patterns(
        self,
        db: AsyncSession,
        principal: Principal,
        start_date: datetime,
        end_date: datetime,
    ) -> List[Dict[str, Any]]:
        """Get permission change patterns from IAM edges."""
        stmt = (
            select(IamEdge)
            .where(
                and_(
                    IamEdge.principal_id == principal.principal_id,
                    IamEdge.captured_at >= start_date,
                    IamEdge.captured_at <= end_date,
                )
            )
            .order_by(IamEdge.captured_at)
        )

        edges = list(await db.scalars(stmt))

        return [
            {
                "permission": edge.permission,
                "resource_id": edge.resource_id,
                "effective": edge.effective,
                "captured_at": edge.captured_at,
                "edge_type": edge.edge_type,
            }
            for edge in edges
        ]

    async def _get_resource_access_patterns(
        self,
        db: AsyncSession,
        principal: Principal,
        start_date: datetime,
        end_date: datetime,
    ) -> List[Dict[str, Any]]:
        """Get resource access patterns from audit events."""
        stmt = (
            select(AuditEvent)
            .where(
                and_(
                    AuditEvent.principal_id == principal.principal_id,
                    AuditEvent.timestamp >= start_date,
                    AuditEvent.timestamp <= end_date,
                )
            )
            .order_by(AuditEvent.timestamp)
        )

        events = list(await db.scalars(stmt))

        return [
            {
                "action": event.action,
                "resource_type": event.resource_type,
                "resource_id": event.resource_id,
                "timestamp": event.timestamp,
                "metadata": event.metadata,
            }
            for event in events
        ]

    async def _collect_behavioral_data(
        self, org_id: str, principal_id: Optional[str] = None
    ) -> pd.DataFrame:
        """Collect and structure behavioral data for ML analysis."""
        features = []

        for pid, baseline in self.baselines.items():
            if principal_id and pid != principal_id:
                continue

            # Feature engineering
            feature_vector = {
                "principal_id": pid,
                "provider": baseline.provider,
                # Login patterns
                "typical_hours_count": len(baseline.typical_login_hours),
                "login_hour_spread": (
                    max(baseline.typical_login_hours)
                    - min(baseline.typical_login_hours)
                    if baseline.typical_login_hours
                    else 0
                ),
                "weekend_activity": sum(
                    1
                    for hour in baseline.typical_login_hours
                    if hour in [0, 1, 2, 3, 4, 5, 6, 23]
                ),
                # Permission patterns
                "unique_permissions": len(baseline.permission_levels),
                "max_permission_level": (
                    max(baseline.permission_levels.values())
                    if baseline.permission_levels
                    else 0
                ),
                "admin_permissions": sum(
                    1 for level in baseline.permission_levels.values() if level >= 3
                ),
                # Resource access patterns
                "unique_resources": len(baseline.resource_access_frequency),
                "high_frequency_access": sum(
                    1
                    for freq in baseline.resource_access_frequency.values()
                    if freq > 0.8
                ),
                "resource_diversity": len(
                    set(
                        res.split("_")[0]
                        for res in baseline.resource_access_frequency.keys()
                    )
                ),
                # Geographic patterns
                "location_count": len(baseline.geographic_locations),
                "multi_geography": 1 if len(baseline.geographic_locations) > 1 else 0,
            }

            features.append(feature_vector)

        if not features:
            return pd.DataFrame()

        return pd.DataFrame(features)

    async def _detect_login_anomalies(self, data: pd.DataFrame) -> List[AnomalyResult]:
        """Detect anomalous login patterns using isolation forest."""
        if data.empty:
            return []

        anomalies = []

        # Features for login analysis
        login_features = [
            "typical_hours_count",
            "login_hour_spread",
            "weekend_activity",
        ]

        if not all(col in data.columns for col in login_features):
            return anomalies

        X = data[login_features].fillna(0)

        if len(X) < 2:
            return anomalies

        # Fit isolation forest
        X_scaled = self.scaler.fit_transform(X)
        outliers = self.isolation_forest.fit_predict(X_scaled)
        scores = self.isolation_forest.decision_function(X_scaled)

        for idx, (is_outlier, score) in enumerate(zip(outliers, scores)):
            if is_outlier == -1:  # Anomaly detected
                principal_id = data.iloc[idx]["principal_id"]

                risk_level = self._calculate_risk_level(abs(score))

                anomaly = AnomalyResult(
                    principal_id=principal_id,
                    anomaly_type=AnomalyType.LOGIN_PATTERN,
                    risk_level=risk_level,
                    score=abs(score),
                    confidence=min(abs(score) * 100, 95),
                    description=f"Unusual login pattern detected for user {principal_id}",
                    details={
                        "typical_hours": int(data.iloc[idx]["typical_hours_count"]),
                        "hour_spread": int(data.iloc[idx]["login_hour_spread"]),
                        "weekend_activity": int(data.iloc[idx]["weekend_activity"]),
                        "anomaly_score": float(score),
                    },
                    detected_at=datetime.now(),
                    baseline_period=self.baselines[principal_id].baseline_period,
                    affected_resources=[],
                    recommended_actions=[
                        "Review recent login activity",
                        "Verify user identity",
                        "Check for compromised credentials",
                        "Consider temporary access restrictions",
                    ],
                )

                anomalies.append(anomaly)

        return anomalies

    async def _detect_permission_anomalies(
        self, data: pd.DataFrame
    ) -> List[AnomalyResult]:
        """Detect permission escalation anomalies."""
        if data.empty:
            return []

        anomalies = []

        # Check for sudden permission increases
        for _, row in data.iterrows():
            principal_id = row["principal_id"]
            baseline = self.baselines[principal_id]

            # Check if current permissions exceed typical levels
            current_admin_perms = row["admin_permissions"]
            if current_admin_perms > 0:
                # Calculate risk based on admin permission acquisition
                risk_score = min(current_admin_perms * 0.3, 1.0)

                if risk_score > 0.5:
                    risk_level = self._calculate_risk_level(risk_score)

                    anomaly = AnomalyResult(
                        principal_id=principal_id,
                        anomaly_type=AnomalyType.PERMISSION_ESCALATION,
                        risk_level=risk_level,
                        score=risk_score,
                        confidence=risk_score * 80,
                        description=f"Potential privilege escalation detected for user {principal_id}",
                        details={
                            "admin_permissions": int(current_admin_perms),
                            "unique_permissions": int(row["unique_permissions"]),
                            "max_permission_level": int(row["max_permission_level"]),
                        },
                        detected_at=datetime.now(),
                        baseline_period=baseline.baseline_period,
                        affected_resources=[],
                        recommended_actions=[
                            "Review recent permission changes",
                            "Verify permission grants are authorized",
                            "Audit admin access usage",
                            "Consider principle of least privilege",
                        ],
                    )

                    anomalies.append(anomaly)

        return anomalies

    async def _detect_access_time_anomalies(
        self, data: pd.DataFrame
    ) -> List[AnomalyResult]:
        """Detect unusual access time patterns."""
        anomalies = []

        for _, row in data.iterrows():
            principal_id = row["principal_id"]
            baseline = self.baselines[principal_id]

            # Check for off-hours access
            weekend_activity = row["weekend_activity"]
            if weekend_activity > 2:  # More than 2 weekend hours
                anomaly = AnomalyResult(
                    principal_id=principal_id,
                    anomaly_type=AnomalyType.ACCESS_TIME,
                    risk_level=RiskLevel.MEDIUM,
                    score=0.6,
                    confidence=70.0,
                    description=f"Off-hours access detected for user {principal_id}",
                    details={"weekend_activity_hours": int(weekend_activity)},
                    detected_at=datetime.now(),
                    baseline_period=baseline.baseline_period,
                    affected_resources=[],
                    recommended_actions=[
                        "Review off-hours access patterns",
                        "Verify legitimate business need",
                        "Consider time-based access controls",
                    ],
                )
                anomalies.append(anomaly)

        return anomalies

    async def _detect_resource_access_anomalies(
        self, data: pd.DataFrame
    ) -> List[AnomalyResult]:
        """Detect unusual resource access patterns."""
        anomalies = []

        for _, row in data.iterrows():
            principal_id = row["principal_id"]
            baseline = self.baselines[principal_id]

            # Check for unusual resource diversity
            resource_diversity = row["resource_diversity"]
            if resource_diversity > 5:  # Accessing more than 5 different resource types
                anomaly = AnomalyResult(
                    principal_id=principal_id,
                    anomaly_type=AnomalyType.RESOURCE_ACCESS,
                    risk_level=RiskLevel.MEDIUM,
                    score=0.7,
                    confidence=75.0,
                    description=f"Unusual resource access diversity for user {principal_id}",
                    details={
                        "resource_diversity": int(resource_diversity),
                        "unique_resources": int(row["unique_resources"]),
                    },
                    detected_at=datetime.now(),
                    baseline_period=baseline.baseline_period,
                    affected_resources=[],
                    recommended_actions=[
                        "Review resource access patterns",
                        "Verify access is role-appropriate",
                        "Consider resource access restrictions",
                    ],
                )
                anomalies.append(anomaly)

        return anomalies

    async def _detect_velocity_anomalies(
        self, data: pd.DataFrame
    ) -> List[AnomalyResult]:
        """Detect rapid successive action patterns."""
        # This would require time-series analysis of audit events
        # Simplified implementation for now
        return []

    async def _detect_cross_provider_anomalies(
        self, data: pd.DataFrame
    ) -> List[AnomalyResult]:
        """Detect cross-provider correlation anomalies."""
        anomalies = []

        # Group by principal and check for multi-provider unusual patterns
        multi_provider_users = (
            data.groupby("principal_id")
            .agg(
                {
                    "provider": "nunique",
                    "admin_permissions": "sum",
                    "unique_permissions": "sum",
                }
            )
            .reset_index()
        )

        multi_provider_users = multi_provider_users[
            multi_provider_users["provider"] > 1
        ]

        for _, row in multi_provider_users.iterrows():
            principal_id = row["principal_id"]

            if row["admin_permissions"] > 1:  # Admin in multiple providers
                anomaly = AnomalyResult(
                    principal_id=principal_id,
                    anomaly_type=AnomalyType.CROSS_PROVIDER,
                    risk_level=RiskLevel.HIGH,
                    score=0.8,
                    confidence=85.0,
                    description=f"Admin privileges across multiple providers for user {principal_id}",
                    details={
                        "provider_count": int(row["provider"]),
                        "total_admin_permissions": int(row["admin_permissions"]),
                    },
                    detected_at=datetime.now(),
                    baseline_period=(
                        datetime.now() - timedelta(days=self.lookback_days),
                        datetime.now(),
                    ),
                    affected_resources=[],
                    recommended_actions=[
                        "Review cross-provider access necessity",
                        "Implement unified access controls",
                        "Consider centralized identity management",
                        "Audit privileged access patterns",
                    ],
                )
                anomalies.append(anomaly)

        return anomalies

    def _calculate_risk_level(self, score: float) -> RiskLevel:
        """Calculate risk level based on anomaly score."""
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= 0.6:
            return RiskLevel.HIGH
        elif score >= 0.4:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def _extract_typical_hours(self, login_data: List[Dict[str, Any]]) -> List[int]:
        """Extract typical login hours from login data."""
        hours = []
        for login in login_data:
            if login.get("last_login"):
                try:
                    dt = datetime.fromisoformat(
                        str(login["last_login"]).replace("Z", "+00:00")
                    )
                    hours.append(dt.hour)
                except Exception:
                    continue
        return list(set(hours))

    def _extract_access_patterns(
        self, login_data: List[Dict[str, Any]]
    ) -> Dict[str, float]:
        """Extract access pattern frequencies."""
        patterns = {}
        total = len(login_data)

        if total == 0:
            return patterns

        # Simple pattern extraction
        for login in login_data:
            status = login.get("status", "unknown")
            patterns[status] = patterns.get(status, 0) + 1

        # Convert to frequencies
        return {k: v / total for k, v in patterns.items()}

    def _extract_permission_levels(
        self, permission_data: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Extract permission levels from permission data."""
        levels = {}
        for perm in permission_data:
            permission = perm.get("permission", "")
            # Simplified permission level calculation
            if "admin" in permission.lower():
                levels[permission] = 3
            elif "write" in permission.lower():
                levels[permission] = 2
            elif "read" in permission.lower():
                levels[permission] = 1
            else:
                levels[permission] = 0
        return levels

    def _extract_resource_frequencies(
        self, resource_data: List[Dict[str, Any]]
    ) -> Dict[str, float]:
        """Extract resource access frequencies."""
        frequencies = {}
        total = len(resource_data)

        if total == 0:
            return frequencies

        for resource in resource_data:
            resource_type = resource.get("resource_type", "unknown")
            frequencies[resource_type] = frequencies.get(resource_type, 0) + 1

        return {k: v / total for k, v in frequencies.items()}

    def _extract_locations(self, login_data: List[Dict[str, Any]]) -> List[str]:
        """Extract geographic locations from login metadata."""
        locations = []
        for login in login_data:
            metadata = login.get("metadata", {})
            if isinstance(metadata, dict) and "location" in metadata:
                locations.append(metadata["location"])
        return list(set(locations))

    async def get_anomaly_summary(self, org_id: str) -> Dict[str, Any]:
        """Get a summary of detected anomalies for an organization."""
        anomalies = await self.analyze_identity_anomalies(org_id)

        summary = {
            "total_anomalies": len(anomalies),
            "by_risk_level": {},
            "by_type": {},
            "top_principals": {},
            "summary_period": (
                datetime.now() - timedelta(days=self.lookback_days),
                datetime.now(),
            ),
        }

        # Group by risk level
        for anomaly in anomalies:
            risk = anomaly.risk_level.value
            summary["by_risk_level"][risk] = summary["by_risk_level"].get(risk, 0) + 1

            # Group by type
            atype = anomaly.anomaly_type.value
            summary["by_type"][atype] = summary["by_type"].get(atype, 0) + 1

            # Top principals
            pid = anomaly.principal_id
            if pid not in summary["top_principals"]:
                summary["top_principals"][pid] = {
                    "count": 0,
                    "max_risk": anomaly.risk_level.value,
                }
            summary["top_principals"][pid]["count"] += 1

            if (
                RiskLevel(summary["top_principals"][pid]["max_risk"]).value
                < anomaly.risk_level.value
            ):
                summary["top_principals"][pid]["max_risk"] = anomaly.risk_level.value

        # Sort top principals by count and risk
        summary["top_principals"] = dict(
            sorted(
                summary["top_principals"].items(),
                key=lambda x: (x[1]["count"], x[1]["max_risk"]),
                reverse=True,
            )[:10]
        )

        return summary


# Convenience functions
async def detect_identity_anomalies(
    org_id: str, principal_id: Optional[str] = None, lookback_days: int = 30
) -> List[AnomalyResult]:
    """Convenience function to detect identity anomalies."""
    detector = IdentityAnomalyDetector(lookback_days=lookback_days)
    return await detector.analyze_identity_anomalies(org_id, principal_id)


async def get_identity_anomaly_summary(
    org_id: str, lookback_days: int = 30
) -> Dict[str, Any]:
    """Convenience function to get anomaly summary."""
    detector = IdentityAnomalyDetector(lookback_days=lookback_days)
    return await detector.get_anomaly_summary(org_id)
