"""Change replay engine for retroactive rule analysis."""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from cerebro.core.models import Rule, Resource, ConfigSnapshot, Finding, Organization
from cerebro.rules.engine import RuleEngine, EvaluationContext
from cerebro.findings.evaluator import RuleEvaluator

logger = logging.getLogger(__name__)


@dataclass
class RuleReplayResult:
    """Result of replaying a rule against historical data."""

    rule_id: UUID
    rule_name: str
    time_period: str
    total_evaluations: int
    matches_found: int
    new_findings_count: int
    findings_that_would_exist: List[Dict[str, Any]]
    coverage_analysis: Dict[str, Any]
    performance_metrics: Dict[str, Any]


class ChangeReplayEngine:
    """Replays security rules against historical configurations."""

    def __init__(self, db_session: AsyncSession, rule_engine: RuleEngine):
        """Initialize change replay engine."""
        self.db = db_session
        self.rule_engine = rule_engine
        self.rule_evaluator = RuleEvaluator(db_session, rule_engine)

    async def replay_rule_historically(
        self,
        rule_id: UUID,
        org_id: UUID,
        start_time: datetime,
        end_time: datetime,
        providers: Optional[List[str]] = None,
    ) -> RuleReplayResult:
        """Replay a rule against historical configurations."""
        rule = await self.db.get(Rule, rule_id)
        if not rule:
            raise ValueError(f"Rule {rule_id} not found")

        logger.info(f"Replaying rule '{rule.name}' from {start_time} to {end_time}")

        # Get historical snapshots in the time period
        snapshots = await self._get_historical_snapshots(
            org_id, start_time, end_time, providers, rule.resource_types
        )

        if not snapshots:
            return RuleReplayResult(
                rule_id=rule_id,
                rule_name=rule.name,
                time_period=f"{start_time.date()} to {end_time.date()}",
                total_evaluations=0,
                matches_found=0,
                new_findings_count=0,
                findings_that_would_exist=[],
                coverage_analysis={},
                performance_metrics={},
            )

        # Evaluate rule against each snapshot
        start_eval_time = datetime.utcnow()
        evaluations = 0
        matches = 0
        findings_that_would_exist = []

        for snapshot, resource in snapshots:
            try:
                # Build evaluation context
                context = EvaluationContext(
                    resource={
                        "resource_id": str(resource.resource_id),
                        "external_id": resource.external_id,
                        "resource_type": resource.resource_type,
                        "provider": resource.provider,
                        "name": resource.name,
                    },
                    config=snapshot.normalized_config,
                )

                # Evaluate rule
                result = self.rule_engine.evaluate_rule(
                    rule_id, rule.expression, context
                )
                evaluations += 1

                if result.matched:
                    matches += 1

                    # Check if this would be a new finding
                    existing_finding = await self._check_existing_finding(
                        rule_id, resource.resource_id, snapshot.captured_at
                    )

                    if not existing_finding:
                        finding_data = {
                            "resource_id": str(resource.resource_id),
                            "resource_external_id": resource.external_id,
                            "resource_type": resource.resource_type,
                            "provider": resource.provider,
                            "captured_at": snapshot.captured_at.isoformat(),
                            "config_hash": snapshot.config_sha.hex(),
                            "would_be_new": True,
                            "evidence": {
                                "rule_name": rule.name,
                                "historical_config": snapshot.normalized_config,
                                "evaluation_time": result.execution_time_ms,
                            },
                        }
                        findings_that_would_exist.append(finding_data)

            except Exception as e:
                logger.warning(
                    f"Rule evaluation failed for snapshot {snapshot.snapshot_id}: {e}"
                )

        eval_duration = (datetime.utcnow() - start_eval_time).total_seconds()

        # Analyze coverage and generate insights
        coverage_analysis = self._analyze_rule_coverage(snapshots, matches, rule)
        performance_metrics = {
            "evaluation_duration_seconds": eval_duration,
            "evaluations_per_second": evaluations / max(eval_duration, 0.001),
            "match_rate_percentage": (matches / max(evaluations, 1)) * 100,
        }

        replay_result = RuleReplayResult(
            rule_id=rule_id,
            rule_name=rule.name,
            time_period=f"{start_time.date()} to {end_time.date()}",
            total_evaluations=evaluations,
            matches_found=matches,
            new_findings_count=len(findings_that_would_exist),
            findings_that_would_exist=findings_that_would_exist,
            coverage_analysis=coverage_analysis,
            performance_metrics=performance_metrics,
        )

        logger.info(
            f"Rule replay complete: {matches}/{evaluations} matches, "
            f"{len(findings_that_would_exist)} new findings"
        )

        return replay_result

    async def replay_all_rules_for_quarter(
        self,
        org_id: UUID,
        quarter_start: datetime,
        providers: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Replay all active rules for a full quarter."""
        quarter_end = quarter_start + timedelta(days=90)

        # Get all active rules for the organization
        stmt = (
            select(Rule)
            .join(Rule.policy)
            .where(and_(Rule.policy.has(org_id=org_id), Rule.is_active == True))
        )

        if providers:
            stmt = stmt.where(Rule.provider.overlap(providers))

        rules = await self.db.scalars(stmt)
        rule_list = list(rules)

        logger.info(
            f"Replaying {len(rule_list)} rules for Q{quarter_start.month//3 + 1} {quarter_start.year}"
        )

        # Replay each rule
        replay_results = []
        total_new_findings = 0

        for rule in rule_list:
            try:
                result = await self.replay_rule_historically(
                    rule.rule_id, org_id, quarter_start, quarter_end, providers
                )
                replay_results.append(result)
                total_new_findings += result.new_findings_count

            except Exception as e:
                logger.error(f"Failed to replay rule {rule.name}: {e}")

        # Generate quarterly summary
        summary = {
            "quarter": f"Q{quarter_start.month//3 + 1} {quarter_start.year}",
            "rules_replayed": len(replay_results),
            "total_evaluations": sum(r.total_evaluations for r in replay_results),
            "total_matches": sum(r.matches_found for r in replay_results),
            "total_new_findings": total_new_findings,
            "rule_effectiveness": {
                r.rule_name: {
                    "match_rate": (r.matches_found / max(r.total_evaluations, 1)) * 100,
                    "new_findings": r.new_findings_count,
                }
                for r in replay_results
            },
            "top_finding_producers": sorted(
                replay_results, key=lambda r: r.new_findings_count, reverse=True
            )[:10],
        }

        return {
            "summary": summary,
            "detailed_results": replay_results,
            "analysis_timestamp": datetime.utcnow().isoformat(),
        }

    async def _get_historical_snapshots(
        self,
        org_id: UUID,
        start_time: datetime,
        end_time: datetime,
        providers: Optional[List[str]],
        resource_types: Optional[List[str]],
    ) -> List[tuple]:
        """Get historical config snapshots for the time period."""
        stmt = (
            select(ConfigSnapshot, Resource)
            .join(Resource)
            .join(Resource.account)
            .where(
                and_(
                    Resource.account.has(org_id=org_id),
                    ConfigSnapshot.captured_at.between(start_time, end_time),
                )
            )
            .order_by(ConfigSnapshot.captured_at)
        )

        if providers:
            stmt = stmt.where(Resource.provider.in_(providers))

        if resource_types:
            stmt = stmt.where(Resource.resource_type.in_(resource_types))

        result = await self.db.execute(stmt)
        return result.fetchall()  # type: ignore[return-value]

    async def _check_existing_finding(
        self, rule_id: UUID, resource_id: UUID, snapshot_time: datetime
    ) -> bool:
        """Check if a finding already existed at the snapshot time."""
        # Generate fingerprint like the real finding manager would
        import hashlib

        fingerprint_str = f"{rule_id}|{resource_id}"
        fingerprint = hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]

        stmt = select(Finding).where(
            and_(
                Finding.rule_id == rule_id,
                Finding.fingerprint == fingerprint,
                Finding.first_seen <= snapshot_time,
            )
        )

        existing = await self.db.scalar(stmt)
        return existing is not None

    def _analyze_rule_coverage(
        self, snapshots: List[tuple], matches: int, rule: Rule
    ) -> Dict[str, Any]:
        """Analyze how well the rule covers historical data."""
        if not snapshots:
            return {}

        # Group by resource type
        resource_type_counts: Dict[str, int] = {}
        for snapshot, resource in snapshots:
            rt = resource.resource_type
            resource_type_counts[rt] = resource_type_counts.get(rt, 0) + 1

        # Provider distribution
        provider_counts: Dict[str, int] = {}
        for snapshot, resource in snapshots:
            prov = resource.provider
            provider_counts[prov] = provider_counts.get(prov, 0) + 1

        # Time distribution
        time_buckets: Dict[str, int] = {}
        for snapshot, resource in snapshots:
            day = snapshot.captured_at.date()
            time_buckets[str(day)] = time_buckets.get(str(day), 0) + 1

        return {
            "total_snapshots_analyzed": len(snapshots),
            "match_rate": (matches / len(snapshots)) * 100,
            "resource_type_distribution": resource_type_counts,
            "provider_distribution": provider_counts,
            "temporal_distribution": time_buckets,
            "rule_specificity": len(rule.resource_types) if rule.resource_types else 0,
        }

    async def what_if_rule_analysis(
        self,
        rule_expression: str,
        org_id: UUID,
        providers: List[str],
        time_period_days: int = 30,
    ) -> Dict[str, Any]:
        """Analyze what would happen if a custom rule had been active."""
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=time_period_days)

        # Create temporary rule for analysis
        temp_rule_id = UUID(
            "00000000-0000-0000-0000-000000000001"
        )  # Deterministic temp ID

        logger.info(f"What-if analysis for custom rule over {time_period_days} days")

        # Get snapshots for analysis
        snapshots = await self._get_historical_snapshots(
            org_id, start_time, end_time, providers, None
        )

        # Evaluate custom rule against snapshots
        evaluations = 0
        matches = 0
        findings = []

        for snapshot, resource in snapshots:
            try:
                context = EvaluationContext(
                    resource={
                        "external_id": resource.external_id,
                        "resource_type": resource.resource_type,
                        "provider": resource.provider,
                        "name": resource.name,
                    },
                    config=snapshot.normalized_config,
                )

                result = self.rule_engine.evaluate_rule(
                    temp_rule_id, rule_expression, context
                )
                evaluations += 1

                if result.matched:
                    matches += 1
                    findings.append(
                        {
                            "resource_external_id": resource.external_id,
                            "resource_type": resource.resource_type,
                            "provider": resource.provider,
                            "timestamp": snapshot.captured_at.isoformat(),
                            "config_subset": self._extract_relevant_config(
                                snapshot.normalized_config, rule_expression
                            ),
                        }
                    )

            except Exception as e:
                logger.warning(f"What-if evaluation failed: {e}")

        return {
            "rule_expression": rule_expression,
            "analysis_period": f"{time_period_days} days",
            "total_evaluations": evaluations,
            "total_matches": matches,
            "match_rate_percentage": (matches / max(evaluations, 1)) * 100,
            "findings_by_provider": self._group_findings_by_provider(findings),
            "findings_by_resource_type": self._group_findings_by_resource_type(
                findings
            ),
            "temporal_pattern": self._analyze_temporal_pattern(findings),
            "sample_findings": findings[:10],  # First 10 for review
        }

    def _extract_relevant_config(
        self, config: Dict[str, Any], rule_expression: str
    ) -> Dict[str, Any]:
        """Extract configuration fields relevant to the rule."""
        # Simple heuristic - look for field names mentioned in the rule
        relevant_fields = {}

        for key, value in config.items():
            if key.lower() in rule_expression.lower():
                relevant_fields[key] = value

        # Always include common security fields
        security_fields = ["encryption", "public", "visibility", "policy", "acl", "mfa"]
        for field in security_fields:
            if field in config:
                relevant_fields[field] = config[field]

        return relevant_fields

    def _group_findings_by_provider(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Group findings by provider."""
        counts: Dict[str, int] = {}
        for finding in findings:
            provider = finding["provider"]
            counts[provider] = counts.get(provider, 0) + 1
        return counts

    def _group_findings_by_resource_type(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Group findings by resource type."""
        counts: Dict[str, int] = {}
        for finding in findings:
            resource_type = finding["resource_type"]
            counts[resource_type] = counts.get(resource_type, 0) + 1
        return counts

    def _analyze_temporal_pattern(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyze temporal patterns in findings."""
        if not findings:
            return {}

        # Group by day
        daily_counts: Dict[str, int] = {}
        for finding in findings:
            day = finding["timestamp"][:10]  # YYYY-MM-DD
            daily_counts[day] = daily_counts.get(day, 0) + 1

        # Calculate trend
        dates = sorted(daily_counts.keys())
        if len(dates) > 1:
            first_half = dates[: len(dates) // 2]
            second_half = dates[len(dates) // 2 :]

            first_avg = sum(daily_counts[d] for d in first_half) / len(first_half)
            second_avg = sum(daily_counts[d] for d in second_half) / len(second_half)

            trend = (
                "increasing"
                if second_avg > first_avg * 1.1
                else "decreasing" if second_avg < first_avg * 0.9 else "stable"
            )
        else:
            trend = "insufficient_data"

        return {
            "daily_distribution": daily_counts,
            "peak_day": (
                max(daily_counts.items(), key=lambda x: x[1]) if daily_counts else None
            ),
            "trend": trend,
            "total_days_with_findings": len(daily_counts),
        }

    async def simulate_rule_deployment(
        self,
        rule_expression: str,
        org_id: UUID,
        deployment_date: datetime,
        simulation_days: int = 30,
    ) -> Dict[str, Any]:
        """Simulate what would happen if a rule was deployed on a specific date."""
        end_date = deployment_date + timedelta(days=simulation_days)

        # Analyze the period as if the rule existed
        what_if_result = await self.what_if_rule_analysis(
            rule_expression, org_id, [], simulation_days
        )

        # Get actual findings that occurred in that period for comparison
        actual_findings = await self._get_actual_findings_in_period(
            org_id, deployment_date, end_date
        )

        return {
            "simulation_scenario": {
                "rule_expression": rule_expression,
                "deployment_date": deployment_date.isoformat(),
                "simulation_period": f"{simulation_days} days",
            },
            "simulated_results": what_if_result,
            "actual_findings_for_comparison": {
                "total_actual_findings": len(actual_findings),
                "actual_findings_by_severity": self._group_by_severity(actual_findings),
            },
            "value_assessment": {
                "additional_findings": what_if_result["total_matches"],
                "coverage_gap_percentage": self._calculate_coverage_gap(
                    what_if_result, actual_findings
                ),
                "recommended_deployment": what_if_result["total_matches"] > 0,
            },
        }

    async def _get_actual_findings_in_period(
        self, org_id: UUID, start_time: datetime, end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Get actual findings that occurred in a time period."""
        stmt = select(Finding).where(
            and_(
                Finding.org_id == org_id,
                Finding.first_seen.between(start_time, end_time),
            )
        )

        findings = await self.db.scalars(stmt)

        return [
            {
                "finding_id": str(f.finding_id),
                "title": f.title,
                "severity": f.severity,
                "provider": f.provider,
                "first_seen": f.first_seen.isoformat(),
            }
            for f in findings
        ]

    def _group_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Group findings by severity."""
        counts: Dict[str, int] = {}
        for finding in findings:
            severity = finding["severity"]
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def _calculate_coverage_gap(
        self, what_if_result: Dict[str, Any], actual_findings: List[Dict[str, Any]]
    ) -> float:
        """Calculate what percentage of issues the new rule would have caught."""
        if not actual_findings:
            return 0.0

        # Simple heuristic - assumes rule would have caught additional issues
        additional_coverage = what_if_result["total_matches"]
        current_coverage = len(actual_findings)

        return (additional_coverage / (additional_coverage + current_coverage)) * 100

    async def generate_rule_effectiveness_report(
        self, org_id: UUID, lookback_days: int = 90
    ) -> Dict[str, Any]:
        """Generate report on rule effectiveness over time."""
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=lookback_days)

        # Get all rules for the organization
        stmt = select(Rule).join(Rule.policy).where(Rule.policy.has(org_id=org_id))
        rules = await self.db.scalars(stmt)

        rule_effectiveness = []

        for rule in rules:
            # Replay rule over the period
            result = await self.replay_rule_historically(
                rule.rule_id, org_id, start_time, end_time
            )

            # Calculate effectiveness metrics
            effectiveness_score = self._calculate_effectiveness_score(result)

            rule_effectiveness.append(
                {
                    "rule_name": rule.name,
                    "rule_id": str(rule.rule_id),
                    "effectiveness_score": effectiveness_score,
                    "findings_generated": result.new_findings_count,
                    "match_rate": (
                        result.matches_found / max(result.total_evaluations, 1)
                    )
                    * 100,
                    "performance": result.performance_metrics,
                    "recommendation": self._get_rule_recommendation(
                        effectiveness_score, result
                    ),
                }
            )

        # Sort by effectiveness
        rule_effectiveness.sort(
            key=lambda r: float(r.get("effectiveness_score", 0)),  # type: ignore[arg-type]
            reverse=True
        )

        org = await self.db.get(Organization, org_id)
        high_eff = [r for r in rule_effectiveness if float(r.get("effectiveness_score", 0)) > 0.7]  # type: ignore[arg-type]
        low_eff = [r for r in rule_effectiveness if float(r.get("effectiveness_score", 0)) < 0.3]  # type: ignore[arg-type]
        avg_eff = sum(float(r.get("effectiveness_score", 0)) for r in rule_effectiveness)  # type: ignore[arg-type, misc]
        return {
            "organization": org.name if org else "Unknown",
            "analysis_period": f"{lookback_days} days",
            "rule_effectiveness": rule_effectiveness,
            "summary": {
                "total_rules_analyzed": len(rule_effectiveness),
                "high_effectiveness_rules": len(high_eff),
                "low_effectiveness_rules": len(low_eff),
                "avg_effectiveness": avg_eff / max(len(rule_effectiveness), 1),
            },
        }

    def _calculate_effectiveness_score(self, result: RuleReplayResult) -> float:
        """Calculate rule effectiveness score (0-1)."""
        if result.total_evaluations == 0:
            return 0.0

        # Weight multiple factors
        match_rate = result.matches_found / result.total_evaluations
        new_findings_rate = result.new_findings_count / result.total_evaluations

        # Effective rules should have moderate match rates (not too high/low)
        # and generate actionable findings
        effectiveness = (match_rate * 0.4) + (new_findings_rate * 0.6)

        # Penalize rules that match everything or nothing
        if match_rate > 0.9 or match_rate < 0.01:
            effectiveness *= 0.5

        return min(effectiveness, 1.0)

    def _get_rule_recommendation(
        self, effectiveness_score: float, result: RuleReplayResult
    ) -> str:
        """Get recommendation for rule based on effectiveness."""
        if effectiveness_score > 0.7:
            return "high_value_keep_active"
        elif effectiveness_score > 0.3:
            return "moderate_value_consider_tuning"
        elif result.total_evaluations < 10:
            return "insufficient_data_monitor"
        else:
            return "low_value_consider_disabling"
