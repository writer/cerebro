"""
Proactive Security Monitoring

Background agents that continuously monitor for security events and proactively alert users.
"""

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from uuid import UUID

import structlog
from sqlalchemy import select, and_, text
from sqlalchemy.orm import selectinload

from cerebro.core.database import async_session_factory
from cerebro.core.models import Finding, Organization
from cerebro.agents.models import AgentSession, AgentType
from cerebro.agents.runtime import CerebroClaudeRuntime
from cerebro.notifications.slack import get_slack_service

logger = structlog.get_logger(__name__)


# ==================== Monitoring Configuration ====================

class MonitoringRule:
    """Configuration for what to monitor and when to alert."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        check_interval_seconds: int,
        condition: str,  # SQL condition or callable
        severity_threshold: str = "high",  # minimum severity to alert
        enabled: bool = True,
    ):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.check_interval_seconds = check_interval_seconds
        self.condition = condition
        self.severity_threshold = severity_threshold
        self.enabled = enabled
        self.last_check: Optional[datetime] = None


# Default monitoring rules
DEFAULT_MONITORING_RULES = [
    MonitoringRule(
        rule_id="critical_findings",
        name="New Critical Findings",
        description="Alert on new critical severity findings",
        check_interval_seconds=300,  # 5 minutes
        condition="severity = 'critical' AND status = 'open'",
        severity_threshold="critical",
    ),
    MonitoringRule(
        rule_id="public_s3_buckets",
        name="Public S3 Buckets",
        description="Alert on S3 buckets becoming publicly accessible",
        check_interval_seconds=600,  # 10 minutes
        condition="title LIKE '%S3%public%' AND severity IN ('critical', 'high')",
        severity_threshold="high",
    ),
    MonitoringRule(
        rule_id="admin_access_changes",
        name="Admin Access Changes",
        description="Alert on changes to admin permissions",
        check_interval_seconds=300,  # 5 minutes
        condition="title LIKE '%admin%' OR title LIKE '%AdministratorAccess%'",
        severity_threshold="high",
    ),
    MonitoringRule(
        rule_id="compliance_failures",
        name="Compliance Control Failures",
        description="Alert on failed compliance controls",
        check_interval_seconds=1800,  # 30 minutes
        condition="compliance_frameworks IS NOT NULL AND jsonb_array_length(compliance_frameworks) > 0",
        severity_threshold="medium",
    ),
]


# ==================== Monitoring Service ====================

class ProactiveMonitoringService:
    """
    Background service that monitors for security events and alerts proactively.

    Features:
    - Continuous monitoring based on rules
    - Event-driven alerts for critical findings
    - Periodic anomaly detection
    - Configurable notification channels
    """

    def __init__(self):
        self.runtime = CerebroClaudeRuntime()
        self.monitoring_rules = DEFAULT_MONITORING_RULES.copy()
        self.is_running = False
        self.monitoring_tasks: Dict[str, asyncio.Task] = {}

    async def start_monitoring(self, org_id: UUID):
        """
        Start proactive monitoring for an organization.

        Args:
            org_id: Organization to monitor
        """

        if self.is_running:
            logger.warning("Monitoring already running", org_id=org_id)
            return

        self.is_running = True

        logger.info("Starting proactive monitoring", org_id=org_id, rules_count=len(self.monitoring_rules))

        # Start monitoring tasks for each rule
        for rule in self.monitoring_rules:
            if rule.enabled:
                task = asyncio.create_task(
                    self._monitor_rule(org_id, rule)
                )
                self.monitoring_tasks[rule.rule_id] = task

        # Start periodic anomaly detection
        anomaly_task = asyncio.create_task(
            self._periodic_anomaly_detection(org_id)
        )
        self.monitoring_tasks["anomaly_detection"] = anomaly_task

        logger.info("All monitoring tasks started", org_id=org_id)

    async def stop_monitoring(self):
        """Stop all monitoring tasks."""

        logger.info("Stopping proactive monitoring")
        self.is_running = False

        # Cancel all tasks
        for task_name, task in self.monitoring_tasks.items():
            logger.info("Cancelling monitoring task", task=task_name)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        self.monitoring_tasks.clear()
        logger.info("All monitoring tasks stopped")

    async def _monitor_rule(self, org_id: UUID, rule: MonitoringRule):
        """
        Monitor a specific rule continuously.

        Args:
            org_id: Organization ID
            rule: Monitoring rule to check
        """

        logger.info("Starting rule monitor", rule=rule.name, interval=rule.check_interval_seconds)

        while self.is_running:
            try:
                # Check for new findings matching rule condition
                new_findings = await self._check_rule_condition(org_id, rule)

                if new_findings:
                    logger.info(
                        "Rule triggered",
                        rule=rule.name,
                        findings_count=len(new_findings),
                    )

                    # Send alert for each new finding
                    for finding in new_findings:
                        await self._send_alert(
                            org_id=org_id,
                            alert_type=rule.rule_id,
                            title=rule.name,
                            message=f"🚨 {rule.description}: {finding.title}",
                            finding=finding,
                            severity=finding.severity,
                        )

                # Update last check time
                rule.last_check = datetime.now(timezone.utc)

                # Sleep until next check
                await asyncio.sleep(rule.check_interval_seconds)

            except asyncio.CancelledError:
                logger.info("Rule monitor cancelled", rule=rule.name)
                raise
            except Exception as e:
                logger.exception("Rule monitor error", rule=rule.name, error=str(e))
                # Continue monitoring despite errors
                await asyncio.sleep(60)  # Wait 1 min before retry

    async def _check_rule_condition(
        self,
        org_id: UUID,
        rule: MonitoringRule,
    ) -> List[Finding]:
        """
        Check if rule condition is met and return new findings.

        Args:
            org_id: Organization ID
            rule: Monitoring rule

        Returns:
            List of new findings matching condition
        """

        async with async_session_factory() as db_session:
            # Build query with rule condition
            since_time = rule.last_check or (datetime.now(timezone.utc) - timedelta(hours=1))

            query = select(Finding).where(
                and_(
                    Finding.org_id == org_id,
                    Finding.created_at > since_time,
                    text(rule.condition),
                )
            ).order_by(Finding.created_at.desc())

            result = await db_session.execute(query)
            findings = result.scalars().all()

            return list(findings)

    async def _periodic_anomaly_detection(self, org_id: UUID):
        """
        Run anomaly detection periodically (hourly).

        Args:
            org_id: Organization ID
        """

        logger.info("Starting periodic anomaly detection", org_id=org_id)

        while self.is_running:
            try:
                # Run anomaly detection
                from cerebro.agents.tools.identity_anomaly_hunter import IdentityAnomalyHunterTool
                from cerebro.agents.tools.base import AgentContext

                anomaly_tool = IdentityAnomalyHunterTool()
                context = AgentContext(
                    session_id=UUID('00000000-0000-0000-0000-000000000000'),
                    org_id=org_id,
                    user_id="system",
                    agent_type="background_monitor",
                )

                result = await anomaly_tool.execute(
                    context=context,
                    lookback_days=1,  # Last 24 hours
                    min_risk_level="high",
                )

                if result.success and result.data:
                    anomalies = result.data.get("anomalies", [])
                    critical_count = result.data.get("critical_count", 0)
                    high_count = result.data.get("high_count", 0)

                    if critical_count > 0 or high_count > 0:
                        logger.info(
                            "Anomalies detected",
                            critical=critical_count,
                            high=high_count,
                        )

                        # Send alert
                        await self._send_alert(
                            org_id=org_id,
                            alert_type="anomaly_detection",
                            title="Identity Anomalies Detected",
                            message=f"🔍 Detected {critical_count} critical and {high_count} high-risk identity anomalies",
                            severity="high" if critical_count > 0 else "medium",
                            metadata={"anomalies": anomalies[:5]},  # First 5
                        )

                # Run hourly
                await asyncio.sleep(3600)

            except asyncio.CancelledError:
                logger.info("Anomaly detection cancelled")
                raise
            except Exception as e:
                logger.exception("Anomaly detection error", error=str(e))
                await asyncio.sleep(600)  # Wait 10 min before retry

    async def _send_alert(
        self,
        org_id: UUID,
        alert_type: str,
        title: str,
        message: str,
        severity: str = "high",
        finding: Optional[Finding] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """
        Send proactive alert to user via configured notification channels.

        Notification channels:
        - Slack webhook ✅ Implemented
        - In-app notification (TODO)
        - Email (TODO)
        - PagerDuty (TODO)
        - Custom webhook (TODO)

        Args:
            org_id: Organization ID
            alert_type: Type of alert
            title: Alert title
            message: Alert message
            severity: Alert severity
            finding: Related finding (optional)
            metadata: Additional metadata
        """

        logger.info(
            "Sending proactive alert",
            org_id=org_id,
            alert_type=alert_type,
            title=title,
            severity=severity,
        )

        alert_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "org_id": str(org_id),
            "alert_type": alert_type,
            "title": title,
            "message": message,
            "severity": severity,
            "finding_id": str(finding.finding_id) if finding else None,
            "metadata": metadata,
        }

        logger.info("Alert created", alert_data=alert_data)

        # Send notifications through configured channels
        try:
            # Send to Slack if webhooks configured
            async with async_session_factory() as db:
                slack_service = get_slack_service()

                # If this is a finding alert, use the finding notification method
                if finding:
                    await slack_service.send_finding_notification(
                        org_id=org_id,
                        finding=finding,
                        db=db,
                    )
                else:
                    # Send as monitoring alert
                    await slack_service.send_monitoring_alert(
                        org_id=org_id,
                        alert_title=title,
                        alert_description=message,
                        severity=severity,
                        db=db,
                    )

        except Exception as e:
            logger.error("Failed to send Slack notification", error=str(e))

    async def _deliver_notification(self, org_id: UUID, alert_data: Dict[str, Any]):
        """
        Deliver notification through configured channels.

        Args:
            org_id: Organization ID
            alert_data: Alert data to send
        """

        # TODO: Implement notification channels
        # - Email via SMTP
        # - Slack via webhook
        - # PagerDuty API
        # - Custom webhooks from org config

        pass


# ==================== Monitoring API ====================

class MonitoringAPI:
    """API for managing proactive monitoring."""

    def __init__(self):
        self.service = ProactiveMonitoringService()
        self.active_monitors: Dict[UUID, ProactiveMonitoringService] = {}

    async def start_monitoring(self, org_id: UUID):
        """Start monitoring for an organization."""

        if org_id in self.active_monitors:
            logger.warning("Monitoring already active", org_id=org_id)
            return

        service = ProactiveMonitoringService()
        await service.start_monitoring(org_id)
        self.active_monitors[org_id] = service

        logger.info("Monitoring started", org_id=org_id)

    async def stop_monitoring(self, org_id: UUID):
        """Stop monitoring for an organization."""

        if org_id not in self.active_monitors:
            logger.warning("No active monitoring", org_id=org_id)
            return

        service = self.active_monitors[org_id]
        await service.stop_monitoring()
        del self.active_monitors[org_id]

        logger.info("Monitoring stopped", org_id=org_id)

    def get_monitoring_status(self, org_id: UUID) -> Dict[str, Any]:
        """Get monitoring status for an organization."""

        if org_id not in self.active_monitors:
            return {"status": "inactive", "rules": []}

        service = self.active_monitors[org_id]
        return {
            "status": "active" if service.is_running else "stopped",
            "rules": [
                {
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "enabled": rule.enabled,
                    "last_check": rule.last_check.isoformat() if rule.last_check else None,
                    "check_interval_seconds": rule.check_interval_seconds,
                }
                for rule in service.monitoring_rules
            ],
            "active_tasks": len(service.monitoring_tasks),
        }


# Global monitoring API instance
monitoring_api = MonitoringAPI()