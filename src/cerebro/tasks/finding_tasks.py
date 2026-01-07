"""Finding generation background tasks."""

import asyncio
from datetime import datetime
from uuid import UUID

import structlog

from cerebro.core.database import async_session_factory
from cerebro.core.models import Organization, Rule
from cerebro.findings.evaluator import RuleEvaluator
from cerebro.findings.manager import FindingManager
from cerebro.rules.engine import rule_engine
from cerebro.tasks.celery_app import celery_app

logger = structlog.get_logger(__name__)


@celery_app.task(bind=True, name="cerebro.tasks.finding_tasks.generate_findings_task")
def generate_findings_task(
    self,
    org_id: str,
    provider: str | None = None,
    resource_types: list[str] | None = None,
    rule_ids: list[str] | None = None,
):
    """Background task to generate findings for an organization."""

    async def _generate():
        task_id = self.request.id
        logger.info(f"Starting finding generation task {task_id} for org {org_id}")

        try:
            self.update_state(
                state="PROGRESS", meta={"status": "Initializing", "progress": 0}
            )

            async with async_session_factory() as db:
                # Get organization
                org = await db.get(Organization, UUID(org_id))
                if not org:
                    raise ValueError("Organization not found")

                self.update_state(
                    state="PROGRESS", meta={"status": "Loading rules", "progress": 10}
                )

                # Initialize finding services
                rule_evaluator = RuleEvaluator(db, rule_engine)
                finding_manager = FindingManager(db, rule_evaluator)

                self.update_state(
                    state="PROGRESS",
                    meta={"status": "Evaluating rules", "progress": 20},
                )

                # Generate findings
                result = await finding_manager.generate_findings(
                    org, provider, resource_types
                )

                self.update_state(
                    state="PROGRESS",
                    meta={"status": "Findings generated", "progress": 100},
                )

                logger.info(
                    f"Finding generation task {task_id} completed: "
                    f"{result.findings_created} created, "
                    f"{result.findings_updated} updated, "
                    f"{result.findings_closed} closed"
                )

                return {
                    "org_id": org_id,
                    "findings_created": result.findings_created,
                    "findings_updated": result.findings_updated,
                    "findings_closed": result.findings_closed,
                    "errors": result.errors,
                }

        except (OSError, RuntimeError, ValueError) as e:
            logger.error(f"Finding generation task {task_id} failed: {e}")
            self.update_state(state="FAILURE", meta={"error": str(e)})
            raise

    return asyncio.run(_generate())


@celery_app.task(bind=True, name="cerebro.tasks.finding_tasks.evaluate_rule_batch")
def evaluate_rule_batch(self, rule_id: str, resource_ids: list[str]):
    """Evaluate a specific rule against a batch of resources."""

    async def _evaluate():
        task_id = self.request.id
        logger.info(
            f"Starting rule evaluation task {task_id} for rule {rule_id} against {len(resource_ids)} resources"
        )

        try:
            self.update_state(
                state="PROGRESS",
                meta={"status": "Loading rule and resources", "progress": 0},
            )

            async with async_session_factory() as db:
                from sqlalchemy import select

                from cerebro.core.models import Resource

                # Get rule
                rule = await db.get(Rule, UUID(rule_id))
                if not rule:
                    raise ValueError("Rule not found")

                # Get resources
                stmt = select(Resource).where(
                    Resource.resource_id.in_([UUID(rid) for rid in resource_ids])
                )
                resources = list(await db.scalars(stmt))

                if not resources:
                    return {"message": "No resources found for evaluation"}

                self.update_state(
                    state="PROGRESS",
                    meta={
                        "status": f"Evaluating rule against {len(resources)} resources",
                        "progress": 20,
                    },
                )

                # Initialize evaluator
                rule_evaluator = RuleEvaluator(db, rule_engine)

                matches = []
                errors = []

                for i, resource in enumerate(resources):
                    try:
                        results = await rule_evaluator.evaluate_resource(
                            resource, [rule]
                        )

                        for result in results:
                            if result.matched:
                                matches.append(
                                    {
                                        "resource_id": str(resource.resource_id),
                                        "resource_external_id": resource.external_id,
                                        "execution_time_ms": result.execution_time_ms,
                                    }
                                )

                        progress = int(20 + (i / len(resources)) * 80)
                        self.update_state(
                            state="PROGRESS",
                            meta={
                                "status": f"Evaluated {i+1}/{len(resources)} resources",
                                "progress": progress,
                                "matches_found": len(matches),
                            },
                        )

                    except (OSError, RuntimeError, ValueError) as e:
                        logger.warning(
                            f"Rule evaluation failed for resource {resource.resource_id}: {e}"
                        )
                        errors.append(f"Resource {resource.external_id}: {e!s}")

                logger.info(
                    f"Rule evaluation task {task_id} completed: {len(matches)} matches, {len(errors)} errors"
                )

                return {
                    "rule_id": rule_id,
                    "resources_evaluated": len(resources),
                    "matches": matches,
                    "errors": errors,
                }

        except (OSError, RuntimeError, ValueError) as e:
            logger.error(f"Rule evaluation task {task_id} failed: {e}")
            self.update_state(state="FAILURE", meta={"error": str(e)})
            raise

    return asyncio.run(_evaluate())


@celery_app.task(
    bind=True, name="cerebro.tasks.finding_tasks.update_finding_status_batch"
)
def update_finding_status_batch(
    self, finding_ids: list[str], status: str, reason: str | None = None
):
    """Batch update finding statuses."""

    async def _update():
        task_id = self.request.id
        logger.info(
            f"Starting batch finding status update {task_id} for {len(finding_ids)} findings"
        )

        try:
            self.update_state(
                state="PROGRESS", meta={"status": "Loading findings", "progress": 0}
            )

            async with async_session_factory() as db:
                from sqlalchemy import select

                from cerebro.core.models import Finding

                # Get findings
                stmt = select(Finding).where(
                    Finding.finding_id.in_([UUID(fid) for fid in finding_ids])
                )
                findings = list(await db.scalars(stmt))

                if not findings:
                    return {"message": "No findings found for update"}

                updated = 0
                errors = []

                for i, finding in enumerate(findings):
                    try:
                        # Update status
                        finding.status = status
                        finding.last_seen = datetime.utcnow()

                        # Add reason to evidence if provided
                        if reason:
                            if not finding.evidence:
                                finding.evidence = {}
                            finding.evidence[f"{status}_reason"] = reason

                        updated += 1

                        progress = int((i / len(findings)) * 100)
                        self.update_state(
                            state="PROGRESS",
                            meta={
                                "status": f"Updated {updated}/{len(findings)} findings",
                                "progress": progress,
                            },
                        )

                    except (OSError, RuntimeError, ValueError) as e:
                        logger.warning(
                            f"Failed to update finding {finding.finding_id}: {e}"
                        )
                        errors.append(f"Finding {finding.finding_id}: {e!s}")

                # Commit changes
                await db.commit()

                logger.info(
                    f"Batch finding update task {task_id} completed: {updated} updated, {len(errors)} errors"
                )

                return {"updated": updated, "errors": errors, "total": len(findings)}

        except (OSError, RuntimeError, ValueError) as e:
            logger.error(f"Batch finding update task {task_id} failed: {e}")
            self.update_state(state="FAILURE", meta={"error": str(e)})
            raise

    return asyncio.run(_update())
