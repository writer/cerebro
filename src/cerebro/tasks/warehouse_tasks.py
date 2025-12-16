"""Snowflake warehouse maintenance tasks."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from uuid import uuid4

from celery import states
from sqlalchemy import text

from cerebro.core.config import settings
from cerebro.core.warehouse import resolve_snowflake_database_url, warehouse_session
from cerebro.tasks.celery_app import celery_app


logger = logging.getLogger(__name__)


_DEV_ENVIRONMENTS = {"dev", "development", "test", "testing"}


@celery_app.task(
    bind=True,
    name="cerebro.tasks.warehouse_tasks.refresh_rule_controls",
)
def refresh_rule_controls(self) -> dict[str, object]:
    """Rebuild the derived rule_controls mapping table in the Snowflake warehouse."""

    if not resolve_snowflake_database_url():
        env = (settings.environment or "development").lower()
        if env in _DEV_ENVIRONMENTS:
            logger.info("Snowflake not configured; skipping rule_controls refresh")
            return {"skipped": True, "reason": "SNOWFLAKE_DATABASE_URL not configured"}
        raise RuntimeError("SNOWFLAKE_DATABASE_URL is not configured")

    self.update_state(state=states.STARTED, meta={"status": "Refreshing rule_controls"})

    job_run_id = str(uuid4())
    component = (
        os.getenv("CELERY_PROCESS_ROLE")
        or os.getenv("CEREBRO_PROCESS_ROLE")
        or os.getenv("CEREBRO_COMPONENT")
        or "worker"
    )
    started_at = datetime.now(timezone.utc)

    with warehouse_session() as session:
        try:
            session.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS warehouse_job_runs (
                        job_run_id STRING NOT NULL,
                        job_name STRING NOT NULL,
                        component STRING,
                        status STRING NOT NULL,
                        started_at TIMESTAMP_TZ,
                        finished_at TIMESTAMP_TZ,
                        row_count INTEGER,
                        details VARIANT,
                        created_at TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
                        PRIMARY KEY (job_run_id)
                    )
                    """
                )
            )

            session.execute(
                text(
                    """
                    INSERT INTO warehouse_job_runs (
                        job_run_id,
                        job_name,
                        component,
                        status,
                        started_at,
                        details
                    )
                    VALUES (
                        :job_run_id,
                        :job_name,
                        :component,
                        :status,
                        :started_at,
                        PARSE_JSON(:details)
                    )
                    """
                ),
                {
                    "job_run_id": job_run_id,
                    "job_name": "refresh_rule_controls",
                    "component": component,
                    "status": "started",
                    "started_at": started_at,
                    "details": json.dumps({"task_id": self.request.id}),
                },
            )

            session.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS rule_controls (
                        rule_id STRING NOT NULL,
                        framework STRING NOT NULL,
                        control_id STRING NOT NULL,
                        created_at TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
                        PRIMARY KEY (rule_id, framework, control_id)
                    )
                    """
                )
            )

            # Build into a staging table then atomically swap, so readers never observe an empty table.
            # COPY GRANTS ensures the swapped-in table retains the grants readers expect.
            session.execute(
                text("CREATE OR REPLACE TABLE rule_controls_staging LIKE rule_controls COPY GRANTS")
            )
            session.execute(text("TRUNCATE TABLE rule_controls_staging"))
            session.execute(
                text(
                    """
                    INSERT INTO rule_controls_staging (rule_id, framework, control_id)
                    SELECT DISTINCT r.rule_id, 'CIS' AS framework, elem.value::string AS control_id
                    FROM rules r, LATERAL FLATTEN(input => r.cis) elem
                    WHERE r.cis IS NOT NULL

                    UNION ALL

                    SELECT DISTINCT r.rule_id, 'NIST_800_53' AS framework, elem.value::string AS control_id
                    FROM rules r, LATERAL FLATTEN(input => r.nist_800_53) elem
                    WHERE r.nist_800_53 IS NOT NULL
                    """
                )
            )
            session.execute(text("ALTER TABLE rule_controls SWAP WITH rule_controls_staging"))
            session.execute(text("DROP TABLE IF EXISTS rule_controls_staging"))

            row_count = session.execute(text("SELECT COUNT(*) AS cnt FROM rule_controls")).scalar() or 0
            finished_at = datetime.now(timezone.utc)

            session.execute(
                text(
                    """
                    UPDATE warehouse_job_runs
                    SET status = :status,
                        finished_at = :finished_at,
                        row_count = :row_count
                    WHERE job_run_id = :job_run_id
                    """
                ),
                {
                    "status": "success",
                    "finished_at": finished_at,
                    "row_count": int(row_count),
                    "job_run_id": job_run_id,
                },
            )

            session.commit()

        except Exception as exc:
            logger.exception("Failed to refresh rule_controls")
            try:
                session.execute(
                    text(
                        """
                        UPDATE warehouse_job_runs
                        SET status = :status,
                            finished_at = :finished_at,
                            details = PARSE_JSON(:details)
                        WHERE job_run_id = :job_run_id
                        """
                    ),
                    {
                        "status": "failed",
                        "finished_at": datetime.now(timezone.utc),
                        "details": json.dumps({"error": str(exc)}),
                        "job_run_id": job_run_id,
                    },
                )
                session.commit()
            except Exception:  # pragma: no cover
                session.rollback()
            raise

    payload = {"status": "Completed", "skipped": False, "job_run_id": job_run_id}
    self.update_state(state=states.SUCCESS, meta=payload)
    return payload


@celery_app.task(
    bind=True,
    name="cerebro.tasks.warehouse_tasks.run_warehouse_data_quality_checks",
)
def run_warehouse_data_quality_checks(self) -> dict[str, object]:
    """Run lightweight warehouse data quality checks and record the results."""

    if not resolve_snowflake_database_url():
        env = (settings.environment or "development").lower()
        if env in _DEV_ENVIRONMENTS:
            logger.info("Snowflake not configured; skipping warehouse DQ checks")
            return {"skipped": True, "reason": "SNOWFLAKE_DATABASE_URL not configured"}
        raise RuntimeError("SNOWFLAKE_DATABASE_URL is not configured")

    self.update_state(state=states.STARTED, meta={"status": "Running warehouse DQ checks"})

    job_run_id = str(uuid4())
    component = (
        os.getenv("CELERY_PROCESS_ROLE")
        or os.getenv("CEREBRO_PROCESS_ROLE")
        or os.getenv("CEREBRO_COMPONENT")
        or "worker"
    )
    started_at = datetime.now(timezone.utc)

    checks: dict[str, str] = {
        "findings_orphan_accounts": """
            SELECT COUNT(*)
            FROM findings f
            LEFT JOIN accounts a ON f.account_id = a.account_id
            WHERE a.account_id IS NULL
        """,
        "findings_orphan_rules": """
            SELECT COUNT(*)
            FROM findings f
            LEFT JOIN rules r ON f.rule_id = r.rule_id
            WHERE r.rule_id IS NULL
        """,
        "accounts_orphan_orgs": """
            SELECT COUNT(*)
            FROM accounts a
            LEFT JOIN orgs o ON a.org_id = o.org_id
            WHERE o.org_id IS NULL
        """,
        "duplicate_finding_ids": """
            SELECT GREATEST(COUNT(*) - COUNT(DISTINCT finding_id), 0)
            FROM findings
        """,
        "duplicate_account_ids": """
            SELECT GREATEST(COUNT(*) - COUNT(DISTINCT account_id), 0)
            FROM accounts
        """,
    }

    results: dict[str, int] = {}

    with warehouse_session() as session:
        try:
            session.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS warehouse_job_runs (
                        job_run_id STRING NOT NULL,
                        job_name STRING NOT NULL,
                        component STRING,
                        status STRING NOT NULL,
                        started_at TIMESTAMP_TZ,
                        finished_at TIMESTAMP_TZ,
                        row_count INTEGER,
                        details VARIANT,
                        created_at TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
                        PRIMARY KEY (job_run_id)
                    )
                    """
                )
            )

            session.execute(
                text(
                    """
                    INSERT INTO warehouse_job_runs (
                        job_run_id,
                        job_name,
                        component,
                        status,
                        started_at,
                        details
                    )
                    VALUES (
                        :job_run_id,
                        :job_name,
                        :component,
                        :status,
                        :started_at,
                        PARSE_JSON(:details)
                    )
                    """
                ),
                {
                    "job_run_id": job_run_id,
                    "job_name": "warehouse_data_quality_checks",
                    "component": component,
                    "status": "started",
                    "started_at": started_at,
                    "details": json.dumps({"task_id": self.request.id}),
                },
            )

            for name, sql in checks.items():
                results[name] = int(session.execute(text(sql)).scalar() or 0)

            issue_total = sum(results.values())
            status = "success" if issue_total == 0 else "warning"
            finished_at = datetime.now(timezone.utc)

            session.execute(
                text(
                    """
                    UPDATE warehouse_job_runs
                    SET status = :status,
                        finished_at = :finished_at,
                        row_count = :row_count,
                        details = PARSE_JSON(:details)
                    WHERE job_run_id = :job_run_id
                    """
                ),
                {
                    "status": status,
                    "finished_at": finished_at,
                    "row_count": issue_total,
                    "details": json.dumps({"checks": results}),
                    "job_run_id": job_run_id,
                },
            )

            session.commit()

        except Exception as exc:
            logger.exception("Failed to run warehouse DQ checks")
            try:
                session.execute(
                    text(
                        """
                        UPDATE warehouse_job_runs
                        SET status = :status,
                            finished_at = :finished_at,
                            details = PARSE_JSON(:details)
                        WHERE job_run_id = :job_run_id
                        """
                    ),
                    {
                        "status": "failed",
                        "finished_at": datetime.now(timezone.utc),
                        "details": json.dumps({"error": str(exc)}),
                        "job_run_id": job_run_id,
                    },
                )
                session.commit()
            except Exception:  # pragma: no cover
                session.rollback()
            raise

    payload = {
        "status": "Completed",
        "skipped": False,
        "job_run_id": job_run_id,
        "issue_total": sum(results.values()),
        "checks": results,
    }
    self.update_state(state=states.SUCCESS, meta=payload)
    return payload
