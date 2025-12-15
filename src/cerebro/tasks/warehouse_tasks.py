"""Snowflake warehouse maintenance tasks."""

from __future__ import annotations

import logging

from celery import states
from sqlalchemy import text

from cerebro.core.warehouse import resolve_snowflake_database_url, warehouse_session
from cerebro.tasks.celery_app import celery_app


logger = logging.getLogger(__name__)


@celery_app.task(
    bind=True,
    name="cerebro.tasks.warehouse_tasks.refresh_rule_controls",
)
def refresh_rule_controls(self) -> dict[str, object]:
    """Rebuild the derived rule_controls mapping table in the Snowflake warehouse."""

    if not resolve_snowflake_database_url():
        logger.info("Snowflake not configured; skipping rule_controls refresh")
        return {"skipped": True, "reason": "SNOWFLAKE_DATABASE_URL not configured"}

    self.update_state(state=states.STARTED, meta={"status": "Refreshing rule_controls"})

    with warehouse_session() as session:
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
        session.commit()

    payload = {"status": "Completed", "skipped": False}
    self.update_state(state=states.SUCCESS, meta=payload)
    return payload
