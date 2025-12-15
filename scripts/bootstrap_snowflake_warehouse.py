"""Bootstrap the Snowflake warehouse schema used by Cerebro analytics.

This script is intentionally idempotent (CREATE ... IF NOT EXISTS) and does not
require Alembic.
"""

from __future__ import annotations

import argparse
import os
from typing import Iterable, List, Optional

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool


def _quote_ident(identifier: str) -> str:
    escaped = identifier.replace('"', '""')
    return f'"{escaped}"'


def _build_ddl() -> List[str]:
    # NOTE: Snowflake unquoted identifiers are case-insensitive, and our code
    # issues unquoted SQL (e.g. `FROM rules`). Keep names simple and unquoted.
    return [
        """
        CREATE TABLE IF NOT EXISTS orgs (
            org_id STRING NOT NULL,
            name STRING NOT NULL,
            created_at TIMESTAMP_TZ,
            PRIMARY KEY (org_id)
        )
        """.strip(),
        """
        CREATE TABLE IF NOT EXISTS accounts (
            account_id STRING NOT NULL,
            org_id STRING NOT NULL,
            provider STRING NOT NULL,
            external_id STRING NOT NULL,
            display_name STRING,
            PRIMARY KEY (account_id)
        )
        """.strip(),
        """
        CREATE TABLE IF NOT EXISTS principals (
            principal_id STRING NOT NULL,
            account_id STRING NOT NULL,
            provider STRING NOT NULL,
            principal_type STRING NOT NULL,
            external_id STRING NOT NULL,
            email STRING,
            display_name STRING,
            is_human BOOLEAN,
            PRIMARY KEY (principal_id)
        )
        """.strip(),
        """
        CREATE TABLE IF NOT EXISTS resources (
            resource_id STRING NOT NULL,
            account_id STRING NOT NULL,
            provider STRING NOT NULL,
            resource_type STRING NOT NULL,
            external_id STRING NOT NULL,
            name STRING,
            parent_external_id STRING,
            created_at TIMESTAMP_TZ,
            PRIMARY KEY (resource_id)
        )
        """.strip(),
        """
        CREATE TABLE IF NOT EXISTS config_snapshots (
            snapshot_id STRING NOT NULL,
            resource_id STRING NOT NULL,
            captured_at TIMESTAMP_TZ NOT NULL,
            config_sha BINARY NOT NULL,
            normalized_config VARIANT NOT NULL,
            collector_version STRING NOT NULL,
            PRIMARY KEY (snapshot_id)
        )
        """.strip(),
        """
        CREATE TABLE IF NOT EXISTS policies (
            policy_id STRING NOT NULL,
            org_id STRING NOT NULL,
            name STRING NOT NULL,
            description STRING,
            framework STRING,
            created_at TIMESTAMP_TZ,
            PRIMARY KEY (policy_id)
        )
        """.strip(),
        """
        CREATE TABLE IF NOT EXISTS rules (
            rule_id STRING NOT NULL,
            policy_id STRING,
            name STRING NOT NULL,
            description STRING,
            provider ARRAY NOT NULL,
            resource_types ARRAY,
            expression_lang STRING NOT NULL,
            expression STRING NOT NULL,
            severity STRING NOT NULL,
            cwe ARRAY,
            cis ARRAY,
            nist_800_53 ARRAY,
            mitre_attack ARRAY,
            version INTEGER NOT NULL,
            is_active BOOLEAN NOT NULL,
            created_at TIMESTAMP_TZ,
            PRIMARY KEY (rule_id)
        )
        """.strip(),
        """
        CREATE TABLE IF NOT EXISTS iam_edges (
            edge_id STRING NOT NULL,
            account_id STRING NOT NULL,
            provider STRING NOT NULL,
            principal_id STRING NOT NULL,
            resource_id STRING,
            permission STRING NOT NULL,
            via STRING,
            effective_at TIMESTAMP_TZ NOT NULL,
            expires_at TIMESTAMP_TZ,
            is_admin BOOLEAN NOT NULL,
            PRIMARY KEY (edge_id)
        )
        """.strip(),
        """
        CREATE TABLE IF NOT EXISTS findings (
            finding_id STRING NOT NULL,
            org_id STRING NOT NULL,
            account_id STRING NOT NULL,
            provider STRING NOT NULL,
            rule_id STRING NOT NULL,
            rule_version INTEGER NOT NULL,
            resource_id STRING,
            principal_id STRING,
            first_seen TIMESTAMP_TZ NOT NULL,
            last_seen TIMESTAMP_TZ NOT NULL,
            status STRING NOT NULL,
            severity STRING NOT NULL,
            fingerprint STRING NOT NULL,
            title STRING NOT NULL,
            summary STRING,
            evidence VARIANT,
            PRIMARY KEY (finding_id)
        )
        """.strip(),
        """
        CREATE TABLE IF NOT EXISTS identity_remediation_actions (
            action_id STRING NOT NULL,
            org_id STRING NOT NULL,
            principal_id STRING NOT NULL,
            summary STRING NOT NULL,
            recommended_action STRING NOT NULL,
            priority STRING NOT NULL,
            status STRING NOT NULL,
            evidence VARIANT,
            notes VARIANT,
            accepted_at TIMESTAMP_TZ,
            accepted_by STRING,
            completed_at TIMESTAMP_TZ,
            completed_by STRING,
            created_at TIMESTAMP_TZ,
            updated_at TIMESTAMP_TZ,
            created_by STRING,
            updated_by STRING,
            PRIMARY KEY (action_id)
        )
        """.strip(),
        """
        CREATE TABLE IF NOT EXISTS security_metric_snapshots (
            snapshot_id STRING NOT NULL,
            org_id STRING NOT NULL,
            metric_type STRING NOT NULL,
            metric_category STRING NOT NULL,
            captured_at TIMESTAMP_TZ NOT NULL,
            aggregation_period STRING NOT NULL,
            value FLOAT NOT NULL,
            previous_value FLOAT,
            breakdown_data VARIANT,
            metadata VARIANT,
            metric_metadata VARIANT,
            created_at TIMESTAMP_TZ,
            PRIMARY KEY (snapshot_id)
        )
        """.strip(),
        """
        CREATE TABLE IF NOT EXISTS agent_runtime_events (
            id STRING NOT NULL,
            org_id STRING NOT NULL,
            session_id STRING NOT NULL,
            event_type STRING NOT NULL,
            payload VARIANT NOT NULL,
            created_at TIMESTAMP_TZ NOT NULL,
            PRIMARY KEY (id)
        )
        """.strip(),
        """
        CREATE TABLE IF NOT EXISTS assessment_results (
            id STRING NOT NULL,
            org_id STRING NOT NULL,
            rule_id STRING NOT NULL,
            status STRING NOT NULL,
            assessed_at TIMESTAMP_TZ,
            details VARIANT,
            PRIMARY KEY (id)
        )
        """.strip(),
    ]


def _execute_all(conn, statements: Iterable[str]) -> None:
    for stmt in statements:
        conn.execute(text(stmt))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Bootstrap the Cerebro Snowflake warehouse schema")
    parser.add_argument(
        "--url",
        default=os.getenv("SNOWFLAKE_DATABASE_URL"),
        help="Snowflake SQLAlchemy URL (or env SNOWFLAKE_DATABASE_URL)",
    )
    parser.add_argument(
        "--database",
        default=None,
        help="Optional database to USE (overrides whatever the URL default is)",
    )
    parser.add_argument(
        "--schema",
        default=None,
        help="Optional schema to CREATE/USE (overrides whatever the URL default is)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print DDL instead of executing",
    )
    args = parser.parse_args(argv)

    if not args.url:
        raise SystemExit("Snowflake URL not provided; set SNOWFLAKE_DATABASE_URL or pass --url")

    ddl = _build_ddl()
    if args.dry_run:
        print("\n\n".join(ddl))
        return 0

    url = make_url(args.url)
    engine = create_engine(
        url,
        poolclass=NullPool,
        pool_pre_ping=True,
        connect_args={
            "client_session_keep_alive": True,
        },
    )

    try:
        with engine.begin() as conn:
            if args.database:
                conn.execute(text(f"USE DATABASE {_quote_ident(args.database)}"))
            if args.schema:
                conn.execute(text(f"CREATE SCHEMA IF NOT EXISTS {_quote_ident(args.schema)}"))
                conn.execute(text(f"USE SCHEMA {_quote_ident(args.schema)}"))

            current = conn.execute(
                text("SELECT CURRENT_DATABASE() AS db, CURRENT_SCHEMA() AS schema")
            ).mappings().one()
            print(f"Using Snowflake database={current['db']} schema={current['schema']}")

            _execute_all(conn, ddl)

        print("Snowflake warehouse schema bootstrap complete.")
        return 0
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
