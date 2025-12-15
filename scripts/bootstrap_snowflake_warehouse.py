"""Bootstrap the Snowflake warehouse schema used by Cerebro analytics.

This script is intentionally idempotent (CREATE ... IF NOT EXISTS) and does not
require Alembic.
"""

from __future__ import annotations

import argparse
import os
from typing import Iterable, List, Mapping, Optional

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
        CREATE TABLE IF NOT EXISTS rule_controls (
            rule_id STRING NOT NULL,
            framework STRING NOT NULL,
            control_id STRING NOT NULL,
            created_at TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
            PRIMARY KEY (rule_id, framework, control_id)
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


def _show_table(conn, table_name: str) -> Optional[Mapping[str, object]]:
    rows = conn.execute(text(f"SHOW TABLES LIKE '{table_name.upper()}'")).mappings().all()
    if not rows:
        return None
    return rows[0]


def _existing_constraints(conn, table_name: str) -> set[str]:
    rows = conn.execute(
        text(
            """
            SELECT constraint_name
            FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS
            WHERE table_name = UPPER(:table_name)
            """
        ),
        {"table_name": table_name},
    ).fetchall()
    return {str(row[0]).upper() for row in rows if row and row[0]}


def _get_primary_key_constraint_name(conn, table_name: str) -> Optional[str]:
    row = conn.execute(
        text(
            """
            SELECT constraint_name
            FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS
            WHERE table_name = UPPER(:table_name)
                AND constraint_type = 'PRIMARY KEY'
            """
        ),
        {"table_name": table_name},
    ).fetchone()
    if not row:
        return None
    return str(row[0])


def _apply_constraints(conn) -> None:
    pk_tables = [
        "orgs",
        "accounts",
        "principals",
        "resources",
        "policies",
        "rules",
        "rule_controls",
        "config_snapshots",
        "iam_edges",
        "findings",
        "identity_remediation_actions",
        "security_metric_snapshots",
        "agent_runtime_events",
        "assessment_results",
    ]

    for table_name in pk_tables:
        pk_name = _get_primary_key_constraint_name(conn, table_name)
        if not pk_name:
            continue
        conn.execute(
            text(f"ALTER TABLE {table_name} MODIFY CONSTRAINT {_quote_ident(pk_name)} RELY")
        )

    foreign_keys = [
        (
            "accounts",
            "fk_accounts_org",
            "ALTER TABLE accounts ADD CONSTRAINT fk_accounts_org FOREIGN KEY (org_id) REFERENCES orgs(org_id) NOT ENFORCED RELY",
        ),
        (
            "principals",
            "fk_principals_account",
            "ALTER TABLE principals ADD CONSTRAINT fk_principals_account FOREIGN KEY (account_id) REFERENCES accounts(account_id) NOT ENFORCED RELY",
        ),
        (
            "resources",
            "fk_resources_account",
            "ALTER TABLE resources ADD CONSTRAINT fk_resources_account FOREIGN KEY (account_id) REFERENCES accounts(account_id) NOT ENFORCED RELY",
        ),
        (
            "policies",
            "fk_policies_org",
            "ALTER TABLE policies ADD CONSTRAINT fk_policies_org FOREIGN KEY (org_id) REFERENCES orgs(org_id) NOT ENFORCED RELY",
        ),
        (
            "rules",
            "fk_rules_policy",
            "ALTER TABLE rules ADD CONSTRAINT fk_rules_policy FOREIGN KEY (policy_id) REFERENCES policies(policy_id) NOT ENFORCED RELY",
        ),
        (
            "rule_controls",
            "fk_rule_controls_rule",
            "ALTER TABLE rule_controls ADD CONSTRAINT fk_rule_controls_rule FOREIGN KEY (rule_id) REFERENCES rules(rule_id) NOT ENFORCED RELY",
        ),
        (
            "config_snapshots",
            "fk_config_snapshots_resource",
            "ALTER TABLE config_snapshots ADD CONSTRAINT fk_config_snapshots_resource FOREIGN KEY (resource_id) REFERENCES resources(resource_id) NOT ENFORCED RELY",
        ),
        (
            "iam_edges",
            "fk_iam_edges_account",
            "ALTER TABLE iam_edges ADD CONSTRAINT fk_iam_edges_account FOREIGN KEY (account_id) REFERENCES accounts(account_id) NOT ENFORCED RELY",
        ),
        (
            "iam_edges",
            "fk_iam_edges_principal",
            "ALTER TABLE iam_edges ADD CONSTRAINT fk_iam_edges_principal FOREIGN KEY (principal_id) REFERENCES principals(principal_id) NOT ENFORCED RELY",
        ),
        (
            "iam_edges",
            "fk_iam_edges_resource",
            "ALTER TABLE iam_edges ADD CONSTRAINT fk_iam_edges_resource FOREIGN KEY (resource_id) REFERENCES resources(resource_id) NOT ENFORCED RELY",
        ),
        (
            "findings",
            "fk_findings_org",
            "ALTER TABLE findings ADD CONSTRAINT fk_findings_org FOREIGN KEY (org_id) REFERENCES orgs(org_id) NOT ENFORCED RELY",
        ),
        (
            "findings",
            "fk_findings_account",
            "ALTER TABLE findings ADD CONSTRAINT fk_findings_account FOREIGN KEY (account_id) REFERENCES accounts(account_id) NOT ENFORCED RELY",
        ),
        (
            "findings",
            "fk_findings_rule",
            "ALTER TABLE findings ADD CONSTRAINT fk_findings_rule FOREIGN KEY (rule_id) REFERENCES rules(rule_id) NOT ENFORCED RELY",
        ),
        (
            "findings",
            "fk_findings_resource",
            "ALTER TABLE findings ADD CONSTRAINT fk_findings_resource FOREIGN KEY (resource_id) REFERENCES resources(resource_id) NOT ENFORCED RELY",
        ),
        (
            "findings",
            "fk_findings_principal",
            "ALTER TABLE findings ADD CONSTRAINT fk_findings_principal FOREIGN KEY (principal_id) REFERENCES principals(principal_id) NOT ENFORCED RELY",
        ),
        (
            "identity_remediation_actions",
            "fk_identity_remediation_org",
            "ALTER TABLE identity_remediation_actions ADD CONSTRAINT fk_identity_remediation_org FOREIGN KEY (org_id) REFERENCES orgs(org_id) NOT ENFORCED RELY",
        ),
        (
            "identity_remediation_actions",
            "fk_identity_remediation_principal",
            "ALTER TABLE identity_remediation_actions ADD CONSTRAINT fk_identity_remediation_principal FOREIGN KEY (principal_id) REFERENCES principals(principal_id) NOT ENFORCED RELY",
        ),
        (
            "security_metric_snapshots",
            "fk_security_metric_snapshots_org",
            "ALTER TABLE security_metric_snapshots ADD CONSTRAINT fk_security_metric_snapshots_org FOREIGN KEY (org_id) REFERENCES orgs(org_id) NOT ENFORCED RELY",
        ),
        (
            "agent_runtime_events",
            "fk_agent_runtime_events_org",
            "ALTER TABLE agent_runtime_events ADD CONSTRAINT fk_agent_runtime_events_org FOREIGN KEY (org_id) REFERENCES orgs(org_id) NOT ENFORCED RELY",
        ),
    ]

    for table_name, constraint_name, statement in foreign_keys:
        existing = _existing_constraints(conn, table_name)
        if constraint_name.upper() in existing:
            continue
        conn.execute(text(statement))


def _apply_clustering(conn) -> None:
    cluster_keys = {
        "findings": "org_id, TO_DATE(last_seen)",
        "iam_edges": "account_id, TO_DATE(effective_at)",
        "security_metric_snapshots": "org_id, metric_type, TO_DATE(captured_at)",
        "agent_runtime_events": "org_id, event_type, TO_DATE(created_at)",
        "config_snapshots": "resource_id, TO_DATE(captured_at)",
    }

    for table_name, key_expr in cluster_keys.items():
        table_info = _show_table(conn, table_name)
        if not table_info:
            continue

        current_key = str(table_info.get("cluster_by") or "").strip().upper()
        desired_key = f"LINEAR({key_expr.upper()})"
        if current_key == desired_key:
            continue

        conn.execute(text(f"ALTER TABLE {table_name} CLUSTER BY ({key_expr})"))


def _apply_search_optimization(conn) -> None:
    configs = {
        "findings": "EQUALITY(org_id, account_id, finding_id, fingerprint, rule_id, resource_id, principal_id)",
        "iam_edges": "EQUALITY(account_id, principal_id, resource_id, edge_id)",
        "rules": "EQUALITY(rule_id)",
        "security_metric_snapshots": "EQUALITY(org_id, metric_type, captured_at)",
        "agent_runtime_events": "EQUALITY(org_id, event_type, session_id, id)",
    }

    for table_name, config in configs.items():
        table_info = _show_table(conn, table_name)
        if not table_info:
            continue

        enabled = str(table_info.get("search_optimization") or "").strip().upper()
        if enabled == "ON":
            continue

        conn.execute(text(f"ALTER TABLE {table_name} ADD SEARCH OPTIMIZATION ON {config}"))


def _refresh_rule_controls(conn) -> None:
    conn.execute(
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
    conn.execute(text("CREATE OR REPLACE TABLE rule_controls_staging CLONE rule_controls"))
    conn.execute(text("TRUNCATE TABLE rule_controls_staging"))
    conn.execute(
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
    conn.execute(text("ALTER TABLE rule_controls SWAP WITH rule_controls_staging"))
    conn.execute(text("DROP TABLE IF EXISTS rule_controls_staging"))


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
    parser.add_argument(
        "--best",
        action="store_true",
        help="Apply recommended best-practice steps (constraints, clustering, derived table refresh)",
    )
    parser.add_argument(
        "--apply-constraints",
        action="store_true",
        help="Add RELY NOT ENFORCED PK/FK constraints (enables join elimination)",
    )
    parser.add_argument(
        "--apply-clustering",
        action="store_true",
        help="Apply recommended CLUSTER BY keys for large-table pruning",
    )
    parser.add_argument(
        "--apply-search-optimization",
        action="store_true",
        help="Enable Search Optimization Service for common lookup predicates (may incur extra cost)",
    )
    parser.add_argument(
        "--refresh-rule-controls",
        action="store_true",
        help="Rebuild derived rule_controls table from rules.cis and rules.nist_800_53",
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

            apply_constraints = args.apply_constraints or args.best
            apply_clustering = args.apply_clustering or args.best
            refresh_rule_controls = args.refresh_rule_controls or args.best

            if apply_constraints:
                _apply_constraints(conn)
            if apply_clustering:
                _apply_clustering(conn)
            if args.apply_search_optimization:
                _apply_search_optimization(conn)
            if refresh_rule_controls:
                _refresh_rule_controls(conn)

        print("Snowflake warehouse schema bootstrap complete.")
        return 0
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
