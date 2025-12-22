#!/usr/bin/env python3
"""PostgreSQL to DynamoDB migration script.

Migrates data from PostgreSQL tables to DynamoDB tables following the
single-table design pattern defined in the migration design document.

Usage:
    # Dry run (shows what would be migrated)
    python scripts/migrate_postgres_to_dynamodb.py --dry-run

    # Migrate specific tables
    python scripts/migrate_postgres_to_dynamodb.py --tables orgs,accounts,findings

    # Full migration
    python scripts/migrate_postgres_to_dynamodb.py

    # Migration with batch size control
    python scripts/migrate_postgres_to_dynamodb.py --batch-size 100

Environment Variables:
    DATABASE_URL: PostgreSQL connection string
    DYNAMODB_ENDPOINT_URL: DynamoDB endpoint (optional, for local dev)
    AWS_REGION: AWS region for DynamoDB
"""

import argparse
import asyncio
import hashlib
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import boto3
from botocore.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class MigrationStats:
    """Track migration statistics."""

    def __init__(self):
        self.tables_processed = 0
        self.records_migrated = 0
        self.records_failed = 0
        self.start_time = datetime.now(timezone.utc)

    def summary(self) -> str:
        elapsed = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        return (
            f"Migration Summary:\n"
            f"  Tables processed: {self.tables_processed}\n"
            f"  Records migrated: {self.records_migrated}\n"
            f"  Records failed: {self.records_failed}\n"
            f"  Duration: {elapsed:.2f} seconds\n"
            f"  Rate: {self.records_migrated / elapsed:.2f} records/second"
        )


def get_postgres_engine(database_url: str):
    """Create PostgreSQL engine."""
    return create_engine(database_url)


def get_dynamodb_client(endpoint_url: Optional[str] = None):
    """Create DynamoDB client."""
    config = Config(
        retries={"max_attempts": 3, "mode": "adaptive"},
    )
    kwargs = {
        "region_name": os.environ.get("AWS_REGION", "us-east-1"),
        "config": config,
    }
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url
    return boto3.client("dynamodb", **kwargs)


def serialize_value(value: Any) -> Dict[str, Any]:
    """Serialize Python value to DynamoDB format."""
    if value is None:
        return {"NULL": True}
    elif isinstance(value, bool):
        return {"BOOL": value}
    elif isinstance(value, str):
        return {"S": value}
    elif isinstance(value, (int, float)):
        return {"N": str(value)}
    elif isinstance(value, bytes):
        return {"B": value}
    elif isinstance(value, UUID):
        return {"S": str(value)}
    elif isinstance(value, datetime):
        return {"S": value.isoformat()}
    elif isinstance(value, list):
        if not value:
            return {"L": []}
        return {"L": [serialize_value(item) for item in value]}
    elif isinstance(value, dict):
        return {"M": {k: serialize_value(v) for k, v in value.items()}}
    else:
        return {"S": str(value)}


def serialize_item(item: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Serialize a dictionary to DynamoDB item format."""
    return {k: serialize_value(v) for k, v in item.items() if v is not None}


class TableMigrator:
    """Base class for table migrations."""

    source_table: str
    target_table: str

    def __init__(
        self,
        pg_engine,
        dynamodb_client,
        batch_size: int = 25,
        dry_run: bool = False,
    ):
        self.pg_engine = pg_engine
        self.dynamodb = dynamodb_client
        self.batch_size = batch_size
        self.dry_run = dry_run

    def fetch_records(self, offset: int, limit: int) -> List[Dict[str, Any]]:
        """Fetch records from PostgreSQL."""
        raise NotImplementedError

    def transform_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Transform PostgreSQL record to DynamoDB item."""
        raise NotImplementedError

    def migrate(self, stats: MigrationStats) -> int:
        """Run migration for this table."""
        logger.info(f"Migrating {self.source_table} -> {self.target_table}")

        offset = 0
        total_migrated = 0

        while True:
            records = self.fetch_records(offset, self.batch_size)
            if not records:
                break

            items = []
            for record in records:
                try:
                    item = self.transform_record(record)
                    items.append(item)
                except Exception as e:
                    logger.error(f"Failed to transform record: {e}")
                    stats.records_failed += 1

            if items and not self.dry_run:
                self._batch_write(items)

            total_migrated += len(items)
            stats.records_migrated += len(items)
            offset += self.batch_size

            if len(records) < self.batch_size:
                break

        logger.info(f"Migrated {total_migrated} records from {self.source_table}")
        stats.tables_processed += 1
        return total_migrated

    def _batch_write(self, items: List[Dict[str, Any]]) -> None:
        """Write items to DynamoDB in batches."""
        for i in range(0, len(items), 25):
            batch = items[i : i + 25]
            request_items = {
                self.target_table: [
                    {"PutRequest": {"Item": serialize_item(item)}} for item in batch
                ]
            }
            self.dynamodb.batch_write_item(RequestItems=request_items)


class OrganizationMigrator(TableMigrator):
    """Migrate organizations table."""

    source_table = "orgs"
    target_table = "cerebro-core"

    def fetch_records(self, offset: int, limit: int) -> List[Dict[str, Any]]:
        with Session(self.pg_engine) as session:
            result = session.execute(
                text(
                    f"SELECT * FROM orgs ORDER BY org_id OFFSET {offset} LIMIT {limit}"
                )
            )
            return [dict(row._mapping) for row in result]

    def transform_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(record["org_id"])
        created_at = (
            record["created_at"].isoformat()
            if record.get("created_at")
            else datetime.now(timezone.utc).isoformat()
        )

        return {
            "PK": f"ORG#{org_id}",
            "SK": f"ORG#{org_id}",
            "entity_type": "ORG",
            "org_id": org_id,
            "name": record["name"],
            "slack_config": record.get("slack_config"),
            "created_at": created_at,
            "GSI3PK": "ORG#ALL",
            "GSI3SK": f"CREATED#{created_at}",
        }


class AccountMigrator(TableMigrator):
    """Migrate accounts table."""

    source_table = "accounts"
    target_table = "cerebro-core"

    def fetch_records(self, offset: int, limit: int) -> List[Dict[str, Any]]:
        with Session(self.pg_engine) as session:
            result = session.execute(
                text(
                    f"SELECT * FROM accounts ORDER BY account_id OFFSET {offset} LIMIT {limit}"
                )
            )
            return [dict(row._mapping) for row in result]

    def transform_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(record["org_id"])
        account_id = str(record["account_id"])
        provider = record["provider"]

        return {
            "PK": f"ORG#{org_id}",
            "SK": f"ACCOUNT#{account_id}",
            "entity_type": "ACCOUNT",
            "account_id": account_id,
            "org_id": org_id,
            "provider": provider,
            "external_id": record["external_id"],
            "display_name": record.get("display_name"),
            "GSI1PK": f"PROVIDER#{provider}",
            "GSI1SK": f"ACCOUNT#{account_id}",
        }


class PrincipalMigrator(TableMigrator):
    """Migrate principals table."""

    source_table = "principals"
    target_table = "cerebro-core"

    def __init__(self, *args, org_map: Dict[str, str] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.org_map = org_map or {}

    def fetch_records(self, offset: int, limit: int) -> List[Dict[str, Any]]:
        with Session(self.pg_engine) as session:
            result = session.execute(
                text(
                    f"""
                    SELECT p.*, a.org_id
                    FROM principals p
                    JOIN accounts a ON p.account_id = a.account_id
                    ORDER BY p.principal_id
                    OFFSET {offset} LIMIT {limit}
                """
                )
            )
            return [dict(row._mapping) for row in result]

    def transform_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(record["org_id"])
        principal_id = str(record["principal_id"])
        account_id = str(record["account_id"])

        return {
            "PK": f"ORG#{org_id}",
            "SK": f"PRINCIPAL#{principal_id}",
            "entity_type": "PRINCIPAL",
            "principal_id": principal_id,
            "account_id": account_id,
            "org_id": org_id,
            "provider": record["provider"],
            "principal_type": record["principal_type"],
            "external_id": record["external_id"],
            "email": record.get("email"),
            "display_name": record.get("display_name"),
            "is_human": record.get("is_human"),
            "GSI1PK": f"ACCOUNT#{account_id}",
            "GSI1SK": f"PRINCIPAL#{principal_id}",
        }


class ResourceMigrator(TableMigrator):
    """Migrate resources table."""

    source_table = "resources"
    target_table = "cerebro-core"

    def fetch_records(self, offset: int, limit: int) -> List[Dict[str, Any]]:
        with Session(self.pg_engine) as session:
            result = session.execute(
                text(
                    f"""
                    SELECT r.*, a.org_id
                    FROM resources r
                    JOIN accounts a ON r.account_id = a.account_id
                    ORDER BY r.resource_id
                    OFFSET {offset} LIMIT {limit}
                """
                )
            )
            return [dict(row._mapping) for row in result]

    def transform_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(record["org_id"])
        resource_id = str(record["resource_id"])
        account_id = str(record["account_id"])
        created_at = (
            record["created_at"].isoformat()
            if record.get("created_at")
            else datetime.now(timezone.utc).isoformat()
        )

        return {
            "PK": f"ORG#{org_id}",
            "SK": f"RESOURCE#{resource_id}",
            "entity_type": "RESOURCE",
            "resource_id": resource_id,
            "account_id": account_id,
            "org_id": org_id,
            "provider": record["provider"],
            "resource_type": record["resource_type"],
            "external_id": record["external_id"],
            "name": record.get("name"),
            "parent_external_id": record.get("parent_external_id"),
            "created_at": created_at,
            "GSI1PK": f"ACCOUNT#{account_id}",
            "GSI1SK": f"RESOURCE#{resource_id}",
        }


class FindingMigrator(TableMigrator):
    """Migrate findings table."""

    source_table = "findings"
    target_table = "cerebro-core"

    def fetch_records(self, offset: int, limit: int) -> List[Dict[str, Any]]:
        with Session(self.pg_engine) as session:
            result = session.execute(
                text(
                    f"SELECT * FROM findings ORDER BY finding_id OFFSET {offset} LIMIT {limit}"
                )
            )
            return [dict(row._mapping) for row in result]

    def transform_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(record["org_id"])
        finding_id = str(record["finding_id"])
        status = record["status"]
        severity = record["severity"]
        last_seen = record["last_seen"].isoformat()

        return {
            "PK": f"ORG#{org_id}",
            "SK": f"FINDING#{finding_id}",
            "entity_type": "FINDING",
            "finding_id": finding_id,
            "org_id": org_id,
            "account_id": str(record["account_id"]),
            "provider": record["provider"],
            "rule_id": str(record["rule_id"]),
            "rule_version": record["rule_version"],
            "resource_id": (
                str(record["resource_id"]) if record.get("resource_id") else None
            ),
            "principal_id": (
                str(record["principal_id"]) if record.get("principal_id") else None
            ),
            "first_seen": record["first_seen"].isoformat(),
            "last_seen": last_seen,
            "status": status,
            "severity": severity,
            "fingerprint": record["fingerprint"],
            "title": record["title"],
            "summary": record.get("summary"),
            "evidence": record.get("evidence"),
            "GSI1PK": f"RULE#{record['rule_id']}",
            "GSI1SK": f"FINDING#{finding_id}",
            "GSI2PK": f"ORG#{org_id}#STATUS#{status}",
            "GSI2SK": f"SEVERITY#{severity}#{finding_id}",
            "GSI3PK": f"ORG#{org_id}",
            "GSI3SK": f"LAST_SEEN#{last_seen}",
        }


class RuleMigrator(TableMigrator):
    """Migrate rules table."""

    source_table = "rules"
    target_table = "cerebro-core"

    def fetch_records(self, offset: int, limit: int) -> List[Dict[str, Any]]:
        with Session(self.pg_engine) as session:
            result = session.execute(
                text(
                    f"SELECT * FROM rules ORDER BY rule_id OFFSET {offset} LIMIT {limit}"
                )
            )
            return [dict(row._mapping) for row in result]

    def transform_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        rule_id = str(record["rule_id"])
        severity = record["severity"]
        is_active = record.get("is_active", True)
        created_at = (
            record["created_at"].isoformat()
            if record.get("created_at")
            else datetime.now(timezone.utc).isoformat()
        )

        return {
            "PK": f"RULE#{rule_id}",
            "SK": f"RULE#{rule_id}",
            "entity_type": "RULE",
            "rule_id": rule_id,
            "policy_id": str(record["policy_id"]) if record.get("policy_id") else None,
            "name": record["name"],
            "description": record.get("description"),
            "provider": record["provider"],
            "resource_types": record.get("resource_types"),
            "expression_lang": record["expression_lang"],
            "expression": record["expression"],
            "severity": severity,
            "cwe": record.get("cwe"),
            "cis": record.get("cis"),
            "nist_800_53": record.get("nist_800_53"),
            "mitre_attack": record.get("mitre_attack"),
            "version": record.get("version", 1),
            "is_active": is_active,
            "created_at": created_at,
            "GSI1PK": f"RULE#ACTIVE#{is_active}",
            "GSI1SK": f"SEVERITY#{severity}#{rule_id}",
        }


class AuditEventMigrator(TableMigrator):
    """Migrate audit_events table to audit DynamoDB table."""

    source_table = "audit_events"
    target_table = "cerebro-audit"

    def __init__(self, *args, ttl_days: int = 90, **kwargs):
        super().__init__(*args, **kwargs)
        self.ttl_days = ttl_days

    def fetch_records(self, offset: int, limit: int) -> List[Dict[str, Any]]:
        with Session(self.pg_engine) as session:
            result = session.execute(
                text(
                    f"""
                    SELECT ae.*, a.org_id
                    FROM audit_events ae
                    JOIN accounts a ON ae.account_id = a.account_id
                    ORDER BY ae.event_id
                    OFFSET {offset} LIMIT {limit}
                """
                )
            )
            return [dict(row._mapping) for row in result]

    def transform_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        account_id = str(record["account_id"])
        event_id = str(record["event_id"])
        org_id = str(record["org_id"])
        occurred_at = record["occurred_at"].isoformat()

        # Calculate TTL (90 days from occurred_at)
        from datetime import timedelta

        ttl_timestamp = int(
            (record["occurred_at"] + timedelta(days=self.ttl_days)).timestamp()
        )

        return {
            "PK": f"ACCOUNT#{account_id}",
            "SK": f"AUDIT#{occurred_at}#{event_id}",
            "entity_type": "AUDIT_EVENT",
            "event_id": event_id,
            "account_id": account_id,
            "org_id": org_id,
            "provider": record["provider"],
            "occurred_at": occurred_at,
            "actor_external_id": record.get("actor_external_id"),
            "action": record["action"],
            "resource_external_id": record.get("resource_external_id"),
            "raw": record["raw"],
            "ttl": ttl_timestamp,
            "GSI1PK": f"ORG#{org_id}#AUDIT",
            "GSI1SK": f"OCCURRED#{occurred_at}",
        }


class AgentSessionMigrator(TableMigrator):
    """Migrate agent_sessions table."""

    source_table = "agent_sessions"
    target_table = "cerebro-agents"

    def fetch_records(self, offset: int, limit: int) -> List[Dict[str, Any]]:
        with Session(self.pg_engine) as session:
            result = session.execute(
                text(
                    f"SELECT * FROM agent_sessions ORDER BY id OFFSET {offset} LIMIT {limit}"
                )
            )
            return [dict(row._mapping) for row in result]

    def transform_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(record["org_id"])
        session_id = str(record["id"])
        agent_type = record["agent_type"]
        created_at = record["created_at"].isoformat()
        is_active = record.get("is_active", True)

        return {
            "PK": f"ORG#{org_id}",
            "SK": f"SESSION#{session_id}",
            "entity_type": "SESSION",
            "id": session_id,
            "org_id": org_id,
            "agent_type": agent_type,
            "created_at": created_at,
            "created_by": record["created_by"],
            "title": record.get("title"),
            "context": record.get("context", {}),
            "is_active": is_active,
            "GSI1PK": f"ORG#{org_id}#AGENT#{agent_type}",
            "GSI1SK": f"CREATED#{created_at}",
            "GSI2PK": f"ORG#{org_id}#ACTIVE#{is_active}",
            "GSI2SK": f"CREATED#{created_at}",
        }


class AgentMessageMigrator(TableMigrator):
    """Migrate agent_messages table."""

    source_table = "agent_messages"
    target_table = "cerebro-agents"

    def __init__(self, *args, session_org_map: Dict[str, str] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.session_org_map = session_org_map or {}

    def fetch_records(self, offset: int, limit: int) -> List[Dict[str, Any]]:
        with Session(self.pg_engine) as session:
            result = session.execute(
                text(
                    f"""
                    SELECT m.*, s.org_id
                    FROM agent_messages m
                    JOIN agent_sessions s ON m.session_id = s.id
                    ORDER BY m.id
                    OFFSET {offset} LIMIT {limit}
                """
                )
            )
            return [dict(row._mapping) for row in result]

    def transform_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        session_id = str(record["session_id"])
        message_id = str(record["id"])
        org_id = str(record["org_id"])
        created_at = record["created_at"].isoformat()

        return {
            "PK": f"SESSION#{session_id}",
            "SK": f"MESSAGE#{created_at}#{message_id}",
            "entity_type": "MESSAGE",
            "id": message_id,
            "session_id": session_id,
            "org_id": org_id,
            "role": record["role"],
            "content": record["content"],
            "created_at": created_at,
            "input_tokens": record.get("input_tokens"),
            "output_tokens": record.get("output_tokens"),
            "GSI1PK": f"SESSION#{session_id}",
            "GSI1SK": f"MESSAGE#{created_at}",
        }


def get_table_count(engine, table_name: str) -> int:
    """Get count of records in a table."""
    try:
        with Session(engine) as session:
            result = session.execute(text(f"SELECT COUNT(*) FROM {table_name}"))
            return result.scalar()
    except Exception:
        return 0


def main():
    parser = argparse.ArgumentParser(description="Migrate PostgreSQL to DynamoDB")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be migrated without writing",
    )
    parser.add_argument(
        "--tables",
        default="all",
        help="Comma-separated list of tables to migrate (default: all)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=25,
        help="Batch size for DynamoDB writes (default: 25)",
    )
    parser.add_argument(
        "--database-url",
        default=os.environ.get(
            "DATABASE_URL", "postgresql://cerebro:cerebro@localhost/cerebro"
        ),
        help="PostgreSQL connection URL",
    )
    parser.add_argument(
        "--dynamodb-endpoint",
        default=os.environ.get("DYNAMODB_ENDPOINT_URL"),
        help="DynamoDB endpoint URL (for local development)",
    )
    parser.add_argument(
        "--core-table",
        default=os.environ.get("DYNAMODB_CORE_TABLE", "cerebro-core"),
        help="DynamoDB core table name",
    )
    parser.add_argument(
        "--audit-table",
        default=os.environ.get("DYNAMODB_AUDIT_TABLE", "cerebro-audit"),
        help="DynamoDB audit table name",
    )
    parser.add_argument(
        "--agents-table",
        default=os.environ.get("DYNAMODB_AGENTS_TABLE", "cerebro-agents"),
        help="DynamoDB agents table name",
    )

    args = parser.parse_args()

    logger.info("Starting PostgreSQL to DynamoDB migration")
    logger.info(f"Dry run: {args.dry_run}")
    logger.info(f"Batch size: {args.batch_size}")

    # Create connections
    pg_engine = get_postgres_engine(args.database_url)
    dynamodb = get_dynamodb_client(args.dynamodb_endpoint)

    # Show source table counts
    logger.info("\nSource table counts:")
    tables_to_check = [
        "orgs",
        "accounts",
        "principals",
        "resources",
        "findings",
        "rules",
        "audit_events",
        "agent_sessions",
        "agent_messages",
    ]
    for table in tables_to_check:
        count = get_table_count(pg_engine, table)
        logger.info(f"  {table}: {count} records")

    # Initialize stats
    stats = MigrationStats()

    # Define migrators
    migrators = [
        (
            "orgs",
            OrganizationMigrator(pg_engine, dynamodb, args.batch_size, args.dry_run),
        ),
        (
            "accounts",
            AccountMigrator(pg_engine, dynamodb, args.batch_size, args.dry_run),
        ),
        (
            "principals",
            PrincipalMigrator(pg_engine, dynamodb, args.batch_size, args.dry_run),
        ),
        (
            "resources",
            ResourceMigrator(pg_engine, dynamodb, args.batch_size, args.dry_run),
        ),
        (
            "findings",
            FindingMigrator(pg_engine, dynamodb, args.batch_size, args.dry_run),
        ),
        ("rules", RuleMigrator(pg_engine, dynamodb, args.batch_size, args.dry_run)),
        (
            "audit_events",
            AuditEventMigrator(pg_engine, dynamodb, args.batch_size, args.dry_run),
        ),
        (
            "agent_sessions",
            AgentSessionMigrator(pg_engine, dynamodb, args.batch_size, args.dry_run),
        ),
        (
            "agent_messages",
            AgentMessageMigrator(pg_engine, dynamodb, args.batch_size, args.dry_run),
        ),
    ]

    # Update table names
    for name, migrator in migrators:
        if name in ["orgs", "accounts", "principals", "resources", "findings", "rules"]:
            migrator.target_table = args.core_table
        elif name == "audit_events":
            migrator.target_table = args.audit_table
        elif name in ["agent_sessions", "agent_messages"]:
            migrator.target_table = args.agents_table

    # Filter tables if specified
    if args.tables != "all":
        selected = set(args.tables.split(","))
        migrators = [(name, m) for name, m in migrators if name in selected]

    # Run migrations
    logger.info("\nStarting migration...")
    for name, migrator in migrators:
        try:
            migrator.migrate(stats)
        except Exception as e:
            logger.error(f"Failed to migrate {name}: {e}")
            stats.records_failed += 1

    # Print summary
    logger.info("\n" + stats.summary())

    if args.dry_run:
        logger.info("\nThis was a dry run. No data was written to DynamoDB.")


if __name__ == "__main__":
    main()
