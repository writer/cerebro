"""
Security data schema definitions for SQL query engine.

Provides standardized column definitions and data types for security resources.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ColumnType(Enum):
    """Standard column types for security data."""

    TEXT = "TEXT"
    INTEGER = "INTEGER"
    BOOLEAN = "BOOLEAN"
    TIMESTAMP = "TIMESTAMP"
    JSON = "JSON"
    UUID = "UUID"
    SEVERITY = "SEVERITY"  # Custom enum for security severity levels
    STATUS = "STATUS"  # Custom enum for status fields


class SeverityLevel(Enum):
    """Standard severity levels across security tools."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class StatusType(Enum):
    """Standard status types for security resources."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    INVESTIGATING = "investigating"
    CLOSED = "closed"


@dataclass
class SecurityColumn:
    """Definition of a security table column."""

    name: str
    type: ColumnType
    description: str
    required: bool = False
    filterable: bool = True
    transform: str | None = None  # Transformation function name
    source_field: str | None = None  # Source API field name


@dataclass
class SecurityIndex:
    """Index definition for query optimization."""

    name: str
    columns: list[str]
    unique: bool = False


class SecuritySchema:
    """
    Standardized security schema with common columns across all providers.

    Based on analysis of CrowdStrike (8 tables), Okta (15+ tables), and AWS patterns.
    """

    # Core identity columns (present in most security tables)
    CORE_COLUMNS = [
        SecurityColumn(
            "id", ColumnType.TEXT, "Unique resource identifier", required=True
        ),
        SecurityColumn(
            "provider",
            ColumnType.TEXT,
            "Security provider (aws, okta, crowdstrike, etc.)",
            required=True,
        ),
        SecurityColumn("account_id", ColumnType.TEXT, "Account/tenant identifier"),
        SecurityColumn("region", ColumnType.TEXT, "Geographic region or zone"),
        SecurityColumn(
            "created_at", ColumnType.TIMESTAMP, "Resource creation timestamp"
        ),
        SecurityColumn(
            "updated_at", ColumnType.TIMESTAMP, "Last modification timestamp"
        ),
        SecurityColumn("tags", ColumnType.JSON, "Resource tags and labels"),
        SecurityColumn(
            "metadata", ColumnType.JSON, "Additional provider-specific metadata"
        ),
    ]

    # Alert/Detection columns (CrowdStrike, SIEM patterns)
    ALERT_COLUMNS = [*CORE_COLUMNS, SecurityColumn("alert_id", ColumnType.TEXT, "Alert identifier", required=True), SecurityColumn("composite_id", ColumnType.TEXT, "Composite alert identifier"), SecurityColumn("aggregate_id", ColumnType.TEXT, "Aggregate alert group identifier"), SecurityColumn("severity", ColumnType.SEVERITY, "Alert severity level"), SecurityColumn("status", ColumnType.STATUS, "Alert status"), SecurityColumn("title", ColumnType.TEXT, "Alert title or name"), SecurityColumn("description", ColumnType.TEXT, "Alert description"), SecurityColumn("host_id", ColumnType.TEXT, "Associated host identifier"), SecurityColumn("user_id", ColumnType.TEXT, "Associated user identifier"), SecurityColumn("confidence", ColumnType.INTEGER, "Confidence score (0-100)"), SecurityColumn("tactics", ColumnType.JSON, "MITRE ATT&CK tactics"), SecurityColumn("techniques", ColumnType.JSON, "MITRE ATT&CK techniques"), SecurityColumn("indicators", ColumnType.JSON, "IOCs and indicators"), SecurityColumn("raw_event", ColumnType.JSON, "Original event data")]

    # Identity columns (Okta, Auth0, Azure AD patterns)
    IDENTITY_COLUMNS = [*CORE_COLUMNS, SecurityColumn("user_id", ColumnType.TEXT, "User identifier", required=True), SecurityColumn("username", ColumnType.TEXT, "Username or login"), SecurityColumn("email", ColumnType.TEXT, "User email address"), SecurityColumn("display_name", ColumnType.TEXT, "User display name"), SecurityColumn("status", ColumnType.STATUS, "User account status"), SecurityColumn("last_login", ColumnType.TIMESTAMP, "Last successful login"), SecurityColumn("failed_logins", ColumnType.INTEGER, "Failed login attempts"), SecurityColumn("groups", ColumnType.JSON, "User group memberships"), SecurityColumn("roles", ColumnType.JSON, "Assigned roles and permissions"), SecurityColumn("mfa_enabled", ColumnType.BOOLEAN, "Multi-factor authentication enabled"), SecurityColumn("locked", ColumnType.BOOLEAN, "Account locked status"), SecurityColumn("password_changed", ColumnType.TIMESTAMP, "Last password change"), SecurityColumn("attributes", ColumnType.JSON, "Custom user attributes")]

    # Asset/Host columns (AWS EC2, CrowdStrike hosts)
    ASSET_COLUMNS = [*CORE_COLUMNS, SecurityColumn("hostname", ColumnType.TEXT, "Host or asset name"), SecurityColumn("ip_address", ColumnType.TEXT, "IP address"), SecurityColumn("mac_address", ColumnType.TEXT, "MAC address"), SecurityColumn("os_family", ColumnType.TEXT, "Operating system family"), SecurityColumn("os_version", ColumnType.TEXT, "Operating system version"), SecurityColumn("agent_version", ColumnType.TEXT, "Security agent version"), SecurityColumn("last_seen", ColumnType.TIMESTAMP, "Last communication timestamp"), SecurityColumn("status", ColumnType.STATUS, "Asset status"), SecurityColumn("criticality", ColumnType.SEVERITY, "Business criticality"), SecurityColumn("owner", ColumnType.TEXT, "Asset owner"), SecurityColumn("environment", ColumnType.TEXT, "Environment (prod, dev, test)"), SecurityColumn("network_interfaces", ColumnType.JSON, "Network interface details"), SecurityColumn("installed_software", ColumnType.JSON, "Installed software inventory")]

    # Vulnerability columns (CrowdStrike Spotlight, AWS Inspector)
    VULNERABILITY_COLUMNS = [*CORE_COLUMNS, SecurityColumn("vulnerability_id", ColumnType.TEXT, "Vulnerability identifier", required=True), SecurityColumn("cve_id", ColumnType.TEXT, "CVE identifier"), SecurityColumn("severity", ColumnType.SEVERITY, "Vulnerability severity"), SecurityColumn("cvss_score", ColumnType.INTEGER, "CVSS base score"), SecurityColumn("title", ColumnType.TEXT, "Vulnerability title"), SecurityColumn("description", ColumnType.TEXT, "Vulnerability description"), SecurityColumn("host_id", ColumnType.TEXT, "Affected host identifier"), SecurityColumn("package_name", ColumnType.TEXT, "Affected package/software"), SecurityColumn("package_version", ColumnType.TEXT, "Package version"), SecurityColumn("fixed_version", ColumnType.TEXT, "Fixed version available"), SecurityColumn("exploit_available", ColumnType.BOOLEAN, "Known exploits available"), SecurityColumn("patch_available", ColumnType.BOOLEAN, "Patch available"), SecurityColumn("first_seen", ColumnType.TIMESTAMP, "First detection timestamp"), SecurityColumn("remediation", ColumnType.TEXT, "Remediation guidance")]

    # Configuration columns (AWS Config, GCP Asset Inventory)
    CONFIG_COLUMNS = [*CORE_COLUMNS, SecurityColumn("resource_type", ColumnType.TEXT, "Resource type", required=True), SecurityColumn("resource_name", ColumnType.TEXT, "Resource name"), SecurityColumn("arn", ColumnType.TEXT, "Amazon Resource Name"), SecurityColumn("configuration", ColumnType.JSON, "Current configuration"), SecurityColumn("compliance_status", ColumnType.STATUS, "Compliance status"), SecurityColumn("compliance_rules", ColumnType.JSON, "Applied compliance rules"), SecurityColumn("configuration_recorder", ColumnType.TEXT, "Config recorder name"), SecurityColumn("availability_zone", ColumnType.TEXT, "Availability zone"), SecurityColumn("relationships", ColumnType.JSON, "Related resources")]

    @classmethod
    def get_schema_for_table(cls, table_type: str) -> list[SecurityColumn]:
        """Get the appropriate column schema for a table type."""
        schema_map = {
            "alert": cls.ALERT_COLUMNS,
            "detection": cls.ALERT_COLUMNS,
            "user": cls.IDENTITY_COLUMNS,
            "identity": cls.IDENTITY_COLUMNS,
            "host": cls.ASSET_COLUMNS,
            "asset": cls.ASSET_COLUMNS,
            "vulnerability": cls.VULNERABILITY_COLUMNS,
            "config": cls.CONFIG_COLUMNS,
            "configuration": cls.CONFIG_COLUMNS,
        }

        # Find matching schema based on table name
        for schema_key, schema_columns in schema_map.items():
            if schema_key in table_type.lower():
                return schema_columns

        # Default to core columns
        return cls.CORE_COLUMNS

    @classmethod
    def create_table_schema(
        cls, table_name: str, custom_columns: list[SecurityColumn] | None = None
    ) -> dict[str, Any]:
        """Create a complete table schema definition."""
        base_columns = cls.get_schema_for_table(table_name)

        if custom_columns:
            # Merge custom columns, avoiding duplicates
            column_names = {col.name for col in base_columns}
            for custom_col in custom_columns:
                if custom_col.name not in column_names:
                    base_columns.append(custom_col)

        return {
            "name": table_name,
            "columns": base_columns,
            "indexes": cls._get_default_indexes(base_columns),
            "description": f"Security data table for {table_name}",
        }

    @classmethod
    def _get_default_indexes(cls, columns: list[SecurityColumn]) -> list[SecurityIndex]:
        """Generate default indexes for a table schema."""
        indexes = []

        # Always index primary identifier
        id_columns = [
            col.name
            for col in columns
            if col.name in ["id", "user_id", "alert_id", "vulnerability_id", "host_id"]
        ]
        if id_columns:
            indexes.append(SecurityIndex("idx_primary_id", id_columns[:1], unique=True))

        # Index timestamp columns for time-based queries
        time_columns = [col.name for col in columns if col.type == ColumnType.TIMESTAMP]
        for time_col in time_columns:
            indexes.append(SecurityIndex(f"idx_{time_col}", [time_col]))

        # Index provider and account for multi-tenant queries
        if any(col.name == "provider" for col in columns):
            indexes.append(
                SecurityIndex("idx_provider_account", ["provider", "account_id"])
            )

        # Index severity and status for filtering
        filterable_columns = [
            col.name
            for col in columns
            if col.name in ["severity", "status"] and col.filterable
        ]
        for filter_col in filterable_columns:
            indexes.append(SecurityIndex(f"idx_{filter_col}", [filter_col]))

        return indexes
