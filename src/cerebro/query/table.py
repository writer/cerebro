"""
Security table definitions for the query engine.

Implements the table interface that providers use to expose their data as SQL tables.
"""

import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)
from typing import Any, Dict, List, Optional, AsyncGenerator, Union
from dataclasses import dataclass
from datetime import datetime

from .schema import SecurityColumn, SecuritySchema


@dataclass
class QueryFilter:
    """Represents a filter condition in a SQL query."""

    column: str
    operator: str  # =, >, <, >=, <=, LIKE, ILIKE, IN
    value: Union[str, int, bool, datetime, List[Any]]


@dataclass
class QueryContext:
    """Context information for executing a query."""

    filters: List[QueryFilter]
    limit: Optional[int] = None
    offset: Optional[int] = None
    order_by: Optional[List[str]] = None
    columns: Optional[List[str]] = None  # Specific columns to select
    config: Optional[Dict[str, Any]] = (
        None  # Configuration (e.g., provider credentials)
    )


class SecurityTable(ABC):
    """
    Abstract base class for security data tables.

    Each security provider implements tables by extending this class.
    Inspired by Steampipe's table interface pattern.
    """

    def __init__(
        self,
        name: str,
        description: str,
        columns: Optional[List[SecurityColumn]] = None,
    ):
        self.name = name
        self.description = description
        self.columns = columns or SecuritySchema.get_schema_for_table(name)
        self.indexes = SecuritySchema._get_default_indexes(self.columns)

        # Column lookup for fast access
        self.column_map = {col.name: col for col in self.columns}

    @abstractmethod
    async def list_resources(
        self, ctx: QueryContext
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Fetch resources from the provider API and yield them as dictionaries.

        This is the main method providers implement to hydrate table data.
        Similar to Steampipe's hydrate functions.
        """
        yield  # type: ignore[misc]  # Abstract method - subclasses must yield actual data

    async def get_resource(self, resource_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch a specific resource by ID.

        Default implementation filters list_resources, but providers can override
        for more efficient single-resource fetching.
        """
        ctx = QueryContext(filters=[QueryFilter("id", "=", resource_id)])
        async for resource in self.list_resources(ctx):
            if resource.get("id") == resource_id:
                return resource
        return None

    def get_column_names(self) -> List[str]:
        """Get list of column names for this table."""
        return [col.name for col in self.columns]

    def get_filterable_columns(self) -> List[str]:
        """Get list of columns that can be used in WHERE clauses."""
        return [col.name for col in self.columns if col.filterable]

    def validate_query(self, ctx: QueryContext) -> List[str]:
        """
        Validate query context and return list of error messages.

        Checks for invalid columns, unsupported operators, etc.
        """
        errors = []
        column_names = self.get_column_names()
        filterable_columns = self.get_filterable_columns()

        # Validate filter columns
        for filter_condition in ctx.filters:
            if filter_condition.column not in column_names:
                errors.append(f"Unknown column: {filter_condition.column}")
            elif filter_condition.column not in filterable_columns:
                errors.append(f"Column not filterable: {filter_condition.column}")

        # Validate selected columns
        if ctx.columns:
            for col in ctx.columns:
                if col not in column_names:
                    errors.append(f"Unknown column in SELECT: {col}")

        # Validate order by columns
        if ctx.order_by:
            for col in ctx.order_by:
                # Remove DESC/ASC suffix
                col_name = col.replace(" DESC", "").replace(" ASC", "").strip()
                if col_name not in column_names:
                    errors.append(f"Unknown column in ORDER BY: {col_name}")

        return errors

    async def count_resources(self, ctx: QueryContext) -> int:
        """
        Count resources matching the query context.

        Default implementation counts all yielded resources, but providers
        can override for more efficient counting.
        """
        count = 0
        async for _ in self.list_resources(ctx):
            count += 1
        return count

    def transform_resource(self, raw_resource: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform raw provider data to match table schema.

        Applies column transformations and ensures all required fields are present.
        """
        transformed = {}

        for column in self.columns:
            value = None

            # Use source_field mapping if specified
            source_field = column.source_field or column.name

            # Handle nested field access (e.g., "State.Name")
            if "." in source_field:
                try:
                    value = raw_resource
                    for part in source_field.split("."):
                        if isinstance(value, dict) and part in value:
                            value = value[part]
                        else:
                            value = None
                            break
                except (TypeError, KeyError):
                    value = None
            elif source_field in raw_resource:
                value = raw_resource[source_field]

            # Apply transformation function if specified
            if value is not None and column.transform:
                try:
                    transform_func = getattr(self, column.transform, None)
                    if transform_func:
                        value = transform_func(value)
                except Exception as e:
                    logger.warning(f"Transform function {column.transform} failed: {e}")
                    value = None

            # Set default values for required fields
            if value is None and column.required:
                value = self._get_default_value(column)

            transformed[column.name] = value

        return transformed

    def _get_default_value(self, column: SecurityColumn) -> Any:
        """Get default value for a column based on its type."""
        from .schema import ColumnType

        defaults = {
            ColumnType.TEXT: "",
            ColumnType.INTEGER: 0,
            ColumnType.BOOLEAN: False,
            ColumnType.TIMESTAMP: datetime.now(),
            ColumnType.JSON: {},
            ColumnType.UUID: "",
            ColumnType.SEVERITY: "unknown",
            ColumnType.STATUS: "unknown",
        }

        return defaults.get(column.type, None)

    def apply_filters(
        self, resource: Dict[str, Any], filters: List[QueryFilter]
    ) -> bool:
        """
        Apply filter conditions to a resource.

        Returns True if the resource matches all filters.
        """
        for filter_condition in filters:
            if not self._apply_single_filter(resource, filter_condition):
                return False
        return True

    def _apply_single_filter(
        self, resource: Dict[str, Any], filter_condition: QueryFilter
    ) -> bool:
        """Apply a single filter condition."""
        resource_value = resource.get(filter_condition.column)
        filter_value = filter_condition.value
        operator = filter_condition.operator.upper()

        # Handle null values
        if resource_value is None:
            return operator == "IS NULL" or (operator == "=" and filter_value is None)

        # Type-specific comparisons
        if operator == "=":
            return resource_value == filter_value
        elif operator == "!=":
            return resource_value != filter_value
        elif operator == ">":
            return resource_value > filter_value
        elif operator == ">=":
            return resource_value >= filter_value
        elif operator == "<":
            return resource_value < filter_value
        elif operator == "<=":
            return resource_value <= filter_value
        elif operator in {"LIKE", "ILIKE"}:
            pattern = str(filter_value).lower()
            value = str(resource_value).lower()

            # Minimal LIKE support for % wildcards.
            if pattern.startswith("%") and pattern.endswith("%"):
                return pattern.strip("%") in value
            if pattern.startswith("%"):
                return value.endswith(pattern[1:])
            if pattern.endswith("%"):
                return value.startswith(pattern[:-1])

            return pattern in value
        elif operator == "IN":
            return isinstance(filter_value, list) and resource_value in filter_value
        elif operator == "IS NOT NULL":
            return resource_value is not None

        return False


class ProviderSecurityTable(SecurityTable):
    """
    Base class for provider-specific security tables.

    Includes common functionality for API-based data fetching.
    """

    def __init__(
        self,
        name: str,
        description: str,
        provider_name: str,
        columns: Optional[List[SecurityColumn]] = None,
    ):
        super().__init__(name, description, columns)
        self.provider_name = provider_name

    @abstractmethod
    async def fetch_from_api(
        self, ctx: QueryContext
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Fetch raw data from provider API."""
        yield  # type: ignore[misc]  # Abstract method - subclasses must yield actual data

    async def list_resources(
        self, ctx: QueryContext
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Standard implementation that fetches from API and transforms data.
        """
        async for raw_resource in self.fetch_from_api(ctx):
            # Add provider metadata
            raw_resource["provider"] = self.provider_name

            # Transform to match schema
            transformed = self.transform_resource(raw_resource)

            # Apply client-side filters (for filters not handled by API)
            if self.apply_filters(transformed, ctx.filters):
                yield transformed


# Example table implementations for different security data types


class AlertTable(ProviderSecurityTable):
    """Table for security alerts/detections."""

    def __init__(self, provider_name: str):
        super().__init__(
            name=f"{provider_name}_alert",
            description=f"Security alerts from {provider_name}",
            provider_name=provider_name,
            columns=SecuritySchema.ALERT_COLUMNS,
        )


class UserTable(ProviderSecurityTable):
    """Table for identity/user data."""

    def __init__(self, provider_name: str):
        super().__init__(
            name=f"{provider_name}_user",
            description=f"User identities from {provider_name}",
            provider_name=provider_name,
            columns=SecuritySchema.IDENTITY_COLUMNS,
        )


class HostTable(ProviderSecurityTable):
    """Table for host/asset data."""

    def __init__(self, provider_name: str):
        super().__init__(
            name=f"{provider_name}_host",
            description=f"Host assets from {provider_name}",
            provider_name=provider_name,
            columns=SecuritySchema.ASSET_COLUMNS,
        )


class VulnerabilityTable(ProviderSecurityTable):
    """Table for vulnerability data."""

    def __init__(self, provider_name: str):
        super().__init__(
            name=f"{provider_name}_vulnerability",
            description=f"Vulnerabilities from {provider_name}",
            provider_name=provider_name,
            columns=SecuritySchema.VULNERABILITY_COLUMNS,
        )
