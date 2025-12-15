"""
SQL Query Engine for Cerebro Security System.

Provides a Steampipe-inspired SQL interface for querying security data
across all providers in real-time.
"""

import logging
import os
import sqlparse
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .bootstrap import ensure_tables_registered
from .registry import get_registry, TableRegistry
from .table import QueryContext, QueryFilter
from ..core.events import emit_event

logger = logging.getLogger(__name__)


class QueryError(Exception):
    """Exception raised when query parsing or execution fails."""
    pass


@dataclass
class QueryResult:
    """Result of a SQL query execution."""
    columns: List[str]
    rows: List[Dict[str, Any]]
    total_rows: int
    execution_time_ms: float
    tables_queried: List[str]
    errors: List[str]


@dataclass
class QueryPlan:
    """Execution plan for a SQL query."""
    table_name: str
    selected_columns: List[str]
    filters: List[QueryFilter]
    order_by: Optional[List[str]]
    limit: Optional[int]
    offset: Optional[int]
    estimated_rows: Optional[int]
    wildcard_tables: Optional[List[str]] = None  # Tables matched by wildcard pattern


class SQLParser:
    """
    Basic SQL parser for security queries.
    
    Supports subset of SQL needed for security data queries:
    - SELECT columns FROM table WHERE conditions ORDER BY columns LIMIT n
    """
    
    def __init__(self):
        pass
    
    def parse_query(self, sql: str) -> QueryPlan:
        """
        Parse SQL query into a QueryPlan.
        
        Note: This is a simplified parser. For production, consider using
        a more robust SQL parser or integrating with existing query engines.
        """
        try:
            # Parse SQL using sqlparse
            parsed = sqlparse.parse(sql)[0]
            
            # Extract query components
            table_name = self._extract_table_name(parsed)
            
            # Handle wildcard table patterns
            registry = get_registry()
            matching_tables = []
            if '*' in table_name:
                matching_tables = registry.find_tables_by_pattern(table_name)
                if not matching_tables:
                    raise QueryError(f"No tables match pattern '{table_name}'")

                max_tables = int(os.getenv("QUERY_ENGINE_MAX_WILDCARD_TABLES", "25"))
                if max_tables > 0 and len(matching_tables) > max_tables:
                    raise QueryError(
                        f"Wildcard pattern '{table_name}' expanded to {len(matching_tables)} tables, "
                        f"exceeding QUERY_ENGINE_MAX_WILDCARD_TABLES={max_tables}."
                    )
                logger.info(f"Expanded wildcard pattern '{table_name}' to {len(matching_tables)} tables: {matching_tables}")
                
                # For multiple tables, we'll handle UNION ALL in execution
                if len(matching_tables) == 1:
                    table_name = matching_tables[0]
                    matching_tables = []  # Clear since we're using single table
                # Otherwise, keep the original wildcard table name and matching_tables list
            
            selected_columns = self._extract_selected_columns(parsed)
            filters = self._extract_filters(parsed)
            order_by = self._extract_order_by(parsed)
            limit = self._extract_limit(parsed)
            offset = self._extract_offset(parsed)
            
            return QueryPlan(
                table_name=table_name,
                selected_columns=selected_columns,
                filters=filters,
                order_by=order_by,
                limit=limit,
                offset=offset,
                estimated_rows=None,
                wildcard_tables=matching_tables if matching_tables else None
            )
            
        except Exception as e:
            logger.error(f"Error parsing SQL query: {e}")
            raise ValueError(f"Invalid SQL query: {e}")
    
    def _extract_table_name(self, parsed) -> str:
        """Extract table name from parsed SQL."""
        from_seen = False
        table_parts: List[str] = []
        stop_keywords = {'WHERE', 'ORDER', 'GROUP', 'HAVING', 'LIMIT', 'OFFSET'}

        for token in parsed.flatten():
            if token.ttype is sqlparse.tokens.Keyword and token.value.upper() == 'FROM':
                from_seen = True
                continue

            if not from_seen:
                continue

            # Stop once we hit whitespace after collecting the identifier (to avoid aliases).
            if token.is_whitespace:
                if table_parts:
                    break
                continue

            if token.ttype is sqlparse.tokens.Keyword and token.value.upper() in stop_keywords:
                break
            if token.value == ';':
                break

            table_parts.append(token.value)

        if table_parts:
            return ''.join(table_parts).strip('"\'`')
        
        # Fallback: look for identifier patterns
        tokens = list(parsed.flatten())
        for i, token in enumerate(tokens):
            if token.ttype is sqlparse.tokens.Keyword and token.value.upper() == 'FROM':
                # Look for next non-whitespace token
                for j in range(i + 1, len(tokens)):
                    next_token = tokens[j]
                    if not next_token.is_whitespace:
                        table_name = next_token.value.strip('"\'`')
                        if table_name.upper() not in ['WHERE', 'ORDER', 'GROUP', 'HAVING', 'LIMIT']:
                            return table_name
                        break
        
        raise ValueError("No table name found in query")
    
    def _extract_selected_columns(self, parsed) -> List[str]:
        """Extract selected columns from parsed SQL."""
        select_seen = False
        columns = []
        current_column = []

        for token in parsed.flatten():
            # Check for SELECT keyword (can be Keyword.DML)
            if token.value.upper() == 'SELECT' and (
                token.ttype is sqlparse.tokens.Keyword.DML or
                token.ttype is sqlparse.tokens.Keyword
            ):
                select_seen = True
            # Check for FROM keyword
            elif token.value.upper() == 'FROM' and (
                token.ttype is sqlparse.tokens.Keyword or
                token.ttype is sqlparse.tokens.Keyword.DML
            ):
                # Add the last column if there is one
                if current_column:
                    col = ''.join(current_column).strip()
                    if col:
                        columns.append(col)
                    current_column = []  # Clear it so we don't add it again
                break
            elif select_seen and not token.is_whitespace:
                if token.value == ',':
                    if current_column:
                        col = ''.join(current_column).strip()
                        if col:
                            columns.append(col)
                        current_column = []
                else:
                    current_column.append(token.value)

        # Add last column if not added yet
        if current_column:
            col = ''.join(current_column).strip()
            if col:
                columns.append(col)

        # If we got columns, return them; otherwise return ['*']
        if columns:
            # Special case: if the only column is *, keep it as is
            if len(columns) == 1 and columns[0] == '*':
                return ['*']
            return columns

        # No columns found means SELECT * implicitly
        return ['*']
    
    def _extract_filters(self, parsed) -> List[QueryFilter]:
        """Extract WHERE clause filters from parsed SQL."""
        filters = []
        where_seen = False
        current_filter = []
        
        for token in parsed.flatten():
            if token.ttype is sqlparse.tokens.Keyword and token.value.upper() == 'WHERE':
                where_seen = True
            elif where_seen and token.ttype is sqlparse.tokens.Keyword and token.value.upper() in ['ORDER', 'LIMIT', 'OFFSET']:
                break
            elif where_seen and not token.is_whitespace:
                current_filter.append(token.value)
        
        # Parse filter conditions (simplified)
        if current_filter:
            filter_text = ' '.join(current_filter)
            filters = self._parse_filter_conditions(filter_text)
            
        return filters
    
    def _parse_filter_conditions(self, filter_text: str) -> List[QueryFilter]:
        """Parse individual filter conditions."""
        filters = []

        lowered = filter_text.lower()
        if " or " in lowered:
            raise QueryError(
                "OR conditions are not supported by the query engine. "
                "Split the query into multiple AND-only queries and merge results client-side."
            )
        
        # Split by AND (simplified - doesn't handle OR, nested conditions)
        conditions = filter_text.split(' AND ')
        
        for condition in conditions:
            condition = condition.strip()
            
            # Parse condition (column operator value)
            for operator in ['>=', '<=', '!=', '=', '>', '<', 'ILIKE', 'LIKE', 'IN']:
                if f' {operator} ' in condition:
                    parts = condition.split(f' {operator} ', 1)
                    if len(parts) == 2:
                        column = self._normalize_filter_column(parts[0])
                        value_str = parts[1].strip().strip("'\"")
                        
                        # Convert value to appropriate type
                        value = self._parse_filter_value(value_str, operator)
                        
                        filters.append(QueryFilter(column, operator, value))
                        break
        
        return filters

    def _normalize_filter_column(self, column_expr: str) -> str:
        """Normalize a WHERE clause column expression into a table column name."""

        import re

        column = column_expr.strip().strip('"`')
        column = column.lstrip('(').rstrip(')')

        # Drop casts like "permissions::text" -> "permissions"
        if "::" in column:
            column = column.split("::", 1)[0].strip()

        # Drop common wrappers like LOWER(column)
        func_match = re.match(r"(?i)^(lower|upper)\((.+)\)$", column)
        if func_match:
            column = func_match.group(2).strip()

        # Drop table qualifiers like "t.column" -> "column"
        if "." in column:
            column = column.split(".")[-1].strip()

        return column
    
    def _parse_filter_value(self, value_str: str, operator: str) -> Any:
        """Parse and convert filter value to appropriate type."""
        value_str = value_str.strip()

        relative_ts = self._parse_relative_timestamp(value_str)
        if relative_ts is not None:
            return relative_ts

        if value_str.lower() in {"now()", "current_timestamp", "current_timestamp()"}:
            return datetime.now(timezone.utc)

        # Handle IN operator (list values)
        if operator == 'IN':
            if value_str.startswith('(') and value_str.endswith(')'):
                list_str = value_str[1:-1]
                values = [v.strip().strip("'\"") for v in list_str.split(',')]
                return values
        
        # Handle different value types
        if value_str.lower() == 'null':
            return None
        elif value_str.lower() in ['true', 'false']:
            return value_str.lower() == 'true'
        elif value_str.isdigit():
            return int(value_str)
        elif self._is_float(value_str):
            return float(value_str)
        elif self._is_timestamp(value_str):
            return self._parse_timestamp(value_str)
        else:
            return value_str

    def _parse_relative_timestamp(self, value_str: str) -> Optional[datetime]:
        """Parse expressions like NOW() - INTERVAL '24 hours' into a datetime."""

        lowered = value_str.lower()
        if "interval" not in lowered or "-" not in lowered:
            return None

        if not ("now()" in lowered or "current_timestamp" in lowered):
            return None

        # Accept patterns like:
        # - NOW() - INTERVAL '24 hours'
        # - current_timestamp - interval '30 days'
        try:
            before_interval, interval_part = lowered.split("interval", 1)
        except ValueError:
            return None

        if "-" not in before_interval:
            return None

        interval_part = interval_part.strip()
        if interval_part.startswith("'"):
            interval_part = interval_part[1:]
        if interval_part.endswith("'"):
            interval_part = interval_part[:-1]

        parts = interval_part.strip().split()
        if len(parts) < 2:
            return None

        amount_raw, unit_raw = parts[0], parts[1]
        if not amount_raw.isdigit():
            return None

        amount = int(amount_raw)
        unit = unit_raw.strip()

        now = datetime.now(timezone.utc)
        if unit.startswith("day"):
            return now - timedelta(days=amount)
        if unit.startswith("hour"):
            return now - timedelta(hours=amount)
        if unit.startswith("minute"):
            return now - timedelta(minutes=amount)

        return None
    
    def _is_float(self, value_str: str) -> bool:
        """Check if string represents a float."""
        try:
            float(value_str)
            return True
        except ValueError:
            return False
    
    def _is_timestamp(self, value_str: str) -> bool:
        """Check if string represents a timestamp."""
        timestamp_patterns = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ',
        ]
        
        for pattern in timestamp_patterns:
            try:
                datetime.strptime(value_str, pattern)
                return True
            except ValueError:
                continue
        return False
    
    def _parse_timestamp(self, value_str: str) -> datetime:
        """Parse timestamp string to datetime object."""
        timestamp_patterns = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ',
        ]
        
        for pattern in timestamp_patterns:
            try:
                return datetime.strptime(value_str, pattern)
            except ValueError:
                continue
                
        raise ValueError(f"Could not parse timestamp: {value_str}")
    
    def _extract_order_by(self, parsed) -> Optional[List[str]]:
        """Extract ORDER BY clause from parsed SQL."""
        order_by_seen = False
        order_columns = []
        current_column = []
        
        for token in parsed.flatten():
            if token.ttype is sqlparse.tokens.Keyword and token.value.upper() == 'ORDER':
                order_by_seen = True
            elif token.ttype is sqlparse.tokens.Keyword and token.value.upper() == 'BY':
                continue
            elif order_by_seen and token.ttype is sqlparse.tokens.Keyword and token.value.upper() in ['LIMIT', 'OFFSET']:
                break
            elif order_by_seen and not token.is_whitespace:
                if token.value == ',':
                    if current_column:
                        order_columns.append(' '.join(current_column).strip())
                        current_column = []
                else:
                    current_column.append(token.value)
        
        # Add last column
        if current_column:
            order_columns.append(' '.join(current_column).strip())
        
        return order_columns if order_columns else None
    
    def _extract_limit(self, parsed) -> Optional[int]:
        """Extract LIMIT clause from parsed SQL."""
        limit_seen = False
        for token in parsed.flatten():
            if token.ttype is sqlparse.tokens.Keyword and token.value.upper() == 'LIMIT':
                limit_seen = True
            elif limit_seen and not token.is_whitespace and token.value.isdigit():
                return int(token.value)
        return None
    
    def _extract_offset(self, parsed) -> Optional[int]:
        """Extract OFFSET clause from parsed SQL."""
        offset_seen = False
        for token in parsed.flatten():
            if token.ttype is sqlparse.tokens.Keyword and token.value.upper() == 'OFFSET':
                offset_seen = True
            elif offset_seen and not token.is_whitespace and token.value.isdigit():
                return int(token.value)
        return None


class QueryEngine:
    """
    SQL Query Engine for security data.
    
    Provides real-time querying of security resources across all providers
    using a SQL interface, inspired by Steampipe's Zero-ETL approach.
    """
    
    def __init__(self, registry: Optional[TableRegistry] = None):
        ensure_tables_registered(registry=registry)
        self.registry = registry or get_registry()
        self.parser = SQLParser()
        
    async def execute_query(self, sql: str, params: Optional[List[Any]] = None) -> QueryResult:
        """
        Execute a SQL query against registered security tables.
        
        Args:
            sql: SQL query string with optional parameter placeholders ($1, $2, etc.)
            params: Optional list of parameter values for placeholders
            
        Returns:
            QueryResult with rows, metadata, and any errors
        """
        start_time = datetime.now()
        errors = []
        
        try:
            # Substitute parameters safely
            if params:
                sql = self._substitute_parameters(sql, params)
            
            # Parse SQL query
            plan = self.parser.parse_query(sql)
            
            # Validate query
            validation_errors = self._validate_query(plan)
            if validation_errors:
                return QueryResult(
                    columns=[],
                    rows=[],
                    total_rows=0,
                    execution_time_ms=0,
                    tables_queried=[],
                    errors=validation_errors
                )
            
            # Execute query
            rows = await self._execute_query_plan(plan)
            
            # Calculate execution time
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            # Determine columns
            columns = plan.selected_columns
            if columns == ['*'] and rows:
                columns = list(rows[0].keys())
            elif columns == ['*']:
                table = self.registry.get_table(plan.table_name)
                columns = table.get_column_names() if table else []
            
            emit_event("query_executed", {
                "table": plan.table_name,
                "rows_returned": len(rows),
                "execution_time_ms": execution_time
            })
            
            # Determine which tables were queried
            tables_queried = plan.wildcard_tables if plan.wildcard_tables else [plan.table_name]
            
            return QueryResult(
                columns=columns,
                rows=rows,
                total_rows=len(rows),
                execution_time_ms=execution_time,
                tables_queried=tables_queried,
                errors=errors
            )
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            logger.error(f"Query execution error: {e}")
            return QueryResult(
                columns=[],
                rows=[],
                total_rows=0,
                execution_time_ms=execution_time,
                tables_queried=[],
                errors=[str(e)]
            )
    
    def _validate_query(self, plan: QueryPlan) -> List[str]:
        """Validate query plan against registered tables."""
        errors = []
        
        # Check table exists
        table = self.registry.get_table(plan.table_name)
        if not table:
            available_tables = self.registry.list_tables()
            errors.append(f"Table '{plan.table_name}' not found. Available tables: {', '.join(available_tables)}")
            return errors
        
        # Validate query context
        ctx = QueryContext(
            filters=plan.filters,
            limit=plan.limit,
            offset=plan.offset,
            order_by=plan.order_by,
            columns=plan.selected_columns if plan.selected_columns != ['*'] else None
        )
        
        validation_errors = table.validate_query(ctx)
        errors.extend(validation_errors)
        
        return errors
    
    async def _execute_query_plan(self, plan: QueryPlan) -> List[Dict[str, Any]]:
        """Execute a validated query plan."""
        # Handle wildcard tables with UNION ALL behavior
        if plan.wildcard_tables:
            return await self._execute_wildcard_query(plan)
        
        # Single table execution
        table = self.registry.get_table(plan.table_name)
        
        # Create query context
        ctx = QueryContext(
            filters=plan.filters,
            limit=plan.limit,
            offset=plan.offset,
            order_by=plan.order_by,
            columns=plan.selected_columns if plan.selected_columns != ['*'] else None,
            config={}  # Empty config for now, could be extended to include provider credentials
        )
        
        # Fetch data from table
        rows = []
        async for resource in table.list_resources(ctx):
            # Apply column selection
            if ctx.columns and ctx.columns != ['*']:
                resource = {col: resource.get(col) for col in ctx.columns}
            
            rows.append(resource)
            
            # Apply limit at engine level (tables might not support it)
            if plan.limit and len(rows) >= plan.limit:
                break
        
        # Apply sorting at engine level
        if plan.order_by:
            rows = self._sort_rows(rows, plan.order_by)
        
        # Apply offset at engine level  
        if plan.offset:
            rows = rows[plan.offset:]
        
        return rows
    
    async def _execute_wildcard_query(self, plan: QueryPlan) -> List[Dict[str, Any]]:
        """Execute query against multiple tables (UNION ALL behavior)."""
        all_rows = []
        
        # For wildcard queries, we need to collect results from all matching tables
        # We'll remove limit/offset from individual table queries and apply them at the end
        ctx_no_limits = QueryContext(
            filters=plan.filters,
            limit=None,  # Don't limit individual tables
            offset=None,  # Don't offset individual tables
            order_by=None,  # Don't sort individual tables
            columns=plan.selected_columns if plan.selected_columns != ['*'] else None,
            config={}  # Empty config for now
        )
        
        for table_name in plan.wildcard_tables:
            try:
                table = self.registry.get_table(table_name)
                if not table:
                    logger.warning(f"Table {table_name} not found in registry")
                    continue
                
                # Fetch data from this table
                table_rows = []
                async for resource in table.list_resources(ctx_no_limits):
                    # Apply column selection
                    if ctx_no_limits.columns and ctx_no_limits.columns != ['*']:
                        resource = {col: resource.get(col) for col in ctx_no_limits.columns}
                    
                    # Add table source metadata for debugging
                    if '_table_source' not in resource:
                        resource['_table_source'] = table_name
                    
                    table_rows.append(resource)
                
                logger.debug(f"Retrieved {len(table_rows)} rows from {table_name}")
                all_rows.extend(table_rows)
                
            except Exception as e:
                logger.error(f"Error querying table {table_name}: {e}")
                continue
        
        logger.info(f"Wildcard query collected {len(all_rows)} total rows from {len(plan.wildcard_tables)} tables")
        
        # Apply sorting at engine level across all results
        if plan.order_by:
            all_rows = self._sort_rows(all_rows, plan.order_by)
        
        # Apply offset at engine level
        if plan.offset:
            all_rows = all_rows[plan.offset:]
        
        # Apply limit at engine level
        if plan.limit:
            all_rows = all_rows[:plan.limit]
        
        return all_rows
    
    def _sort_rows(self, rows: List[Dict[str, Any]], order_by: List[str]) -> List[Dict[str, Any]]:
        """Sort rows by specified columns."""
        if not rows or not order_by:
            return rows
            
        # Parse order by columns and directions
        sort_keys = []
        for order_col in order_by:
            parts = order_col.strip().split()
            column = parts[0]
            direction = parts[1].upper() if len(parts) > 1 else 'ASC'
            reverse = direction == 'DESC'
            sort_keys.append((column, reverse))
        
        # Sort by each column (in reverse order for stable sorting)
        for column, reverse in reversed(sort_keys):
            rows.sort(key=lambda row: row.get(column, ''), reverse=reverse)
        
        return rows
    
    async def describe_table(self, table_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed schema information for a table."""
        return self.registry.get_table_info(table_name)
    
    async def list_tables(self, provider: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all available tables with basic information."""
        table_names = self.registry.list_tables(provider)
        tables_info = []
        
        for table_name in table_names:
            info = self.registry.get_table_info(table_name)
            if info:
                # Include summary info
                summary = {
                    "name": info["name"],
                    "provider": info["provider"], 
                    "description": info["description"],
                    "columns": len(info["columns"]),
                    "filterable_columns": len([c for c in info["columns"] if c["filterable"]])
                }
                tables_info.append(summary)
        
        return tables_info
    
    async def execute_count_query(self, table_name: str, filters: Optional[List[QueryFilter]] = None) -> int:
        """Execute a count query against a table."""
        table = self.registry.get_table(table_name)
        if not table:
            raise ValueError(f"Table '{table_name}' not found")
        
        ctx = QueryContext(filters=filters or [])
        return await table.count_resources(ctx)
    
    async def health_check(self) -> Dict[str, Any]:
        """Check health of the query engine."""
        return {
            "status": "healthy",
            "registered_tables": len(self.registry.list_tables()),
            "providers": self.registry.list_providers(),
            "version": "1.0.0"
        }
    
    def _substitute_parameters(self, sql: str, params: List[Any]) -> str:
        """
        Safely substitute parameters in SQL query.
        
        Args:
            sql: SQL with parameter placeholders ($1, $2, etc.)
            params: List of parameter values
            
        Returns:
            SQL with parameters safely substituted
        """
        import re
        
        def replace_param(match):
            param_num = int(match.group(1)) - 1  # Convert to 0-based index
            if param_num >= len(params):
                raise ValueError(f"Parameter ${param_num + 1} not provided")
            
            value = params[param_num]
            
            # Handle None/NULL
            if value is None:
                return 'NULL'
            
            # Handle strings - escape single quotes and wrap in quotes
            if isinstance(value, str):
                escaped_value = value.replace("'", "''")  # SQL standard escaping
                return f"'{escaped_value}'"
            
            # Handle numbers
            if isinstance(value, (int, float)):
                return str(value)
            
            # Handle booleans
            if isinstance(value, bool):
                return 'TRUE' if value else 'FALSE'
            
            # Handle dates/timestamps
            if hasattr(value, 'isoformat'):
                return f"'{value.isoformat()}'"
            
            # Fallback - treat as string
            escaped_value = str(value).replace("'", "''")
            return f"'{escaped_value}'"
        
        # Replace $1, $2, etc. with actual values
        return re.sub(r'\$(\d+)', replace_param, sql)


# Convenience functions for common query patterns

async def query_security_alerts(
    provider: Optional[str] = None,
    severity: Optional[str] = None,
    since: Optional[datetime] = None,
    limit: int = 100
) -> QueryResult:
    """Query security alerts with common filters."""
    engine = QueryEngine()
    
    # Build SQL query
    table_name = f"{provider}_alert" if provider else "*_alert"
    conditions = []
    
    if severity:
        conditions.append(f"severity = '{severity}'")
    if since:
        conditions.append(f"created_at >= '{since.isoformat()}'")
    
    where_clause = f" WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"SELECT * FROM {table_name}{where_clause} ORDER BY created_at DESC LIMIT {limit}"
    
    return await engine.execute_query(sql)


async def query_user_activity(
    user_id: Optional[str] = None,
    provider: Optional[str] = None,
    since: Optional[datetime] = None,
    limit: int = 100
) -> QueryResult:
    """Query user identity and activity data."""
    engine = QueryEngine()
    
    table_name = f"{provider}_user" if provider else "*_user"  
    conditions = []
    
    if user_id:
        conditions.append(f"user_id = '{user_id}'")
    if since:
        conditions.append(f"last_login >= '{since.isoformat()}'")
    
    where_clause = f" WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"SELECT * FROM {table_name}{where_clause} ORDER BY last_login DESC LIMIT {limit}"
    
    return await engine.execute_query(sql)
