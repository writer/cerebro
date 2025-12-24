"""
SQL query commands for Cerebro CLI.

Provides interactive SQL querying capabilities for security data.
"""

from typing import Optional, List, TYPE_CHECKING
import click

from ...core.database import async_session_factory
from ...integrations.freshness import IntegrationFreshnessService
from ...query.bootstrap import get_query_engine

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...query.engine import QueryEngine
from ..utils import async_command, format_datetime, print_json, print_table  # type: ignore[import-untyped]


@click.group(name="query")
def query_group():
    """SQL query commands for security data."""
    pass


@query_group.command("execute")
@click.argument("sql", required=False)
@click.option("--file", "-f", help="Read SQL from file")
@click.option(
    "--output",
    "-o",
    type=click.Choice(["table", "json", "csv"]),
    default="table",
    help="Output format",
)
@click.option("--limit", type=int, help="Limit number of results")
@click.option("--timeout", type=int, default=30, help="Query timeout in seconds")
@async_command
async def execute_sql(
    sql: Optional[str],
    file: Optional[str],
    output: str,
    limit: Optional[int],
    timeout: int,
):
    """
    Execute a SQL query against security tables.

    Examples:
        cerebro query execute "SELECT * FROM aws_ec2_instance LIMIT 5"
        cerebro query execute --file query.sql --output json
    """
    # Initialize query engine
    query_engine = get_query_engine()

    # Get SQL query
    if file:
        try:
            with open(file, "r") as f:
                sql = f.read().strip()
        except FileNotFoundError:
            click.echo(f"Error: File '{file}' not found", err=True)
            return
    elif not sql:
        click.echo("Error: Must provide SQL query or --file option", err=True)
        return

    # Add LIMIT if specified
    if limit and "LIMIT" not in sql.upper():
        sql = f"{sql.rstrip(';')} LIMIT {limit}"

    try:
        click.echo(f"Executing query: {sql}")
        result = await query_engine.execute_query(sql)

        if result.errors:
            click.echo("Query execution failed:", err=True)
            for error in result.errors:
                click.echo(f"  - {error}", err=True)
            return

        # Display results
        click.echo(f"\nQuery completed in {result.execution_time_ms:.2f}ms")
        click.echo(
            f"Returned {result.total_rows} rows from tables: {', '.join(result.tables_queried)}"
        )

        providers = _derive_providers(query_engine, result)
        if providers:
            async with async_session_factory() as session:
                freshness_service = IntegrationFreshnessService(session)
                provider_freshness = await freshness_service.provider_freshness(
                    providers
                )

            click.echo("Data freshness:")
            for provider, summary in provider_freshness.items():
                last_synced = (
                    format_datetime(summary.last_synced_at)
                    if summary.last_synced_at
                    else "unknown"
                )
                age = summary.age_human or "age unknown"
                click.echo(
                    f"  - {provider}: last synced {last_synced} ({age}, status {summary.status}, confidence {summary.confidence})"
                )
                if summary.warning:
                    click.echo(f"    {summary.warning}")

        click.echo()

        if not result.rows:
            click.echo("No results returned.")
            return

        if output == "json":
            print_json(
                {
                    "columns": result.columns,
                    "rows": result.rows,
                    "total_rows": result.total_rows,
                    "execution_time_ms": result.execution_time_ms,
                }
            )
        elif output == "csv":
            import csv
            import sys

            writer = csv.DictWriter(sys.stdout, fieldnames=result.columns)
            writer.writeheader()
            writer.writerows(result.rows)
        else:  # table format
            print_table(result.rows, headers=result.columns)

    except Exception as e:
        click.echo(f"Error executing query: {e}", err=True)


def _derive_providers(query_engine: "QueryEngine", result) -> List[str]:
    providers: List[str] = []
    tables = getattr(result, "tables_queried", []) or []
    if not tables:
        return providers
    seen = set()
    registry = query_engine.registry
    for table in tables:
        info = registry.get_table_info(table)
        provider = (info or {}).get("provider") if info else None
        if provider and provider not in seen:
            providers.append(provider)
            seen.add(provider)
    return providers


@query_group.command("tables")
@click.option("--provider", help="Filter by provider (aws, okta, github, etc.)")
@click.option(
    "--output",
    "-o",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
@async_command
async def list_tables(provider: Optional[str], output: str):
    """
    List all available security tables.
    """
    query_engine = get_query_engine()

    try:
        tables = await query_engine.list_tables(provider=provider)

        if output == "json":
            print_json({"tables": tables})
        else:
            if not tables:
                click.echo("No tables found.")
                return

            # Format for table display
            table_data = [
                {
                    "Name": table["name"],
                    "Provider": table["provider"],
                    "Columns": table["columns"],
                    "Filterable": table["filterable_columns"],
                    "Description": (
                        table["description"][:60] + "..."
                        if len(table["description"]) > 60
                        else table["description"]
                    ),
                }
                for table in tables
            ]

            print_table(table_data)

    except Exception as e:
        click.echo(f"Error listing tables: {e}", err=True)


@query_group.command("describe")
@click.argument("table_name")
@click.option(
    "--output",
    "-o",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
@async_command
async def describe_table(table_name: str, output: str):
    """
    Describe the schema of a security table.
    """
    query_engine = get_query_engine()

    try:
        table_info = await query_engine.describe_table(table_name)

        if not table_info:
            click.echo(f"Table '{table_name}' not found.", err=True)
            return

        if output == "json":
            print_json(table_info)
        else:
            click.echo(f"\nTable: {table_info['name']}")
            click.echo(f"Provider: {table_info['provider']}")
            click.echo(f"Description: {table_info['description']}")
            click.echo()

            # Display columns
            column_data = [
                {
                    "Column": col["name"],
                    "Type": col["type"],
                    "Required": "✓" if col["required"] else "",
                    "Filterable": "✓" if col["filterable"] else "",
                    "Description": (
                        col["description"][:50] + "..."
                        if len(col["description"]) > 50
                        else col["description"]
                    ),
                }
                for col in table_info["columns"]
            ]

            click.echo("Columns:")
            print_table(column_data)

            # Display indexes
            if table_info["indexes"]:
                click.echo("\nIndexes:")
                index_data = [
                    {
                        "Name": idx["name"],
                        "Columns": ", ".join(idx["columns"]),
                        "Unique": "✓" if idx["unique"] else "",
                    }
                    for idx in table_info["indexes"]
                ]
                print_table(index_data)

    except Exception as e:
        click.echo(f"Error describing table: {e}", err=True)


@query_group.command("examples")
@click.option("--provider", help="Filter examples by provider")
@async_command
async def show_examples(provider: Optional[str]):
    """
    Show example SQL queries for common security use cases.
    """
    examples = [
        {
            "name": "List AWS EC2 instances",
            "provider": "aws",
            "description": "Get all EC2 instances with basic information",
            "sql": "SELECT instance_id, instance_type, state, public_ip FROM aws_ec2_instance LIMIT 10",
        },
        {
            "name": "Find inactive Okta users",
            "provider": "okta",
            "description": "List Okta users that haven't logged in recently",
            "sql": "SELECT username, email, status, last_login FROM okta_user WHERE status = 'inactive' ORDER BY last_login DESC LIMIT 20",
        },
        {
            "name": "High severity GitHub vulnerabilities",
            "provider": "github",
            "description": "Find critical vulnerability alerts in GitHub repos",
            "sql": "SELECT repository, state, security_advisory FROM github_vulnerability_alert WHERE severity IN ('high', 'critical') LIMIT 10",
        },
        {
            "name": "AWS security groups with wide access",
            "provider": "aws",
            "description": "Find security groups allowing access from anywhere",
            "sql": "SELECT group_id, group_name, vpc_id FROM aws_security_group WHERE ingress_rules LIKE '%0.0.0.0/0%'",
        },
        {
            "name": "Recent Okta applications",
            "provider": "okta",
            "description": "List recently created or updated applications",
            "sql": "SELECT app_name, label, app_status, updated_at FROM okta_application WHERE updated_at > '2024-01-01' ORDER BY updated_at DESC",
        },
        {
            "name": "GitHub secret scanning alerts",
            "provider": "github",
            "description": "Find unresolved secret scanning alerts",
            "sql": "SELECT repository, secret_type, state, created_at FROM github_secret_scanning_alert WHERE state = 'open' ORDER BY created_at DESC",
        },
    ]

    # Filter by provider if specified
    if provider:
        examples = [ex for ex in examples if ex["provider"] == provider]

    if not examples:
        click.echo(
            f"No examples found{f' for provider {provider}' if provider else ''}."
        )
        return

    click.echo(f"SQL Query Examples{f' for {provider}' if provider else ''}:")
    click.echo()

    for i, example in enumerate(examples, 1):
        click.echo(f"{i}. {example['name']} ({example['provider']})")
        click.echo(f"   {example['description']}")
        click.echo(f"   SQL: {example['sql']}")
        click.echo()


@query_group.command("interactive")
@async_command
async def interactive_query():
    """
    Start an interactive SQL query session.

    Type SQL queries and see results immediately. Type 'quit' or 'exit' to leave.
    """
    query_engine = get_query_engine()

    click.echo("Cerebro Interactive SQL Query Session")
    click.echo("Type SQL queries and press Enter. Use 'quit' or 'exit' to leave.")
    click.echo("Commands: .tables (list tables), .describe <table> (show schema)")
    click.echo()

    while True:
        try:
            query = click.prompt("cerebro> ", type=str).strip()

            if query.lower() in ["quit", "exit", "q"]:
                click.echo("Goodbye!")
                break

            if not query:
                continue

            # Handle special commands
            if query.startswith("."):
                await handle_special_command(query, query_engine)
                continue

            # Execute SQL query
            try:
                result = await query_engine.execute_query(query)

                if result.errors:
                    click.echo("Errors:", err=True)
                    for error in result.errors:
                        click.echo(f"  {error}", err=True)
                    continue

                click.echo(
                    f"({result.total_rows} rows, {result.execution_time_ms:.2f}ms)"
                )

                providers = _derive_providers(query_engine, result)
                if providers:
                    async with async_session_factory() as session:
                        freshness_service = IntegrationFreshnessService(session)
                        provider_freshness = await freshness_service.provider_freshness(
                            providers
                        )

                    click.echo("Data freshness:")
                    for provider, summary in provider_freshness.items():
                        last_synced = (
                            format_datetime(summary.last_synced_at)
                            if summary.last_synced_at
                            else "unknown"
                        )
                        age = summary.age_human or "age unknown"
                        click.echo(
                            f"  - {provider}: last synced {last_synced} ({age}, status {summary.status}, confidence {summary.confidence})"
                        )
                        if summary.warning:
                            click.echo(f"    {summary.warning}")

                if result.rows:
                    # Limit display to first 50 rows for readability
                    display_rows = result.rows[:50]
                    print_table(display_rows, headers=result.columns)

                    if len(result.rows) > 50:
                        click.echo(f"... and {len(result.rows) - 50} more rows")
                else:
                    click.echo("No results.")

                click.echo()

            except Exception as e:
                click.echo(f"Query error: {e}", err=True)

        except KeyboardInterrupt:
            click.echo("\nGoodbye!")
            break
        except EOFError:
            click.echo("\nGoodbye!")
            break


async def handle_special_command(command: str, query_engine: "QueryEngine"):
    """Handle special dot commands in interactive mode."""
    parts = command.split()
    cmd = parts[0].lower()

    if cmd == ".tables":
        tables = await query_engine.list_tables()
        click.echo("Available tables:")
        for table in tables:
            click.echo(
                f"  {table['name']} ({table['provider']}) - {table['description']}"
            )
        click.echo()

    elif cmd == ".describe" and len(parts) > 1:
        table_name = parts[1]
        table_info = await query_engine.describe_table(table_name)

        if not table_info:
            click.echo(f"Table '{table_name}' not found.")
            return

        click.echo(f"\nTable: {table_info['name']} ({table_info['provider']})")
        click.echo(f"Description: {table_info['description']}")
        click.echo("\nColumns:")

        for col in table_info["columns"]:
            required = " (required)" if col["required"] else ""
            filterable = " [filterable]" if col["filterable"] else ""
            click.echo(f"  {col['name']}: {col['type']}{required}{filterable}")
            click.echo(f"    {col['description']}")
        click.echo()

    elif cmd == ".help":
        click.echo("Special commands:")
        click.echo("  .tables        - List all available tables")
        click.echo("  .describe <table> - Show table schema")
        click.echo("  .help          - Show this help")
        click.echo("  quit/exit      - Exit interactive session")
        click.echo()

    else:
        click.echo(f"Unknown command: {command}")
        click.echo("Use '.help' for available commands.")


# Convenience query commands


@query_group.command("alerts")
@click.option("--provider", help="Filter by provider")
@click.option("--severity", help="Filter by severity (critical, high, medium, low)")
@click.option("--since", help="Filter by creation date (YYYY-MM-DD)")
@click.option("--limit", type=int, default=20, help="Maximum results")
@click.option(
    "--output",
    "-o",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
@async_command
async def query_alerts(
    provider: Optional[str],
    severity: Optional[str],
    since: Optional[str],
    limit: int,
    output: str,
):
    """Query security alerts with common filters."""
    query_engine = get_query_engine()

    conditions = []
    if provider:
        conditions.append(f"provider = '{provider}'")
    if severity:
        conditions.append(f"severity = '{severity}'")
    if since:
        conditions.append(f"created_at >= '{since}'")

    where_clause = f" WHERE {' AND '.join(conditions)}" if conditions else ""

    # Query GitHub vulnerability alerts (expand for other providers)
    sql = f"SELECT repository, state, severity, created_at FROM github_vulnerability_alert{where_clause} ORDER BY created_at DESC LIMIT {limit}"

    try:
        result = await query_engine.execute_query(sql)

        if output == "json":
            print_json({"alerts": result.rows})
        else:
            if result.rows:
                print_table(result.rows, headers=result.columns)
            else:
                click.echo("No alerts found matching criteria.")

    except Exception as e:
        click.echo(f"Error querying alerts: {e}", err=True)


@query_group.command("users")
@click.option("--provider", help="Filter by provider")
@click.option("--status", help="Filter by status")
@click.option("--mfa", type=bool, help="Filter by MFA enabled (true/false)")
@click.option("--limit", type=int, default=20, help="Maximum results")
@click.option(
    "--output",
    "-o",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
@async_command
async def query_users(
    provider: Optional[str],
    status: Optional[str],
    mfa: Optional[bool],
    limit: int,
    output: str,
):
    """Query user identities across providers."""
    query_engine = get_query_engine()

    conditions = []
    if provider:
        conditions.append(f"provider = '{provider}'")
    if status:
        conditions.append(f"status = '{status}'")
    if mfa is not None:
        conditions.append(f"mfa_enabled = {str(mfa).lower()}")

    where_clause = f" WHERE {' AND '.join(conditions)}" if conditions else ""

    # Query Okta users (expand for other identity providers)
    sql = f"SELECT username, email, status, last_login, mfa_enabled FROM okta_user{where_clause} ORDER BY last_login DESC LIMIT {limit}"

    try:
        result = await query_engine.execute_query(sql)

        if output == "json":
            print_json({"users": result.rows})
        else:
            if result.rows:
                print_table(result.rows, headers=result.columns)
            else:
                click.echo("No users found matching criteria.")

    except Exception as e:
        click.echo(f"Error querying users: {e}", err=True)
