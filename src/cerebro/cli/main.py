"""CLI interface for Cerebro."""

import asyncio
from datetime import datetime, timezone
from typing import List, Optional
import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from cerebro.core.database import async_session_factory
from cerebro.core.models import Organization, Rule, Finding
from cerebro.collectors.manager import CollectorManager
from cerebro.findings.manager import FindingManager
from cerebro.findings.evaluator import RuleEvaluator
from cerebro.rules.engine import rule_engine
from cerebro.query.bootstrap import get_query_engine
from cerebro.auditability.evidence_bundles import get_evidence_manager
from cerebro.auditability.transparency_log import get_transparency_log
from cerebro.cli.agents import app as agents_app
from cerebro.integrations.state import IntegrationStateRepository

app = typer.Typer(name="cerebro", help="Cerebro Security System of Record CLI")
console = Console()

# Add agents subcommand
app.add_typer(agents_app, name="agents")


@app.command()
def collect(
    org_name: str = typer.Argument(..., help="Organization name"),
    providers: Optional[List[str]] = typer.Option(
        None, "--provider", "-p", help="Providers to collect"
    ),
    resource_types: Optional[List[str]] = typer.Option(
        None, "--type", "-t", help="Resource types to collect"
    ),
):
    """Collect configuration data for an organization."""

    async def _collect():
        async with async_session_factory() as db:
            # Find organization
            from sqlalchemy import select

            stmt = select(Organization).where(Organization.name == org_name)
            org = await db.scalar(stmt)

            if not org:
                rprint(f"[red]Organization '{org_name}' not found[/red]")
                return

            collector_manager = CollectorManager(db)

            rprint(f"[blue]Starting collection for organization '{org_name}'...[/blue]")
            result = await collector_manager.collect_organization(
                str(org.org_id), providers=providers, resource_types=resource_types
            )

            # Display results
            table = Table(title="Collection Results")
            table.add_column("Metric", style="cyan")
            table.add_column("Count", style="green")

            table.add_row("Accounts Processed", str(result["accounts_processed"]))
            table.add_row("Total Resources", str(result["summary"]["total_resources"]))
            table.add_row(
                "Total Principals", str(result["summary"]["total_principals"])
            )
            table.add_row("Config Snapshots", str(result["summary"]["total_configs"]))
            table.add_row("IAM Edges", str(result["summary"]["total_iam_edges"]))
            table.add_row("Duration (seconds)", f"{result['duration_seconds']:.2f}")

            console.print(table)

            if result["errors"]:
                rprint("[yellow]Errors encountered:[/yellow]")
                for error in result["errors"]:
                    rprint(f"  - {error}")

    asyncio.run(_collect())


@app.command()
def rules(
    action: str = typer.Argument(..., help="Action: list, create, test"),
    name: Optional[str] = typer.Option(None, help="Rule name"),
    expression: Optional[str] = typer.Option(None, help="CEL expression"),
    severity: Optional[str] = typer.Option("medium", help="Severity level"),
    providers: Optional[List[str]] = typer.Option(
        ["github"], help="Applicable providers"
    ),
):
    """Manage security rules."""

    async def _rules():
        async with async_session_factory() as db:
            from sqlalchemy import select

            if action == "list":
                stmt = select(Rule).where(Rule.is_active == True)
                rules = list(await db.scalars(stmt))

                if not rules:
                    rprint("[yellow]No active rules found[/yellow]")
                    return

                table = Table(title="Active Rules")
                table.add_column("Name", style="cyan")
                table.add_column("Providers", style="blue")
                table.add_column("Severity", style="red")
                table.add_column("Language", style="green")

                for rule in rules:
                    table.add_row(
                        rule.name,
                        ", ".join(rule.provider),
                        rule.severity,
                        rule.expression_lang,
                    )

                console.print(table)

            elif action == "create":
                if not name or not expression:
                    rprint("[red]Name and expression required for creating rules[/red]")
                    return

                # Test compile the rule
                try:
                    rule_engine.compile_rule(expression)
                    rprint("[green]Rule compiled successfully[/green]")
                except Exception as e:
                    rprint(f"[red]Rule compilation failed: {e}[/red]")
                    return

                rule = Rule(
                    name=name,
                    provider=list(providers),
                    expression_lang="cel",
                    expression=expression,
                    severity=severity,
                )

                db.add(rule)
                await db.commit()
                rprint(f"[green]Rule '{name}' created successfully[/green]")

            elif action == "test":
                if not expression:
                    rprint("[red]Expression required for testing[/red]")
                    return

                try:
                    rule_engine.compile_rule(expression)
                    rprint("[green]✓ Rule compiles successfully[/green]")
                except Exception as e:
                    rprint(f"[red]✗ Rule compilation failed: {e}[/red]")

    asyncio.run(_rules())


@app.command()
def findings(
    action: str = typer.Argument(..., help="Action: list, generate, stats"),
    org_name: Optional[str] = typer.Option(None, help="Organization name"),
    status: Optional[str] = typer.Option(None, help="Filter by status"),
    severity: Optional[str] = typer.Option(None, help="Filter by severity"),
):
    """Manage security findings."""

    async def _findings():
        async with async_session_factory() as db:
            from sqlalchemy import select

            org = None
            if org_name:
                stmt = select(Organization).where(Organization.name == org_name)
                org = await db.scalar(stmt)
                if not org:
                    rprint(f"[red]Organization '{org_name}' not found[/red]")
                    return

            if action == "list":
                stmt = select(Finding)
                if org:
                    stmt = stmt.where(Finding.org_id == org.org_id)
                if status:
                    stmt = stmt.where(Finding.status == status)
                if severity:
                    stmt = stmt.where(Finding.severity == severity)

                findings = list(await db.scalars(stmt.limit(20)))

                if not findings:
                    rprint("[yellow]No findings found[/yellow]")
                    return

                table = Table(title="Security Findings")
                table.add_column("Title", style="cyan")
                table.add_column("Severity", style="red")
                table.add_column("Status", style="blue")
                table.add_column("Provider", style="green")
                table.add_column("Last Seen", style="dim")

                for finding in findings:
                    table.add_row(
                        (
                            finding.title[:50] + "..."
                            if len(finding.title) > 50
                            else finding.title
                        ),
                        finding.severity,
                        finding.status,
                        finding.provider,
                        finding.last_seen.strftime("%Y-%m-%d %H:%M"),
                    )

                console.print(table)

            elif action == "generate":
                if not org:
                    rprint(
                        "[red]Organization name required for generating findings[/red]"
                    )
                    return

                rprint(f"[blue]Generating findings for '{org_name}'...[/blue]")

                rule_evaluator = RuleEvaluator(db, rule_engine)
                finding_manager = FindingManager(db, rule_evaluator)

                result = await finding_manager.generate_findings(org)

                table = Table(title="Finding Generation Results")
                table.add_column("Metric", style="cyan")
                table.add_column("Count", style="green")

                table.add_row("Findings Created", str(result.findings_created))
                table.add_row("Findings Updated", str(result.findings_updated))
                table.add_row("Findings Closed", str(result.findings_closed))

                console.print(table)

                if result.errors:
                    rprint("[yellow]Errors encountered:[/yellow]")
                    for error in result.errors:
                        rprint(f"  - {error}")

            elif action == "stats":
                if not org:
                    rprint("[red]Organization name required for stats[/red]")
                    return

                rule_evaluator = RuleEvaluator(db, rule_engine)
                finding_manager = FindingManager(db, rule_evaluator)

                stats = await finding_manager.get_finding_stats(org.org_id)

                rprint(f"[blue]Finding Statistics for '{org_name}'[/blue]")
                rprint(f"Total Findings: {stats['total']}")

                if stats["by_status"]:
                    rprint("\nBy Status:")
                    for status_key, count in stats["by_status"].items():
                        rprint(f"  {status_key}: {count}")

                if stats["by_severity"]:
                    rprint("\nBy Severity:")
                    for severity_key, count in stats["by_severity"].items():
                        rprint(f"  {severity_key}: {count}")

    asyncio.run(_findings())


@app.command()
def org(
    action: str = typer.Argument(..., help="Action: list, create"),
    name: Optional[str] = typer.Option(None, help="Organization name"),
):
    """Manage organizations."""

    async def _org():
        async with async_session_factory() as db:
            from sqlalchemy import select

            if action == "list":
                stmt = select(Organization)
                orgs = list(await db.scalars(stmt))

                if not orgs:
                    rprint("[yellow]No organizations found[/yellow]")
                    return

                table = Table(title="Organizations")
                table.add_column("Name", style="cyan")
                table.add_column("Created", style="dim")

                for org in orgs:
                    table.add_row(org.name, org.created_at.strftime("%Y-%m-%d %H:%M"))

                console.print(table)

            elif action == "create":
                if not name:
                    rprint("[red]Organization name required[/red]")
                    return

                org = Organization(name=name)
                db.add(org)
                await db.commit()
                rprint(f"[green]Organization '{name}' created successfully[/green]")

    asyncio.run(_org())


@app.command()
def query(
    sql: Optional[str] = typer.Argument(None, help="SQL query to execute"),
    file: Optional[str] = typer.Option(None, "--file", "-f", help="Read SQL from file"),
    output: str = typer.Option("table", help="Output format: table, json"),
    limit: Optional[int] = typer.Option(None, help="Limit results"),
):
    """Execute SQL queries against security data."""

    async def _query():
        # Initialize query engine
        query_engine = get_query_engine()

        # Get SQL query
        query_sql = sql
        if file:
            try:
                with open(file, "r") as f:
                    query_sql = f.read().strip()
            except FileNotFoundError:
                rprint(f"[red]File '{file}' not found[/red]")
                return

        if not query_sql:
            rprint("[red]Must provide SQL query or --file option[/red]")
            return

        # Add LIMIT if specified
        if limit and "LIMIT" not in query_sql.upper():
            query_sql = f"{query_sql.rstrip(';')} LIMIT {limit}"

        try:
            rprint(f"[blue]Executing: {query_sql}[/blue]")
            result = await query_engine.execute_query(query_sql)

            if result.errors:
                rprint("[red]Query execution failed:[/red]")
                for error in result.errors:
                    rprint(f"  - {error}")
                return

            rprint(
                f"[green]Query completed in {result.execution_time_ms:.2f}ms[/green]"
            )
            rprint(f"[dim]Returned {result.total_rows} rows[/dim]")

            if not result.rows:
                rprint("[yellow]No results returned[/yellow]")
                return

            if output == "json":
                import json

                print(json.dumps(result.rows, indent=2, default=str))
            else:
                # Display as table
                table = Table()

                # Add columns
                for col in result.columns:
                    table.add_column(col, style="cyan")

                # Add rows (limit to 50 for readability)
                display_rows = result.rows[:50]
                for row in display_rows:
                    values = []
                    for col in result.columns:
                        value = row.get(col, "")
                        # Truncate long values
                        if isinstance(value, str) and len(value) > 50:
                            value = value[:47] + "..."
                        values.append(str(value))
                    table.add_row(*values)

                console.print(table)

                if len(result.rows) > 50:
                    rprint(f"[dim]... and {len(result.rows) - 50} more rows[/dim]")

        except Exception as e:
            rprint(f"[red]Error executing query: {e}[/red]")

    asyncio.run(_query())


@app.command()
def tables(
    provider: Optional[str] = typer.Option(None, help="Filter by provider"),
):
    """List available security tables."""

    async def _tables():
        query_engine = get_query_engine()

        try:
            tables = await query_engine.list_tables(provider=provider)

            if not tables:
                rprint("[yellow]No tables found[/yellow]")
                return

            table = Table(title="Available Security Tables")
            table.add_column("Name", style="cyan")
            table.add_column("Provider", style="blue")
            table.add_column("Columns", style="green")
            table.add_column("Description", style="dim")

            for tbl in tables:
                desc = tbl["description"]
                if len(desc) > 60:
                    desc = desc[:57] + "..."

                table.add_row(tbl["name"], tbl["provider"], str(tbl["columns"]), desc)

            console.print(table)

        except Exception as e:
            rprint(f"[red]Error listing tables: {e}[/red]")

    asyncio.run(_tables())


@app.command()
def evidence(
    action: str = typer.Argument(..., help="Action: export, verify, list"),
    bundle_path: Optional[str] = typer.Option(
        None, "--bundle", "-b", help="Evidence bundle file path"
    ),
    finding_id: Optional[str] = typer.Option(
        None, "--finding", help="Finding ID for evidence export"
    ),
    output_dir: str = typer.Option(
        "./evidence", "--output", "-o", help="Output directory for evidence bundles"
    ),
):
    """Manage cryptographic evidence bundles."""

    async def _evidence():
        evidence_manager = get_evidence_manager()

        if action == "export":
            if not finding_id:
                rprint("[red]Finding ID required for evidence export[/red]")
                return

            try:
                rprint(
                    f"[blue]Creating evidence bundle for finding {finding_id}...[/blue]"
                )

                # Create evidence bundle
                bundle = await evidence_manager.create_finding_evidence_bundle(
                    finding_id=finding_id,
                    created_by="cli_user",
                    organization_id="default_org",
                )

                # Seal the bundle
                seal_result = await bundle.seal_bundle()

                # Export to file
                output_path = f"{output_dir}/{bundle.metadata.bundle_id}.evb"
                exported_path = await bundle.export_bundle(output_path)

                rprint("[green]Evidence bundle created successfully[/green]")
                rprint(f"Bundle ID: {bundle.metadata.bundle_id}")
                rprint(f"Evidence items: {len(bundle.evidence_items)}")
                rprint(f"Exported to: {exported_path}")
                rprint(f"Bundle hash: {seal_result['bundle_hash']}")

            except Exception as e:
                rprint(f"[red]Evidence export failed: {e}[/red]")

        elif action == "verify":
            if not bundle_path:
                rprint("[red]Bundle path required for verification[/red]")
                return

            try:
                rprint(f"[blue]Verifying evidence bundle: {bundle_path}[/blue]")

                verification_result = await evidence_manager.verify_bundle(bundle_path)

                if verification_result["valid"]:
                    rprint("[green]✓ Bundle verification PASSED[/green]")
                    rprint(f"Bundle ID: {verification_result['bundle_id']}")

                    for check in verification_result["checks"]:
                        rprint(f"  ✓ {check}")
                else:
                    rprint("[red]✗ Bundle verification FAILED[/red]")

                    for error in verification_result["errors"]:
                        rprint(f"  ✗ {error}")

            except Exception as e:
                rprint(f"[red]Bundle verification error: {e}[/red]")

        elif action == "list":
            try:
                transparency_log = get_transparency_log()
                log_summary = await transparency_log.get_log_summary()

                rprint("[blue]Transparency Log Summary[/blue]")
                rprint(f"Total entries: {log_summary['total_entries']}")
                rprint(f"Latest sequence: {log_summary['latest_sequence']}")
                rprint(
                    f"Log period: {log_summary.get('log_start', 'N/A')} to {log_summary.get('log_end', 'N/A')}"
                )

                if log_summary.get("entries_by_type"):
                    rprint("\nEntries by type:")
                    for entry_type, count in log_summary["entries_by_type"].items():
                        rprint(f"  {entry_type}: {count}")

                rprint(
                    f"\nPublic key fingerprint: {log_summary.get('public_key_fingerprint', 'N/A')}"
                )

            except Exception as e:
                rprint(f"[red]Failed to list evidence: {e}[/red]")

    asyncio.run(_evidence())


@app.command()
def integrations(
    integration: Optional[str] = typer.Option(
        None, help="Filter by integration identifier"
    ),
    scope: Optional[str] = typer.Option(None, help="Filter by integration scope"),
    stale_after: int = typer.Option(
        3600, help="Mark syncs older than this many seconds as stale (0 to disable)"
    ),
):
    """Display integration synchronization freshness."""

    async def _integrations():
        async with async_session_factory() as db:
            repo = IntegrationStateRepository(db)
            states = await repo.list_states(integration=integration)

            if scope:
                states = [state for state in states if state.scope == scope]

            if not states:
                rprint("[yellow]No integration sync state found[/yellow]")
                return

            table = Table(title="Integration Sync Freshness")
            table.add_column("Integration", style="cyan")
            table.add_column("Scope", style="blue")
            table.add_column("Last Sync", style="green")
            table.add_column("Age", style="magenta")
            table.add_column("Metadata", style="dim")

            now = datetime.now(timezone.utc)
            stale_threshold = stale_after if stale_after and stale_after > 0 else None

            for state in states:
                last_ts = state.last_timestamp
                if last_ts and last_ts.tzinfo is None:
                    last_ts = last_ts.replace(tzinfo=timezone.utc)

                if last_ts is None:
                    last_sync_text = "[italic]never[/italic]"
                    age_text = "n/a"
                    is_stale = True if stale_threshold is not None else False
                else:
                    age_seconds = max((now - last_ts).total_seconds(), 0)
                    minutes, seconds = divmod(int(age_seconds), 60)
                    age_text = f"{minutes}m {seconds}s"
                    last_sync_text = last_ts.isoformat()
                    is_stale = (
                        stale_threshold is not None and age_seconds > stale_threshold
                    )

                if is_stale:
                    last_sync_display = f"[red]{last_sync_text}[/red]"
                    age_display = f"[red]{age_text}[/red]"
                else:
                    last_sync_display = last_sync_text
                    age_display = age_text

                metadata = state.state_metadata or {}
                metadata_display = (
                    ", ".join(f"{k}={v}" for k, v in metadata.items()) or "-"
                )

                table.add_row(
                    state.integration,
                    state.scope or "default",
                    last_sync_display,
                    age_display,
                    metadata_display,
                )

            console.print(table)

    asyncio.run(_integrations())


if __name__ == "__main__":
    app()
