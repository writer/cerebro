"""CLI interface for Cerebro."""

import asyncio
from typing import List, Optional
from uuid import UUID
import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from cerebro.core.database import async_session_factory
from cerebro.core.models import Organization, Account, Rule, Finding
from cerebro.collectors.manager import CollectorManager
from cerebro.findings.manager import FindingManager
from cerebro.findings.evaluator import RuleEvaluator
from cerebro.rules.engine import rule_engine

app = typer.Typer(name="cerebro", help="Cerebro Security System of Record CLI")
console = Console()


@app.command()
def collect(
    org_name: str = typer.Argument(..., help="Organization name"),
    providers: Optional[List[str]] = typer.Option(None, "--provider", "-p", help="Providers to collect"),
    resource_types: Optional[List[str]] = typer.Option(None, "--type", "-t", help="Resource types to collect"),
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
                str(org.org_id),
                providers=providers,
                resource_types=resource_types
            )
            
            # Display results
            table = Table(title="Collection Results")
            table.add_column("Metric", style="cyan")
            table.add_column("Count", style="green")
            
            table.add_row("Accounts Processed", str(result["accounts_processed"]))
            table.add_row("Total Resources", str(result["summary"]["total_resources"]))
            table.add_row("Total Principals", str(result["summary"]["total_principals"]))
            table.add_row("Config Snapshots", str(result["summary"]["total_configs"]))
            table.add_row("IAM Edges", str(result["summary"]["total_iam_edges"]))
            table.add_row("Duration (seconds)", f"{result['duration_seconds']:.2f}")
            
            console.print(table)
            
            if result["errors"]:
                rprint(f"[yellow]Errors encountered:[/yellow]")
                for error in result["errors"]:
                    rprint(f"  - {error}")
    
    asyncio.run(_collect())


@app.command()
def rules(
    action: str = typer.Argument(..., help="Action: list, create, test"),
    name: Optional[str] = typer.Option(None, help="Rule name"),
    expression: Optional[str] = typer.Option(None, help="CEL expression"),
    severity: Optional[str] = typer.Option("medium", help="Severity level"),
    providers: Optional[List[str]] = typer.Option(["github"], help="Applicable providers"),
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
                        rule.expression_lang
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
                    severity=severity
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
            from sqlalchemy import select, and_
            
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
                        finding.title[:50] + "..." if len(finding.title) > 50 else finding.title,
                        finding.severity,
                        finding.status,
                        finding.provider,
                        finding.last_seen.strftime("%Y-%m-%d %H:%M")
                    )
                
                console.print(table)
                
            elif action == "generate":
                if not org:
                    rprint("[red]Organization name required for generating findings[/red]")
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
                    rprint(f"[yellow]Errors encountered:[/yellow]")
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
                
                if stats['by_status']:
                    rprint("\nBy Status:")
                    for status, count in stats['by_status'].items():
                        rprint(f"  {status}: {count}")
                
                if stats['by_severity']:
                    rprint("\nBy Severity:")
                    for severity, count in stats['by_severity'].items():
                        rprint(f"  {severity}: {count}")
    
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
                    table.add_row(
                        org.name,
                        org.created_at.strftime("%Y-%m-%d %H:%M")
                    )
                
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


if __name__ == "__main__":
    app()
