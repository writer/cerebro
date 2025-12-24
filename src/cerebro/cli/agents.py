"""
CLI commands for managing Cerebro security agents.

Provides comprehensive agent session management including creation, interaction,
monitoring, and approval workflows.
"""

import asyncio
import json
from datetime import UTC, datetime
from uuid import UUID

import typer
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from sqlalchemy import select

from cerebro.agents.models import AgentType, ApprovalStatus
from cerebro.agents.service import (
    AgentAnalyticsService,
    AgentSessionService,
    ToolApprovalService,
)
from cerebro.core.database import async_session_factory
from cerebro.core.models import Organization

app = typer.Typer(name="agents", help="Manage Cerebro security agents")
console = Console()


@app.command()
def create(
    org_name: str = typer.Argument(..., help="Organization name"),
    agent_type: str = typer.Option(
        "security_analyst",
        "--type",
        "-t",
        help="Agent type: security_analyst, compliance_auditor, incident_responder",
    ),
    title: str | None = typer.Option(None, "--title", help="Session title"),
    created_by: str = typer.Option(
        "cli_user", "--user", help="User creating the session"
    ),
    context_file: str | None = typer.Option(
        None, "--context", help="JSON file with agent context"
    ),
):
    """Create a new agent session."""

    async def _create():
        # Find organization
        async with async_session_factory() as db:
            stmt = select(Organization).where(Organization.name == org_name)
            org = await db.scalar(stmt)

            if not org:
                rprint(f"[red]Organization '{org_name}' not found[/red]")
                return

            # Load context
            context = {}
            if context_file:
                try:
                    with open(context_file) as f:
                        context = json.load(f)
                except FileNotFoundError:
                    rprint(f"[red]Context file '{context_file}' not found[/red]")
                    return
                except json.JSONDecodeError:
                    rprint(f"[red]Invalid JSON in context file '{context_file}'[/red]")
                    return

            # Create session
            service = AgentSessionService()

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                task = progress.add_task("Creating agent session...", total=None)

                try:
                    session = await service.create_session(
                        org_id=org.org_id,
                        agent_type=agent_type,
                        created_by=created_by,
                        context=context,
                        title=title,
                    )

                    progress.update(task, completed=1)

                    # Display success
                    rprint("[green]✓ Agent session created successfully[/green]")

                    table = Table(title="Session Details")
                    table.add_column("Property", style="cyan")
                    table.add_column("Value", style="white")

                    table.add_row("Session ID", str(session.id))
                    table.add_row("Agent Type", session.agent_type.value)
                    table.add_row("Organization", org_name)
                    table.add_row("Created By", session.created_by)
                    table.add_row(
                        "Created At", session.created_at.strftime("%Y-%m-%d %H:%M:%S")
                    )
                    if session.title:
                        table.add_row("Title", session.title)

                    console.print(table)

                    if context:
                        rprint(f"\n[dim]Context loaded with {len(context)} keys[/dim]")

                    rprint(
                        f"\n[blue]💬 Start chatting with: cerebro agents chat {session.id}[/blue]"
                    )

                except ValueError as e:
                    rprint(f"[red]Invalid agent type '{agent_type}': {e}[/red]")
                    rprint(
                        f"[dim]Valid types: {', '.join([t.value for t in AgentType])}[/dim]"
                    )
                except Exception as e:
                    rprint(f"[red]Error creating session: {e}[/red]")

    asyncio.run(_create())


@app.command()
def list(
    org_name: str = typer.Argument(..., help="Organization name"),
    agent_type: str | None = typer.Option(
        None, "--type", "-t", help="Filter by agent type"
    ),
    created_by: str | None = typer.Option(None, "--user", help="Filter by creator"),
    limit: int = typer.Option(
        20, "--limit", "-l", help="Maximum number of sessions to show"
    ),
    offset: int = typer.Option(0, "--offset", help="Offset for pagination"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List agent sessions for an organization."""

    async def _list():
        # Find organization
        async with async_session_factory() as db:
            stmt = select(Organization).where(Organization.name == org_name)
            org = await db.scalar(stmt)

            if not org:
                rprint(f"[red]Organization '{org_name}' not found[/red]")
                return

            service = AgentSessionService()

            try:
                sessions, total_count = await service.list_sessions(
                    org_id=org.org_id,
                    agent_type=agent_type,
                    created_by=created_by,
                    limit=limit,
                    offset=offset,
                )

                if json_output:
                    session_data = [
                        {
                            "id": str(session.id),
                            "agent_type": session.agent_type.value,
                            "title": session.title,
                            "created_by": session.created_by,
                            "created_at": session.created_at.isoformat(),
                            "last_activity": (
                                session.last_activity_at.isoformat()
                                if session.last_activity_at
                                else None
                            ),
                            "message_count": session.message_count,
                        }
                        for session in sessions
                    ]
                    print(
                        json.dumps(
                            {"sessions": session_data, "total": total_count}, indent=2
                        )
                    )
                    return

                if not sessions:
                    rprint(f"[yellow]No agent sessions found for '{org_name}'[/yellow]")
                    if agent_type or created_by:
                        rprint("[dim]Try removing filters to see more results[/dim]")
                    return

                # Display as table
                table = Table(
                    title=f"Agent Sessions for '{org_name}' ({total_count} total)"
                )
                table.add_column("Session ID", style="cyan", width=36)
                table.add_column("Type", style="blue")
                table.add_column("Title", style="white")
                table.add_column("Created By", style="green")
                table.add_column("Created", style="dim")
                table.add_column("Messages", style="yellow", justify="right")
                table.add_column("Last Activity", style="dim")

                for session in sessions:
                    last_activity = (
                        session.last_activity_at.strftime("%m-%d %H:%M")
                        if session.last_activity_at
                        else "Never"
                    )

                    table.add_row(
                        str(session.id)[:36],
                        session.agent_type.value.replace("_", " ").title(),
                        session.title or "[dim]No title[/dim]",
                        session.created_by,
                        session.created_at.strftime("%m-%d %H:%M"),
                        str(session.message_count),
                        last_activity,
                    )

                console.print(table)

                # Show pagination info
                if total_count > limit:
                    start = offset + 1
                    end = min(offset + limit, total_count)
                    rprint(
                        f"\n[dim]Showing {start}-{end} of {total_count} sessions[/dim]"
                    )

                    if end < total_count:
                        rprint(
                            f"[blue]Show more: cerebro agents list {org_name} --offset {offset + limit}[/blue]"
                        )

            except Exception as e:
                rprint(f"[red]Error listing sessions: {e}[/red]")

    asyncio.run(_list())


@app.command()
def chat(
    session_id: str = typer.Argument(..., help="Agent session ID"),
    org_name: str | None = typer.Option(
        None, "--org", help="Organization name for access control"
    ),
    user_id: str = typer.Option("cli_user", "--user", help="User identifier"),
    stream: bool = typer.Option(True, "--stream/--no-stream", help="Stream responses"),
):
    """Start an interactive chat session with an agent."""

    async def _chat():
        service = AgentSessionService()

        # Validate session exists
        try:
            session_uuid = UUID(session_id)
        except ValueError:
            rprint(f"[red]Invalid session ID format: {session_id}[/red]")
            return

        # Get organization if specified
        org_uuid = None
        if org_name:
            async with async_session_factory() as db:
                stmt = select(Organization).where(Organization.name == org_name)
                org = await db.scalar(stmt)
                if not org:
                    rprint(f"[red]Organization '{org_name}' not found[/red]")
                    return
                org_uuid = org.org_id

        # Verify session exists
        session = await service.get_session(session_uuid, org_uuid)
        if not session:
            rprint(f"[red]Session not found or access denied: {session_id}[/red]")
            return

        # Display session info
        panel = Panel(
            f"[bold]Agent Type:[/bold] {session.agent_type.value.replace('_', ' ').title()}\n"
            f"[bold]Created:[/bold] {session.created_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"[bold]Messages:[/bold] {session.message_count}\n"
            f"[bold]Title:[/bold] {session.title or 'No title'}",
            title=f"Chat Session {session_id[:8]}...",
            border_style="blue",
        )
        console.print(panel)

        rprint("[dim]Type 'quit' or 'exit' to end the chat session[/dim]")
        rprint("[dim]Type 'help' for available commands[/dim]")
        rprint()

        # Interactive chat loop
        while True:
            try:
                message = Prompt.ask("You", default="").strip()

                if message.lower() in ["quit", "exit", "q"]:
                    rprint("[blue]👋 Chat session ended[/blue]")
                    break

                if message.lower() == "help":
                    _show_chat_help()
                    continue

                if message.lower().startswith("status"):
                    await _show_session_status(service, session_uuid)
                    continue

                if not message:
                    continue

                # Send message to agent
                rprint("[blue]Agent:[/blue]", end=" ")

                response_parts = []

                async for response in service.send_message(
                    session_id=session_uuid,
                    message=message,
                    user_id=user_id,
                    org_id=org_uuid,
                    stream=stream,
                ):
                    if response["type"] == "error":
                        rprint(f"[red]Error: {response['content']['message']}[/red]")
                        break

                    elif response["type"] == "content":
                        content = response["content"]
                        if stream:
                            print(content.get("text", ""), end="", flush=True)
                        response_parts.append(content.get("text", ""))

                    elif response["type"] == "tool_use":
                        tool_info = response["content"]
                        rprint(f"\n[yellow]🔧 Using tool: {tool_info['name']}[/yellow]")
                        if tool_info.get("input"):
                            rprint(
                                f"[dim]Input: {json.dumps(tool_info['input'], indent=2)}[/dim]"
                            )

                    elif response["type"] == "tool_result":
                        result = response["content"]
                        if result.get("is_error"):
                            rprint(f"[red]❌ Tool error: {result.get('content')}[/red]")
                        else:
                            rprint("[green]✅ Tool completed[/green]")

                    elif response["type"] == "approval_required":
                        approval_info = response["content"]
                        rprint(
                            f"\n[yellow]⚠️  Tool approval required for: {approval_info['tool_name']}[/yellow]"
                        )
                        rprint(
                            f"[dim]Approval ID: {approval_info['approval_id']}[/dim]"
                        )
                        rprint(
                            f"[dim]Use: cerebro agents approve {approval_info['approval_id']}[/dim]"
                        )

                if stream:
                    print()  # New line after streamed response

                print()  # Extra line for readability

            except KeyboardInterrupt:
                rprint("\n[blue]👋 Chat session interrupted[/blue]")
                break
            except EOFError:
                rprint("\n[blue]👋 Chat session ended[/blue]")
                break
            except Exception as e:
                rprint(f"[red]Error in chat: {e}[/red]")

    asyncio.run(_chat())


def _show_chat_help():
    """Show chat session help."""
    help_panel = Panel(
        """[bold]Chat Commands:[/bold]

[cyan]help[/cyan] - Show this help message
[cyan]status[/cyan] - Show session status and metrics
[cyan]quit[/cyan] / [cyan]exit[/cyan] / [cyan]q[/cyan] - End chat session

[bold]Tips:[/bold]
• Ask questions about your security posture
• Request compliance reports and audits
• Get help with incident response
• The agent has access to your organization's security data
""",
        title="Chat Help",
        border_style="green",
    )
    console.print(help_panel)


async def _show_session_status(service: AgentSessionService, session_id: UUID):
    """Show detailed session status."""
    try:
        session = await service.get_session(session_id)
        if not session:
            rprint("[red]Session not found[/red]")
            return

        status_table = Table(title="Session Status")
        status_table.add_column("Metric", style="cyan")
        status_table.add_column("Value", style="white")

        status_table.add_row("Session ID", str(session.id))
        status_table.add_row("Agent Type", session.agent_type.value)
        status_table.add_row("Message Count", str(session.message_count))
        status_table.add_row(
            "Created At", session.created_at.strftime("%Y-%m-%d %H:%M:%S")
        )

        if session.last_activity_at:
            status_table.add_row(
                "Last Activity", session.last_activity_at.strftime("%Y-%m-%d %H:%M:%S")
            )

        console.print(status_table)

    except Exception as e:
        rprint(f"[red]Error getting status: {e}[/red]")


@app.command()
def status(
    session_id: str = typer.Argument(..., help="Agent session ID"),
    org_name: str | None = typer.Option(None, "--org", help="Organization name"),
    detailed: bool = typer.Option(
        False, "--detailed", "-d", help="Show detailed metrics"
    ),
):
    """Show agent session status and metrics."""

    async def _status():
        service = AgentSessionService()

        try:
            session_uuid = UUID(session_id)
        except ValueError:
            rprint(f"[red]Invalid session ID format: {session_id}[/red]")
            return

        # Get organization if specified
        org_uuid = None
        if org_name:
            async with async_session_factory() as db:
                stmt = select(Organization).where(Organization.name == org_name)
                org = await db.scalar(stmt)
                if not org:
                    rprint(f"[red]Organization '{org_name}' not found[/red]")
                    return
                org_uuid = org.org_id

        session = await service.get_session(session_uuid, org_uuid)
        if not session:
            rprint(f"[red]Session not found or access denied: {session_id}[/red]")
            return

        # Basic status
        table = Table(title=f"Session Status: {session_id[:12]}...")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Session ID", str(session.id))
        table.add_row("Agent Type", session.agent_type.value.replace("_", " ").title())
        table.add_row("Title", session.title or "[dim]No title[/dim]")
        table.add_row("Created By", session.created_by)
        table.add_row("Created At", session.created_at.strftime("%Y-%m-%d %H:%M:%S"))
        table.add_row("Message Count", str(session.message_count))

        if session.last_activity_at:
            table.add_row(
                "Last Activity", session.last_activity_at.strftime("%Y-%m-%d %H:%M:%S")
            )
        else:
            table.add_row("Last Activity", "[dim]No activity[/dim]")

        # Session context info
        if hasattr(session, "context") and session.context:
            context_keys = [k for k in session.context.keys()]
            table.add_row("Context Keys", f"{len(context_keys)} keys")

        console.print(table)

        if detailed:
            # TODO: Show detailed metrics like token usage, tool invocations, etc.
            rprint("\n[yellow]Detailed metrics coming soon...[/yellow]")

    asyncio.run(_status())


@app.command()
def approve(
    approval_id: str = typer.Argument(..., help="Tool approval ID"),
    org_name: str = typer.Argument(..., help="Organization name"),
    approved_by: str = typer.Option(
        "cli_user", "--user", help="User approving the tool"
    ),
    reason: str | None = typer.Option(None, "--reason", help="Approval reason"),
    auto_confirm: bool = typer.Option(
        False, "--yes", "-y", help="Skip confirmation prompt"
    ),
):
    """Approve a pending tool invocation."""

    async def _approve():
        # Find organization
        async with async_session_factory() as db:
            stmt = select(Organization).where(Organization.name == org_name)
            org = await db.scalar(stmt)

            if not org:
                rprint(f"[red]Organization '{org_name}' not found[/red]")
                return

        try:
            approval_uuid = UUID(approval_id)
        except ValueError:
            rprint(f"[red]Invalid approval ID format: {approval_id}[/red]")
            return

        service = ToolApprovalService()

        # Get approval details
        approval = await service.get_approval(approval_uuid, org.org_id)
        if not approval:
            rprint(f"[red]Approval not found or access denied: {approval_id}[/red]")
            return

        if approval.status != ApprovalStatus.PENDING:
            rprint(
                f"[yellow]Approval is not pending (status: {approval.status.value})[/yellow]"
            )
            return

        # Show approval details
        details_table = Table(title="Tool Approval Details")
        details_table.add_column("Property", style="cyan")
        details_table.add_column("Value", style="white")

        details_table.add_row("Approval ID", str(approval.id))
        details_table.add_row(
            "Tool Name",
            (
                approval.tool_invocation.tool_name
                if approval.tool_invocation
                else "Unknown"
            ),
        )
        details_table.add_row("Requested By", approval.requested_by)
        details_table.add_row(
            "Requested At", approval.requested_at.strftime("%Y-%m-%d %H:%M:%S")
        )
        details_table.add_row("Risk Level", approval.risk_level)

        if approval.justification:
            details_table.add_row("Justification", approval.justification)

        if approval.expires_at:
            details_table.add_row(
                "Expires At", approval.expires_at.strftime("%Y-%m-%d %H:%M:%S")
            )

        console.print(details_table)

        # Show tool input if available
        if approval.tool_invocation and approval.tool_invocation.input:
            rprint("\n[bold]Tool Input:[/bold]")
            syntax = Syntax(
                json.dumps(approval.tool_invocation.input, indent=2),
                "json",
                theme="monokai",
                line_numbers=True,
            )
            console.print(syntax)

        # Confirmation
        if not auto_confirm:
            if not Confirm.ask("\n[yellow]Approve this tool invocation?[/yellow]"):
                rprint("[blue]Approval cancelled[/blue]")
                return

        # Get reason if not provided
        approval_reason = (
            reason
            if reason
            else Prompt.ask("Approval reason", default="Approved by CLI user")
        )

        # Approve the tool
        try:
            updated_approval = await service.approve_tool_invocation(
                approval_id=approval_uuid,
                org_id=org.org_id,
                approved_by=approved_by,
                decision_reason=approval_reason,
            )

            if updated_approval:
                rprint("[green]✅ Tool invocation approved successfully[/green]")
                rprint(f"[dim]Approved by: {approved_by}[/dim]")
                rprint(f"[dim]Reason: {approval_reason}[/dim]")
            else:
                rprint("[red]Failed to approve tool invocation[/red]")

        except Exception as e:
            rprint(f"[red]Error approving tool: {e}[/red]")

    asyncio.run(_approve())


@app.command()
def reject(
    approval_id: str = typer.Argument(..., help="Tool approval ID"),
    org_name: str = typer.Argument(..., help="Organization name"),
    rejected_by: str = typer.Option(
        "cli_user", "--user", help="User rejecting the tool"
    ),
    reason: str = typer.Option(..., "--reason", help="Rejection reason (required)"),
    auto_confirm: bool = typer.Option(
        False, "--yes", "-y", help="Skip confirmation prompt"
    ),
):
    """Reject a pending tool invocation."""

    async def _reject():
        # Find organization
        async with async_session_factory() as db:
            stmt = select(Organization).where(Organization.name == org_name)
            org = await db.scalar(stmt)

            if not org:
                rprint(f"[red]Organization '{org_name}' not found[/red]")
                return

        try:
            approval_uuid = UUID(approval_id)
        except ValueError:
            rprint(f"[red]Invalid approval ID format: {approval_id}[/red]")
            return

        service = ToolApprovalService()

        # Get approval details
        approval = await service.get_approval(approval_uuid, org.org_id)
        if not approval:
            rprint(f"[red]Approval not found or access denied: {approval_id}[/red]")
            return

        if approval.status != ApprovalStatus.PENDING:
            rprint(
                f"[yellow]Approval is not pending (status: {approval.status.value})[/yellow]"
            )
            return

        # Show basic info
        rprint(
            f"[yellow]Rejecting tool: {approval.tool_invocation.tool_name if approval.tool_invocation else 'Unknown'}[/yellow]"
        )
        rprint(f"[dim]Requested by: {approval.requested_by}[/dim]")
        rprint(f"[dim]Reason: {reason}[/dim]")

        # Confirmation
        if not auto_confirm:
            if not Confirm.ask("\n[red]Reject this tool invocation?[/red]"):
                rprint("[blue]Rejection cancelled[/blue]")
                return

        # Reject the tool
        try:
            updated_approval = await service.reject_tool_invocation(
                approval_id=approval_uuid,
                org_id=org.org_id,
                rejected_by=rejected_by,
                decision_reason=reason,
            )

            if updated_approval:
                rprint("[red]❌ Tool invocation rejected[/red]")
                rprint(f"[dim]Rejected by: {rejected_by}[/dim]")
                rprint(f"[dim]Reason: {reason}[/dim]")
            else:
                rprint("[red]Failed to reject tool invocation[/red]")

        except Exception as e:
            rprint(f"[red]Error rejecting tool: {e}[/red]")

    asyncio.run(_reject())


@app.command()
def pending(
    org_name: str = typer.Argument(..., help="Organization name"),
    limit: int = typer.Option(
        20, "--limit", "-l", help="Maximum number of approvals to show"
    ),
    offset: int = typer.Option(0, "--offset", help="Offset for pagination"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List pending tool approvals."""

    async def _pending():
        # Find organization
        async with async_session_factory() as db:
            stmt = select(Organization).where(Organization.name == org_name)
            org = await db.scalar(stmt)

            if not org:
                rprint(f"[red]Organization '{org_name}' not found[/red]")
                return

        service = ToolApprovalService()

        try:
            approvals, total_count = await service.list_pending_approvals(
                org_id=org.org_id, limit=limit, offset=offset
            )

            if json_output:
                approval_data = [
                    {
                        "id": str(approval.id),
                        "tool_name": (
                            approval.tool_invocation.tool_name
                            if approval.tool_invocation
                            else None
                        ),
                        "requested_by": approval.requested_by,
                        "requested_at": approval.requested_at.isoformat(),
                        "risk_level": approval.risk_level,
                        "justification": approval.justification,
                        "expires_at": (
                            approval.expires_at.isoformat()
                            if approval.expires_at
                            else None
                        ),
                    }
                    for approval in approvals
                ]
                print(
                    json.dumps(
                        {"approvals": approval_data, "total": total_count}, indent=2
                    )
                )
                return

            if not approvals:
                rprint(f"[green]✅ No pending tool approvals for '{org_name}'[/green]")
                return

            # Display as table
            table = Table(
                title=f"Pending Tool Approvals for '{org_name}' ({total_count} total)"
            )
            table.add_column("Approval ID", style="cyan", width=36)
            table.add_column("Tool", style="blue")
            table.add_column("Requested By", style="green")
            table.add_column("Risk Level", style="yellow")
            table.add_column("Requested", style="dim")
            table.add_column("Expires", style="red")
            table.add_column("Justification", style="white")

            for approval in approvals:
                expires_str = (
                    approval.expires_at.strftime("%m-%d %H:%M")
                    if approval.expires_at
                    else "No expiry"
                )

                # Check if expired
                if approval.expires_at and approval.expires_at < datetime.now(
                    UTC
                ):
                    expires_str = "[red]EXPIRED[/red]"

                justification = approval.justification or "[dim]No justification[/dim]"
                if len(justification) > 40:
                    justification = justification[:37] + "..."

                table.add_row(
                    str(approval.id)[:36],
                    (
                        approval.tool_invocation.tool_name
                        if approval.tool_invocation
                        else "Unknown"
                    ),
                    approval.requested_by,
                    (approval.risk_level or "unknown").upper(),
                    approval.requested_at.strftime("%m-%d %H:%M"),
                    expires_str,
                    justification,
                )

            console.print(table)

            # Show actions
            if approvals:
                rprint("\n[blue]💡 Actions:[/blue]")
                rprint(
                    f"  Approve: [cyan]cerebro agents approve <approval-id> {org_name}[/cyan]"
                )
                rprint(
                    f'  Reject:  [cyan]cerebro agents reject <approval-id> {org_name} --reason "<reason>"[/cyan]'
                )

            # Show pagination info
            if total_count > limit:
                start = offset + 1
                end = min(offset + limit, total_count)
                rprint(
                    f"\n[dim]Showing {start}-{end} of {total_count} pending approvals[/dim]"
                )

                if end < total_count:
                    rprint(
                        f"[blue]Show more: cerebro agents pending {org_name} --offset {offset + limit}[/blue]"
                    )

        except Exception as e:
            rprint(f"[red]Error listing pending approvals: {e}[/red]")

    asyncio.run(_pending())


@app.command()
def analytics(
    org_name: str = typer.Argument(..., help="Organization name"),
    days: int = typer.Option(30, "--days", "-d", help="Number of days to analyze"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show agent usage analytics for an organization."""

    async def _analytics():
        # Find organization
        async with async_session_factory() as db:
            stmt = select(Organization).where(Organization.name == org_name)
            org = await db.scalar(stmt)

            if not org:
                rprint(f"[red]Organization '{org_name}' not found[/red]")
                return

        service = AgentAnalyticsService()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("Analyzing agent usage...", total=None)

            try:
                analytics = await service.get_org_agent_usage(
                    org_id=org.org_id, days=days
                )

                progress.update(task, completed=1)

                if json_output:
                    print(json.dumps(analytics, indent=2, default=str))
                    return

                # Display analytics
                rprint(
                    f"[bold blue]Agent Analytics for '{org_name}' (Last {days} days)[/bold blue]\n"
                )

                # Agent type usage
                if analytics.get("agent_type_stats"):
                    agent_table = Table(title="Agent Type Usage")
                    agent_table.add_column("Agent Type", style="cyan")
                    agent_table.add_column("Sessions", style="green", justify="right")
                    agent_table.add_column(
                        "Unique Users", style="blue", justify="right"
                    )

                    for stats in analytics["agent_type_stats"]:
                        agent_table.add_row(
                            stats["agent_type"].replace("_", " ").title(),
                            str(stats["session_count"]),
                            str(stats["unique_users"]),
                        )

                    console.print(agent_table)
                    rprint()

                # Tool usage
                if analytics.get("tool_stats"):
                    tool_table = Table(title="Tool Usage")
                    tool_table.add_column("Tool", style="cyan")
                    tool_table.add_column("Status", style="blue")
                    tool_table.add_column("Invocations", style="green", justify="right")

                    for stats in analytics["tool_stats"]:
                        status_style = (
                            "green" if stats["status"] == "completed" else "red"
                        )

                        tool_table.add_row(
                            stats["tool_name"],
                            Text(stats["status"].upper(), style=status_style),
                            str(stats["invocation_count"]),
                        )

                    console.print(tool_table)
                    rprint()

                # Token usage summary
                if analytics.get("token_stats"):
                    token_panel = Panel(
                        f"[bold]Total Tokens:[/bold] {analytics['token_stats'].get('total_tokens', 0):,}\n"
                        f"[bold]Input Tokens:[/bold] {analytics['token_stats'].get('input_tokens', 0):,}\n"
                        f"[bold]Output Tokens:[/bold] {analytics['token_stats'].get('output_tokens', 0):,}\n"
                        f"[bold]Average per Session:[/bold] {analytics['token_stats'].get('avg_tokens_per_session', 0):.1f}",
                        title="Token Usage",
                        border_style="yellow",
                    )
                    console.print(token_panel)
                    rprint()

                # Summary insights
                if analytics.get("insights"):
                    insights_panel = Panel(
                        "\n".join(f"• {insight}" for insight in analytics["insights"]),
                        title="📊 Insights",
                        border_style="green",
                    )
                    console.print(insights_panel)

            except Exception as e:
                rprint(f"[red]Error generating analytics: {e}[/red]")

    asyncio.run(_analytics())


@app.command()
def delete(
    session_id: str = typer.Argument(..., help="Agent session ID"),
    org_name: str = typer.Argument(..., help="Organization name"),
    deleted_by: str = typer.Option(
        "cli_user", "--user", help="User deleting the session"
    ),
    auto_confirm: bool = typer.Option(
        False, "--yes", "-y", help="Skip confirmation prompt"
    ),
):
    """Delete an agent session."""

    async def _delete():
        # Find organization
        async with async_session_factory() as db:
            stmt = select(Organization).where(Organization.name == org_name)
            org = await db.scalar(stmt)

            if not org:
                rprint(f"[red]Organization '{org_name}' not found[/red]")
                return

        try:
            session_uuid = UUID(session_id)
        except ValueError:
            rprint(f"[red]Invalid session ID format: {session_id}[/red]")
            return

        service = AgentSessionService()

        # Verify session exists
        session = await service.get_session(session_uuid, org.org_id)
        if not session:
            rprint(f"[red]Session not found or access denied: {session_id}[/red]")
            return

        # Show session info
        rprint(f"[yellow]Deleting session:[/yellow] {session_id[:12]}...")
        rprint(f"[dim]Agent Type: {session.agent_type.value}[/dim]")
        rprint(
            f"[dim]Created: {session.created_at.strftime('%Y-%m-%d %H:%M:%S')}[/dim]"
        )
        rprint(f"[dim]Messages: {session.message_count}[/dim]")

        # Confirmation
        if not auto_confirm:
            if not Confirm.ask("\n[red]Permanently delete this session?[/red]"):
                rprint("[blue]Deletion cancelled[/blue]")
                return

        # Delete session
        try:
            success = await service.delete_session(
                session_id=session_uuid, org_id=org.org_id, deleted_by=deleted_by
            )

            if success:
                rprint("[green]✅ Session deleted successfully[/green]")
            else:
                rprint("[red]Failed to delete session[/red]")

        except Exception as e:
            rprint(f"[red]Error deleting session: {e}[/red]")

    asyncio.run(_delete())


if __name__ == "__main__":
    app()
