"""
Cerebro Claude Runtime

Integrates Claude Code SDK with Cerebro's security architecture, providing
streaming agent capabilities with tool calling, audit logging, and safety guardrails.
"""

import asyncio
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional
from uuid import UUID

import structlog
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions
from claude_agent_sdk.types import (
    AssistantMessage,
    TextBlock,
    ToolUseBlock,
    ResultMessage,
    SystemMessage,
)

from sqlalchemy import func, select

from cerebro.core.database import get_db
from cerebro.agents.models import (
    AgentSession,
    AgentMessage,
    MessageRole,
    AgentType,
    ToolInvocation,
)
from cerebro.agents.tools import tool_registry, ToolExecutor, AgentContext
from cerebro.agents.mcp_bridge import create_cerebro_mcp_server

logger = structlog.get_logger(__name__)


class CerebroClaudeRuntime:
    """
    Claude runtime for Cerebro security agents.
    
    Provides streaming conversation capabilities with security-focused tools,
    audit logging, and integration with Cerebro's append-only architecture.
    """
    
    def __init__(
        self,
        model: str = "claude-3-5-sonnet-20241022",
        max_tokens: int = 8192,
        temperature: float = 0.1,
    ):
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.tool_executor = ToolExecutor()
    
    async def create_session(
        self,
        org_id: UUID,
        agent_type: AgentType,
        created_by: str,
        context: Dict[str, Any],
        title: Optional[str] = None,
    ) -> AgentSession:
        """Create a new agent session with automatic context injection."""
        from cerebro.core.database import async_session_factory

        # AUTO-LOAD CONTEXT: Load org and system context before creating session
        try:
            from cerebro.agents.tools.org_context import GetOrgContextTool
            from cerebro.agents.tools.system_context import GetSystemContextTool

            # Build temporary context for tool execution
            temp_context = AgentContext(
                session_id=UUID('00000000-0000-0000-0000-000000000000'),  # Temp ID
                org_id=org_id,
                user_id=created_by,
                agent_type=agent_type.value,
            )

            # Load organizational context
            org_context_tool = GetOrgContextTool()
            org_context_result = await org_context_tool.execute(
                context=temp_context,
                include_repositories=True,
                include_providers=True,
                include_statistics=True,
                include_tools=True,
            )

            # Load system context
            system_context_tool = GetSystemContextTool()
            system_context_result = await system_context_tool.execute(
                context=temp_context,
                include_database=True,
                include_environment=True,
                include_providers=True,
                include_health=True,
            )

            # Inject loaded context into session context
            if org_context_result.success and system_context_result.success:
                context['_auto_loaded_org_context'] = org_context_result.data
                context['_auto_loaded_system_context'] = system_context_result.data

                logger.info(
                    "Auto-loaded context for agent session",
                    org_id=org_id,
                    org_name=org_context_result.data.get('org_name'),
                    providers_count=len(org_context_result.data.get('providers_connected', [])),
                    tools_count=org_context_result.data.get('agent_tools_count'),
                )
            else:
                logger.warning(
                    "Failed to auto-load context for agent session",
                    org_id=org_id,
                    org_context_success=org_context_result.success,
                    system_context_success=system_context_result.success,
                )

        except Exception as e:
            logger.warning(
                "Context auto-loading failed, continuing without",
                org_id=org_id,
                error=str(e),
            )

        async with async_session_factory() as db_session:
            session = AgentSession(
                org_id=org_id,
                agent_type=agent_type,
                created_by=created_by,
                title=title,
                context=context,
            )
            db_session.add(session)
            await db_session.commit()
            await db_session.refresh(session)

            logger.info(
                "Created agent session with auto-context",
                session_id=session.id,
                agent_type=agent_type.value,
                org_id=org_id,
                has_org_context=('_auto_loaded_org_context' in context),
                has_system_context=('_auto_loaded_system_context' in context),
            )

            return session
    
    async def get_session(self, session_id: UUID) -> Optional[AgentSession]:
        """Get an existing agent session."""
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as db_session:
            return await db_session.get(AgentSession, session_id)
    
    async def send_message(
        self,
        session: AgentSession,
        message: str,
        user_id: str,
        stream: bool = False,
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Send a message to the agent and stream the response.

        The SDK now handles tool calling automatically via MCP servers.

        Yields dictionaries with:
        - type: "text" | "tool_use" | "system" | "error" | "complete"
        - content: message content or tool data
        - metadata: additional information
        """

        # Store user message
        await self._store_message(session, MessageRole.USER, {"text": message})

        # Build agent context
        agent_context = await self._build_agent_context(session, user_id)

        try:
            # Get available tools from registry based on permission level
            available_tools = tool_registry.list_tools(agent_context.permission_level)

            # Create MCP server from Cerebro tools
            mcp_server = create_cerebro_mcp_server(
                tools=available_tools,
                context=agent_context,
                executor=self.tool_executor,
                server_name="cerebro",
                server_version="1.0.0",
            )

            # Build allowed tools list (mcp__servername__toolname format)
            allowed_tools = [f"mcp__cerebro__{tool.name}" for tool in available_tools]

            # Configure Claude options with MCP server and session context
            options = ClaudeAgentOptions(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                system_prompt=self._get_system_prompt(session.agent_type, session=session),
                mcp_servers={"cerebro": mcp_server},
                allowed_tools=allowed_tools,
            )

            # Track response data
            assistant_content = []
            tool_calls_count = 0
            total_input_tokens = 0
            total_output_tokens = 0

            # Create Claude client and send query
            async with ClaudeSDKClient(options=options) as client:
                await client.connect()

                # Send the user message
                await client.query(message, session_id=str(session.id))

                # Process streaming responses
                async for response_msg in client.receive_messages():

                    # Handle assistant messages
                    if isinstance(response_msg, AssistantMessage):
                        for block in response_msg.content:

                            if isinstance(block, TextBlock):
                                # Stream text content to user
                                if stream:
                                    yield {
                                        "type": "text",
                                        "content": block.text,
                                        "metadata": {"streaming": True}
                                    }
                                assistant_content.append({"type": "text", "text": block.text})

                            elif isinstance(block, ToolUseBlock):
                                # Tool use - SDK handles execution automatically
                                tool_name = block.name
                                tool_input = block.input
                                tool_call_id = block.id

                                logger.info(
                                    "Tool invoked by agent",
                                    tool_name=tool_name,
                                    session_id=session.id,
                                    tool_call_id=tool_call_id,
                                )

                                tool_calls_count += 1

                                if stream:
                                    yield {
                                        "type": "tool_use",
                                        "content": {
                                            "tool_name": tool_name,
                                            "input": tool_input,
                                        },
                                        "metadata": {"tool_call_id": tool_call_id}
                                    }

                                assistant_content.append({
                                    "type": "tool_use",
                                    "tool_call_id": tool_call_id,
                                    "tool_name": tool_name,
                                    "input": tool_input,
                                })

                    # Handle system messages
                    elif isinstance(response_msg, SystemMessage):
                        logger.info(
                            "System message received",
                            subtype=response_msg.subtype,
                            session_id=session.id,
                        )

                        if stream:
                            yield {
                                "type": "system",
                                "content": {
                                    "subtype": response_msg.subtype,
                                    "data": response_msg.data,
                                },
                                "metadata": {}
                            }

                    # Handle result messages (token usage, completion)
                    elif isinstance(response_msg, ResultMessage):
                        # Extract token usage
                        if hasattr(response_msg, 'usage') and response_msg.usage:
                            usage = response_msg.usage
                            total_input_tokens = getattr(usage, 'input_tokens', 0)
                            total_output_tokens = getattr(usage, 'output_tokens', 0)

                        logger.info(
                            "Result message received",
                            session_id=session.id,
                            input_tokens=total_input_tokens,
                            output_tokens=total_output_tokens,
                        )

                # Store assistant response with all content
                await self._store_message(
                    session,
                    MessageRole.ASSISTANT,
                    {
                        "content": assistant_content,
                        "tool_calls": tool_calls_count,
                        "token_usage": {
                            "input_tokens": total_input_tokens,
                            "output_tokens": total_output_tokens,
                            "total_tokens": total_input_tokens + total_output_tokens,
                        }
                    },
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                )

                # Final completion message
                if stream:
                    yield {
                        "type": "complete",
                        "content": {
                            "message_stored": True,
                            "tool_calls_executed": tool_calls_count,
                        },
                        "metadata": {"session_id": str(session.id)}
                    }

        except Exception as e:
            logger.exception("Agent message processing failed", session_id=session.id, error=str(e))

            # Store error message
            await self._store_message(
                session,
                MessageRole.ASSISTANT,
                {
                    "error": str(e),
                    "type": "system_error",
                }
            )

            yield {
                "type": "error",
                "content": {
                    "message": "Agent processing failed",
                    "error": str(e),
                },
                "metadata": {"session_id": str(session.id)}
            }
    
    async def _build_agent_context(
        self,
        session: AgentSession,
        user_id: str,
    ) -> AgentContext:
        """Build agent context for tool execution."""
        
        # Extract context information
        finding_ids = [
            UUID(fid) for fid in session.context.get("finding_ids", [])
        ]
        incident_id = None
        if session.context.get("incident_id"):
            incident_id = UUID(session.context["incident_id"])
        
        provider_scope = session.context.get("provider_scope", [])
        
        return AgentContext(
            session_id=session.id,
            org_id=session.org_id,
            user_id=user_id,
            agent_type=session.agent_type.value,
            provider_scope=provider_scope,
            finding_ids=finding_ids,
            incident_id=incident_id,
            cel_context={
                "agent_type": session.agent_type.value,
                "context": session.context,
            },
        )

    async def _store_message(
        self,
        session: AgentSession,
        role: MessageRole,
        content: Dict[str, Any],
        input_tokens: Optional[int] = None,
        output_tokens: Optional[int] = None,
    ) -> None:
        """Store message in database with append-only pattern and audit event."""
        from cerebro.core.database import async_session_factory

        async with async_session_factory() as db_session:
            # Store agent message
            message = AgentMessage(
                session_id=session.id,
                role=role,
                content=content,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )
            db_session.add(message)
            await db_session.commit()
            await db_session.refresh(message)

            # Create audit event - NOTE: AuditEvent schema requires account_id not org_id
            # For now we skip audit events as the schema doesn't match Cerebro's org-centric model
            # TODO: Refactor AuditEvent to support org-level events or create AgentAuditEvent table
            logger.info(
                "Agent message stored",
                session_id=session.id,
                message_id=message.id,
                role=role.value,
                org_id=session.org_id,
                content_length=len(str(content)),
                tool_calls=content.get("tool_calls", 0) if isinstance(content, dict) else 0,
            )
    
    def _get_system_prompt(self, agent_type: AgentType, session: Optional[AgentSession] = None) -> str:
        """Get system prompt for specific agent type with auto-loaded context."""

        base_prompt = """You are a specialized security agent within the Cerebro security system of record.
You have access to powerful tools for analyzing security findings, investigating incidents, and providing
actionable recommendations.

MULTI-STEP PLANNING:
For complex tasks, break them down into clear steps and execute them sequentially:

Example 1 - "Conduct full AWS security audit":
Step 1: Use get_org_context to identify AWS accounts
Step 2: Use findings_list to get all AWS findings
Step 3: Use test_compliance_control for CIS AWS benchmarks
Step 4: Use simulate_attack_path to analyze lateral movement risks
Step 5: Use hunt_identity_anomalies for behavioral threats
Step 6: Synthesize comprehensive report with prioritized recommendations

Example 2 - "Investigate suspicious user activity":
Step 1: Use nl_query to find user's recent activity
Step 2: Use hunt_identity_anomalies to check for anomalies
Step 3: Use forensic_replay to see historical permissions
Step 4: Use calculate_blast_radius to assess impact
Step 5: Build incident timeline with evidence
Step 6: Recommend containment actions

Example 3 - "Prepare for SOC2 audit":
Step 1: Use get_org_context to understand scope
Step 2: Use test_compliance_control for all SOC2 controls
Step 3: Use findings_list filtered by compliance frameworks
Step 4: Use build_evidence_bundle to create audit package
Step 5: Generate executive summary of compliance status

WHEN TO USE MULTI-STEP PLANNING:
- Comprehensive audits or assessments
- Complex investigations requiring multiple data sources
- Compliance preparation requiring evidence collection
- Risk analysis needing multiple perspectives
- Any task with "full", "comprehensive", "complete" in the request

SAFETY GUIDELINES:
- Always default to dry-run mode for any potentially destructive actions
- Request human approval for any changes to production systems
- Never expose sensitive credentials or secrets in responses
- All your actions are audited in append-only logs
- Provide clear, actionable recommendations with compliance mappings

RESPONSE STYLE:
- Be concise and technical - assume security expertise
- Cite specific evidence from findings and audit trails
- Map security issues to CIS, NIST, or CWE frameworks when relevant
- Prioritize actions by risk and business impact
- Always provide clear next steps
- For multi-step tasks, announce your plan before starting execution"""
        
        # AUTO-INJECTED CONTEXT: Add pre-loaded organizational and system context
        context_section = ""
        if session and session.context:
            org_context = session.context.get('_auto_loaded_org_context')
            system_context = session.context.get('_auto_loaded_system_context')

            if org_context or system_context:
                context_section = "\n\n=== YOUR ENVIRONMENT (YOU ALREADY KNOW THIS) ==="

                if org_context:
                    org_name = org_context.get('org_name', 'Unknown Organization')
                    context_section += f"\n\nOrganization: {org_name}"

                    # Repository info
                    repos = org_context.get('repositories', [])
                    if repos:
                        context_section += f"\n\nRepositories ({len(repos)}):"
                        for repo in repos[:5]:  # Show first 5
                            context_section += f"\n  - {repo.get('name')}: {repo.get('framework', 'unknown')} ({repo.get('type', 'unknown')})"

                    # Provider info
                    providers = org_context.get('providers_connected', [])
                    if providers:
                        context_section += f"\n\nConnected Providers ({len(providers)}):"
                        for prov in providers:
                            context_section += f"\n  - {prov.get('provider', 'unknown').upper()}: {prov.get('resource_count', 0)} resources"

                    # Statistics
                    stats = org_context.get('statistics', {})
                    if stats:
                        context_section += "\n\nSecurity Statistics:"
                        context_section += f"\n  - Total Resources: {stats.get('total_resources', 0)}"
                        context_section += f"\n  - Total Principals: {stats.get('total_principals', 0)}"
                        context_section += f"\n  - Open Findings: {stats.get('open_findings', 0)}"

                    # Tools
                    tools_count = org_context.get('agent_tools_count', 0)
                    if tools_count > 0:
                        context_section += f"\n\nAvailable Tools: {tools_count} specialized security tools"

                if system_context:
                    # Database info
                    db_info = system_context.get('database', {})
                    if db_info.get('connected'):
                        context_section += "\n\nDatabase: PostgreSQL"
                        if db_info.get('pg_version'):
                            context_section += f" {db_info['pg_version']}"

                    # Environment info
                    env_info = system_context.get('environment', {})
                    if env_info:
                        deployment = env_info.get('deployment_type', 'unknown')
                        environment = env_info.get('environment', 'unknown')
                        context_section += f"\n\nDeployment: {deployment} ({environment})"

                    # Provider health
                    provider_health = system_context.get('provider_health', [])
                    if provider_health:
                        degraded = [p for p in provider_health if p.get('status') != 'healthy']
                        if degraded:
                            context_section += "\n\n⚠️ Provider Health Alerts:"
                            for p in degraded:
                                context_section += f"\n  - {p.get('provider', 'unknown').upper()}: {p.get('status', 'unknown')}"

                context_section += "\n\nIMPORTANT: You ALREADY KNOW this information. Don't ask the user about it."
                context_section += "\nUse this context to provide specific, informed responses without needing to ask for basic setup details."
                context_section += "\n=== END ENVIRONMENT CONTEXT ===\n"

        agent_prompts = {
            AgentType.SECURITY_ANALYST: """
ROLE: Security Analyst
FOCUS: Triage findings, assess risk, cluster similar issues, recommend remediation
EXPERTISE: Vulnerability assessment, risk scoring, compliance mapping, threat analysis
""",
            AgentType.INCIDENT_RESPONDER: """
ROLE: Incident Response Specialist
FOCUS: Build timelines, coordinate containment, collect evidence, manage incidents
EXPERTISE: Digital forensics, incident coordination, timeline analysis, containment strategies
""",
            AgentType.IDENTITY_ADVISOR: """
ROLE: Identity & Access Management Advisor
FOCUS: Analyze IAM configurations, privilege escalation, access reviews, identity stitching
EXPERTISE: Identity governance, privilege management, access controls, identity correlation
""",
            AgentType.COMPLIANCE_ADVISOR: """
ROLE: Compliance & Risk Advisor
FOCUS: Map findings to frameworks, generate compliance reports, track remediation
EXPERTISE: CIS Controls, NIST Cybersecurity Framework, SOC 2, compliance management
""",
            AgentType.ATTACK_PATH_ANALYST: """
ROLE: Attack Path & Threat Analyst
FOCUS: Model attack paths, identify choke points, recommend defensive measures
EXPERTISE: Attack path modeling, threat modeling, network analysis, defensive architecture
"""
        }

        agent_specific = agent_prompts.get(agent_type, "")

        return f"{base_prompt}{context_section}\n\n{agent_specific}"
    
    async def get_session_messages(
        self,
        session_id: UUID,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Get messages from a session."""
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as db_session:
            stmt = (
                select(
                    AgentMessage.id,
                    AgentMessage.role,
                    AgentMessage.content,
                    AgentMessage.created_at,
                    AgentMessage.input_tokens,
                    AgentMessage.output_tokens,
                )
                .where(AgentMessage.session_id == session_id)
                .order_by(AgentMessage.created_at.desc())
                .limit(limit)
                .offset(offset)
            )

            result = await db_session.execute(stmt)
            rows = result.all()

            return [
                {
                    "id": str(row.id),
                    "role": row.role,
                    "content": row.content,
                    "created_at": row.created_at.isoformat(),
                    "input_tokens": row.input_tokens,
                    "output_tokens": row.output_tokens,
                }
                for row in rows
            ]
    
    async def get_session_metrics(self, session_id: UUID) -> Dict[str, Any]:
        """Get metrics for a session."""
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as db_session:
            # Message counts and token usage
            message_stats_stmt = (
                select(
                    AgentMessage.role.label("role"),
                    func.count().label("count"),
                    func.sum(func.coalesce(AgentMessage.input_tokens, 0)).label("total_input_tokens"),
                    func.sum(func.coalesce(AgentMessage.output_tokens, 0)).label("total_output_tokens"),
                )
                .where(AgentMessage.session_id == session_id)
                .group_by(AgentMessage.role)
            )
            message_stats = (
                await db_session.execute(message_stats_stmt)
            ).mappings().all()
            
            # Tool invocation stats
            tool_stats_stmt = (
                select(
                    ToolInvocation.tool_name.label("tool_name"),
                    ToolInvocation.status.label("status"),
                    func.count().label("count"),
                )
                .where(ToolInvocation.session_id == session_id)
                .group_by(ToolInvocation.tool_name, ToolInvocation.status)
            )
            tool_stats = (
                await db_session.execute(tool_stats_stmt)
            ).mappings().all()
            
            return {
                "session_id": str(session_id),
                "message_stats": [dict(row) for row in message_stats],
                "tool_stats": [dict(row) for row in tool_stats],
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }
