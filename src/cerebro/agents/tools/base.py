"""
Base classes and infrastructure for Cerebro agent tools.

This module provides the foundation for all agent tools, including:
- Tool interface and registry
- CEL policy enforcement
- Audit logging and context management
- Safety guardrails and approval workflows
"""

import asyncio
import os
import time
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from functools import wraps
from typing import Any, TypeVar
from uuid import UUID

import anyio
import structlog
from pydantic import BaseModel

from cerebro.agents.analytics_service import AgentAnalyticsService
from cerebro.agents.metrics import record_tool_metrics
from cerebro.agents.models import (
    AgentSession,
    ApprovalStatus,
    ToolApproval,
    ToolInvocation,
    ToolInvocationStatus,
)
from cerebro.agents.review_service import AgentReviewService
from cerebro.agents.tool_stats import performance_tracker
from cerebro.rules.engine import RuleEngine

logger = structlog.get_logger(__name__)

T = TypeVar("T", bound="Tool")


class ToolPermissionLevel(str, Enum):
    """Permission levels for tool execution."""

    READ_ONLY = "read_only"
    WRITE_SAFE = "write_safe"
    WRITE_DESTRUCTIVE = "write_destructive"
    ADMIN = "admin"


class ToolResult(BaseModel):
    """Standardized tool execution result."""

    success: bool
    data: dict[str, Any] | None = None
    error: str | None = None
    warnings: list[str] | None = None
    metadata: dict[str, Any] | None = None

    # Dry run preview for destructive actions
    dry_run: bool = False
    preview: dict[str, Any] | None = None

    # Approval workflow
    requires_approval: bool = False
    approval_id: UUID | None = None


@dataclass
class AgentContext:
    """
    Context provided to tools during execution.

    Contains information about the agent session, user, organization,
    and security scope for safe tool execution.
    """

    # Session info
    session_id: UUID
    org_id: UUID
    user_id: str
    agent_type: str

    # Security context
    provider_scope: list[str] | None = None  # aws, github, gcp, azure
    finding_ids: list[UUID] | None = None
    incident_id: UUID | None = None
    memory_entries: list[dict[str, Any]] | None = None

    # Permissions and policies
    permission_level: ToolPermissionLevel = ToolPermissionLevel.READ_ONLY
    cel_context: dict[str, Any] | None = None

    # Execution controls
    dry_run: bool = True  # Default to dry-run for safety
    roles: list[str] | None = None  # User roles for RBAC

    def __post_init__(self):
        if self.provider_scope is None:
            self.provider_scope = []
        if self.finding_ids is None:
            self.finding_ids = []
        if self.cel_context is None:
            self.cel_context = {}
        if self.roles is None:
            self.roles = []
        if self.memory_entries is None:
            self.memory_entries = []

    def build_cel_context(self, inputs: dict[str, Any] | None = None) -> dict[str, Any]:
        """Build CEL evaluation context with session and input data."""
        context = {
            "org_id": str(self.org_id),
            "user_id": self.user_id,
            "session_id": str(self.session_id),
            "agent_type": self.agent_type,
            "permission_level": self.permission_level.value,
            "provider_scope": self.provider_scope,
            "finding_count": len(self.finding_ids) if self.finding_ids else 0,
            "has_incident": self.incident_id is not None,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        # Add custom context
        if self.cel_context:
            context.update(self.cel_context)

        # Add tool inputs if provided
        if inputs:
            context["inputs"] = inputs  # type: ignore[assignment]

        return context


class Tool(ABC):
    """
    Abstract base class for all Cerebro agent tools.

    Tools provide specific capabilities to agents while enforcing security
    policies, audit logging, and approval workflows.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique tool name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable tool description."""
        pass

    @property
    @abstractmethod
    def input_schema(self) -> type[BaseModel]:
        """Pydantic model for tool input validation."""
        pass

    @property
    @abstractmethod
    def output_schema(self) -> type[BaseModel]:
        """Pydantic model for tool output validation."""
        pass

    @property
    def version(self) -> str:
        """Tool version for compatibility tracking."""
        return "1.0.0"

    @property
    def permission_level(self) -> ToolPermissionLevel:
        """Required permission level to execute this tool."""
        return ToolPermissionLevel.READ_ONLY

    @property
    def cel_policy_key(self) -> str | None:
        """CEL policy key for authorization checks."""
        return None

    @property
    def cel_expression(self) -> str | None:
        """Default CEL expression for this tool."""
        return None

    @property
    def requires_approval(self) -> bool:
        """Whether this tool requires human approval."""
        return self.permission_level in [
            ToolPermissionLevel.WRITE_DESTRUCTIVE,
            ToolPermissionLevel.ADMIN,
        ]

    @abstractmethod
    async def execute(
        self,
        inputs: BaseModel,
        context: AgentContext,
    ) -> ToolResult:
        """Execute the tool with given inputs and context."""
        pass

    async def validate_inputs(self, raw_inputs: dict[str, Any]) -> BaseModel:
        """Validate and parse tool inputs."""
        try:
            return self.input_schema(**raw_inputs)
        except Exception as e:
            raise ValueError(f"Invalid inputs for tool {self.name}: {e}") from e


    def to_schema(self) -> dict[str, Any]:
        """Convert tool to JSON schema for Claude integration."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema.model_json_schema(),
            "version": self.version,
            "permission_level": self.permission_level.value,
        }


class StructuredTool(Tool):
    """Helper base class for tools exposing structured input/output schemas.

    Legacy tools that previously accepted keyword arguments can inherit from this
    class and implement ``_run`` to avoid rewriting business logic. Subclasses
    should define the following class attributes:

    - ``tool_name``: unique tool identifier
    - ``tool_description``: human readable description
    - ``input_model`` / ``output_model``: pydantic schemas
    - ``tool_version`` (optional): defaults to ``1.0.0``
    - ``required_permission`` (optional): defaults to ``READ_ONLY``
    - ``tool_cel_policy_key`` / ``tool_cel_expression`` (optional)
    """

    tool_name: str
    tool_description: str
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    tool_version: str = "1.0.0"
    required_permission: ToolPermissionLevel = ToolPermissionLevel.READ_ONLY
    tool_cel_policy_key: str | None = None
    tool_cel_expression: str | None = None

    @property
    def name(self) -> str:
        return self.tool_name

    @property
    def description(self) -> str:
        return self.tool_description

    @property
    def input_schema(self) -> type[BaseModel]:
        return self.input_model

    @property
    def output_schema(self) -> type[BaseModel]:
        return self.output_model

    @property
    def version(self) -> str:
        return self.tool_version

    @property
    def permission_level(self) -> ToolPermissionLevel:
        return self.required_permission

    @property
    def cel_policy_key(self) -> str | None:
        return self.tool_cel_policy_key

    @property
    def cel_expression(self) -> str | None:
        return self.tool_cel_expression

    async def execute(
        self,
        inputs: BaseModel,
        context: AgentContext,
    ) -> ToolResult:
        """Adapt structured models into legacy keyword execution."""

        kwargs = inputs.model_dump()
        return await self._run(context=context, **kwargs)

    async def _run(self, context: AgentContext, **kwargs: Any) -> ToolResult:
        raise NotImplementedError


class ToolRegistry:
    """Registry for managing available agent tools."""

    def __init__(self):
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        """Register a new tool."""
        if tool.name in self._tools:
            logger.warning(
                "Tool already registered, overwriting",
                tool_name=tool.name,
            )
        self._tools[tool.name] = tool
        logger.info("Registered tool", tool_name=tool.name, version=tool.version)

    def get(self, name: str) -> Tool | None:
        """Get a tool by name."""
        return self._tools.get(name)

    def list_tools(
        self,
        permission_level: ToolPermissionLevel | None = None,
    ) -> list[Tool]:
        """List available tools, optionally filtered by permission level."""
        tools = list(self._tools.values())

        if permission_level is not None:
            # Filter by permission level hierarchy
            level_order = [
                ToolPermissionLevel.READ_ONLY,
                ToolPermissionLevel.WRITE_SAFE,
                ToolPermissionLevel.WRITE_DESTRUCTIVE,
                ToolPermissionLevel.ADMIN,
            ]
            max_level_idx = level_order.index(permission_level)
            allowed_levels = level_order[: max_level_idx + 1]

            tools = [t for t in tools if t.permission_level in allowed_levels]

        return tools

    def to_schema(
        self,
        permission_level: ToolPermissionLevel | None = None,
    ) -> list[dict[str, Any]]:
        """Convert tools to JSON schema for Claude integration."""
        tools = self.list_tools(permission_level)
        return [tool.to_schema() for tool in tools]


class ToolExecutor:
    """
    Executes tools with full security and audit infrastructure.

    Handles CEL policy enforcement, approval workflows, audit logging,
    and error handling for all tool invocations.
    """

    _rate_lock: asyncio.Lock
    _rate_buckets: dict[str, Any]

    def __init__(self, rule_engine: RuleEngine | None = None):
        self.rule_engine = rule_engine or RuleEngine()

        # Process-local rate limiter (best-effort guardrail).
        if not hasattr(self.__class__, "_rate_lock"):
            self.__class__._rate_lock = asyncio.Lock()
            self.__class__._rate_buckets = {}

    @staticmethod
    def _resolve_timeout_seconds(tool: Tool) -> float:
        override = os.getenv("AGENT_TOOL_TIMEOUT_SECONDS")
        if override:
            try:
                return float(override)
            except ValueError:
                return 60.0

        if tool.permission_level == ToolPermissionLevel.READ_ONLY:
            return float(os.getenv("AGENT_TOOL_TIMEOUT_SECONDS_READ_ONLY", "30"))
        if tool.permission_level == ToolPermissionLevel.WRITE_SAFE:
            return float(os.getenv("AGENT_TOOL_TIMEOUT_SECONDS_WRITE_SAFE", "60"))
        return float(os.getenv("AGENT_TOOL_TIMEOUT_SECONDS_WRITE_DESTRUCTIVE", "120"))

    @staticmethod
    def _resolve_rate_limit_per_minute() -> int:
        value = os.getenv("AGENT_TOOL_RATE_LIMIT_PER_MINUTE", "120")
        try:
            return max(0, int(value))
        except ValueError:
            return 120

    async def _enforce_rate_limit(self, context: AgentContext) -> bool:
        limit = self._resolve_rate_limit_per_minute()
        if limit <= 0:
            return True

        now = time.monotonic()
        window_seconds = 60.0
        bucket_key = str(context.session_id)

        async with self.__class__._rate_lock:
            bucket = self.__class__._rate_buckets.setdefault(bucket_key, deque())
            cutoff = now - window_seconds
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True

    async def execute_tool(
        self,
        tool: Tool,
        raw_inputs: dict[str, Any],
        context: AgentContext,
        dry_run: bool = False,
    ) -> ToolResult:
        """Execute a tool with full security checks and audit logging."""

        # Create tool invocation record
        invocation = await self._create_tool_invocation(tool, raw_inputs, context)

        started_at = time.perf_counter()
        try:
            # Validate inputs
            inputs = await tool.validate_inputs(raw_inputs)

            # Check permissions
            if not self._check_permission_level(tool, context):
                failure = await self._fail_invocation(
                    invocation,
                    "Insufficient permission level",
                    "PERMISSION_DENIED",
                )
                duration = time.perf_counter() - started_at
                record_tool_metrics(
                    tool_name=tool.name,
                    agent_type=context.agent_type,
                    success=False,
                    duration_seconds=duration,
                    error_code="PERMISSION_DENIED",
                )
                await performance_tracker.record(
                    tool_name=tool.name,
                    success=False,
                    duration_seconds=duration,
                )
                await self._record_tool_event(
                    context=context,
                    invocation=invocation,
                    tool=tool,
                    outcome="permission_denied",
                    duration=duration,
                    metadata={"error_code": "PERMISSION_DENIED"},
                )
                return failure

            # Enforce CEL policies
            cel_result = await self._enforce_cel_policy(
                tool, inputs.model_dump(), context, invocation
            )

            if not cel_result.allowed:
                if cel_result.requires_approval:
                    result = await self._request_approval(
                        invocation,
                        cel_result.reason,
                        requested_by=context.user_id,
                    )
                    duration = time.perf_counter() - started_at
                    record_tool_metrics(
                        tool_name=tool.name,
                        agent_type=context.agent_type,
                        success=False,
                        duration_seconds=duration,
                        error_code="APPROVAL_REQUIRED",
                    )
                    await performance_tracker.record(
                        tool_name=tool.name,
                        success=False,
                        duration_seconds=duration,
                    )
                    await self._record_tool_event(
                        context=context,
                        invocation=invocation,
                        tool=tool,
                        outcome="approval_required",
                        duration=duration,
                        metadata={
                            "error_code": "APPROVAL_REQUIRED",
                            "reason": cel_result.reason,
                        },
                    )
                    return result
                else:
                    failure = await self._fail_invocation(
                        invocation,
                        cel_result.reason,
                        "POLICY_VIOLATION",
                    )
                    duration = time.perf_counter() - started_at
                    record_tool_metrics(
                        tool_name=tool.name,
                        agent_type=context.agent_type,
                        success=False,
                        duration_seconds=duration,
                        error_code="POLICY_VIOLATION",
                    )
                    await performance_tracker.record(
                        tool_name=tool.name,
                        success=False,
                        duration_seconds=duration,
                    )
                    await self._record_tool_event(
                        context=context,
                        invocation=invocation,
                        tool=tool,
                        outcome="policy_violation",
                        duration=duration,
                        metadata={
                            "error_code": "POLICY_VIOLATION",
                            "reason": cel_result.reason,
                        },
                    )
                    return failure

            # Enforce dry-run for destructive tools unless explicitly approved
            if tool.permission_level == ToolPermissionLevel.WRITE_DESTRUCTIVE:
                dry_run = dry_run or not cel_result.explicitly_approved

            if not await self._enforce_rate_limit(context):
                failure = await self._fail_invocation(
                    invocation,
                    "Tool execution rate limit exceeded",
                    "TOOL_RATE_LIMITED",
                )
                duration = time.perf_counter() - started_at
                record_tool_metrics(
                    tool_name=tool.name,
                    agent_type=context.agent_type,
                    success=False,
                    duration_seconds=duration,
                    error_code="TOOL_RATE_LIMITED",
                )
                await performance_tracker.record(
                    tool_name=tool.name,
                    success=False,
                    duration_seconds=duration,
                )
                await self._record_tool_event(
                    context=context,
                    invocation=invocation,
                    tool=tool,
                    outcome="rate_limited",
                    duration=duration,
                    metadata={"error_code": "TOOL_RATE_LIMITED"},
                )
                return failure

            # CRITICAL: Set dry_run in context BEFORE execution
            execution_context = AgentContext(
                session_id=context.session_id,
                org_id=context.org_id,
                user_id=context.user_id,
                agent_type=context.agent_type,
                provider_scope=context.provider_scope,
                finding_ids=context.finding_ids,
                incident_id=context.incident_id,
                permission_level=context.permission_level,
                cel_context=context.cel_context,
                dry_run=dry_run,  # Pass dry_run to tool BEFORE execution
                roles=context.roles,
                memory_entries=context.memory_entries,
            )

            # Execute the tool with dry-run context
            invocation.status = ToolInvocationStatus.RUNNING
            await self._update_invocation(invocation)

            timeout_seconds = self._resolve_timeout_seconds(tool)
            try:
                with anyio.fail_after(timeout_seconds):
                    result = await tool.execute(inputs, execution_context)
            except TimeoutError:
                failure = await self._fail_invocation(
                    invocation,
                    f"Tool execution exceeded timeout of {timeout_seconds:.0f}s",
                    "TOOL_TIMEOUT",
                )
                duration = time.perf_counter() - started_at
                record_tool_metrics(
                    tool_name=tool.name,
                    agent_type=context.agent_type,
                    success=False,
                    duration_seconds=duration,
                    error_code="TOOL_TIMEOUT",
                )
                await performance_tracker.record(
                    tool_name=tool.name,
                    success=False,
                    duration_seconds=duration,
                )
                await self._record_tool_event(
                    context=context,
                    invocation=invocation,
                    tool=tool,
                    outcome="timeout",
                    duration=duration,
                    metadata={"error_code": "TOOL_TIMEOUT"},
                )
                return failure

            # ENFORCE: Mark result as dry-run and validate tool respected it
            result.dry_run = dry_run
            if dry_run:
                invocation.status = ToolInvocationStatus.DRY_RUN

                # Safety check: Destructive tools in dry-run MUST provide preview
                if tool.permission_level in [
                    ToolPermissionLevel.WRITE_DESTRUCTIVE,
                    ToolPermissionLevel.ADMIN,
                ]:
                    if not result.preview:
                        logger.warning(
                            "Destructive tool did not provide dry-run preview",
                            tool_name=tool.name,
                            session_id=context.session_id,
                        )
                        result.preview = {
                            "warning": "Tool did not implement proper dry-run preview",
                            "would_execute": (
                                str(inputs.model_dump())
                                if hasattr(inputs, "model_dump")
                                else str(inputs)
                            ),
                        }

            # Update invocation with results
            completed = await self._complete_invocation(invocation, result)
            await self._maybe_enqueue_review_task(
                tool=tool,
                invocation=invocation,
                context=context,
                result=completed,
            )
            duration = time.perf_counter() - started_at
            record_tool_metrics(
                tool_name=tool.name,
                agent_type=context.agent_type,
                success=completed.success,
                duration_seconds=duration,
            )
            await performance_tracker.record(
                tool_name=tool.name,
                success=completed.success,
                duration_seconds=duration,
            )
            await self._record_tool_event(
                context=context,
                invocation=invocation,
                tool=tool,
                outcome="success" if completed.success else "failure",
                duration=duration,
                metadata={
                    "dry_run": completed.dry_run,
                    "requires_approval": completed.requires_approval,
                    "result_metadata": completed.metadata or {},
                },
            )
            return completed

        except Exception as e:
            logger.exception(
                "Tool execution failed",
                tool_name=tool.name,
                session_id=context.session_id,
                error=str(e),
            )
            duration = time.perf_counter() - started_at
            failure_result = await self._fail_invocation(
                invocation,
                f"Tool execution error: {e!s}",
                "EXECUTION_ERROR",
            )
            record_tool_metrics(
                tool_name=tool.name,
                agent_type=context.agent_type,
                success=False,
                duration_seconds=duration,
                error_code="EXECUTION_ERROR",
            )
            await performance_tracker.record(
                tool_name=tool.name,
                success=False,
                duration_seconds=duration,
            )
            await self._record_tool_event(
                context=context,
                invocation=invocation,
                tool=tool,
                outcome="execution_error",
                duration=duration,
                metadata={
                    "error_code": "EXECUTION_ERROR",
                    "error": str(e),
                },
            )
            return failure_result

    def _check_permission_level(self, tool: Tool, context: AgentContext) -> bool:
        """Check if context has sufficient permission level for tool."""
        level_order = [
            ToolPermissionLevel.READ_ONLY,
            ToolPermissionLevel.WRITE_SAFE,
            ToolPermissionLevel.WRITE_DESTRUCTIVE,
            ToolPermissionLevel.ADMIN,
        ]

        tool_level_idx = level_order.index(tool.permission_level)
        context_level_idx = level_order.index(context.permission_level)

        return context_level_idx >= tool_level_idx

    async def _enforce_cel_policy(
        self,
        tool: Tool,
        inputs: dict[str, Any],
        context: AgentContext,
        invocation: ToolInvocation,
    ) -> "CELResult":
        """Enforce CEL policies for tool execution."""

        if not tool.cel_policy_key or not tool.cel_expression:
            return CELResult(allowed=True, reason="No policy defined")

        cel_context = context.build_cel_context(inputs)

        try:
            # Create evaluation context for rule engine
            from uuid import uuid4

            from cerebro.rules.engine import EvaluationContext

            eval_context = EvaluationContext(
                resource=cel_context,  # Pass all context as resource for now
                config=cel_context,
                principal={"user_id": context.user_id, "org_id": str(context.org_id)},
            )

            rule_result = self.rule_engine.evaluate_rule(
                rule_id=uuid4(),  # Generate temp UUID for this evaluation
                expression=tool.cel_expression,
                context=eval_context,
            )

            result = rule_result.matched

            # Update invocation with CEL details
            invocation.cel_policy_key = tool.cel_policy_key
            invocation.cel_expression = tool.cel_expression
            invocation.cel_result = result
            invocation.cel_context = cel_context
            await self._update_invocation(invocation)

            if result:
                return CELResult(allowed=True, reason="Policy check passed")
            else:
                # Check if this can be approved
                if tool.requires_approval:
                    return CELResult(
                        allowed=False,
                        requires_approval=True,
                        reason="Policy check failed but approval available",
                    )
                else:
                    return CELResult(
                        allowed=False,
                        reason="Policy check failed",
                    )

        except Exception as e:
            logger.error(
                "CEL policy evaluation failed",
                tool_name=tool.name,
                policy_key=tool.cel_policy_key,
                error=str(e),
            )
            return CELResult(
                allowed=False,
                reason=f"Policy evaluation error: {e!s}",
            )

    async def _create_tool_invocation(
        self,
        tool: Tool,
        inputs: dict[str, Any],
        context: AgentContext,
    ) -> ToolInvocation:
        """Create and persist tool invocation record."""
        from cerebro.core.database import async_session_factory

        async with async_session_factory() as session:
            invocation = ToolInvocation(
                session_id=context.session_id,
                tool_name=tool.name,
                tool_version=tool.version,
                input_data=inputs,
                status=ToolInvocationStatus.PENDING,
            )
            session.add(invocation)
            await session.commit()
            await session.refresh(invocation)
            return invocation

    async def _update_invocation(self, invocation: ToolInvocation) -> None:
        """Update tool invocation in database."""
        from cerebro.core.database import async_session_factory

        async with async_session_factory() as session:
            await session.merge(invocation)
            await session.commit()

    async def _complete_invocation(
        self,
        invocation: ToolInvocation,
        result: ToolResult,
    ) -> ToolResult:
        """Complete tool invocation with results."""
        invocation.status = (
            ToolInvocationStatus.SUCCESS
            if result.success
            else ToolInvocationStatus.ERROR
        )
        invocation.output_data = result.model_dump()
        invocation.completed_at = datetime.now(UTC)

        await self._update_invocation(invocation)
        return result

    async def _fail_invocation(
        self,
        invocation: ToolInvocation,
        error: str,
        error_code: str,
    ) -> ToolResult:
        """Mark invocation as failed."""
        invocation.status = ToolInvocationStatus.ERROR
        invocation.error_message = error
        invocation.error_code = error_code
        invocation.completed_at = datetime.now(UTC)

        await self._update_invocation(invocation)

        return ToolResult(
            success=False,
            error=error,
            metadata={"error_code": error_code},
        )

    async def _request_approval(
        self,
        invocation: ToolInvocation,
        reason: str,
        requested_by: str,
    ) -> ToolResult:
        """Create approval request for tool invocation."""
        from cerebro.core.database import async_session_factory

        async with async_session_factory() as session:
            approval = ToolApproval(
                org_id=invocation.session.org_id,  # type: ignore
                tool_invocation_id=invocation.id,
                requested_by=requested_by,
                reason=reason,
                risk_assessment={
                    "tool_name": invocation.tool_name,
                    "permission_level": "write_destructive",
                    "blast_radius": "medium",
                },
                status=ApprovalStatus.PENDING,
            )
            session.add(approval)
            await session.commit()
            await session.refresh(approval)

            invocation.status = ToolInvocationStatus.APPROVAL_REQUIRED
            await self._update_invocation(invocation)

            session_obj = invocation.session
            if session_obj is None:
                session_obj = await self._get_agent_session(invocation.session_id)
            if session_obj is not None:
                await AgentReviewService.create_task(
                    session=session_obj,
                    created_by=requested_by,
                    title=f"Approval required for {invocation.tool_name}",
                    summary=reason,
                    payload={
                        "tool_name": invocation.tool_name,
                        "inputs": invocation.input_data,
                        "reason": reason,
                    },
                    tool_invocation_id=invocation.id,
                )

            return ToolResult(
                success=False,
                requires_approval=True,
                approval_id=approval.id,
                metadata={
                    "message": "This action requires approval",
                    "reason": reason,
                },
            )

    async def _record_tool_event(
        self,
        *,
        context: AgentContext,
        invocation: ToolInvocation,
        tool: Tool,
        outcome: str,
        duration: float,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Send tool execution telemetry to the analytics service."""

        metadata = metadata or {}
        payload = {
            "tool_name": tool.name,
            "outcome": outcome,
            "duration_seconds": round(duration, 4),
            "invocation_id": str(invocation.id),
            "dry_run": metadata.get("dry_run"),
            "metadata": metadata,
        }
        await AgentAnalyticsService.record_event(
            org_id=context.org_id,
            session_id=context.session_id,
            event_type="tool_execution",
            payload=payload,
        )

    async def _maybe_enqueue_review_task(
        self,
        *,
        tool: Tool,
        invocation: ToolInvocation,
        context: AgentContext,
        result: ToolResult,
    ) -> None:
        """Queue human review tasks for destructive tools when appropriate."""

        if tool.permission_level not in {
            ToolPermissionLevel.WRITE_DESTRUCTIVE,
            ToolPermissionLevel.ADMIN,
        }:
            return
        if not result.success or result.requires_approval:
            return

        session = await self._get_agent_session(context.session_id)
        if not session:
            return

        metadata = result.metadata or {}
        summary = metadata.get("summary")
        await AgentReviewService.create_task(
            session=session,
            created_by=context.user_id,
            title=f"Review {tool.name} execution",
            summary=summary,
            payload={
                "tool_name": tool.name,
                "inputs": invocation.input_data,
                "output": invocation.output_data,
                "dry_run": result.dry_run,
            },
            tool_invocation_id=invocation.id,
            promotion_target=metadata.get("promotion_target"),
        )

    async def _get_agent_session(self, session_id: UUID) -> AgentSession | None:
        """Fetch an :class:`AgentSession` without mutating the caller's context."""

        from cerebro.core.database import async_session_factory

        async with async_session_factory() as db_session:
            return await db_session.get(AgentSession, session_id)


@dataclass
class CELResult:
    """Result of CEL policy evaluation."""

    allowed: bool
    reason: str
    requires_approval: bool = False
    explicitly_approved: bool = False


def tool(
    name: str,
    description: str,
    permission_level: ToolPermissionLevel = ToolPermissionLevel.READ_ONLY,
    cel_policy_key: str | None = None,
    cel_expression: str | None = None,
) -> Callable[[Any], Any]:
    """
    Decorator to register a function as a tool.

    This provides a simple way to create tools from functions without
    needing to subclass the Tool abstract class.
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await func(*args, **kwargs)

        # Add tool metadata to function
        wrapper._tool_name = name  # type: ignore[attr-defined]
        wrapper._tool_description = description  # type: ignore[attr-defined]
        wrapper._tool_permission_level = permission_level  # type: ignore[attr-defined]
        wrapper._tool_cel_policy_key = cel_policy_key  # type: ignore[attr-defined]
        wrapper._tool_cel_expression = cel_expression  # type: ignore[attr-defined]

        return wrapper

    return decorator
