"""
Natural Language Query Tool

Translate natural language questions to SQL queries and execute them.
Enables users to query security data without knowing SQL syntax.
"""

from typing import Any, Dict, List, Optional
import structlog
from pydantic import BaseModel, Field

from cerebro.agents.tools.base import (
    StructuredTool,
    ToolResult,
    AgentContext,
    ToolPermissionLevel,
)
from cerebro.core.config import settings
from cerebro.query.bootstrap import get_query_engine

from .nl_translator import build_translator, TranslationError

logger = structlog.get_logger(__name__)


# ==================== Input/Output Schemas ====================

class NLQueryInput(BaseModel):
    """Input for natural language query tool."""
    question: str = Field(
        description="Natural language question about security data",
        min_length=5,
        examples=[
            "Show me all users without MFA enabled",
            "Which S3 buckets are publicly accessible?",
            "List AWS IAM users with admin permissions",
            "Find critical findings from the last 7 days",
        ],
    )
    limit: Optional[int] = Field(
        default=100,
        description="Maximum number of results to return",
        ge=1,
        le=1000,
    )


class NLQueryOutput(BaseModel):
    """Output for natural language query tool."""
    success: bool
    question: str
    sql_query: str
    results: List[Dict[str, Any]]
    result_count: int
    execution_time_ms: float
    explanation: str


# ==================== Query Schema ====================

QUERY_SCHEMA = """
Available Security Tables:

## Cloud Resources
- aws_iam_user (user_name, arn, mfa_enabled, access_keys, permissions_boundary, tags)
- aws_iam_role (role_name, arn, assume_role_policy, max_session_duration, tags)
- aws_iam_policy (policy_name, arn, is_aws_managed, permissions, attached_users, attached_roles)
- aws_s3_bucket (bucket_name, region, public_access, encryption, versioning, logging, tags)
- aws_ec2_instance (instance_id, instance_type, state, public_ip, security_groups, tags)
- aws_security_group (group_id, group_name, vpc_id, ingress_rules, egress_rules)
- aws_lambda_function (function_name, runtime, handler, role, environment_variables, vpc_config)

## Identity Providers
- okta_user (email, status, mfa_factors, last_login, created, profile)
- okta_group (name, description, member_count, members)
- okta_application (name, status, sign_on_mode, users_assigned, features)
- github_user (login, name, email, role, two_factor_enabled, company)
- github_repository (name, full_name, private, default_branch, permissions, topics)

## Security Findings
- findings (id, title, severity, status, resource_id, principal_id, created_at, resolved_at, compliance_frameworks)
- rules (id, name, description, severity, enabled, cel_expression, framework_mappings)

## Identity & Access
- principals (id, principal_id, name, type, provider, permissions, last_active)
- resources (id, resource_id, name, type, provider, tags, configuration)
- iam_edges (principal_id, resource_id, permission, path_length, effective_permissions)

## Compliance
- compliance_controls (id, framework, control_id, title, description, status, last_tested)
- evidence_bundles (id, framework, controls_covered, created_at, signed_hash, bundle_path)

Common Queries:
- MFA status: WHERE mfa_enabled = false OR mfa_factors IS NULL OR jsonb_array_length(mfa_factors) = 0
- Public access: WHERE public_access = true OR (ingress_rules @> '[{"cidr": "0.0.0.0/0"}]')
- Critical severity: WHERE severity = 'critical'
- Recent (7 days): WHERE created_at > NOW() - INTERVAL '7 days'
- Admin permissions: WHERE permissions::text LIKE '%admin%' OR permissions::text LIKE '%AdministratorAccess%'
"""

FEW_SHOT_EXAMPLES = """
Example translations:

Q: "Show me all users without MFA"
SQL: SELECT user_name, arn, mfa_enabled FROM aws_iam_user WHERE mfa_enabled = false;

Q: "Which S3 buckets are publicly accessible?"
SQL: SELECT bucket_name, region, public_access FROM aws_s3_bucket WHERE public_access = true;

Q: "List critical findings from last week"
SQL: SELECT id, title, severity, created_at FROM findings WHERE severity = 'critical' AND created_at > NOW() - INTERVAL '7 days' ORDER BY created_at DESC;

Q: "Find admin users in Okta"
SQL: SELECT email, status, profile FROM okta_user WHERE profile::text LIKE '%admin%';

Q: "Show IAM roles with admin permissions"
SQL: SELECT role_name, arn, permissions FROM aws_iam_role WHERE permissions::text LIKE '%AdministratorAccess%';

Q: "Which Lambda functions have environment variables?"
SQL: SELECT function_name, runtime, environment_variables FROM aws_lambda_function WHERE environment_variables IS NOT NULL AND jsonb_typeof(environment_variables) = 'object';

Q: "List open findings for S3 resources"
SQL: SELECT f.title, f.severity, f.status, r.name FROM findings f JOIN resources r ON f.resource_id = r.id WHERE r.type = 'AWS::S3::Bucket' AND f.status = 'open';

Q: "Find GitHub users without 2FA"
SQL: SELECT login, name, email FROM github_user WHERE two_factor_enabled = false;

Q: "Show EC2 instances with public IPs"
SQL: SELECT instance_id, instance_type, state, public_ip FROM aws_ec2_instance WHERE public_ip IS NOT NULL;

Q: "List security groups allowing SSH from anywhere"
SQL: SELECT group_id, group_name, ingress_rules FROM aws_security_group WHERE ingress_rules::text LIKE '%0.0.0.0/0%' AND ingress_rules::text LIKE '%port": 22%';
"""


# ==================== Tool Implementation ====================

class NaturalLanguageQueryTool(StructuredTool):
    """
    Translate natural language questions to SQL and execute them.

    Examples:
    - "Show me users without MFA" → Automatically translates to SQL and executes
    - "Which S3 buckets are public?" → Generates and runs appropriate SQL query
    - "Find critical findings" → Translates and executes filtering query

    Uses Claude to translate natural language to SQL with schema awareness.
    Includes safety validation to prevent destructive operations.
    """

    tool_name = "nl_query"
    tool_description = """Query security data using natural language instead of SQL.
Ask questions in plain English about users, resources, findings, compliance, etc.
The system will automatically translate to SQL and execute the query safely."""

    tool_version = "1.0.0"
    input_model = NLQueryInput
    output_model = NLQueryOutput
    required_permission = ToolPermissionLevel.READ_ONLY  # Only read queries allowed

    def __init__(self):
        super().__init__()
        self.query_engine = get_query_engine()
        self.translator = build_translator(settings)

    async def _run(
        self,
        context: AgentContext,
        question: str,
        limit: int = 100,
    ) -> ToolResult:
        """
        Translate natural language question to SQL and execute.

        Args:
            context: Agent execution context
            question: Natural language question
            limit: Maximum results to return

        Returns:
            ToolResult with SQL query, results, and explanation
        """

        try:
            logger.info("Translating natural language to SQL", question=question)
            sql_query = await self.translator.translate(
                question=question,
                limit=limit,
                schema=QUERY_SCHEMA,
                examples=FEW_SHOT_EXAMPLES,
            )
        except TranslationError as exc:
            logger.warning(
                "Natural language translation failed; returning fallback response",
                question=question,
                error=str(exc),
            )
            explanation = (
                "Natural language query translation is currently unavailable. "
                "Please try again later or provide a SQL query directly."
            )
            output = NLQueryOutput(
                success=False,
                question=question,
                sql_query="",
                results=[],
                result_count=0,
                execution_time_ms=0,
                explanation=f"{explanation} Details: {exc}",
            )
            return ToolResult(
                success=False,
                data=output.model_dump(),
                metadata={"error": "translation_failed", "details": str(exc)},
            )

        logger.info("Generated SQL query", question=question, sql=sql_query)

        if not self._is_safe_query(sql_query):
            output = NLQueryOutput(
                success=False,
                question=question,
                sql_query=sql_query,
                results=[],
                result_count=0,
                execution_time_ms=0,
                explanation=(
                    "Query contains potentially destructive operations (INSERT, UPDATE, DELETE, DROP). "
                    "Only read queries are allowed."
                ),
            )
            return ToolResult(
                success=False,
                data=output.model_dump(),
                metadata={"error": "unsafe_query"},
            )

        import time

        start_time = time.time()

        try:
            result = await self.query_engine.execute_query(sql_query)
        except Exception as exc:
            logger.exception("Query execution failed", error=str(exc), question=question)
            output = NLQueryOutput(
                success=False,
                question=question,
                sql_query=sql_query,
                results=[],
                result_count=0,
                execution_time_ms=0,
                explanation=f"Query execution failed: {exc}",
            )
            return ToolResult(
                success=False,
                data=output.model_dump(),
                metadata={"error": "execution_error", "details": str(exc)},
            )

        execution_time = result.execution_time_ms or ((time.time() - start_time) * 1000)

        if result.errors:
            logger.warning(
                "Query returned errors", question=question, sql=sql_query, errors=result.errors
            )
            error_message = "; ".join(result.errors)
            output = NLQueryOutput(
                success=False,
                question=question,
                sql_query=sql_query,
                results=[],
                result_count=0,
                execution_time_ms=execution_time,
                explanation=f"Query execution failed: {error_message}",
            )
            return ToolResult(
                success=False,
                data=output.model_dump(),
                metadata={"error": "query_failed", "details": result.errors},
            )

        rows = result.rows
        result_count = result.total_rows

        explanation = self._generate_explanation(question, sql_query, result_count)

        output = NLQueryOutput(
            success=True,
            question=question,
            sql_query=sql_query,
            results=rows,
            result_count=result_count,
            execution_time_ms=execution_time,
            explanation=explanation,
        )

        logger.info(
            "Natural language query executed successfully",
            question=question,
            result_count=result_count,
            execution_time_ms=execution_time,
        )

        return ToolResult(
            success=True,
            data=output.model_dump(),
            metadata={
                "sql_query": sql_query,
                "result_count": result_count,
                "execution_time_ms": execution_time,
            },
        )

    def _is_safe_query(self, sql: str) -> bool:
        """
        Validate that SQL query is safe (read-only).

        Args:
            sql: SQL query to validate

        Returns:
            True if safe, False otherwise
        """

        sql_upper = sql.upper()

        # Destructive operations not allowed
        dangerous_keywords = [
            "INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE",
            "ALTER", "CREATE", "GRANT", "REVOKE",
        ]

        for keyword in dangerous_keywords:
            if keyword in sql_upper:
                logger.warning(
                    "Unsafe SQL query detected",
                    sql=sql,
                    keyword=keyword,
                )
                return False

        # Must contain SELECT
        if "SELECT" not in sql_upper:
            logger.warning("SQL query must contain SELECT", sql=sql)
            return False

        return True

    def _generate_explanation(self, question: str, sql: str, result_count: int) -> str:
        """Generate human-readable explanation of query results."""

        if result_count == 0:
            return f"No results found for: {question}"
        elif result_count == 1:
            return f"Found 1 result for: {question}"
        else:
            return f"Found {result_count} results for: {question}"