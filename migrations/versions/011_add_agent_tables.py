"""Add agent system tables for conversation sessions, messages, and tool tracking

Revision ID: 011
Revises: 010
Create Date: 2024-01-15 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Agent Sessions table
    op.create_table(
        "agent_sessions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "agent_type",
            sa.Enum(
                "security_analyst",
                "incident_responder",
                "identity_advisor",
                "compliance_advisor",
                "attack_path_analyst",
                name="agenttype",
            ),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            default=sa.text("now()"),
        ),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("title", sa.String(500), nullable=True),
        sa.Column(
            "context",
            postgresql.JSONB(),
            nullable=False,
            default=sa.text("'{}'::jsonb"),
        ),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.org_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # Add indexes for agent sessions
    op.create_index("ix_agent_sessions_org_id", "agent_sessions", ["org_id"])
    op.create_index("ix_agent_sessions_created_at", "agent_sessions", ["created_at"])
    op.create_index("ix_agent_sessions_agent_type", "agent_sessions", ["agent_type"])

    # Agent Messages table
    op.create_table(
        "agent_messages",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "role",
            sa.Enum("user", "assistant", "tool", "system", name="messagerole"),
            nullable=False,
        ),
        sa.Column("content", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            default=sa.text("now()"),
        ),
        sa.Column("input_tokens", sa.Integer(), nullable=True),
        sa.Column("output_tokens", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["session_id"], ["agent_sessions.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # Add indexes for agent messages
    op.create_index("ix_agent_messages_session_id", "agent_messages", ["session_id"])
    op.create_index("ix_agent_messages_created_at", "agent_messages", ["created_at"])

    # Tool Invocations table
    op.create_table(
        "tool_invocations",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tool_name", sa.String(100), nullable=False),
        sa.Column("tool_version", sa.String(20), nullable=False, default="1.0"),
        sa.Column("input_data", postgresql.JSONB(), nullable=False),
        sa.Column("output_data", postgresql.JSONB(), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "running",
                "success",
                "error",
                "dry_run",
                "approval_required",
                name="toolinvocationstatus",
            ),
            nullable=False,
            default="pending",
        ),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            default=sa.text("now()"),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cel_policy_key", sa.String(200), nullable=True),
        sa.Column("cel_expression", sa.Text(), nullable=True),
        sa.Column("cel_result", sa.Boolean(), nullable=True),
        sa.Column("cel_context", postgresql.JSONB(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("error_code", sa.String(50), nullable=True),
        sa.Column("celery_task_id", sa.String(100), nullable=True),
        sa.ForeignKeyConstraint(
            ["session_id"], ["agent_sessions.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # Add indexes for tool invocations
    op.create_index(
        "ix_tool_invocations_session_id", "tool_invocations", ["session_id"]
    )
    op.create_index("ix_tool_invocations_tool_name", "tool_invocations", ["tool_name"])
    op.create_index("ix_tool_invocations_status", "tool_invocations", ["status"])
    op.create_index(
        "ix_tool_invocations_celery_task_id", "tool_invocations", ["celery_task_id"]
    )
    op.create_index(
        "ix_tool_invocations_started_at", "tool_invocations", ["started_at"]
    )

    # Tool Approvals table
    op.create_table(
        "tool_approvals",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tool_invocation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("requested_by", sa.String(255), nullable=False),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            nullable=False,
            default=sa.text("now()"),
        ),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("risk_assessment", postgresql.JSONB(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "pending", "approved", "rejected", "expired", name="approvalstatus"
            ),
            nullable=False,
            default="pending",
        ),
        sa.Column("decided_by", sa.String(255), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.org_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["tool_invocation_id"], ["tool_invocations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tool_invocation_id", name="uq_tool_approvals_tool_invocation_id"
        ),
    )

    # Add indexes for tool approvals
    op.create_index("ix_tool_approvals_org_id", "tool_approvals", ["org_id"])
    op.create_index(
        "ix_tool_approvals_tool_invocation_id", "tool_approvals", ["tool_invocation_id"]
    )
    op.create_index("ix_tool_approvals_status", "tool_approvals", ["status"])
    op.create_index("ix_tool_approvals_expires_at", "tool_approvals", ["expires_at"])

    # Agent Recommendations table
    op.create_table(
        "agent_recommendations",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("type", sa.String(50), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("priority", sa.String(20), nullable=False),
        sa.Column(
            "action_items",
            postgresql.JSONB(),
            nullable=False,
            default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("estimated_effort", sa.String(50), nullable=True),
        sa.Column("implementation_timeline", sa.String(50), nullable=True),
        sa.Column(
            "cis_controls",
            postgresql.JSONB(),
            nullable=False,
            default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "nist_controls",
            postgresql.JSONB(),
            nullable=False,
            default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "cwe_ids",
            postgresql.JSONB(),
            nullable=False,
            default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            default=sa.text("now()"),
        ),
        sa.Column("status", sa.String(20), nullable=False, default="draft"),
        sa.ForeignKeyConstraint(
            ["session_id"], ["agent_sessions.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.org_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # Add indexes for agent recommendations
    op.create_index(
        "ix_agent_recommendations_session_id", "agent_recommendations", ["session_id"]
    )
    op.create_index(
        "ix_agent_recommendations_org_id", "agent_recommendations", ["org_id"]
    )
    op.create_index(
        "ix_agent_recommendations_created_at", "agent_recommendations", ["created_at"]
    )
    op.create_index(
        "ix_agent_recommendations_status", "agent_recommendations", ["status"]
    )
    op.create_index(
        "ix_agent_recommendations_priority", "agent_recommendations", ["priority"]
    )
    op.create_index("ix_agent_recommendations_type", "agent_recommendations", ["type"])


def downgrade() -> None:
    op.drop_table("agent_recommendations")
    op.drop_table("tool_approvals")
    op.drop_table("tool_invocations")
    op.drop_table("agent_messages")
    op.drop_table("agent_sessions")

    # Drop the enums
    op.execute("DROP TYPE IF EXISTS approvalstatus")
    op.execute("DROP TYPE IF EXISTS toolinvocationstatus")
    op.execute("DROP TYPE IF EXISTS messagerole")
    op.execute("DROP TYPE IF EXISTS agenttype")
