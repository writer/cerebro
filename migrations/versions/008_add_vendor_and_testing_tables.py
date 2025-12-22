"""Add vendor management and testing tables

Revision ID: 008
Revises: 007
Create Date: 2024-01-08 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Security Reviews table
    op.create_table(
        "security_reviews",
        sa.Column(
            "review_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("vendor_id", sa.String(100), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("review_type", sa.String(50), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, default="pending"),
        sa.Column("framework", sa.String(50), nullable=False),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            nullable=False,
            default=sa.text("now()"),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("due_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scope", sa.Text(), nullable=True),
        sa.Column("objectives", sa.Text(), nullable=True),
        sa.Column("methodology", sa.Text(), nullable=True),
        sa.Column("overall_score", sa.Float(), nullable=True),
        sa.Column("risk_rating", sa.String(20), nullable=True),
        sa.Column("findings_summary", sa.Text(), nullable=True),
        sa.Column("remediation_plan", sa.Text(), nullable=True),
        sa.Column("reviewer_id", sa.String(100), nullable=True),
        sa.Column("approved_by", sa.String(100), nullable=True),
        sa.Column("next_review_due", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            default=sa.text("now()"),
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, default=True),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.org_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("review_id"),
    )

    # Security Review Controls table
    op.create_table(
        "security_review_controls",
        sa.Column(
            "control_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("review_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("control_reference", sa.String(50), nullable=False),
        sa.Column("control_name", sa.String(200), nullable=False),
        sa.Column("control_description", sa.Text(), nullable=True),
        sa.Column("control_category", sa.String(100), nullable=True),
        sa.Column("assessment_status", sa.String(50), nullable=False),
        sa.Column("assessment_notes", sa.Text(), nullable=True),
        sa.Column("evidence_links", sa.Text(), nullable=True),
        sa.Column("remediation_required", sa.Boolean(), nullable=False, default=False),
        sa.Column("remediation_priority", sa.String(20), nullable=True),
        sa.Column("remediation_deadline", sa.DateTime(timezone=True), nullable=True),
        sa.Column("remediation_status", sa.String(50), nullable=True),
        sa.Column("assessed_by", sa.String(100), nullable=True),
        sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["review_id"], ["security_reviews.review_id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("control_id"),
    )

    # Vendor Risk Assessments table
    op.create_table(
        "vendor_risk_assessments",
        sa.Column(
            "assessment_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("vendor_id", sa.String(100), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assessment_type", sa.String(50), nullable=False),
        sa.Column(
            "assessment_date",
            sa.DateTime(timezone=True),
            nullable=False,
            default=sa.text("now()"),
        ),
        sa.Column("assessor_id", sa.String(100), nullable=False),
        sa.Column("overall_risk_score", sa.Float(), nullable=False),
        sa.Column("risk_level", sa.String(20), nullable=False),
        sa.Column("data_security_score", sa.Float(), nullable=False, default=0.0),
        sa.Column("access_control_score", sa.Float(), nullable=False, default=0.0),
        sa.Column("compliance_score", sa.Float(), nullable=False, default=0.0),
        sa.Column("business_continuity_score", sa.Float(), nullable=False, default=0.0),
        sa.Column("operational_score", sa.Float(), nullable=False, default=0.0),
        sa.Column("methodology", sa.Text(), nullable=True),
        sa.Column("scope", sa.Text(), nullable=True),
        sa.Column("assumptions", sa.Text(), nullable=True),
        sa.Column("limitations", sa.Text(), nullable=True),
        sa.Column("key_findings", sa.Text(), nullable=True),
        sa.Column("recommendations", sa.Text(), nullable=True),
        sa.Column("risk_scenarios", postgresql.JSONB(), nullable=True),
        sa.Column("mitigation_plan", sa.Text(), nullable=True),
        sa.Column("next_assessment_due", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "assessment_frequency_days", sa.Integer(), nullable=False, default=365
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            default=sa.text("now()"),
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, default=True),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.org_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("assessment_id"),
    )

    # Test Entities table
    op.create_table(
        "test_entities",
        sa.Column(
            "entity_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("entity_type", sa.String(50), nullable=False),
        sa.Column("external_id", sa.String(200), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("entity_config", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, default="active"),
        sa.Column("test_suite_id", sa.String(100), nullable=True),
        sa.Column("test_purpose", sa.Text(), nullable=False),
        sa.Column("environment", sa.String(50), nullable=False),
        sa.Column("created_by", sa.String(100), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cleanup_required", sa.Boolean(), nullable=False, default=True),
        sa.Column("cleanup_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("depends_on", postgresql.JSONB(), nullable=True),
        sa.Column("supports", postgresql.JSONB(), nullable=True),
        sa.Column("tags", postgresql.JSONB(), nullable=True),
        sa.Column("entity_metadata", postgresql.JSONB(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            default=sa.text("now()"),
        ),
        sa.Column("last_accessed", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.org_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("entity_id"),
        sa.UniqueConstraint("org_id", "external_id", "entity_type"),
    )

    # Test Executions table
    op.create_table(
        "test_executions",
        sa.Column(
            "execution_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("test_id", sa.String(100), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("execution_status", sa.String(50), nullable=False, default="pending"),
        sa.Column("priority", sa.String(20), nullable=False, default="medium"),
        sa.Column("environment", sa.String(50), nullable=False),
        sa.Column(
            "scheduled_at",
            sa.DateTime(timezone=True),
            nullable=False,
            default=sa.text("now()"),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("timeout_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("test_status", sa.String(50), nullable=True),
        sa.Column("execution_time_ms", sa.Float(), nullable=True),
        sa.Column("test_score", sa.Float(), nullable=True),
        sa.Column("test_output", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("warnings", postgresql.JSONB(), nullable=True),
        sa.Column("evidence_data", postgresql.JSONB(), nullable=True),
        sa.Column("metrics", postgresql.JSONB(), nullable=True),
        sa.Column("executed_by", sa.String(100), nullable=False),
        sa.Column("execution_context", postgresql.JSONB(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.org_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("execution_id"),
    )

    # Add indexes for performance
    op.create_index("ix_security_reviews_vendor_id", "security_reviews", ["vendor_id"])
    op.create_index("ix_security_reviews_org_id", "security_reviews", ["org_id"])
    op.create_index("ix_security_reviews_status", "security_reviews", ["status"])
    op.create_index("ix_security_reviews_due_date", "security_reviews", ["due_date"])

    op.create_index(
        "ix_security_review_controls_review_id",
        "security_review_controls",
        ["review_id"],
    )
    op.create_index(
        "ix_security_review_controls_status",
        "security_review_controls",
        ["assessment_status"],
    )

    op.create_index(
        "ix_vendor_risk_assessments_vendor_id", "vendor_risk_assessments", ["vendor_id"]
    )
    op.create_index(
        "ix_vendor_risk_assessments_org_id", "vendor_risk_assessments", ["org_id"]
    )
    op.create_index(
        "ix_vendor_risk_assessments_risk_level",
        "vendor_risk_assessments",
        ["risk_level"],
    )

    op.create_index("ix_test_entities_org_id", "test_entities", ["org_id"])
    op.create_index("ix_test_entities_entity_type", "test_entities", ["entity_type"])
    op.create_index("ix_test_entities_status", "test_entities", ["status"])
    op.create_index("ix_test_entities_expires_at", "test_entities", ["expires_at"])

    op.create_index("ix_test_executions_test_id", "test_executions", ["test_id"])
    op.create_index("ix_test_executions_org_id", "test_executions", ["org_id"])
    op.create_index(
        "ix_test_executions_status", "test_executions", ["execution_status"]
    )
    op.create_index(
        "ix_test_executions_scheduled_at", "test_executions", ["scheduled_at"]
    )


def downgrade() -> None:
    op.drop_table("test_executions")
    op.drop_table("test_entities")
    op.drop_table("vendor_risk_assessments")
    op.drop_table("security_review_controls")
    op.drop_table("security_reviews")
