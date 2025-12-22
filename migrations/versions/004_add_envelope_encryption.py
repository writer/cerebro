"""Add envelope encryption support

Revision ID: 004
Revises: 003
Create Date: 2024-01-04 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add envelope encryption support to existing provider_credentials table."""
    import os
    import logging
    from sqlalchemy import text, inspect

    logger = logging.getLogger("alembic")
    conn = op.get_bind()
    inspector = inspect(conn)

    # Check if provider_credentials table exists
    if "provider_credentials" not in inspector.get_table_names():
        logger.info(
            "provider_credentials table doesn't exist yet - will be created in migration 005"
        )
        return

    # Check if encrypted_dek column already exists
    columns = [col["name"] for col in inspector.get_columns("provider_credentials")]
    if "encrypted_dek" in columns:
        logger.info("encrypted_dek column already exists - skipping migration")
        return

    logger.info("Adding envelope encryption support to provider_credentials table")

    # Step 1: Add encrypted_dek column (nullable initially)
    op.add_column(
        "provider_credentials",
        sa.Column("encrypted_dek", sa.LargeBinary(), nullable=True),
    )

    # Step 2: Check if there are existing rows that need migration
    result = conn.execute(text("SELECT COUNT(*) FROM provider_credentials")).scalar()
    existing_rows = result or 0

    if existing_rows > 0:
        logger.info(
            f"Found {existing_rows} existing credential rows that need envelope encryption migration"
        )

        # Step 3: Generate DEKs and migrate existing encrypted credentials
        # This requires the KMS to be configured
        kms_provider = os.getenv("KMS_PROVIDER", "local")

        if kms_provider == "local":
            logger.warning(
                "Using local KMS for migration - this should only be done in development"
            )
            # Use a predictable DEK for local development (insecure but functional)
            conn.execute(
                text(
                    """
                UPDATE provider_credentials
                SET encrypted_dek = decode('0123456789abcdef0123456789abcdef', 'hex')
                WHERE encrypted_dek IS NULL
            """
                )
            )
        else:
            logger.warning(
                f"Production KMS ({kms_provider}) detected. Envelope encryption migration requires manual intervention.\n"
                "Please run the envelope encryption migration script after this migration completes:\n"
                "python -m cerebro.migrations.migrate_envelope_encryption"
            )
            # Leave encrypted_dek as NULL for manual migration

    # Step 4: Create index for performance
    op.create_index(
        "ix_provider_credentials_encrypted_dek",
        "provider_credentials",
        ["encrypted_dek"],
    )

    logger.info("Envelope encryption migration completed")


def downgrade() -> None:
    """Remove envelope encryption support from provider_credentials table."""
    import logging
    from sqlalchemy import inspect

    logger = logging.getLogger("alembic")
    conn = op.get_bind()
    inspector = inspect(conn)

    # Check if provider_credentials table exists
    if "provider_credentials" not in inspector.get_table_names():
        logger.info("provider_credentials table doesn't exist - nothing to downgrade")
        return

    # Check if encrypted_dek column exists
    columns = [col["name"] for col in inspector.get_columns("provider_credentials")]
    if "encrypted_dek" not in columns:
        logger.info("encrypted_dek column doesn't exist - nothing to downgrade")
        return

    logger.warning("Downgrading envelope encryption - this will remove encrypted DEKs")
    logger.warning(
        "Credentials will fall back to direct SECRET_KEY encryption (less secure)"
    )

    # Drop index first
    try:
        op.drop_index("ix_provider_credentials_encrypted_dek", "provider_credentials")
    except Exception as e:
        logger.warning(f"Could not drop index (may not exist): {e}")

    # Remove encrypted_dek column
    op.drop_column("provider_credentials", "encrypted_dek")

    logger.info("Envelope encryption downgrade completed")
