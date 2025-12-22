"""Tests for DynamoDB repositories using moto mock.

These tests verify that the DynamoDB repositories work correctly
with a mocked DynamoDB backend.
"""

import pytest
from uuid import uuid4

import boto3
from moto import mock_aws

from cerebro.core.dynamodb_client import reset_client, TableName, get_table_name


def create_tables(client):
    """Create test DynamoDB tables."""
    # Core table
    client.create_table(
        TableName=get_table_name(TableName.CORE),
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "S"},
            {"AttributeName": "GSI2PK", "AttributeType": "S"},
            {"AttributeName": "GSI2SK", "AttributeType": "S"},
            {"AttributeName": "GSI3PK", "AttributeType": "S"},
            {"AttributeName": "GSI3SK", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI2",
                "KeySchema": [
                    {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI3",
                "KeySchema": [
                    {"AttributeName": "GSI3PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI3SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )

    # Agents table
    client.create_table(
        TableName=get_table_name(TableName.AGENTS),
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "S"},
            {"AttributeName": "GSI2PK", "AttributeType": "S"},
            {"AttributeName": "GSI2SK", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI2",
                "KeySchema": [
                    {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@pytest.fixture
def mock_dynamodb():
    """Set up mocked DynamoDB."""
    with mock_aws():
        # Reset the cached client
        reset_client()

        # Create tables
        client = boto3.client("dynamodb", region_name="us-east-1")
        create_tables(client)

        yield client

        # Reset again after test
        reset_client()


class TestOrganizationRepository:
    """Tests for OrganizationRepository."""

    @pytest.mark.asyncio
    async def test_create_and_get(self, mock_dynamodb):
        """Test creating and retrieving an organization."""
        from cerebro.core.repositories.organization import (
            Organization,
            OrganizationRepository,
        )

        repo = OrganizationRepository()
        org_id = uuid4()

        # Create
        org = Organization(org_id=org_id, name="Test Org")
        created = await repo.create(org)

        assert created.org_id == org_id
        assert created.name == "Test Org"

        # Get
        retrieved = await repo.get(org_id)
        assert retrieved is not None
        assert retrieved.org_id == org_id
        assert retrieved.name == "Test Org"

    @pytest.mark.asyncio
    async def test_update(self, mock_dynamodb):
        """Test updating an organization."""
        from cerebro.core.repositories.organization import (
            Organization,
            OrganizationRepository,
        )

        repo = OrganizationRepository()
        org_id = uuid4()

        # Create
        org = Organization(org_id=org_id, name="Original Name")
        await repo.create(org)

        # Update
        updated = await repo.update(org_id, name="Updated Name")

        assert updated is not None
        assert updated.name == "Updated Name"

    @pytest.mark.asyncio
    async def test_delete(self, mock_dynamodb):
        """Test deleting an organization."""
        from cerebro.core.repositories.organization import (
            Organization,
            OrganizationRepository,
        )

        repo = OrganizationRepository()
        org_id = uuid4()

        # Create
        org = Organization(org_id=org_id, name="To Delete")
        await repo.create(org)

        # Delete
        result = await repo.delete(org_id)
        assert result is True

        # Verify deleted
        retrieved = await repo.get(org_id)
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_list_all(self, mock_dynamodb):
        """Test listing all organizations."""
        from cerebro.core.repositories.organization import (
            Organization,
            OrganizationRepository,
        )

        repo = OrganizationRepository()

        # Create multiple orgs
        for i in range(3):
            org = Organization(name=f"Org {i}")
            await repo.create(org)

        # List
        orgs = await repo.list_all()
        assert len(orgs) == 3


class TestFindingRepository:
    """Tests for FindingRepository."""

    @pytest.mark.asyncio
    async def test_create_and_get(self, mock_dynamodb):
        """Test creating and retrieving a finding."""
        from cerebro.core.repositories.finding import (
            Finding,
            FindingRepository,
            Severity,
            FindingStatus,
        )

        repo = FindingRepository()
        org_id = uuid4()
        account_id = uuid4()
        rule_id = uuid4()

        # Create
        finding = Finding(
            org_id=org_id,
            account_id=account_id,
            provider="aws",
            rule_id=rule_id,
            severity=Severity.HIGH,
            fingerprint="test-fingerprint",
            title="Test Finding",
        )
        created = await repo.create(finding)

        assert created.org_id == org_id
        assert created.status == FindingStatus.OPEN

        # Get
        retrieved = await repo.get(created.finding_id, org_id)
        assert retrieved is not None
        assert retrieved.title == "Test Finding"

    @pytest.mark.asyncio
    async def test_list_by_status(self, mock_dynamodb):
        """Test listing findings by status."""
        from cerebro.core.repositories.finding import (
            Finding,
            FindingRepository,
            Severity,
            FindingStatus,
        )

        repo = FindingRepository()
        org_id = uuid4()
        account_id = uuid4()
        rule_id = uuid4()

        # Create findings with different statuses
        for i, status in enumerate(
            [FindingStatus.OPEN, FindingStatus.OPEN, FindingStatus.FIXED]
        ):
            finding = Finding(
                org_id=org_id,
                account_id=account_id,
                provider="aws",
                rule_id=rule_id,
                severity=Severity.HIGH,
                status=status,
                fingerprint=f"fp-{i}",
                title=f"Finding {i}",
            )
            await repo.create(finding)

        # List open findings
        open_findings = await repo.list_by_org(org_id, status=FindingStatus.OPEN)
        assert len(open_findings) == 2

        # List fixed findings
        fixed_findings = await repo.list_by_org(org_id, status=FindingStatus.FIXED)
        assert len(fixed_findings) == 1

    @pytest.mark.asyncio
    async def test_update_status(self, mock_dynamodb):
        """Test updating finding status."""
        from cerebro.core.repositories.finding import (
            Finding,
            FindingRepository,
            Severity,
            FindingStatus,
        )

        repo = FindingRepository()
        org_id = uuid4()

        # Create
        finding = Finding(
            org_id=org_id,
            account_id=uuid4(),
            provider="aws",
            rule_id=uuid4(),
            severity=Severity.HIGH,
            fingerprint="test-fp",
            title="Test",
        )
        created = await repo.create(finding)

        # Update status
        updated = await repo.update(
            created.finding_id,
            org_id,
            status=FindingStatus.SUPPRESSED,
        )

        assert updated is not None
        assert updated.status == FindingStatus.SUPPRESSED


class TestAgentSessionRepository:
    """Tests for AgentSessionRepository."""

    @pytest.mark.asyncio
    async def test_create_and_get(self, mock_dynamodb):
        """Test creating and retrieving a session."""
        from cerebro.core.repositories.agents import (
            AgentSession,
            AgentSessionRepository,
            AgentType,
        )

        repo = AgentSessionRepository()
        org_id = uuid4()

        # Create
        session = AgentSession(
            org_id=org_id,
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="test-user",
            title="Test Session",
        )
        created = await repo.create(session)

        assert created.org_id == org_id
        assert created.agent_type == AgentType.SECURITY_ANALYST

        # Get
        retrieved = await repo.get(created.id, org_id)
        assert retrieved is not None
        assert retrieved.title == "Test Session"

    @pytest.mark.asyncio
    async def test_list_by_agent_type(self, mock_dynamodb):
        """Test listing sessions by agent type."""
        from cerebro.core.repositories.agents import (
            AgentSession,
            AgentSessionRepository,
            AgentType,
        )

        repo = AgentSessionRepository()
        org_id = uuid4()

        # Create sessions with different types
        for agent_type in [
            AgentType.SECURITY_ANALYST,
            AgentType.SECURITY_ANALYST,
            AgentType.INCIDENT_RESPONDER,
        ]:
            session = AgentSession(
                org_id=org_id,
                agent_type=agent_type,
                created_by="test-user",
            )
            await repo.create(session)

        # List by type
        analyst_sessions, total = await repo.list_by_org(
            org_id,
            agent_type=AgentType.SECURITY_ANALYST,
        )
        assert len(analyst_sessions) == 2

    @pytest.mark.asyncio
    async def test_deactivate(self, mock_dynamodb):
        """Test deactivating a session."""
        from cerebro.core.repositories.agents import (
            AgentSession,
            AgentSessionRepository,
            AgentType,
        )

        repo = AgentSessionRepository()
        org_id = uuid4()

        # Create
        session = AgentSession(
            org_id=org_id,
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="test-user",
        )
        created = await repo.create(session)
        assert created.is_active is True

        # Deactivate
        deactivated = await repo.deactivate(created.id, org_id)
        assert deactivated is not None
        assert deactivated.is_active is False


class TestAgentMessageRepository:
    """Tests for AgentMessageRepository."""

    @pytest.mark.asyncio
    async def test_create_and_list(self, mock_dynamodb):
        """Test creating and listing messages."""
        from cerebro.core.repositories.agents import (
            AgentMessage,
            AgentMessageRepository,
            MessageRole,
        )

        repo = AgentMessageRepository()
        session_id = uuid4()
        org_id = uuid4()

        # Create messages
        for i, role in enumerate(
            [MessageRole.USER, MessageRole.ASSISTANT, MessageRole.USER]
        ):
            message = AgentMessage(
                session_id=session_id,
                org_id=org_id,
                role=role,
                content={"text": f"Message {i}"},
            )
            await repo.create(message)

        # List
        messages = await repo.list_by_session(session_id)
        assert len(messages) == 3

        # Should be in chronological order
        assert messages[0].content["text"] == "Message 0"
        assert messages[2].content["text"] == "Message 2"

    @pytest.mark.asyncio
    async def test_token_usage(self, mock_dynamodb):
        """Test getting token usage."""
        from cerebro.core.repositories.agents import (
            AgentMessage,
            AgentMessageRepository,
            MessageRole,
        )

        repo = AgentMessageRepository()
        session_id = uuid4()
        org_id = uuid4()

        # Create messages with tokens
        for i in range(3):
            message = AgentMessage(
                session_id=session_id,
                org_id=org_id,
                role=MessageRole.ASSISTANT,
                content={"text": f"Message {i}"},
                input_tokens=100,
                output_tokens=50,
            )
            await repo.create(message)

        # Get usage
        usage = await repo.get_token_usage(session_id)
        assert usage["input_tokens"] == 300
        assert usage["output_tokens"] == 150
        assert usage["total_tokens"] == 450
