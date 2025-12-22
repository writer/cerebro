"""DynamoDB test fixtures and utilities.

Provides pytest fixtures for testing with DynamoDB Local or moto mock.
"""

import pytest
from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import UUID, uuid4

import boto3
from moto import mock_dynamodb


# Test data factories
def create_test_org(
    org_id: UUID = None,
    name: str = "Test Organization",
    slack_config: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """Create test organization data."""
    org_id = org_id or uuid4()
    return {
        "PK": f"ORG#{org_id}",
        "SK": f"ORG#{org_id}",
        "entity_type": "ORG",
        "org_id": str(org_id),
        "name": name,
        "slack_config": slack_config,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "GSI3PK": "ORG#ALL",
        "GSI3SK": f"CREATED#{datetime.now(timezone.utc).isoformat()}",
    }


def create_test_account(
    account_id: UUID = None,
    org_id: UUID = None,
    provider: str = "aws",
    external_id: str = "123456789012",
) -> Dict[str, Any]:
    """Create test account data."""
    account_id = account_id or uuid4()
    org_id = org_id or uuid4()
    return {
        "PK": f"ORG#{org_id}",
        "SK": f"ACCOUNT#{account_id}",
        "entity_type": "ACCOUNT",
        "account_id": str(account_id),
        "org_id": str(org_id),
        "provider": provider,
        "external_id": external_id,
        "display_name": f"Test Account {external_id}",
        "GSI1PK": f"PROVIDER#{provider}",
        "GSI1SK": f"ACCOUNT#{account_id}",
    }


def create_test_finding(
    finding_id: UUID = None,
    org_id: UUID = None,
    account_id: UUID = None,
    rule_id: UUID = None,
    status: str = "open",
    severity: str = "high",
) -> Dict[str, Any]:
    """Create test finding data."""
    finding_id = finding_id or uuid4()
    org_id = org_id or uuid4()
    account_id = account_id or uuid4()
    rule_id = rule_id or uuid4()
    now = datetime.now(timezone.utc).isoformat()

    return {
        "PK": f"ORG#{org_id}",
        "SK": f"FINDING#{finding_id}",
        "entity_type": "FINDING",
        "finding_id": str(finding_id),
        "org_id": str(org_id),
        "account_id": str(account_id),
        "provider": "aws",
        "rule_id": str(rule_id),
        "rule_version": 1,
        "first_seen": now,
        "last_seen": now,
        "status": status,
        "severity": severity,
        "fingerprint": f"test-fingerprint-{finding_id}",
        "title": "Test Finding",
        "summary": "Test finding summary",
        "GSI1PK": f"RULE#{rule_id}",
        "GSI1SK": f"FINDING#{finding_id}",
        "GSI2PK": f"ORG#{org_id}#STATUS#{status}",
        "GSI2SK": f"SEVERITY#{severity}#{finding_id}",
        "GSI3PK": f"ORG#{org_id}",
        "GSI3SK": f"LAST_SEEN#{now}",
    }


def create_test_rule(
    rule_id: UUID = None,
    name: str = "Test Rule",
    severity: str = "high",
    is_active: bool = True,
) -> Dict[str, Any]:
    """Create test rule data."""
    rule_id = rule_id or uuid4()
    now = datetime.now(timezone.utc).isoformat()

    return {
        "PK": f"RULE#{rule_id}",
        "SK": f"RULE#{rule_id}",
        "entity_type": "RULE",
        "rule_id": str(rule_id),
        "name": name,
        "description": "Test rule description",
        "provider": ["aws"],
        "expression_lang": "cel",
        "expression": "resource.type == 's3_bucket'",
        "severity": severity,
        "version": 1,
        "is_active": is_active,
        "created_at": now,
        "GSI1PK": f"RULE#ACTIVE#{is_active}",
        "GSI1SK": f"SEVERITY#{severity}#{rule_id}",
    }


def create_test_session(
    session_id: UUID = None,
    org_id: UUID = None,
    agent_type: str = "security_analyst",
    created_by: str = "test-user",
) -> Dict[str, Any]:
    """Create test agent session data."""
    session_id = session_id or uuid4()
    org_id = org_id or uuid4()
    now = datetime.now(timezone.utc).isoformat()

    return {
        "PK": f"ORG#{org_id}",
        "SK": f"SESSION#{session_id}",
        "entity_type": "SESSION",
        "id": str(session_id),
        "org_id": str(org_id),
        "agent_type": agent_type,
        "created_at": now,
        "created_by": created_by,
        "title": "Test Session",
        "context": {},
        "is_active": True,
        "GSI1PK": f"ORG#{org_id}#AGENT#{agent_type}",
        "GSI1SK": f"CREATED#{now}",
        "GSI2PK": f"ORG#{org_id}#ACTIVE#True",
        "GSI2SK": f"CREATED#{now}",
    }


def create_test_message(
    message_id: UUID = None,
    session_id: UUID = None,
    org_id: UUID = None,
    role: str = "user",
    content: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """Create test agent message data."""
    message_id = message_id or uuid4()
    session_id = session_id or uuid4()
    org_id = org_id or uuid4()
    now = datetime.now(timezone.utc).isoformat()

    return {
        "PK": f"SESSION#{session_id}",
        "SK": f"MESSAGE#{now}#{message_id}",
        "entity_type": "MESSAGE",
        "id": str(message_id),
        "session_id": str(session_id),
        "org_id": str(org_id),
        "role": role,
        "content": content or {"text": "Test message"},
        "created_at": now,
        "GSI1PK": f"SESSION#{session_id}",
        "GSI1SK": f"MESSAGE#{now}",
    }


def serialize_item(item: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Serialize item for DynamoDB."""

    def serialize_value(value: Any) -> Dict[str, Any]:
        if value is None:
            return {"NULL": True}
        elif isinstance(value, bool):
            return {"BOOL": value}
        elif isinstance(value, str):
            return {"S": value}
        elif isinstance(value, (int, float)):
            return {"N": str(value)}
        elif isinstance(value, list):
            return {"L": [serialize_value(v) for v in value]}
        elif isinstance(value, dict):
            return {"M": {k: serialize_value(v) for k, v in value.items()}}
        else:
            return {"S": str(value)}

    return {k: serialize_value(v) for k, v in item.items() if v is not None}


class DynamoDBTestHelper:
    """Helper class for DynamoDB testing."""

    def __init__(self, client, table_name: str):
        self.client = client
        self.table_name = table_name

    def put_item(self, item: Dict[str, Any]) -> None:
        """Put an item into the table."""
        self.client.put_item(
            TableName=self.table_name,
            Item=serialize_item(item),
        )

    def get_item(self, pk: str, sk: str) -> Dict[str, Any]:
        """Get an item from the table."""
        response = self.client.get_item(
            TableName=self.table_name,
            Key={"PK": {"S": pk}, "SK": {"S": sk}},
        )
        return response.get("Item")

    def query(self, pk: str, sk_prefix: str = None) -> List[Dict[str, Any]]:
        """Query items by partition key."""
        params = {
            "TableName": self.table_name,
            "KeyConditionExpression": "PK = :pk",
            "ExpressionAttributeValues": {":pk": {"S": pk}},
        }
        if sk_prefix:
            params["KeyConditionExpression"] += " AND begins_with(SK, :sk)"
            params["ExpressionAttributeValues"][":sk"] = {"S": sk_prefix}

        response = self.client.query(**params)
        return response.get("Items", [])

    def delete_item(self, pk: str, sk: str) -> None:
        """Delete an item from the table."""
        self.client.delete_item(
            TableName=self.table_name,
            Key={"PK": {"S": pk}, "SK": {"S": sk}},
        )

    def clear_table(self) -> None:
        """Clear all items from the table."""
        response = self.client.scan(TableName=self.table_name)
        for item in response.get("Items", []):
            self.client.delete_item(
                TableName=self.table_name,
                Key={"PK": item["PK"], "SK": item["SK"]},
            )


def create_test_tables(client) -> None:
    """Create all test DynamoDB tables."""
    tables = [
        {
            "TableName": "cerebro-core-test",
            "KeySchema": [
                {"AttributeName": "PK", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
            "AttributeDefinitions": [
                {"AttributeName": "PK", "AttributeType": "S"},
                {"AttributeName": "SK", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "S"},
                {"AttributeName": "GSI2PK", "AttributeType": "S"},
                {"AttributeName": "GSI2SK", "AttributeType": "S"},
                {"AttributeName": "GSI3PK", "AttributeType": "S"},
                {"AttributeName": "GSI3SK", "AttributeType": "S"},
            ],
            "GlobalSecondaryIndexes": [
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
            "BillingMode": "PAY_PER_REQUEST",
        },
        {
            "TableName": "cerebro-agents-test",
            "KeySchema": [
                {"AttributeName": "PK", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
            "AttributeDefinitions": [
                {"AttributeName": "PK", "AttributeType": "S"},
                {"AttributeName": "SK", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "S"},
                {"AttributeName": "GSI2PK", "AttributeType": "S"},
                {"AttributeName": "GSI2SK", "AttributeType": "S"},
            ],
            "GlobalSecondaryIndexes": [
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
            "BillingMode": "PAY_PER_REQUEST",
        },
        {
            "TableName": "cerebro-audit-test",
            "KeySchema": [
                {"AttributeName": "PK", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
            "AttributeDefinitions": [
                {"AttributeName": "PK", "AttributeType": "S"},
                {"AttributeName": "SK", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "S"},
            ],
            "GlobalSecondaryIndexes": [
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            "BillingMode": "PAY_PER_REQUEST",
        },
    ]

    for table_def in tables:
        try:
            client.create_table(**table_def)
        except client.exceptions.ResourceInUseException:
            pass


# Pytest fixtures


@pytest.fixture
def dynamodb_client():
    """Create a mocked DynamoDB client."""
    with mock_dynamodb():
        client = boto3.client("dynamodb", region_name="us-east-1")
        create_test_tables(client)
        yield client


@pytest.fixture
def dynamodb_core_helper(dynamodb_client) -> DynamoDBTestHelper:
    """Helper for core table operations."""
    return DynamoDBTestHelper(dynamodb_client, "cerebro-core-test")


@pytest.fixture
def dynamodb_agents_helper(dynamodb_client) -> DynamoDBTestHelper:
    """Helper for agents table operations."""
    return DynamoDBTestHelper(dynamodb_client, "cerebro-agents-test")


@pytest.fixture
def dynamodb_audit_helper(dynamodb_client) -> DynamoDBTestHelper:
    """Helper for audit table operations."""
    return DynamoDBTestHelper(dynamodb_client, "cerebro-audit-test")


@pytest.fixture
def test_org_id() -> UUID:
    """Fixed test organization ID."""
    return UUID("12345678-1234-5678-1234-567812345678")


@pytest.fixture
def test_account_id() -> UUID:
    """Fixed test account ID."""
    return UUID("87654321-4321-8765-4321-876543218765")


@pytest.fixture
def test_org(dynamodb_core_helper, test_org_id) -> Dict[str, Any]:
    """Create and return a test organization."""
    org = create_test_org(org_id=test_org_id, name="Test Org")
    dynamodb_core_helper.put_item(org)
    return org


@pytest.fixture
def test_account(dynamodb_core_helper, test_org_id, test_account_id) -> Dict[str, Any]:
    """Create and return a test account."""
    account = create_test_account(
        account_id=test_account_id,
        org_id=test_org_id,
        provider="aws",
    )
    dynamodb_core_helper.put_item(account)
    return account


@pytest.fixture
def test_findings(
    dynamodb_core_helper, test_org_id, test_account_id
) -> List[Dict[str, Any]]:
    """Create and return test findings."""
    rule_id = uuid4()
    findings = [
        create_test_finding(
            org_id=test_org_id,
            account_id=test_account_id,
            rule_id=rule_id,
            status="open",
            severity="high",
        ),
        create_test_finding(
            org_id=test_org_id,
            account_id=test_account_id,
            rule_id=rule_id,
            status="open",
            severity="medium",
        ),
        create_test_finding(
            org_id=test_org_id,
            account_id=test_account_id,
            rule_id=rule_id,
            status="fixed",
            severity="high",
        ),
    ]
    for finding in findings:
        dynamodb_core_helper.put_item(finding)
    return findings


@pytest.fixture
def test_session(dynamodb_agents_helper, test_org_id) -> Dict[str, Any]:
    """Create and return a test agent session."""
    session = create_test_session(org_id=test_org_id)
    dynamodb_agents_helper.put_item(session)
    return session


@pytest.fixture
def mock_dynamodb_env(monkeypatch):
    """Set up environment for DynamoDB testing."""
    monkeypatch.setenv("CEREBRO_DB_BACKEND", "dynamodb")
    monkeypatch.setenv("DYNAMODB_CORE_TABLE", "cerebro-core-test")
    monkeypatch.setenv("DYNAMODB_AGENTS_TABLE", "cerebro-agents-test")
    monkeypatch.setenv("DYNAMODB_AUDIT_TABLE", "cerebro-audit-test")
    monkeypatch.setenv("DYNAMODB_NOTIFICATIONS_TABLE", "cerebro-notifications-test")
    monkeypatch.setenv("DYNAMODB_USERS_TABLE", "cerebro-users-test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
