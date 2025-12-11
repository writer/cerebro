"""DynamoDB client and utilities for Cerebro.

This module provides the DynamoDB client configuration, session management,
and common utilities for interacting with DynamoDB tables following the
single-table design pattern with GSIs for access patterns.

Tables:
    - cerebro-core: Organizations, accounts, principals, resources, findings, rules
    - cerebro-audit: Audit events, config snapshots (time-series with TTL)
    - cerebro-agents: Agent sessions, messages, tools, reviews
    - cerebro-notifications: Webhook/email configs and delivery logs
    - cerebro-users: User authentication, API keys, integrations
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from functools import lru_cache
from typing import Any, Dict, List, Optional, Sequence, Tuple, TypeVar, Union
from uuid import UUID

import boto3
from botocore.config import Config
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


def _get_settings() -> "Settings":
    """Lazy import settings to avoid circular imports."""
    from cerebro.core.config import settings

    return settings


def _get_table_name_from_settings(table_type: str) -> str:
    """Get table name from settings."""
    settings = _get_settings()
    table_map = {
        "core": settings.dynamodb_core_table,
        "audit": settings.dynamodb_audit_table,
        "agents": settings.dynamodb_agents_table,
        "notifications": settings.dynamodb_notifications_table,
        "users": settings.dynamodb_users_table,
    }
    return table_map.get(table_type, f"cerebro-{table_type}")


def _get_aws_region() -> str:
    """Get AWS region from settings or environment."""
    return os.environ.get("AWS_REGION", "us-east-1")


def _get_endpoint_url() -> Optional[str]:
    """Get DynamoDB endpoint URL from settings or environment."""
    env_url = os.environ.get("DYNAMODB_ENDPOINT_URL")
    if env_url:
        return env_url
    try:
        settings = _get_settings()
        return settings.dynamodb_endpoint_url
    except Exception:
        return None


class TableName(str, Enum):
    """DynamoDB table names."""

    CORE = "core"
    AUDIT = "audit"
    AGENTS = "agents"
    NOTIFICATIONS = "notifications"
    USERS = "users"


def get_table_name(table: TableName) -> str:
    """Get the actual table name from settings."""
    return _get_table_name_from_settings(table.value)


_dynamodb_client: Optional["boto3.client"] = None
_dynamodb_resource: Optional["boto3.resource"] = None


def get_dynamodb_client() -> "boto3.client":
    """Get a cached DynamoDB client.

    Returns:
        boto3 DynamoDB client configured for the application.
    """
    global _dynamodb_client
    if _dynamodb_client is not None:
        return _dynamodb_client

    config = Config(
        retries={"max_attempts": 3, "mode": "adaptive"},
        connect_timeout=5,
        read_timeout=30,
    )

    kwargs: Dict[str, Any] = {
        "region_name": _get_aws_region(),
        "config": config,
    }

    endpoint_url = _get_endpoint_url()
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url

    _dynamodb_client = boto3.client("dynamodb", **kwargs)
    return _dynamodb_client


def get_dynamodb_resource() -> "boto3.resource":
    """Get a cached DynamoDB resource for higher-level operations.

    Returns:
        boto3 DynamoDB resource.
    """
    global _dynamodb_resource
    if _dynamodb_resource is not None:
        return _dynamodb_resource

    kwargs: Dict[str, Any] = {"region_name": _get_aws_region()}

    endpoint_url = _get_endpoint_url()
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url

    _dynamodb_resource = boto3.resource("dynamodb", **kwargs)
    return _dynamodb_resource


def reset_dynamodb_clients() -> None:
    """Reset cached DynamoDB clients (useful for testing)."""
    global _dynamodb_client, _dynamodb_resource
    _dynamodb_client = None
    _dynamodb_resource = None


def get_table(table: TableName) -> "boto3.dynamodb.Table":
    """Get a DynamoDB Table resource.

    Args:
        table: Table identifier.

    Returns:
        DynamoDB Table resource.
    """
    resource = get_dynamodb_resource()
    return resource.Table(get_table_name(table))


# Type serialization utilities


def serialize_value(value: Any) -> Dict[str, Any]:
    """Serialize a Python value to DynamoDB AttributeValue format.

    Args:
        value: Python value to serialize.

    Returns:
        DynamoDB AttributeValue dictionary.
    """
    if value is None:
        return {"NULL": True}
    elif isinstance(value, bool):
        return {"BOOL": value}
    elif isinstance(value, str):
        return {"S": value}
    elif isinstance(value, (int, float, Decimal)):
        return {"N": str(value)}
    elif isinstance(value, bytes):
        return {"B": value}
    elif isinstance(value, UUID):
        return {"S": str(value)}
    elif isinstance(value, datetime):
        return {"S": value.isoformat()}
    elif isinstance(value, Enum):
        return {"S": value.value}
    elif isinstance(value, list):
        if not value:
            return {"L": []}
        return {"L": [serialize_value(item) for item in value]}
    elif isinstance(value, dict):
        return {"M": {k: serialize_value(v) for k, v in value.items()}}
    elif isinstance(value, set):
        if not value:
            return {"L": []}
        first = next(iter(value))
        if isinstance(first, str):
            return {"SS": list(value)}
        elif isinstance(first, (int, float, Decimal)):
            return {"NS": [str(v) for v in value]}
        elif isinstance(first, bytes):
            return {"BS": list(value)}
        return {"L": [serialize_value(item) for item in value]}
    else:
        return {"S": str(value)}


def deserialize_value(attr: Dict[str, Any]) -> Any:
    """Deserialize a DynamoDB AttributeValue to Python value.

    Args:
        attr: DynamoDB AttributeValue dictionary.

    Returns:
        Deserialized Python value.
    """
    if "NULL" in attr:
        return None
    elif "BOOL" in attr:
        return attr["BOOL"]
    elif "S" in attr:
        return attr["S"]
    elif "N" in attr:
        num_str = attr["N"]
        if "." in num_str:
            return float(num_str)
        return int(num_str)
    elif "B" in attr:
        return attr["B"]
    elif "L" in attr:
        return [deserialize_value(item) for item in attr["L"]]
    elif "M" in attr:
        return {k: deserialize_value(v) for k, v in attr["M"].items()}
    elif "SS" in attr:
        return set(attr["SS"])
    elif "NS" in attr:
        return {float(n) if "." in n else int(n) for n in attr["NS"]}
    elif "BS" in attr:
        return set(attr["BS"])
    else:
        return None


def serialize_item(item: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Serialize a dictionary to DynamoDB item format.

    Args:
        item: Dictionary with Python values.

    Returns:
        Dictionary with DynamoDB AttributeValue format.
    """
    return {k: serialize_value(v) for k, v in item.items() if v is not None}


def deserialize_item(item: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Deserialize a DynamoDB item to Python dictionary.

    Args:
        item: DynamoDB item with AttributeValue format.

    Returns:
        Dictionary with Python values.
    """
    return {k: deserialize_value(v) for k, v in item.items()}


# Key building utilities for single-table design


def build_pk(entity_type: str, org_id: Union[str, UUID]) -> str:
    """Build partition key for org-scoped entities.

    Args:
        entity_type: Entity type prefix (e.g., "ORG", "ACCOUNT", "FINDING").
        org_id: Organization ID.

    Returns:
        Partition key string.
    """
    return f"{entity_type}#{org_id}"


def build_sk(entity_type: str, entity_id: Union[str, UUID], *parts: str) -> str:
    """Build sort key for entity identification.

    Args:
        entity_type: Entity type prefix.
        entity_id: Primary entity identifier.
        *parts: Additional sort key parts.

    Returns:
        Sort key string.
    """
    sk = f"{entity_type}#{entity_id}"
    for part in parts:
        sk += f"#{part}"
    return sk


def build_gsi1_pk(index_type: str, value: Union[str, UUID]) -> str:
    """Build GSI1 partition key for alternate access patterns.

    Args:
        index_type: Index type prefix.
        value: Index value.

    Returns:
        GSI1 partition key string.
    """
    return f"{index_type}#{value}"


def build_gsi1_sk(sort_type: str, value: Union[str, UUID, datetime]) -> str:
    """Build GSI1 sort key.

    Args:
        sort_type: Sort type prefix.
        value: Sort value (will be converted to ISO format if datetime).

    Returns:
        GSI1 sort key string.
    """
    if isinstance(value, datetime):
        return f"{sort_type}#{value.isoformat()}"
    return f"{sort_type}#{value}"


# Common query patterns


async def query_by_pk(
    table: TableName,
    pk: str,
    sk_prefix: Optional[str] = None,
    limit: Optional[int] = None,
    scan_forward: bool = True,
    index_name: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Query items by partition key with optional sort key prefix.

    Args:
        table: Table to query.
        pk: Partition key value.
        sk_prefix: Optional sort key prefix for begins_with condition.
        limit: Maximum items to return.
        scan_forward: Sort direction (True=ascending, False=descending).
        index_name: Optional GSI name.

    Returns:
        List of deserialized items.
    """
    client = get_dynamodb_client()
    table_name = get_table_name(table)

    key_attr = "PK" if not index_name else "GSI1PK"
    sort_attr = "SK" if not index_name else "GSI1SK"

    params: Dict[str, Any] = {
        "TableName": table_name,
        "KeyConditionExpression": f"{key_attr} = :pk",
        "ExpressionAttributeValues": {":pk": {"S": pk}},
        "ScanIndexForward": scan_forward,
    }

    if index_name:
        params["IndexName"] = index_name

    if sk_prefix:
        params["KeyConditionExpression"] += f" AND begins_with({sort_attr}, :sk)"
        params["ExpressionAttributeValues"][":sk"] = {"S": sk_prefix}

    if limit:
        params["Limit"] = limit

    items: List[Dict[str, Any]] = []
    while True:
        response = client.query(**params)
        items.extend([deserialize_item(item) for item in response.get("Items", [])])

        if limit and len(items) >= limit:
            break

        if "LastEvaluatedKey" not in response:
            break

        params["ExclusiveStartKey"] = response["LastEvaluatedKey"]

    return items[:limit] if limit else items


async def get_item(
    table: TableName,
    pk: str,
    sk: str,
    consistent_read: bool = False,
) -> Optional[Dict[str, Any]]:
    """Get a single item by primary key.

    Args:
        table: Table to query.
        pk: Partition key value.
        sk: Sort key value.
        consistent_read: Whether to use strongly consistent read.

    Returns:
        Deserialized item or None if not found.
    """
    client = get_dynamodb_client()
    table_name = get_table_name(table)

    response = client.get_item(
        TableName=table_name,
        Key={"PK": {"S": pk}, "SK": {"S": sk}},
        ConsistentRead=consistent_read,
    )

    item = response.get("Item")
    return deserialize_item(item) if item else None


async def put_item(
    table: TableName,
    item: Dict[str, Any],
    condition_expression: Optional[str] = None,
) -> None:
    """Put an item into a table.

    Args:
        table: Target table.
        item: Item to put (will be serialized).
        condition_expression: Optional condition for conditional write.
    """
    client = get_dynamodb_client()
    table_name = get_table_name(table)

    params: Dict[str, Any] = {
        "TableName": table_name,
        "Item": serialize_item(item),
    }

    if condition_expression:
        params["ConditionExpression"] = condition_expression

    client.put_item(**params)


async def delete_item(
    table: TableName,
    pk: str,
    sk: str,
    condition_expression: Optional[str] = None,
) -> None:
    """Delete an item from a table.

    Args:
        table: Target table.
        pk: Partition key value.
        sk: Sort key value.
        condition_expression: Optional condition for conditional delete.
    """
    client = get_dynamodb_client()
    table_name = get_table_name(table)

    params: Dict[str, Any] = {
        "TableName": table_name,
        "Key": {"PK": {"S": pk}, "SK": {"S": sk}},
    }

    if condition_expression:
        params["ConditionExpression"] = condition_expression

    client.delete_item(**params)


async def update_item(
    table: TableName,
    pk: str,
    sk: str,
    updates: Dict[str, Any],
    condition_expression: Optional[str] = None,
) -> Dict[str, Any]:
    """Update an item with specified attributes.

    Args:
        table: Target table.
        pk: Partition key value.
        sk: Sort key value.
        updates: Dictionary of attributes to update.
        condition_expression: Optional condition for conditional update.

    Returns:
        Updated item attributes.
    """
    client = get_dynamodb_client()
    table_name = get_table_name(table)

    update_parts = []
    attr_names = {}
    attr_values = {}

    for i, (key, value) in enumerate(updates.items()):
        name_placeholder = f"#attr{i}"
        value_placeholder = f":val{i}"
        update_parts.append(f"{name_placeholder} = {value_placeholder}")
        attr_names[name_placeholder] = key
        attr_values[value_placeholder] = serialize_value(value)

    params: Dict[str, Any] = {
        "TableName": table_name,
        "Key": {"PK": {"S": pk}, "SK": {"S": sk}},
        "UpdateExpression": "SET " + ", ".join(update_parts),
        "ExpressionAttributeNames": attr_names,
        "ExpressionAttributeValues": attr_values,
        "ReturnValues": "ALL_NEW",
    }

    if condition_expression:
        params["ConditionExpression"] = condition_expression

    response = client.update_item(**params)
    return deserialize_item(response.get("Attributes", {}))


async def batch_get_items(
    table: TableName,
    keys: List[tuple[str, str]],
) -> List[Dict[str, Any]]:
    """Batch get multiple items by primary keys.

    Args:
        table: Table to query.
        keys: List of (pk, sk) tuples.

    Returns:
        List of deserialized items (order not guaranteed).
    """
    if not keys:
        return []

    client = get_dynamodb_client()
    table_name = get_table_name(table)

    items: List[Dict[str, Any]] = []
    batch_size = 100

    for i in range(0, len(keys), batch_size):
        batch_keys = keys[i : i + batch_size]
        request_keys = [
            {"PK": {"S": pk}, "SK": {"S": sk}} for pk, sk in batch_keys
        ]

        response = client.batch_get_item(
            RequestItems={table_name: {"Keys": request_keys}}
        )

        for item in response.get("Responses", {}).get(table_name, []):
            items.append(deserialize_item(item))

    return items


async def batch_write_items(
    table: TableName,
    put_items: Optional[List[Dict[str, Any]]] = None,
    delete_keys: Optional[List[tuple[str, str]]] = None,
) -> None:
    """Batch write (put/delete) multiple items.

    Args:
        table: Target table.
        put_items: List of items to put (will be serialized).
        delete_keys: List of (pk, sk) tuples to delete.
    """
    client = get_dynamodb_client()
    table_name = get_table_name(table)

    requests: List[Dict[str, Any]] = []

    if put_items:
        for item in put_items:
            requests.append({"PutRequest": {"Item": serialize_item(item)}})

    if delete_keys:
        for pk, sk in delete_keys:
            requests.append(
                {"DeleteRequest": {"Key": {"PK": {"S": pk}, "SK": {"S": sk}}}}
            )

    if not requests:
        return

    batch_size = 25
    for i in range(0, len(requests), batch_size):
        batch = requests[i : i + batch_size]
        client.batch_write_item(RequestItems={table_name: batch})


async def transact_write_items(
    items: List[Dict[str, Any]],
) -> None:
    """Execute a transactional write across tables.

    Args:
        items: List of transact write items (Put, Update, Delete, ConditionCheck).
    """
    if not items:
        return

    client = get_dynamodb_client()
    client.transact_write_items(TransactItems=items)


# Pagination utilities


class PaginatedResult(BaseModel):
    """Result container for paginated queries."""

    items: List[Dict[str, Any]]
    last_evaluated_key: Optional[str] = None
    count: int
    has_more: bool


async def query_by_pk_paginated(
    table: TableName,
    pk: str,
    sk_prefix: Optional[str] = None,
    limit: int = 100,
    scan_forward: bool = True,
    index_name: Optional[str] = None,
    cursor: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Query items by partition key with pagination support.

    Returns:
        Tuple of (items, next_cursor). next_cursor is None if no more pages.
    """
    client = get_dynamodb_client()
    table_name = get_table_name(table)

    key_attr = "PK" if not index_name else "GSI1PK"
    sort_attr = "SK" if not index_name else "GSI1SK"

    params: Dict[str, Any] = {
        "TableName": table_name,
        "KeyConditionExpression": f"{key_attr} = :pk",
        "ExpressionAttributeValues": {":pk": {"S": pk}},
        "ScanIndexForward": scan_forward,
        "Limit": limit,
    }

    if index_name:
        params["IndexName"] = index_name

    if sk_prefix:
        params["KeyConditionExpression"] += f" AND begins_with({sort_attr}, :sk)"
        params["ExpressionAttributeValues"][":sk"] = {"S": sk_prefix}

    if cursor:
        params["ExclusiveStartKey"] = decode_pagination_token(cursor)

    response = client.query(**params)
    items = [deserialize_item(item) for item in response.get("Items", [])]

    next_cursor = None
    if "LastEvaluatedKey" in response:
        next_cursor = encode_pagination_token(response["LastEvaluatedKey"])

    return items, next_cursor


def encode_pagination_token(key: Dict[str, Any]) -> str:
    """Encode a DynamoDB LastEvaluatedKey to a pagination token.

    Args:
        key: DynamoDB LastEvaluatedKey.

    Returns:
        Base64-encoded pagination token.
    """
    import base64
    import json

    return base64.urlsafe_b64encode(json.dumps(key).encode()).decode()


def decode_pagination_token(token: str) -> Dict[str, Any]:
    """Decode a pagination token to DynamoDB ExclusiveStartKey.

    Args:
        token: Base64-encoded pagination token.

    Returns:
        DynamoDB ExclusiveStartKey dictionary.
    """
    import base64
    import json

    return json.loads(base64.urlsafe_b64decode(token.encode()).decode())


# TTL utilities for audit table


def set_ttl(days: int) -> int:
    """Calculate TTL timestamp for item expiration.

    Args:
        days: Number of days until expiration.

    Returns:
        Unix timestamp for TTL attribute.
    """
    from datetime import timedelta

    expiry = datetime.now(timezone.utc) + timedelta(days=days)
    return int(expiry.timestamp())


def get_current_timestamp() -> str:
    """Get current timestamp in ISO format for created_at/updated_at fields."""
    return datetime.now(timezone.utc).isoformat()
