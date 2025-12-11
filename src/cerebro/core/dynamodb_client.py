"""DynamoDB client for Cerebro.

This module provides a properly configured DynamoDB client with all necessary
utilities for the single-table design pattern.

Note: boto3 is synchronous. We wrap operations in async functions using
run_in_executor for compatibility with the async FastAPI application.
"""

from __future__ import annotations

import asyncio
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from functools import partial
from typing import Any, Dict, List, Optional, Tuple, TypeVar, Union
from uuid import UUID

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger(__name__)

# Thread pool for running boto3 operations
_executor = ThreadPoolExecutor(max_workers=10)


class DynamoDBError(Exception):
    """Base exception for DynamoDB operations."""
    pass


class ItemNotFoundError(DynamoDBError):
    """Raised when an item is not found."""
    pass


class ConditionalCheckFailedError(DynamoDBError):
    """Raised when a conditional check fails."""
    pass


class ValidationError(DynamoDBError):
    """Raised when validation fails."""
    pass


def _get_settings():
    """Get settings lazily to avoid circular imports."""
    try:
        from cerebro.core.config import settings
        return settings
    except Exception:
        return None


class TableName(str, Enum):
    """DynamoDB table identifiers."""
    CORE = "core"
    AUDIT = "audit"
    AGENTS = "agents"
    NOTIFICATIONS = "notifications"
    USERS = "users"


def get_table_name(table: TableName) -> str:
    """Get actual table name from environment or settings."""
    env_map = {
        TableName.CORE: "DYNAMODB_CORE_TABLE",
        TableName.AUDIT: "DYNAMODB_AUDIT_TABLE",
        TableName.AGENTS: "DYNAMODB_AGENTS_TABLE",
        TableName.NOTIFICATIONS: "DYNAMODB_NOTIFICATIONS_TABLE",
        TableName.USERS: "DYNAMODB_USERS_TABLE",
    }
    default_map = {
        TableName.CORE: "cerebro-core",
        TableName.AUDIT: "cerebro-audit",
        TableName.AGENTS: "cerebro-agents",
        TableName.NOTIFICATIONS: "cerebro-notifications",
        TableName.USERS: "cerebro-users",
    }
    
    # Check environment first
    env_var = env_map[table]
    if env_var in os.environ:
        return os.environ[env_var]
    
    # Then check settings
    settings = _get_settings()
    if settings:
        attr_map = {
            TableName.CORE: "dynamodb_core_table",
            TableName.AUDIT: "dynamodb_audit_table",
            TableName.AGENTS: "dynamodb_agents_table",
            TableName.NOTIFICATIONS: "dynamodb_notifications_table",
            TableName.USERS: "dynamodb_users_table",
        }
        return getattr(settings, attr_map[table], default_map[table])
    
    return default_map[table]


def get_endpoint_url() -> Optional[str]:
    """Get DynamoDB endpoint URL for local development."""
    url = os.environ.get("DYNAMODB_ENDPOINT_URL")
    if url:
        return url
    settings = _get_settings()
    if settings and hasattr(settings, "dynamodb_endpoint_url"):
        return settings.dynamodb_endpoint_url
    return None


def get_region() -> str:
    """Get AWS region."""
    return os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))


# Client singleton
_client: Optional[boto3.client] = None


def get_client() -> boto3.client:
    """Get or create DynamoDB client."""
    global _client
    if _client is None:
        config = Config(
            retries={"max_attempts": 3, "mode": "adaptive"},
            connect_timeout=5,
            read_timeout=30,
        )
        kwargs: Dict[str, Any] = {
            "region_name": get_region(),
            "config": config,
        }
        endpoint = get_endpoint_url()
        if endpoint:
            kwargs["endpoint_url"] = endpoint
        _client = boto3.client("dynamodb", **kwargs)
    return _client


def reset_client() -> None:
    """Reset client (for testing)."""
    global _client
    _client = None


# Serialization utilities

def to_dynamodb(value: Any) -> Dict[str, Any]:
    """Convert Python value to DynamoDB AttributeValue."""
    if value is None:
        return {"NULL": True}
    if isinstance(value, bool):
        return {"BOOL": value}
    # Check Enum before str because str Enums inherit from str
    if isinstance(value, Enum):
        return {"S": value.value}
    if isinstance(value, str):
        return {"S": value}
    if isinstance(value, bytes):
        return {"B": value}
    if isinstance(value, (int, float, Decimal)):
        return {"N": str(value)}
    if isinstance(value, UUID):
        return {"S": str(value)}
    if isinstance(value, datetime):
        return {"S": value.isoformat()}
    if isinstance(value, (list, tuple)):
        return {"L": [to_dynamodb(v) for v in value]}
    if isinstance(value, dict):
        return {"M": {k: to_dynamodb(v) for k, v in value.items()}}
    if isinstance(value, set):
        if not value:
            return {"L": []}
        first = next(iter(value))
        if isinstance(first, str):
            return {"SS": list(value)}
        if isinstance(first, (int, float)):
            return {"NS": [str(v) for v in value]}
        return {"L": [to_dynamodb(v) for v in value]}
    return {"S": str(value)}


def from_dynamodb(attr: Dict[str, Any]) -> Any:
    """Convert DynamoDB AttributeValue to Python value."""
    if "NULL" in attr:
        return None
    if "BOOL" in attr:
        return attr["BOOL"]
    if "S" in attr:
        return attr["S"]
    if "N" in attr:
        s = attr["N"]
        return float(s) if "." in s else int(s)
    if "B" in attr:
        return attr["B"]
    if "L" in attr:
        return [from_dynamodb(v) for v in attr["L"]]
    if "M" in attr:
        return {k: from_dynamodb(v) for k, v in attr["M"].items()}
    if "SS" in attr:
        return set(attr["SS"])
    if "NS" in attr:
        return {float(n) if "." in n else int(n) for n in attr["NS"]}
    if "BS" in attr:
        return set(attr["BS"])
    return None


def serialize_item(item: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Serialize dict to DynamoDB item."""
    return {k: to_dynamodb(v) for k, v in item.items() if v is not None}


def deserialize_item(item: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Deserialize DynamoDB item to dict."""
    return {k: from_dynamodb(v) for k, v in item.items()}


# Key builders for single-table design

def pk(entity_type: str, id_value: Union[str, UUID]) -> str:
    """Build partition key."""
    return f"{entity_type}#{id_value}"


def sk(entity_type: str, id_value: Union[str, UUID], *parts: str) -> str:
    """Build sort key."""
    key = f"{entity_type}#{id_value}"
    for part in parts:
        key += f"#{part}"
    return key


# Async wrappers for DynamoDB operations

async def put_item(
    table: TableName,
    item: Dict[str, Any],
    condition: Optional[str] = None,
) -> None:
    """Put item into table.
    
    Raises:
        ConditionalCheckFailedError: If condition expression fails
        DynamoDBError: For other DynamoDB errors
    """
    client = get_client()
    table_name = get_table_name(table)
    params: Dict[str, Any] = {
        "TableName": table_name,
        "Item": serialize_item(item),
    }
    if condition:
        params["ConditionExpression"] = condition
    
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(_executor, partial(client.put_item, **params))
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "ConditionalCheckFailedException":
            raise ConditionalCheckFailedError(f"Condition failed for put_item on {table_name}")
        logger.error(f"DynamoDB put_item error: {e}", extra={"table": table_name})
        raise DynamoDBError(f"Failed to put item: {e}")


async def get_item(
    table: TableName,
    pk_val: str,
    sk_val: str,
    consistent: bool = False,
) -> Optional[Dict[str, Any]]:
    """Get single item by key."""
    client = get_client()
    params = {
        "TableName": get_table_name(table),
        "Key": {"PK": {"S": pk_val}, "SK": {"S": sk_val}},
        "ConsistentRead": consistent,
    }
    
    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(_executor, partial(client.get_item, **params))
    
    item = response.get("Item")
    return deserialize_item(item) if item else None


async def delete_item(
    table: TableName,
    pk_val: str,
    sk_val: str,
    condition: Optional[str] = None,
) -> bool:
    """Delete item by key."""
    client = get_client()
    params: Dict[str, Any] = {
        "TableName": get_table_name(table),
        "Key": {"PK": {"S": pk_val}, "SK": {"S": sk_val}},
    }
    if condition:
        params["ConditionExpression"] = condition
    
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(_executor, partial(client.delete_item, **params))
        return True
    except ClientError:
        return False


async def update_item(
    table: TableName,
    pk_val: str,
    sk_val: str,
    updates: Dict[str, Any],
    condition: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Update item attributes. Returns None if updates dict is empty."""
    if not updates:
        # No updates to apply, return current item
        return await get_item(table, pk_val, sk_val)
    
    client = get_client()
    
    set_parts = []
    names = {}
    values = {}
    
    for i, (key, val) in enumerate(updates.items()):
        name_key = f"#k{i}"
        val_key = f":v{i}"
        set_parts.append(f"{name_key} = {val_key}")
        names[name_key] = key
        values[val_key] = to_dynamodb(val)
    
    params: Dict[str, Any] = {
        "TableName": get_table_name(table),
        "Key": {"PK": {"S": pk_val}, "SK": {"S": sk_val}},
        "UpdateExpression": "SET " + ", ".join(set_parts),
        "ExpressionAttributeNames": names,
        "ExpressionAttributeValues": values,
        "ReturnValues": "ALL_NEW",
    }
    if condition:
        params["ConditionExpression"] = condition
    
    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(_executor, partial(client.update_item, **params))
    
    return deserialize_item(response.get("Attributes", {}))


async def query(
    table: TableName,
    pk_val: str,
    sk_prefix: Optional[str] = None,
    sk_between: Optional[Tuple[str, str]] = None,
    index: Optional[str] = None,
    limit: Optional[int] = None,
    forward: bool = True,
    filter_expr: Optional[str] = None,
    filter_values: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Query items by partition key."""
    client = get_client()
    
    pk_attr = "GSI1PK" if index == "GSI1" else ("GSI2PK" if index == "GSI2" else ("GSI3PK" if index == "GSI3" else "PK"))
    sk_attr = "GSI1SK" if index == "GSI1" else ("GSI2SK" if index == "GSI2" else ("GSI3SK" if index == "GSI3" else "SK"))
    
    key_expr = f"{pk_attr} = :pk"
    expr_values: Dict[str, Any] = {":pk": {"S": pk_val}}
    
    if sk_prefix:
        key_expr += f" AND begins_with({sk_attr}, :sk)"
        expr_values[":sk"] = {"S": sk_prefix}
    elif sk_between:
        key_expr += f" AND {sk_attr} BETWEEN :sk_start AND :sk_end"
        expr_values[":sk_start"] = {"S": sk_between[0]}
        expr_values[":sk_end"] = {"S": sk_between[1]}
    
    params: Dict[str, Any] = {
        "TableName": get_table_name(table),
        "KeyConditionExpression": key_expr,
        "ExpressionAttributeValues": expr_values,
        "ScanIndexForward": forward,
    }
    
    if index:
        params["IndexName"] = index
    if limit:
        params["Limit"] = limit
    if filter_expr:
        params["FilterExpression"] = filter_expr
        if filter_values:
            for k, v in filter_values.items():
                params["ExpressionAttributeValues"][k] = to_dynamodb(v)
    
    loop = asyncio.get_event_loop()
    
    items: List[Dict[str, Any]] = []
    while True:
        response = await loop.run_in_executor(_executor, partial(client.query, **params))
        items.extend([deserialize_item(item) for item in response.get("Items", [])])
        
        if limit and len(items) >= limit:
            break
        if "LastEvaluatedKey" not in response:
            break
        params["ExclusiveStartKey"] = response["LastEvaluatedKey"]
    
    return items[:limit] if limit else items


async def batch_get(
    table: TableName,
    keys: List[Tuple[str, str]],
) -> List[Dict[str, Any]]:
    """Batch get items by keys."""
    if not keys:
        return []
    
    client = get_client()
    table_name = get_table_name(table)
    loop = asyncio.get_event_loop()
    
    items: List[Dict[str, Any]] = []
    
    # Process in batches of 100
    for i in range(0, len(keys), 100):
        batch_keys = keys[i:i + 100]
        request_items = {
            table_name: {
                "Keys": [{"PK": {"S": pk}, "SK": {"S": sk}} for pk, sk in batch_keys]
            }
        }
        
        response = await loop.run_in_executor(
            _executor,
            partial(client.batch_get_item, RequestItems=request_items)
        )
        
        for item in response.get("Responses", {}).get(table_name, []):
            items.append(deserialize_item(item))
    
    return items


async def batch_write(
    table: TableName,
    put_items: Optional[List[Dict[str, Any]]] = None,
    delete_keys: Optional[List[Tuple[str, str]]] = None,
) -> None:
    """Batch write items."""
    client = get_client()
    table_name = get_table_name(table)
    loop = asyncio.get_event_loop()
    
    requests: List[Dict[str, Any]] = []
    
    if put_items:
        for item in put_items:
            requests.append({"PutRequest": {"Item": serialize_item(item)}})
    
    if delete_keys:
        for pk_val, sk_val in delete_keys:
            requests.append({
                "DeleteRequest": {
                    "Key": {"PK": {"S": pk_val}, "SK": {"S": sk_val}}
                }
            })
    
    # Process in batches of 25
    for i in range(0, len(requests), 25):
        batch = requests[i:i + 25]
        await loop.run_in_executor(
            _executor,
            partial(client.batch_write_item, RequestItems={table_name: batch})
        )


async def transact_write(items: List[Dict[str, Any]]) -> None:
    """Transactional write."""
    if not items:
        return
    
    client = get_client()
    loop = asyncio.get_event_loop()
    
    await loop.run_in_executor(
        _executor,
        partial(client.transact_write_items, TransactItems=items)
    )


# Utility functions

def now_iso() -> str:
    """Get current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def ttl_timestamp(days: int) -> int:
    """Calculate TTL timestamp (seconds since epoch)."""
    from datetime import timedelta
    expiry = datetime.now(timezone.utc) + timedelta(days=days)
    return int(expiry.timestamp())


def parse_uuid(value: str) -> UUID:
    """Parse UUID from string."""
    return UUID(value)


def encode_cursor(key: Dict[str, Any]) -> str:
    """Encode LastEvaluatedKey to cursor string."""
    import base64
    return base64.urlsafe_b64encode(json.dumps(key).encode()).decode()


def decode_cursor(cursor: str) -> Dict[str, Any]:
    """Decode cursor string to ExclusiveStartKey."""
    import base64
    return json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())


async def health_check() -> Dict[str, Any]:
    """Check DynamoDB connectivity and table status.
    
    Returns:
        Dict with status, tables info, and any errors
    """
    client = get_client()
    loop = asyncio.get_event_loop()
    
    results = {
        "healthy": True,
        "tables": {},
        "errors": [],
    }
    
    for table in TableName:
        table_name = get_table_name(table)
        try:
            response = await loop.run_in_executor(
                _executor,
                partial(client.describe_table, TableName=table_name)
            )
            table_info = response.get("Table", {})
            results["tables"][table.value] = {
                "name": table_name,
                "status": table_info.get("TableStatus"),
                "item_count": table_info.get("ItemCount", 0),
            }
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "ResourceNotFoundException":
                results["tables"][table.value] = {
                    "name": table_name,
                    "status": "NOT_FOUND",
                    "error": "Table does not exist",
                }
                results["errors"].append(f"Table {table_name} not found")
            else:
                results["tables"][table.value] = {
                    "name": table_name,
                    "status": "ERROR",
                    "error": str(e),
                }
                results["errors"].append(f"Error checking {table_name}: {e}")
            results["healthy"] = False
    
    return results


def get_table_arn(table: TableName) -> str:
    """Get table ARN for IAM policies."""
    region = get_region()
    # Note: In production, get account ID from STS
    account_id = os.environ.get("AWS_ACCOUNT_ID", "*")
    table_name = get_table_name(table)
    return f"arn:aws:dynamodb:{region}:{account_id}:table/{table_name}"
