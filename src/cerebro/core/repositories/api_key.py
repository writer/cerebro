"""DynamoDB repository for API keys."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog

from cerebro.core.api_keys import APIKey
from cerebro.core.config import settings
from cerebro.core.dynamodb_client import get_client

logger = structlog.get_logger(__name__)


class APIKeyRepository:
    """Repository for API key storage in DynamoDB."""

    def __init__(self, table_name: str | None = None):
        self.table_name = table_name or settings.dynamodb_users_table
        self._client = None

    @property
    def client(self):
        if self._client is None:
            self._client = get_client()
        return self._client

    def _to_item(self, api_key: APIKey) -> dict[str, Any]:
        """Convert APIKey to DynamoDB item."""
        item = {
            "PK": f"ORG#{api_key.org_id}",
            "SK": f"APIKEY#{api_key.key_id}",
            "GSI1PK": f"APIKEY_HASH#{api_key.key_hash}",
            "GSI1SK": f"APIKEY#{api_key.key_id}",
            "entity_type": "api_key",
            "key_id": str(api_key.key_id),
            "org_id": str(api_key.org_id),
            "name": api_key.name,
            "key_hash": api_key.key_hash,
            "key_prefix": api_key.key_prefix,
            "scopes": api_key.scopes,
            "rate_limit_per_minute": api_key.rate_limit_per_minute,
            "is_active": api_key.is_active,
            "is_test_key": api_key.is_test_key,
            "created_at": api_key.created_at.isoformat(),
        }

        if api_key.description:
            item["description"] = api_key.description
        if api_key.expires_at:
            item["expires_at"] = api_key.expires_at.isoformat()
            item["ttl"] = int(api_key.expires_at.timestamp())
        if api_key.last_used_at:
            item["last_used_at"] = api_key.last_used_at.isoformat()
        if api_key.last_used_ip:
            item["last_used_ip"] = api_key.last_used_ip
        if api_key.created_by:
            item["created_by"] = str(api_key.created_by)
        if api_key.revoked_at:
            item["revoked_at"] = api_key.revoked_at.isoformat()
        if api_key.revoked_by:
            item["revoked_by"] = str(api_key.revoked_by)
        if api_key.metadata:
            item["metadata"] = api_key.metadata

        return item

    def _from_item(self, item: dict[str, Any]) -> APIKey:
        """Convert DynamoDB item to APIKey."""
        return APIKey(
            key_id=UUID(item["key_id"]),
            org_id=UUID(item["org_id"]),
            name=item["name"],
            description=item.get("description"),
            key_hash=item["key_hash"],
            key_prefix=item["key_prefix"],
            scopes=item.get("scopes", []),
            rate_limit_per_minute=item.get("rate_limit_per_minute", 100),
            is_active=item.get("is_active", True),
            is_test_key=item.get("is_test_key", False),
            expires_at=(
                datetime.fromisoformat(item["expires_at"])
                if item.get("expires_at")
                else None
            ),
            last_used_at=(
                datetime.fromisoformat(item["last_used_at"])
                if item.get("last_used_at")
                else None
            ),
            last_used_ip=item.get("last_used_ip"),
            created_at=datetime.fromisoformat(item["created_at"]),
            created_by=UUID(item["created_by"]) if item.get("created_by") else None,
            revoked_at=(
                datetime.fromisoformat(item["revoked_at"])
                if item.get("revoked_at")
                else None
            ),
            revoked_by=UUID(item["revoked_by"]) if item.get("revoked_by") else None,
            metadata=item.get("metadata", {}),
        )

    async def create(self, api_key: APIKey) -> APIKey:
        """Create a new API key."""
        item = self._to_item(api_key)

        await self.client.put_item(
            TableName=self.table_name,
            Item=self._serialize_item(item),
            ConditionExpression="attribute_not_exists(PK)",
        )

        logger.info(
            "api_key_stored",
            key_id=str(api_key.key_id),
            org_id=str(api_key.org_id),
        )

        return api_key

    async def get_by_hash(self, key_hash: str) -> APIKey | None:
        """Look up an API key by its hash using GSI."""
        response = await self.client.query(
            TableName=self.table_name,
            IndexName="GSI1",
            KeyConditionExpression="GSI1PK = :pk",
            ExpressionAttributeValues={
                ":pk": {"S": f"APIKEY_HASH#{key_hash}"},
            },
            Limit=1,
        )

        items = response.get("Items", [])
        if not items:
            return None

        return self._from_item(self._deserialize_item(items[0]))

    async def get(self, key_id: UUID, org_id: UUID) -> APIKey | None:
        """Get an API key by ID."""
        response = await self.client.get_item(
            TableName=self.table_name,
            Key={
                "PK": {"S": f"ORG#{org_id}"},
                "SK": {"S": f"APIKEY#{key_id}"},
            },
        )

        item = response.get("Item")
        if not item:
            return None

        return self._from_item(self._deserialize_item(item))

    async def list_by_org(
        self,
        org_id: UUID,
        include_revoked: bool = False,
        limit: int = 100,
    ) -> list[APIKey]:
        """List API keys for an organization."""
        response = await self.client.query(
            TableName=self.table_name,
            KeyConditionExpression="PK = :pk AND begins_with(SK, :sk_prefix)",
            ExpressionAttributeValues={
                ":pk": {"S": f"ORG#{org_id}"},
                ":sk_prefix": {"S": "APIKEY#"},
            },
            Limit=limit,
        )

        keys = []
        for item in response.get("Items", []):
            api_key = self._from_item(self._deserialize_item(item))
            if include_revoked or api_key.revoked_at is None:
                keys.append(api_key)

        return keys

    async def update(
        self,
        key_id: UUID,
        org_id: UUID,
        **updates: Any,
    ) -> APIKey | None:
        """Update an API key."""
        update_expr_parts = []
        expr_attr_values = {}
        expr_attr_names = {}

        for key, value in updates.items():
            if value is not None:
                placeholder = f":{key}"
                name_placeholder = f"#{key}"
                update_expr_parts.append(f"{name_placeholder} = {placeholder}")
                expr_attr_names[name_placeholder] = key

                if isinstance(value, datetime):
                    expr_attr_values[placeholder] = {"S": value.isoformat()}
                elif isinstance(value, bool):
                    expr_attr_values[placeholder] = {"BOOL": value}
                elif isinstance(value, int):
                    expr_attr_values[placeholder] = {"N": str(value)}
                elif isinstance(value, UUID):
                    expr_attr_values[placeholder] = {"S": str(value)}
                elif isinstance(value, list):
                    expr_attr_values[placeholder] = {"L": [{"S": str(v)} for v in value]}
                else:
                    expr_attr_values[placeholder] = {"S": str(value)}

        if not update_expr_parts:
            return await self.get(key_id, org_id)

        update_expr = "SET " + ", ".join(update_expr_parts)

        try:
            response = await self.client.update_item(
                TableName=self.table_name,
                Key={
                    "PK": {"S": f"ORG#{org_id}"},
                    "SK": {"S": f"APIKEY#{key_id}"},
                },
                UpdateExpression=update_expr,
                ExpressionAttributeNames=expr_attr_names,
                ExpressionAttributeValues=expr_attr_values,
                ReturnValues="ALL_NEW",
                ConditionExpression="attribute_exists(PK)",
            )

            return self._from_item(self._deserialize_item(response["Attributes"]))
        except Exception as e:
            if "ConditionalCheckFailedException" in str(e):
                return None
            raise

    async def revoke(
        self,
        key_id: UUID,
        org_id: UUID,
        revoked_by: UUID | None = None,
    ) -> bool:
        """Revoke an API key."""
        now = datetime.now(UTC)
        updates = {
            "is_active": False,
            "revoked_at": now,
        }
        if revoked_by:
            updates["revoked_by"] = revoked_by

        result = await self.update(key_id, org_id, **updates)
        return result is not None

    async def update_last_used(
        self,
        key_id: UUID,
        org_id: UUID,
        ip_address: str | None = None,
    ) -> None:
        """Update the last used timestamp."""
        updates = {"last_used_at": datetime.now(UTC)}
        if ip_address:
            updates["last_used_ip"] = ip_address

        await self.update(key_id, org_id, **updates)

    async def delete(self, key_id: UUID, org_id: UUID) -> bool:
        """Delete an API key (hard delete - use revoke for soft delete)."""
        try:
            await self.client.delete_item(
                TableName=self.table_name,
                Key={
                    "PK": {"S": f"ORG#{org_id}"},
                    "SK": {"S": f"APIKEY#{key_id}"},
                },
                ConditionExpression="attribute_exists(PK)",
            )
            return True
        except Exception as e:
            if "ConditionalCheckFailedException" in str(e):
                return False
            raise

    def _serialize_item(self, item: dict[str, Any]) -> dict[str, Any]:
        """Serialize a dict to DynamoDB format."""
        result = {}
        for key, value in item.items():
            if isinstance(value, str):
                result[key] = {"S": value}
            elif isinstance(value, bool):
                result[key] = {"BOOL": value}
            elif isinstance(value, int):
                result[key] = {"N": str(value)}
            elif isinstance(value, list):
                result[key] = {"L": [{"S": str(v)} for v in value]}
            elif isinstance(value, dict):
                result[key] = {"M": self._serialize_item(value)}
            elif value is None:
                continue
            else:
                result[key] = {"S": str(value)}
        return result

    def _deserialize_item(self, item: dict[str, Any]) -> dict[str, Any]:
        """Deserialize a DynamoDB item to dict."""
        result = {}
        for key, value in item.items():
            if "S" in value:
                result[key] = value["S"]
            elif "N" in value:
                result[key] = int(value["N"])
            elif "BOOL" in value:
                result[key] = value["BOOL"]
            elif "L" in value:
                result[key] = [self._deserialize_value(v) for v in value["L"]]
            elif "M" in value:
                result[key] = self._deserialize_item(value["M"])
            elif "NULL" in value:
                result[key] = None
        return result

    def _deserialize_value(self, value: dict[str, Any]) -> Any:
        """Deserialize a single DynamoDB value."""
        if "S" in value:
            return value["S"]
        elif "N" in value:
            return int(value["N"])
        elif "BOOL" in value:
            return value["BOOL"]
        elif "L" in value:
            return [self._deserialize_value(v) for v in value["L"]]
        elif "M" in value:
            return self._deserialize_item(value["M"])
        return None
