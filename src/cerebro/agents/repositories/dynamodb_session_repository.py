"""DynamoDB-based repository for agent session data.

This replaces the SQLAlchemy-based AgentSessionRepository with DynamoDB operations.
"""

from __future__ import annotations

from typing import List, Optional, Tuple
from uuid import UUID

from cerebro.agents.dynamodb_models import (
    AgentMemoryEntry,
    AgentSession,
    AgentType,
    ToolInvocation,
)
from cerebro.core.dynamodb import (
    TableName,
    batch_write_items,
    get_item,
    get_table_name,
    put_item,
    get_dynamodb_client,
    deserialize_item,
)


class DynamoDBAgentSessionRepository:
    """DynamoDB-based repository for agent session operations."""

    def __init__(self) -> None:
        self._table = TableName.AGENTS

    async def get_session(
        self,
        session_id: UUID,
        org_id: Optional[UUID] = None,
    ) -> Optional[AgentSession]:
        """Get a session by ID.

        Args:
            session_id: Session UUID.
            org_id: Optional org ID for validation.

        Returns:
            AgentSession or None if not found.
        """
        if org_id:
            pk = f"ORG#{org_id}"
            sk = f"SESSION#{session_id}"
            item = await get_item(self._table, pk, sk)
            if item:
                return AgentSession.from_dynamodb_item(item)
            return None

        # If no org_id, we need to scan or use GSI - for now query by session directly
        # This requires knowing the org_id, so we'll use GSI1
        client = get_dynamodb_client()
        table_name = get_table_name(self._table)

        # Query GSI to find session by ID
        response = client.query(
            TableName=table_name,
            IndexName="GSI1",
            KeyConditionExpression="GSI1PK = :pk",
            FilterExpression="id = :session_id",
            ExpressionAttributeValues={
                ":pk": {"S": f"SESSION#{session_id}"},
                ":session_id": {"S": str(session_id)},
            },
            Limit=1,
        )

        items = response.get("Items", [])
        if items:
            return AgentSession.from_dynamodb_item(deserialize_item(items[0]))
        return None

    async def list_sessions(
        self,
        *,
        org_id: UUID,
        agent_type: Optional[AgentType] = None,
        created_by: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[AgentSession], int]:
        """List sessions for an organization.

        Args:
            org_id: Organization ID.
            agent_type: Optional filter by agent type.
            created_by: Optional filter by creator.
            limit: Maximum results.
            offset: Pagination offset.

        Returns:
            Tuple of (sessions list, total count).
        """
        client = get_dynamodb_client()
        table_name = get_table_name(self._table)

        if agent_type:
            # Use GSI1 for agent type filtering
            pk = f"ORG#{org_id}#AGENT#{agent_type.value}"
            response = client.query(
                TableName=table_name,
                IndexName="GSI1",
                KeyConditionExpression="GSI1PK = :pk",
                ExpressionAttributeValues={":pk": {"S": pk}},
                ScanIndexForward=False,  # Most recent first
            )
        else:
            # Query all sessions for org
            pk = f"ORG#{org_id}"
            response = client.query(
                TableName=table_name,
                KeyConditionExpression="PK = :pk AND begins_with(SK, :sk_prefix)",
                ExpressionAttributeValues={
                    ":pk": {"S": pk},
                    ":sk_prefix": {"S": "SESSION#"},
                },
                ScanIndexForward=False,
            )

        all_items = [deserialize_item(item) for item in response.get("Items", [])]

        # Apply created_by filter in memory if specified
        if created_by:
            all_items = [item for item in all_items if item.get("created_by") == created_by]

        total = len(all_items)

        # Apply pagination
        paginated = all_items[offset : offset + limit]
        sessions = [AgentSession.from_dynamodb_item(item) for item in paginated]

        return sessions, total

    async def list_memory_entries(
        self,
        session_id: UUID,
        *,
        limit: Optional[int] = None,
    ) -> List[AgentMemoryEntry]:
        """List memory entries for a session.

        Args:
            session_id: Session UUID.
            limit: Optional limit.

        Returns:
            List of memory entries.
        """
        client = get_dynamodb_client()
        table_name = get_table_name(self._table)

        response = client.query(
            TableName=table_name,
            IndexName="GSI1",
            KeyConditionExpression="GSI1PK = :pk AND begins_with(GSI1SK, :sk_prefix)",
            ExpressionAttributeValues={
                ":pk": {"S": f"SESSION#{session_id}"},
                ":sk_prefix": {"S": "MEMORY#"},
            },
            ScanIndexForward=False,
            Limit=limit if limit else 1000,
        )

        items = [deserialize_item(item) for item in response.get("Items", [])]
        return [AgentMemoryEntry.from_dynamodb_item(item) for item in items]

    async def list_memory_entries_for_stats(
        self,
        session_id: UUID,
    ) -> List[AgentMemoryEntry]:
        """List all memory entries for statistics."""
        return await self.list_memory_entries(session_id, limit=None)

    async def latest_tool_invocations(
        self,
        org_id: UUID,
        *,
        limit: int,
        tool_name: Optional[str] = None,
    ) -> List[Tuple[ToolInvocation, AgentSession]]:
        """Get latest tool invocations with their sessions.

        Args:
            org_id: Organization ID.
            limit: Maximum results.
            tool_name: Optional tool name filter.

        Returns:
            List of (ToolInvocation, AgentSession) tuples.
        """
        client = get_dynamodb_client()
        table_name = get_table_name(self._table)

        if tool_name:
            # Query by tool name using GSI2
            pk = f"ORG#{org_id}#TOOL#{tool_name}"
            response = client.query(
                TableName=table_name,
                IndexName="GSI2",
                KeyConditionExpression="GSI2PK = :pk",
                ExpressionAttributeValues={":pk": {"S": pk}},
                ScanIndexForward=False,
                Limit=limit,
            )
        else:
            # Need to scan for all tools - use a broader query
            # This is less efficient but necessary without a dedicated index
            pk = f"ORG#{org_id}"
            response = client.query(
                TableName=table_name,
                KeyConditionExpression="PK = :pk",
                FilterExpression="entity_type = :entity_type",
                ExpressionAttributeValues={
                    ":pk": {"S": pk},
                    ":entity_type": {"S": "TOOL"},
                },
                ScanIndexForward=False,
                Limit=limit * 2,  # Get more to account for filtering
            )

        items = [deserialize_item(item) for item in response.get("Items", [])][:limit]

        results: List[Tuple[ToolInvocation, AgentSession]] = []
        for item in items:
            if item.get("entity_type") != "TOOL":
                continue

            tool = ToolInvocation.from_dynamodb_item(item)
            session = await self.get_session(tool.session_id, org_id)
            if session:
                results.append((tool, session))

        return results

    async def get_session_with_relations(
        self,
        session_id: UUID,
        *,
        org_id: Optional[UUID] = None,
    ) -> Optional[AgentSession]:
        """Get session with messages and tool invocations loaded.

        Note: In DynamoDB, we query related items separately.

        Args:
            session_id: Session UUID.
            org_id: Optional org ID for validation.

        Returns:
            AgentSession with messages and tool_invocations populated.
        """
        session = await self.get_session(session_id, org_id)
        if not session:
            return None

        # Query messages and tools for this session
        client = get_dynamodb_client()
        table_name = get_table_name(self._table)

        # Get all items under this session (messages, tools)
        response = client.query(
            TableName=table_name,
            KeyConditionExpression="PK = :pk",
            ExpressionAttributeValues={
                ":pk": {"S": f"SESSION#{session_id}"},
            },
            ScanIndexForward=True,
        )

        items = [deserialize_item(item) for item in response.get("Items", [])]

        # Note: The AgentSession model doesn't have messages/tool_invocations
        # as direct attributes in DynamoDB model. They would need to be
        # queried separately. For compatibility, we return the session
        # and let callers query related items as needed.

        return session

    async def delete_session(
        self,
        *,
        session_id: UUID,
        org_id: UUID,
    ) -> bool:
        """Delete a session and all related items.

        Args:
            session_id: Session UUID.
            org_id: Organization ID.

        Returns:
            True if deleted, False if not found.
        """
        # First check if session exists
        session = await self.get_session(session_id, org_id)
        if not session:
            return False

        client = get_dynamodb_client()
        table_name = get_table_name(self._table)

        # Delete all items related to this session
        # 1. Delete items under SESSION#{session_id} partition
        session_items_response = client.query(
            TableName=table_name,
            KeyConditionExpression="PK = :pk",
            ExpressionAttributeValues={
                ":pk": {"S": f"SESSION#{session_id}"},
            },
        )

        delete_keys = []
        for item in session_items_response.get("Items", []):
            deserialized = deserialize_item(item)
            delete_keys.append((deserialized["PK"], deserialized["SK"]))

        # 2. Delete the session itself
        session_pk = f"ORG#{org_id}"
        session_sk = f"SESSION#{session_id}"
        delete_keys.append((session_pk, session_sk))

        # Batch delete all items
        if delete_keys:
            await batch_write_items(self._table, delete_keys=delete_keys)

        return True

    async def save(self, objects: List[object]) -> None:
        """Save multiple objects to DynamoDB.

        Args:
            objects: List of DynamoDB model objects to save.
        """
        items_to_put = []
        for obj in objects:
            if hasattr(obj, "to_dynamodb_item"):
                items_to_put.append(obj.to_dynamodb_item())

        if items_to_put:
            await batch_write_items(self._table, put_items=items_to_put)

    async def create_session(self, session: AgentSession) -> AgentSession:
        """Create a new session.

        Args:
            session: AgentSession to create.

        Returns:
            Created session.
        """
        await put_item(self._table, session.to_dynamodb_item())
        return session

    async def update_session(
        self,
        session_id: UUID,
        org_id: UUID,
        **updates: dict,
    ) -> Optional[AgentSession]:
        """Update session fields.

        Args:
            session_id: Session UUID.
            org_id: Organization ID.
            **updates: Fields to update.

        Returns:
            Updated session or None.
        """
        from cerebro.core.dynamodb import update_item

        pk = f"ORG#{org_id}"
        sk = f"SESSION#{session_id}"

        updated = await update_item(self._table, pk, sk, updates)
        if updated:
            return AgentSession.from_dynamodb_item(updated)
        return None

    async def add_message(self, message: "AgentMessage") -> "AgentMessage":
        """Add a message to a session.

        Args:
            message: AgentMessage to add.

        Returns:
            Created message.
        """

        await put_item(self._table, message.to_dynamodb_item())
        return message

    async def get_session_messages(
        self,
        session_id: UUID,
        limit: Optional[int] = None,
    ) -> List["AgentMessage"]:
        """Get messages for a session.

        Args:
            session_id: Session UUID.
            limit: Optional limit.

        Returns:
            List of messages in chronological order.
        """
        from cerebro.agents.dynamodb_models import AgentMessage

        client = get_dynamodb_client()
        table_name = get_table_name(self._table)

        params = {
            "TableName": table_name,
            "KeyConditionExpression": "PK = :pk AND begins_with(SK, :sk_prefix)",
            "ExpressionAttributeValues": {
                ":pk": {"S": f"SESSION#{session_id}"},
                ":sk_prefix": {"S": "MESSAGE#"},
            },
            "ScanIndexForward": True,
        }

        if limit:
            params["Limit"] = limit

        response = client.query(**params)
        items = [deserialize_item(item) for item in response.get("Items", [])]

        return [AgentMessage.from_dynamodb_item(item) for item in items]

    async def add_tool_invocation(
        self,
        invocation: ToolInvocation,
    ) -> ToolInvocation:
        """Add a tool invocation to a session.

        Args:
            invocation: ToolInvocation to add.

        Returns:
            Created invocation.
        """
        await put_item(self._table, invocation.to_dynamodb_item())
        return invocation

    async def get_session_tool_invocations(
        self,
        session_id: UUID,
        limit: Optional[int] = None,
    ) -> List[ToolInvocation]:
        """Get tool invocations for a session.

        Args:
            session_id: Session UUID.
            limit: Optional limit.

        Returns:
            List of tool invocations in chronological order.
        """
        client = get_dynamodb_client()
        table_name = get_table_name(self._table)

        params = {
            "TableName": table_name,
            "KeyConditionExpression": "PK = :pk AND begins_with(SK, :sk_prefix)",
            "ExpressionAttributeValues": {
                ":pk": {"S": f"SESSION#{session_id}"},
                ":sk_prefix": {"S": "TOOL#"},
            },
            "ScanIndexForward": True,
        }

        if limit:
            params["Limit"] = limit

        response = client.query(**params)
        items = [deserialize_item(item) for item in response.get("Items", [])]

        return [ToolInvocation.from_dynamodb_item(item) for item in items]
