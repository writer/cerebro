"""DynamoDB-based repositories for core entities.

These repositories provide data access patterns for core Cerebro entities
using DynamoDB instead of SQLAlchemy.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from cerebro.core.dynamodb import (
    TableName,
    batch_get_items,
    batch_write_items,
    delete_item,
    get_dynamodb_client,
    get_item,
    get_table_name,
    put_item,
    query_by_pk,
    update_item,
    deserialize_item,
    serialize_item,
)
from cerebro.core.dynamodb_models import (
    Account,
    AuditEvent,
    ConfigSnapshot,
    EntityType,
    Finding,
    FindingStatus,
    IamEdge,
    Organization,
    Policy,
    Principal,
    Provider,
    Resource,
    Rule,
    Severity,
    Suppression,
)


class OrganizationRepository:
    """Repository for Organization entity operations."""

    def __init__(self) -> None:
        self._table = TableName.CORE

    async def get(self, org_id: UUID) -> Optional[Organization]:
        """Get organization by ID."""
        pk = f"ORG#{org_id}"
        sk = f"ORG#{org_id}"
        item = await get_item(self._table, pk, sk)
        if item:
            return Organization.from_dynamodb_item(item)
        return None

    async def create(self, org: Organization) -> Organization:
        """Create a new organization."""
        await put_item(
            self._table,
            org.to_dynamodb_item(),
            condition_expression="attribute_not_exists(PK)",
        )
        return org

    async def update(
        self,
        org_id: UUID,
        **updates: Any,
    ) -> Optional[Organization]:
        """Update organization fields."""
        pk = f"ORG#{org_id}"
        sk = f"ORG#{org_id}"
        updated = await update_item(self._table, pk, sk, updates)
        if updated:
            return Organization.from_dynamodb_item(updated)
        return None

    async def delete(self, org_id: UUID) -> bool:
        """Delete an organization."""
        pk = f"ORG#{org_id}"
        sk = f"ORG#{org_id}"
        try:
            await delete_item(self._table, pk, sk)
            return True
        except Exception:
            return False

    async def list_all(
        self,
        limit: int = 100,
        last_key: Optional[str] = None,
    ) -> Tuple[List[Organization], Optional[str]]:
        """List all organizations."""
        client = get_dynamodb_client()
        table_name = get_table_name(self._table)

        params: Dict[str, Any] = {
            "TableName": table_name,
            "IndexName": "GSI3",
            "KeyConditionExpression": "GSI3PK = :pk",
            "ExpressionAttributeValues": {":pk": {"S": "ORG#ALL"}},
            "ScanIndexForward": False,
            "Limit": limit,
        }

        if last_key:
            from cerebro.core.dynamodb import decode_pagination_token

            params["ExclusiveStartKey"] = decode_pagination_token(last_key)

        response = client.query(**params)
        items = [deserialize_item(item) for item in response.get("Items", [])]
        orgs = [Organization.from_dynamodb_item(item) for item in items]

        next_key = None
        if "LastEvaluatedKey" in response:
            from cerebro.core.dynamodb import encode_pagination_token

            next_key = encode_pagination_token(response["LastEvaluatedKey"])

        return orgs, next_key


class AccountRepository:
    """Repository for Account entity operations."""

    def __init__(self) -> None:
        self._table = TableName.CORE

    async def get(self, account_id: UUID, org_id: UUID) -> Optional[Account]:
        """Get account by ID."""
        pk = f"ORG#{org_id}"
        sk = f"ACCOUNT#{account_id}"
        item = await get_item(self._table, pk, sk)
        if item:
            return Account.from_dynamodb_item(item)
        return None

    async def create(self, account: Account) -> Account:
        """Create a new account."""
        await put_item(self._table, account.to_dynamodb_item())
        return account

    async def list_by_org(
        self,
        org_id: UUID,
        provider: Optional[Provider] = None,
        limit: int = 100,
    ) -> List[Account]:
        """List accounts for an organization."""
        pk = f"ORG#{org_id}"
        items = await query_by_pk(
            self._table,
            pk,
            sk_prefix="ACCOUNT#",
            limit=limit,
        )

        accounts = [Account.from_dynamodb_item(item) for item in items]

        if provider:
            provider_val = provider.value if isinstance(provider, Provider) else provider
            accounts = [a for a in accounts if a.provider.value == provider_val]

        return accounts

    async def list_by_provider(
        self,
        provider: Provider,
        limit: int = 100,
    ) -> List[Account]:
        """List accounts by provider (across all orgs)."""
        client = get_dynamodb_client()
        table_name = get_table_name(self._table)

        provider_val = provider.value if isinstance(provider, Provider) else provider

        response = client.query(
            TableName=table_name,
            IndexName="GSI1",
            KeyConditionExpression="GSI1PK = :pk",
            ExpressionAttributeValues={":pk": {"S": f"PROVIDER#{provider_val}"}},
            Limit=limit,
        )

        items = [deserialize_item(item) for item in response.get("Items", [])]
        return [Account.from_dynamodb_item(item) for item in items]

    async def get_by_external_id(
        self,
        org_id: UUID,
        provider: Provider,
        external_id: str,
    ) -> Optional[Account]:
        """Get account by external ID."""
        accounts = await self.list_by_org(org_id, provider)
        for account in accounts:
            if account.external_id == external_id:
                return account
        return None

    async def delete(self, account_id: UUID, org_id: UUID) -> bool:
        """Delete an account."""
        pk = f"ORG#{org_id}"
        sk = f"ACCOUNT#{account_id}"
        try:
            await delete_item(self._table, pk, sk)
            return True
        except Exception:
            return False


class FindingRepository:
    """Repository for Finding entity operations."""

    def __init__(self) -> None:
        self._table = TableName.CORE

    async def get(self, finding_id: UUID, org_id: UUID) -> Optional[Finding]:
        """Get finding by ID."""
        pk = f"ORG#{org_id}"
        sk = f"FINDING#{finding_id}"
        item = await get_item(self._table, pk, sk)
        if item:
            return Finding.from_dynamodb_item(item)
        return None

    async def create(self, finding: Finding) -> Finding:
        """Create a new finding."""
        await put_item(self._table, finding.to_dynamodb_item())
        return finding

    async def update(
        self,
        finding_id: UUID,
        org_id: UUID,
        **updates: Any,
    ) -> Optional[Finding]:
        """Update finding fields."""
        pk = f"ORG#{org_id}"
        sk = f"FINDING#{finding_id}"

        # Update last_seen timestamp
        if "last_seen" not in updates:
            updates["last_seen"] = datetime.now(timezone.utc).isoformat()

        # Need to update GSI keys if status/severity changes
        if "status" in updates or "severity" in updates:
            # Fetch current finding to get all values
            current = await self.get(finding_id, org_id)
            if current:
                status = updates.get("status", current.status)
                severity = updates.get("severity", current.severity)
                status_val = status.value if isinstance(status, FindingStatus) else status
                severity_val = severity.value if isinstance(severity, Severity) else severity
                updates["GSI2PK"] = f"ORG#{org_id}#STATUS#{status_val}"
                updates["GSI2SK"] = f"SEVERITY#{severity_val}#{finding_id}"

        updated = await update_item(self._table, pk, sk, updates)
        if updated:
            return Finding.from_dynamodb_item(updated)
        return None

    async def list_by_org(
        self,
        org_id: UUID,
        status: Optional[FindingStatus] = None,
        severity: Optional[Severity] = None,
        limit: int = 100,
    ) -> List[Finding]:
        """List findings for an organization."""
        client = get_dynamodb_client()
        table_name = get_table_name(self._table)

        if status:
            # Use GSI2 for status filtering
            status_val = status.value if isinstance(status, FindingStatus) else status
            pk = f"ORG#{org_id}#STATUS#{status_val}"

            params: Dict[str, Any] = {
                "TableName": table_name,
                "IndexName": "GSI2",
                "KeyConditionExpression": "GSI2PK = :pk",
                "ExpressionAttributeValues": {":pk": {"S": pk}},
                "ScanIndexForward": False,
                "Limit": limit,
            }

            if severity:
                severity_val = severity.value if isinstance(severity, Severity) else severity
                params["KeyConditionExpression"] += " AND begins_with(GSI2SK, :sk)"
                params["ExpressionAttributeValues"][":sk"] = {"S": f"SEVERITY#{severity_val}"}

            response = client.query(**params)
        else:
            # Query all findings for org
            pk = f"ORG#{org_id}"
            items = await query_by_pk(
                self._table,
                pk,
                sk_prefix="FINDING#",
                limit=limit,
                scan_forward=False,
            )
            findings = [Finding.from_dynamodb_item(item) for item in items]

            if severity:
                severity_val = severity.value if isinstance(severity, Severity) else severity
                findings = [f for f in findings if f.severity.value == severity_val]

            return findings

        items = [deserialize_item(item) for item in response.get("Items", [])]
        return [Finding.from_dynamodb_item(item) for item in items]

    async def list_by_rule(
        self,
        rule_id: UUID,
        limit: int = 100,
    ) -> List[Finding]:
        """List findings for a specific rule."""
        client = get_dynamodb_client()
        table_name = get_table_name(self._table)

        response = client.query(
            TableName=table_name,
            IndexName="GSI1",
            KeyConditionExpression="GSI1PK = :pk",
            ExpressionAttributeValues={":pk": {"S": f"RULE#{rule_id}"}},
            Limit=limit,
        )

        items = [deserialize_item(item) for item in response.get("Items", [])]
        return [Finding.from_dynamodb_item(item) for item in items]

    async def get_by_fingerprint(
        self,
        org_id: UUID,
        fingerprint: str,
    ) -> Optional[Finding]:
        """Get finding by fingerprint."""
        findings = await self.list_by_org(org_id, limit=1000)
        for finding in findings:
            if finding.fingerprint == fingerprint:
                return finding
        return None

    async def bulk_upsert(self, findings: List[Finding]) -> int:
        """Bulk upsert findings."""
        items = [f.to_dynamodb_item() for f in findings]
        await batch_write_items(self._table, put_items=items)
        return len(findings)


class RuleRepository:
    """Repository for Rule entity operations."""

    def __init__(self) -> None:
        self._table = TableName.CORE

    async def get(self, rule_id: UUID) -> Optional[Rule]:
        """Get rule by ID."""
        pk = f"RULE#{rule_id}"
        sk = f"RULE#{rule_id}"
        item = await get_item(self._table, pk, sk)
        if item:
            return Rule.from_dynamodb_item(item)
        return None

    async def create(self, rule: Rule) -> Rule:
        """Create a new rule."""
        await put_item(self._table, rule.to_dynamodb_item())
        return rule

    async def update(
        self,
        rule_id: UUID,
        **updates: Any,
    ) -> Optional[Rule]:
        """Update rule fields."""
        pk = f"RULE#{rule_id}"
        sk = f"RULE#{rule_id}"

        # Increment version on update
        current = await self.get(rule_id)
        if current:
            updates["version"] = current.version + 1

        updated = await update_item(self._table, pk, sk, updates)
        if updated:
            return Rule.from_dynamodb_item(updated)
        return None

    async def list_active(
        self,
        severity: Optional[Severity] = None,
        limit: int = 100,
    ) -> List[Rule]:
        """List active rules."""
        client = get_dynamodb_client()
        table_name = get_table_name(self._table)

        pk = "RULE#ACTIVE#True"

        params: Dict[str, Any] = {
            "TableName": table_name,
            "IndexName": "GSI1",
            "KeyConditionExpression": "GSI1PK = :pk",
            "ExpressionAttributeValues": {":pk": {"S": pk}},
            "Limit": limit,
        }

        if severity:
            severity_val = severity.value if isinstance(severity, Severity) else severity
            params["KeyConditionExpression"] += " AND begins_with(GSI1SK, :sk)"
            params["ExpressionAttributeValues"][":sk"] = {"S": f"SEVERITY#{severity_val}"}

        response = client.query(**params)
        items = [deserialize_item(item) for item in response.get("Items", [])]
        return [Rule.from_dynamodb_item(item) for item in items]

    async def list_by_provider(
        self,
        provider: str,
        limit: int = 100,
    ) -> List[Rule]:
        """List rules for a provider."""
        # Provider is stored as a list, so we need to filter
        rules = await self.list_active(limit=limit * 2)
        return [r for r in rules if provider in r.provider][:limit]


class PrincipalRepository:
    """Repository for Principal entity operations."""

    def __init__(self) -> None:
        self._table = TableName.CORE

    async def get(self, principal_id: UUID, org_id: UUID) -> Optional[Principal]:
        """Get principal by ID."""
        pk = f"ORG#{org_id}"
        sk = f"PRINCIPAL#{principal_id}"
        item = await get_item(self._table, pk, sk)
        if item:
            return Principal.from_dynamodb_item(item)
        return None

    async def create(self, principal: Principal) -> Principal:
        """Create a new principal."""
        await put_item(self._table, principal.to_dynamodb_item())
        return principal

    async def list_by_account(
        self,
        account_id: UUID,
        limit: int = 100,
    ) -> List[Principal]:
        """List principals for an account."""
        client = get_dynamodb_client()
        table_name = get_table_name(self._table)

        response = client.query(
            TableName=table_name,
            IndexName="GSI1",
            KeyConditionExpression="GSI1PK = :pk",
            ExpressionAttributeValues={":pk": {"S": f"ACCOUNT#{account_id}"}},
            Limit=limit,
        )

        items = [deserialize_item(item) for item in response.get("Items", [])]
        return [Principal.from_dynamodb_item(item) for item in items if item.get("entity_type") == "PRINCIPAL"]

    async def list_by_org(
        self,
        org_id: UUID,
        limit: int = 100,
    ) -> List[Principal]:
        """List principals for an organization."""
        pk = f"ORG#{org_id}"
        items = await query_by_pk(
            self._table,
            pk,
            sk_prefix="PRINCIPAL#",
            limit=limit,
        )
        return [Principal.from_dynamodb_item(item) for item in items]

    async def bulk_upsert(self, principals: List[Principal]) -> int:
        """Bulk upsert principals."""
        items = [p.to_dynamodb_item() for p in principals]
        await batch_write_items(self._table, put_items=items)
        return len(principals)


class ResourceRepository:
    """Repository for Resource entity operations."""

    def __init__(self) -> None:
        self._table = TableName.CORE

    async def get(self, resource_id: UUID, org_id: UUID) -> Optional[Resource]:
        """Get resource by ID."""
        pk = f"ORG#{org_id}"
        sk = f"RESOURCE#{resource_id}"
        item = await get_item(self._table, pk, sk)
        if item:
            return Resource.from_dynamodb_item(item)
        return None

    async def create(self, resource: Resource) -> Resource:
        """Create a new resource."""
        await put_item(self._table, resource.to_dynamodb_item())
        return resource

    async def list_by_account(
        self,
        account_id: UUID,
        resource_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Resource]:
        """List resources for an account."""
        client = get_dynamodb_client()
        table_name = get_table_name(self._table)

        response = client.query(
            TableName=table_name,
            IndexName="GSI1",
            KeyConditionExpression="GSI1PK = :pk",
            ExpressionAttributeValues={":pk": {"S": f"ACCOUNT#{account_id}"}},
            Limit=limit,
        )

        items = [deserialize_item(item) for item in response.get("Items", [])]
        resources = [Resource.from_dynamodb_item(item) for item in items if item.get("entity_type") == "RESOURCE"]

        if resource_type:
            resources = [r for r in resources if r.resource_type == resource_type]

        return resources

    async def list_by_org(
        self,
        org_id: UUID,
        limit: int = 100,
    ) -> List[Resource]:
        """List resources for an organization."""
        pk = f"ORG#{org_id}"
        items = await query_by_pk(
            self._table,
            pk,
            sk_prefix="RESOURCE#",
            limit=limit,
        )
        return [Resource.from_dynamodb_item(item) for item in items]

    async def bulk_upsert(self, resources: List[Resource]) -> int:
        """Bulk upsert resources."""
        items = [r.to_dynamodb_item() for r in resources]
        await batch_write_items(self._table, put_items=items)
        return len(resources)


class AuditEventRepository:
    """Repository for AuditEvent entity operations (stored in audit table)."""

    def __init__(self) -> None:
        self._table = TableName.AUDIT

    async def create(self, event: AuditEvent) -> AuditEvent:
        """Create a new audit event."""
        await put_item(self._table, event.to_dynamodb_item())
        return event

    async def list_by_account(
        self,
        account_id: UUID,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """List audit events for an account."""
        client = get_dynamodb_client()
        table_name = get_table_name(self._table)

        pk = f"ACCOUNT#{account_id}"

        params: Dict[str, Any] = {
            "TableName": table_name,
            "KeyConditionExpression": "PK = :pk",
            "ExpressionAttributeValues": {":pk": {"S": pk}},
            "ScanIndexForward": False,
            "Limit": limit,
        }

        if start_time and end_time:
            params["KeyConditionExpression"] += " AND SK BETWEEN :sk_start AND :sk_end"
            params["ExpressionAttributeValues"][":sk_start"] = {"S": f"AUDIT#{start_time.isoformat()}"}
            params["ExpressionAttributeValues"][":sk_end"] = {"S": f"AUDIT#{end_time.isoformat()}"}
        elif start_time:
            params["KeyConditionExpression"] += " AND SK >= :sk_start"
            params["ExpressionAttributeValues"][":sk_start"] = {"S": f"AUDIT#{start_time.isoformat()}"}

        response = client.query(**params)
        items = [deserialize_item(item) for item in response.get("Items", [])]
        return [AuditEvent.from_dynamodb_item(item) for item in items]

    async def list_by_org(
        self,
        org_id: UUID,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """List audit events for an organization using GSI1."""
        client = get_dynamodb_client()
        table_name = get_table_name(self._table)

        pk = f"ORG#{org_id}#AUDIT"

        params: Dict[str, Any] = {
            "TableName": table_name,
            "IndexName": "GSI1",
            "KeyConditionExpression": "GSI1PK = :pk",
            "ExpressionAttributeValues": {":pk": {"S": pk}},
            "ScanIndexForward": False,
            "Limit": limit,
        }

        if start_time:
            params["KeyConditionExpression"] += " AND GSI1SK >= :sk_start"
            params["ExpressionAttributeValues"][":sk_start"] = {"S": f"OCCURRED#{start_time.isoformat()}"}

        response = client.query(**params)
        items = [deserialize_item(item) for item in response.get("Items", [])]
        return [AuditEvent.from_dynamodb_item(item) for item in items]

    async def bulk_create(self, events: List[AuditEvent]) -> int:
        """Bulk create audit events."""
        items = [e.to_dynamodb_item() for e in events]
        await batch_write_items(self._table, put_items=items)
        return len(events)


class ConfigSnapshotRepository:
    """Repository for ConfigSnapshot entity operations (stored in audit table)."""

    def __init__(self) -> None:
        self._table = TableName.AUDIT

    async def create(self, snapshot: ConfigSnapshot) -> ConfigSnapshot:
        """Create a new config snapshot."""
        await put_item(self._table, snapshot.to_dynamodb_item())
        return snapshot

    async def list_by_resource(
        self,
        resource_id: UUID,
        limit: int = 100,
    ) -> List[ConfigSnapshot]:
        """List config snapshots for a resource."""
        pk = f"RESOURCE#{resource_id}"
        items = await query_by_pk(
            self._table,
            pk,
            sk_prefix="CONFIG_SNAPSHOT#",
            limit=limit,
            scan_forward=False,
        )
        return [ConfigSnapshot.from_dynamodb_item(item) for item in items]

    async def get_latest(self, resource_id: UUID) -> Optional[ConfigSnapshot]:
        """Get the latest config snapshot for a resource."""
        snapshots = await self.list_by_resource(resource_id, limit=1)
        return snapshots[0] if snapshots else None

    async def bulk_create(self, snapshots: List[ConfigSnapshot]) -> int:
        """Bulk create config snapshots."""
        items = [s.to_dynamodb_item() for s in snapshots]
        await batch_write_items(self._table, put_items=items)
        return len(snapshots)


class SuppressionRepository:
    """Repository for Suppression entity operations."""

    def __init__(self) -> None:
        self._table = TableName.CORE

    async def get(self, suppression_id: UUID, org_id: UUID) -> Optional[Suppression]:
        """Get suppression by ID."""
        pk = f"ORG#{org_id}"
        sk = f"SUPPRESSION#{suppression_id}"
        item = await get_item(self._table, pk, sk)
        if item:
            return Suppression.from_dynamodb_item(item)
        return None

    async def create(self, suppression: Suppression) -> Suppression:
        """Create a new suppression."""
        await put_item(self._table, suppression.to_dynamodb_item())
        return suppression

    async def list_by_org(
        self,
        org_id: UUID,
        include_expired: bool = False,
        limit: int = 100,
    ) -> List[Suppression]:
        """List suppressions for an organization."""
        pk = f"ORG#{org_id}"
        items = await query_by_pk(
            self._table,
            pk,
            sk_prefix="SUPPRESSION#",
            limit=limit,
        )

        suppressions = [Suppression.from_dynamodb_item(item) for item in items]

        if not include_expired:
            now = datetime.now(timezone.utc)
            suppressions = [
                s for s in suppressions
                if s.expires_at is None or s.expires_at > now
            ]

        return suppressions

    async def delete(self, suppression_id: UUID, org_id: UUID) -> bool:
        """Delete a suppression."""
        pk = f"ORG#{org_id}"
        sk = f"SUPPRESSION#{suppression_id}"
        try:
            await delete_item(self._table, pk, sk)
            return True
        except Exception:
            return False
