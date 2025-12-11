"""Finding repository for DynamoDB."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from cerebro.core.dynamodb_client import (
    TableName,
    batch_write,
    delete_item,
    get_item,
    now_iso,
    pk,
    put_item,
    query,
    sk,
    update_item,
)


class FindingStatus(str, Enum):
    """Finding lifecycle states."""
    OPEN = "open"
    SUPPRESSED = "suppressed"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"


class Severity(str, Enum):
    """Severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    """Finding entity - security misconfiguration or violation."""
    
    finding_id: UUID = Field(default_factory=uuid4)
    org_id: UUID
    account_id: UUID
    provider: str
    rule_id: UUID
    rule_version: int = 1
    resource_id: Optional[UUID] = None
    principal_id: Optional[UUID] = None
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: FindingStatus = FindingStatus.OPEN
    severity: Severity
    fingerprint: str
    title: str
    summary: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    
    class Config:
        from_attributes = True
        use_enum_values = True
    
    def to_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB item."""
        finding_id = str(self.finding_id)
        org_id = str(self.org_id)
        status = self.status.value if isinstance(self.status, Enum) else self.status
        severity = self.severity.value if isinstance(self.severity, Enum) else self.severity
        last_seen = self.last_seen.isoformat()
        
        return {
            "PK": pk("ORG", org_id),
            "SK": sk("FINDING", finding_id),
            "entity_type": "FINDING",
            "finding_id": finding_id,
            "org_id": org_id,
            "account_id": str(self.account_id),
            "provider": self.provider,
            "rule_id": str(self.rule_id),
            "rule_version": self.rule_version,
            "resource_id": str(self.resource_id) if self.resource_id else None,
            "principal_id": str(self.principal_id) if self.principal_id else None,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": last_seen,
            "status": status,
            "severity": severity,
            "fingerprint": self.fingerprint,
            "title": self.title,
            "summary": self.summary,
            "evidence": self.evidence,
            # GSIs
            "GSI1PK": f"RULE#{self.rule_id}",
            "GSI1SK": f"FINDING#{finding_id}",
            "GSI2PK": f"ORG#{org_id}#STATUS#{status}",
            "GSI2SK": f"SEVERITY#{severity}#{finding_id}",
            "GSI3PK": f"ORG#{org_id}",
            "GSI3SK": f"LAST_SEEN#{last_seen}",
        }
    
    @classmethod
    def from_item(cls, item: Dict[str, Any]) -> "Finding":
        """Create from DynamoDB item."""
        return cls(
            finding_id=UUID(item["finding_id"]),
            org_id=UUID(item["org_id"]),
            account_id=UUID(item["account_id"]),
            provider=item["provider"],
            rule_id=UUID(item["rule_id"]),
            rule_version=item.get("rule_version", 1),
            resource_id=UUID(item["resource_id"]) if item.get("resource_id") else None,
            principal_id=UUID(item["principal_id"]) if item.get("principal_id") else None,
            first_seen=datetime.fromisoformat(item["first_seen"]),
            last_seen=datetime.fromisoformat(item["last_seen"]),
            status=FindingStatus(item["status"]),
            severity=Severity(item["severity"]),
            fingerprint=item["fingerprint"],
            title=item["title"],
            summary=item.get("summary"),
            evidence=item.get("evidence"),
        )


class FindingRepository:
    """Repository for Finding operations."""
    
    _table = TableName.CORE
    
    async def get(self, finding_id: UUID, org_id: UUID) -> Optional[Finding]:
        """Get finding by ID."""
        item = await get_item(
            self._table,
            pk("ORG", str(org_id)),
            sk("FINDING", str(finding_id)),
        )
        return Finding.from_item(item) if item else None
    
    async def create(self, finding: Finding) -> Finding:
        """Create new finding."""
        await put_item(self._table, finding.to_item())
        return finding
    
    async def update(
        self,
        finding_id: UUID,
        org_id: UUID,
        **updates,
    ) -> Optional[Finding]:
        """Update finding."""
        # Always update last_seen
        updates["last_seen"] = now_iso()
        
        # If status or severity changed, update GSI keys
        current = await self.get(finding_id, org_id)
        if current:
            status = updates.get("status", current.status)
            severity = updates.get("severity", current.severity)
            status_val = status.value if isinstance(status, Enum) else status
            severity_val = severity.value if isinstance(severity, Enum) else severity
            updates["GSI2PK"] = f"ORG#{org_id}#STATUS#{status_val}"
            updates["GSI2SK"] = f"SEVERITY#{severity_val}#{finding_id}"
            updates["GSI3SK"] = f"LAST_SEEN#{updates['last_seen']}"
        
        result = await update_item(
            self._table,
            pk("ORG", str(org_id)),
            sk("FINDING", str(finding_id)),
            updates,
        )
        return Finding.from_item(result) if result else None
    
    async def delete(self, finding_id: UUID, org_id: UUID) -> bool:
        """Delete finding."""
        return await delete_item(
            self._table,
            pk("ORG", str(org_id)),
            sk("FINDING", str(finding_id)),
        )
    
    async def list_by_org(
        self,
        org_id: UUID,
        status: Optional[FindingStatus] = None,
        severity: Optional[Severity] = None,
        limit: int = 100,
    ) -> List[Finding]:
        """List findings for an organization."""
        if status:
            # Use GSI2 for status filtering
            status_val = status.value if isinstance(status, Enum) else status
            pk_val = f"ORG#{org_id}#STATUS#{status_val}"
            
            if severity:
                severity_val = severity.value if isinstance(severity, Enum) else severity
                items = await query(
                    self._table,
                    pk_val,
                    sk_prefix=f"SEVERITY#{severity_val}",
                    index="GSI2",
                    limit=limit,
                )
            else:
                items = await query(
                    self._table,
                    pk_val,
                    index="GSI2",
                    limit=limit,
                )
        else:
            # Query all findings for org
            items = await query(
                self._table,
                pk("ORG", str(org_id)),
                sk_prefix="FINDING#",
                limit=limit,
                forward=False,
            )
            
            if severity:
                severity_val = severity.value if isinstance(severity, Enum) else severity
                items = [i for i in items if i.get("severity") == severity_val]
        
        return [Finding.from_item(item) for item in items]
    
    async def list_by_rule(self, rule_id: UUID, limit: int = 100) -> List[Finding]:
        """List findings for a specific rule."""
        items = await query(
            self._table,
            f"RULE#{rule_id}",
            index="GSI1",
            limit=limit,
        )
        return [Finding.from_item(item) for item in items]
    
    async def list_by_account(
        self,
        org_id: UUID,
        account_id: UUID,
        limit: int = 100,
    ) -> List[Finding]:
        """List findings for an account."""
        findings = await self.list_by_org(org_id, limit=limit * 2)
        return [f for f in findings if f.account_id == account_id][:limit]
    
    async def get_by_fingerprint(
        self,
        org_id: UUID,
        fingerprint: str,
    ) -> Optional[Finding]:
        """Get finding by fingerprint."""
        findings = await self.list_by_org(org_id, limit=10000)
        for finding in findings:
            if finding.fingerprint == fingerprint:
                return finding
        return None
    
    async def upsert(self, finding: Finding) -> Finding:
        """Create or update finding by fingerprint."""
        existing = await self.get_by_fingerprint(finding.org_id, finding.fingerprint)
        if existing:
            # Update existing
            return await self.update(
                existing.finding_id,
                existing.org_id,
                last_seen=finding.last_seen.isoformat(),
                status=finding.status,
                severity=finding.severity,
                evidence=finding.evidence,
            ) or existing
        else:
            # Create new
            return await self.create(finding)
    
    async def bulk_upsert(self, findings: List[Finding]) -> int:
        """Bulk upsert findings."""
        items = [f.to_item() for f in findings]
        await batch_write(self._table, put_items=items)
        return len(findings)
    
    async def count_by_status(self, org_id: UUID) -> Dict[str, int]:
        """Count findings by status for an organization."""
        counts = {}
        for status in FindingStatus:
            findings = await self.list_by_org(org_id, status=status, limit=10000)
            counts[status.value] = len(findings)
        return counts
    
    async def count_by_severity(self, org_id: UUID) -> Dict[str, int]:
        """Count findings by severity for an organization."""
        counts = {}
        for severity in Severity:
            findings = await self.list_by_org(org_id, severity=severity, limit=10000)
            counts[severity.value] = len(findings)
        return counts
