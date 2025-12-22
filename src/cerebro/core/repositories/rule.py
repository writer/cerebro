"""Rule repository for DynamoDB."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from cerebro.core.dynamodb_client import (
    TableName,
    delete_item,
    get_item,
    pk,
    put_item,
    query,
    query_paginated,
    sk,
    update_item,
)


class ExpressionLang(str, Enum):
    """Rule expression languages."""

    SQL = "sql"
    REGO = "rego"
    CEL = "cel"


class Severity(str, Enum):
    """Severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Rule(BaseModel):
    """Rule entity - CEL/SQL/Rego rule expression."""

    rule_id: UUID = Field(default_factory=uuid4)
    policy_id: Optional[UUID] = None
    name: str
    description: Optional[str] = None
    provider: List[str]
    resource_types: Optional[List[str]] = None
    expression_lang: ExpressionLang
    expression: str
    severity: Severity
    cwe: Optional[List[str]] = None
    cis: Optional[List[str]] = None
    nist_800_53: Optional[List[str]] = None
    mitre_attack: Optional[List[str]] = None
    version: int = 1
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        from_attributes = True
        use_enum_values = True

    def to_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB item."""
        rule_id = str(self.rule_id)
        severity = (
            self.severity.value if isinstance(self.severity, Enum) else self.severity
        )
        expr_lang = (
            self.expression_lang.value
            if isinstance(self.expression_lang, Enum)
            else self.expression_lang
        )

        return {
            "PK": pk("RULE", rule_id),
            "SK": sk("RULE", rule_id),
            "entity_type": "RULE",
            "rule_id": rule_id,
            "policy_id": str(self.policy_id) if self.policy_id else None,
            "name": self.name,
            "description": self.description,
            "provider": self.provider,
            "resource_types": self.resource_types,
            "expression_lang": expr_lang,
            "expression": self.expression,
            "severity": severity,
            "cwe": self.cwe,
            "cis": self.cis,
            "nist_800_53": self.nist_800_53,
            "mitre_attack": self.mitre_attack,
            "version": self.version,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            # GSI for listing active rules by severity
            "GSI1PK": f"RULE#ACTIVE#{self.is_active}",
            "GSI1SK": f"SEVERITY#{severity}#{rule_id}",
        }

    @classmethod
    def from_item(cls, item: Dict[str, Any]) -> "Rule":
        """Create from DynamoDB item."""
        return cls(
            rule_id=UUID(item["rule_id"]),
            policy_id=UUID(item["policy_id"]) if item.get("policy_id") else None,
            name=item["name"],
            description=item.get("description"),
            provider=item["provider"],
            resource_types=item.get("resource_types"),
            expression_lang=ExpressionLang(item["expression_lang"]),
            expression=item["expression"],
            severity=Severity(item["severity"]),
            cwe=item.get("cwe"),
            cis=item.get("cis"),
            nist_800_53=item.get("nist_800_53"),
            mitre_attack=item.get("mitre_attack"),
            version=item.get("version", 1),
            is_active=item.get("is_active", True),
            created_at=(
                datetime.fromisoformat(item["created_at"])
                if item.get("created_at")
                else datetime.now(timezone.utc)
            ),
        )


class RuleRepository:
    """Repository for Rule operations."""

    _table = TableName.CORE

    async def get(self, rule_id: UUID) -> Optional[Rule]:
        """Get rule by ID."""
        item = await get_item(
            self._table,
            pk("RULE", str(rule_id)),
            sk("RULE", str(rule_id)),
        )
        return Rule.from_item(item) if item else None

    async def create(self, rule: Rule) -> Rule:
        """Create new rule."""
        await put_item(self._table, rule.to_item())
        return rule

    async def update(self, rule_id: UUID, **updates) -> Optional[Rule]:
        """Update rule."""
        # Increment version
        current = await self.get(rule_id)
        if current:
            updates["version"] = current.version + 1

            # Update GSI if is_active or severity changed
            is_active = updates.get("is_active", current.is_active)
            severity = updates.get("severity", current.severity)
            severity_val = severity.value if isinstance(severity, Enum) else severity
            updates["GSI1PK"] = f"RULE#ACTIVE#{is_active}"
            updates["GSI1SK"] = f"SEVERITY#{severity_val}#{rule_id}"

        result = await update_item(
            self._table,
            pk("RULE", str(rule_id)),
            sk("RULE", str(rule_id)),
            updates,
        )
        return Rule.from_item(result) if result else None

    async def delete(self, rule_id: UUID) -> bool:
        """Delete rule."""
        return await delete_item(
            self._table,
            pk("RULE", str(rule_id)),
            sk("RULE", str(rule_id)),
        )

    async def list_active(
        self,
        severity: Optional[Severity] = None,
        limit: int = 100,
    ) -> List[Rule]:
        """List active rules."""
        if severity:
            severity_val = severity.value if isinstance(severity, Enum) else severity
            items = await query(
                self._table,
                "RULE#ACTIVE#True",
                sk_prefix=f"SEVERITY#{severity_val}",
                index="GSI1",
                limit=limit,
            )
        else:
            items = await query(
                self._table,
                "RULE#ACTIVE#True",
                index="GSI1",
                limit=limit,
            )
        return [Rule.from_item(item) for item in items]

    async def list_by_provider(
        self,
        provider: str,
        active_only: bool = True,
        limit: int = 100,
    ) -> List[Rule]:
        """List rules for a provider."""
        if active_only:
            rules = await self.list_active(limit=limit * 2)
        else:
            # Get all rules (less efficient)
            items = await query(
                self._table,
                "RULE#ACTIVE#True",
                index="GSI1",
                limit=limit * 2,
            )
            inactive_items = await query(
                self._table,
                "RULE#ACTIVE#False",
                index="GSI1",
                limit=limit * 2,
            )
            items.extend(inactive_items)
            rules = [Rule.from_item(item) for item in items]

        return [r for r in rules if provider in r.provider][:limit]

    async def get_by_name(self, name: str) -> Optional[Rule]:
        """Get rule by name.

        Note: Scans active rules. Consider adding GSI on name for better performance.
        """
        cursor = None
        while True:
            items, cursor = await query_paginated(
                self._table,
                "RULE#ACTIVE#True",
                index="GSI1",
                limit=100,
                cursor=cursor,
            )
            for item in items:
                if item.get("name") == name:
                    return Rule.from_item(item)
            if not cursor:
                break
        return None

    async def deactivate(self, rule_id: UUID) -> Optional[Rule]:
        """Deactivate a rule."""
        return await self.update(rule_id, is_active=False)

    async def activate(self, rule_id: UUID) -> Optional[Rule]:
        """Activate a rule."""
        return await self.update(rule_id, is_active=True)
