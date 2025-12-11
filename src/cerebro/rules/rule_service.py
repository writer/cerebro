"""Rule management service."""

from typing import List, Optional, Dict, Any
from uuid import UUID
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from cerebro.core.models import Rule, Policy
from cerebro.rules.library import RuleLibrary

logger = logging.getLogger(__name__)

# Global rule name to ID mapping cache
_rule_name_cache: Dict[str, UUID] = {}


class RuleService:
    """Service for rule management operations."""
    
    def __init__(self, db_session: AsyncSession):
        """Initialize rule service."""
        self.db = db_session
    
    async def create_rule_from_template(
        self,
        template_name: str,
        policy_id: Optional[UUID] = None,
        org_id: Optional[UUID] = None
    ) -> Rule:
        """Create a rule from a library template."""
        # Get rule template
        templates = RuleLibrary.get_all_rules()
        template = next((t for t in templates if t.name == template_name), None)
        
        if not template:
            raise ValueError(f"Rule template '{template_name}' not found")
        
        # Create rule
        rule = Rule(
            policy_id=policy_id,
            name=template.name,
            description=template.description,
            provider=template.provider,
            resource_types=template.resource_types,
            expression_lang="cel",
            expression=template.expression,
            severity=template.severity,
            cis=template.framework_mappings.get("cis", []),
            nist_800_53=template.framework_mappings.get("nist_800_53", []),
            cwe=template.framework_mappings.get("cwe", [])
        )
        
        self.db.add(rule)
        await self.db.commit()
        await self.db.refresh(rule)
        
        # Update cache
        rule_name_key = self._normalize_rule_name(template.name)
        _rule_name_cache[rule_name_key] = rule.rule_id
        
        logger.info(f"Created rule from template: {template.name}")
        return rule
    
    async def get_rule_by_name(self, rule_name: str) -> Optional[UUID]:
        """Get rule ID by normalized name."""
        rule_name_key = self._normalize_rule_name(rule_name)
        
        # Check cache first
        if rule_name_key in _rule_name_cache:
            return _rule_name_cache[rule_name_key]
        
        # Search database
        stmt = select(Rule).where(Rule.name.ilike(f"%{rule_name}%"))
        rule = await self.db.scalar(stmt)
        
        if rule:
            _rule_name_cache[rule_name_key] = rule.rule_id
            return rule.rule_id
        
        # Try to find by description
        stmt = select(Rule).where(Rule.description.ilike(f"%{rule_name}%"))
        rule = await self.db.scalar(stmt)
        
        if rule:
            _rule_name_cache[rule_name_key] = rule.rule_id
            return rule.rule_id
        
        logger.warning(f"Rule not found for name: {rule_name}")
        return None
    
    async def ensure_library_rules_exist(self, org_id: UUID) -> Dict[str, UUID]:
        """Ensure all library rules exist in database and return name->ID mapping."""
        # Get or create default policy
        stmt = select(Policy).where(
            and_(
                Policy.org_id == org_id,
                Policy.name == "Security Baseline"
            )
        )
        policy = await self.db.scalar(stmt)
        
        if not policy:
            policy = Policy(
                org_id=org_id,
                name="Security Baseline",
                description="Core security rules from Cerebro library",
                framework="CIS"
            )
            self.db.add(policy)
            await self.db.flush()
        
        # Get all rule templates
        templates = RuleLibrary.get_all_rules()
        rule_mapping = {}
        
        for template in templates:
            # Check if rule exists
            stmt = select(Rule).where(
                and_(
                    Rule.name == template.name,
                    Rule.policy_id == policy.policy_id
                )
            )
            existing_rule = await self.db.scalar(stmt)
            
            if existing_rule:
                rule_mapping[self._normalize_rule_name(template.name)] = existing_rule.rule_id
            else:
                # Create rule from template
                new_rule = await self.create_rule_from_template(
                    template.name,
                    policy_id=policy.policy_id
                )
                rule_mapping[self._normalize_rule_name(template.name)] = new_rule.rule_id
        
        await self.db.commit()
        logger.info(f"Ensured {len(rule_mapping)} library rules exist")
        return rule_mapping
    
    async def get_rules_for_provider(
        self,
        provider: str,
        resource_types: Optional[List[str]] = None,
        active_only: bool = True
    ) -> List[Rule]:
        """Get all rules applicable to a provider."""
        stmt = select(Rule).where(Rule.provider.contains([provider]))
        
        if resource_types:
            stmt = stmt.where(
                Rule.resource_types.is_(None) | 
                Rule.resource_types.overlap(resource_types)
            )
        
        if active_only:
            stmt = stmt.where(Rule.is_active == True)
        
        rules = await self.db.scalars(stmt)
        return list(rules)
    
    async def create_rule_from_producer(
        self,
        producer_metadata: Dict[str, Any],
        policy_id: UUID,
        rule_expression: str
    ) -> Rule:
        """Create a rule from producer metadata."""
        rule = Rule(
            policy_id=policy_id,
            name=producer_metadata["finding_name"],
            description=producer_metadata["description"],
            provider=producer_metadata["desired_sources"],
            resource_types=producer_metadata["resource_types"],
            expression_lang="cel",
            expression=rule_expression,
            severity=producer_metadata["severity"],
            cis=producer_metadata.get("framework_mappings", {}).get("cis", []),
            nist_800_53=producer_metadata.get("framework_mappings", {}).get("nist_800_53", []),
            cwe=producer_metadata.get("framework_mappings", {}).get("cwe", [])
        )
        
        self.db.add(rule)
        await self.db.commit()
        await self.db.refresh(rule)
        
        # Update cache
        rule_name_key = self._normalize_rule_name(producer_metadata["rule_name"])
        _rule_name_cache[rule_name_key] = rule.rule_id
        
        logger.info(f"Created rule from producer: {producer_metadata['finding_name']}")
        return rule
    
    def _normalize_rule_name(self, name: str) -> str:
        """Normalize rule name for consistent lookups."""
        return name.lower().replace(" ", "_").replace(":", "").replace("-", "_")
    
    async def sync_rules_with_producers(self, org_id: UUID) -> Dict[str, Any]:
        """Sync database rules with registered producers."""
        from cerebro.core.interfaces import producer_registry
        
        # Get default policy
        stmt = select(Policy).where(
            and_(
                Policy.org_id == org_id,
                Policy.name == "Producer Rules"
            )
        )
        policy = await self.db.scalar(stmt)
        
        if not policy:
            policy = Policy(
                org_id=org_id,
                name="Producer Rules",
                description="Rules generated from finding producers",
                framework="Custom"
            )
            self.db.add(policy)
            await self.db.flush()
        
        # Get all producer info
        producer_infos = producer_registry.get_all_producer_info()
        created = 0
        updated = 0
        
        for producer_info in producer_infos:
            rule_name_key = self._normalize_rule_name(producer_info["rule_name"])
            
            # Check if rule exists
            stmt = select(Rule).where(
                and_(
                    Rule.name == producer_info["finding_name"],
                    Rule.policy_id == policy.policy_id
                )
            )
            existing_rule = await self.db.scalar(stmt)
            
            if existing_rule:
                # Update cache
                _rule_name_cache[rule_name_key] = existing_rule.rule_id
                updated += 1
            else:
                # Create CEL expression for this producer (simplified)
                cel_expression = f"producer.{producer_info['rule_name']}(resource, config)"
                
                new_rule = await self.create_rule_from_producer(
                    producer_info,
                    policy.policy_id,
                    cel_expression
                )
                created += 1
        
        await self.db.commit()
        
        result = {
            "created": created,
            "updated": updated,
            "total_producers": len(producer_infos),
        }
        
        logger.info(f"Synced rules with producers: {result}")
        return result


# Global helper function for use in producers
def get_rule_by_name_sync(rule_name: str) -> UUID:
    """Synchronous helper to get rule ID by name using deterministic UUID."""
    # Check cache first
    rule_name_key = rule_name.lower().replace(" ", "_").replace(":", "").replace("-", "_")
    
    if rule_name_key in _rule_name_cache:
        return _rule_name_cache[rule_name_key]
    
    # Generate deterministic UUID based on rule name
    import hashlib
    name_hash = hashlib.sha256(rule_name.encode()).hexdigest()
    # Take first 32 chars and format as UUID
    uuid_str = f"{name_hash[:8]}-{name_hash[8:12]}-{name_hash[12:16]}-{name_hash[16:20]}-{name_hash[20:32]}"
    rule_id = UUID(uuid_str)
    
    # Cache the result
    _rule_name_cache[rule_name_key] = rule_id
    
    return rule_id


# Async version for use with database
async def get_rule_by_name_async(rule_name: str, db_session: AsyncSession) -> UUID:
    """Async helper to get rule ID by name from database."""
    rule_service = RuleService(db_session)
    rule_id = await rule_service.get_rule_by_name(rule_name)
    
    if not rule_id:
        # Fall back to deterministic UUID
        rule_id = get_rule_by_name_sync(rule_name)
        logger.warning(f"Rule not found in DB, using deterministic UUID for {rule_name}: {rule_id}")
    
    return rule_id


def invalidate_rule_cache():
    """Invalidate the rule name cache."""
    global _rule_name_cache
    _rule_name_cache.clear()
    logger.info("Rule name cache invalidated")
