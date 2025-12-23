"""
No-Code Rules Engine for Evidence Analysis.

Provides a visual rule builder and execution engine that operates on the
evidence data fabric - similar to Anecdotes.ai's rule system.

Key capabilities:
- No-code rule builder with visual UI components
- Cross-evidence analysis and joins
- Temporal logic (within X days of Y)
- Policy statement parsing and rule generation
- Real-time gap detection and alerting
- Requirement-level rule binding
"""

import re
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from uuid import uuid4

from .evidence_data_fabric import (
    EvidenceDataFabric,
    EvidenceQuery,
    EvidenceEntityType,
    EvidenceRecord,
)


class RuleType(Enum):
    """Types of compliance rules."""

    EXISTENCE = "existence"  # Evidence must exist
    ABSENCE = "absence"  # Evidence must not exist
    THRESHOLD = "threshold"  # Numeric threshold check
    PATTERN = "pattern"  # String pattern matching
    TEMPORAL = "temporal"  # Time-based conditions
    CROSS_EVIDENCE = "cross_evidence"  # Join multiple evidence sources
    POLICY_DERIVED = "policy_derived"  # Generated from policy statements


class RuleOperator(Enum):
    """Operators for rule conditions."""

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    MATCHES = "matches"
    NOT_MATCHES = "not_matches"
    IN = "in"
    NOT_IN = "not_in"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


class RuleSeverity(Enum):
    """Severity levels for rule violations."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RuleCondition:
    """Individual condition within a rule."""

    id: str
    field_path: str  # e.g., "normalized_data.mfa_enabled"
    operator: RuleOperator
    value: Any
    entity_filter: Optional[Dict[str, Any]] = None
    description: str = ""


@dataclass
class RuleDefinition:
    """Complete rule definition."""

    id: str
    name: str
    description: str
    rule_type: RuleType
    severity: RuleSeverity

    # Rule logic
    conditions: List[RuleCondition] = field(default_factory=list)
    logic_operator: str = "AND"  # AND, OR

    # Evidence selection
    evidence_filters: Dict[str, Any] = field(default_factory=dict)
    time_window_days: Optional[int] = None

    # Framework binding
    requirements: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)

    # Actions and remediation
    remediation_guidance: str = ""
    automated_remediation: Optional[str] = None
    alert_channels: List[str] = field(default_factory=list)

    # Metadata
    created_by: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    enabled: bool = True

    # Policy linking
    derived_from_policy: Optional[str] = None
    policy_statement: Optional[str] = None


@dataclass
class RuleResult:
    """Result of rule evaluation."""

    rule_id: str
    rule_name: str
    passed: bool
    severity: RuleSeverity

    # Evaluation details
    evaluated_at: datetime
    evidence_count: int
    violations: List[Dict[str, Any]] = field(default_factory=list)

    # Context
    entity_id: Optional[str] = None
    entity_type: Optional[str] = None
    requirements: List[str] = field(default_factory=list)

    # Remediation
    remediation_guidance: str = ""
    automated_fix_available: bool = False

    @property
    def violation_count(self) -> int:
        return len(self.violations)

    @property
    def pass_rate(self) -> float:
        if self.evidence_count == 0:
            return 1.0
        return max(
            0.0, (self.evidence_count - self.violation_count) / self.evidence_count
        )


class PolicyStatementParser:
    """Parses policy statements to generate compliance rules."""

    # Patterns for extracting actionable statements
    SHALL_PATTERNS = [
        r"shall\s+(.+?)(?:\.|;|$)",
        r"must\s+(.+?)(?:\.|;|$)",
        r"will\s+(.+?)(?:\.|;|$)",
        r"are\s+required\s+to\s+(.+?)(?:\.|;|$)",
    ]

    # Common compliance terms and their mappings
    TERM_MAPPINGS = {
        "multi-factor authentication": {
            "field": "mfa_enabled",
            "operator": "equals",
            "value": True,
        },
        "two-factor authentication": {
            "field": "mfa_enabled",
            "operator": "equals",
            "value": True,
        },
        "2fa": {"field": "mfa_enabled", "operator": "equals", "value": True},
        "strong password": {
            "field": "password_policy.min_length",
            "operator": "greater_than",
            "value": 8,
        },
        "encrypted": {
            "field": "encryption_enabled",
            "operator": "equals",
            "value": True,
        },
        "backup": {"field": "backup_enabled", "operator": "equals", "value": True},
        "monitoring": {
            "field": "monitoring_enabled",
            "operator": "equals",
            "value": True,
        },
        "access review": {
            "field": "last_access_review",
            "operator": "within_days",
            "value": 90,
        },
    }

    def parse_policy_statements(self, policy_text: str) -> List[Dict[str, Any]]:
        """Extract actionable statements from policy text."""

        statements = []
        sentences = policy_text.split(".")

        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence:
                continue

            # Look for shall/must/will statements
            for pattern in self.SHALL_PATTERNS:
                matches = re.findall(pattern, sentence, re.IGNORECASE)
                for match in matches:
                    statement = {
                        "original": sentence,
                        "actionable": match.strip(),
                        "suggested_rules": self._suggest_rules_for_statement(
                            match.strip()
                        ),
                    }
                    statements.append(statement)

        return statements

    def _suggest_rules_for_statement(self, statement: str) -> List[Dict[str, Any]]:
        """Suggest rule definitions based on policy statement."""

        suggestions = []
        statement_lower = statement.lower()

        for term, mapping in self.TERM_MAPPINGS.items():
            if term in statement_lower:
                rule_suggestion = {
                    "name": f"Policy Requirement: {term.title()}",
                    "description": f"Verify {term} as required by policy",
                    "rule_type": (
                        "existence" if mapping["operator"] == "equals" else "threshold"
                    ),
                    "conditions": [
                        {
                            "field_path": f"normalized_data.{mapping['field']}",
                            "operator": mapping["operator"],
                            "value": mapping["value"],
                        }
                    ],
                    "confidence": 0.8,  # How confident we are in this mapping
                }
                suggestions.append(rule_suggestion)

        return suggestions

    def generate_rule_from_statement(
        self,
        statement: str,
        rule_name: str,
        requirements: List[str],
        entity_types: List[EvidenceEntityType],
    ) -> Optional[RuleDefinition]:
        """Generate a complete rule definition from policy statement."""

        suggestions = self._suggest_rules_for_statement(statement)
        if not suggestions:
            return None

        # Use the highest confidence suggestion
        best_suggestion = max(suggestions, key=lambda x: x["confidence"])

        conditions = []
        for i, cond in enumerate(best_suggestion["conditions"]):
            conditions.append(
                RuleCondition(
                    id=str(uuid4()),
                    field_path=cond["field_path"],
                    operator=RuleOperator(cond["operator"]),
                    value=cond["value"],
                    description=f"Check {cond['field_path']}",
                )
            )

        rule = RuleDefinition(
            id=str(uuid4()),
            name=rule_name,
            description=best_suggestion["description"],
            rule_type=RuleType(best_suggestion["rule_type"]),
            severity=RuleSeverity.MEDIUM,
            conditions=conditions,
            requirements=requirements,
            policy_statement=statement,
            derived_from_policy="policy-derived",
        )

        return rule


class NoCodeRulesEngine:
    """Main rules engine with no-code builder capabilities."""

    def __init__(self, evidence_fabric: EvidenceDataFabric):
        self.evidence_fabric = evidence_fabric
        self.policy_parser = PolicyStatementParser()
        self._rules: Dict[str, RuleDefinition] = {}
        self._rule_templates: Dict[str, Dict] = {}
        self._load_rule_templates()

    def create_rule_from_template(
        self,
        template_name: str,
        rule_name: str,
        parameters: Dict[str, Any],
        requirements: Optional[List[str]] = None,
    ) -> RuleDefinition:
        """Create a rule from a predefined template."""

        if template_name not in self._rule_templates:
            raise ValueError(f"Unknown rule template: {template_name}")

        template = self._rule_templates[template_name]

        # Substitute parameters in template
        conditions = []
        for cond_template in template["conditions"]:
            condition = RuleCondition(
                id=str(uuid4()),
                field_path=cond_template["field_path"].format(**parameters),
                operator=RuleOperator(cond_template["operator"]),
                value=parameters.get(
                    cond_template["value_param"], cond_template.get("default_value")
                ),
                description=cond_template["description"].format(**parameters),
            )
            conditions.append(condition)

        rule = RuleDefinition(
            id=str(uuid4()),
            name=rule_name,
            description=template["description"].format(**parameters),
            rule_type=RuleType(template["rule_type"]),
            severity=RuleSeverity(
                parameters.get("severity", template.get("default_severity", "medium"))
            ),
            conditions=conditions,
            requirements=requirements or [],
            remediation_guidance=template.get("remediation_guidance", "").format(
                **parameters
            ),
        )

        self._rules[rule.id] = rule
        return rule

    def create_custom_rule(
        self,
        name: str,
        description: str,
        conditions: List[Dict[str, Any]],
        evidence_filters: Dict[str, Any],
        requirements: Optional[List[str]] = None,
        severity: str = "medium",
    ) -> RuleDefinition:
        """Create a custom rule with specific conditions."""

        rule_conditions = []
        for i, cond in enumerate(conditions):
            rule_conditions.append(
                RuleCondition(
                    id=str(uuid4()),
                    field_path=cond["field_path"],
                    operator=RuleOperator(cond["operator"]),
                    value=cond["value"],
                    entity_filter=cond.get("entity_filter"),
                    description=cond.get("description", f"Condition {i+1}"),
                )
            )

        rule = RuleDefinition(
            id=str(uuid4()),
            name=name,
            description=description,
            rule_type=RuleType.CROSS_EVIDENCE,  # Most flexible type
            severity=RuleSeverity(severity),
            conditions=rule_conditions,
            evidence_filters=evidence_filters,
            requirements=requirements or [],
        )

        self._rules[rule.id] = rule
        return rule

    def create_rule_from_policy(
        self, policy_text: str, policy_id: str, requirements: List[str]
    ) -> List[RuleDefinition]:
        """Generate rules from policy text."""

        statements = self.policy_parser.parse_policy_statements(policy_text)
        rules = []

        for i, statement in enumerate(statements):
            if statement["suggested_rules"]:
                rule_name = f"Policy Rule {i+1}: {policy_id}"
                rule = self.policy_parser.generate_rule_from_statement(
                    statement=statement["actionable"],
                    rule_name=rule_name,
                    requirements=requirements,
                    entity_types=[
                        EvidenceEntityType.IDENTITY,
                        EvidenceEntityType.CONFIGURATION,
                    ],
                )

                if rule:
                    rule.derived_from_policy = policy_id
                    self._rules[rule.id] = rule
                    rules.append(rule)

        return rules

    def evaluate_rule(
        self,
        rule_id: str,
        entity_id: Optional[str] = None,
        time_range: Optional[tuple[datetime, datetime]] = None,
    ) -> RuleResult:
        """Evaluate a specific rule."""

        if rule_id not in self._rules:
            raise ValueError(f"Rule not found: {rule_id}")

        rule = self._rules[rule_id]

        # Build evidence query
        query = EvidenceQuery(
            requirements=rule.requirements, time_range=time_range, include_derived=True
        )

        if entity_id:
            query.entity_ids = [entity_id]

        # Apply rule-specific filters
        if rule.evidence_filters:
            if "entity_types" in rule.evidence_filters:
                query.entity_types = [
                    EvidenceEntityType(et)
                    for et in rule.evidence_filters["entity_types"]
                ]
            if "source_systems" in rule.evidence_filters:
                query.source_systems = rule.evidence_filters["source_systems"]

        # Get evidence
        evidence_records = self.evidence_fabric.query_evidence(query)

        # Evaluate conditions
        violations = self._evaluate_conditions(rule, evidence_records)

        result = RuleResult(
            rule_id=rule.id,
            rule_name=rule.name,
            passed=len(violations) == 0,
            severity=rule.severity,
            evaluated_at=datetime.now(),
            evidence_count=len(evidence_records),
            violations=violations,
            entity_id=entity_id,
            requirements=rule.requirements,
            remediation_guidance=rule.remediation_guidance,
            automated_fix_available=bool(rule.automated_remediation),
        )

        return result

    def evaluate_all_rules(
        self, entity_id: Optional[str] = None, requirements: Optional[List[str]] = None
    ) -> List[RuleResult]:
        """Evaluate all enabled rules."""

        results = []

        for rule in self._rules.values():
            if not rule.enabled:
                continue

            # Filter by requirements if specified
            if requirements and not any(
                req in rule.requirements for req in requirements
            ):
                continue

            try:
                result = self.evaluate_rule(rule.id, entity_id)
                results.append(result)
            except Exception as e:
                # Create error result
                error_result = RuleResult(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    passed=False,
                    severity=RuleSeverity.HIGH,
                    evaluated_at=datetime.now(),
                    evidence_count=0,
                    violations=[{"error": str(e)}],
                    requirements=rule.requirements,
                )
                results.append(error_result)

        return results

    def get_rule_definition(self, rule_id: str) -> Optional[RuleDefinition]:
        """Get rule definition by ID."""
        return self._rules.get(rule_id)

    def list_rules(self) -> List[RuleDefinition]:
        """List all rules."""
        return list(self._rules.values())

    def get_no_code_builder_config(self) -> Dict[str, Any]:
        """Get configuration for no-code rule builder UI."""

        return {
            "field_paths": [
                {
                    "path": "normalized_data.mfa_enabled",
                    "type": "boolean",
                    "label": "MFA Enabled",
                },
                {
                    "path": "normalized_data.last_login",
                    "type": "datetime",
                    "label": "Last Login",
                },
                {
                    "path": "normalized_data.permissions",
                    "type": "array",
                    "label": "Permissions",
                },
                {
                    "path": "normalized_data.password_policy.min_length",
                    "type": "number",
                    "label": "Min Password Length",
                },
                {"path": "tags.department", "type": "string", "label": "Department"},
                {"path": "entity_name", "type": "string", "label": "Entity Name"},
            ],
            "operators": [
                {
                    "value": "equals",
                    "label": "Equals",
                    "types": ["string", "number", "boolean"],
                },
                {
                    "value": "not_equals",
                    "label": "Not Equals",
                    "types": ["string", "number", "boolean"],
                },
                {
                    "value": "greater_than",
                    "label": "Greater Than",
                    "types": ["number", "datetime"],
                },
                {
                    "value": "less_than",
                    "label": "Less Than",
                    "types": ["number", "datetime"],
                },
                {
                    "value": "contains",
                    "label": "Contains",
                    "types": ["string", "array"],
                },
                {"value": "exists", "label": "Exists", "types": ["any"]},
                {"value": "not_exists", "label": "Does Not Exist", "types": ["any"]},
            ],
            "entity_types": [
                {"value": "identity", "label": "Identity (Users, Roles)"},
                {"value": "asset", "label": "Asset (Servers, Apps)"},
                {"value": "configuration", "label": "Configuration"},
                {"value": "activity", "label": "Activity (Logs)"},
            ],
            "rule_templates": list(self._rule_templates.keys()),
        }

    def _evaluate_conditions(
        self, rule: RuleDefinition, evidence_records: List[EvidenceRecord]
    ) -> List[Dict[str, Any]]:
        """Evaluate rule conditions against evidence."""

        violations = []

        for record in evidence_records:
            record_violations = []

            for condition in rule.conditions:
                violation = self._evaluate_single_condition(condition, record)
                if violation:
                    record_violations.append(violation)

            # Apply logic operator
            if rule.logic_operator == "AND" and len(record_violations) > 0:
                violations.extend(record_violations)
            elif rule.logic_operator == "OR" and len(record_violations) == len(
                rule.conditions
            ):
                violations.extend(record_violations)

        return violations

    def _evaluate_single_condition(
        self, condition: RuleCondition, record: EvidenceRecord
    ) -> Optional[Dict[str, Any]]:
        """Evaluate a single condition against an evidence record."""

        # Extract field value from record
        field_value = self._extract_field_value(record, condition.field_path)

        # Apply operator
        violates = False

        if condition.operator == RuleOperator.EQUALS:
            violates = field_value != condition.value
        elif condition.operator == RuleOperator.NOT_EQUALS:
            violates = field_value == condition.value
        elif condition.operator == RuleOperator.GREATER_THAN:
            violates = field_value is None or field_value <= condition.value
        elif condition.operator == RuleOperator.LESS_THAN:
            violates = field_value is None or field_value >= condition.value
        elif condition.operator == RuleOperator.EXISTS:
            violates = field_value is None
        elif condition.operator == RuleOperator.NOT_EXISTS:
            violates = field_value is not None
        elif condition.operator == RuleOperator.CONTAINS:
            if isinstance(field_value, (list, str)):
                violates = condition.value not in field_value
            else:
                violates = True

        if violates:
            return {
                "condition_id": condition.id,
                "field_path": condition.field_path,
                "expected": condition.value,
                "actual": field_value,
                "operator": condition.operator.value,
                "entity_id": record.entity_id,
                "entity_name": record.entity_name,
                "source_system": record.source_system,
                "observed_at": record.observed_at.isoformat(),
            }

        return None

    def _extract_field_value(self, record: EvidenceRecord, field_path: str) -> Any:
        """Extract field value from evidence record using dot notation."""

        # Start with the record
        current = {
            "id": str(record.id),
            "entity_id": record.entity_id,
            "entity_name": record.entity_name,
            "entity_type": record.entity_type,
            "source_system": record.source_system,
            "observed_at": record.observed_at,
            "raw_data": record.raw_data or {},
            "normalized_data": record.normalized_data or {},
            "tags": record.tags or {},
        }

        # Navigate the path
        path_parts = field_path.split(".")

        for part in path_parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None

        return current

    def _load_rule_templates(self):
        """Load predefined rule templates."""

        self._rule_templates = {
            "mfa_required": {
                "description": "Verify that {entity_type} has MFA enabled",
                "rule_type": "existence",
                "default_severity": "high",
                "conditions": [
                    {
                        "field_path": "normalized_data.mfa_enabled",
                        "operator": "equals",
                        "value_param": "mfa_required",
                        "default_value": True,
                        "description": "Check MFA enabled for {entity_type}",
                    }
                ],
                "remediation_guidance": "Enable multi-factor authentication for {entity_type}",
            },
            "password_policy": {
                "description": "Verify password policy meets minimum requirements",
                "rule_type": "threshold",
                "default_severity": "medium",
                "conditions": [
                    {
                        "field_path": "normalized_data.password_policy.min_length",
                        "operator": "greater_than",
                        "value_param": "min_length",
                        "default_value": 8,
                        "description": "Check minimum password length",
                    }
                ],
                "remediation_guidance": "Update password policy to require at least {min_length} characters",
            },
            "access_review_currency": {
                "description": "Verify access reviews are current within {review_days} days",
                "rule_type": "temporal",
                "default_severity": "medium",
                "conditions": [
                    {
                        "field_path": "normalized_data.last_access_review",
                        "operator": "greater_than",
                        "value_param": "cutoff_date",
                        "description": "Check access review recency",
                    }
                ],
                "remediation_guidance": "Conduct access review for {entity_type}",
            },
        }


# Factory function
def create_rules_engine(evidence_fabric: EvidenceDataFabric) -> NoCodeRulesEngine:
    """Create and initialize the rules engine."""
    return NoCodeRulesEngine(evidence_fabric)
