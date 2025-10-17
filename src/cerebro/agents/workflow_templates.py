"""Workflow templates for review task automation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from uuid import UUID

from cerebro.agents.models import ReviewTaskStatus


@dataclass
class WorkflowStep:
    """A single step in a workflow template."""
    
    name: str
    description: str
    action: str  # status change, assignment, notification, etc.
    conditions: Dict[str, Any]
    parameters: Dict[str, Any]
    order: int


@dataclass
class WorkflowTemplate:
    """Template for automated review task workflows."""
    
    id: str
    name: str
    description: str
    trigger: str  # on_create, on_status_change, on_sla_breach, etc.
    conditions: Dict[str, Any]
    steps: List[WorkflowStep]
    metadata: Dict[str, Any]


class WorkflowTemplateLibrary:
    """Built-in workflow templates."""
    
    CRITICAL_ESCALATION = WorkflowTemplate(
        id="critical_escalation",
        name="Critical Priority Auto-Escalation",
        description="Automatically escalate critical priority tasks if not resolved within SLA",
        trigger="on_sla_breach",
        conditions={"priority": "critical"},
        steps=[
            WorkflowStep(
                name="Escalate to security manager",
                description="Automatically escalate to security team lead",
                action="escalate",
                conditions={},
                parameters={
                    "escalated_to": "security_manager",
                    "notification_channel": "slack",
                },
                order=1,
            ),
            WorkflowStep(
                name="Create high-priority ticket",
                description="Create ticket in ticketing system",
                action="create_ticket",
                conditions={},
                parameters={
                    "ticket_system": "jira",
                    "priority": "P0",
                },
                order=2,
            ),
        ],
        metadata={"category": "escalation", "auto_run": True},
    )
    
    SECURITY_FINDING_WORKFLOW = WorkflowTemplate(
        id="security_finding_workflow",
        name="Security Finding Review Workflow",
        description="Standard workflow for security finding reviews",
        trigger="on_create",
        conditions={"payload.type": "security_finding"},
        steps=[
            WorkflowStep(
                name="Assign to security analyst",
                description="Auto-assign to on-call security analyst",
                action="assign",
                conditions={},
                parameters={
                    "assigned_to": "{{on_call_analyst}}",
                },
                order=1,
            ),
            WorkflowStep(
                name="Set SLA based on severity",
                description="Set due date based on finding severity",
                action="set_due_date",
                conditions={},
                parameters={
                    "sla_mapping": {
                        "critical": 2,
                        "high": 8,
                        "medium": 24,
                        "low": 72,
                    }
                },
                order=2,
            ),
            WorkflowStep(
                name="Notify security channel",
                description="Post notification to security Slack channel",
                action="notify",
                conditions={},
                parameters={
                    "channel": "slack",
                    "channel_id": "#security-alerts",
                },
                order=3,
            ),
        ],
        metadata={"category": "security", "auto_run": True},
    )
    
    COMPLIANCE_AUDIT_WORKFLOW = WorkflowTemplate(
        id="compliance_audit_workflow",
        name="Compliance Audit Workflow",
        description="Workflow for compliance-related agent actions",
        trigger="on_create",
        conditions={"payload.type": "compliance_action"},
        steps=[
            WorkflowStep(
                name="Require dual approval",
                description="Set status to require two approvals",
                action="set_approval_threshold",
                conditions={},
                parameters={
                    "required_approvals": 2,
                    "approver_roles": ["compliance_officer", "security_manager"],
                },
                order=1,
            ),
            WorkflowStep(
                name="Create audit trail entry",
                description="Log to compliance audit log",
                action="create_audit_entry",
                conditions={},
                parameters={
                    "audit_type": "compliance_review",
                    "retention_years": 7,
                },
                order=2,
            ),
        ],
        metadata={"category": "compliance", "auto_run": False},
    )
    
    AUTO_APPROVE_LOW_RISK = WorkflowTemplate(
        id="auto_approve_low_risk",
        name="Auto-Approve Low Risk Actions",
        description="Automatically approve low-risk, routine actions",
        trigger="on_create",
        conditions={
            "priority": "low",
            "payload.risk_score": {"$lt": 30},
        },
        steps=[
            WorkflowStep(
                name="Add automated approval comment",
                description="Add comment explaining auto-approval",
                action="add_comment",
                conditions={},
                parameters={
                    "content": "Automatically approved due to low risk score and established trust pattern.",
                    "author": "system",
                },
                order=1,
            ),
            WorkflowStep(
                name="Approve task",
                description="Set status to approved",
                action="approve",
                conditions={},
                parameters={
                    "resolved_by": "system",
                    "notes": "Auto-approved by workflow",
                },
                order=2,
            ),
        ],
        metadata={"category": "automation", "auto_run": False},
    )
    
    @classmethod
    def get_all_templates(cls) -> List[WorkflowTemplate]:
        """Get all available workflow templates."""
        return [
            cls.CRITICAL_ESCALATION,
            cls.SECURITY_FINDING_WORKFLOW,
            cls.COMPLIANCE_AUDIT_WORKFLOW,
            cls.AUTO_APPROVE_LOW_RISK,
        ]
    
    @classmethod
    def get_template(cls, template_id: str) -> Optional[WorkflowTemplate]:
        """Get a specific template by ID."""
        for template in cls.get_all_templates():
            if template.id == template_id:
                return template
        return None
    
    @classmethod
    def get_templates_by_trigger(cls, trigger: str) -> List[WorkflowTemplate]:
        """Get all templates for a specific trigger."""
        return [
            template
            for template in cls.get_all_templates()
            if template.trigger == trigger
        ]


class WorkflowEngine:
    """Execute workflow templates."""
    
    @staticmethod
    def evaluate_conditions(
        conditions: Dict[str, Any],
        context: Dict[str, Any],
    ) -> bool:
        """Evaluate if conditions match the context."""
        for key, expected_value in conditions.items():
            # Handle nested keys with dot notation
            context_value = WorkflowEngine._get_nested_value(context, key)
            
            # Handle comparison operators
            if isinstance(expected_value, dict):
                if "$lt" in expected_value and context_value >= expected_value["$lt"]:
                    return False
                if "$gt" in expected_value and context_value <= expected_value["$gt"]:
                    return False
                if "$eq" in expected_value and context_value != expected_value["$eq"]:
                    return False
            elif context_value != expected_value:
                return False
        
        return True
    
    @staticmethod
    def _get_nested_value(data: Dict[str, Any], key_path: str) -> Any:
        """Get value from nested dict using dot notation."""
        keys = key_path.split(".")
        value = data
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value
    
    @staticmethod
    async def find_matching_templates(
        trigger: str,
        context: Dict[str, Any],
    ) -> List[WorkflowTemplate]:
        """Find all templates that match the trigger and conditions."""
        matching = []
        templates = WorkflowTemplateLibrary.get_templates_by_trigger(trigger)
        
        for template in templates:
            if WorkflowEngine.evaluate_conditions(template.conditions, context):
                matching.append(template)
        
        return matching
    
    @staticmethod
    def to_dict(template: WorkflowTemplate) -> Dict[str, Any]:
        """Convert workflow template to dict representation."""
        return {
            "id": template.id,
            "name": template.name,
            "description": template.description,
            "trigger": template.trigger,
            "conditions": template.conditions,
            "steps": [
                {
                    "name": step.name,
                    "description": step.description,
                    "action": step.action,
                    "conditions": step.conditions,
                    "parameters": step.parameters,
                    "order": step.order,
                }
                for step in sorted(template.steps, key=lambda s: s.order)
            ],
            "metadata": template.metadata,
        }
