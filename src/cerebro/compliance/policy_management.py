"""
Policy document management and employee attestation system.

Handles policy templates, versioning, approvals, publication, and employee acknowledgments.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from uuid import uuid4

from .evidence_store import EvidenceMetadata, EvidenceStore
from .models import EvidenceCategory


class PolicyStatus(Enum):
    """Status of policy documents."""

    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    PUBLISHED = "published"
    SUPERSEDED = "superseded"
    ARCHIVED = "archived"


class AttestationStatus(Enum):
    """Status of employee attestations."""

    PENDING = "pending"
    ACKNOWLEDGED = "acknowledged"
    OVERDUE = "overdue"
    EXEMPTED = "exempted"


@dataclass
class PolicyTemplate:
    """Template for creating new policy documents."""

    id: str
    name: str
    description: str
    category: str  # security, hr, legal, operational

    # Template content
    template_content: str
    variables: dict[str, Any] = field(default_factory=dict)  # Replaceable variables

    # Framework mappings
    framework_control_mappings: dict[str, list[str]] = field(default_factory=dict)

    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    created_by: str = ""
    updated_at: datetime = field(default_factory=datetime.now)
    version: str = "1.0"

    # Requirements
    requires_legal_review: bool = False
    requires_hr_approval: bool = False
    requires_ciso_approval: bool = True
    annual_review_required: bool = True


@dataclass
class PolicyDocument:
    """Individual policy document with versioning."""

    id: str
    template_id: str | None
    title: str
    content: str
    category: str

    # Versioning
    version: str
    supersedes: str | None = None  # Previous version ID

    # Status and lifecycle
    status: PolicyStatus = PolicyStatus.DRAFT
    effective_date: datetime | None = None
    expiry_date: datetime | None = None
    next_review_date: datetime | None = None

    # Approval workflow
    approvals: list[dict[str, Any]] = field(default_factory=list)
    approval_required_roles: list[str] = field(default_factory=list)

    # Framework compliance
    control_mappings: dict[str, list[str]] = field(default_factory=dict)
    compliance_notes: str = ""

    # Distribution and access
    target_audiences: list[str] = field(
        default_factory=list
    )  # all_employees, contractors, admins
    requires_attestation: bool = True
    attestation_frequency: str = "annually"  # annually, onboarding, policy_change

    # Content metadata
    content_hash: str | None = None
    evidence_item_id: str | None = None  # Reference to stored policy

    # Audit trail
    created_at: datetime = field(default_factory=datetime.now)
    created_by: str = ""
    updated_at: datetime = field(default_factory=datetime.now)
    published_at: datetime | None = None
    published_by: str | None = None

    # Change tracking
    change_summary: str = ""
    change_reason: str = ""


@dataclass
class PolicyAttestation:
    """Employee attestation/acknowledgment of policy."""

    id: str
    policy_id: str
    policy_version: str

    # Employee details
    employee_id: str
    employee_name: str
    employee_email: str
    employee_department: str | None = None

    # Attestation details
    status: AttestationStatus = AttestationStatus.PENDING
    acknowledged_at: datetime | None = None
    ip_address: str | None = None
    user_agent: str | None = None

    # Attestation content
    attestation_text: str = ""
    employee_signature: str | None = None  # Electronic signature
    attestation_method: str = "web_form"  # web_form, email, docusign

    # Deadlines and reminders
    due_date: datetime | None = None
    reminder_sent_at: datetime | None = None
    escalation_sent_at: datetime | None = None

    # Evidence and audit
    evidence_item_id: str | None = None

    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    # Manager and exemptions
    manager_id: str | None = None
    exemption_reason: str | None = None
    exempted_by: str | None = None
    exempted_at: datetime | None = None


@dataclass
class Employee:
    """Basic employee record for policy management."""

    id: str
    name: str
    email: str
    department: str
    job_title: str
    manager_id: str | None = None
    employment_status: str = "active"  # active, inactive, terminated
    start_date: datetime | None = None
    end_date: datetime | None = None

    # Policy-related metadata
    requires_background_check: bool = True
    security_clearance_level: str | None = None
    training_requirements: list[str] = field(default_factory=list)


class PolicyManagementSystem:
    """Manages policy documents, templates, and employee attestations."""

    def __init__(self, evidence_store: EvidenceStore):
        self.evidence_store = evidence_store
        self._templates: dict[str, PolicyTemplate] = {}
        self._policies: dict[str, PolicyDocument] = {}
        self._attestations: dict[str, PolicyAttestation] = {}
        self._employees: dict[str, Employee] = {}

        # Load default templates
        self._load_default_templates()

    def create_policy_from_template(
        self, template_id: str, title: str, variables: dict[str, Any], created_by: str
    ) -> PolicyDocument | None:
        """Create a new policy from a template."""

        if template_id not in self._templates:
            return None

        template = self._templates[template_id]
        policy_id = str(uuid4())

        # Substitute variables in template content
        content = template.template_content
        for var_name, var_value in variables.items():
            content = content.replace(f"{{{var_name}}}", str(var_value))

        policy = PolicyDocument(
            id=policy_id,
            template_id=template_id,
            title=title,
            content=content,
            category=template.category,
            version="1.0",
            control_mappings=template.framework_control_mappings.copy(),
            approval_required_roles=self._get_required_approvers(template),
            target_audiences=["all_employees"],
            created_by=created_by,
        )

        self._policies[policy_id] = policy
        return policy

    def submit_policy_for_approval(
        self, policy_id: str, submitted_by: str, submission_notes: str = ""
    ) -> bool:
        """Submit a policy for approval workflow."""

        if policy_id not in self._policies:
            return False

        policy = self._policies[policy_id]
        if policy.status != PolicyStatus.DRAFT:
            return False

        policy.status = PolicyStatus.IN_REVIEW
        policy.updated_at = datetime.now()

        # Add submission to approvals
        policy.approvals.append(
            {
                "id": str(uuid4()),
                "action": "submitted",
                "actor": submitted_by,
                "timestamp": datetime.now(),
                "notes": submission_notes,
            }
        )

        return True

    def approve_policy(
        self,
        policy_id: str,
        approver_role: str,
        approved_by: str,
        approved: bool,
        notes: str = "",
    ) -> bool:
        """Approve or reject a policy."""

        if policy_id not in self._policies:
            return False

        policy = self._policies[policy_id]

        # Add approval record
        approval = {
            "id": str(uuid4()),
            "action": "approved" if approved else "rejected",
            "role": approver_role,
            "actor": approved_by,
            "timestamp": datetime.now(),
            "notes": notes,
        }

        policy.approvals.append(approval)
        policy.updated_at = datetime.now()

        if not approved:
            policy.status = PolicyStatus.DRAFT
            return True

        # Check if all required approvals are complete
        approved_roles = {
            appr["role"] for appr in policy.approvals if appr["action"] == "approved"
        }

        if set(policy.approval_required_roles).issubset(approved_roles):
            policy.status = PolicyStatus.APPROVED

        return True

    async def publish_policy(
        self,
        policy_id: str,
        published_by: str,
        effective_date: datetime | None = None,
    ) -> bool:
        """Publish an approved policy."""

        if policy_id not in self._policies:
            return False

        policy = self._policies[policy_id]
        if policy.status != PolicyStatus.APPROVED:
            return False

        # Store policy content in evidence store
        evidence_metadata = EvidenceMetadata(
            id=str(uuid4()),
            category=EvidenceCategory.POLICY_DOCUMENT,
            content_type="text/html",
            content_hash="",  # Will be calculated by evidence store
            content_size=0,  # Will be calculated by evidence store
            collector_id="policy_system",
            collector_type="system",
            source_system="cerebro_policy_mgmt",
            collection_method="policy_publication",
            control_id=None,
            framework_name=None,
            tags={
                "policy_id": policy_id,
                "policy_title": policy.title,
                "policy_version": policy.version,
                "policy_category": policy.category,
            },
        )

        # Store the policy content
        evidence_id = await self.evidence_store.store_evidence(
            content=policy.content, metadata=evidence_metadata, seal_immediately=True
        )

        # Update policy
        policy.status = PolicyStatus.PUBLISHED
        policy.published_at = datetime.now()
        policy.published_by = published_by
        policy.effective_date = effective_date or datetime.now()
        policy.evidence_item_id = evidence_id
        policy.updated_at = datetime.now()

        # Set review date
        if policy.next_review_date is None:
            policy.next_review_date = datetime.now() + timedelta(days=365)

        # Create attestation requirements
        if policy.requires_attestation:
            await self._create_attestation_requirements(policy)

        return True

    def get_policy_by_id(self, policy_id: str) -> PolicyDocument | None:
        """Get a policy by ID."""
        return self._policies.get(policy_id)

    def get_published_policies(
        self, category: str | None = None, audience: str | None = None
    ) -> list[PolicyDocument]:
        """Get all published policies, optionally filtered."""

        policies = [
            policy
            for policy in self._policies.values()
            if policy.status == PolicyStatus.PUBLISHED
        ]

        if category:
            policies = [p for p in policies if p.category == category]

        if audience:
            policies = [
                p
                for p in policies
                if audience in p.target_audiences
                or "all_employees" in p.target_audiences
            ]

        return sorted(
            policies, key=lambda p: p.published_at or datetime.min, reverse=True
        )

    async def create_employee_attestation(
        self, policy_id: str, employee_id: str, due_date: datetime | None = None
    ) -> PolicyAttestation | None:
        """Create an attestation requirement for an employee."""

        if policy_id not in self._policies or employee_id not in self._employees:
            return None

        policy = self._policies[policy_id]
        employee = self._employees[employee_id]

        attestation_id = str(uuid4())

        attestation = PolicyAttestation(
            id=attestation_id,
            policy_id=policy_id,
            policy_version=policy.version,
            employee_id=employee_id,
            employee_name=employee.name,
            employee_email=employee.email,
            employee_department=employee.department,
            due_date=due_date or (datetime.now() + timedelta(days=30)),
            attestation_text=f"I acknowledge that I have read and understand the {policy.title} policy.",
        )

        self._attestations[attestation_id] = attestation
        return attestation

    async def submit_attestation(
        self,
        attestation_id: str,
        employee_signature: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> bool:
        """Submit an employee attestation."""

        if attestation_id not in self._attestations:
            return False

        attestation = self._attestations[attestation_id]

        # Create evidence record for the attestation
        evidence_metadata = EvidenceMetadata(
            id=str(uuid4()),
            category=EvidenceCategory.ATTESTATION,
            content_type="application/json",
            content_hash="",
            content_size=0,
            collector_id="policy_system",
            collector_type="system",
            source_system="cerebro_policy_mgmt",
            collection_method="employee_attestation",
            tags={
                "policy_id": attestation.policy_id,
                "employee_id": attestation.employee_id,
                "attestation_type": "policy_acknowledgment",
            },
        )

        attestation_data = {
            "attestation_id": attestation_id,
            "policy_id": attestation.policy_id,
            "policy_version": attestation.policy_version,
            "employee": {
                "id": attestation.employee_id,
                "name": attestation.employee_name,
                "email": attestation.employee_email,
            },
            "attestation_text": attestation.attestation_text,
            "signature": employee_signature,
            "acknowledged_at": datetime.now().isoformat(),
            "ip_address": ip_address,
            "user_agent": user_agent,
        }

        evidence_id = await self.evidence_store.store_evidence(
            content=attestation_data, metadata=evidence_metadata, seal_immediately=True
        )

        # Update attestation
        attestation.status = AttestationStatus.ACKNOWLEDGED
        attestation.acknowledged_at = datetime.now()
        attestation.employee_signature = employee_signature
        attestation.ip_address = ip_address
        attestation.user_agent = user_agent
        attestation.evidence_item_id = evidence_id
        attestation.updated_at = datetime.now()

        return True

    def get_employee_attestation_status(
        self, employee_id: str, policy_id: str | None = None
    ) -> list[dict[str, Any]]:
        """Get attestation status for an employee."""

        attestations = []
        for attestation in self._attestations.values():
            if attestation.employee_id == employee_id:
                if policy_id is None or attestation.policy_id == policy_id:
                    policy = self._policies.get(attestation.policy_id)
                    attestations.append(
                        {
                            "attestation_id": attestation.id,
                            "policy_id": attestation.policy_id,
                            "policy_title": policy.title if policy else "Unknown",
                            "policy_version": attestation.policy_version,
                            "status": attestation.status.value,
                            "due_date": attestation.due_date,
                            "acknowledged_at": attestation.acknowledged_at,
                            "days_overdue": (
                                (datetime.now() - attestation.due_date).days
                                if attestation.due_date
                                and attestation.due_date < datetime.now()
                                and attestation.status == AttestationStatus.PENDING
                                else 0
                            ),
                        }
                    )

        return sorted(attestations, key=lambda x: x["due_date"] or datetime.min)

    def get_attestation_compliance_report(self) -> dict[str, Any]:
        """Generate compliance report for policy attestations."""

        total_attestations = len(self._attestations)
        acknowledged = len(
            [
                a
                for a in self._attestations.values()
                if a.status == AttestationStatus.ACKNOWLEDGED
            ]
        )
        pending = len(
            [
                a
                for a in self._attestations.values()
                if a.status == AttestationStatus.PENDING
            ]
        )
        overdue = len(
            [
                a
                for a in self._attestations.values()
                if a.status == AttestationStatus.PENDING
                and a.due_date
                and a.due_date < datetime.now()
            ]
        )

        # Group by policy
        policy_stats: dict[str, dict[str, Any]] = {}
        for attestation in self._attestations.values():
            policy_id = attestation.policy_id
            if policy_id not in policy_stats:
                policy = self._policies.get(policy_id)
                policy_stats[policy_id] = {
                    "policy_title": policy.title if policy else "Unknown",
                    "total": 0,
                    "acknowledged": 0,
                    "pending": 0,
                    "overdue": 0,
                }

            policy_stats[policy_id]["total"] += 1
            if attestation.status == AttestationStatus.ACKNOWLEDGED:
                policy_stats[policy_id]["acknowledged"] += 1
            elif attestation.status == AttestationStatus.PENDING:
                policy_stats[policy_id]["pending"] += 1
                if attestation.due_date and attestation.due_date < datetime.now():
                    policy_stats[policy_id]["overdue"] += 1

        return {
            "generated_at": datetime.now(),
            "summary": {
                "total_attestations": total_attestations,
                "acknowledged": acknowledged,
                "pending": pending,
                "overdue": overdue,
                "compliance_rate": (
                    (acknowledged / total_attestations * 100)
                    if total_attestations > 0
                    else 0
                ),
            },
            "policy_breakdown": {
                pid: {
                    **stats,
                    "compliance_rate": (
                        (stats["acknowledged"] / stats["total"] * 100)
                        if stats["total"] > 0
                        else 0
                    ),
                }
                for pid, stats in policy_stats.items()
            },
        }

    async def _create_attestation_requirements(self, policy: PolicyDocument) -> None:
        """Create attestation requirements for all applicable employees."""

        # Get target employees
        target_employees = []
        for employee in self._employees.values():
            if employee.employment_status == "active":
                # Check if employee is in target audience
                if "all_employees" in policy.target_audiences:
                    target_employees.append(employee)
                elif employee.department in policy.target_audiences:
                    target_employees.append(employee)

        # Create attestations
        for employee in target_employees:
            await self.create_employee_attestation(
                policy_id=policy.id,
                employee_id=employee.id,
                due_date=datetime.now() + timedelta(days=30),
            )

    def _get_required_approvers(self, template: PolicyTemplate) -> list[str]:
        """Get list of required approver roles for a template."""
        approvers = []

        if template.requires_legal_review:
            approvers.append("legal")
        if template.requires_hr_approval:
            approvers.append("hr")
        if template.requires_ciso_approval:
            approvers.append("ciso")

        return approvers

    def _load_default_templates(self) -> None:
        """Load default policy templates."""

        templates = [
            PolicyTemplate(
                id="security_policy",
                name="Information Security Policy",
                description="Company-wide information security policy",
                category="security",
                template_content="""
# {company_name} Information Security Policy

## Purpose
This policy establishes the framework for protecting {company_name}'s information assets.

## Scope
This policy applies to all employees, contractors, and third parties.

## Policy Statements
1. All users must use strong passwords and multi-factor authentication
2. Data must be classified and protected according to its sensitivity
3. Security incidents must be reported immediately
4. Regular security training is mandatory

## Compliance
Violations of this policy may result in disciplinary action.
                """.strip(),
                variables={"company_name": ""},
                framework_control_mappings={
                    "soc2": ["CC6.1", "CC6.2", "CC7.1"],
                    "iso27001": ["A.5.1.1", "A.9.1.1", "A.12.1.1"],
                },
                requires_ciso_approval=True,
                requires_legal_review=True,
            ),
            PolicyTemplate(
                id="acceptable_use_policy",
                name="Acceptable Use Policy",
                description="Policy governing acceptable use of company IT resources",
                category="security",
                template_content="""
# {company_name} Acceptable Use Policy

## Purpose
Define acceptable use of {company_name} information technology resources.

## Acceptable Use
- Business-related activities
- Authorized personal use as permitted
- Compliance with all applicable laws

## Prohibited Activities
- Unauthorized access or disclosure of data
- Installing unauthorized software
- Using systems for illegal activities

## Monitoring
Usage may be monitored and logged for security purposes.
                """.strip(),
                variables={"company_name": ""},
                framework_control_mappings={"soc2": ["CC6.3"], "iso27001": ["A.8.1.3"]},
            ),
        ]

        for template in templates:
            self._templates[template.id] = template

    # Employee management methods
    def add_employee(self, employee: Employee) -> None:
        """Add an employee to the system."""
        self._employees[employee.id] = employee

    def get_employee(self, employee_id: str) -> Employee | None:
        """Get an employee by ID."""
        return self._employees.get(employee_id)

    def get_active_employees(self) -> list[Employee]:
        """Get all active employees."""
        return [
            emp for emp in self._employees.values() if emp.employment_status == "active"
        ]
