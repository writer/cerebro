"""
Audit workflows for compliance management.

Provides request lists, task management, approvals, and auditor portals
that compliance managers and auditors expect.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from uuid import uuid4

from .evidence_store import EvidenceBundle, EvidenceStore
from .frameworks import get_framework


class TaskStatus(Enum):
    """Status of audit tasks."""

    DRAFT = "draft"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    SUBMITTED = "submitted"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXCEPTION_REQUESTED = "exception_requested"
    EXCEPTION_APPROVED = "exception_approved"
    COMPLETED = "completed"
    OVERDUE = "overdue"


class RequestListType(Enum):
    """Types of audit request lists."""

    SOC2_TYPE1 = "soc2_type1"
    SOC2_TYPE2 = "soc2_type2"
    ISO27001 = "iso27001"
    PCI_DSS = "pci_dss"
    CUSTOM = "custom"
    INTERNAL_REVIEW = "internal_review"


class ExceptionType(Enum):
    """Types of control exceptions."""

    RISK_ACCEPTED = "risk_accepted"
    COMPENSATING_CONTROL = "compensating_control"
    REMEDIATION_PLAN = "remediation_plan"
    NOT_APPLICABLE = "not_applicable"
    TEMPORARY = "temporary"


@dataclass
class AuditTask:
    """Individual audit task within a request list."""

    id: str
    request_list_id: str
    control_id: str
    framework_name: str

    # Task details
    title: str
    description: str
    instructions: str
    priority: str = "medium"  # low, medium, high, critical

    # Assignment and timing
    assignee: str | None = None
    reviewer: str | None = None
    due_date: datetime | None = None
    estimated_hours: float | None = None

    # Status and progress
    status: TaskStatus = TaskStatus.DRAFT
    progress_percentage: int = 0

    # Evidence and deliverables
    required_evidence_types: list[str] = field(default_factory=list)
    submitted_evidence_ids: list[str] = field(default_factory=list)
    attestation_required: bool = False
    attestation_text: str | None = None
    attestation_signed_by: str | None = None
    attestation_signed_at: datetime | None = None

    # Communication and approval
    comments: list[dict[str, Any]] = field(default_factory=list)
    reviewer_notes: str | None = None
    approval_notes: str | None = None

    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    completed_at: datetime | None = None

    # Sampling (if applicable)
    sample_size: int | None = None
    sample_selection_method: str | None = None
    sample_items: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ControlException:
    """Exception or compensating control for audit findings."""

    id: str
    control_id: str
    framework_name: str
    request_list_id: str | None = None

    # Exception details
    exception_type: ExceptionType = ExceptionType.RISK_ACCEPTED
    title: str = ""
    description: str = ""
    justification: str = ""

    # Risk and impact
    risk_level: str = "medium"  # low, medium, high, critical
    business_impact: str = ""
    technical_impact: str = ""

    # Compensating controls (if applicable)
    compensating_controls: list[str] = field(default_factory=list)
    compensating_evidence_ids: list[str] = field(default_factory=list)

    # Remediation plan (if applicable)
    remediation_plan: str = ""
    remediation_due_date: datetime | None = None
    remediation_owner: str | None = None
    remediation_status: str = "not_started"

    # Approval workflow
    requested_by: str = ""
    approved_by: str | None = None
    approved_at: datetime | None = None
    expires_at: datetime | None = None

    # Review cycle
    next_review_date: datetime | None = None
    review_frequency: str = "annually"  # quarterly, annually

    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class AuditRequestList:
    """Collection of audit tasks for a specific framework and period."""

    id: str
    name: str
    description: str

    # Framework and scope
    framework_name: str
    request_type: RequestListType

    # Audit period
    period_start: datetime
    period_end: datetime

    # Optional fields with defaults
    scope_description: str = ""
    opinion_date: datetime | None = None  # For Type II audits

    # Tasks and evidence
    task_ids: list[str] = field(default_factory=list)
    evidence_bundle_id: str | None = None

    # Parties and roles
    audit_firm: str = ""
    lead_auditor: str = ""
    client_contact: str = ""

    # Status and progress
    status: str = "draft"  # draft, active, in_review, completed
    progress_percentage: int = 0

    # Deadlines and milestones
    kickoff_date: datetime | None = None
    interim_date: datetime | None = None  # For Type II
    final_due_date: datetime | None = None

    # Quality and completeness
    total_tasks: int = 0
    completed_tasks: int = 0
    approved_tasks: int = 0
    exception_tasks: int = 0

    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    created_by: str = ""
    updated_at: datetime = field(default_factory=datetime.now)
    tags: dict[str, str] = field(default_factory=dict)


class AuditWorkflowManager:
    """Manages audit workflows, tasks, and request lists."""

    def __init__(self, evidence_store: EvidenceStore):
        self.evidence_store = evidence_store
        self._request_lists: dict[str, AuditRequestList] = {}
        self._tasks: dict[str, AuditTask] = {}
        self._exceptions: dict[str, ControlException] = {}

    def create_request_list(
        self,
        framework_name: str,
        request_type: RequestListType,
        period_start: datetime,
        period_end: datetime,
        name: str | None = None,
        scope_controls: list[str] | None = None,
    ) -> AuditRequestList:
        """Create a new audit request list."""

        request_id = str(uuid4())

        if not name:
            name = (
                f"{framework_name.upper()} {request_type.value} - {period_start.year}"
            )

        request_list = AuditRequestList(
            id=request_id,
            name=name,
            description=f"{request_type.value} audit for {framework_name}",
            framework_name=framework_name,
            request_type=request_type,
            period_start=period_start,
            period_end=period_end,
        )

        # Generate tasks for the framework
        tasks = self._generate_tasks_for_framework(
            request_list, framework_name, scope_controls
        )

        request_list.task_ids = [task.id for task in tasks]
        request_list.total_tasks = len(tasks)

        # Store request list and tasks
        self._request_lists[request_id] = request_list
        for task in tasks:
            self._tasks[task.id] = task

        return request_list

    def assign_task(
        self,
        task_id: str,
        assignee: str,
        due_date: datetime | None = None,
        reviewer: str | None = None,
    ) -> bool:
        """Assign a task to a team member."""
        if task_id not in self._tasks:
            return False

        task = self._tasks[task_id]
        task.assignee = assignee
        task.reviewer = reviewer
        task.due_date = due_date
        task.status = TaskStatus.ASSIGNED
        task.updated_at = datetime.now()

        self._add_task_comment(task_id, f"Task assigned to {assignee}", "system")
        return True

    def submit_task_evidence(
        self,
        task_id: str,
        evidence_ids: list[str],
        comments: str | None = None,
        submitted_by: str | None = None,
    ) -> bool:
        """Submit evidence for a task."""
        if task_id not in self._tasks:
            return False

        task = self._tasks[task_id]
        task.submitted_evidence_ids.extend(evidence_ids)
        task.status = TaskStatus.SUBMITTED
        task.progress_percentage = 100
        task.updated_at = datetime.now()

        if comments:
            self._add_task_comment(task_id, comments, submitted_by or "unknown")

        # Update request list progress
        self._update_request_list_progress(task.request_list_id)
        return True

    def review_task(
        self,
        task_id: str,
        approved: bool,
        reviewer_notes: str | None = None,
        reviewer: str | None = None,
    ) -> bool:
        """Review and approve/reject a submitted task."""
        if task_id not in self._tasks:
            return False

        task = self._tasks[task_id]
        task.reviewer_notes = reviewer_notes
        task.status = TaskStatus.APPROVED if approved else TaskStatus.REJECTED
        task.updated_at = datetime.now()

        if approved:
            task.completed_at = datetime.now()

        comment = (
            f"Task {'approved' if approved else 'rejected'} by {reviewer or 'reviewer'}"
        )
        if reviewer_notes:
            comment += f": {reviewer_notes}"

        self._add_task_comment(task_id, comment, reviewer or "reviewer")

        # Update request list progress
        self._update_request_list_progress(task.request_list_id)
        return True

    def create_control_exception(
        self,
        control_id: str,
        framework_name: str,
        exception_type: ExceptionType,
        title: str,
        description: str,
        justification: str,
        requested_by: str,
        expires_at: datetime | None = None,
        request_list_id: str | None = None,
    ) -> ControlException:
        """Create a control exception request."""

        exception_id = str(uuid4())

        exception = ControlException(
            id=exception_id,
            control_id=control_id,
            framework_name=framework_name,
            request_list_id=request_list_id,
            exception_type=exception_type,
            title=title,
            description=description,
            justification=justification,
            requested_by=requested_by,
            expires_at=expires_at,
        )

        self._exceptions[exception_id] = exception
        return exception

    def approve_exception(
        self, exception_id: str, approved_by: str, approval_notes: str | None = None
    ) -> bool:
        """Approve a control exception."""
        if exception_id not in self._exceptions:
            return False

        exception = self._exceptions[exception_id]
        exception.approved_by = approved_by
        exception.approved_at = datetime.now()
        exception.updated_at = datetime.now()

        # Set next review date
        if exception.review_frequency == "quarterly":
            exception.next_review_date = datetime.now() + timedelta(days=90)
        else:
            exception.next_review_date = datetime.now() + timedelta(days=365)

        return True

    async def create_evidence_bundle_for_request(
        self, request_list_id: str, bundle_name: str | None = None
    ) -> str | None:
        """Create evidence bundle for a request list."""
        if request_list_id not in self._request_lists:
            return None

        request_list = self._request_lists[request_list_id]

        # Collect all evidence from completed tasks
        evidence_ids = []
        control_ids = []

        for task_id in request_list.task_ids:
            if task_id in self._tasks:
                task = self._tasks[task_id]
                evidence_ids.extend(task.submitted_evidence_ids)
                if task.control_id not in control_ids:
                    control_ids.append(task.control_id)

        if not evidence_ids:
            return None

        bundle_id = str(uuid4())
        bundle_name = bundle_name or f"{request_list.name} Evidence Bundle"

        bundle = EvidenceBundle(
            id=bundle_id,
            name=bundle_name,
            description=f"Evidence bundle for {request_list.framework_name} audit",
            framework_name=request_list.framework_name,
            control_ids=control_ids,
            evidence_ids=evidence_ids,
            period_start=request_list.period_start,
            period_end=request_list.period_end,
            created_by="system",
        )

        # Create the bundle in evidence store
        await self.evidence_store.create_evidence_bundle(bundle)

        # Update request list
        request_list.evidence_bundle_id = bundle_id
        request_list.updated_at = datetime.now()

        return bundle_id

    def get_request_list_status(self, request_list_id: str) -> dict[str, Any] | None:
        """Get detailed status of a request list."""
        if request_list_id not in self._request_lists:
            return None

        request_list = self._request_lists[request_list_id]

        # Count tasks by status
        task_statuses: dict[str, int] = {}
        overdue_tasks: list[dict[str, Any]] = []

        for task_id in request_list.task_ids:
            if task_id in self._tasks:
                task = self._tasks[task_id]
                status = task.status.value
                task_statuses[status] = task_statuses.get(status, 0) + 1

                # Check for overdue tasks
                if (
                    task.due_date
                    and task.due_date < datetime.now()
                    and task.status not in [TaskStatus.COMPLETED, TaskStatus.APPROVED]
                ):
                    overdue_tasks.append(
                        {
                            "task_id": task.id,
                            "title": task.title,
                            "assignee": task.assignee,
                            "due_date": task.due_date,
                            "days_overdue": (datetime.now() - task.due_date).days,
                        }
                    )

        return {
            "request_list": request_list,
            "task_statuses": task_statuses,
            "overdue_tasks": overdue_tasks,
            "completion_percentage": request_list.progress_percentage,
            "evidence_bundle_ready": bool(request_list.evidence_bundle_id),
            "total_tasks": request_list.total_tasks,
            "completed_tasks": request_list.completed_tasks,
        }

    def get_auditor_portal_data(
        self, request_list_id: str, _auditor_email: str
    ) -> dict[str, Any] | None:
        """Get read-only data for auditor portal."""
        if request_list_id not in self._request_lists:
            return None

        request_list = self._request_lists[request_list_id]

        # Get tasks with evidence
        tasks_data = []
        for task_id in request_list.task_ids:
            if task_id in self._tasks:
                task = self._tasks[task_id]
                if task.status in [TaskStatus.APPROVED, TaskStatus.COMPLETED]:
                    tasks_data.append(
                        {
                            "control_id": task.control_id,
                            "title": task.title,
                            "status": task.status.value,
                            "evidence_count": len(task.submitted_evidence_ids),
                            "completed_at": task.completed_at,
                            "attestation_signed": bool(task.attestation_signed_at),
                        }
                    )

        # Get exceptions
        exceptions_data = []
        for exception in self._exceptions.values():
            if (
                exception.framework_name == request_list.framework_name
                and exception.request_list_id == request_list_id
            ):
                exceptions_data.append(
                    {
                        "control_id": exception.control_id,
                        "exception_type": exception.exception_type.value,
                        "title": exception.title,
                        "approved": bool(exception.approved_by),
                        "expires_at": exception.expires_at,
                    }
                )

        return {
            "audit_info": {
                "framework": request_list.framework_name,
                "period_start": request_list.period_start,
                "period_end": request_list.period_end,
                "opinion_date": request_list.opinion_date,
                "audit_firm": request_list.audit_firm,
                "lead_auditor": request_list.lead_auditor,
            },
            "controls_tested": len(tasks_data),
            "tasks": tasks_data,
            "exceptions": exceptions_data,
            "evidence_bundle_id": request_list.evidence_bundle_id,
            "last_updated": request_list.updated_at,
            "access_granted_at": datetime.now(),
        }

    def _generate_tasks_for_framework(
        self,
        request_list: AuditRequestList,
        framework_name: str,
        scope_controls: list[str] | None = None,
    ) -> list[AuditTask]:
        """Generate audit tasks for a compliance framework."""

        framework = get_framework(framework_name)
        if not framework:
            return []

        tasks = []
        controls = framework.controls

        # Filter by scope if specified
        if scope_controls:
            controls = [c for c in controls if c.control_id in scope_controls]

        for control in controls:
            task_id = str(uuid4())

            # Determine due date based on audit schedule
            if request_list.request_type == RequestListType.SOC2_TYPE2:
                # Type II audits need interim and final testing
                due_date = request_list.period_end - timedelta(days=30)
            else:
                due_date = request_list.final_due_date or request_list.period_end

            # Determine required evidence types
            evidence_types = control.evidence_collection_methods or []

            task = AuditTask(
                id=task_id,
                request_list_id=request_list.id,
                control_id=control.control_id,
                framework_name=framework_name,
                title=f"{control.control_id}: {control.title}",
                description=control.description,
                instructions=control.remediation_guidance,
                due_date=due_date,
                required_evidence_types=evidence_types,
                attestation_required=control.control_type.value == "administrative",
            )

            tasks.append(task)

        return tasks

    def _add_task_comment(self, task_id: str, comment: str, author: str) -> None:
        """Add a comment to a task."""
        if task_id in self._tasks:
            task = self._tasks[task_id]
            task.comments.append(
                {
                    "id": str(uuid4()),
                    "author": author,
                    "comment": comment,
                    "timestamp": datetime.now(),
                    "type": "comment",
                }
            )

    def _update_request_list_progress(self, request_list_id: str) -> None:
        """Update progress percentage for a request list."""
        if request_list_id not in self._request_lists:
            return

        request_list = self._request_lists[request_list_id]
        completed = 0
        approved = 0
        exceptions = 0

        for task_id in request_list.task_ids:
            if task_id in self._tasks:
                task = self._tasks[task_id]
                if task.status == TaskStatus.COMPLETED:
                    completed += 1
                elif task.status == TaskStatus.APPROVED:
                    approved += 1
                    completed += 1
                elif task.status == TaskStatus.EXCEPTION_APPROVED:
                    exceptions += 1
                    completed += 1

        request_list.completed_tasks = completed
        request_list.approved_tasks = approved
        request_list.exception_tasks = exceptions

        if request_list.total_tasks > 0:
            request_list.progress_percentage = int(
                (completed / request_list.total_tasks) * 100
            )

        request_list.updated_at = datetime.now()


# Utility functions for common audit workflows
def create_soc2_type2_request_list(
    workflow_manager: AuditWorkflowManager,
    period_start: datetime,
    period_end: datetime,
    audit_firm: str = "",
    lead_auditor: str = "",
) -> AuditRequestList:
    """Create a SOC 2 Type II audit request list."""
    request_list = workflow_manager.create_request_list(
        framework_name="soc2",
        request_type=RequestListType.SOC2_TYPE2,
        period_start=period_start,
        period_end=period_end,
    )

    request_list.audit_firm = audit_firm
    request_list.lead_auditor = lead_auditor
    request_list.opinion_date = period_end + timedelta(
        days=45
    )  # Standard 45-day opinion

    return request_list


async def generate_audit_readiness_report(
    workflow_manager: AuditWorkflowManager, framework_name: str
) -> dict[str, Any]:
    """Generate a report on audit readiness for a framework."""

    # This would integrate with the control test results
    # and evidence store to provide comprehensive readiness metrics

    return {
        "framework": framework_name,
        "generated_at": datetime.now(),
        "summary": "Audit readiness analysis placeholder",
        "recommendations": [
            "Complete automated control testing",
            "Gather missing manual evidence",
            "Review and approve control exceptions",
        ],
    }
