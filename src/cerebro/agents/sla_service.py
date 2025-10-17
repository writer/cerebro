"""SLA tracking and alerting for review tasks."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from uuid import UUID

from sqlalchemy import select

from cerebro.agents.models import AgentReviewTask, ReviewTaskStatus
from cerebro.core.database import async_session_factory


class SLAConfig:
    """SLA configuration for review tasks."""
    
    # Default SLA times by priority (in hours)
    DEFAULT_SLAS = {
        "critical": 2,   # 2 hours
        "high": 8,       # 8 hours
        "medium": 24,    # 24 hours
        "low": 72,       # 72 hours
    }
    
    # Escalation thresholds (percentage of SLA elapsed)
    WARNING_THRESHOLD = 0.75  # 75% of SLA
    CRITICAL_THRESHOLD = 1.0  # 100% of SLA (breached)


class SLAStatus:
    """SLA status for a task."""
    
    def __init__(
        self,
        task: AgentReviewTask,
        sla_hours: int,
        elapsed_hours: float,
        remaining_hours: float,
        percentage_elapsed: float,
        is_breached: bool,
        is_at_risk: bool,
    ):
        self.task = task
        self.sla_hours = sla_hours
        self.elapsed_hours = elapsed_hours
        self.remaining_hours = remaining_hours
        self.percentage_elapsed = percentage_elapsed
        self.is_breached = is_breached
        self.is_at_risk = is_at_risk
    
    def to_dict(self) -> Dict:
        return {
            "task_id": str(self.task.id),
            "sla_hours": self.sla_hours,
            "elapsed_hours": round(self.elapsed_hours, 2),
            "remaining_hours": round(self.remaining_hours, 2),
            "percentage_elapsed": round(self.percentage_elapsed * 100, 1),
            "is_breached": self.is_breached,
            "is_at_risk": self.is_at_risk,
            "created_at": self.task.created_at.isoformat(),
            "due_at": self.task.due_at.isoformat() if self.task.due_at else None,
        }


class SLAService:
    """Service for SLA tracking and alerting."""
    
    @staticmethod
    def calculate_sla_status(
        task: AgentReviewTask,
        custom_slas: Optional[Dict[str, int]] = None,
    ) -> SLAStatus:
        """Calculate SLA status for a task."""
        sla_config = custom_slas or SLAConfig.DEFAULT_SLAS
        priority = task.priority or "medium"
        sla_hours = sla_config.get(priority.lower(), SLAConfig.DEFAULT_SLAS["medium"])
        
        # Calculate elapsed time
        now = datetime.now(timezone.utc)
        created_at = task.created_at.replace(tzinfo=timezone.utc) if task.created_at.tzinfo is None else task.created_at
        elapsed = now - created_at
        elapsed_hours = elapsed.total_seconds() / 3600
        
        # Calculate remaining time
        remaining_hours = sla_hours - elapsed_hours
        percentage_elapsed = elapsed_hours / sla_hours if sla_hours > 0 else 0
        
        # Determine breach and risk status
        is_breached = percentage_elapsed >= SLAConfig.CRITICAL_THRESHOLD
        is_at_risk = percentage_elapsed >= SLAConfig.WARNING_THRESHOLD and not is_breached
        
        return SLAStatus(
            task=task,
            sla_hours=sla_hours,
            elapsed_hours=elapsed_hours,
            remaining_hours=remaining_hours,
            percentage_elapsed=percentage_elapsed,
            is_breached=is_breached,
            is_at_risk=is_at_risk,
        )
    
    @staticmethod
    async def get_breached_tasks(
        *,
        org_id: UUID,
        custom_slas: Optional[Dict[str, int]] = None,
    ) -> List[SLAStatus]:
        """Get all tasks that have breached their SLA."""
        async with async_session_factory() as db_session:
            stmt = (
                select(AgentReviewTask)
                .where(AgentReviewTask.org_id == org_id)
                .where(AgentReviewTask.status == ReviewTaskStatus.PENDING)
            )
            result = await db_session.execute(stmt)
            tasks = list(result.scalars())
        
        breached = []
        for task in tasks:
            sla_status = SLAService.calculate_sla_status(task, custom_slas)
            if sla_status.is_breached:
                breached.append(sla_status)
        
        return breached
    
    @staticmethod
    async def get_at_risk_tasks(
        *,
        org_id: UUID,
        custom_slas: Optional[Dict[str, int]] = None,
    ) -> List[SLAStatus]:
        """Get all tasks that are at risk of breaching SLA."""
        async with async_session_factory() as db_session:
            stmt = (
                select(AgentReviewTask)
                .where(AgentReviewTask.org_id == org_id)
                .where(AgentReviewTask.status == ReviewTaskStatus.PENDING)
            )
            result = await db_session.execute(stmt)
            tasks = list(result.scalars())
        
        at_risk = []
        for task in tasks:
            sla_status = SLAService.calculate_sla_status(task, custom_slas)
            if sla_status.is_at_risk:
                at_risk.append(sla_status)
        
        return at_risk
    
    @staticmethod
    async def set_due_date(
        *,
        task_id: UUID,
        due_at: Optional[datetime] = None,
        sla_hours: Optional[int] = None,
    ) -> Optional[AgentReviewTask]:
        """Set or update the due date for a task."""
        async with async_session_factory() as db_session:
            task = await db_session.get(AgentReviewTask, task_id)
            if not task:
                return None
            
            if due_at:
                task.due_at = due_at
            elif sla_hours:
                # Calculate due date based on SLA hours
                task.due_at = task.created_at + timedelta(hours=sla_hours)
            
            await db_session.commit()
            await db_session.refresh(task)
            return task
    
    @staticmethod
    async def get_sla_summary(
        *,
        org_id: UUID,
        custom_slas: Optional[Dict[str, int]] = None,
    ) -> Dict:
        """Get summary statistics for SLA compliance."""
        async with async_session_factory() as db_session:
            stmt = (
                select(AgentReviewTask)
                .where(AgentReviewTask.org_id == org_id)
                .where(AgentReviewTask.status == ReviewTaskStatus.PENDING)
            )
            result = await db_session.execute(stmt)
            tasks = list(result.scalars())
        
        total = len(tasks)
        breached_count = 0
        at_risk_count = 0
        on_track_count = 0
        
        for task in tasks:
            sla_status = SLAService.calculate_sla_status(task, custom_slas)
            if sla_status.is_breached:
                breached_count += 1
            elif sla_status.is_at_risk:
                at_risk_count += 1
            else:
                on_track_count += 1
        
        return {
            "total_pending": total,
            "breached": breached_count,
            "at_risk": at_risk_count,
            "on_track": on_track_count,
            "compliance_rate": round((on_track_count / total * 100) if total > 0 else 100, 1),
        }
