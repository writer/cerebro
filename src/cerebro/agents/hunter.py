"""
Hunter Agent Service

Proactive security hunting that uses the Attack Graph to identify and
remediate high-risk attack paths before they can be exploited.
"""

import structlog
from typing import List, Any
from uuid import UUID
from datetime import datetime, UTC

from cerebro.core.database import async_session_factory
from cerebro.attack_path.graph_model import get_attack_graph
from cerebro.attack_path.path_analysis import get_path_analyzer, PathQuery, PathType, AttackPath
from cerebro.agents.models import AgentSession, AgentType
from cerebro.agents.review_service import AgentReviewService
from cerebro.agents.models import ReviewTaskStatus

logger = structlog.get_logger(__name__)

class HunterService:
    """
    Proactive threat hunting service.
    
    Identifies high-risk attack paths using the graph engine and creates
    remediation tasks for human review.
    """
    
    @staticmethod
    async def hunt(org_id: UUID, dry_run: bool = False) -> List[Any]:
        """
        Execute a hunting run for the organization.
        
        Args:
            org_id: Organization ID to hunt in
            dry_run: If True, do not create tasks, just return findings
            
        Returns:
            List of created tasks or findings
        """
        logger.info("Starting hunter run", org_id=str(org_id))
        
        # 1. Get Graph & Analyzer
        # Convert UUID to str for graph components as they expect string IDs mostly
        org_id_str = str(org_id)
        
        # Ensure graph is fresh
        attack_graph = await get_attack_graph(org_id_str, rebuild=True)
        path_analyzer = await get_path_analyzer(org_id_str)
        
        # 2. Define Hunting Queries
        # We look for:
        # - Critical paths to high-value targets
        # - Privilege escalation paths
        # - Shortest paths to critical assets from internet-exposed principals
        
        queries = [
            # High-value target compromise paths
            PathQuery(
                source_principal=None, # Any source
                target_resource=None, # Any high-value target (logic inside analyzer handles this if target is None)
                max_path_length=5,
                path_type=PathType.K_STEP_ESCALATION, # Looks for escalation patterns
                min_privilege_level=1, # Write/Admin access
                exclude_conditions=[]
            ),
            # Privilege Escalation detection
            PathQuery(
                source_principal=None, # Any principal
                target_resource=None, 
                max_path_length=4,
                path_type=PathType.PRIVILEGE_ESCALATION,
                min_privilege_level=0,
                exclude_conditions=[]
            )
        ]
        
        found_paths: List[AttackPath] = []
        for query in queries:
            paths = await path_analyzer.find_attack_paths(query)
            # Filter for high/critical severity only
            high_risk_paths = [p for p in paths if p.severity.value in ('high', 'critical')]
            found_paths.extend(high_risk_paths)
            
        # Deduplicate paths by ID
        unique_paths = {p.path_id: p for p in found_paths}.values()
        
        logger.info(f"Hunter found {len(unique_paths)} unique high-risk paths")
        
        results = []
        
        if not unique_paths:
            return results

        # 3. Create Hunter Session context
        # We need a session to anchor the review tasks
        session = await HunterService._ensure_hunter_session(org_id)
        
        # 4. Create Review Tasks for each unique path
        for path in unique_paths:
            if dry_run:
                results.append({
                    "type": "attack_path",
                    "id": path.path_id,
                    "severity": path.severity.value,
                    "steps": len(path.steps),
                    "target": path.target_resource
                })
                continue
                
            # Check if we already have an open task for this path signature
            # This prevents spamming duplicate tasks for the same issue
            if await HunterService._task_exists_for_path(org_id, path.path_id):
                logger.debug(f"Skipping existing task for path {path.path_id}")
                continue
                
            # Create the task
            task = await AgentReviewService.create_task(
                session=session,
                created_by="hunter_agent",
                title=f"Fix {path.severity.value} risk: {path.target_resource}",
                summary=f"Attack path detected: {path.source_principal} -> {path.target_resource} ({len(path.steps)} steps)",
                priority=path.severity.value,
                payload={
                    "path_id": path.path_id,
                    "source": path.source_principal,
                    "target": path.target_resource,
                    "steps": [
                        {
                            "source": s.source_node,
                            "target": s.target_node,
                            "permission": s.permission,
                            "description": s.description
                        } for s in path.steps
                    ],
                    "mitigations": path.mitigations,
                    "exploitability": path.exploitability_score
                },
                notification_channel="slack" # Default to slack for hunter findings
            )
            
            logger.info(f"Created hunter task {task.id} for path {path.path_id}")
            results.append(task)
            
        return results

    @staticmethod
    async def _ensure_hunter_session(org_id: UUID) -> AgentSession:
        """Get or create a persistent session for the Hunter Agent."""
        async with async_session_factory() as db_session:
            # Look for active hunter session
            from sqlalchemy import select
            stmt = select(AgentSession).where(
                AgentSession.org_id == org_id,
                AgentSession.agent_type == AgentType.SECURITY_ANALYST,
                AgentSession.title == "Hunter Agent - Continuous Monitoring"
            ).order_by(AgentSession.created_at.desc()).limit(1)
            
            session = (await db_session.execute(stmt)).scalar_one_or_none()
            
            if session:
                return session
                
            # Create new one
            session = AgentSession(
                org_id=org_id,
                agent_type=AgentType.SECURITY_ANALYST,
                created_by="system",
                title="Hunter Agent - Continuous Monitoring",
                context={
                    "mode": "hunter",
                    "start_time": datetime.now(UTC).isoformat()
                }
            )
            db_session.add(session)
            await db_session.commit()
            await db_session.refresh(session)
            return session

    @staticmethod
    async def _task_exists_for_path(org_id: UUID, path_id: str) -> bool:
        """Check if an active review task already exists for this path."""
        # This is a heuristic - in production we'd want a proper 'fingerprint' column
        # on the task or finding table. For now, we search the payload JSON.
        from cerebro.agents.models import AgentReviewTask
        from sqlalchemy import select, or_
        
        async with async_session_factory() as db_session:
            # Postgres JSONB containment query
            # We look for tasks that have this path_id in their payload
            # and are not resolved (PENDING or ESCALATED)
            
            # Note: SQLAlchemy JSON containment syntax depends on backend. 
            # Assuming Postgres here.
            stmt = select(AgentReviewTask).where(
                AgentReviewTask.org_id == org_id,
                AgentReviewTask.payload['path_id'].astext == path_id,
                AgentReviewTask.status.in_([
                    ReviewTaskStatus.PENDING, 
                    ReviewTaskStatus.ESCALATED,
                    ReviewTaskStatus.IN_PROGRESS
                ])
            )
            result = await db_session.execute(stmt)
            return result.first() is not None
