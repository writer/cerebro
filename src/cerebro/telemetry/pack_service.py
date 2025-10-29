"""Service layer for artifact pack management."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional
from uuid import UUID, uuid4

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from cerebro.core.models import Organization
from cerebro.telemetry.models import ArtifactPack, ArtifactPackTask
from cerebro.telemetry.schemas import (
    ArtifactPackCreate,
    ArtifactPackDefinition,
    ArtifactPackTaskCreate,
    ArtifactPackUpdate,
    ArtifactTaskDefinition,
)


class PackManagementService:
    """Manage lifecycle of artifact packs for endpoint orchestration."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def list_packs(self, *, org_id: Optional[UUID] = None) -> List[ArtifactPackDefinition]:
        stmt = select(ArtifactPack).options(selectinload(ArtifactPack.tasks)).order_by(ArtifactPack.created_at.desc())
        if org_id:
            stmt = stmt.where(ArtifactPack.org_id == org_id)
        result = await self.db.execute(stmt)
        packs = result.scalars().unique().all()
        return [self._serialize_pack(pack) for pack in packs]

    async def get_pack(self, pack_id: UUID) -> ArtifactPackDefinition:
        pack = await self._load_pack(pack_id)
        return self._serialize_pack(pack)

    async def create_pack(self, payload: ArtifactPackCreate, *, org_name: Optional[str] = None) -> ArtifactPackDefinition:
        org = await self._ensure_org(org_name)

        pack = ArtifactPack(
            pack_id=uuid4(),
            org_id=org.org_id,
            name=payload.name,
            version=payload.version,
            description=payload.description,
            selectors=payload.selectors or {},
            enabled=payload.enabled,
            approval_state=payload.approval_state or "draft",
            approval_notes=payload.approval_notes,
            schedule_interval_seconds=payload.schedule_interval_seconds,
        )

        pack.tasks = [self._build_task(task) for task in payload.tasks]

        self.db.add(pack)
        await self.db.commit()
        await self.db.refresh(pack, attribute_names=["tasks"])

        return self._serialize_pack(pack)

    async def update_pack(self, pack_id: UUID, payload: ArtifactPackUpdate) -> ArtifactPackDefinition:
        pack = await self._load_pack(pack_id, for_update=True)

        if payload.name is not None:
            pack.name = payload.name
        if payload.version is not None:
            pack.version = payload.version
        if payload.description is not None:
            pack.description = payload.description
        if payload.selectors is not None:
            pack.selectors = payload.selectors
        if payload.enabled is not None:
            pack.enabled = payload.enabled
        if payload.approval_state is not None:
            pack.approval_state = payload.approval_state
            if payload.approval_state == "approved":
                pack.last_deployed_at = datetime.utcnow()
        if payload.approval_notes is not None:
            pack.approval_notes = payload.approval_notes
        if payload.schedule_interval_seconds is not None:
            pack.schedule_interval_seconds = payload.schedule_interval_seconds

        if payload.tasks is not None:
            await self._replace_tasks(pack, payload.tasks)

        await self.db.commit()
        await self.db.refresh(pack, attribute_names=["tasks"])
        return self._serialize_pack(pack)

    async def delete_pack(self, pack_id: UUID) -> None:
        stmt = delete(ArtifactPack).where(ArtifactPack.pack_id == pack_id)
        await self.db.execute(stmt)
        await self.db.commit()

    async def _load_pack(self, pack_id: UUID, *, for_update: bool = False) -> ArtifactPack:
        stmt = (
            select(ArtifactPack)
            .options(selectinload(ArtifactPack.tasks))
            .where(ArtifactPack.pack_id == pack_id)
        )
        if for_update:
            stmt = stmt.with_for_update()

        result = await self.db.execute(stmt)
        pack = result.scalars().unique().first()
        if pack is None:
            raise ValueError(f"Artifact pack {pack_id} not found")
        return pack

    async def _ensure_org(self, org_name: Optional[str]) -> Organization:
        if org_name:
            stmt = select(Organization).where(Organization.name == org_name)
            org = await self.db.scalar(stmt)
            if org:
                return org

        stmt = select(Organization).order_by(Organization.created_at.asc())
        org = await self.db.scalar(stmt)
        if org:
            return org

        org = Organization(name=org_name or "default")
        self.db.add(org)
        await self.db.commit()
        await self.db.refresh(org)
        return org

    async def _replace_tasks(self, pack: ArtifactPack, tasks: List[ArtifactPackTaskCreate]) -> None:
        await self.db.flush()
        pack.tasks.clear()
        for task in tasks:
            pack.tasks.append(self._build_task(task))

    def _build_task(self, task: ArtifactPackTaskCreate) -> ArtifactPackTask:
        return ArtifactPackTask(
            task_id=uuid4(),
            name=task.name,
            collector=task.collector,
            interval_seconds=task.interval_seconds,
            tags=task.tags or {},
            config=task.config or {},
            discovery=task.discovery or [],
            parameters=[param.model_dump() for param in task.parameters or []],
            parameter_values=task.parameter_values or {},
            resources=(task.resources.model_dump() if task.resources else {}),
            tools=[tool.model_dump() for tool in task.tools or []],
        )

    def _serialize_pack(self, pack: ArtifactPack) -> ArtifactPackDefinition:
        return ArtifactPackDefinition(
            pack_id=pack.pack_id,
            name=pack.name,
            version=pack.version,
            description=pack.description,
            selectors=pack.selectors,
            enabled=pack.enabled,
            approval_state=pack.approval_state,
            approval_notes=pack.approval_notes,
            schedule_interval_seconds=pack.schedule_interval_seconds,
            last_deployed_at=pack.last_deployed_at,
            tasks=[self._serialize_task(task) for task in sorted(pack.tasks, key=lambda t: t.name)],
        )

    def _serialize_task(self, task: ArtifactPackTask) -> ArtifactTaskDefinition:
        return ArtifactTaskDefinition(
            task_id=task.task_id,
            name=task.name,
            collector=task.collector,
            interval_seconds=task.interval_seconds,
            tags=task.tags or None,
            config=task.config or None,
            discovery=task.discovery or None,
            parameters=task.parameters or None,
            parameter_values=task.parameter_values or None,
            resources=task.resources or None,
            tools=task.tools or None,
        )
