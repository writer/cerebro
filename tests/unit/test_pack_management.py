import pytest
from uuid import UUID

from cerebro.telemetry.pack_service import PackManagementService
from cerebro.telemetry.schemas import ArtifactPackCreate, ArtifactPackTaskCreate, ArtifactPackUpdate


@pytest.mark.asyncio
async def test_pack_management_crud(test_db):
    service = PackManagementService(test_db)

    create_payload = ArtifactPackCreate(
        name="Hunt - Suspicious Processes",
        version="1.0.0",
        description="Detect anomalous process creation patterns",
        selectors={"tags": {"tier": "prod"}},
        tasks=[
            ArtifactPackTaskCreate(
                name="snapshot",
                collector="snapshot.basic",
                interval_seconds=300,
                discovery=["tag:tier=prod"],
                parameters=[{"name": "limit", "type": "int", "default": 50}],
                parameter_values={"limit": 25},
            )
        ],
    )

    created = await service.create_pack(create_payload, org_name="Acme")
    assert created.name == "Hunt - Suspicious Processes"
    assert created.enabled is True
    assert created.approval_state == "draft"
    assert len(created.tasks) == 1
    assert created.tasks[0].parameter_values == {"limit": 25}

    listed = await service.list_packs()
    assert len(listed) == 1

    pack_id = UUID(str(created.pack_id))
    update_payload = ArtifactPackUpdate(
        approval_state="approved",
        approval_notes="Reviewed by SOC lead",
        enabled=True,
        tasks=[
            ArtifactPackTaskCreate(
                name="snapshot",
                collector="snapshot.basic",
                interval_seconds=120,
            ),
            ArtifactPackTaskCreate(
                name="process-events",
                collector="events.process.delta",
            ),
        ],
    )

    updated = await service.update_pack(pack_id, update_payload)
    assert updated.approval_state == "approved"
    assert updated.approval_notes == "Reviewed by SOC lead"
    assert len(updated.tasks) == 2
    assert any(task.collector == "events.process.delta" for task in updated.tasks)

    await service.delete_pack(pack_id)
    listed_after_delete = await service.list_packs()
    assert listed_after_delete == []
