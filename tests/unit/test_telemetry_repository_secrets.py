from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from cerebro.core.models import Finding
from cerebro.telemetry.schemas import ComplianceEvidence, DependencyGraph
from cerebro.telemetry.services import TelemetryIngestionService


@pytest.mark.asyncio
async def test_compliance_evidence_secret_detection(test_db):
    service = TelemetryIngestionService(test_db)

    payload = ComplianceEvidence(
        repository="acme/secrets-repo",
        framework="soc2",
        collected_at=datetime.now(UTC),
        evidence={
            "sc-12": {
                "secret_scan": [
                    {
                        "secret_type": "aws_access_key_id",
                        "file_path": "infra/terraform.tfvars",
                        "detector": "tfsec",
                        "verified": True,
                    }
                ]
            }
        },
    )

    result = await service.process_compliance_evidence(payload)

    assert result["status"] == "processed"
    assert result["findings_created"] == 1

    findings = (await test_db.execute(select(Finding))).scalars().all()
    assert len(findings) == 1
    stored = findings[0]
    assert stored.evidence["secret_family"] == "aws_access_key_id"
    assert stored.evidence["validation"]["status"] in {"verified", "format_match"}


@pytest.mark.asyncio
async def test_dependency_graph_secret_detection(test_db):
    service = TelemetryIngestionService(test_db)

    payload = DependencyGraph(
        repository="acme/dependency-repo",
        timestamp=datetime.now(UTC),
        dependency_graph={
            "pip": {
                "leaked": {
                    "secret_type": "openai_api_key",
                    "file_path": "ci/.env",
                    "detector": "supply-chain",
                }
            }
        },
        licenses={},
        vulnerabilities=[],
    )

    result = await service.process_dependency_graph(payload)

    assert result["status"] == "processed"
    assert result["findings_created"] == 1

    findings = (await test_db.execute(select(Finding))).scalars().all()
    assert len(findings) == 1
    stored = findings[0]
    assert stored.evidence["secret_family"] == "openai_api_key"
