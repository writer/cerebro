from datetime import datetime
from uuid import uuid4

from cerebro.domain.entities import ConfigEntity, ResourceEntity, Severity
from cerebro.findings.producers.cross_provider.inconsistent_mfa_enforcement import (
    InconsistentMFAEnforcementProducer,
)


def _make_identity_resource() -> ResourceEntity:
    return ResourceEntity(
        external_id="user-123",
        resource_type="identity_cluster",
        provider="github",
        name="user@example.com",
    )


def test_inconsistent_mfa_generates_finding() -> None:
    producer = InconsistentMFAEnforcementProducer()

    resource = _make_identity_resource()
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "email": "user@example.com",
            "display_name": "Example User",
            "github": {"mfa": {"enabled": True}, "username": "example"},
            "aws": {"mfa": {"enabled": False}, "username": "example"},
        },
    )

    context = {"rule_id": uuid4()}
    findings = producer.evaluate(resource, config, context)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.MEDIUM
    evidence = finding.evidence
    assert evidence["providers_with_mfa"] == ["github"]
    assert evidence["providers_without_mfa"] == ["aws"]
    assert evidence["mfa_coverage_percentage"] == 50.0


def test_consistent_mfa_no_finding() -> None:
    producer = InconsistentMFAEnforcementProducer()

    resource = _make_identity_resource()
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "github": {"mfa": {"enabled": True}},
            "aws": {"mfa": {"enabled": True}},
        },
    )

    findings = producer.evaluate(resource, config)

    assert findings == []
