from datetime import UTC, datetime
from uuid import uuid4

from cerebro.domain.entities import ConfigEntity, ResourceEntity, Severity
from cerebro.findings.producers.sentinelone.command_control import (
    SentinelOneCommandControlProducer,
)
from cerebro.findings.producers.sentinelone.malware import (
    SentinelOneMalwareProducer,
)


def _make_endpoint_resource() -> ResourceEntity:
    return ResourceEntity(
        external_id="endpoint-1",
        resource_type="endpoint.device",
        provider="endpoint",
        name="endpoint-1",
    )


def test_malware_producer_flags_active_threat() -> None:
    producer = SentinelOneMalwareProducer()

    resource = _make_endpoint_resource()
    now = datetime.now(UTC)
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=now,
        normalized_config={
            "threats": [
                {
                    "threat_id": "thr-1",
                    "classification": "Malware",
                    "categories": [f"cat-{i}" for i in range(15)],
                    "severity": "high",
                    "status": "active",
                    "mitigation_status": "pending",
                    "detected_at": now.isoformat(),
                    "confidence": "high",
                }
            ]
        },
    )

    context = {"rule_id": uuid4()}
    findings = producer.evaluate(resource, config, context)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.HIGH
    evidence = finding.evidence
    assert len(evidence["categories"]) == 10
    assert evidence["hashes"] == {}


def test_command_control_limits_evidence_lists() -> None:
    producer = SentinelOneCommandControlProducer()

    resource = _make_endpoint_resource()
    now = datetime.now(UTC)
    domains = [f"c2-{i}.example.com" for i in range(12)]
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=now,
        normalized_config={
            "threats": [
                {
                    "threat_id": "thr-2",
                    "classification": "Command-Control",
                    "status": "active",
                    "mitigation_status": "pending",
                    "severity": "critical",
                    "c2_domains": domains,
                }
            ]
        },
    )

    findings = producer.evaluate(resource, config, {"rule_id": uuid4()})

    assert len(findings) == 1
    evidence = findings[0].evidence
    assert len(evidence["c2_domains"]) == 10
    assert evidence["indicators"] == {}
