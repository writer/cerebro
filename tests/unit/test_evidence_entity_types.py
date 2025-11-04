from datetime import datetime, timezone

from cerebro.compliance.evidence_data_fabric import (
    EvidenceEntityType,
    EvidenceQuery,
    EvidenceSourceType,
    create_evidence_data_fabric,
)
from cerebro.compliance.models import (
    EvidenceCategory,
    create_customer_evidence,
    create_vendor_evidence,
    metadata_to_dict,
)


def test_vendor_entity_type_ingest_and_query():
    fabric = create_evidence_data_fabric("sqlite:///:memory:")

    vendor_id = "vendor_acme_corp"
    raw_vendor = {
        "id": vendor_id,
        "name": "Acme Corp",
        "risk_level": "high",
        "primary_contact": "security@acme.test",
    }

    evidence_id = fabric.ingest_evidence(
        source_system="vendor_registry",
        source_type=EvidenceSourceType.MANUAL_ENTRY,
        entity_type=EvidenceEntityType.VENDOR,
        entity_id=vendor_id,
        raw_data=raw_vendor,
        observed_at=datetime.now(timezone.utc),
        collector_id="vendor_sync",
        tags={"vendor_id": vendor_id},
    )

    assert evidence_id

    results = fabric.query_evidence(
        EvidenceQuery(entity_types=[EvidenceEntityType.VENDOR], entity_ids=[vendor_id])
    )

    assert len(results) == 1
    record = results[0]
    assert record.entity_type == EvidenceEntityType.VENDOR.value
    assert record.entity_id == vendor_id
    assert record.entity_name == "Acme Corp"


def test_customer_entity_type_ingest_and_query():
    fabric = create_evidence_data_fabric("sqlite:///:memory:")

    customer_id = "customer_galaxy_inc"
    raw_customer = {
        "id": customer_id,
        "customerName": "Galaxy Industries",
        "lifecycle_stage": "enterprise",
    }

    evidence_id = fabric.ingest_evidence(
        source_system="customer_success_platform",
        source_type=EvidenceSourceType.API,
        entity_type=EvidenceEntityType.CUSTOMER,
        entity_id=customer_id,
        raw_data=raw_customer,
        observed_at=datetime.now(timezone.utc),
        collector_id="cs_sync",
        tags={"customer_id": customer_id},
    )

    assert evidence_id

    results = fabric.query_evidence(
        EvidenceQuery(entity_types=[EvidenceEntityType.CUSTOMER], entity_ids=[customer_id])
    )

    assert len(results) == 1
    record = results[0]
    assert record.entity_type == EvidenceEntityType.CUSTOMER.value
    assert record.entity_id == customer_id
    assert record.entity_name == "Galaxy Industries"


def test_vendor_metadata_serialization():
    metadata = create_vendor_evidence(
        vendor_id="vendor_1",
        vendor_name="Acme Analytics",
        created_by="system",
        risk_level="high",
        inherent_risk_score=0.76,
        residual_risk_score=0.55,
        business_criticality="critical",
        vendor_category="analytics",
        data_types_processed=["PII", "Confidential"],
        certifications=["SOC2"],
        compliance_frameworks=["ISO27001"],
        lifecycle_stage="active",
    )

    payload = metadata_to_dict(metadata)

    assert payload["category"] == EvidenceCategory.VENDOR_ASSESSMENT.value
    assert payload["vendor_id"] == "vendor_1"
    assert payload["risk_level"] == "high"
    assert payload["tags"]["vendor_id"] == "vendor_1"


def test_customer_metadata_serialization():
    metadata = create_customer_evidence(
        customer_id="customer_1",
        customer_name="Galaxy Industries",
        created_by="csm-jane",
        segment="enterprise",
        lifecycle_stage="expansion",
        health_score=0.92,
        churn_risk_score=0.08,
        adoption_metrics={"automation": 0.8},
    )

    payload = metadata_to_dict(metadata)

    assert payload["category"] == EvidenceCategory.CUSTOMER_PROFILE.value
    assert payload["customer_id"] == "customer_1"
    assert payload["health_score"] == 0.92
    assert payload["tags"]["entity_type"] == "customer"
