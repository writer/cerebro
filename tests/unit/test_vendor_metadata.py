import pytest
from datetime import datetime, timedelta

from cerebro.vendor_management.vendor_registry import (
    VendorCategory,
    VendorRegistry,
)


@pytest.mark.asyncio
async def test_vendor_registry_generates_metadata_envelope():
    registry = VendorRegistry()

    vendor = await registry.register_vendor(
        name="Acme Cloud",
        website_url="https://acme.example.com",
        category=VendorCategory.SECURITY_VENDOR,
        created_by="security@app",
        primary_contact="security@acme.example.com",
        data_processing_locations=["us-east-1"],
        certifications=["SOC2"],
        compliance_frameworks=["ISO27001"],
        data_types_processed=["PII"],
        business_criticality="high",
        incident_response_plan=True,
    )

    metadata = vendor.metadata
    assert metadata["lifecycle_stage"] == "active"
    assert metadata["risk_summary"]["level"] == vendor.risk_level.value
    assert metadata["evidence"]["vendor_id"] == vendor.vendor_id
    assert metadata["evidence"]["category"] == "vendor_assessment"
    assert metadata["compliance_summary"]["certifications"] == ["SOC2"]
    assert any(tag.startswith("risk:") for tag in vendor.tags)


@pytest.mark.asyncio
async def test_vendor_lifecycle_updates_on_refresh():
    registry = VendorRegistry()
    vendor = await registry.register_vendor(
        name="Future Corp",
        website_url="https://future.example.com",
        category=VendorCategory.CLOUD_PROVIDER,
        created_by="risk@app",
    )

    vendor.next_review_due = datetime.now() - timedelta(days=2)

    refreshed = await registry.refresh_vendor_profile(vendor.vendor_id)
    assert refreshed is not None
    assert refreshed.metadata["lifecycle_stage"] == "review_overdue"
    assert any(tag.endswith("review_overdue") for tag in refreshed.tags)
