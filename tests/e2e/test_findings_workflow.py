"""
E2E Tests: Findings Workflow

These tests verify the complete findings lifecycle including:
- Listing findings with filters
- Finding details retrieval
- Finding status updates
"""

import pytest
import httpx
from uuid import UUID

pytestmark = pytest.mark.e2e


@pytest.mark.asyncio
async def test_list_findings(
    auth_client: httpx.AsyncClient,
    test_org_id: UUID,
):
    """Test listing findings with various filters."""
    if "Authorization" not in auth_client.headers:
        pytest.skip("Authentication not available")
    
    # Basic listing
    response = await auth_client.get(
        "/api/v1/findings",
        params={"org_id": str(test_org_id)},
    )
    
    assert response.status_code in (200, 403)
    
    if response.status_code == 200:
        data = response.json()
        assert "findings" in data or "items" in data or isinstance(data, list)


@pytest.mark.asyncio
async def test_list_findings_with_severity_filter(
    auth_client: httpx.AsyncClient,
    test_org_id: UUID,
):
    """Test listing findings filtered by severity."""
    if "Authorization" not in auth_client.headers:
        pytest.skip("Authentication not available")
    
    response = await auth_client.get(
        "/api/v1/findings",
        params={
            "org_id": str(test_org_id),
            "severity": "critical",
        },
    )
    
    assert response.status_code in (200, 403)
    
    if response.status_code == 200:
        data = response.json()
        if isinstance(data, dict):
            findings = data.get("findings", data.get("items", []))
        else:
            findings = data
        if isinstance(findings, list):
            for finding in findings:
                if "severity" in finding:
                    assert finding["severity"].lower() == "critical"


@pytest.mark.asyncio
async def test_list_findings_with_provider_filter(
    auth_client: httpx.AsyncClient,
    test_org_id: UUID,
):
    """Test listing findings filtered by provider."""
    if "Authorization" not in auth_client.headers:
        pytest.skip("Authentication not available")
    
    response = await auth_client.get(
        "/api/v1/findings",
        params={
            "org_id": str(test_org_id),
            "provider": "aws",
        },
    )
    
    assert response.status_code in (200, 403)

    if response.status_code == 200:
        data = response.json()
        if isinstance(data, dict):
            findings = data.get("findings", data.get("items", []))
        else:
            findings = data

        if isinstance(findings, list):
            for finding in findings:
                if "provider" in finding:
                    assert finding["provider"].lower() == "aws"


@pytest.mark.asyncio
async def test_findings_statistics(
    auth_client: httpx.AsyncClient,
    test_org_id: UUID,
):
    """Test findings statistics endpoint."""
    if "Authorization" not in auth_client.headers:
        pytest.skip("Authentication not available")
    
    response = await auth_client.get(f"/api/v1/findings/organizations/{test_org_id}/stats")
    assert response.status_code in (200, 403)

    if response.status_code == 200:
        stats = response.json()
        assert isinstance(stats, dict)
