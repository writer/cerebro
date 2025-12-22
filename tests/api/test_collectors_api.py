from uuid import uuid4

from fastapi.testclient import TestClient


def test_collectors_require_auth(client: TestClient) -> None:
    response = client.post(
        "/api/v1/collectors/organizations/00000000-0000-0000-0000-000000000000/collect",
        json={"providers": [], "resource_types": []},
    )
    assert response.status_code in {401, 403}


def test_collect_organization_happy_path(
    client: TestClient, admin_token: str, test_org, monkeypatch
):
    async def fake_collect(self, org_id: str, providers=None, resource_types=None):
        return {
            "organization": "Test Organization",
            "accounts_processed": 1,
            "results": [],
            "duration_seconds": 0.1,
            "errors": [],
            "summary": {
                "total_resources": 0,
                "total_principals": 0,
                "total_configs": 0,
                "total_iam_edges": 0,
            },
        }

    monkeypatch.setattr(
        "cerebro.collectors.manager.CollectorManager.collect_organization", fake_collect
    )

    response = client.post(
        f"/api/v1/collectors/organizations/{test_org.org_id}/collect",
        json={"providers": ["github"], "resource_types": ["repo"]},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    assert response.json()["organization"] == "Test Organization"


def test_collect_organization_missing_org(
    client: TestClient, admin_token: str, monkeypatch
):
    async def fake_collect(self, org_id: str, providers=None, resource_types=None):
        raise ValueError("Collection failed")

    monkeypatch.setattr(
        "cerebro.collectors.manager.CollectorManager.collect_organization", fake_collect
    )

    response = client.post(
        f"/api/v1/collectors/organizations/{uuid4()}/collect",
        json={"providers": ["aws"]},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Organization not found"


def test_collect_organization_background_missing_org(
    client: TestClient, admin_token: str
):
    response = client.post(
        f"/api/v1/collectors/organizations/{uuid4()}/collect/background",
        json={"providers": ["github"], "resource_types": []},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 404
