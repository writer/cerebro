from uuid import UUID

from fastapi.testclient import TestClient


def test_list_organizations_requires_auth(client: TestClient) -> None:
    response = client.get("/api/v1/organizations/")
    assert response.status_code in {401, 403}


def test_create_and_fetch_organization(client: TestClient, admin_token: str) -> None:
    create_response = client.post(
        "/api/v1/organizations/",
        json={"name": "Test Org"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert create_response.status_code == 200
    data = create_response.json()
    org_id = UUID(data["org_id"])
    assert data["name"] == "Test Org"

    fetch_response = client.get(
        f"/api/v1/organizations/{org_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert fetch_response.status_code == 200
    assert fetch_response.json()["org_id"] == str(org_id)


def test_create_requires_admin_scope(client: TestClient, test_token: str) -> None:
    response = client.post(
        "/api/v1/organizations/",
        json={"name": "Unauthorized"},
        headers={"Authorization": f"Bearer {test_token}"},
    )
    assert response.status_code == 403
