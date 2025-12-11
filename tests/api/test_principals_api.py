
from fastapi.testclient import TestClient


def test_principals_require_auth(client: TestClient) -> None:
    response = client.get("/api/v1/principals/")
    assert response.status_code in {401, 403}


def test_principal_flow(client: TestClient, admin_token: str, test_principal, test_resource, test_rule) -> None:
    list_response = client.get(
        "/api/v1/principals/",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert list_response.status_code == 200

    principal_id = list_response.json()[0]["principal_id"]

    get_response = client.get(
        f"/api/v1/principals/{principal_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert get_response.status_code == 200

    permissions_response = client.get(
        f"/api/v1/principals/{principal_id}/permissions",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert permissions_response.status_code == 200
