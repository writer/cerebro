from uuid import UUID

from fastapi.testclient import TestClient


def test_account_crud_flow(client: TestClient, admin_token: str, test_org) -> None:
    create_response = client.post(
        "/api/v1/accounts/",
        json={
            "org_id": str(test_org.org_id),
            "provider": "github",
            "external_id": "example",
            "display_name": "Example Org"
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert create_response.status_code == 200
    account = create_response.json()
    account_id = UUID(account["account_id"])

    get_response = client.get(
        f"/api/v1/accounts/{account_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert get_response.status_code == 200

    list_response = client.get(
        "/api/v1/accounts/",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert list_response.status_code == 200
    accounts = list_response.json()
    assert any(item["account_id"] == str(account_id) for item in accounts)

    delete_response = client.delete(
        f"/api/v1/accounts/{account_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert delete_response.status_code == 200


def test_account_creation_requires_existing_org(client: TestClient, admin_token: str) -> None:
    response = client.post(
        "/api/v1/accounts/",
        json={
            "org_id": "00000000-0000-0000-0000-000000000000",
            "provider": "github",
            "external_id": "missing",
            "display_name": "Missing"
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 404
