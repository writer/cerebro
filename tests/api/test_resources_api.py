from fastapi.testclient import TestClient


def test_list_resources_requires_auth(client: TestClient) -> None:
    response = client.get("/api/v1/resources/")
    assert response.status_code in {401, 403}


def test_get_resource_not_found(client: TestClient, admin_token: str) -> None:
    response = client.get(
        "/api/v1/resources/00000000-0000-0000-0000-000000000000",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 404


def test_resource_configuration_requires_existing_resource(client: TestClient, admin_token: str) -> None:
    response = client.get(
        "/api/v1/resources/00000000-0000-0000-0000-000000000000/configurations",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 404
