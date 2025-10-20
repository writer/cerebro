from fastapi.testclient import TestClient


def test_findings_require_auth(client: TestClient) -> None:
    response = client.get("/api/v1/findings/")
    assert response.status_code in {401, 403}
