from uuid import UUID

from fastapi.testclient import TestClient


def test_rules_list_requires_auth(client: TestClient) -> None:
    response = client.get("/api/v1/rules/")
    assert response.status_code in {401, 403}


def test_rule_crud_flow(client: TestClient, admin_token: str, test_policy) -> None:
    create_response = client.post(
        "/api/v1/rules/",
        json={
            "name": "Test Rule",
            "description": "Ensures provider is github",
            "provider": ["github"],
            "resource_types": ["repo"],
            "expression_lang": "cel",
            "expression": "resource.provider == 'github'",
            "severity": "high",
            "cis": [],
            "cwe": [],
            "nist_800_53": [],
            "mitre_attack": []
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert create_response.status_code == 200
    rule = create_response.json()
    rule_id = UUID(rule["rule_id"])

    get_response = client.get(
        f"/api/v1/rules/{rule_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert get_response.status_code == 200

    update_response = client.put(
        f"/api/v1/rules/{rule_id}",
        json={
            "name": "Updated Rule",
            "description": "Updated description",
            "provider": ["github"],
            "resource_types": ["repo"],
            "expression_lang": "cel",
            "expression": "resource.provider == 'github'",
            "severity": "medium",
            "cis": [],
            "cwe": [],
            "nist_800_53": [],
            "mitre_attack": []
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert update_response.status_code == 200
    assert update_response.json()["version"] == 2

    test_response = client.post(
        f"/api/v1/rules/{rule_id}/test",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert test_response.status_code == 200
    assert test_response.json()["status"] == "success"

    delete_response = client.delete(
        f"/api/v1/rules/{rule_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert delete_response.status_code == 200
