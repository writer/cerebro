from fastapi.testclient import TestClient


def test_metrics_endpoint_exposes_prometheus(client: TestClient) -> None:
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "cerebro_agent_runtime_duration_seconds" in response.text
