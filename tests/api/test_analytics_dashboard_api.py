from copy import deepcopy

from cerebro.analytics.dashboard_analytics import DashboardAnalytics

from tests.api.dashboard_samples import build_sample_dashboard_response


def test_dashboard_endpoint_includes_identity_and_heatmap(
    client,
    test_db,
    test_org,
    test_token,
    monkeypatch,
):
    sample = build_sample_dashboard_response()

    async def _fake_dashboard(self, org_id):
        payload = deepcopy(sample)
        payload["executive_summary"]["org_id"] = str(org_id)
        return payload

    monkeypatch.setattr(DashboardAnalytics, "generate_comprehensive_dashboard", _fake_dashboard)

    response = client.get(
        f"/api/v1/analytics/organizations/{test_org.org_id}/dashboard",
        headers={"Authorization": f"Bearer {test_token}"},
    )

    assert response.status_code == 200, response.text
    payload = response.json()

    assert "identity_analytics" in payload
    assert "risk_heatmap" in payload
    assert "compliance_trends" in payload
    assert "metadata" in payload

    identity = payload["identity_analytics"]
    heatmap = payload["risk_heatmap"]
    metadata = payload["metadata"]
    provider_breakdown = payload["security_metrics"].get("provider_breakdown")

    assert identity["summary"]["total_identities"] >= 1
    assert "drilldown_identities" in identity
    assert "remediation_queue" in identity
    assert identity["generated_at"], "Identity analytics should include generated_at"
    assert identity.get("risk_level_breakdown"), "Risk level breakdown should exist"
    assert identity.get("privilege_segments"), "Privilege segments should exist"
    assert identity.get("provider_segments"), "Provider segments should exist"
    assert heatmap["heatmap_data"], "Heatmap data should not be empty"
    assert metadata["generated_at"], "Metadata should include generated_at"
    assert metadata.get("cache_ttl_seconds") is not None
    assert "supports_streaming_updates" in metadata
    assert provider_breakdown, "Provider breakdown should be populated"
