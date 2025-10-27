from copy import deepcopy
from pathlib import Path
from typing import Dict, List

from cerebro.analytics.dashboard_analytics import DashboardAnalytics

from tests.api.dashboard_samples import build_sample_dashboard_response


TYPES_PATH = Path(__file__).resolve().parents[2] / "frontend" / "lib" / "types.ts"

EXPECTED_FIELDS: Dict[str, set[str]] = {
    "ExecutiveDashboardResponse": {
        "executive_summary",
        "security_metrics",
        "compliance_status",
        "compliance_trends",
        "investment_recommendations",
        "identity_analytics",
        "risk_heatmap",
        "metadata",
    },
    "ExecutiveSummaryResponse": {
        "org_id",
        "report_date",
        "overall_risk_score",
        "risk_level",
        "risk_trend",
        "dimension_scores",
        "total_assets",
        "total_identities",
        "active_findings",
        "compliance_score",
        "top_5_risks",
        "progress_indicators",
    },
    "ExecutiveSummaryProgress": {
        "findings_burned_down_30d",
        "new_controls_implemented",
        "risk_score_change_30d",
    },
    "SecurityMetricsResponse": {"findings", "sla_performance", "provider_breakdown"},
    "ProviderFindingBreakdown": {
        "provider",
        "open_findings",
        "critical_open",
        "high_open",
        "new_last_24h",
        "sla_breaches",
        "mttr_hours",
    },
    "ComplianceStatusEntry": {
        "total_controls",
        "compliant_controls",
        "compliance_percentage",
        "status",
    },
    "InvestmentRecommendation": {
        "priority",
        "category",
        "recommendation",
        "rationale",
        "estimated_impact",
        "investment_level",
    },
    "IdentityAnalyticsResponse": {
        "summary",
        "privilege_distribution",
        "privilege_segments",
        "top_risky_identities",
        "privilege_anomalies",
        "mfa_compliance_by_provider",
        "provider_breakdown",
        "provider_segments",
        "drilldown_identities",
        "remediation_queue",
        "risk_level_breakdown",
        "generated_at",
    },
    "IdentityPrivilegeSegment": {"label", "count"},
    "IdentityProviderSegment": {
        "provider",
        "identity_count",
        "admin_grants",
        "risk_level",
    },
    "IdentityAnalyticsSummary": {
        "total_identities",
        "high_privilege_identities",
        "cross_provider_identities",
        "avg_permissions_per_identity",
        "max_permissions_per_identity",
    },
    "IdentityAnalyticsRiskyIdentity": {
        "principal_id",
        "display_name",
        "email",
        "risk_score",
        "risk_level",
        "cross_provider_access",
        "admin_access_count",
        "mfa_status",
        "top_risk_factor",
    },
    "IdentityPrivilegeAnomaly": {
        "type",
        "principal_id",
        "principal_name",
        "description",
        "risk_level",
        "recommendation",
    },
    "IdentityDrilldownPermission": {
        "provider",
        "permission",
        "is_admin",
        "granted_at",
    },
    "IdentityDrilldownFinding": {
        "finding_id",
        "title",
        "severity",
        "status",
        "last_seen",
    },
    "IdentityDrilldownIdentity": {
        "principal_id",
        "display_name",
        "email",
        "risk_score",
        "risk_level",
        "providers",
        "permissions",
        "open_findings",
        "recommended_actions",
        "risk_factors",
    },
    "IdentityRemediationItem": {
        "principal_id",
        "priority",
        "summary",
        "recommended_action",
        "evidence",
    },
    "IdentityMfaCompliance": {
        "total_users",
        "mfa_enabled_users",
        "compliance_rate",
        "status",
    },
    "IdentityProviderBreakdown": {
        "identity_count",
        "unique_permissions",
        "admin_grants",
        "recent_activity_ratio",
        "risk_level",
    },
    "RiskHeatmapResponse": {
        "heatmap_data",
        "high_risk_areas",
        "improvement_opportunities",
    },
    "RiskHeatmapArea": {
        "provider",
        "resource_type",
        "risk_score",
        "finding_count",
    },
    "RiskImprovementOpportunity": {
        "area",
        "current_risk",
        "potential_reduction",
        "impact",
    },
    "ComplianceTrendPoint": {"date", "score"},
    "ComplianceTrendResponse": {"overall", "frameworks", "delta"},
    "DashboardMetadata": {
        "generated_at",
        "component_timings",
        "filters_applied",
        "cache_ttl_seconds",
        "supports_streaming_updates",
        "alert_thresholds",
    },
}


def _extract_type_fields(source: str, type_name: str) -> List[str]:
    marker = f"export type {type_name}"
    start = source.find(marker)
    if start == -1:
        raise AssertionError(f"Type {type_name} not found in types.ts")

    brace_start = source.find("{", start)
    if brace_start == -1:
        raise AssertionError(f"Type {type_name} missing opening brace")

    depth = 0
    block_chars = []
    for char in source[brace_start:]:
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                break
        block_chars.append(char)
    else:  # pragma: no cover - malformed types file
        raise AssertionError(f"Type {type_name} missing closing brace")

    block = "".join(block_chars)[1:]  # drop initial opening brace

    fields: List[str] = []
    depth = 0
    current: List[str] = []
    for char in block:
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        current.append(char)
        if char == ";" and depth == 0:
            segment = "".join(current).strip()
            current.clear()
            if not segment or ":" not in segment:
                continue
            field_name = segment.split(":", 1)[0].strip()
            if field_name.startswith("|"):
                continue
            if field_name.endswith("?"):
                field_name = field_name[:-1]
            fields.append(field_name)

    return fields


def _assert_field_set(name: str, parsed: List[str]) -> None:
    expected = EXPECTED_FIELDS[name]
    assert set(parsed) == expected, f"TypeScript definition for {name} changed"


def _validate_api_response(payload: Dict[str, object]) -> None:
    assert set(payload.keys()) == EXPECTED_FIELDS["ExecutiveDashboardResponse"]

    executive = payload["executive_summary"]
    assert set(executive.keys()) == EXPECTED_FIELDS["ExecutiveSummaryResponse"]
    assert set(executive["progress_indicators"].keys()) == EXPECTED_FIELDS["ExecutiveSummaryProgress"]

    metrics = payload["security_metrics"]
    assert set(metrics.keys()) == EXPECTED_FIELDS["SecurityMetricsResponse"]
    assert set(metrics["findings"].keys()) == {
        "total",
        "critical",
        "high",
        "open",
        "trend_7d",
        "critical_trend_7d",
    }
    assert set(metrics["sla_performance"].keys()) == {
        "breaches",
        "mttr_hours",
        "new_24h",
        "resolved_24h",
    }
    provider_breakdown = metrics.get("provider_breakdown") or []
    for entry in provider_breakdown:
        assert set(entry.keys()) == EXPECTED_FIELDS["ProviderFindingBreakdown"]

    for entry in payload["compliance_status"].values():
        assert set(entry.keys()) == EXPECTED_FIELDS["ComplianceStatusEntry"]

    recommendations = payload["investment_recommendations"]
    assert recommendations
    for rec in recommendations:
        assert set(rec.keys()) == EXPECTED_FIELDS["InvestmentRecommendation"]

    identity = payload["identity_analytics"]
    assert set(identity.keys()) == EXPECTED_FIELDS["IdentityAnalyticsResponse"]
    assert set(identity["summary"].keys()) == EXPECTED_FIELDS["IdentityAnalyticsSummary"]
    assert identity["privilege_distribution"], "Privilege distribution should not be empty"
    for segment in identity.get("privilege_segments", []):
        assert set(segment.keys()) == EXPECTED_FIELDS["IdentityPrivilegeSegment"]
    assert identity["generated_at"], "Identity analytics should include generation timestamp"

    assert identity["top_risky_identities"], "Risky identities should not be empty"
    for risky in identity["top_risky_identities"]:
        assert set(risky.keys()) == EXPECTED_FIELDS["IdentityAnalyticsRiskyIdentity"]

    for anomaly in identity["privilege_anomalies"]:
        assert set(anomaly.keys()) == EXPECTED_FIELDS["IdentityPrivilegeAnomaly"]

    for compliance in identity["mfa_compliance_by_provider"].values():
        assert set(compliance.keys()) == EXPECTED_FIELDS["IdentityMfaCompliance"]

    for breakdown in identity["provider_breakdown"].values():
        assert set(breakdown.keys()) == EXPECTED_FIELDS["IdentityProviderBreakdown"]
    for provider_segment in identity.get("provider_segments", []):
        assert set(provider_segment.keys()) == EXPECTED_FIELDS["IdentityProviderSegment"]

    risk_breakdown = identity.get("risk_level_breakdown") or {}
    assert risk_breakdown, "Risk level breakdown should be provided"

    drilldown = identity["drilldown_identities"]
    assert drilldown, "Drilldown identities should not be empty"
    for detailed in drilldown:
        assert set(detailed.keys()) == EXPECTED_FIELDS["IdentityDrilldownIdentity"]
        for permission in detailed["permissions"]:
            assert set(permission.keys()) == EXPECTED_FIELDS["IdentityDrilldownPermission"]
        for finding in detailed["open_findings"]:
            assert set(finding.keys()) == EXPECTED_FIELDS["IdentityDrilldownFinding"]

    remediation_queue = identity["remediation_queue"]
    assert remediation_queue, "Remediation queue should surface actions"
    for item in remediation_queue:
        assert set(item.keys()) == EXPECTED_FIELDS["IdentityRemediationItem"]

    heatmap = payload["risk_heatmap"]
    assert set(heatmap.keys()) == EXPECTED_FIELDS["RiskHeatmapResponse"]
    assert heatmap["heatmap_data"], "Heatmap data should not be empty"
    for area in heatmap["high_risk_areas"]:
        assert set(area.keys()) == EXPECTED_FIELDS["RiskHeatmapArea"]
    for opportunity in heatmap["improvement_opportunities"]:
        assert set(opportunity.keys()) == EXPECTED_FIELDS["RiskImprovementOpportunity"]

    trends = payload["compliance_trends"]
    assert set(trends.keys()) == EXPECTED_FIELDS["ComplianceTrendResponse"]
    assert trends["overall"], "Overall compliance trend should not be empty"
    for point in trends["overall"]:
        assert set(point.keys()) == EXPECTED_FIELDS["ComplianceTrendPoint"]
    for series in trends["frameworks"].values():
        for point in series:
            assert set(point.keys()) == EXPECTED_FIELDS["ComplianceTrendPoint"]
    delta = trends.get("delta") or {}
    assert "overall" in delta

    metadata = payload["metadata"]
    assert set(metadata.keys()) == EXPECTED_FIELDS["DashboardMetadata"]
    assert metadata["generated_at"], "Dashboard metadata should include generation timestamp"
    component_timings = metadata.get("component_timings") or {}
    assert component_timings, "Component timings should be present"
    if metadata.get("filters_applied"):
        assert set(metadata["filters_applied"].keys()) == {"identity_risk_filter", "compliance_trend_range"}
    assert metadata.get("cache_ttl_seconds") is not None
    assert "supports_streaming_updates" in metadata
    alert_thresholds = metadata.get("alert_thresholds") or {}
    for thresholds in alert_thresholds.values():
        assert set(thresholds.keys()) == {"warning", "critical"}


def test_typescript_contract_matches_api_schema(client, test_db, test_org, test_token, monkeypatch):
    types_source = TYPES_PATH.read_text(encoding="utf-8")
    for type_name in EXPECTED_FIELDS:
        parsed_fields = _extract_type_fields(types_source, type_name)
        _assert_field_set(type_name, parsed_fields)

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

    _validate_api_response(payload)


def test_dashboard_contract_captures_generation_timings(client, test_db, test_org, test_token, monkeypatch):
    sample = build_sample_dashboard_response()
    captured: Dict[str, DashboardAnalytics] = {}

    async def _fake_dashboard(self, org_id):
        payload = deepcopy(sample)
        payload["executive_summary"]["org_id"] = str(org_id)
        self._last_generation_timings = {
            "security_metrics": 0.05,
            "executive_summary": 0.02,
            "identity_analytics": 0.04,
            "risk_heatmap": 0.03,
            "compliance_status": 0.01,
            "compliance_trends": 0.015,
            "total": 0.17,
        }
        payload["metadata"]["component_timings"] = {
            **payload["metadata"].get("component_timings", {}),
            **self._last_generation_timings,
        }
        captured["instance"] = self
        return payload

    monkeypatch.setattr(DashboardAnalytics, "generate_comprehensive_dashboard", _fake_dashboard)

    response = client.get(
        f"/api/v1/analytics/organizations/{test_org.org_id}/dashboard",
        headers={"Authorization": f"Bearer {test_token}"},
    )

    assert response.status_code == 200
    payload = response.json()
    instance = captured["instance"]
    timings = instance.last_generation_timings
    assert timings["total"] == 0.17
    assert set(timings.keys()) == {
        "security_metrics",
        "executive_summary",
        "identity_analytics",
        "risk_heatmap",
        "compliance_status",
        "compliance_trends",
        "total",
    }
    assert payload["metadata"]["component_timings"]["total"] == 0.17
