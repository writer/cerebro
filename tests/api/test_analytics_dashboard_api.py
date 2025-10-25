from cerebro.analytics.dashboard_analytics import DashboardAnalytics


def test_dashboard_endpoint_includes_identity_and_heatmap(
    client,
    test_db,
    test_org,
    test_token,
    monkeypatch,
):
    async def _fake_dashboard(self, org_id):
        return {
            "executive_summary": {
                "overall_risk_score": 15.2,
                "risk_level": "medium",
                "risk_trend": "stable",
                "dimension_scores": {
                    "vulnerability_exposure": 10.0,
                    "identity_hygiene": 5.0,
                },
                "total_assets": 4,
                "total_identities": 2,
                "active_findings": 1,
                "compliance_score": 92.0,
                "top_5_risks": ["Sample risk"],
            },
            "security_metrics": {
                "findings": {
                    "total": 5,
                    "critical": 1,
                    "high": 2,
                    "open": 4,
                    "trend_7d": [1, 2, 3],
                    "critical_trend_7d": [0, 1, 1],
                },
                "sla_performance": {
                    "breaches": 1,
                    "mttr_hours": 12.5,
                    "new_24h": 2,
                    "resolved_24h": 3,
                },
            },
            "compliance_status": {
                "CIS": {
                    "total_controls": 10,
                    "compliant_controls": 9,
                    "compliance_percentage": 90.0,
                    "status": "partial",
                }
            },
            "identity_analytics": {
                "summary": {
                    "total_identities": 2,
                    "high_privilege_identities": 1,
                    "cross_provider_identities": 1,
                    "avg_permissions_per_identity": 12.0,
                    "max_permissions_per_identity": 20,
                },
                "privilege_distribution": {"admin": 1, "low_privilege": 1},
                "top_risky_identities": [
                    {
                        "principal_id": "123",
                        "display_name": "Analyst",
                        "email": "analyst@example.com",
                        "risk_score": 65.0,
                        "risk_level": "high",
                        "cross_provider_access": 2,
                        "admin_access_count": 1,
                        "mfa_status": "enabled",
                        "top_risk_factor": "Cross-provider admin",
                    }
                ],
                "privilege_anomalies": [
                    {
                        "type": "orphaned_permissions",
                        "principal_id": "123",
                        "description": "Unused permissions detected",
                        "risk_level": "medium",
                        "recommendation": "Review IAM assignments",
                    }
                ],
                "mfa_compliance_by_provider": {
                    "github": {
                        "total_users": 2,
                        "mfa_enabled_users": 2,
                        "compliance_rate": 100.0,
                        "status": "compliant",
                    }
                },
                "provider_breakdown": {
                    "github": {
                        "identity_count": 2,
                        "unique_permissions": 10,
                        "admin_grants": 1,
                        "recent_activity_ratio": 0.5,
                        "risk_level": "medium",
                    }
                },
            },
            "risk_heatmap": {
                "heatmap_data": {"github": {"repo": 70.0}},
                "high_risk_areas": [
                    {
                        "provider": "github",
                        "resource_type": "repo",
                        "risk_score": 70.0,
                        "finding_count": 3,
                    }
                ],
                "improvement_opportunities": [
                    {
                        "area": "github repo",
                        "current_risk": 70.0,
                        "potential_reduction": 49.0,
                        "impact": "high",
                    }
                ],
            },
            "investment_recommendations": [
                {
                    "priority": "high",
                    "category": "Identity",
                    "recommendation": "Automate onboarding",
                    "rationale": "Reduce manual grant errors",
                    "estimated_impact": "30% risk reduction",
                    "investment_level": "medium",
                }
            ],
        }

    monkeypatch.setattr(DashboardAnalytics, "generate_comprehensive_dashboard", _fake_dashboard)

    response = client.get(
        f"/api/v1/analytics/organizations/{test_org.org_id}/dashboard",
        headers={"Authorization": f"Bearer {test_token}"},
    )

    assert response.status_code == 200, response.text
    payload = response.json()

    assert "identity_analytics" in payload
    assert "risk_heatmap" in payload

    identity = payload["identity_analytics"]
    heatmap = payload["risk_heatmap"]

    assert identity["summary"]["total_identities"] >= 1
    assert heatmap["heatmap_data"], "Heatmap data should not be empty"
