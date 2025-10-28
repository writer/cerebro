from datetime import datetime, timedelta, timezone


def build_sample_dashboard_response() -> dict:
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()
    previous = (now_dt - timedelta(days=1)).isoformat()

    return {
        "executive_summary": {
            "org_id": "00000000-0000-0000-0000-000000000000",
            "report_date": now,
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
            "progress_indicators": {
                "findings_burned_down_30d": 3,
                "new_controls_implemented": 2,
                "risk_score_change_30d": -1.2,
                "risk_score_change_7d": -0.4,
            },
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
            "provider_breakdown": [
                {
                    "provider": "github",
                    "open_findings": 3,
                    "critical_open": 1,
                    "high_open": 1,
                    "new_last_24h": 1,
                    "sla_breaches": 1,
                    "mttr_hours": 10.0,
                }
            ],
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
            "privilege_segments": [
                {"label": "admin", "count": 1},
                {"label": "low_privilege", "count": 1},
            ],
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
                    "principal_name": "Analyst",
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
            "provider_segments": [
                {
                    "provider": "github",
                    "identity_count": 2,
                    "admin_grants": 1,
                    "risk_level": "medium",
                }
            ],
            "drilldown_identities": [
                {
                    "principal_id": "123",
                    "display_name": "Analyst",
                    "email": "analyst@example.com",
                    "risk_score": 65.0,
                    "risk_level": "high",
                    "providers": ["github", "aws"],
                    "permissions": [
                        {
                            "provider": "github",
                            "permission": "repo:admin",
                            "is_admin": True,
                            "granted_at": now,
                        }
                    ],
                    "open_findings": [
                        {
                            "finding_id": "f-1",
                            "title": "Repository publicly accessible",
                            "severity": "critical",
                            "status": "open",
                            "last_seen": now,
                        }
                    ],
                    "recommended_actions": ["Restrict admin access", "Rotate credentials"],
                    "risk_factors": ["Cross-provider admin"],
                }
            ],
            "remediation_queue": [
                {
                    "action_id": "action-1",
                    "principal_id": "123",
                    "priority": "high",
                    "summary": "Analyst",
                    "recommended_action": "Enable least privilege roles",
                    "evidence": ["Repository publicly accessible"],
                    "risk_level": "high",
                    "status": "pending",
                    "notes": [],
                    "accepted_at": None,
                    "accepted_by": None,
                    "completed_at": None,
                    "completed_by": None,
                    "created_at": now,
                    "updated_at": now,
                    "source": "analytics",
                }
            ],
            "risk_level_breakdown": {"critical": 0, "high": 1, "medium": 1, "low": 0},
            "generated_at": now,
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
        "compliance_trends": {
            "overall": [
                {
                    "date": previous,
                    "score": 90.0,
                },
                {
                    "date": now,
                    "score": 92.0,
                },
            ],
            "frameworks": {
                "CIS": [
                    {
                        "date": previous,
                        "score": 89.0,
                    },
                    {
                        "date": now,
                        "score": 90.0,
                    }
                ]
            },
            "delta": {
                "overall": 2.0,
                "frameworks": {"CIS": 1.0},
            },
        },
        "metadata": {
            "generated_at": now,
            "component_timings": {
                "security_metrics": 0.12,
                "executive_summary": 0.05,
                "identity_analytics": 0.09,
                "risk_heatmap": 0.07,
                "compliance_status": 0.02,
                "compliance_trends": 0.03,
                "total": 0.38,
            },
            "filters_applied": {
                "identity_risk_filter": "all",
                "compliance_trend_range": "30d",
            },
            "cache_ttl_seconds": 60,
            "supports_streaming_updates": False,
            "alert_thresholds": {
                "critical_findings": {"warning": 5, "critical": 10},
                "mttr_hours": {"warning": 24, "critical": 48},
                "sla_breaches": {"warning": 5, "critical": 10},
            },
        },
    }
