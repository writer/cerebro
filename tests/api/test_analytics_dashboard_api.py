from copy import deepcopy
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

from cerebro.analytics.dashboard_analytics import DashboardAnalytics
from cerebro.analytics.dashboard_repository import DashboardRepository
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

    monkeypatch.setattr(
        DashboardAnalytics, "generate_comprehensive_dashboard", _fake_dashboard
    )

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
    runtime_health = payload.get("runtime_health")
    integration_coverage = payload.get("integration_coverage")

    assert identity["summary"]["total_identities"] >= 1
    assert "drilldown_identities" in identity
    assert "remediation_queue" in identity
    assert identity["generated_at"], "Identity analytics should include generated_at"
    assert identity.get("risk_level_breakdown"), "Risk level breakdown should exist"
    assert identity.get("privilege_segments"), "Privilege segments should exist"
    assert identity.get("provider_segments"), "Provider segments should exist"
    assert identity["remediation_queue"], "Remediation queue populated"
    first_action = identity["remediation_queue"][0]
    assert first_action["status"] in {"pending", "accepted", "completed"}
    assert isinstance(first_action["notes"], list)
    assert heatmap["heatmap_data"], "Heatmap data should not be empty"
    assert metadata["generated_at"], "Metadata should include generated_at"
    assert metadata.get("cache_ttl_seconds") is not None
    assert "supports_streaming_updates" in metadata
    assert provider_breakdown, "Provider breakdown should be populated"
    assert isinstance(runtime_health, list)
    assert isinstance(integration_coverage, list)


def test_provider_findings_endpoint_returns_details(
    client,
    test_db,
    test_org,
    test_token,
    monkeypatch,
):
    sample_findings = [
        {
            "finding_id": "f-123",
            "title": "Excessive admin access",
            "severity": "critical",
            "status": "open",
            "first_seen": "2024-01-01T00:00:00+00:00",
            "last_seen": "2024-01-03T00:00:00+00:00",
            "resource_id": "res-1",
            "rule_name": "admin_access_rule",
        },
        {
            "finding_id": "f-456",
            "title": "Stale credentials",
            "severity": "high",
            "status": "investigating",
            "first_seen": "2024-01-02T00:00:00+00:00",
            "last_seen": "2024-01-04T00:00:00+00:00",
            "resource_id": "res-2",
            "rule_name": None,
        },
    ]

    async def _fake_provider_findings(self, org_id, provider, limit):
        assert org_id == test_org.org_id
        assert provider == "github"
        assert limit == 10
        return sample_findings[:limit]

    monkeypatch.setattr(
        DashboardRepository, "get_findings_by_provider", _fake_provider_findings
    )

    response = client.get(
        f"/api/v1/analytics/organizations/{test_org.org_id}/providers/github/findings?limit=10",
        headers={"Authorization": f"Bearer {test_token}"},
    )

    assert response.status_code == 200, response.text
    payload = response.json()

    assert payload["provider"] == "github"
    assert len(payload["findings"]) == 2
    first = payload["findings"][0]
    assert first["title"] == "Excessive admin access"
    assert first["severity"] == "critical"


def test_remediation_action_endpoints(
    client,
    test_db,
    test_org,
    test_token,
    monkeypatch,
):
    test_action_id = uuid4()
    principal_id = uuid4()

    def _make_action(status: str = "pending"):
        now = datetime.now(UTC)
        return SimpleNamespace(
            action_id=test_action_id,
            principal_id=principal_id,
            summary="Analyst",
            recommended_action="Enable least privilege",
            priority="high",
            status=status,
            evidence=["Repository publicly accessible"],
            notes=[],
            created_by=None,
            accepted_at=None,
            accepted_by=None,
            completed_at=None,
            completed_by=None,
            created_at=now,
            updated_at=now,
        )

    action_state = _make_action()

    async def _fake_update(
        self,
        org_id,
        action_id,
        status,
        user_id,
        note=None,
        user_display_name=None,
    ):
        assert org_id == test_org.org_id
        assert action_id == test_action_id
        now = datetime.now(UTC)
        action_state.status = status
        action_state.updated_at = now
        if status == "accepted":
            action_state.accepted_at = now
            action_state.accepted_by = user_id
        elif status == "completed":
            action_state.completed_at = now
            action_state.completed_by = user_id
        if note:
            action_state.notes = [*list(action_state.notes), {"note_id": str(uuid4()), "author_id": str(user_id), "author": user_display_name, "note": note, "created_at": now.isoformat() + "Z"}]
        return action_state

    async def _fake_add_note(
        self,
        org_id,
        action_id,
        user_id,
        note,
        user_display_name=None,
    ):
        assert org_id == test_org.org_id
        assert action_id == test_action_id
        now = datetime.now(UTC)
        action_state.notes = [*list(action_state.notes), {"note_id": str(uuid4()), "author_id": str(user_id), "author": user_display_name, "note": note, "created_at": now.isoformat() + "Z"}]
        action_state.updated_at = now
        return action_state

    monkeypatch.setattr(
        DashboardRepository, "update_remediation_action_status", _fake_update
    )
    monkeypatch.setattr(DashboardRepository, "add_remediation_note", _fake_add_note)

    accept_response = client.post(
        f"/api/v1/analytics/organizations/{test_org.org_id}/remediation/actions/{test_action_id}/accept",
        json={"note": "Investigating"},
        headers={"Authorization": f"Bearer {test_token}"},
    )
    assert accept_response.status_code == 200, accept_response.text
    accept_payload = accept_response.json()
    assert accept_payload["status"] == "accepted"
    assert accept_payload["notes"], "Accept should append note"

    complete_response = client.post(
        f"/api/v1/analytics/organizations/{test_org.org_id}/remediation/actions/{test_action_id}/complete",
        json={"note": "Resolved"},
        headers={"Authorization": f"Bearer {test_token}"},
    )
    assert complete_response.status_code == 200, complete_response.text
    complete_payload = complete_response.json()
    assert complete_payload["status"] == "completed"
    assert complete_payload["completed_at"] is not None

    note_response = client.post(
        f"/api/v1/analytics/organizations/{test_org.org_id}/remediation/actions/{test_action_id}/notes",
        json={"note": "Follow-up scheduled"},
        headers={"Authorization": f"Bearer {test_token}"},
    )
    assert note_response.status_code == 200, note_response.text
    note_payload = note_response.json()
    assert len(note_payload["notes"]) >= 2


def test_bulk_remediation_action_endpoints(
    client,
    test_db,
    test_org,
    test_token,
    monkeypatch,
):
    action_ids = [uuid4(), uuid4()]
    principal_ids = [uuid4(), uuid4()]

    def _make_action(action_id, principal_id, status="pending"):
        now = datetime.now(UTC)
        return SimpleNamespace(
            action_id=action_id,
            principal_id=principal_id,
            summary="Identity remediation",
            recommended_action="Reduce privileges",
            priority="high",
            status=status,
            evidence=["Excessive admin access"],
            notes=[],
            created_by=None,
            accepted_at=None,
            accepted_by=None,
            completed_at=None,
            completed_by=None,
            created_at=now,
            updated_at=now,
        )

    action_state = {
        aid: _make_action(aid, pid) for aid, pid in zip(action_ids, principal_ids, strict=False)
    }

    async def _fake_bulk_update(
        self,
        org_id,
        action_ids,
        status,
        user_id,
        note=None,
        user_display_name=None,
    ):
        assert org_id == test_org.org_id
        assert set(action_ids) == set(action_state)
        now = datetime.now(UTC)
        updated = []
        for aid in action_ids:
            action = action_state[aid]
            action.status = status
            action.updated_at = now
            if status == "accepted":
                action.accepted_at = now
                action.accepted_by = user_id
            if status == "completed":
                action.completed_at = now
                action.completed_by = user_id
            if note:
                action.notes = [*list(action.notes), {"note_id": str(uuid4()), "author_id": str(user_id), "author": user_display_name, "note": note, "created_at": now.isoformat() + "Z"}]
            updated.append(action)
        return updated

    monkeypatch.setattr(
        DashboardRepository, "update_remediation_actions_status_bulk", _fake_bulk_update
    )

    accept_response = client.post(
        f"/api/v1/analytics/organizations/{test_org.org_id}/remediation/actions/bulk/accept",
        json={
            "action_ids": [str(aid) for aid in action_ids],
            "note": "Investigating batch",
        },
        headers={"Authorization": f"Bearer {test_token}"},
    )
    assert accept_response.status_code == 200, accept_response.text
    accept_payload = accept_response.json()
    assert len(accept_payload["updated"]) == 2
    assert all(item["status"] == "accepted" for item in accept_payload["updated"])
    assert all(item["notes"] for item in accept_payload["updated"])

    complete_response = client.post(
        f"/api/v1/analytics/organizations/{test_org.org_id}/remediation/actions/bulk/complete",
        json={
            "action_ids": [str(aid) for aid in action_ids],
            "note": "Completed batch",
        },
        headers={"Authorization": f"Bearer {test_token}"},
    )
    assert complete_response.status_code == 200, complete_response.text
    complete_payload = complete_response.json()
    assert {item["status"] for item in complete_payload["updated"]} == {"completed"}
    assert all(item["completed_at"] is not None for item in complete_payload["updated"])
