package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestAbnormalSecurityAssetProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "abnormal_security", Kind: "abnormal_security.resources", Attributes: map[string]string{"resource_id": "asset-1", "resource_type": "host", "resource_name": "host-1", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := abnormalSecurityResourcesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected entities")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
}

func TestAbnormalSecurityFindingProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "abnormal_security", Kind: "abnormal_security.threats", Attributes: map[string]string{"finding_id": "finding-1", "title": "Finding One", "severity": "high", "status": "open", "resource_urn": "urn:cerebro:tenant:runtime_asset:asset-1", "evidence_id": "evidence-1"}}
	entities, links, err := abnormalSecurityThreatsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected finding")
	}
	if len(links) == 0 {
		t.Fatal("expected projected finding links")
	}
	if !hasProjectedEntityType(entities, "runtime_evidence") {
		t.Fatal("expected projected runtime evidence entity")
	}
}

func TestAbnormalSecurityPolicyProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "abnormal_security", Kind: "abnormal_security.posture_catalog", Attributes: map[string]string{"policy_id": "policy-1", "policy_name": "Require MFA", "policy_type": "posture_catalog", "policy_status": "enabled", "evidence_id": "evidence-1"}}
	entities, links, err := abnormalSecurityPostureCatalogProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected policy")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
}

func TestAbnormalSecurityCaseProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "abnormal_security", Kind: "abnormal_security.cases", Attributes: map[string]string{"finding_id": "case-1", "title": "Case One", "severity": "medium", "status": "open", "resource_urn": "urn:cerebro:tenant:identity:employee@example.com", "evidence_id": "evidence-1"}}
	entities, links, err := abnormalSecurityCasesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected case")
	}
	if len(links) == 0 {
		t.Fatal("expected projected case links")
	}
}

func TestAbnormalSecurityAuditProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "abnormal_security", Kind: "abnormal_security.audit_events", Attributes: map[string]string{"event_type": "user.login", "actor_id": "user-1", "actor_email": "user@example.test", "resource_id": "app-1", "resource_type": "application"}}
	entities, links, err := abnormalSecurityAuditEventsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want audit projection", len(entities), len(links))
	}
}
