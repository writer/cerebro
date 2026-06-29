package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestRootlyAssetProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "rootly", Kind: "rootly.monitors", Attributes: map[string]string{"resource_id": "asset-1", "resource_type": "host", "resource_name": "host-1", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := rootlyMonitorsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected entities")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
	assertRootlyEvidenceEntity(t, entities, "evidence-1")
}

func TestRootlyFindingProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "rootly", Kind: "rootly.incidents", Attributes: map[string]string{"finding_id": "finding-1", "title": "Finding One", "severity": "high", "status": "open", "resource_urn": "urn:cerebro:tenant:runtime_asset:asset-1", "evidence_id": "evidence-1"}}
	entities, links, err := rootlyIncidentsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected finding")
	}
	if len(links) == 0 {
		t.Fatal("expected projected finding links")
	}
	assertRootlyEvidenceEntity(t, entities, "evidence-1")
}

func TestRootlyAlertProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "rootly", Kind: "rootly.alerts", Attributes: map[string]string{"alert_id": "alert-1", "alert_name": "High Error Rate", "alert_severity": "critical", "alert_status": "open", "evidence_id": "evidence-1"}}
	entities, links, err := rootlyAlertsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected alert")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
	assertRootlyEvidenceEntity(t, entities, "evidence-1")
}

func TestRootlyAuditProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "rootly", Kind: "rootly.audit_events", Attributes: map[string]string{"event_type": "user.login", "actor_id": "user-1", "actor_email": "user@example.test", "resource_id": "app-1", "resource_type": "application"}}
	entities, links, err := rootlyAuditEventsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want audit projection", len(entities), len(links))
	}
}

func assertRootlyEvidenceEntity(t *testing.T, entities []*ports.ProjectedEntity, evidenceID string) {
	t.Helper()
	for _, entity := range entities {
		if entity.EntityType == "runtime.evidence" && entity.Attributes["evidence_id"] == evidenceID {
			return
		}
	}
	t.Fatalf("runtime.evidence entity for %q not found: %#v", evidenceID, entities)
}
