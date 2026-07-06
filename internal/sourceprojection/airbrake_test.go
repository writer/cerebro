package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestAirbrakeProjectsProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "airbrake", Kind: "airbrake.projects", Attributes: map[string]string{"resource_id": "project-1", "resource_type": "airbrake_project", "resource_name": "Checkout", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := airbrakeProjectsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected project")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
}

func TestAirbrakeGroupsProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "airbrake", Kind: "airbrake.groups", Attributes: map[string]string{"finding_id": "group-1", "title": "RuntimeError", "severity": "error", "status": "open", "resource_urn": "urn:cerebro:tenant:runtime_asset:project-1", "evidence_id": "evidence-1"}}
	entities, links, err := airbrakeGroupsProjections(event)
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

func TestAirbrakeDeploysProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "airbrake", Kind: "airbrake.deploys", Attributes: map[string]string{"resource_id": "deploy-1", "resource_type": "airbrake_deploy", "resource_name": "v1.2.3"}}
	entities, _, err := airbrakeDeploysProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected deploy")
	}
}

func TestAirbrakeSourceMapsProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "airbrake", Kind: "airbrake.source_maps", Attributes: map[string]string{"resource_id": "map-1", "resource_type": "airbrake_source_map", "resource_name": "app.min.js.map"}}
	entities, _, err := airbrakeSourceMapsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected source map")
	}
}

func TestAirbrakeProjectActivitiesProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "airbrake", Kind: "airbrake.project_activities", Attributes: map[string]string{"event_type": "group.resolved", "actor_id": "user-1", "actor_email": "user@example.test", "resource_id": "group-1", "resource_type": "Group"}}
	entities, links, err := airbrakeProjectActivitiesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want audit projection", len(entities), len(links))
	}
}
