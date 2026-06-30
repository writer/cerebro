package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestSnykAssetProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.assets", Attributes: map[string]string{"resource_id": "asset-1", "resource_type": "host", "resource_name": "host-1", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := snykAssetsProjections(event)
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

func TestSnykFindingProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.findings", Attributes: map[string]string{"finding_id": "finding-1", "title": "Finding One", "severity": "high", "status": "open", "resource_urn": "urn:cerebro:tenant:runtime_asset:asset-1", "evidence_id": "evidence-1"}}
	entities, links, err := snykFindingsProjections(event)
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

func TestSnykVulnerabilitiesProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.vulnerabilities", Attributes: map[string]string{"finding_id": "finding-1", "title": "Finding One", "severity": "high", "status": "open", "resource_urn": "urn:cerebro:tenant:runtime_asset:asset-1", "evidence_id": "evidence-1"}}
	entities, links, err := snykVulnerabilitiesProjections(event)
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

func TestSnykRuntimeKindsAreExplicitDepthEvidence(t *testing.T) {
	cases := []struct {
		event      *cerebrov1.EventEnvelope
		entityType string
	}{
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-org-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.orgs", Attributes: map[string]string{"org_id": "org-1", "name": "Security"}},
			entityType: "snyk.orgs",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-group-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.groups", Attributes: map[string]string{"group_id": "group-1", "name": "Engineering"}},
			entityType: "snyk.groups",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-project-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.projects", Attributes: map[string]string{"project_id": "project-1", "name": "Checkout API", "resource_type": "snyk_project"}},
			entityType: "snyk.projects",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-target-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.targets", Attributes: map[string]string{"target_id": "target-1", "display_name": "writer/cerebro", "resource_type": "snyk_target"}},
			entityType: "snyk.targets",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-asset-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.assets", Attributes: map[string]string{"resource_id": "asset-1", "resource_type": "repository", "resource_name": "writer/cerebro"}},
			entityType: "runtime.repository",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-finding-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.findings", Attributes: map[string]string{"finding_id": "issue-1", "title": "Critical package issue", "severity": "critical", "status": "open"}},
			entityType: "finding",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-vulnerability-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.vulnerabilities", Attributes: map[string]string{"finding_id": "vuln-1", "title": "CVE-2026-0001", "severity": "high", "status": "open"}},
			entityType: "finding",
		},
	}
	registered := make(map[string]struct{})
	for _, kind := range BuiltinRegistry().Kinds() {
		registered[kind] = struct{}{}
	}
	for _, tc := range cases {
		t.Run(tc.event.Kind, func(t *testing.T) {
			if _, ok := registered[tc.event.Kind]; !ok {
				t.Fatalf("declared Snyk kind %q is not routed in the projection registry", tc.event.Kind)
			}
			entities, _, err := BuiltinRegistry().Project(tc.event)
			if err != nil {
				t.Fatalf("Project(%s) error = %v", tc.event.Kind, err)
			}
			if !hasProjectedEntityType(entities, tc.entityType) {
				t.Fatalf("kind %q did not project %q; entities=%#v", tc.event.Kind, tc.entityType, entities)
			}
		})
	}
}
