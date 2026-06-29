package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestSonarcloudAssetProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "sonarcloud", Kind: "sonarcloud.assets", Attributes: map[string]string{"resource_id": "asset-1", "resource_type": "host", "resource_name": "host-1", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := sonarcloudAssetsProjections(event)
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

func TestSonarcloudFindingProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "sonarcloud", Kind: "sonarcloud.findings", Attributes: map[string]string{"finding_id": "finding-1", "title": "Finding One", "severity": "high", "status": "open", "resource_urn": "urn:cerebro:tenant:runtime_asset:asset-1", "evidence_id": "evidence-1"}}
	entities, links, err := sonarcloudFindingsProjections(event)
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

func TestSonarcloudVulnerabilitiesProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "sonarcloud", Kind: "sonarcloud.vulnerabilities", Attributes: map[string]string{"finding_id": "finding-1", "title": "Finding One", "severity": "high", "status": "open", "resource_urn": "urn:cerebro:tenant:runtime_asset:asset-1", "evidence_id": "evidence-1"}}
	entities, links, err := sonarcloudVulnerabilitiesProjections(event)
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
