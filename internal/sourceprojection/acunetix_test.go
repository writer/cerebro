package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestAcunetixTargetProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "acunetix", Kind: "acunetix.targets", Attributes: map[string]string{"resource_id": "target-1", "resource_type": "target", "resource_name": "https://app.example.test", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := acunetixTargetsProjections(event)
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

func TestAcunetixScanProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "acunetix", Kind: "acunetix.scans", Attributes: map[string]string{"finding_id": "scan-1", "title": "Full Scan", "status": "completed", "resource_urn": "urn:cerebro:tenant:runtime_target:target-1", "evidence_id": "evidence-1"}}
	entities, links, err := acunetixScansProjections(event)
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

func TestAcunetixVulnerabilityProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "acunetix", Kind: "acunetix.vulnerabilities", Attributes: map[string]string{"finding_id": "vuln-1", "title": "Cross-site scripting", "severity": "high", "status": "open", "resource_urn": "urn:cerebro:tenant:runtime_target:target-1", "evidence_id": "evidence-1"}}
	entities, links, err := acunetixVulnerabilitiesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected vulnerability")
	}
	if len(links) == 0 {
		t.Fatal("expected projected vulnerability links")
	}
	if !hasProjectedEntityType(entities, "runtime_evidence") {
		t.Fatal("expected projected runtime evidence entity")
	}
}

func TestAcunetixScanningProfileProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "acunetix", Kind: "acunetix.scanning_profiles", Attributes: map[string]string{"policy_id": "profile-1", "policy_name": "Full Scan", "policy_type": "scanning_profile", "policy_status": "enabled", "evidence_id": "evidence-1"}}
	entities, links, err := acunetixScanningProfilesProjections(event)
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

func TestAcunetixReportProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "acunetix", Kind: "acunetix.reports", Attributes: map[string]string{"resource_id": "report-1", "resource_type": "report", "resource_name": "Developer Report", "evidence_id": "evidence-1"}}
	entities, links, err := acunetixReportsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want report projection", len(entities), len(links))
	}
}
