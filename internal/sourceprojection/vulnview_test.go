package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectVulnViewVulnerabilityLinksAssetFindingAndCanonicalCVE(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "vulnview-vuln-1",
		TenantId: "writer",
		SourceId: "vulnview",
		Kind:     "vulnview.vulnerability",
		Attributes: map[string]string{
			"external_id":      "scan-1:cve-2026-1234:https://app.writer.com/login",
			"host":             "app.writer.com",
			"matched_at":       "https://app.writer.com/login",
			"name":             "Test CVE",
			"scan_id":          "scan-1",
			"severity":         "high",
			"template_id":      "cve-2026-1234",
			"vulnerability_id": "cve-2026-1234",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 3 {
		t.Fatalf("Project().EntitiesProjected = %d, want 3", result.EntitiesProjected)
	}
	if result.LinksProjected != 4 {
		t.Fatalf("Project().LinksProjected = %d, want 4", result.LinksProjected)
	}
	assetURN := "urn:cerebro:writer:external_asset:app.writer.com"
	findingURN := "urn:cerebro:writer:vulnview_finding:scan-1:cve-2026-1234:https://app.writer.com/login"
	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-1234"
	if entity := state.entities[assetURN]; entity == nil || entity.EntityType != "external.asset" {
		t.Fatalf("external asset entity missing: %#v", entity)
	}
	if entity := state.entities[findingURN]; entity == nil || entity.EntityType != "vulnview.finding" {
		t.Fatalf("finding entity missing: %#v", entity)
	}
	if entity := state.entities[vulnerabilityURN]; entity == nil || entity.EntityType != "vulnerability" {
		t.Fatalf("canonical vulnerability entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, assetURN, relationHasEvidence, findingURN)
	assertProjectedLink(t, state, findingURN, relationObservedOn, assetURN)
	assertProjectedLink(t, state, assetURN, relationAffectedBy, vulnerabilityURN)
	assertProjectedLink(t, state, findingURN, relationAffectedBy, vulnerabilityURN)
}

func TestProjectVulnViewDNSAlertLinksAssetEvidence(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "vulnview-dns-1",
		TenantId: "writer",
		SourceId: "vulnview",
		Kind:     "vulnview.dns_alert",
		Attributes: map[string]string{
			"asset_id":    "stale.writer.com",
			"external_id": "stale.writer.com:dangling_cname:0",
			"name":        "dangling_cname",
			"severity":    "high",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 2 {
		t.Fatalf("Project().EntitiesProjected = %d, want 2", result.EntitiesProjected)
	}
	if result.LinksProjected != 2 {
		t.Fatalf("Project().LinksProjected = %d, want 2", result.LinksProjected)
	}
	assetURN := "urn:cerebro:writer:external_asset:stale.writer.com"
	alertURN := "urn:cerebro:writer:vulnview_dns_alert:stale.writer.com:dangling_cname:0"
	assertProjectedLink(t, state, assetURN, relationHasEvidence, alertURN)
	assertProjectedLink(t, state, alertURN, relationObservedOn, assetURN)
}
