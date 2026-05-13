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
	if result.EntitiesProjected != 6 {
		t.Fatalf("Project().EntitiesProjected = %d, want 6", result.EntitiesProjected)
	}
	if result.LinksProjected != 8 {
		t.Fatalf("Project().LinksProjected = %d, want 8", result.LinksProjected)
	}
	assetURN := "urn:cerebro:writer:external_asset:app.writer.com"
	hostURN := "urn:cerebro:writer:internet_host:app.writer.com"
	findingURN := "urn:cerebro:writer:vulnview_finding:scan-1:cve-2026-1234:https://app.writer.com/login"
	scanURN := "urn:cerebro:writer:vulnview_scan:scan-1"
	templateURN := "urn:cerebro:writer:vulnview_template:cve-2026-1234"
	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-1234"
	if entity := state.entities[assetURN]; entity == nil || entity.EntityType != "external.asset" {
		t.Fatalf("external asset entity missing: %#v", entity)
	}
	if entity := state.entities[hostURN]; entity == nil || entity.EntityType != "internet.host" {
		t.Fatalf("internet host entity missing: %#v", entity)
	}
	if entity := state.entities[findingURN]; entity == nil || entity.EntityType != "vulnview.finding" {
		t.Fatalf("finding entity missing: %#v", entity)
	}
	if entity := state.entities[scanURN]; entity == nil || entity.EntityType != "vulnview.scan" {
		t.Fatalf("scan entity missing: %#v", entity)
	}
	if entity := state.entities[templateURN]; entity == nil || entity.EntityType != "vulnview.template" {
		t.Fatalf("template entity missing: %#v", entity)
	}
	if entity := state.entities[vulnerabilityURN]; entity == nil || entity.EntityType != "vulnerability" {
		t.Fatalf("canonical vulnerability entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, assetURN, relationRepresents, hostURN)
	assertProjectedLink(t, state, assetURN, relationHasEvidence, findingURN)
	assertProjectedLink(t, state, findingURN, relationObservedOn, assetURN)
	assertProjectedLink(t, state, assetURN, relationBelongsTo, scanURN)
	assertProjectedLink(t, state, findingURN, relationBelongsTo, scanURN)
	assertProjectedLink(t, state, findingURN, relationHasClassification, templateURN)
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
	if result.EntitiesProjected != 4 {
		t.Fatalf("Project().EntitiesProjected = %d, want 4", result.EntitiesProjected)
	}
	if result.LinksProjected != 4 {
		t.Fatalf("Project().LinksProjected = %d, want 4", result.LinksProjected)
	}
	assetURN := "urn:cerebro:writer:external_asset:stale.writer.com"
	hostURN := "urn:cerebro:writer:internet_host:stale.writer.com"
	alertURN := "urn:cerebro:writer:vulnview_dns_alert:stale.writer.com:dangling_cname:0"
	alertTypeURN := "urn:cerebro:writer:vulnview_dns_alert_type:dangling_cname"
	assertProjectedLink(t, state, assetURN, relationRepresents, hostURN)
	assertProjectedLink(t, state, assetURN, relationHasEvidence, alertURN)
	assertProjectedLink(t, state, alertURN, relationObservedOn, assetURN)
	assertProjectedLink(t, state, alertURN, relationHasClassification, alertTypeURN)
}

func TestProjectVulnViewAssetLinksSitesScansAndInternetHost(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "vulnview-asset-1",
		TenantId: "writer",
		SourceId: "vulnview",
		Kind:     "vulnview.asset",
		Attributes: map[string]string{
			"asset_id":   "https://app.writer.com/login",
			"scan_names": "dns-writer.com, port-scan",
			"sites":      "writer.com",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 5 {
		t.Fatalf("Project().EntitiesProjected = %d, want 5", result.EntitiesProjected)
	}
	if result.LinksProjected != 4 {
		t.Fatalf("Project().LinksProjected = %d, want 4", result.LinksProjected)
	}
	assetURN := "urn:cerebro:writer:external_asset:app.writer.com"
	hostURN := "urn:cerebro:writer:internet_host:app.writer.com"
	siteURN := "urn:cerebro:writer:vulnview_site:writer.com"
	scanURN := "urn:cerebro:writer:vulnview_scan:dns-writer.com"
	if _, ok := state.entities[siteURN].Attributes["site_id"]; ok {
		t.Fatal("context site entity should not project blank site_id")
	}
	if _, ok := state.entities[scanURN].Attributes["scan_id"]; ok {
		t.Fatal("context scan entity should not project blank scan_id")
	}
	assertProjectedLink(t, state, assetURN, relationRepresents, hostURN)
	assertProjectedLink(t, state, assetURN, relationBelongsTo, siteURN)
	assertProjectedLink(t, state, assetURN, relationBelongsTo, scanURN)
}

func TestProjectVulnViewScanLinksSite(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "vulnview-scan-1",
		TenantId: "writer",
		SourceId: "vulnview",
		Kind:     "vulnview.scan",
		Attributes: map[string]string{
			"family":           "scan",
			"name":             "dns-writer.com",
			"scan_id":          "scan-1",
			"scan_type":        "dns",
			"site_id":          "site-1",
			"site_name":        "writer.com",
			"cloud_account_id": "123456789012",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 3 {
		t.Fatalf("Project().EntitiesProjected = %d, want 3", result.EntitiesProjected)
	}
	if result.LinksProjected != 2 {
		t.Fatalf("Project().LinksProjected = %d, want 2", result.LinksProjected)
	}
	scanURN := "urn:cerebro:writer:vulnview_scan:dns-writer.com"
	siteURN := "urn:cerebro:writer:vulnview_site:writer.com"
	accountURN := "urn:cerebro:writer:cloud_account:123456789012"
	if got := state.entities[scanURN].Attributes["scan_name"]; got != "dns-writer.com" {
		t.Fatalf("scan_name = %q, want dns-writer.com", got)
	}
	if got := state.entities[scanURN].Attributes["scan_id"]; got != "scan-1" {
		t.Fatalf("scan_id = %q, want scan-1", got)
	}
	if got := state.entities[siteURN].Attributes["site_id"]; got != "site-1" {
		t.Fatalf("site_id = %q, want site-1", got)
	}
	if entity := state.entities[accountURN]; entity == nil || entity.EntityType != "cloud.account" {
		t.Fatalf("cloud account entity missing: %#v", entity)
	}
	if got := state.entities[accountURN].Attributes["provider"]; got != "" {
		t.Fatalf("cloud account provider = %q, want blank without explicit cloud_provider", got)
	}
	assertProjectedLink(t, state, scanURN, relationBelongsTo, siteURN)
	assertProjectedLink(t, state, scanURN, relationBelongsTo, accountURN)
}
