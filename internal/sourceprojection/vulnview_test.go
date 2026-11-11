package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectVulnViewFindingLinksAssetEvidence(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "vulnview-finding-1",
		TenantId: "writer",
		SourceId: "vulnview",
		Kind:     "vulnview.finding",
		Attributes: map[string]string{
			"finding_id": "scan-1:cve-2026-1234:https://app.writer.com/login",
			"source":     "nuclei",
			"check_id":   "cve-2026-1234",
			"title":      "Test CVE",
			"severity":   "high",
			"status":     "open",
			"asset":      "app.writer.com",
			"asset_id":   "app.writer.com",
			"location":   "https://app.writer.com/login",
			"version":    "1",
			"updated_at": "2026-05-12T00:00:00Z",
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
	assetURN := "urn:cerebro:writer:external_asset:app.writer.com"
	hostURN := "urn:cerebro:writer:internet_host:app.writer.com"
	domainURN := "urn:cerebro:writer:internet_domain:writer.com"
	findingURN := "urn:cerebro:writer:vulnview_finding:scan-1:cve-2026-1234:https://app.writer.com/login"
	if entity := state.entities[assetURN]; entity == nil || entity.EntityType != "external.asset" {
		t.Fatalf("external asset entity missing: %#v", entity)
	}
	if entity := state.entities[hostURN]; entity == nil || entity.EntityType != "internet.host" {
		t.Fatalf("internet host entity missing: %#v", entity)
	}
	if entity := state.entities[findingURN]; entity == nil || entity.EntityType != "vulnview.finding" {
		t.Fatalf("finding entity missing: %#v", entity)
	}
	if got := state.entities[findingURN].Attributes["observation_version"]; got != "1" {
		t.Fatalf("observation_version = %q, want 1", got)
	}
	if got := state.entities[findingURN].Attributes["observation_precedence"]; got != "strict" {
		t.Fatalf("observation_precedence = %q, want strict", got)
	}
	assertProjectedLink(t, state, assetURN, relationRepresents, hostURN)
	assertProjectedLink(t, state, hostURN, relationBelongsTo, domainURN)
	assertProjectedLink(t, state, assetURN, relationHasEvidence, findingURN)
	assertProjectedLink(t, state, findingURN, relationObservedOn, assetURN)
}

// Only external attack-surface sources scan network hosts. A cloud_identity
// finding's asset is its principal ARN and a prowler finding's is a cloud
// resource ID; projecting either as an external.asset would mint a bogus
// host node (and, for cloud_identity, a second has_evidence edge beside the
// canonical principal).
func TestProjectVulnViewFindingDoesNotTreatNonHostAssetsAsExternalAssets(t *testing.T) {
	for _, source := range []string{"cloud_identity", "prowler", "github"} {
		t.Run(source, func(t *testing.T) {
			state := &projectionRecorder{}
			findingID := source + "|check|arn:aws:iam::111111111111:role/example"
			_, err := New(state, nil).Project(context.Background(), &cerebrov1.EventEnvelope{
				Id:       "vulnview-finding-" + source,
				TenantId: "writer",
				SourceId: "vulnview",
				Kind:     "vulnview.finding",
				Attributes: map[string]string{
					"finding_id":        findingID,
					"source":            source,
					"check_id":          "check",
					"severity":          "high",
					"status":            "open",
					"asset":             "arn:aws:iam::111111111111:role/example",
					"asset_id":          "arn:aws:iam::111111111111:role/example",
					"resource_provider": "aws",
					"principal_id":      "arn:aws:iam::111111111111:role/example",
					"principal_kind":    "aws_role",
					"version":           "1",
					"updated_at":        "2026-05-12T00:00:00Z",
				},
			})
			if err != nil {
				t.Fatalf("Project() error = %v", err)
			}
			findingURN := "urn:cerebro:writer:vulnview_finding:" + findingID
			if state.entities[findingURN] == nil {
				t.Fatalf("finding entity missing")
			}
			for urn, entity := range state.entities {
				switch entity.EntityType {
				case "external.asset", "internet.host", "internet.domain":
					t.Fatalf("%s finding minted %s entity %q from a non-host asset", source, entity.EntityType, urn)
				}
			}
			evidenceSources := 0
			for _, link := range state.links {
				if link.ToURN == findingURN && link.Relation == relationHasEvidence {
					evidenceSources++
				}
			}
			want := 0
			if source == "cloud_identity" {
				want = 1 // the canonical principal only
			}
			if evidenceSources != want {
				t.Fatalf("%s finding has %d has_evidence sources, want %d", source, evidenceSources, want)
			}
		})
	}
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
	if result.EntitiesProjected != 6 {
		t.Fatalf("Project().EntitiesProjected = %d, want 6", result.EntitiesProjected)
	}
	if result.LinksProjected != 5 {
		t.Fatalf("Project().LinksProjected = %d, want 5", result.LinksProjected)
	}
	assetURN := "urn:cerebro:writer:external_asset:app.writer.com"
	hostURN := "urn:cerebro:writer:internet_host:app.writer.com"
	domainURN := "urn:cerebro:writer:internet_domain:writer.com"
	siteURN := "urn:cerebro:writer:vulnview_site:writer.com"
	scanURN := "urn:cerebro:writer:vulnview_scan:dns-writer.com"
	if _, ok := state.entities[siteURN].Attributes["site_id"]; ok {
		t.Fatal("context site entity should not project blank site_id")
	}
	if _, ok := state.entities[scanURN].Attributes["scan_id"]; ok {
		t.Fatal("context scan entity should not project blank scan_id")
	}
	assertProjectedLink(t, state, assetURN, relationRepresents, hostURN)
	assertProjectedLink(t, state, hostURN, relationBelongsTo, domainURN)
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

// TestVulnViewFindingRetractsClearedTriageOnUntriage pins F10: triage is
// ALWAYS present in the standardized export ("none" when untriaged), but
// the reason/by/at/expiresAt fields a prior accepted/false-positive triage
// set are simply absent from an untriaged observation. The finding entity
// must list them in RetractedAttributes so a store actually clears them
// instead of keeping the older observation's stale triage disposition.
func TestVulnViewFindingRetractsClearedTriageOnUntriage(t *testing.T) {
	triaged := &cerebrov1.EventEnvelope{
		Id: "event-1", TenantId: "writer", SourceId: "vulnview", Kind: "vulnview.finding",
		Attributes: map[string]string{
			"finding_id": "f1", "source": "nuclei", "check_id": "exposed-panel",
			"title": "Exposed Admin Panel", "severity": "high", "status": "open",
			"asset": "admin.writer.com", "location": "https://admin.writer.com/login",
			"triage_state": "accepted", "triage_reason": "accepted risk",
			"triage_by": "alice@writer.com", "triage_at": "2026-01-01T00:00:00Z",
			"triage_expires_at": "2026-06-01T00:00:00Z",
			"version":           "1", "updated_at": "2026-01-01T00:00:00Z",
		},
	}
	triagedEntities, _, err := vulnViewFindingProjections(triaged)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections(triaged) error = %v", err)
	}
	triagedFinding := findEntity(triagedEntities, "vulnview.finding")
	if triagedFinding == nil || triagedFinding.Attributes["triage_state"] != "accepted" {
		t.Fatalf("triaged finding entity = %#v, want triage_state accepted", triagedFinding)
	}
	for _, key := range triagedFinding.RetractedAttributes {
		if key == "triage_reason" || key == "triage_by" || key == "triage_at" || key == "triage_expires_at" {
			t.Fatalf("triaged RetractedAttributes = %v, must not retract a triage field this observation carries", triagedFinding.RetractedAttributes)
		}
	}

	untriaged := &cerebrov1.EventEnvelope{
		Id: "event-2", TenantId: "writer", SourceId: "vulnview", Kind: "vulnview.finding",
		Attributes: map[string]string{
			"finding_id": "f1", "source": "nuclei", "check_id": "exposed-panel",
			"title": "Exposed Admin Panel", "severity": "high", "status": "open",
			"asset": "admin.writer.com", "location": "https://admin.writer.com/login",
			"triage_state": "none",
			"version":      "2", "updated_at": "2026-02-01T00:00:00Z",
		},
	}
	untriagedEntities, _, err := vulnViewFindingProjections(untriaged)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections(untriaged) error = %v", err)
	}
	untriagedFinding := findEntity(untriagedEntities, "vulnview.finding")
	if untriagedFinding == nil || untriagedFinding.Attributes["triage_state"] != "none" {
		t.Fatalf("untriaged finding entity = %#v, want triage_state none", untriagedFinding)
	}
	wantRetracted := map[string]bool{
		"triage_reason": true, "triage_by": true, "triage_at": true, "triage_expires_at": true,
	}
	gotRetracted := map[string]bool{}
	for _, key := range untriagedFinding.RetractedAttributes {
		gotRetracted[key] = true
	}
	for key := range wantRetracted {
		if !gotRetracted[key] {
			t.Fatalf("RetractedAttributes = %v, want it to include %q", untriagedFinding.RetractedAttributes, key)
		}
	}
	if _, ok := untriagedFinding.Attributes["triage_reason"]; ok {
		t.Fatalf("untriaged Attributes still carries triage_reason: %#v", untriagedFinding.Attributes)
	}
}

// TestVulnViewFindingMatcherDetailsAreOwnedAttributes pins F13: matcher
// and template_path reach the finding entity's owned attributes, and are
// retracted on a later version that no longer carries them (e.g. a
// template rename producing a fresh evaluation without the old path).
func TestVulnViewFindingMatcherDetailsAreOwnedAttributes(t *testing.T) {
	withMatcher := &cerebrov1.EventEnvelope{
		Id: "event-1", TenantId: "writer", SourceId: "vulnview", Kind: "vulnview.finding",
		Attributes: map[string]string{
			"finding_id": "f1", "source": "nuclei", "check_id": "exposed-panel",
			"title": "Exposed Admin Panel", "severity": "high", "status": "open",
			"asset": "admin.writer.com", "location": "https://admin.writer.com/login",
			"matcher": "status-and-word", "template_path": "http/exposed-panels/admin-panel.yaml",
			"version": "1", "updated_at": "2026-01-01T00:00:00Z",
		},
	}
	withMatcherEntities, _, err := vulnViewFindingProjections(withMatcher)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections(withMatcher) error = %v", err)
	}
	withMatcherFinding := findEntity(withMatcherEntities, "vulnview.finding")
	if withMatcherFinding == nil || withMatcherFinding.Attributes["matcher"] != "status-and-word" || withMatcherFinding.Attributes["template_path"] != "http/exposed-panels/admin-panel.yaml" {
		t.Fatalf("finding entity = %#v, want matcher/template_path attributes", withMatcherFinding)
	}

	withoutMatcher := &cerebrov1.EventEnvelope{
		Id: "event-2", TenantId: "writer", SourceId: "vulnview", Kind: "vulnview.finding",
		Attributes: map[string]string{
			"finding_id": "f1", "source": "nuclei", "check_id": "exposed-panel",
			"title": "Exposed Admin Panel", "severity": "high", "status": "open",
			"asset": "admin.writer.com", "location": "https://admin.writer.com/login",
			"version": "2", "updated_at": "2026-02-01T00:00:00Z",
		},
	}
	withoutMatcherEntities, _, err := vulnViewFindingProjections(withoutMatcher)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections(withoutMatcher) error = %v", err)
	}
	withoutMatcherFinding := findEntity(withoutMatcherEntities, "vulnview.finding")
	if withoutMatcherFinding == nil {
		t.Fatal("missing finding entity")
	}
	if _, ok := withoutMatcherFinding.Attributes["matcher"]; ok {
		t.Fatalf("Attributes still carries matcher: %#v", withoutMatcherFinding.Attributes)
	}
	retracted := map[string]bool{}
	for _, key := range withoutMatcherFinding.RetractedAttributes {
		retracted[key] = true
	}
	if !retracted["matcher"] || !retracted["template_path"] {
		t.Fatalf("RetractedAttributes = %v, want it to include matcher and template_path", withoutMatcherFinding.RetractedAttributes)
	}
}

// TestVulnViewFindingProvenanceIntegrationsAreOwnedAttributes pins Contract
// C2: durable integration attribution (provenance.integrations,
// provenance.repositoryIntegrations, provenance.integrationAttribution,
// already flattened onto bounded event attributes by
// sources/vulnview/records.go) reaches the finding entity's owned
// attributes as sorted, comma-joined kind:id pairs, and is retracted on a
// later version that no longer carries it -- an attribution change must
// never fabricate an identity nor get stuck on a stale run's attribution.
func TestVulnViewFindingProvenanceIntegrationsAreOwnedAttributes(t *testing.T) {
	withIntegrations := &cerebrov1.EventEnvelope{
		Id: "event-1", TenantId: "writer", SourceId: "vulnview", Kind: "vulnview.finding",
		Attributes: map[string]string{
			"finding_id": "f1", "source": "cloud_identity", "check_id": "cloud_identity_excess_privilege",
			"title": "Role grants unused write access", "severity": "high", "status": "open",
			"version": "1", "updated_at": "2026-01-01T00:00:00Z",
			"provenance_integrations":            "cloud_account:prof-example",
			"provenance_repository_integrations": "github:gh-1",
			"provenance_integration_attribution": "run",
		},
	}
	withEntities, _, err := vulnViewFindingProjections(withIntegrations)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections(withIntegrations) error = %v", err)
	}
	withFinding := findEntity(withEntities, "vulnview.finding")
	if withFinding == nil {
		t.Fatal("missing finding entity")
	}
	if got := withFinding.Attributes["provenance_integrations"]; got != "cloud_account:prof-example" {
		t.Fatalf("provenance_integrations = %q, want cloud_account:prof-example", got)
	}
	if got := withFinding.Attributes["provenance_repository_integrations"]; got != "github:gh-1" {
		t.Fatalf("provenance_repository_integrations = %q, want github:gh-1", got)
	}
	if got := withFinding.Attributes["provenance_integration_attribution"]; got != "run" {
		t.Fatalf("provenance_integration_attribution = %q, want run", got)
	}

	withoutIntegrations := &cerebrov1.EventEnvelope{
		Id: "event-2", TenantId: "writer", SourceId: "vulnview", Kind: "vulnview.finding",
		Attributes: map[string]string{
			"finding_id": "f1", "source": "cloud_identity", "check_id": "cloud_identity_excess_privilege",
			"title": "Role grants unused write access", "severity": "high", "status": "open",
			"version": "2", "updated_at": "2026-02-01T00:00:00Z",
		},
	}
	withoutEntities, _, err := vulnViewFindingProjections(withoutIntegrations)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections(withoutIntegrations) error = %v", err)
	}
	withoutFinding := findEntity(withoutEntities, "vulnview.finding")
	if withoutFinding == nil {
		t.Fatal("missing finding entity")
	}
	for _, key := range []string{"provenance_integrations", "provenance_repository_integrations", "provenance_integration_attribution"} {
		if _, ok := withoutFinding.Attributes[key]; ok {
			t.Fatalf("Attributes still carries %q: %#v", key, withoutFinding.Attributes)
		}
	}
	retracted := map[string]bool{}
	for _, key := range withoutFinding.RetractedAttributes {
		retracted[key] = true
	}
	for _, key := range []string{"provenance_integrations", "provenance_repository_integrations", "provenance_integration_attribution"} {
		if !retracted[key] {
			t.Fatalf("RetractedAttributes = %v, want it to include %q", withoutFinding.RetractedAttributes, key)
		}
	}
}
