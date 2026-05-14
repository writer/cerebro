package sourceprojection

import (
	"context"
	"fmt"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type endpointCheckingGraphRecorder struct {
	projectionRecorder
}

func (r *endpointCheckingGraphRecorder) UpsertProjectedLink(ctx context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return nil
	}
	if r.entities[link.FromURN] == nil {
		return fmt.Errorf("graph link source entity %q missing", link.FromURN)
	}
	if r.entities[link.ToURN] == nil {
		return fmt.Errorf("graph link target entity %q missing", link.ToURN)
	}
	return r.projectionRecorder.UpsertProjectedLink(ctx, link)
}

func TestProjectGRCVendorWithOwner(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vendor-vendor-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vendor",
		Attributes: map[string]string{
			"provider":               "vanta",
			"vendor_id":              "vendor-1",
			"name":                   "Acme SaaS",
			"website_url":            "https://app.writer.com",
			"security_owner_user_id": "user-1",
			"inherent_risk_level":    "HIGH",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	vendorURN := "urn:cerebro:writer:vendor:vanta:vendor-1"
	ownerURN := "urn:cerebro:writer:user:vanta:user-1"
	hostURN := "urn:cerebro:writer:internet_host:app.writer.com"
	if entity := state.entities[vendorURN]; entity == nil || entity.EntityType != "vendor" {
		t.Fatalf("vendor entity missing: %#v", entity)
	}
	if got := state.entities[vendorURN].Attributes["inherent_risk_level"]; got != "HIGH" {
		t.Fatalf("vendor inherent_risk_level = %q, want HIGH", got)
	}
	if entity := state.entities[ownerURN]; entity == nil || entity.EntityType != "user" {
		t.Fatalf("owner user entity missing: %#v", entity)
	}
	if entity := state.entities[hostURN]; entity == nil || entity.EntityType != "internet.host" {
		t.Fatalf("internet host entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, vendorURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, vendorURN, relationHasIdentifier, hostURN)
}

func TestProjectGRCControlTestSupportsControlReferences(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-control-test-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.control_test",
		Attributes: map[string]string{
			"provider":             "vanta",
			"test_id":              "test-1",
			"control_ids":          "control-1,control-2",
			"control_external_ids": "CC6.2,CC7.1",
			"status":               "FAIL",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	testURN := "urn:cerebro:writer:evidence:vanta:control_test:test-1"
	firstControlURN := "urn:cerebro:writer:policy:vanta:control:control-1"
	secondControlURN := "urn:cerebro:writer:policy:vanta:control:control-2"
	assertProjectedLink(t, state, testURN, relationSupports, firstControlURN)
	assertProjectedLink(t, state, testURN, relationSupports, secondControlURN)
	if got := state.entities[firstControlURN].Attributes["control_external_id"]; got != "CC6.2" {
		t.Fatalf("first control_external_id = %q, want CC6.2", got)
	}
	if got := state.entities[firstControlURN].Label; got != "CC6.2" {
		t.Fatalf("first control label = %q, want CC6.2", got)
	}
}

func TestProjectGRCControlTestKeepsPairedControlReferences(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-control-test-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.control_test",
		Attributes: map[string]string{
			"provider":             "vanta",
			"test_id":              "test-1",
			"control_ids":          "control-1,control-2",
			"control_external_ids": "CC7.1",
			"control_references":   "control-1=;control-2=CC7.1",
			"status":               "FAIL",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	firstControlURN := "urn:cerebro:writer:policy:vanta:control:control-1"
	secondControlURN := "urn:cerebro:writer:policy:vanta:control:control-2"
	if state.entities[firstControlURN] != nil {
		t.Fatalf("first control entity = %#v, want no placeholder without external ID", state.entities[firstControlURN])
	}
	if got := state.entities[secondControlURN].Attributes["control_external_id"]; got != "CC7.1" {
		t.Fatalf("second control_external_id = %q, want CC7.1", got)
	}
}

func TestProjectGRCControlTestDoesNotRegressControlLabelWhenExternalIDMissingLater(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	first := &cerebrov1.EventEnvelope{
		Id:       "grc-control-test-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.control_test",
		Attributes: map[string]string{
			"provider":           "vanta",
			"test_id":            "test-1",
			"control_references": "control-1=CC6.2",
			"status":             "FAIL",
		},
	}
	if _, err := service.Project(context.Background(), first); err != nil {
		t.Fatalf("Project(first) error = %v", err)
	}
	second := &cerebrov1.EventEnvelope{
		Id:       "grc-control-test-2",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.control_test",
		Attributes: map[string]string{
			"provider":           "vanta",
			"test_id":            "test-2",
			"control_references": "control-1=",
			"status":             "FAIL",
		},
	}
	if _, err := service.Project(context.Background(), second); err != nil {
		t.Fatalf("Project(second) error = %v", err)
	}

	controlURN := "urn:cerebro:writer:policy:vanta:control:control-1"
	if got := state.entities[controlURN].Label; got != "CC6.2" {
		t.Fatalf("control label = %q, want CC6.2", got)
	}
}

func TestProjectGRCRiskScenarioOwnerDoesNotCreatePersonIdentityBridge(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-risk-risk-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.risk_scenario",
		Attributes: map[string]string{
			"provider":    "vanta",
			"risk_id":     "risk-1",
			"description": "AI vendor risk",
			"owner":       "alice@writer.com",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	riskURN := "urn:cerebro:writer:claim:vanta:risk_scenario:risk-1"
	contactURN := "urn:cerebro:writer:contact:vanta:owner:alice@writer.com"
	personURN := "urn:cerebro:writer:person:vanta:owner:alice@writer.com"
	assertProjectedLink(t, state, riskURN, relationAssignedTo, contactURN)
	if _, ok := state.entities[personURN]; ok {
		t.Fatalf("risk owner projected as GRC person: %#v", state.entities[personURN])
	}
	assertProjectedLinkMissing(t, state, contactURN, relationRepresentsIdentity, "urn:cerebro:writer:identity:email:alice@writer.com")
}

func TestProjectGRCPersonIdentifier(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-person-person-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.person",
		Attributes: map[string]string{
			"provider":          "vanta",
			"person_id":         "person-1",
			"email":             "alice@writer.com",
			"employment_status": "CURRENT",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	personURN := "urn:cerebro:writer:person:vanta:person-1"
	identifierURN := "urn:cerebro:writer:identifier:email:alice@writer.com"
	if entity := state.entities[personURN]; entity == nil || entity.EntityType != "person" {
		t.Fatalf("person entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, personURN, relationHasIdentifier, identifierURN)
}

func TestProjectGRCPersonStampsIdentifierLinksWithObservationTime(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	historicalEmploymentDate := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	before := time.Now().UTC()

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         "grc-person-person-1",
		TenantId:   "writer",
		SourceId:   "grc",
		Kind:       "grc.person",
		OccurredAt: timestamppb.New(historicalEmploymentDate),
		Attributes: map[string]string{
			"provider":          "vanta",
			"person_id":         "person-1",
			"email":             "alice@writer.com",
			"employment_status": "CURRENT",
		},
	})
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	personURN := "urn:cerebro:writer:person:vanta:person-1"
	identityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	link, ok := state.links[personURN+"|"+relationRepresentsIdentity+"|"+identityURN]
	if !ok {
		t.Fatalf("represents_identity link missing for %s -> %s: %#v", personURN, identityURN, state.links)
	}
	stamped, err := time.Parse(time.RFC3339, link.Attributes["at"])
	if err != nil {
		t.Fatalf("represents_identity at = %q is not RFC3339: %v", link.Attributes["at"], err)
	}
	if stamped.Equal(historicalEmploymentDate) {
		t.Fatalf("represents_identity at = %q, want projection observation time", link.Attributes["at"])
	}
	if stamped.Before(before.Add(-time.Second)) || stamped.After(after.Add(time.Second)) {
		t.Fatalf("represents_identity at = %v not within projection window [%v, %v]", stamped, before, after)
	}
}

func TestProjectGRCVulnerabilityUsesCanonicalVulnerability(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerability-vuln-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerability",
		Attributes: map[string]string{
			"provider":          "vanta",
			"vulnerability_id":  "vuln-1",
			"name":              "CVE-2026-4242",
			"package":           "pkg:golang/example/module@1.2.3",
			"package_purl":      "pkg:golang/example/module@1.2.3",
			"severity":          "HIGH",
			"remediate_by_date": "2026-05-30T00:00:00Z",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	if entity := state.entities[vulnerabilityURN]; entity == nil || entity.EntityType != "vulnerability" {
		t.Fatalf("vulnerability entity missing: %#v", entity)
	}
	if got := state.entities[vulnerabilityURN].Attributes["remediate_by_date"]; got != "" {
		t.Fatalf("canonical vulnerability remediate_by_date = %q, want empty package-specific deadline", got)
	}
	if got := state.entities[vulnerabilityURN].Attributes["package"]; got != "" {
		t.Fatalf("canonical vulnerability package = %q, want empty package-specific package", got)
	}
	packageURN := "urn:cerebro:writer:package:grc:pkg:golang/example/module@1.2.3"
	link := state.links[packageURN+"|"+relationAffectedBy+"|"+vulnerabilityURN]
	if link == nil {
		t.Fatalf("GRC package affected_by vulnerability link missing: %#v", state.links)
	}
	if got := link.Attributes["remediate_by_date"]; got != "2026-05-30T00:00:00Z" {
		t.Fatalf("affected_by remediate_by_date = %q, want deadline", got)
	}
}

func TestProjectGRCVulnerabilitySkipsMissingTargetAndIntegrationIDs(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerability-vuln-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerability",
		Attributes: map[string]string{
			"provider":         "vanta",
			"vulnerability_id": "vuln-1",
			"name":             "CVE-2026-4242",
			"package":          "example/module",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:grc_target:vanta"
	integrationURN := "urn:cerebro:writer:source:vanta:integration"
	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	packageURN := "urn:cerebro:writer:package:grc:example/module"

	if entity := state.entities[targetURN]; entity != nil {
		t.Fatalf("phantom GRC target entity = %#v, want nil", entity)
	}
	if entity := state.entities[integrationURN]; entity != nil {
		t.Fatalf("phantom GRC integration entity = %#v, want nil", entity)
	}
	assertProjectedLinkMissing(t, state, targetURN, relationAffectedBy, vulnerabilityURN)
	assertProjectedLinkMissing(t, state, targetURN, relationContains, packageURN)
	assertProjectedLinkMissing(t, state, targetURN, relationBelongsTo, integrationURN)
}

func TestProjectGRCVulnerabilityLinksTargetPackageAndIntegration(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerability-vuln-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerability",
		Attributes: map[string]string{
			"provider":           "vanta",
			"vulnerability_id":   "vuln-1",
			"name":               "CVE-2026-4242",
			"package":            "example/module",
			"package_purl":       "pkg:golang/example/module@1.2.3",
			"severity":           "HIGH",
			"target_id":          "target-1",
			"integration_id":     "integration-1",
			"vulnerability_type": "package",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:grc_target:vanta:target-1"
	integrationURN := "urn:cerebro:writer:source:vanta:integration:integration-1"
	packageURN := "urn:cerebro:writer:package:grc:example/module"
	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"

	if entity := state.entities[targetURN]; entity == nil || entity.EntityType != "grc.target" {
		t.Fatalf("GRC target entity missing: %#v", entity)
	}
	if got := state.entities[targetURN].Attributes["integration_id"]; got != "integration-1" {
		t.Fatalf("target integration_id = %q, want integration-1", got)
	}
	if entity := state.entities[integrationURN]; entity == nil || entity.EntityType != "source" {
		t.Fatalf("GRC integration source reference missing: %#v", entity)
	}
	assertProjectedLink(t, state, targetURN, relationAffectedBy, vulnerabilityURN)
	assertProjectedLink(t, state, targetURN, relationContains, packageURN)
	assertProjectedLink(t, state, targetURN, relationBelongsTo, integrationURN)
}

func TestProjectGRCVulnerabilityLinksHostLikeTargetID(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerability-host-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerability",
		Attributes: map[string]string{
			"provider":         "vanta",
			"vulnerability_id": "vuln-1",
			"name":             "CVE-2026-4242",
			"target_id":        "app.writer.com",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:grc_target:vanta:app.writer.com"
	hostURN := "urn:cerebro:writer:internet_host:app.writer.com"
	if got := state.entities[targetURN].Attributes["host"]; got != "app.writer.com" {
		t.Fatalf("target host = %q, want app.writer.com", got)
	}
	assertProjectedLink(t, state, targetURN, relationRepresents, hostURN)
}

func TestProjectGRCVulnerableAssetEnrichesVulnerabilityTarget(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":                   "vanta",
			"target_id":                  "target-1",
			"target_name":                "App Server",
			"hostname":                   "app.writer.com",
			"ip":                         "203.0.113.10",
			"integration_id":             "integration-1",
			"asset_type":                 "server",
			"vulnerability_ids":          "CVE-2026-4242",
			"package_identifiers":        "pkg:golang/example/module@1.2.3",
			"vulnerability_package_refs": `[{"vulnerability_id":"CVE-2026-4242","package_identifier":"pkg:golang/example/module@1.2.3"}]`,
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:grc_target:vanta:target-1"
	hostURN := "urn:cerebro:writer:internet_host:app.writer.com"
	ipURN := "urn:cerebro:writer:internet_ip:203.0.113.10"
	integrationURN := "urn:cerebro:writer:source:vanta:integration:integration-1"
	packageURN := "urn:cerebro:writer:package:grc:pkg:golang/example/module@1.2.3"
	canonicalPackageURN := "urn:cerebro:writer:package:canonical:pkg:golang/example/module"
	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"

	if entity := state.entities[targetURN]; entity == nil || entity.EntityType != "grc.target" {
		t.Fatalf("GRC target entity missing: %#v", entity)
	}
	if got := state.entities[targetURN].Attributes["host"]; got != "app.writer.com" {
		t.Fatalf("target host = %q, want app.writer.com", got)
	}
	if got := state.entities[targetURN].Attributes["target_type"]; got != "server" {
		t.Fatalf("target_type = %q, want server", got)
	}
	assertProjectedLink(t, state, targetURN, relationRepresents, hostURN)
	assertProjectedLink(t, state, targetURN, relationRepresents, ipURN)
	assertProjectedLink(t, state, targetURN, relationBelongsTo, integrationURN)
	assertProjectedLink(t, state, targetURN, relationAffectedBy, vulnerabilityURN)
	assertProjectedLink(t, state, targetURN, relationContains, packageURN)
	assertProjectedLink(t, state, packageURN, relationRepresents, canonicalPackageURN)
	assertProjectedLink(t, state, packageURN, relationAffectedBy, vulnerabilityURN)
	assertProjectedLink(t, state, canonicalPackageURN, relationAffectedBy, vulnerabilityURN)
}

func TestProjectGRCVulnerableAssetPreservesPackageVulnerabilityPairs(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-2",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":            "vanta",
			"target_id":           "target-2",
			"vulnerability_ids":   "CVE-2026-4242,CVE-2026-4243",
			"package_identifiers": "pkg:golang/example/one@1.0.0,pkg:golang/example/two@2.0.0",
			"vulnerability_package_refs": `[` +
				`{"vulnerability_id":"CVE-2026-4242","package_identifier":"pkg:golang/example/one@1.0.0"},` +
				`{"vulnerability_id":"CVE-2026-4243","package_identifier":"pkg:golang/example/two@2.0.0"}` +
				`]`,
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	packageOneURN := "urn:cerebro:writer:package:grc:pkg:golang/example/one@1.0.0"
	packageTwoURN := "urn:cerebro:writer:package:grc:pkg:golang/example/two@2.0.0"
	vulnerabilityOneURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	vulnerabilityTwoURN := "urn:cerebro:writer:vulnerability:cve-2026-4243"

	assertProjectedLink(t, state, packageOneURN, relationAffectedBy, vulnerabilityOneURN)
	assertProjectedLink(t, state, packageTwoURN, relationAffectedBy, vulnerabilityTwoURN)
	assertProjectedLinkMissing(t, state, packageOneURN, relationAffectedBy, vulnerabilityTwoURN)
	assertProjectedLinkMissing(t, state, packageTwoURN, relationAffectedBy, vulnerabilityOneURN)
}

func TestProjectGRCVulnerableAssetZipsFlatPackageVulnerabilityFields(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-flat",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":            "vanta",
			"target_id":           "target-flat",
			"vulnerability_ids":   "CVE-2026-4242,CVE-2026-4243",
			"package_identifiers": "pkg:golang/example/one@1.0.0,pkg:golang/example/two@2.0.0",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	packageOneURN := "urn:cerebro:writer:package:grc:pkg:golang/example/one@1.0.0"
	packageTwoURN := "urn:cerebro:writer:package:grc:pkg:golang/example/two@2.0.0"
	vulnerabilityOneURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	vulnerabilityTwoURN := "urn:cerebro:writer:vulnerability:cve-2026-4243"

	assertProjectedLink(t, state, packageOneURN, relationAffectedBy, vulnerabilityOneURN)
	assertProjectedLink(t, state, packageTwoURN, relationAffectedBy, vulnerabilityTwoURN)
	assertProjectedLinkMissing(t, state, packageOneURN, relationAffectedBy, vulnerabilityTwoURN)
	assertProjectedLinkMissing(t, state, packageTwoURN, relationAffectedBy, vulnerabilityOneURN)
}

func TestProjectGRCVulnerableAssetMergesFlatPackagesIntoReferences(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-mixed",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":                   "vanta",
			"target_id":                  "target-mixed",
			"package_identifiers":        "pkg:golang/example/one@1.0.0,pkg:golang/example/two@2.0.0",
			"vulnerability_package_refs": `[{"vulnerability_id":"CVE-2026-4242"},{"vulnerability_id":"CVE-2026-4243"}]`,
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	packageOneURN := "urn:cerebro:writer:package:grc:pkg:golang/example/one@1.0.0"
	packageTwoURN := "urn:cerebro:writer:package:grc:pkg:golang/example/two@2.0.0"
	vulnerabilityOneURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	vulnerabilityTwoURN := "urn:cerebro:writer:vulnerability:cve-2026-4243"

	assertProjectedLink(t, state, packageOneURN, relationAffectedBy, vulnerabilityOneURN)
	assertProjectedLink(t, state, packageTwoURN, relationAffectedBy, vulnerabilityTwoURN)
	assertProjectedLinkMissing(t, state, packageOneURN, relationAffectedBy, vulnerabilityTwoURN)
	assertProjectedLinkMissing(t, state, packageTwoURN, relationAffectedBy, vulnerabilityOneURN)
}

func TestProjectGRCVulnerableAssetAppendsTrailingFlatTuples(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-trailing",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":                   "vanta",
			"target_id":                  "target-trailing",
			"vulnerability_ids":          "CVE-2026-4242,CVE-2026-4243",
			"package_identifiers":        "pkg:golang/example/one@1.0.0,pkg:golang/example/two@2.0.0",
			"vulnerability_package_refs": `[{"vulnerability_id":"CVE-2026-4242","package_identifier":"pkg:golang/example/one@1.0.0"}]`,
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	packageTwoURN := "urn:cerebro:writer:package:grc:pkg:golang/example/two@2.0.0"
	vulnerabilityTwoURN := "urn:cerebro:writer:vulnerability:cve-2026-4243"

	assertProjectedLink(t, state, packageTwoURN, relationAffectedBy, vulnerabilityTwoURN)
}

func TestProjectGRCVulnerableAssetZipsFlatVulnerabilityNames(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-names",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":            "vanta",
			"target_id":           "target-names",
			"vulnerability_ids":   "CVE-2026-4242,CVE-2026-4243",
			"vulnerability_names": "openssl bug,nginx bug",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:grc_target:vanta:target-names"
	firstVulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	secondVulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-4243"
	assertProjectedLink(t, state, targetURN, relationAffectedBy, firstVulnerabilityURN)
	assertProjectedLink(t, state, targetURN, relationAffectedBy, secondVulnerabilityURN)
	if got := state.links[targetURN+"|"+relationAffectedBy+"|"+firstVulnerabilityURN].Attributes["name"]; got != "openssl bug" {
		t.Fatalf("first vulnerability evidence name = %q, want openssl bug", got)
	}
	if got := state.links[targetURN+"|"+relationAffectedBy+"|"+secondVulnerabilityURN].Attributes["name"]; got != "nginx bug" {
		t.Fatalf("second vulnerability evidence name = %q, want nginx bug", got)
	}
}

func TestProjectGRCVulnerableAssetDoesNotInferVulnerabilityFromReferenceJSON(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-3",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":  "vanta",
			"target_id": "target-3",
			"vulnerability_package_refs": `[` +
				`{"package_identifier":"pkg:golang/example/one@1.0.0"},` +
				`{"vulnerability_id":"CVE-2026-4243","package_identifier":"pkg:golang/example/two@2.0.0"}` +
				`]`,
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	packageOneURN := "urn:cerebro:writer:package:grc:pkg:golang/example/one@1.0.0"
	vulnerabilityTwoURN := "urn:cerebro:writer:vulnerability:cve-2026-4243"

	assertProjectedLinkMissing(t, state, packageOneURN, relationAffectedBy, vulnerabilityTwoURN)
}

func TestProjectGRCVulnerabilityWritesGraphTargetIntegrationLinks(t *testing.T) {
	state := &projectionRecorder{}
	graph := &endpointCheckingGraphRecorder{}
	service := New(state, graph)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerability-vuln-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerability",
		Attributes: map[string]string{
			"provider":         "vanta",
			"vulnerability_id": "vuln-1",
			"name":             "CVE-2026-4242",
			"package":          "example/module",
			"target_id":        "target-1",
			"integration_id":   "integration-1",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:grc_target:vanta:target-1"
	integrationURN := "urn:cerebro:writer:source:vanta:integration:integration-1"
	packageURN := "urn:cerebro:writer:package:grc:example/module"
	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	if graph.entities[targetURN] == nil {
		t.Fatalf("graph target entity missing")
	}
	if graph.entities[integrationURN] == nil {
		t.Fatalf("graph integration entity missing")
	}
	assertProjectedLink(t, &graph.projectionRecorder, targetURN, relationAffectedBy, vulnerabilityURN)
	assertProjectedLink(t, &graph.projectionRecorder, targetURN, relationContains, packageURN)
	assertProjectedLink(t, &graph.projectionRecorder, targetURN, relationBelongsTo, integrationURN)
}

func TestProjectGRCVulnerabilityDoesNotRegressIntegrationLabel(t *testing.T) {
	integrationURN := "urn:cerebro:writer:source:vanta:integration:integration-1"
	targetURN := "urn:cerebro:writer:grc_target:vanta:target-1"
	entities, links, err := grcVulnerabilityProjections(&cerebrov1.EventEnvelope{
		Id:       "grc-vulnerability-vuln-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerability",
		Attributes: map[string]string{
			"provider":         "vanta",
			"vulnerability_id": "vuln-1",
			"name":             "CVE-2026-4242",
			"package":          "example/module",
			"target_id":        "target-1",
			"integration_id":   "integration-1",
		},
	})
	if err != nil {
		t.Fatalf("grcVulnerabilityProjections() error = %v", err)
	}

	var integrationLabel string
	integrationFound := false
	for _, entity := range entities {
		if entity.URN == integrationURN {
			integrationFound = true
			integrationLabel = entity.Label
			break
		}
	}
	if !integrationFound {
		t.Fatalf("integration reference entity missing: %#v", entities)
	}
	if integrationLabel != "" {
		t.Fatalf("integration reference label = %q, want empty fallback-preserving label", integrationLabel)
	}
	for _, link := range links {
		if link.FromURN == targetURN && link.Relation == relationBelongsTo && link.ToURN == integrationURN {
			return
		}
	}
	t.Fatalf("target belongs_to integration link missing: %#v", links)
}
