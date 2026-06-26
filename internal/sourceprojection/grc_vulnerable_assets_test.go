package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

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

func TestProjectGRCVulnerableAssetLinksURLOnlyHost(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-url",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":     "vanta",
			"target_id":    "asset-123",
			"external_url": "https://app.writer.com",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:grc_target:vanta:asset-123"
	hostURN := "urn:cerebro:writer:internet_host:app.writer.com"
	assertProjectedLink(t, state, targetURN, relationRepresents, hostURN)
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
