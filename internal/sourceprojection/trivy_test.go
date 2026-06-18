package sourceprojection

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func trivyTestEvent(id string, kind string, attrs map[string]string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "trivy",
		Kind:       kind,
		OccurredAt: timestamppb.New(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)),
		Attributes: attrs,
		Payload:    []byte(`{}`),
	}
}

func TestProjectTrivyImageGraphRelationships(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	ctx := context.Background()

	// The in-memory recorder replaces entities on upsert (production stores
	// merge), so families that emit stub references (scan/package/fix) are
	// projected before the rich vulnerability event to keep attribute
	// assertions deterministic.
	events := []*cerebrov1.EventEnvelope{
		trivyTestEvent("trivy-scan-1", "trivy.image_scan", map[string]string{
			"image_digest": "sha256:deadbeef", "image_uri": "registry.example/app", "scanner": "trivy",
		}),
		trivyTestEvent("trivy-pkg-1", "trivy.image_package", map[string]string{
			"image_digest": "sha256:deadbeef", "package": "openssl", "installed_version": "1.0.0", "ecosystem": "debian",
		}),
		trivyTestEvent("trivy-fix-1", "trivy.fix", map[string]string{
			"image_digest": "sha256:deadbeef", "vulnerability_id": "CVE-2026-0001", "package": "openssl", "fixed_version": "1.0.1",
		}),
		trivyTestEvent("trivy-vuln-1", "trivy.image_vulnerability", map[string]string{
			"image_digest": "sha256:deadbeef", "vulnerability_id": "CVE-2026-0001", "package": "openssl",
			"installed_version": "1.0.0", "fixed_version": "1.0.1", "fix_available": "true", "severity": "HIGH", "status": "fixed",
		}),
	}
	for _, event := range events {
		if _, err := service.Project(ctx, event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.GetKind(), err)
		}
	}

	imageURN := "urn:cerebro:writer:trivy_image:sha256:deadbeef"
	packageURN := "urn:cerebro:writer:trivy_package:sha256:deadbeef:openssl"
	vulnerabilityURN := "urn:cerebro:writer:trivy_vulnerability:sha256:deadbeef:CVE-2026-0001:openssl"
	fixURN := "urn:cerebro:writer:trivy_fix:sha256:deadbeef:CVE-2026-0001:openssl:1.0.1"

	if entity := state.entities[imageURN]; entity == nil || entity.EntityType != "trivy.image" {
		t.Fatalf("trivy.image entity missing or wrong: %#v", entity)
	}
	if entity := state.entities[packageURN]; entity == nil || entity.EntityType != "trivy.package" {
		t.Fatalf("trivy.package entity missing or wrong: %#v", entity)
	}
	vuln := state.entities[vulnerabilityURN]
	if vuln == nil || vuln.EntityType != "trivy.vulnerability" {
		t.Fatalf("trivy.vulnerability entity missing or wrong: %#v", vuln)
	}
	if got := vuln.Attributes["severity"]; got != "HIGH" {
		t.Fatalf("vulnerability severity attribute = %q, want HIGH", got)
	}
	if entity := state.entities[fixURN]; entity == nil || entity.EntityType != "trivy.fix" {
		t.Fatalf("trivy.fix entity missing or wrong: %#v", entity)
	}

	assertProjectedLink(t, state, imageURN, relationContains, packageURN)
	assertProjectedLink(t, state, packageURN, relationBelongsTo, imageURN)
	assertProjectedLink(t, state, packageURN, relationAffectedBy, vulnerabilityURN)
	assertProjectedLink(t, state, imageURN, relationAffectedBy, vulnerabilityURN)
	// trivy.fix links to the same vulnerability identity emitted by the vulnerability family.
	assertProjectedLink(t, state, fixURN, relationResolvesTo, vulnerabilityURN)
}

func TestRegistryRoutesTrivyKinds(t *testing.T) {
	cases := []struct {
		kind       string
		attrs      map[string]string
		entityType string
	}{
		{"trivy.image_scan", map[string]string{"image_digest": "sha256:deadbeef", "image_uri": "registry.example/app"}, "trivy.image"},
		{"trivy.image_package", map[string]string{"image_digest": "sha256:deadbeef", "package": "openssl"}, "trivy.package"},
		{"trivy.image_vulnerability", map[string]string{"image_digest": "sha256:deadbeef", "vulnerability_id": "CVE-2026-0001", "package": "openssl", "severity": "HIGH", "status": "affected"}, "trivy.vulnerability"},
		{"trivy.fix", map[string]string{"image_digest": "sha256:deadbeef", "vulnerability_id": "CVE-2026-0001", "package": "openssl", "fixed_version": "1.0.1"}, "trivy.fix"},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			entities, _, err := BuiltinRegistry().Project(trivyTestEvent("trivy-"+tc.kind, tc.kind, tc.attrs))
			if err != nil {
				t.Fatalf("Project(%s) error = %v", tc.kind, err)
			}
			found := false
			for _, entity := range entities {
				if entity.EntityType == tc.entityType {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("kind %q did not route to dedicated projector; entities=%#v", tc.kind, entities)
			}
		})
	}
}

func TestProjectTrivyResolvedVulnerabilitySupersession(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	ctx := context.Background()

	open := trivyTestEvent("trivy-vuln-open", "trivy.image_vulnerability", map[string]string{
		"image_digest": "sha256:deadbeef", "vulnerability_id": "CVE-2026-0001", "package": "openssl",
		"severity": "HIGH", "status": "affected", "fixed_version": "1.0.1", "fix_available": "true",
	})
	if _, err := service.Project(ctx, open); err != nil {
		t.Fatalf("Project(open) error = %v", err)
	}

	imageURN := "urn:cerebro:writer:trivy_image:sha256:deadbeef"
	packageURN := "urn:cerebro:writer:trivy_package:sha256:deadbeef:openssl"
	vulnerabilityURN := "urn:cerebro:writer:trivy_vulnerability:sha256:deadbeef:CVE-2026-0001:openssl"
	assertProjectedLink(t, state, packageURN, relationAffectedBy, vulnerabilityURN)
	assertProjectedLink(t, state, imageURN, relationAffectedBy, vulnerabilityURN)

	// A later scan reports the same vulnerability as VEX-suppressed; the obsolete
	// affecting links must be reconciled away.
	resolved := trivyTestEvent("trivy-vuln-resolved", "trivy.image_vulnerability", map[string]string{
		"image_digest": "sha256:deadbeef", "vulnerability_id": "CVE-2026-0001", "package": "openssl",
		"severity": "HIGH", "status": "not_affected",
	})
	if _, err := service.Project(ctx, resolved); err != nil {
		t.Fatalf("Project(resolved) error = %v", err)
	}
	assertProjectedLinkMissing(t, state, packageURN, relationAffectedBy, vulnerabilityURN)
	assertProjectedLinkMissing(t, state, imageURN, relationAffectedBy, vulnerabilityURN)
}

func TestProjectTrivyVulnerabilityNoRetractionWhileActive(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := trivyTestEvent("trivy-vuln-active", "trivy.image_vulnerability", map[string]string{
		"image_digest": "sha256:deadbeef", "vulnerability_id": "CVE-2026-0001", "package": "openssl",
		"severity": "HIGH", "status": "affected",
	})
	links, err := service.ProjectRetractions(event)
	if err != nil {
		t.Fatalf("ProjectRetractions() error = %v", err)
	}
	if len(links) != 0 {
		t.Fatalf("expected no retractions for active vulnerability; got %#v", links)
	}
}
