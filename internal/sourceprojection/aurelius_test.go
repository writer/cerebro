package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectAureliusReadsMetadataFromPayload(t *testing.T) {
	tests := []struct {
		name       string
		event      *cerebrov1.EventEnvelope
		entityURN  string
		attributes map[string]string
	}{
		{
			name: "verdict",
			event: &cerebrov1.EventEnvelope{
				Id:       "aurelius-verdict-1",
				TenantId: "writer",
				SourceId: "aurelius",
				Kind:     "aurelius.verdict",
				Attributes: map[string]string{
					"image_digest": "sha256:aaa",
				},
				Payload: mustJSON(t, map[string]any{
					"blocking_findings": 2,
					"excepted_findings": 1,
					"verdict":           "warn",
				}),
			},
			entityURN: "urn:cerebro:writer:aurelius_verdict:sha256:aaa",
			attributes: map[string]string{
				"blocking_findings": "2",
				"excepted_findings": "1",
				"verdict":           "warn",
			},
		},
		{
			name: "image-scan",
			event: &cerebrov1.EventEnvelope{
				Id:       "aurelius-image-scan-1",
				TenantId: "writer",
				SourceId: "aurelius",
				Kind:     "aurelius.image_scan",
				Attributes: map[string]string{
					"image_digest": "sha256:bbb",
				},
				Payload: mustJSON(t, map[string]any{
					"completed_at": "2026-05-22T15:30:00Z",
					"registry":     "us-docker.pkg.dev",
					"scan_id":      "scan-1",
					"scanner":      "aurelius",
					"status":       "complete",
					"verdict":      "pass",
				}),
			},
			entityURN: "urn:cerebro:writer:aurelius_image_scan:scan-1",
			attributes: map[string]string{
				"completed_at": "2026-05-22T15:30:00Z",
				"registry":     "us-docker.pkg.dev",
				"scanner":      "aurelius",
				"status":       "complete",
				"verdict":      "pass",
			},
		},
		{
			name: "catalog-promotion",
			event: &cerebrov1.EventEnvelope{
				Id:       "aurelius-catalog-promotion-1",
				TenantId: "writer",
				SourceId: "aurelius",
				Kind:     "aurelius.catalog_promotion",
				Attributes: map[string]string{
					"image_digest": "sha256:ccc",
				},
				Payload: mustJSON(t, map[string]any{
					"promoted_at": "2026-05-22T16:30:00Z",
					"promoted_by": "security@example.com",
					"track":       "prod",
					"verdict":     "pass",
				}),
			},
			entityURN: "urn:cerebro:writer:aurelius_catalog_promotion:prod|sha256:ccc",
			attributes: map[string]string{
				"promoted_at": "2026-05-22T16:30:00Z",
				"promoted_by": "security@example.com",
				"track":       "prod",
				"verdict":     "pass",
			},
		},
		{
			name: "policy-exception",
			event: &cerebrov1.EventEnvelope{
				Id:       "aurelius-policy-exception-1",
				TenantId: "writer",
				SourceId: "aurelius",
				Kind:     "aurelius.policy_exception",
				Payload: mustJSON(t, map[string]any{
					"approver":     "security@example.com",
					"cve_id":       "CVE-2026-1111",
					"expires_at":   "2026-06-01T00:00:00Z",
					"reason":       "accepted risk",
					"scope":        "prod",
					"status":       "active",
					"image_digest": "sha256:ddd",
				}),
			},
			entityURN: "urn:cerebro:writer:aurelius_policy_exception:CVE-2026-1111",
			attributes: map[string]string{
				"approver":   "security@example.com",
				"expires_at": "2026-06-01T00:00:00Z",
				"reason":     "accepted risk",
				"scope":      "prod",
				"status":     "active",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := &projectionRecorder{}
			service := New(state, nil)

			if _, err := service.Project(context.Background(), tc.event); err != nil {
				t.Fatalf("Project() error = %v", err)
			}
			entity := state.entities[tc.entityURN]
			if entity == nil {
				t.Fatalf("entity %q missing; entities=%v", tc.entityURN, state.entities)
			}
			for key, want := range tc.attributes {
				if got := entity.Attributes[key]; got != want {
					t.Fatalf("entity attribute %q = %q, want %q; attributes=%#v", key, got, want, entity.Attributes)
				}
			}
		})
	}
}

func TestProjectAureliusFindingRecordsPromotedRiskEvidence(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "aurelius-finding-promoted",
		TenantId: "writer",
		SourceId: "aurelius",
		Kind:     "aurelius.finding",
		Attributes: map[string]string{
			"exception_status": "active",
			"promoted":         "true",
			"track":            "prod",
		},
		Payload: mustJSON(t, map[string]any{
			"cve_id":       "CVE-2026-1111",
			"image_digest": "sha256:c6b86af5b3d40000",
			"image_uri":    "us-docker.pkg.dev/writer/prod/api@sha256:c6b86af5b3d40000",
			"package":      "openssl",
			"severity":     "high",
		}),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	imageURN := "urn:cerebro:writer:gcp_artifact_registry_image:us-docker.pkg.dev/writer/prod/api@sha256:c6b86af5b3d40000"
	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-1111"
	link := state.links[imageURN+"|"+relationAffectedBy+"|"+vulnerabilityURN]
	if link == nil {
		t.Fatalf("affected_by link missing; links=%v", state.links)
	}
	for key, want := range map[string]string{
		"promoted":         "true",
		"promoted_track":   "prod",
		"exception_status": "active",
	} {
		if got := link.Attributes[key]; got != want {
			t.Fatalf("affected_by link attribute %q = %q, want %q", key, got, want)
		}
	}
}

func TestProjectAureliusVerdictSupersededReplacementIsDeterministic(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	verdictEvent := func(id string, verdict string) *cerebrov1.EventEnvelope {
		return &cerebrov1.EventEnvelope{
			Id:       id,
			TenantId: "writer",
			SourceId: "aurelius",
			Kind:     "aurelius.verdict",
			Attributes: map[string]string{
				"image_digest": "sha256:superseded",
				"verdict":      verdict,
			},
		}
	}

	if _, err := service.Project(context.Background(), verdictEvent("aurelius-verdict-warn", "warn")); err != nil {
		t.Fatalf("Project(warn) error = %v", err)
	}
	if _, err := service.Project(context.Background(), verdictEvent("aurelius-verdict-block", "block")); err != nil {
		t.Fatalf("Project(block) error = %v", err)
	}

	verdictURN := "urn:cerebro:writer:aurelius_verdict:sha256:superseded"
	entity := state.entities[verdictURN]
	if entity == nil {
		t.Fatalf("verdict entity %q missing; superseded verdict must reuse the same canonical anchor", verdictURN)
	}
	if got := entity.Attributes["verdict"]; got != "block" {
		t.Fatalf("verdict = %q, want superseding value block (deterministic replacement on stable identity)", got)
	}
}

func TestProjectAureliusSparseImageOmitsEmptyImageMetadata(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "aurelius-finding-1",
		TenantId: "writer",
		SourceId: "aurelius",
		Kind:     "aurelius.finding",
		Attributes: map[string]string{
			"cve_id":       "CVE-2026-1111",
			"image_digest": "sha256:c6b86af5b3d40000",
			"image_uri":    "us-docker.pkg.dev/writer/prod/api@sha256:c6b86af5b3d40000",
			"package":      "openssl",
			"severity":     "high",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	imageURN := "urn:cerebro:writer:gcp_artifact_registry_image:us-docker.pkg.dev/writer/prod/api@sha256:c6b86af5b3d40000"
	entity := state.entities[imageURN]
	if entity == nil {
		t.Fatalf("image entity %q missing", imageURN)
	}
	if entity.Attributes["digest"] != "sha256:c6b86af5b3d40000" {
		t.Fatalf("digest = %q, want sha256:c6b86af5b3d40000", entity.Attributes["digest"])
	}
	if entity.Attributes["image_uri"] != "us-docker.pkg.dev/writer/prod/api@sha256:c6b86af5b3d40000" {
		t.Fatalf("image_uri = %q, want canonical image URI", entity.Attributes["image_uri"])
	}
	for _, key := range []string{"registry", "repository"} {
		if value, ok := entity.Attributes[key]; ok {
			t.Fatalf("sparse image attribute %q = %q, want omitted so existing metadata is preserved", key, value)
		}
	}
}

func TestProjectAureliusCatalogPromotionLinksPromoterEmail(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "aurelius-catalog-promotion-promoter",
		TenantId: "writer",
		SourceId: "aurelius",
		Kind:     "aurelius.catalog_promotion",
		Payload: mustJSON(t, map[string]any{
			"image_digest": "sha256:promoted",
			"promoted_by":  "security@example.com",
			"track":        "prod",
		}),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	promotionURN := "urn:cerebro:writer:aurelius_catalog_promotion:prod|sha256:promoted"
	identityURN := "urn:cerebro:writer:identity:email:security@example.com"
	assertProjectedLink(t, state, promotionURN, relationAssociatedWith, identityURN)
	link := state.links[promotionURN+"|"+relationAssociatedWith+"|"+identityURN]
	if got := link.Attributes["contact_type"]; got != "promoted_by" {
		t.Fatalf("contact_type = %q, want promoted_by", got)
	}
}

func TestProjectAureliusDigestOnlyFindingDoesNotCreateArtifactRegistryImage(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "aurelius-finding-digest-only",
		TenantId: "writer",
		SourceId: "aurelius",
		Kind:     "aurelius.finding",
		Attributes: map[string]string{
			"cve_id":       "CVE-2026-1111",
			"image_digest": "sha256:c6b86af5b3d40000",
			"package":      "openssl",
			"severity":     "high",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if entity := state.entities["urn:cerebro:writer:gcp_artifact_registry_image:sha256:c6b86af5b3d40000"]; entity != nil {
		t.Fatalf("digest-only event created non-canonical image entity: %#v", entity)
	}
}

func TestProjectAureliusScanAndVerdictShareDigestAnchor(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "aurelius-image-scan-digest",
			TenantId: "writer",
			SourceId: "aurelius",
			Kind:     "aurelius.image_scan",
			Attributes: map[string]string{
				"image_digest": "sha256:shared",
				"scan_id":      "scan-shared",
			},
		},
		{
			Id:       "aurelius-verdict-digest",
			TenantId: "writer",
			SourceId: "aurelius",
			Kind:     "aurelius.verdict",
			Attributes: map[string]string{
				"image_digest": "sha256:shared",
				"verdict":      "warn",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.GetKind(), err)
		}
	}

	digestURN := "urn:cerebro:writer:container_image_digest:sha256:shared"
	scanURN := "urn:cerebro:writer:aurelius_image_scan:scan-shared"
	verdictURN := "urn:cerebro:writer:aurelius_verdict:sha256:shared"
	if entity := state.entities[digestURN]; entity == nil || entity.EntityType != "container.image_digest" {
		t.Fatalf("digest anchor missing or wrong: %#v", entity)
	}
	assertProjectedLink(t, state, scanURN, relationObservedOn, digestURN)
	assertProjectedLink(t, state, digestURN, relationHasEvidence, scanURN)
	assertProjectedLink(t, state, verdictURN, relationObservedOn, digestURN)
	assertProjectedLink(t, state, digestURN, relationHasEvidence, verdictURN)
	if entity := state.entities["urn:cerebro:writer:gcp_artifact_registry_image:sha256:shared"]; entity != nil {
		t.Fatalf("digest-only scan/verdict created non-canonical image entity: %#v", entity)
	}
}

func TestProjectAureliusImageScanLinksImageRepositoryHierarchy(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "aurelius-image-scan-context",
		TenantId: "writer",
		SourceId: "aurelius",
		Kind:     "aurelius.image_scan",
		Payload: mustJSON(t, map[string]any{
			"image_digest": "sha256:scan",
			"project_id":   "writer-prod",
			"registry":     "us-docker.pkg.dev",
			"repository":   "writer-prod/prod",
			"scan_id":      "scan-context",
		}),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	imageURN := "urn:cerebro:writer:gcp_artifact_registry_image:us-docker.pkg.dev/writer-prod/prod@sha256:scan"
	repositoryURN := "urn:cerebro:writer:container_repository:us-docker.pkg.dev:writer-prod/prod"
	registryURN := "urn:cerebro:writer:container_registry:us-docker.pkg.dev"
	assertProjectedLink(t, state, imageURN, relationBelongsTo, repositoryURN)
	assertProjectedLink(t, state, repositoryURN, relationBelongsTo, registryURN)
	assertProjectedLink(t, state, imageURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:writer-prod")
}

func TestProjectAureliusImageScanOmitsBlankOptionalMetadata(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "aurelius-image-scan-sparse",
		TenantId: "writer",
		SourceId: "aurelius",
		Kind:     "aurelius.image_scan",
		Payload: mustJSON(t, map[string]any{
			"completed_at": "2026-05-22T15:30:00Z",
			"image_digest": "sha256:scan",
			"registry":     "us-docker.pkg.dev",
		}),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	entity := state.entities["urn:cerebro:writer:aurelius_image_scan:sha256:scan"]
	if entity == nil {
		t.Fatal("image scan entity missing")
	}
	for _, key := range []string{"scanner", "status", "verdict"} {
		if value, ok := entity.Attributes[key]; ok {
			t.Fatalf("image scan attribute %q = %q, want omitted", key, value)
		}
	}
}

func TestProjectAureliusCatalogPromotionOmitsBlankOptionalMetadata(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "aurelius-catalog-promotion-sparse",
		TenantId: "writer",
		SourceId: "aurelius",
		Kind:     "aurelius.catalog_promotion",
		Payload: mustJSON(t, map[string]any{
			"image_digest": "sha256:promoted",
			"promoted_by":  "release-bot",
			"track":        "prod",
		}),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	entity := state.entities["urn:cerebro:writer:aurelius_catalog_promotion:prod|sha256:promoted"]
	if entity == nil {
		t.Fatal("catalog promotion entity missing")
	}
	for _, key := range []string{"promoted_at", "verdict"} {
		if value, ok := entity.Attributes[key]; ok {
			t.Fatalf("catalog promotion attribute %q = %q, want omitted", key, value)
		}
	}
}

func TestProjectAureliusFindingUsesPayloadVersionEvidence(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "aurelius-finding-versions",
		TenantId: "writer",
		SourceId: "aurelius",
		Kind:     "aurelius.finding",
		Payload: mustJSON(t, map[string]any{
			"cve_id":            "CVE-2026-1111",
			"fixed_version":     "3.0.12",
			"image_digest":      "sha256:c6b86af5b3d40000",
			"image_uri":         "us-docker.pkg.dev/writer/prod/api@sha256:c6b86af5b3d40000",
			"installed_version": "3.0.0",
			"package":           "openssl",
			"severity":          "high",
		}),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	imageURN := "urn:cerebro:writer:gcp_artifact_registry_image:us-docker.pkg.dev/writer/prod/api@sha256:c6b86af5b3d40000"
	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-1111"
	link := state.links[imageURN+"|"+relationAffectedBy+"|"+vulnerabilityURN]
	if link == nil {
		t.Fatalf("affected_by link missing; links=%v", state.links)
	}
	if got := link.Attributes["vulnerable_version"]; got != "3.0.0" {
		t.Fatalf("vulnerable_version = %q, want 3.0.0", got)
	}
	if got := link.Attributes["fixed_version"]; got != "3.0.12" {
		t.Fatalf("fixed_version = %q, want 3.0.12", got)
	}
}

func TestProjectAureliusFindingPreservesPackageScopedEvidence(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	for _, tc := range []struct {
		id               string
		pkg              string
		installedVersion string
		fixedVersion     string
	}{
		{id: "finding-openssl", pkg: "openssl", installedVersion: "3.0.0", fixedVersion: "3.0.12"},
		{id: "finding-zlib", pkg: "zlib", installedVersion: "1.2.11", fixedVersion: "1.3.1"},
	} {
		if _, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
			Id:       tc.id,
			TenantId: "writer",
			SourceId: "aurelius",
			Kind:     "aurelius.finding",
			Payload: mustJSON(t, map[string]any{
				"cve_id":            "CVE-2026-1111",
				"fixed_version":     tc.fixedVersion,
				"image_digest":      "sha256:c6b86af5b3d40000",
				"installed_version": tc.installedVersion,
				"package":           tc.pkg,
				"severity":          "high",
			}),
		}); err != nil {
			t.Fatalf("Project(%s) error = %v", tc.id, err)
		}
	}

	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-1111"
	for _, tc := range []struct {
		pkg              string
		installedVersion string
		fixedVersion     string
	}{
		{pkg: "openssl", installedVersion: "3.0.0", fixedVersion: "3.0.12"},
		{pkg: "zlib", installedVersion: "1.2.11", fixedVersion: "1.3.1"},
	} {
		packageURN := "urn:cerebro:writer:package:aurelius:" + tc.pkg
		link := state.links[packageURN+"|"+relationAffectedBy+"|"+vulnerabilityURN]
		if link == nil {
			t.Fatalf("package-scoped affected_by link missing for %s; links=%v", tc.pkg, state.links)
		}
		if got := link.Attributes["package"]; got != tc.pkg {
			t.Fatalf("%s link package = %q, want %q", tc.pkg, got, tc.pkg)
		}
		if got := link.Attributes["vulnerable_version"]; got != tc.installedVersion {
			t.Fatalf("%s vulnerable_version = %q, want %q", tc.pkg, got, tc.installedVersion)
		}
		if got := link.Attributes["fixed_version"]; got != tc.fixedVersion {
			t.Fatalf("%s fixed_version = %q, want %q", tc.pkg, got, tc.fixedVersion)
		}
	}
}

func TestProjectAureliusPolicyExceptionOmitsBlankVulnerabilityMetadata(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "aurelius-policy-exception-sparse",
		TenantId: "writer",
		SourceId: "aurelius",
		Kind:     "aurelius.policy_exception",
		Payload: mustJSON(t, map[string]any{
			"cve_id":     "CVE-2026-1111",
			"expires_at": "2026-06-01T00:00:00Z",
			"status":     "active",
		}),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-1111"
	entity := state.entities[vulnerabilityURN]
	if entity == nil {
		t.Fatalf("vulnerability entity %q missing", vulnerabilityURN)
	}
	if got := entity.Attributes["identifier"]; got != "CVE-2026-1111" {
		t.Fatalf("identifier = %q, want CVE-2026-1111; attrs=%v", got, entity.Attributes)
	}
	for _, key := range []string{"severity", "source_provider", "vulnerability_type"} {
		if value, ok := entity.Attributes[key]; ok {
			t.Fatalf("vulnerability attribute %q = %q, want omitted", key, value)
		}
	}
}

func TestProjectAureliusPolicyExceptionOmitsBlankOptionalMetadata(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "aurelius-policy-exception-sparse-update",
		TenantId: "writer",
		SourceId: "aurelius",
		Kind:     "aurelius.policy_exception",
		Payload: mustJSON(t, map[string]any{
			"cve_id":       "CVE-2026-1111",
			"exception_id": "waiver-123",
			"status":       "expired",
		}),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	entity := state.entities["urn:cerebro:writer:aurelius_policy_exception:waiver-123"]
	if entity == nil {
		t.Fatal("policy exception entity missing")
	}
	if got := entity.Attributes["status"]; got != "expired" {
		t.Fatalf("status = %q, want expired", got)
	}
	for _, key := range []string{"approver", "expires_at", "reason", "scope"} {
		if value, ok := entity.Attributes[key]; ok {
			t.Fatalf("policy exception attribute %q = %q, want omitted", key, value)
		}
	}
}

func TestProjectAureliusPolicyExceptionPrefersExceptionIDIdentity(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "aurelius-policy-exception-specific",
		TenantId: "writer",
		SourceId: "aurelius",
		Kind:     "aurelius.policy_exception",
		Payload: mustJSON(t, map[string]any{
			"cve_id":       "CVE-2026-1111",
			"exception_id": "waiver-123",
			"expires_at":   "2026-06-01T00:00:00Z",
			"status":       "active",
		}),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	if state.entities["urn:cerebro:writer:aurelius_policy_exception:waiver-123"] == nil {
		t.Fatalf("exception_id entity missing; entities=%v", state.entities)
	}
	if state.entities["urn:cerebro:writer:aurelius_policy_exception:CVE-2026-1111"] != nil {
		t.Fatalf("policy exception keyed by cve_id despite exception_id; entities=%v", state.entities)
	}
}

func TestProjectAureliusPolicyExceptionLinksApproverEmailIdentity(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "aurelius-policy-exception-approver",
		TenantId: "writer",
		SourceId: "aurelius",
		Kind:     "aurelius.policy_exception",
		Payload: mustJSON(t, map[string]any{
			"approver":   "security@example.com",
			"cve_id":     "CVE-2026-1111",
			"expires_at": "2026-06-01T00:00:00Z",
			"status":     "active",
		}),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	exceptionURN := "urn:cerebro:writer:aurelius_policy_exception:CVE-2026-1111"
	identityURN := "urn:cerebro:writer:identity:email:security@example.com"
	assertProjectedLink(t, state, exceptionURN, relationAssociatedWith, identityURN)
	link := state.links[exceptionURN+"|"+relationAssociatedWith+"|"+identityURN]
	if got := link.Attributes["contact_type"]; got != "approver" {
		t.Fatalf("contact_type = %q, want approver", got)
	}
}
