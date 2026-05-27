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
			"package":      "openssl",
			"severity":     "high",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	imageURN := "urn:cerebro:writer:gcp_artifact_registry_image:sha256:c6b86af5b3d40000"
	entity := state.entities[imageURN]
	if entity == nil {
		t.Fatalf("image entity %q missing", imageURN)
	}
	if entity.Attributes["digest"] != "sha256:c6b86af5b3d40000" {
		t.Fatalf("digest = %q, want sha256:c6b86af5b3d40000", entity.Attributes["digest"])
	}
	for _, key := range []string{"image_uri", "registry", "repository"} {
		if value, ok := entity.Attributes[key]; ok {
			t.Fatalf("sparse image attribute %q = %q, want omitted so existing metadata is preserved", key, value)
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
			"installed_version": "3.0.0",
			"package":           "openssl",
			"severity":          "high",
		}),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	imageURN := "urn:cerebro:writer:gcp_artifact_registry_image:sha256:c6b86af5b3d40000"
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
