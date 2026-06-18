package trivyinternal

import (
	"strings"
	"testing"
	"time"
)

func TestLoadReportAcceptsMetadataImageID(t *testing.T) {
	source := &Source{
		readFile: func(string) ([]byte, error) {
			return []byte(`{
				"ArtifactName": "registry.example/app:latest",
				"Metadata": {"ImageID": "sha256:cccc"},
				"Results": []
			}`), nil
		},
	}
	report, err := source.loadReport(settings{tenantID: "writer", family: familyImageScan, path: "report.json"})
	if err != nil {
		t.Fatalf("loadReport() error = %v", err)
	}
	if got := imageDigest(report); got != "sha256:cccc" {
		t.Fatalf("imageDigest() = %q, want sha256:cccc", got)
	}
}

func TestFixEventIDsIncludeImageDigest(t *testing.T) {
	source := &Source{now: func() time.Time { return time.Unix(0, 0).UTC() }}
	st := settings{tenantID: "writer", family: familyFix}
	first := fixReport("registry.example/app@sha256:aaaa")
	second := fixReport("registry.example/app@sha256:bbbb")

	firstEvents, err := source.fixEvents(st, first)
	if err != nil {
		t.Fatalf("fixEvents(first) error = %v", err)
	}
	secondEvents, err := source.fixEvents(st, second)
	if err != nil {
		t.Fatalf("fixEvents(second) error = %v", err)
	}
	if len(firstEvents) != 1 || len(secondEvents) != 1 {
		t.Fatalf("event counts = %d/%d, want 1/1", len(firstEvents), len(secondEvents))
	}
	if firstEvents[0].Id == secondEvents[0].Id {
		t.Fatalf("fix event IDs both = %q, want image-scoped IDs", firstEvents[0].Id)
	}
	if !strings.Contains(firstEvents[0].Attributes["image_digest"], "sha256:aaaa") {
		t.Fatalf("first image_digest = %q, want sha256:aaaa", firstEvents[0].Attributes["image_digest"])
	}
}

func fixReport(digest string) report {
	return report{
		ArtifactName: "registry.example/app",
		Metadata: metadata{
			RepoDigests: []string{digest},
		},
		Results: []result{{
			Type: "debian",
			Vulnerabilities: []vulnerability{{
				VulnerabilityID:  "CVE-2026-0001",
				PkgName:          "openssl",
				InstalledVersion: "1.0.0",
				FixedVersion:     "1.0.1",
				Severity:         "HIGH",
			}},
		}},
	}
}
