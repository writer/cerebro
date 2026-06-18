package trivy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := source.Spec().GetId(); got != "trivy" {
		t.Fatalf("Spec().Id = %q, want trivy", got)
	}
}

const trivyReportFixture = `{
  "SchemaVersion": 2,
  "ArtifactName": "registry.example/app:latest",
  "ArtifactType": "container_image",
  "Metadata": {
    "ImageID": "sha256:imageid",
    "RepoTags": ["registry.example/app:latest"],
    "RepoDigests": ["registry.example/app@sha256:deadbeef"]
  },
  "Results": [
    {
      "Target": "registry.example/app (debian 12)",
      "Class": "os-pkgs",
      "Type": "debian",
      "Packages": [
        {"Name": "openssl", "Version": "1.0.0", "Identifier": {"PURL": "pkg:deb/debian/openssl@1.0.0"}}
      ],
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2026-0001",
          "PkgName": "openssl",
          "InstalledVersion": "1.0.0",
          "FixedVersion": "1.0.1",
          "Status": "fixed",
          "Severity": "HIGH",
          "Title": "OpenSSL flaw",
          "PrimaryURL": "https://example.test/CVE-2026-0001",
          "PkgIdentifier": {"PURL": "pkg:deb/debian/openssl@1.0.0"}
        }
      ]
    }
  ]
}`

func writeTrivyReport(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, []byte(trivyReportFixture), 0o600); err != nil {
		t.Fatalf("write report fixture: %v", err)
	}
	return path
}

func TestReadEmitsContractCompleteTrivyKinds(t *testing.T) {
	reportPath := writeTrivyReport(t)
	for _, tt := range []struct {
		family       string
		kind         string
		requiredAttr []string
		want         map[string]string
	}{
		{
			family:       "image_scan",
			kind:         "trivy.image_scan",
			requiredAttr: []string{"image_digest"},
		},
		{
			family:       "image_package",
			kind:         "trivy.image_package",
			requiredAttr: []string{"image_digest", "package"},
			want:         map[string]string{"package": "openssl", "installed_version": "1.0.0"},
		},
		{
			family:       "image_vulnerability",
			kind:         "trivy.image_vulnerability",
			requiredAttr: []string{"image_digest", "vulnerability_id", "package"},
			want: map[string]string{
				"vulnerability_id": "CVE-2026-0001",
				"package":          "openssl",
				"severity":         "HIGH",
				"status":           "fixed",
				"fix_available":    "true",
			},
		},
		{
			family:       "fix",
			kind:         "trivy.fix",
			requiredAttr: []string{"vulnerability_id", "package", "fixed_version"},
			want: map[string]string{
				"vulnerability_id": "CVE-2026-0001",
				"package":          "openssl",
				"fixed_version":    "1.0.1",
			},
		},
	} {
		t.Run(tt.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
				"tenant_id": "writer",
				"family":    tt.family,
				"path":      reportPath,
			}), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("Read(%s) emitted %d events, want 1", tt.family, len(pull.Events))
			}
			event := pull.Events[0]
			if event.GetKind() != tt.kind {
				t.Fatalf("Kind = %q, want %q", event.GetKind(), tt.kind)
			}
			for _, attr := range tt.requiredAttr {
				if got := event.GetAttributes()[attr]; got == "" {
					t.Fatalf("%s required attribute %q is empty", tt.kind, attr)
				}
			}
			for key, value := range tt.want {
				if got := event.GetAttributes()[key]; got != value {
					t.Fatalf("%s attribute %q = %q, want %q", tt.kind, key, got, value)
				}
			}
		})
	}
}

func TestReadSuppressedVulnerabilityReportsNotAffectedStatus(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	report := `{
  "SchemaVersion": 2,
  "ArtifactName": "registry.example/app",
  "Metadata": {"RepoDigests": ["registry.example/app@sha256:deadbeef"]},
  "Results": [
    {
      "Type": "debian",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2026-0002", "PkgName": "curl", "InstalledVersion": "7.0.0", "Status": "not_affected", "Severity": "CRITICAL"}
      ]
    }
  ]
}`
	if err := os.WriteFile(path, []byte(report), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"family":    "image_vulnerability",
		"path":      path,
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(pull.Events))
	}
	if got := pull.Events[0].GetAttributes()["status"]; got != "not_affected" {
		t.Fatalf("status = %q, want not_affected", got)
	}
}
