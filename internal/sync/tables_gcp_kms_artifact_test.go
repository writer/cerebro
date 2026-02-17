package sync

import (
	"testing"

	"cloud.google.com/go/asset/apiv1/assetpb"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestGCPResourceSegment(t *testing.T) {
	resource := "//cloudkms.googleapis.com/projects/p1/locations/us-east1/keyRings/ring-a/cryptoKeys/key-a"
	if got := gcpResourceSegment(resource, "keyRings"); got != "ring-a" {
		t.Fatalf("expected key ring ring-a, got %q", got)
	}
	if got := gcpResourceSegment(resource, "cryptoKeys"); got != "key-a" {
		t.Fatalf("expected key key-a, got %q", got)
	}
}

func TestGCPAssetValueAndString(t *testing.T) {
	attrs := map[string]interface{}{
		"purpose": "ENCRYPT_DECRYPT",
		"versionTemplate": map[string]interface{}{
			"protectionLevel": "HSM",
		},
	}

	if got := gcpAssetString(attrs, "purpose"); got != "ENCRYPT_DECRYPT" {
		t.Fatalf("unexpected purpose: %q", got)
	}
	if got := gcpAssetString(attrs, "versionTemplate.protectionLevel"); got != "HSM" {
		t.Fatalf("unexpected protection level: %q", got)
	}
	if got := gcpAssetValue(attrs, "missing"); got != nil {
		t.Fatalf("expected nil missing value, got %#v", got)
	}
}

func TestGCPAssetAttributes(t *testing.T) {
	attrs, err := structpb.NewStruct(map[string]interface{}{"mode": "STANDARD_REPOSITORY"})
	if err != nil {
		t.Fatalf("failed to create attributes: %v", err)
	}

	resource := &assetpb.ResourceSearchResult{AdditionalAttributes: attrs}
	parsed := gcpAssetAttributes(resource)
	if parsed["mode"] != "STANDARD_REPOSITORY" {
		t.Fatalf("unexpected parsed mode: %#v", parsed["mode"])
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "   ", "value"); got != "value" {
		t.Fatalf("expected value, got %q", got)
	}
}

func TestGCPArtifactRegistryResourceSegments(t *testing.T) {
	resource := "//artifactregistry.googleapis.com/projects/p1/locations/us/repositories/repo-a/packages/pkg-a/versions/v1"
	if got := gcpResourceSegment(resource, "repositories"); got != "repo-a" {
		t.Fatalf("expected repository repo-a, got %q", got)
	}
	if got := gcpResourceSegment(resource, "packages"); got != "pkg-a" {
		t.Fatalf("expected package pkg-a, got %q", got)
	}
	if got := gcpResourceSegment(resource, "versions"); got != "v1" {
		t.Fatalf("expected version v1, got %q", got)
	}
}

func TestGCPTablesIncludeArtifactRegistryDepth(t *testing.T) {
	e := &GCPSyncEngine{}
	tables := e.getGCPTables()

	seen := make(map[string]bool, len(tables))
	for _, table := range tables {
		seen[table.Name] = true
	}

	for _, name := range []string{"gcp_artifact_registry_repositories", "gcp_artifact_registry_packages", "gcp_artifact_registry_versions"} {
		if !seen[name] {
			t.Fatalf("expected table %s in GCP table set", name)
		}
	}
}
