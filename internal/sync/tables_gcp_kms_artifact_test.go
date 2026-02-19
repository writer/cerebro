package sync

import (
	"reflect"
	"testing"

	"cloud.google.com/go/asset/apiv1/assetpb"
	"cloud.google.com/go/iam/apiv1/iampb"
	exprpb "google.golang.org/genproto/googleapis/type/expr"
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

func TestSerializeGCPIAMBindings(t *testing.T) {
	bindings := []*iampb.Binding{
		{
			Role:    "roles/artifactregistry.admin",
			Members: []string{"user:alice@example.com", "serviceAccount:ci@example.iam.gserviceaccount.com"},
			Condition: &exprpb.Expr{
				Title:      "expires-soon",
				Expression: "request.time < timestamp('2026-01-01T00:00:00Z')",
			},
		},
		{
			Role:    "roles/viewer",
			Members: []string{"group:devs@example.com"},
		},
	}

	got := serializeGCPIAMBindings(bindings)
	if len(got) != 2 {
		t.Fatalf("expected 2 bindings, got %d", len(got))
	}

	if got[0]["role"] != "roles/artifactregistry.admin" {
		t.Fatalf("unexpected role: %v", got[0]["role"])
	}
	if got[0]["members_count"] != 2 {
		t.Fatalf("unexpected members_count: %v", got[0]["members_count"])
	}
	if !reflect.DeepEqual(got[0]["members"], []string{"user:alice@example.com", "serviceAccount:ci@example.iam.gserviceaccount.com"}) {
		t.Fatalf("unexpected members: %#v", got[0]["members"])
	}

	condition, ok := got[0]["condition"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected condition map, got %T", got[0]["condition"])
	}
	if condition["title"] != "expires-soon" {
		t.Fatalf("unexpected condition title: %v", condition["title"])
	}
}

func TestNormalizeGCPAssetName(t *testing.T) {
	tests := map[string]string{
		"//artifactregistry.googleapis.com/projects/p1/locations/us/repositories/repo-a": "artifactregistry.googleapis.com/projects/p1/locations/us/repositories/repo-a",
		"artifactregistry.googleapis.com/projects/p1/locations/us/repositories/repo-a":   "artifactregistry.googleapis.com/projects/p1/locations/us/repositories/repo-a",
		"": "",
	}

	for input, want := range tests {
		if got := normalizeGCPAssetName(input); got != want {
			t.Fatalf("normalizeGCPAssetName(%q) = %q, want %q", input, got, want)
		}
	}
}
