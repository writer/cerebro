package sourcefixture

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteBundleAndVerifyRepository(t *testing.T) {
	root := t.TempDir()
	catalogPath := filepath.Join(root, "sources", "demo", "catalog.yaml")
	if err := os.MkdirAll(filepath.Dir(catalogPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(catalogPath, []byte("id: demo\nruntime_families: [users]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(catalogPath), "source_test.go"), []byte("package demo\n\nfunc TestReplayUsers() { _ = sourcefixture.FindBundle; _ = \"list\" }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle, err := WriteBundle(root, Manifest{
		SourceID:   "demo",
		Family:     "users",
		Case:       "list",
		ReplayTest: "source_test.go#TestReplayUsers",
		Request:    Request{Method: "GET", URL: "https://api.example.test/v1/users"},
		Response:   Response{Status: 200, ContentType: "application/json", CapturedAt: "2026-07-18T00:00:00Z"},
		Origin:     Origin{Type: "operator_request"},
	}, []byte(`{"items":[{"id":"user-1","email":"user@example.test"}]}`))
	if err != nil {
		t.Fatalf("WriteBundle() error = %v", err)
	}
	if bundle.Manifest.Response.SHA256 == "" {
		t.Fatal("response digest is empty")
	}
	report, err := VerifyRepository(root)
	if err != nil {
		t.Fatalf("VerifyRepository() error = %v", err)
	}
	if report.Bundles != 1 || report.Sources != 1 || report.Families != 1 {
		t.Fatalf("report = %#v", report)
	}
}

func TestValidateManifestRejectsCredentialAndPersonalEmail(t *testing.T) {
	base := Manifest{
		SchemaVersion: SchemaVersion,
		SourceID:      "demo",
		Family:        "users",
		Case:          "list",
		ReplayTest:    "source_test.go#TestReplayUsers",
		Request:       Request{Method: "GET", URL: "https://api.example.test/v1/users"},
		Response:      Response{Status: 200, ContentType: "application/json", CapturedAt: "2026-07-18T00:00:00Z"},
		Sanitization:  Sanitization{Tool: SanitizerName, Version: SanitizerVersion},
		Origin:        Origin{Type: "operator_request"},
	}
	for _, test := range []struct {
		name    string
		payload string
		want    error
	}{
		{name: "credential", payload: `{"access_token":"secret"}`, want: ErrCredentialField},
		{name: "credential array", payload: `{"tokens":["ghp_realtoken123"]}`, want: ErrCredentialField},
		{name: "credential object", payload: `{"secret":{"access_key":"AKIAIOSFODNN7EXAMPLE"}}`, want: ErrCredentialField},
		{name: "email", payload: `{"email":"person@company.com"}`, want: ErrPersonalEmail},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload, err := CanonicalJSON([]byte(test.payload))
			if err != nil {
				t.Fatal(err)
			}
			manifest := base
			manifest.Response.SHA256 = Digest(payload)
			err = ValidateManifest(manifest, payload)
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateManifest() error = %v, want errors.Is(_, %v)", err, test.want)
			}
		})
	}
}

func TestValidateManifestAllowsEmptyCredentialShapesAndMetadataFields(t *testing.T) {
	payload, err := CanonicalJSON([]byte(`{
		"authorization_url":"https://auth.example.test/oauth/authorize",
		"credential_type":"oauth2",
		"credential_id":"credential-1",
		"credential_name":"primary",
		"api_key_id":"key-1",
		"credentials":{"provider":{"type":""}}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	manifest := testManifest(payload, "https://api.example.test/v1/connections?per_page=1")
	if err := ValidateManifest(manifest, payload); err != nil {
		t.Fatalf("ValidateManifest() error = %v, want credential metadata accepted", err)
	}
}

func TestValidateRelativeArtifactPath(t *testing.T) {
	for _, value := range []string{"", ".", "..", "../fixture.yaml", "/fixture.yaml", `tests\\fixture.yaml`, "tests/../fixture.yaml"} {
		t.Run(value, func(t *testing.T) {
			if err := validateRelativeArtifactPath("origin.path", value); err == nil {
				t.Fatalf("validateRelativeArtifactPath(%q) error = nil", value)
			}
		})
	}
	if err := validateRelativeArtifactPath("origin.path", "tests/cassettes/fixture.yaml"); err != nil {
		t.Fatalf("validateRelativeArtifactPath(valid) error = %v", err)
	}
}

func TestValidateManifestRejectsCredentialQueryParameters(t *testing.T) {
	payload, err := CanonicalJSON([]byte(`{"items":[{"id":"record-1"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"token", "secret", "key", "sig", "pat", "private_token", "auth", "authorization", "X-Amz-Signature"} {
		t.Run(key, func(t *testing.T) {
			manifest := testManifest(payload, "https://api.example.test/v1/items?"+key+"=secret")
			if err := ValidateManifest(manifest, payload); !errors.Is(err, ErrCredentialQuery) {
				t.Fatalf("ValidateManifest() error = %v, want errors.Is(_, ErrCredentialQuery)", err)
			}
		})
	}
}

func TestScanPayloadRestrictsSSHEmailCarveOut(t *testing.T) {
	valid, err := CanonicalJSON([]byte(`{"ssh_url":"git@github.com:writer/cerebro.git"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := scanPayload(valid); err != nil {
		t.Fatalf("scanPayload(valid SSH URL) error = %v", err)
	}
	crafted, err := CanonicalJSON([]byte(`{"description":"git@github.com:writer/cerebro.git contact:victim@company.com:"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := scanPayload(crafted); !errors.Is(err, ErrPersonalEmail) {
		t.Fatalf("scanPayload(crafted description) error = %v, want errors.Is(_, ErrPersonalEmail)", err)
	}
}

func TestScanPayloadAcceptsCommitSHABeginningWithProviderPrefix(t *testing.T) {
	payload, err := CanonicalJSON([]byte(`{"commit":"00a1234567890abcdef0123456789abcdef01234567"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := scanPayload(payload); err != nil {
		t.Fatalf("scanPayload(commit SHA) error = %v", err)
	}
}

func testManifest(payload []byte, requestURL string) Manifest {
	return Manifest{
		SchemaVersion: SchemaVersion,
		SourceID:      "demo",
		Family:        "users",
		Case:          "list",
		ReplayTest:    "source_test.go#TestReplayUsers",
		Request:       Request{Method: "GET", URL: requestURL},
		Response: Response{
			Status:      200,
			ContentType: "application/json",
			CapturedAt:  "2026-07-18T00:00:00Z",
			SHA256:      Digest(payload),
		},
		Sanitization: Sanitization{Tool: SanitizerName, Version: SanitizerVersion},
		Origin:       Origin{Type: "operator_request"},
	}
}

func TestValidateManifestRequiresImmutableUpstreamOrigin(t *testing.T) {
	payload, err := CanonicalJSON([]byte(`{"items":[{"id":"record-1"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	manifest := testManifest(payload, "https://api.example.test/v1/items")
	manifest.Origin = Origin{
		Type:             "upstream_recording",
		Repository:       "https://github.com/example/provider-sdk",
		Commit:           "0123456789abcdef0123456789abcdef01234567",
		Path:             "tests/cassettes/items.yaml",
		ArtifactSHA256:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		License:          "Apache-2.0",
		RecordingTool:    "go-vcr",
		HarnessPath:      "tests/recording_test.go",
		Freshness:        "current",
		CaptureTimeBasis: "response_header",
	}
	if err := ValidateManifest(manifest, payload); err != nil {
		t.Fatalf("ValidateManifest() error = %v", err)
	}
	manifest.Origin.Commit = "main"
	if err := ValidateManifest(manifest, payload); err == nil {
		t.Fatal("ValidateManifest() error = nil, want immutable commit rejection")
	}
}

func TestCanonicalJSONRejectsEmptyResponses(t *testing.T) {
	for _, payload := range []string{"{}", "[]", `""`, "null"} {
		if _, err := CanonicalJSON([]byte(payload)); err == nil {
			t.Fatalf("CanonicalJSON(%s) error = nil", payload)
		}
	}
}
