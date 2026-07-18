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
	}
	for _, test := range []struct {
		name    string
		payload string
		want    error
	}{
		{name: "credential", payload: `{"access_token":"secret"}`, want: ErrCredentialField},
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

func TestCanonicalJSONRejectsEmptyResponses(t *testing.T) {
	for _, payload := range []string{"{}", "[]", `""`, "null"} {
		if _, err := CanonicalJSON([]byte(payload)); err == nil {
			t.Fatalf("CanonicalJSON(%s) error = nil", payload)
		}
	}
}
