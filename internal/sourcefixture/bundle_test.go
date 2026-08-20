package sourcefixture

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	if err := os.WriteFile(filepath.Join(filepath.Dir(catalogPath), "source_test.go"), []byte("package demo\n\nfunc TestReplayUsers() { _, _ = sourcefixture.FindBundle(\"\", \"demo\", \"users\", \"list\"); _ = sourcefixture.ValidateReplayContract(nil, nil) }\n"), 0o600); err != nil {
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
	accessKey := "AKIA" + "IOSFODNN7EXAMPLE"
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
		{name: "credential object", payload: fmt.Sprintf(`{"secret":{"access_key":%q}}`, accessKey), want: ErrCredentialField},
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
		"credentials":{"provider":{"type":""}},
		"issue_token":0,
		"next_token":"4611686018799963893",
		"pagination_token":"page-2",
		"credential_enabled":false
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

func TestValidateManifestRequiresExplicitLangfuseHostSanitization(t *testing.T) {
	payload, err := CanonicalJSON([]byte(`{"data":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	manifest := testManifest(payload, "https://langfuse.example.com/api/public/projects")
	manifest.SourceID = "langfuse"
	if err := ValidateManifest(manifest, payload); !errors.Is(err, ErrSanitizedURL) {
		t.Fatalf("ValidateManifest(unmarked example host) error = %v, want errors.Is(_, ErrSanitizedURL)", err)
	}
	manifest.Sanitization.ChangedFields = []string{"$request.url"}
	if err := ValidateManifest(manifest, payload); err != nil {
		t.Fatalf("ValidateManifest(marked example host) error = %v", err)
	}
	manifest.Request.URL = "https://private.langfuse.writer.com/api/public/projects"
	if err := ValidateManifest(manifest, payload); !errors.Is(err, ErrSanitizedURL) {
		t.Fatalf("ValidateManifest(environment host) error = %v, want errors.Is(_, ErrSanitizedURL)", err)
	}
}

func TestValidateManifestAcceptsOnlyExplicitReadOnlyPostQuery(t *testing.T) {
	payload, err := CanonicalJSON([]byte(`{"runs":[{"id":"run-example"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	bodyDigest, err := CanonicalRequestBodySHA256([]byte(`{"limit":100,"select":["id","name","run_type","start_time","end_time","status","error","session_id","total_tokens","prompt_tokens","completion_tokens","trace_id"]}`))
	if err != nil {
		t.Fatal(err)
	}
	valid := testManifest(payload, "https://api.smith.langchain.com/api/v1/runs/query")
	valid.SourceID = "langchain"
	valid.Request = Request{
		Method:     "POST",
		URL:        valid.Request.URL,
		Semantics:  "read_only_query",
		BodySHA256: bodyDigest,
	}
	if err := ValidateManifest(valid, payload); err != nil {
		t.Fatalf("ValidateManifest(read-only POST) error = %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*Manifest)
	}{
		{name: "missing semantics", mutate: func(manifest *Manifest) { manifest.Request.Semantics = "" }},
		{name: "write semantics", mutate: func(manifest *Manifest) { manifest.Request.Semantics = "mutation" }},
		{name: "missing body digest", mutate: func(manifest *Manifest) { manifest.Request.BodySHA256 = "" }},
		{name: "invalid body digest", mutate: func(manifest *Manifest) { manifest.Request.BodySHA256 = "sha256:not-a-digest" }},
		{name: "another canonical body digest", mutate: func(manifest *Manifest) { manifest.Request.BodySHA256 = strings.Repeat("a", 64) }},
		{name: "unapproved method", mutate: func(manifest *Manifest) { manifest.Request.Method = "PUT" }},
		{name: "another source", mutate: func(manifest *Manifest) { manifest.SourceID = "writer" }},
		{name: "another host", mutate: func(manifest *Manifest) { manifest.Request.URL = "https://langsmith.example.test/api/v1/runs/query" }},
		{name: "another path", mutate: func(manifest *Manifest) { manifest.Request.URL = "https://api.smith.langchain.com/api/v1/runs/search" }},
		{name: "mutation endpoint", mutate: func(manifest *Manifest) { manifest.Request.URL = "https://api.smith.langchain.com/api/v1/runs/batch" }},
		{name: "query string", mutate: func(manifest *Manifest) { manifest.Request.URL += "?limit=1" }},
		{name: "fragment", mutate: func(manifest *Manifest) { manifest.Request.URL += "#fragment" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest := valid
			test.mutate(&manifest)
			if err := ValidateManifest(manifest, payload); err == nil {
				t.Fatal("ValidateManifest() error = nil, want fail-closed request rejection")
			}
		})
	}
}

func TestValidateManifestRejectsGETFragment(t *testing.T) {
	payload, err := CanonicalJSON([]byte(`{"data":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	manifest := testManifest(payload, "https://api.example.test/v1/items#fragment")
	if err := ValidateManifest(manifest, payload); !errors.Is(err, ErrURLFragment) {
		t.Fatalf("ValidateManifest() error = %v, want errors.Is(_, ErrURLFragment)", err)
	}
}

func TestValidateManifestRejectsMalformedQuery(t *testing.T) {
	payload, err := CanonicalJSON([]byte(`{"data":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		rawQuery string
	}{
		{name: "semicolon", rawQuery: "kept=1;discarded=2"},
		{name: "percent_escape", rawQuery: "kept=%zz"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest := testManifest(payload, "https://api.example.test/v1/items?"+test.rawQuery)
			if err := ValidateManifest(manifest, payload); !errors.Is(err, ErrMalformedQuery) {
				t.Fatalf("ValidateManifest() error = %v, want errors.Is(_, ErrMalformedQuery)", err)
			}
		})
	}
}

func TestValidateReplayContractBindsIdentityAndSanitizedRequest(t *testing.T) {
	payload, err := CanonicalJSON([]byte(`{"data":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	manifest := testManifest(payload, "https://api.example.test/v1/items?limit=1&offset=0")
	manifest.SourceID = "demo"
	manifest.Family = "item"
	manifest.Case = "authorized_first_page"
	bundle := Bundle{Manifest: manifest, Payload: payload}
	expected := ReplayContract{
		SourceID: "demo",
		Family:   "item",
		Case:     "authorized_first_page",
		Method:   "GET",
		Host:     "api.example.test",
		Path:     "/v1/items",
		RawQuery: "offset=0&limit=1",
	}
	if err := ValidateReplayContract(bundle, expected); err != nil {
		t.Fatalf("ValidateReplayContract() error = %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*ReplayContract)
	}{
		{name: "source", mutate: func(contract *ReplayContract) { contract.SourceID = "other" }},
		{name: "family", mutate: func(contract *ReplayContract) { contract.Family = "other" }},
		{name: "case", mutate: func(contract *ReplayContract) { contract.Case = "other" }},
		{name: "method", mutate: func(contract *ReplayContract) { contract.Method = "POST" }},
		{name: "host", mutate: func(contract *ReplayContract) { contract.Host = "other.example.test" }},
		{name: "path", mutate: func(contract *ReplayContract) { contract.Path = "/v1/other" }},
		{name: "query", mutate: func(contract *ReplayContract) { contract.RawQuery = "limit=2&offset=0" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			contract := expected
			test.mutate(&contract)
			if err := ValidateReplayContract(bundle, contract); err == nil {
				t.Fatal("ValidateReplayContract() error = nil, want mismatch rejection")
			}
		})
	}
	bundle.Manifest.Request.URL += "#fragment"
	if err := ValidateReplayContract(bundle, expected); !errors.Is(err, ErrURLFragment) {
		t.Fatalf("ValidateReplayContract(fragment) error = %v, want errors.Is(_, ErrURLFragment)", err)
	}
}

func TestValidateReplayContractRejectsMalformedActualAndExpectedQuery(t *testing.T) {
	payload, err := CanonicalJSON([]byte(`{"data":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	manifest := testManifest(payload, "https://api.example.test/v1/items?kept=1")
	manifest.SourceID = "demo"
	manifest.Family = "item"
	manifest.Case = "authorized_first_page"
	bundle := Bundle{Manifest: manifest, Payload: payload}
	expected := ReplayContract{SourceID: "demo", Family: "item", Case: "authorized_first_page", Method: http.MethodGet, Host: "api.example.test", Path: "/v1/items", RawQuery: "kept=1"}
	for _, test := range []struct {
		name     string
		rawQuery string
	}{
		{name: "semicolon", rawQuery: "kept=1;discarded=2"},
		{name: "percent_escape", rawQuery: "kept=%zz"},
	} {
		t.Run("actual_"+test.name, func(t *testing.T) {
			bundle.Manifest.Request.URL = "https://api.example.test/v1/items?" + test.rawQuery
			if err := ValidateReplayContract(bundle, expected); !errors.Is(err, ErrReplayQuery) {
				t.Fatalf("ValidateReplayContract(actual malformed query) error = %v, want errors.Is(_, ErrReplayQuery)", err)
			}
		})
	}
	bundle.Manifest.Request.URL = "https://api.example.test/v1/items?kept=1"
	for _, test := range []struct {
		name     string
		rawQuery string
	}{
		{name: "semicolon", rawQuery: "kept=1;discarded=2"},
		{name: "percent_escape", rawQuery: "kept=%zz"},
	} {
		t.Run("expected_"+test.name, func(t *testing.T) {
			expected.RawQuery = test.rawQuery
			if err := ValidateReplayContract(bundle, expected); !errors.Is(err, ErrReplayQuery) {
				t.Fatalf("ValidateReplayContract(expected malformed query) error = %v, want errors.Is(_, ErrReplayQuery)", err)
			}
		})
	}
}

func TestVerifyReplayTestRequiresBoundProvenanceForAIGovernanceBatch(t *testing.T) {
	root := t.TempDir()
	testDir := filepath.Join(root, "sources", "writer")
	if err := os.MkdirAll(testDir, 0o750); err != nil {
		t.Fatal(err)
	}
	testPath := filepath.Join(testDir, "source_test.go")
	bundle := Bundle{ManifestPath: "fixture/provenance.yaml", Manifest: Manifest{
		SourceID:   "writer",
		Family:     "model",
		Case:       "authorized_first_page",
		ReplayTest: "source_test.go#TestReplay",
		Request:    Request{Method: http.MethodGet, URL: "https://api.writer.com/v1/models"},
	}}
	fixturePreamble := "package writer\n\nimport (\n\t\"net/http\"\n\t\"testing\"\n\n\t\"github.com/writer/cerebro/internal/sourcefixture\"\n)\n\n"
	validContract := `sourcefixture.ReplayContract{SourceID: "writer", Family: "model", Case: "authorized_first_page", Method: http.MethodGet, Host: "api.writer.com", Path: "/v1/models", RawQuery: ""}`
	for _, test := range []struct {
		name   string
		source string
	}{
		{name: "if_false", source: fixturePreamble + "func TestReplay(t *testing.T) { bundle, _ := sourcefixture.FindBundle(\"\", \"writer\", \"model\", \"authorized_first_page\"); if false { sourcefixture.RequireReplayContract(t, bundle, " + validContract + ") } }\n"},
		{name: "blank_contract", source: fixturePreamble + "func TestReplay(t *testing.T) { bundle, _ := sourcefixture.FindBundle(\"\", \"writer\", \"model\", \"authorized_first_page\"); sourcefixture.RequireReplayContract(t, bundle, sourcefixture.ReplayContract{}) }\n"},
		{name: "wrong_family", source: fixturePreamble + "func TestReplay(t *testing.T) { bundle, _ := sourcefixture.FindBundle(\"\", \"writer\", \"model\", \"authorized_first_page\"); sourcefixture.RequireReplayContract(t, bundle, sourcefixture.ReplayContract{SourceID: \"writer\", Family: \"graph\", Case: \"authorized_first_page\", Method: http.MethodGet, Host: \"api.writer.com\", Path: \"/v1/models\", RawQuery: \"\"}) }\n"},
		{name: "ignored_error", source: fixturePreamble + "func TestReplay(t *testing.T) { bundle, _ := sourcefixture.FindBundle(\"\", \"writer\", \"model\", \"authorized_first_page\"); _ = sourcefixture.ValidateReplayContract(bundle, " + validContract + ") }\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(testPath, []byte(test.source), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := verifyReplayTest(root, bundle); !errors.Is(err, ErrReplayBinding) {
				t.Fatalf("verifyReplayTest() error = %v, want errors.Is(_, ErrReplayBinding)", err)
			}
		})
	}
	validSource := fixturePreamble + "func TestReplay(t *testing.T) { bundle, _ := sourcefixture.FindBundle(\"\", \"writer\", \"model\", \"authorized_first_page\"); sourcefixture.RequireReplayContract(t, bundle, " + validContract + ") }\n"
	if err := os.WriteFile(testPath, []byte(validSource), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyReplayTest(root, bundle); err != nil {
		t.Fatalf("verifyReplayTest(bound) error = %v", err)
	}
}

func TestReplayTestBindingsRejectCompileValidNegativeFixtures(t *testing.T) {
	payload, err := os.ReadFile("replay_binding_fixtures_test.go")
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{
		SourceID: "writer",
		Family:   "model",
		Case:     "authorized_first_page",
		Request:  Request{Method: http.MethodGet, URL: "https://api.writer.com/v1/models"},
	}
	for _, testName := range []string{
		"replayBindingIfFalse",
		"replayBindingBlankContract",
		"replayBindingWrongFamily",
		"replayBindingIgnoredError",
	} {
		t.Run(testName, func(t *testing.T) {
			foundFunction, foundBundle, foundContract, err := replayTestBindings(payload, testName, manifest)
			if err != nil {
				t.Fatal(err)
			}
			if !foundFunction || !foundBundle || foundContract {
				t.Fatalf("replayTestBindings() = function:%t bundle:%t contract:%t, want true, true, false", foundFunction, foundBundle, foundContract)
			}
		})
	}
}

func TestValidateOriginRejectsOperatorRequestUpstreamFields(t *testing.T) {
	for _, test := range []struct {
		name   string
		origin Origin
	}{
		{name: "repository", origin: Origin{Type: "operator_request", Repository: "https://example.test/repository"}},
		{name: "commit", origin: Origin{Type: "operator_request", Commit: strings.Repeat("a", 40)}},
		{name: "artifact", origin: Origin{Type: "operator_request", ArtifactSHA256: strings.Repeat("a", 64)}},
		{name: "locator", origin: Origin{Type: "operator_request", Locator: "provider-response-1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateOrigin(test.origin); err == nil {
				t.Fatal("validateOrigin() error = nil, want conflicting origin field rejection")
			}
		})
	}
}

func TestCanonicalRequestBodySHA256IsStableAcrossJSONFormatting(t *testing.T) {
	first, err := CanonicalRequestBodySHA256([]byte(`{"select":["id","name"],"limit":1}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalRequestBodySHA256([]byte("{\n  \"limit\": 1,\n  \"select\": [\"id\", \"name\"]\n}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(first) != 64 {
		t.Fatalf("request body digests = %q and %q, want identical SHA-256 values", first, second)
	}
	if _, err := CanonicalRequestBodySHA256([]byte(`{"limit":1}{"limit":2}`)); err == nil {
		t.Fatal("CanonicalRequestBodySHA256(multiple values) error = nil")
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
	commit := "00a" + strings.Repeat("1", 37)
	payload, err := CanonicalJSON([]byte(fmt.Sprintf(`{"commit":%q}`, commit)))
	if err != nil {
		t.Fatal(err)
	}
	if err := scanPayload(payload); err != nil {
		t.Fatalf("scanPayload(commit SHA) error = %v", err)
	}
}

func TestScanPayloadRejectsBase64EncodedProviderIdentifier(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("cursor,auth0|69e90a4415cfe76760975a99"))
	payload, err := CanonicalJSON([]byte(fmt.Sprintf(`{"next":%q}`, encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if err := scanPayload(payload); !errors.Is(err, ErrProviderID) {
		t.Fatalf("scanPayload(base64 provider ID) error = %v, want errors.Is(_, ErrProviderID)", err)
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
