package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcegen"
)

func TestGeneratedProviderPilotsAreHighFidelity(t *testing.T) {
	root := t.TempDir()
	pilots := []struct {
		name       string
		auth       string
		method     string
		pagination *connectordefinitions.PaginationSpec
	}{
		{
			name: "bearer_cursor_pilot",
			auth: sourcegen.AuthModelBearerToken,
			pagination: &connectordefinitions.PaginationSpec{
				Type: "cursor", CursorParam: "after", CursorJSONPath: "$.paging.next",
			},
		},
		{
			name: "oauth_page_pilot",
			auth: sourcegen.AuthModelOAuthClientCredentials,
			pagination: &connectordefinitions.PaginationSpec{
				Type: "page", PageParam: "page", PageSizeParam: "per_page", StartPage: 1,
			},
		},
		{
			name:   "post_list_pilot",
			auth:   sourcegen.AuthModelBearerToken,
			method: "POST",
		},
	}
	for _, pilot := range pilots {
		t.Run(pilot.name, func(t *testing.T) {
			if _, err := sourcegen.GenerateDefinition(sourcegen.DefinitionRequest{
				Definition: providerPilotDefinition(pilot.name, pilot.auth, pilot.method, pilot.pagination),
				OutputDir:  root,
			}); err != nil {
				t.Fatalf("GenerateDefinition() error = %v", err)
			}
		})
	}

	result, err := buildReport(root)
	if err != nil {
		t.Fatalf("buildReport() error = %v", err)
	}
	for _, pilot := range pilots {
		source := sourceByID(t, result, pilot.name)
		if source.Score != 100 || source.Level != "reference" {
			t.Fatalf("%s fidelity = %d (%s), missing %#v", pilot.name, source.Score, source.Level, source.Missing)
		}
		if !source.IsGeneratedScaffold {
			t.Fatalf("%s was not recognized as sourcegen output", pilot.name)
		}
	}
}

func providerPilotDefinition(sourceID string, authModel string, method string, pagination *connectordefinitions.PaginationSpec) connectordefinitions.Definition {
	credentialFields := []connectordefinitions.Field{{Key: "token", Secret: true, ReferenceOnly: true}}
	auth := connectordefinitions.AuthSpec{Model: authModel, CredentialFields: credentialFields}
	if authModel == sourcegen.AuthModelOAuthClientCredentials {
		auth.TokenURL = "https://api." + sourceID + ".example/oauth/token"
		auth.CredentialFields = []connectordefinitions.Field{
			{Key: "client_id", ReferenceOnly: true},
			{Key: "client_secret", Secret: true, ReferenceOnly: true},
		}
	}
	providerFamilies := make([]connectordefinitions.ProviderAPIFamilySpec, 0, 2)
	resourceFamilies := make([]connectordefinitions.ResourceFamily, 0, 2)
	for _, family := range []string{"accounts", "users"} {
		path := "/v1/" + family
		providerFamilies = append(providerFamilies, connectordefinitions.ProviderAPIFamilySpec{ID: family, Method: firstNonEmpty(method, "GET"), Path: path})
		resourceFamilies = append(resourceFamilies, connectordefinitions.ResourceFamily{
			ID:             family,
			Path:           path,
			Method:         method,
			RecordSelector: "$.data[*]",
			IDField:        "id",
			NameField:      "name",
			Pagination:     pagination,
			Event: connectordefinitions.EventMappingSpec{
				Kind:      sourceID + "." + family,
				SchemaRef: sourceID + "/" + family + "/v1",
			},
			Projection: &connectordefinitions.ProjectionSpec{Template: "asset"},
			Coverage: []connectordefinitions.CoverageDimensionSpec{{
				ID:             family,
				Type:           "entity_family",
				Title:          strings.ToUpper(family[:1]) + family[1:],
				Families:       []string{family},
				Support:        "supported",
				HighValue:      true,
				EvidenceTypes:  []string{"asset_inventory"},
				ControlDomains: []string{"asset_inventory"},
				ControlRefs: []connectordefinitions.CoverageControlRefSpec{{
					FrameworkName: "SOC 2", ControlID: "CC7.2",
				}},
			}},
		})
	}
	return connectordefinitions.Definition{
		ID:          "builtin-" + sourceID,
		TenantID:    "builtin",
		SourceID:    sourceID,
		DisplayName: strings.ReplaceAll(sourceID, "_", " "),
		Auth:        auth,
		Transport: &connectordefinitions.TransportSpec{
			BaseURL:      "https://api." + sourceID + ".example",
			Verification: &connectordefinitions.VerificationSpec{Path: "/health"},
		},
		ProviderAPI: &connectordefinitions.ProviderAPISpec{
			Status:        "verified",
			Basis:         "provider_documentation",
			VerifiedAt:    "2026-07-14T00:00:00Z",
			Transport:     "rest",
			Auth:          authModel,
			AuthMechanics: authModel,
			BaseURL:       "https://api." + sourceID + ".example",
			References:    []string{"https://docs." + sourceID + ".example/api"},
			AuthEvidence:  []string{"https://docs." + sourceID + ".example/auth"},
			ScopeEvidence: []string{"https://docs." + sourceID + ".example/scopes"},
			Families:      providerFamilies,
		},
		ResourceFamilies: resourceFamilies,
	}
}

func TestBuildReportScoresProviderLikeSourceAboveGeneratedScaffold(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "provider", sourceFiles{
		Catalog: `
id: provider
emitted_kinds:
  - provider.audit
runtime_families:
  - audit
  - repositories
coverage_contract:
  owner_domain: source_runtime
  authority_domain: provider
  dimensions:
    - id: audit
      type: audit_event
      title: Audit events
      families: [audit]
      support: supported
      high_value: true
      evidence_types: [logging_configuration]
      control_domains: [logging_monitoring]
      control_refs:
        - framework_name: SOC 2
          control_id: CC7.2
event_contracts:
  - kind: provider.audit
    schema_ref: provider/audit/v1
`,
		Deploy: `
sourceId: provider
runtimes:
  - localId: audit
    config:
      family: audit
  - localId: repositories
    config:
      family: repositories
`,
		SourceGo: `package provider

func ReadWithCheckpoint() {}
func ProviderUnavailable() {}
`,
		SourceTestGo: `package provider

func TestNewFixtureReplaysEveryRuntimeFamily() {}
func TestLiveHTTP() { _ = "httptest.NewServer" }
func TestProviderUnavailable() {}
`,
		ReadFixtures: map[string]string{
			"audit":        `[{"payload":{"action":"repo.create","actor":"octocat"},"attributes":{"action":"repo.create"}}]`,
			"repositories": `[{"payload":{"id":1,"full_name":"provider/example"},"attributes":{"repository":"provider/example"}}]`,
		},
		DiscoverFixtures: []string{"audit", "repositories"},
	})
	writeSource(t, root, "generated", sourceFiles{
		Catalog: `
id: generated
emitted_kinds:
  - generated.users
runtime_families:
  - users
  - audit_events
coverage_contract:
  owner_domain: source_runtime
  authority_domain: generated
  dimensions:
    - id: users
      type: entity_family
      title: Users
      families: [users]
      support: partial
      high_value: true
      evidence_types: [source_snapshot]
      control_domains: [asset_inventory]
      notes:
        - Generated Source Runtime SDK mapping requires provider field review before certification.
event_contracts:
  - kind: generated.users
    schema_ref: generated/users/v1
`,
		Deploy: `
sourceId: generated
runtimes:
  - localId: users
    config:
      family: users
`,
		SourceGo: `package generated

import _ "github.com/writer/cerebro/sources/internal/jsonapi"
`,
		SourceTestGo: `package generated

func TestSourceCheckAndRead() { _ = "Record One"; _ = "httptest.NewServer" }
`,
		ReadFixtures: map[string]string{
			"users": `[{"payload":{"api_path":"/users","id":"source-generated-users-1","name":"Generated Users Fixture"},"attributes":{"family":"users"}}]`,
		},
		DiscoverFixtures: []string{"users"},
	})

	result, err := buildReport(root)
	if err != nil {
		t.Fatalf("buildReport() error = %v", err)
	}
	provider := sourceByID(t, result, "provider")
	generated := sourceByID(t, result, "generated")

	if provider.Score <= generated.Score {
		t.Fatalf("provider score %d <= generated score %d", provider.Score, generated.Score)
	}
	if provider.Level != "reference" {
		t.Fatalf("provider level = %q, want reference", provider.Level)
	}
	if generated.SyntheticReadFixtures != 1 || generated.ProviderLikeReadFixtures != 0 {
		t.Fatalf("generated fixture counts = synthetic %d provider-like %d", generated.SyntheticReadFixtures, generated.ProviderLikeReadFixtures)
	}
	if len(generated.BlockingCandidate) == 0 {
		t.Fatalf("generated blocking candidates empty: %#v", generated)
	}
}

func TestSyntheticFixtureDetectsGeneratedMarkers(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    bool
	}{
		{name: "api path", payload: `[{"payload":{"api_path":"/v1/users"}}]`, want: true},
		{name: "source id", payload: `[{"payload":{"id":"source-example-users-1"}}]`, want: true},
		{name: "fixture suffix", payload: `[{"payload":{"name":"Example Users Fixture"}}]`, want: true},
		{name: "contract metadata", payload: `[{"attributes":{"record_class":"asset"},"payload":{"id":123,"login":"octocat"}}]`, want: false},
		{name: "provider shaped", payload: `[{"payload":{"id":123,"login":"octocat"}}]`, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := syntheticFixture([]byte(test.payload)); got != test.want {
				t.Fatalf("syntheticFixture() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestScoreSourceNormalizesInapplicableCriteria(t *testing.T) {
	source := sourceReport{
		SourceID:                 "single_family",
		RuntimeFamilies:          1,
		ReadFixtures:             1,
		DiscoverFixtures:         1,
		ProviderLikeReadFixtures: 1,
		HasEveryFamilyTest:       true,
		CoverageDimensions:       1,
		CoverageWithControlRefs:  1,
		HasHTTPTest:              true,
	}

	scoreSource(&source)

	if source.Score != 100 || source.PossibleScore != 100 {
		t.Fatalf("score = %d/%d, want 100/100", source.Score, source.PossibleScore)
	}
	if level := fidelityLevel(source.Score); level != "reference" {
		t.Fatalf("level = %q, want reference", level)
	}
	for _, missing := range source.Missing {
		if strings.Contains(missing, "incremental") || strings.Contains(missing, "provider-unavailable") {
			t.Fatalf("missing includes inapplicable criterion %q: %#v", missing, source.Missing)
		}
	}
}

func TestHasCheckpointEvidenceDetectsCursorAssertions(t *testing.T) {
	root := t.TempDir()
	sourceRoot := filepath.Join(root, "sources", "provider")
	if err := os.MkdirAll(sourceRoot, 0o750); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	sourcePath := filepath.Join(sourceRoot, "source.go")
	testPath := filepath.Join(sourceRoot, "source_test.go")
	writeFileForTest(t, sourcePath, `package provider

func Read() {}
`)
	writeFileForTest(t, testPath, `package provider

func TestReadPaginatesWithDurableState() {
	_ = "NextCursor"
	_ = "Checkpoint"
	_ = "CursorOpaque"
}
`)

	if !hasCheckpointEvidence(testPath, sourcePath) {
		t.Fatalf("hasCheckpointEvidence() = false, want true for cursor/checkpoint assertions")
	}
	if fileContains(testPath, "ReadWithCheckpoint") {
		t.Fatalf("test fixture unexpectedly uses ReadWithCheckpoint")
	}
}

type sourceFiles struct {
	Catalog          string
	Deploy           string
	SourceGo         string
	SourceTestGo     string
	ReadFixtures     map[string]string
	DiscoverFixtures []string
}

func writeSource(t *testing.T, root string, name string, files sourceFiles) {
	t.Helper()
	sourceRoot := filepath.Join(root, "sources", name)
	if err := os.MkdirAll(filepath.Join(sourceRoot, "testdata"), 0o750); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	writeFileForTest(t, filepath.Join(sourceRoot, "catalog.yaml"), strings.TrimSpace(files.Catalog)+"\n")
	writeFileForTest(t, filepath.Join(sourceRoot, "deploy.yaml"), strings.TrimSpace(files.Deploy)+"\n")
	writeFileForTest(t, filepath.Join(sourceRoot, "source.go"), strings.TrimSpace(files.SourceGo)+"\n")
	writeFileForTest(t, filepath.Join(sourceRoot, "source_test.go"), strings.TrimSpace(files.SourceTestGo)+"\n")
	for family, payload := range files.ReadFixtures {
		writeFileForTest(t, filepath.Join(sourceRoot, "testdata", "read_"+family+".json"), payload+"\n")
	}
	for _, family := range files.DiscoverFixtures {
		writeFileForTest(t, filepath.Join(sourceRoot, "testdata", "discover_"+family+".json"), `["urn:cerebro:tenant:`+family+`:1"]`+"\n")
	}
}

func writeFileForTest(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func sourceByID(t *testing.T, result report, id string) sourceReport {
	t.Helper()
	for _, source := range result.Sources {
		if source.SourceID == id {
			return source
		}
	}
	t.Fatalf("source %q not found in %#v", id, result.Sources)
	return sourceReport{}
}
