package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
