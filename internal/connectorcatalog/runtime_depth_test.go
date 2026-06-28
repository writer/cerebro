package connectorcatalog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverRuntimeDepthScoresReferenceSourcePackage(t *testing.T) {
	root := t.TempDir()
	writeRuntimeDepthFile(t, root, "sources/github/catalog.yaml", `
id: github
name: GitHub
emitted_kinds: [github.audit]
runtime_families: [audit]
coverage_contract:
  dimensions:
    - id: audit
      type: audit_event
event_contracts:
  - kind: github.audit
    schema_ref: github/audit/v1
`)
	writeRuntimeDepthFile(t, root, "sources/github/source.go", "package github\n")
	writeRuntimeDepthFile(t, root, "sources/github/source_test.go", "package github\n")
	writeRuntimeDepthFile(t, root, "sources/github/deploy.yaml", "sourceId: github\n")
	writeRuntimeDepthFile(t, root, "sources/github/testdata/discover_audit.json", "[]")
	writeRuntimeDepthFile(t, root, "sources/github/testdata/read_audit.json", "[]")
	writeRuntimeDepthFile(t, root, "internal/sourceprojection/github_test.go", `package sourceprojection

func TestProjectGitHubAudit(t *testing.T) {
	_ = struct{ SourceId, Kind string }{SourceId: "github", Kind: "github.audit"}
}
`)

	inventory, err := DiscoverRuntimeDepth(root)
	if err != nil {
		t.Fatalf("DiscoverRuntimeDepth() error = %v", err)
	}
	depth := inventory["github"]
	if depth.Score != 100 {
		t.Fatalf("runtime depth score = %d missing=%v, want 100", depth.Score, depth.Missing)
	}
	if !depth.HasSourcePackage || !depth.HasSourceCatalog || !depth.HasSourceImplementation || !depth.HasSourceTests || !depth.HasFixturePair || !depth.HasDeployManifest || !depth.HasProjectorTests {
		t.Fatalf("runtime depth flags = %#v, want all reference-runtime flags", depth)
	}
	if got := depth.PackagePath; got != "sources/github" {
		t.Fatalf("package path = %q, want sources/github", got)
	}
}

func TestDiscoverRuntimeDepthQueuesPartialSourcePackage(t *testing.T) {
	root := t.TempDir()
	writeRuntimeDepthFile(t, root, "sources/example/catalog.yaml", `
id: example
name: Example
coverage_contract:
  dimensions: []
`)
	writeRuntimeDepthFile(t, root, "sources/example/source.go", "package example\n")

	inventory, err := DiscoverRuntimeDepth(root)
	if err != nil {
		t.Fatalf("DiscoverRuntimeDepth() error = %v", err)
	}
	depth := inventory["example"]
	if depth.Score >= runtimeDepthReviewThreshold {
		t.Fatalf("runtime depth score = %d missing=%v, want below threshold", depth.Score, depth.Missing)
	}
	for _, want := range []string{"runtime:catalog_contracts", "runtime:deploy_manifest", "runtime:fixture_pair", "runtime:projector_tests", "runtime:source_tests"} {
		if !containsString(depth.Missing, want) {
			t.Fatalf("missing = %v, want %s", depth.Missing, want)
		}
	}
}

func TestSourceIDsFromProjectorTestRequiresSourceEvent(t *testing.T) {
	got := sourceIDsFromProjectorTest(`package sourceprojection

import (
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestProjectGRCAsset(t *testing.T) {
	_ = &cerebrov1.EventEnvelope{SourceId: "grc", Kind: "grc.asset"}
	_ = "github.org"
	_ = "user@example.test"
	_ = "10.0.1.2"
	_ = ports.ProjectedEntity{EntityType: "github.code.repository"}
}
`)

	if !containsString(got, "grc") {
		t.Fatalf("source IDs = %v, want grc", got)
	}
	if containsString(got, "github") {
		t.Fatalf("source IDs = %v, did not expect foreign graph entity source", got)
	}
}

func writeRuntimeDepthFile(t *testing.T, root string, rel string, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
