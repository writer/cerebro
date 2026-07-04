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
emitted_kinds: [github.audit, github.code.repository]
runtime_families: [audit, repository]
provider_api:
  status: verified
  basis: detected
  verified_at: 2026-07-02T00:00:00Z
  transport: rest
  auth: github_app
  auth_mechanics: github_app_installation
  base_url: https://api.github.com
  spec_url: https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json
  spec_kind: openapi
  references:
    - https://docs.github.com/rest
    - https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json
  auth_evidence:
    - https://docs.github.com/apps/creating-github-apps/authenticating-with-a-github-app
  families:
    - id: audit
      method: GET
      path: /orgs/{org}/audit-log
    - id: repository
      method: GET
      path: /orgs/{org}/repos
coverage_contract:
  dimensions:
    - id: audit
      type: audit_event
event_contracts:
  - kind: github.audit
    schema_ref: github/audit/v1
  - kind: github.code.repository
    schema_ref: github/code_repository/v1
`)
	writeRuntimeDepthFile(t, root, "sources/github/source.go", "package github\n\nimport _ \"github.com/google/go-github/v66/github\"\n")
	writeRuntimeDepthFile(t, root, "sources/github/source_test.go", "package github\n")
	writeRuntimeDepthFile(t, root, "sources/github/deploy.yaml", "sourceId: github\n")
	writeRuntimeDepthFile(t, root, "sources/github/testdata/discover_audit.json", "[]")
	writeRuntimeDepthFile(t, root, "sources/github/testdata/read_audit.json", "[]")
	writeRuntimeDepthFile(t, root, "sources/github/testdata/discover_repository.json", "[]")
	writeRuntimeDepthFile(t, root, "sources/github/testdata/read_repository.json", "[]")
	writeRuntimeDepthFile(t, root, "internal/sourceprojection/github_test.go", `package sourceprojection

func TestProjectGitHubAudit(t *testing.T) {
	_ = struct{ SourceId, Kind string }{SourceId: "github", Kind: "github.audit"}
	_ = struct{ SourceId, Kind string }{SourceId: "github", Kind: "github.code.repository"}
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
	if !depth.HasSourcePackage || !depth.HasSourceCatalog || !depth.ProviderAPI.HasContract || !depth.ProviderAPI.HasMapping || !depth.ProviderAPI.HasRuntimeTransport || !depth.ProviderAPI.HasProof || !depth.HasSourceImplementation || !depth.HasSourceTests || !depth.HasFixturePair || !depth.HasDeployManifest || !depth.HasProjectorTests {
		t.Fatalf("runtime depth flags = %#v, want all reference-runtime flags", depth)
	}
	if depth.ProviderAPI.ProofScore != providerAPIProofThreshold || depth.ProviderAPI.ProofLevel != "verified" {
		t.Fatalf("provider API proof = %#v, want verified proof", depth.ProviderAPI)
	}
	if depth.ProviderAPI.BaseURL != "https://api.github.com" || !containsString(depth.ProviderAPI.References, "https://docs.github.com/rest") || !containsString(depth.ProviderAPI.MappedFamilies, "repository") {
		t.Fatalf("provider API details = %#v", depth.ProviderAPI)
	}
	if got := depth.PackagePath; got != "sources/github" {
		t.Fatalf("package path = %q, want sources/github", got)
	}
	for _, want := range []string{"github.audit", "github.code.repository"} {
		if !containsString(depth.ProjectedKinds, want) {
			t.Fatalf("projected kinds = %v, want %s", depth.ProjectedKinds, want)
		}
	}
}

func TestDiscoverRuntimeDepthRequiresDeclaredFamilyFixturesAndProjectorKinds(t *testing.T) {
	root := t.TempDir()
	writeRuntimeDepthFile(t, root, "sources/github/catalog.yaml", `
id: github
name: GitHub
emitted_kinds: [github.audit, github.code.repository]
families:
  - id: audit
  - id: repository
coverage_contract:
  dimensions:
    - id: audit
      type: audit_event
event_contracts:
  - kind: github.audit
    schema_ref: github/audit/v1
  - kind: github.code.repository
    schema_ref: github/code_repository/v1
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
	if depth.Score >= runtimeDepthReviewThreshold {
		t.Fatalf("runtime depth score = %d missing=%v, want below threshold", depth.Score, depth.Missing)
	}
	for _, want := range []string{
		"runtime:provider_api_contract",
		"runtime:provider_api_reference",
		"runtime:fixture_pair",
		"runtime:read_fixture:repository",
		"runtime:discover_fixture:repository",
		"runtime:projector_tests",
		"runtime:projector_kind:github.code.repository",
	} {
		if !containsString(depth.Missing, want) {
			t.Fatalf("missing = %v, want %s", depth.Missing, want)
		}
	}
	if !containsString(depth.RuntimeFamilies, "repository") {
		t.Fatalf("runtime families = %v, want repository from catalog families", depth.RuntimeFamilies)
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
	for _, want := range []string{"runtime:provider_api_contract", "runtime:provider_api_reference", "runtime:catalog_contracts", "runtime:deploy_manifest", "runtime:fixture_pair", "runtime:projector_tests", "runtime:source_tests"} {
		if !containsString(depth.Missing, want) {
			t.Fatalf("missing = %v, want %s", depth.Missing, want)
		}
	}
}

func TestDiscoverRuntimeDepthRejectsGraphQLProviderOnJSONRuntime(t *testing.T) {
	root := t.TempDir()
	writeRuntimeDepthFile(t, root, "sources/wiz/catalog.yaml", `
id: wiz
name: Wiz
emitted_kinds: [wiz.assets]
families:
  - id: assets
provider_api:
  status: verified
  transport: graphql
  auth: oauth_client_credentials
  endpoint: https://api.us1.app.wiz.io/graphql
  references:
    - https://docs.wiz.io
  families:
    - id: assets
      operation: CloudResources
coverage_contract:
  dimensions:
    - id: assets
      type: entity_family
event_contracts:
  - kind: wiz.assets
    schema_ref: wiz/assets/v1
`)
	writeRuntimeDepthFile(t, root, "sources/wiz/source.go", "package wiz\n\nimport _ \"github.com/writer/cerebro/sources/internal/jsonapi\"\n")
	writeRuntimeDepthFile(t, root, "sources/wiz/source_test.go", "package wiz\n")
	writeRuntimeDepthFile(t, root, "sources/wiz/deploy.yaml", "sourceId: wiz\n")
	writeRuntimeDepthFile(t, root, "sources/wiz/testdata/discover_assets.json", "[]")
	writeRuntimeDepthFile(t, root, "sources/wiz/testdata/read_assets.json", "[]")
	writeRuntimeDepthFile(t, root, "internal/sourceprojection/wiz_test.go", `package sourceprojection

func TestProjectWizAsset(t *testing.T) {
	_ = struct{ SourceId, Kind string }{SourceId: "wiz", Kind: "wiz.assets"}
}
`)

	inventory, err := DiscoverRuntimeDepth(root)
	if err != nil {
		t.Fatalf("DiscoverRuntimeDepth() error = %v", err)
	}
	depth := inventory["wiz"]
	if depth.Score >= runtimeDepthReviewThreshold {
		t.Fatalf("runtime depth score = %d missing=%v, want below threshold", depth.Score, depth.Missing)
	}
	if !depth.ProviderAPI.HasContract || !depth.ProviderAPI.HasMapping {
		t.Fatalf("provider API flags = %#v, want contract and family mapping present", depth)
	}
	if depth.ProviderAPI.HasRuntimeTransport {
		t.Fatalf("runtime transport match = true, want graphql/jsonapi mismatch")
	}
	if !containsString(depth.Missing, "runtime:provider_api_transport_mismatch") {
		t.Fatalf("missing = %v, want provider API transport mismatch", depth.Missing)
	}
}

func TestDiscoverRuntimeDepthReadsProviderAPIDisproof(t *testing.T) {
	root := t.TempDir()
	writeRuntimeDepthFile(t, root, "sources/digitalocean/catalog.yaml", `
id: digitalocean
name: DigitalOcean
runtime_families: [droplets, teams, audit_events]
provider_api_disproof:
  status: invalidated
  reason: runtime_families_not_in_provider_spec
  checked_at: 2026-07-04T00:00:00Z
  references:
    - https://api-engineering.nyc3.digitaloceanspaces.com/spec-ci/DigitalOcean-public.v2.yaml
  affected_families:
    - teams
    - audit_events
  missing_paths:
    - /v2/teams
  notes:
    - The public v2 OpenAPI lists actions but not actor-scoped audit events.
coverage_contract:
  dimensions: []
`)
	writeRuntimeDepthFile(t, root, "sources/digitalocean/source.go", "package digitalocean\n")

	inventory, err := DiscoverRuntimeDepth(root)
	if err != nil {
		t.Fatalf("DiscoverRuntimeDepth() error = %v", err)
	}
	depth := inventory["digitalocean"]
	if !depth.ProviderAPI.HasDisproof {
		t.Fatalf("provider API disproof = %#v, want present", depth.ProviderAPI)
	}
	if depth.ProviderAPI.DisproofReason != "runtime_families_not_in_provider_spec" || depth.ProviderAPI.DisproofCheckedAt == "" {
		t.Fatalf("provider API disproof = %#v, want reason and checked timestamp", depth.ProviderAPI)
	}
	for _, want := range []string{"teams", "audit_events"} {
		if !containsString(depth.ProviderAPI.DisproofFamilies, want) {
			t.Fatalf("disproof families = %v, want %s", depth.ProviderAPI.DisproofFamilies, want)
		}
	}
	if !containsString(depth.ProviderAPI.DisproofMissingPaths, "/v2/teams") {
		t.Fatalf("disproof missing paths = %v, want /v2/teams", depth.ProviderAPI.DisproofMissingPaths)
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
	kinds := sourceKindsFromProjectorTest(`package sourceprojection

func TestProjectGRCAsset(t *testing.T) {
	_ = struct{ SourceId, Kind string }{SourceId: "grc", Kind: "grc.asset"}
	_ = "github.org"
	_ = struct{ EntityType string }{EntityType: "github.code.repository"}
}
`)
	if !containsString(kinds["grc"], "grc.asset") {
		t.Fatalf("source kinds = %#v, want grc.asset", kinds)
	}
	if _, ok := kinds["github"]; ok {
		t.Fatalf("source kinds = %#v, did not expect foreign graph entity kind", kinds)
	}
}

func TestSourceKindsFromProjectorTestFindsTableDrivenKinds(t *testing.T) {
	kinds := sourceKindsFromProjectorTest(`package sourceprojection

import cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"

func TestFivetranProviderFamiliesProjectToGraph(t *testing.T) {
	cases := []struct {
		name string
		kind string
	}{
		{name: "users", kind: "fivetran.users"},
		{name: "connections", kind: "fivetran.connections"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_ = &cerebrov1.EventEnvelope{SourceId: "fivetran", Kind: tt.kind}
		})
	}
}
`)

	for _, want := range []string{"fivetran.users", "fivetran.connections"} {
		if !containsString(kinds["fivetran"], want) {
			t.Fatalf("source kinds = %#v, want %s", kinds, want)
		}
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
