package archtests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRustOrganizationalPlatformBoundary(t *testing.T) {
	root := repoRoot(t)
	manifest := readText(t, filepath.Join(root, "Cargo.toml"))
	for _, member := range []string{
		"crates/organizational-model",
		"crates/organizational-store",
		"crates/source-catalog",
		"crates/organizational-graph",
		"crates/source-runtime-next",
		"crates/agent-context",
		"crates/cerebro-platform",
	} {
		if !strings.Contains(manifest, `"`+member+`"`) {
			t.Errorf("root Cargo workspace missing %q", member)
		}
	}

	modelSource := readText(t, filepath.Join(root, "crates/organizational-model/src/lib.rs"))
	if strings.Contains(modelSource, "use serde::Deserialize") ||
		strings.Contains(modelSource, "derive(Deserialize") {
		t.Error("validated organizational-model types must not implement or import Deserialize")
	}
	for _, required := range []string{
		"pub struct CanonicalIdentity",
		"pub struct ProviderIdentity",
		"pub struct IdentityBindingAssertion",
		"pub struct IdentityClaim",
		"GraphDeltaBuilder<Authoritative>",
		"IdentityResolutionMethod::ExistingClaimMatch",
		`EntityId::parse(format!("person:canonical:{id}"))`,
		"pub fn agent_key(&self) -> String",
	} {
		if !strings.Contains(modelSource, required) {
			t.Errorf("organizational model missing enforced construct %q", required)
		}
	}

	for _, directory := range []string{
		"crates/organizational-model",
		"crates/organizational-graph",
		"crates/organizational-store",
		"crates/source-catalog",
		"crates/source-runtime-next",
		"crates/agent-context",
		"crates/cerebro-platform",
	} {
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() && entry.Name() == "generated" {
				return filepath.SkipDir
			}
			if entry.IsDir() || filepath.Ext(path) != ".rs" {
				return nil
			}
			source := readText(t, path)
			for _, forbidden := range []string{
				"cerebrov1",
				"EventEnvelope",
				"ProjectedEntity",
				"ProjectedLink",
				"internal/sourceprojection",
			} {
				if strings.Contains(source, forbidden) {
					t.Errorf("%s depends on forbidden Go compatibility contract %q", filepath.ToSlash(path), forbidden)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan %s: %v", directory, err)
		}
	}

	storeSource := readText(t, filepath.Join(root, "crates/organizational-store/src/postgres.rs"))
	for _, required := range []string{
		"FORCE ROW LEVEL SECURITY",
		"PRIMARY KEY (tenant_id, provider_identity_id)",
		"PRIMARY KEY (tenant_id, claim_kind, claim_value)",
		"organizational_projection_outbox",
		"organizational_parity_receipts",
		"current_setting(''cerebro.tenant_id'', true)",
	} {
		if !strings.Contains(storeSource, required) {
			t.Errorf("organizational store missing enforced boundary %q", required)
		}
	}

	paritySource := readText(t, filepath.Join(root, "crates/organizational-store/src/parity.rs"))
	for _, required := range []string{
		"pub struct SemanticSnapshot",
		"pub struct ParityReceipt",
		"MAX_MISMATCHES_IN_RECEIPT",
		"ScopeMismatch",
	} {
		if !strings.Contains(paritySource, required) {
			t.Errorf("projection parity gate missing enforced boundary %q", required)
		}
	}

	catalogSource := readText(t, filepath.Join(root, "crates/source-catalog/src/lib.rs"))
	for _, required := range []string{
		"CollectionAuthority::Authoritative",
		"provider_api",
		"proof_is_complete",
		"ShadowOnly",
	} {
		if !strings.Contains(catalogSource, required) {
			t.Errorf("source catalog missing authority gate %q", required)
		}
	}

	doc := readText(t, filepath.Join(root, "docs/engineering/rust-organizational-platform.md"))
	for _, rule := range []string{
		"replacement architecture",
		"Only the Rust platform workload receives graph-write credentials",
		"Go deployments become read-only",
	} {
		if !strings.Contains(doc, rule) {
			t.Errorf("Rust organizational platform decision missing rule %q", rule)
		}
	}

	queryAdapter := readText(t, filepath.Join(root, "internal/sourcehttp/organizationalgraph/query.go"))
	for _, required := range []string{
		"NewOrganizationalGraphServiceClient",
		".ExpandBatch(ctx, request)",
		"rawCypher.ExecuteReadCypher",
		"ErrGraphTypedOperationRequired",
		"maxBatchRoots",
		"GetAgentKey",
	} {
		if !strings.Contains(queryAdapter, required) {
			t.Errorf("Rust graph read adapter missing enforced boundary %q", required)
		}
	}
	for _, forbidden := range []string{
		`"/v1/graph/expand"`,
		`"/v1/graph/expand-batch"`,
		"type rustNeighborhood struct",
		"type expandBatchRequest struct",
	} {
		if strings.Contains(queryAdapter, forbidden) {
			t.Errorf("Rust graph read adapter restored handwritten wire contract %q", forbidden)
		}
	}
	for _, forbidden := range []string{
		"NewShadowQueryStore",
		"NewLegacyQueryStore",
		"readModeShadow",
		"readModeLegacy",
		"RecordOrganizationalGraphShadow",
		"return legacy, nil",
	} {
		if strings.Contains(queryAdapter, forbidden) {
			t.Errorf("Rust graph read adapter retained removed compatibility mode %q", forbidden)
		}
	}

	for _, productionPath := range []string{
		"internal/bootstrap/compliance_impact_runtime.go",
		"internal/bootstrap/policy_candidates.go",
		"cmd/cerebro/orchestrator.go",
		"cmd/cerebro/finding_rule_graph_evaluate.go",
	} {
		source := readText(t, filepath.Join(root, filepath.FromSlash(productionPath)))
		if !strings.Contains(source, "dependencyGraphQueryStore(") {
			t.Errorf("%s bypasses configured Rust graph authority", productionPath)
		}
	}
	for _, bootstrapPath := range []string{
		"internal/bootstrap/compliance_impact_runtime.go",
		"internal/bootstrap/policy_candidates.go",
	} {
		source := readText(t, filepath.Join(root, filepath.FromSlash(bootstrapPath)))
		if strings.Contains(source, "deps.GraphStore.(ports.GraphQueryStore)") {
			t.Errorf("%s restored direct Go product-read authority", bootstrapPath)
		}
	}

	goNeo4jStore := readText(t, filepath.Join(root, "internal/graphstore/neo4j/store.go"))
	for _, removedTypedRead := range []string{
		"func (s *Store) GetEntityNeighborhood(",
		"func (s *Store) GetEntityNeighborhoods(",
	} {
		if strings.Contains(goNeo4jStore, removedTypedRead) {
			t.Errorf("Go Neo4j store retained removed typed read %q", removedTypedRead)
		}
	}
	for _, retained := range []string{
		"func (s *Store) ExecuteReadCypher(",
		"func (s *Store) ExplainReadCypher(",
	} {
		if !strings.Contains(goNeo4jStore, retained) {
			t.Errorf("Go Neo4j store removed raw-Cypher compatibility %q", retained)
		}
	}

	replacementWorkflow := readText(t, filepath.Join(root, ".github/workflows/rust-graph-replacement.yml"))
	for _, required := range []string{
		"name: Rust-only persisted product read",
		`- "crates/action-catalog/**"`,
		"--target replacement-test-runtime",
		"--entrypoint /usr/local/bin/organizational-graph-e2e",
		`receipt.json)" -eq 14`,
	} {
		if !strings.Contains(replacementWorkflow, required) {
			t.Errorf("Rust graph replacement workflow missing proof %q", required)
		}
	}
	for _, forbidden := range []string{
		"actions/setup-go",
		"make build-go",
		"go test",
		"./bin/cerebro serve",
		"CEREBRO_GRAPH_STORE_DRIVER",
		"CEREBRO_NEO4J_DATABASE",
	} {
		if strings.Contains(replacementWorkflow, forbidden) {
			t.Errorf("Rust graph replacement workflow restored non-Rust path %q", forbidden)
		}
	}

	rustImage := readText(t, filepath.Join(root, "Dockerfile.rust"))
	for _, required := range []string{
		"FROM runtime AS replacement-test-runtime",
		"/out/organizational-graph-e2e",
		"FROM runtime AS final",
	} {
		if !strings.Contains(rustImage, required) {
			t.Errorf("Rust replacement test image missing boundary %q", required)
		}
	}
}

func readText(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}
