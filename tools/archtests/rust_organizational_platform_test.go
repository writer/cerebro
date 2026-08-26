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
		"internal/bootstrap/policy_candidates.go",
		"cmd/cerebro/orchestrator.go",
		"cmd/cerebro/finding_rule_graph_evaluate.go",
	} {
		source := readText(t, filepath.Join(root, filepath.FromSlash(productionPath)))
		if !strings.Contains(source, ".GraphReads.RawCypher") {
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

	queryAdapterSource := readText(t, filepath.Join(root, "internal/sourcehttp/organizationalgraph/query.go"))
	for _, widenedRawCypherBoundary := range []string{
		"func NewQueryStore(rawCypher ports.GraphQueryStore",
		"func NewConfiguredQueryStore(rawCypher ports.GraphQueryStore",
	} {
		if strings.Contains(queryAdapterSource, widenedRawCypherBoundary) {
			t.Errorf("Rust graph query adapter widened raw-Cypher compatibility boundary %q", widenedRawCypherBoundary)
		}
	}
	knowledgeService := readText(t, filepath.Join(root, "internal/knowledge/service.go"))
	if strings.Contains(knowledgeService, "func New(query ports.RawCypherQueryStore") {
		t.Error("knowledge writer restored unused graph query dependency")
	}
	grcPolicyLifecycle := readText(t, filepath.Join(root, "internal/grcpolicylifecycle/lifecycle.go"))
	if strings.Contains(grcPolicyLifecycle, "func Build(ctx context.Context, store ports.GraphQueryStore") {
		t.Error("GRC policy lifecycle restored full graph query dependency")
	}
	reportService := readText(t, filepath.Join(root, "internal/reports/service.go"))
	if strings.Contains(reportService, "graphStore   ports.GraphQueryStore") {
		t.Error("reports service restored full graph query dependency")
	}
	complianceImpactGraph := readText(t, filepath.Join(root, "internal/complianceimpact/projected_graph.go"))
	complianceImpactBootstrap := readText(t, filepath.Join(root, "internal/bootstrap/compliance_impact_runtime.go"))
	for _, source := range []string{complianceImpactGraph, complianceImpactBootstrap} {
		if strings.Contains(source, "RawCypher") || strings.Contains(source, "ExecuteReadCypher") {
			t.Error("compliance impact restored retired raw-Cypher reads")
		}
	}
	policyCandidateService := readText(t, filepath.Join(root, "internal/policycandidate/service.go"))
	if strings.Contains(policyCandidateService, "Graph       ports.GraphQueryStore") {
		t.Error("policy candidate service restored full graph query dependency")
	}
	policyCandidateGrounding := readText(t, filepath.Join(root, "internal/policycandidate/grounding.go"))
	if strings.Contains(policyCandidateGrounding, "graph ports.GraphQueryStore") {
		t.Error("policy candidate grounding restored full graph query dependency")
	}
	findingsService := readText(t, filepath.Join(root, "internal/findings/service.go"))
	if strings.Contains(findingsService, "WithGraphQueryStore") || strings.Contains(findingsService, "graphQuery                ports.RawCypherQueryStore") {
		t.Error("findings service restored graph query naming for raw-Cypher dependency")
	}
	grcVendorService := readText(t, filepath.Join(root, "internal/grcvendor/service.go"))
	if strings.Contains(grcVendorService, "store ports.GraphQueryStore") {
		t.Error("GRC vendor service restored full graph query dependency")
	}
	mcpSource := readText(t, filepath.Join(root, "internal/bootstrap/mcp.go"))
	if strings.Contains(mcpSource, "fetchMCPGraphStoreNeighborhoods(ctx context.Context, graphStore ports.GraphQueryStore") {
		t.Error("MCP graph neighborhood helper restored full graph query dependency")
	}
	securityPathCapture := readText(t, filepath.Join(root, "internal/runtimeorchestration/security_path_capture.go"))
	if strings.Contains(securityPathCapture, "GraphQueries ports.GraphQueryStore") {
		t.Error("security path capture restored full graph query dependency")
	}
	if strings.Contains(securityPathCapture, "GraphQueries ports.RawCypherQueryStore") {
		t.Error("security path capture restored graph query naming for raw-Cypher dependency")
	}
	graphAgentValidator := readText(t, filepath.Join(root, "internal/graphagent/validator.go"))
	if strings.Contains(graphAgentValidator, "store   ports.GraphQueryStore") || strings.Contains(graphAgentValidator, "func NewValidator(store ports.GraphQueryStore") {
		t.Error("graph agent validator restored full graph query dependency")
	}
	graphAgentProbe := readText(t, filepath.Join(root, "internal/graphagent/probe.go"))
	if strings.Contains(graphAgentProbe, "func probeCounts(ctx context.Context, store ports.GraphQueryStore") {
		t.Error("graph agent probe counts restored full graph query dependency")
	}
	graphAgentAsk := readText(t, filepath.Join(root, "internal/graphagent/ask.go"))
	if strings.Contains(graphAgentAsk, "func scopedNeighborhood(ctx context.Context, store ports.GraphQueryStore") {
		t.Error("graph agent scoped neighborhood restored full graph query dependency")
	}
	if strings.Contains(graphAgentAsk, "store     ports.GraphQueryStore") {
		t.Error("graph agent service restored stored full graph query dependency")
	}
	if strings.Contains(graphAgentAsk, "func NewService(store ports.GraphQueryStore") || strings.Contains(graphAgentAsk, "func NewServiceWithOptions(store ports.GraphQueryStore") {
		t.Error("graph agent service restored full graph query constructor dependency")
	}

	graphQueryService := readText(t, filepath.Join(root, "internal/graphquery/service.go"))
	if strings.Contains(graphQueryService, "store ports.GraphQueryStore") || strings.Contains(graphQueryService, "func New(store ports.GraphQueryStore") {
		t.Error("graphquery service restored full graph query dependency")
	}
	bootstrapApp := readText(t, filepath.Join(root, "internal/bootstrap/app.go"))
	if strings.Contains(bootstrapApp, "ports.GraphQueryStore") {
		t.Error("bootstrap app restored transitional composite graph query dependency")
	}
	featureDependencies := readText(t, filepath.Join(root, "internal/bootstrap/feature_dependencies.go"))
	if strings.Contains(featureDependencies, "ports.GraphQueryStore") {
		t.Error("bootstrap feature dependencies restored transitional composite graph query dependency")
	}
	cerebroMain := readText(t, filepath.Join(root, "cmd/cerebro/main.go"))
	if strings.Contains(cerebroMain, "ports.GraphQueryStore") {
		t.Error("cerebro main restored transitional composite graph query dependency")
	}
	portsGraphQuery := readText(t, filepath.Join(root, "internal/ports/graphquery.go"))
	if strings.Contains(portsGraphQuery, "type GraphReadStore interface") {
		t.Error("ports restored aggregate graph read store interface")
	}
	if strings.Contains(bootstrapApp, "GraphQueries") || strings.Contains(bootstrapApp, "ports.GraphReadStore") {
		t.Error("bootstrap app restored aggregate graph read handle")
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
