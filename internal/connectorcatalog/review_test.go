package connectorcatalog

import (
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
)

func TestReviewAnalysisBuildsPromotionCleanupAndQuestions(t *testing.T) {
	analysis := Analysis{
		Summary: Summary{
			Total:              2,
			Generateable:       1,
			NeedsAuthExtension: 1,
		},
		Entries: []Entry{
			{
				Path:             "identity/azure.yaml",
				Status:           StatusGenerateable,
				ClassifierOutput: "supported",
				Generateable:     true,
				Definition: reviewDefinition("azure", "Azure", []connectordefinitions.ResourceFamily{
					reviewFamily("users", "identity_user", true),
					reviewFamily("groups", "identity_group", false),
				}),
			},
			{
				Path:             "identity/azure_com.yaml",
				Status:           StatusNeedsAuthExtension,
				ClassifierOutput: "supported",
				SourcegenError:   "auth model requires an extension",
				Definition: reviewDefinition("azure_com", "Azure REST API", []connectordefinitions.ResourceFamily{
					reviewFamily("users", "identity_user", true),
					{ID: "roles", Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "app_entitlement", Support: "partial"}}},
				}),
			},
		},
	}

	report := ReviewAnalysis(analysis)

	if report.Summary.ProjectedFamilies != 3 {
		t.Fatalf("projected families = %d, want 3", report.Summary.ProjectedFamilies)
	}
	if report.Summary.SourcesWithProjectionGap != 1 {
		t.Fatalf("sources with projection gap = %d, want 1", report.Summary.SourcesWithProjectionGap)
	}
	if !hasCleanupFinding(report, "azure_com", "source_id_cleanup") {
		t.Fatalf("cleanup findings = %#v, want azure_com source_id_cleanup", report.CleanupFindings)
	}
	if !hasCleanupFinding(report, "azure_com", "display_name_cleanup") {
		t.Fatalf("cleanup findings = %#v, want azure_com display_name_cleanup", report.CleanupFindings)
	}
	if !hasQueue(report, "sourcegen_ready", "azure") {
		t.Fatalf("promotion queues = %#v, want azure in sourcegen_ready", report.PromotionQueues)
	}
	if !hasQueue(report, "auth_extension", "azure_com") {
		t.Fatalf("promotion queues = %#v, want azure_com in auth_extension", report.PromotionQueues)
	}
	if !hasQuestion(report, "azure_com", "projection_gap") {
		t.Fatalf("questions = %#v, want azure_com projection_gap", report.Questions)
	}
	if !hasQuestion(report, "azure_com", "source_id_cleanup") {
		t.Fatalf("questions = %#v, want azure_com source_id_cleanup", report.Questions)
	}
}

func TestReviewAnalysisOmitsRuntimeDepthWithoutInventory(t *testing.T) {
	analysis := Analysis{
		Summary: Summary{Total: 1, Generateable: 1},
		Entries: []Entry{{
			Path:         "identity/catalog_only.yaml",
			Status:       StatusGenerateable,
			Generateable: true,
			Definition:   reviewDefinition("catalog_only", "Catalog Only", []connectordefinitions.ResourceFamily{reviewDetailedFamily("users", "identity_user")}),
		}},
	}

	report := ReviewAnalysis(analysis)

	if report.Summary.RuntimeDepth != nil {
		t.Fatalf("runtime depth summary = %#v, want nil without runtime inventory", report.Summary.RuntimeDepth)
	}
	if len(report.RuntimeDepthQueue) != 0 {
		t.Fatalf("runtime depth queue = %#v, want empty without runtime inventory", report.RuntimeDepthQueue)
	}
	if hasQuestion(report, "catalog_only", "runtime_depth") {
		t.Fatalf("questions = %#v, did not expect runtime_depth question without runtime inventory", report.Questions)
	}
}

func TestReviewAnalysisFlagsScrapedSourceIdentity(t *testing.T) {
	analysis := Analysis{
		Summary: Summary{Total: 2, Generateable: 2},
		Entries: []Entry{
			{
				Path:         "business/akeneo_com.yaml",
				Status:       StatusGenerateable,
				Generateable: true,
				Definition: reviewDefinition("akeneo_com", "Akeneo PIM REST API", []connectordefinitions.ResourceFamily{
					reviewDetailedFamily("products", "asset"),
				}),
			},
			{
				Path:         "business/monday_com.yaml",
				Status:       StatusGenerateable,
				Generateable: true,
				Definition: reviewDefinition("monday_com", "monday.com", []connectordefinitions.ResourceFamily{
					reviewDetailedFamily("boards", "asset"),
				}),
			},
		},
	}

	report := ReviewAnalysis(analysis)

	if !hasCleanupFinding(report, "akeneo_com", "source_id_cleanup") {
		t.Fatalf("cleanup findings = %#v, want akeneo_com source_id_cleanup", report.CleanupFindings)
	}
	if !hasCleanupFinding(report, "akeneo_com", "display_name_cleanup") {
		t.Fatalf("cleanup findings = %#v, want akeneo_com display_name_cleanup", report.CleanupFindings)
	}
	if hasCleanupFinding(report, "monday_com", "source_id_cleanup") {
		t.Fatalf("cleanup findings = %#v, did not expect monday.com source cleanup", report.CleanupFindings)
	}
}

func TestProviderAPISearchQueriesPreservePriorityOrder(t *testing.T) {
	entry := Entry{
		Definition: reviewDefinition("example_api", "Example API", nil),
	}
	queries := providerAPISearchQueries(entry, SourceReview{SourceID: "example_api"}, []string{"users", "roles"})
	if len(queries) == 0 {
		t.Fatal("queries = empty")
	}
	wantFirst := "gh search code 'Example API openapi' --filename openapi.yaml --limit 20"
	if queries[0] != wantFirst {
		t.Fatalf("first query = %q, want %q; queries = %#v", queries[0], wantFirst, queries)
	}
}

func TestProviderAPISearchQueriesTruncateFamilyHintsWithoutOverflowText(t *testing.T) {
	entry := Entry{
		Definition: reviewDefinition("example_api", "Example API", nil),
	}
	queries := providerAPISearchQueries(entry, SourceReview{SourceID: "example_api"}, []string{"users", "groups", "roles", "teams", "audit", "repos"})
	var webSearch string
	for _, query := range queries {
		if strings.HasPrefix(query, "web search: ") {
			webSearch = query
			break
		}
	}
	want := "web search: Example API API reference users groups roles teams"
	if webSearch != want {
		t.Fatalf("web search query = %q, want %q; queries = %#v", webSearch, want, queries)
	}
	if strings.Contains(webSearch, "more") {
		t.Fatalf("web search query included overflow text: %q", webSearch)
	}
}

func TestReviewAnalysisDisambiguatesOverlappingCleanupQuestions(t *testing.T) {
	analysis := Analysis{
		Summary: Summary{Total: 2, Generateable: 2},
		Entries: []Entry{
			{
				Path:         "business/acme_one.yaml",
				Status:       StatusGenerateable,
				Generateable: true,
				Definition: reviewDefinition("acme_one", "Acme REST API", []connectordefinitions.ResourceFamily{
					reviewDetailedFamily("records", "asset"),
				}),
			},
			{
				Path:         "business/acme_two.yaml",
				Status:       StatusGenerateable,
				Generateable: true,
				Definition: reviewDefinition("acme_two", "Acme REST API", []connectordefinitions.ResourceFamily{
					reviewDetailedFamily("records", "asset"),
				}),
			},
		},
	}

	report := ReviewAnalysis(analysis)

	questionIDs := map[string]struct{}{}
	displayCleanupQuestions := 0
	for _, question := range report.Questions {
		if question.SourceID != "acme_one" || question.Category != "display_name_cleanup" {
			continue
		}
		displayCleanupQuestions++
		if _, exists := questionIDs[question.ID]; exists {
			t.Fatalf("duplicate cleanup question ID %q in questions %#v", question.ID, report.Questions)
		}
		questionIDs[question.ID] = struct{}{}
	}
	if displayCleanupQuestions != 2 {
		t.Fatalf("display cleanup questions = %d, want 2; questions = %#v", displayCleanupQuestions, report.Questions)
	}
}

func TestRenderReviewMarkdownIncludesQueuesAndQA(t *testing.T) {
	report := ReviewReport{
		Summary: ReviewSummary{Total: 1, ProjectedFamilies: 1, Questions: 1},
		PromotionQueues: []PromotionQueue{{
			ID:    "sourcegen_ready",
			Label: "Sourcegen ready",
			Count: 1,
			Entries: []PromotionCandidate{{
				SourceID:   "okta",
				Status:     StatusGenerateable,
				NextAction: "Generate the runtime package.",
			}},
		}},
		FidelityQueue: []FidelityCandidate{{
			SourceID:   "okta",
			Score:      70,
			Missing:    []string{"family:users:event_contract"},
			NextAction: "Add event schema fields.",
		}},
		ProviderAPIProofQueue: []ProviderAPIProofCandidate{{
			SourceID:   "okta",
			Score:      85,
			Missing:    []string{"provider_api:verified_at"},
			SpecURL:    "https://developer.okta.com/openapi.yaml",
			NextAction: "Record provider API proof.",
		}},
		Questions: []ReviewQuestion{{
			SourceID:   "okta",
			Category:   "graph_projection",
			Question:   "Do users project?",
			Answer:     "1 of 1 families project through identity_user.",
			NextAction: "Open the source detail data view.",
		}},
	}

	markdown := RenderReviewMarkdown(report, 10)
	for _, want := range []string{"# Connector Catalog Review", "## Promotion Queues", "## Fidelity Queue", "family:users:event_contract", "## Provider API Proof Queue", "provider_api:verified_at", "## Review Q&A", "Do users project?"} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("markdown missing %q:\n%s", want, markdown)
		}
	}
}

func TestReviewAnalysisFlagsFamiliesWithoutCoverageIndividually(t *testing.T) {
	familyWithTwoCoverageDimensions := reviewFamily("users", "identity_user", true)
	familyWithTwoCoverageDimensions.Coverage = append(familyWithTwoCoverageDimensions.Coverage, connectordefinitions.CoverageDimensionSpec{
		Type:    "access",
		Support: "partial",
	})
	analysis := Analysis{
		Summary: Summary{Total: 1, Generateable: 1},
		Entries: []Entry{{
			Path:         "identity/example.yaml",
			Status:       StatusGenerateable,
			Generateable: true,
			Definition: reviewDefinition("example", "Example", []connectordefinitions.ResourceFamily{
				familyWithTwoCoverageDimensions,
				{ID: "groups", Projection: &connectordefinitions.ProjectionSpec{Template: "identity_group"}},
			}),
		}},
	}

	report := ReviewAnalysis(analysis)
	question, ok := questionFor(report, "example", "coverage_depth")
	if !ok {
		t.Fatalf("questions = %#v, want coverage_depth question", report.Questions)
	}
	if !strings.Contains(question.Answer, "1 of 2 families have no coverage dimensions") {
		t.Fatalf("coverage_depth answer = %q, want per-family gap count", question.Answer)
	}
}

func TestReviewAnalysisBuildsFidelityQueue(t *testing.T) {
	deepDefinition := reviewDefinition("deep", "Deep", []connectordefinitions.ResourceFamily{
		reviewDetailedFamily("users", "identity_user"),
		reviewDetailedFamily("groups", "identity_group"),
	})
	deepDefinition.Description = "Collects users and groups from Deep and projects them into the graph with evidence, inventory, access, and review context for operators."
	deepDefinition.ScopeOptions = []connectordefinitions.ScopeOption{
		{ID: "users", Label: "Users", Families: []string{"users"}, DefaultEnabled: true},
		{ID: "groups", Label: "Groups", Families: []string{"groups"}, DefaultEnabled: true},
	}
	deepDefinition.Transport.Verification.ExpectStatus = []int{200}
	shallowDefinition := reviewDefinition("shallow", "Shallow", []connectordefinitions.ResourceFamily{
		{ID: "records", Projection: &connectordefinitions.ProjectionSpec{Template: "asset"}},
	})
	analysis := Analysis{
		Summary: Summary{Total: 2, Generateable: 2},
		Entries: []Entry{
			{Path: "identity/deep.yaml", Status: StatusGenerateable, Generateable: true, Definition: deepDefinition},
			{Path: "identity/shallow.yaml", Status: StatusGenerateable, Generateable: true, Definition: shallowDefinition},
		},
	}

	report := ReviewAnalysis(analysis)

	if report.Summary.HighFidelitySources != 1 {
		t.Fatalf("high fidelity sources = %d, want 1", report.Summary.HighFidelitySources)
	}
	if report.Summary.NeedsFidelityReview != 1 {
		t.Fatalf("needs fidelity review = %d, want 1", report.Summary.NeedsFidelityReview)
	}
	if _, ok := fidelityFor(report, "deep"); ok {
		t.Fatalf("fidelity queue = %#v, did not expect deep source", report.FidelityQueue)
	}
	candidate, ok := fidelityFor(report, "shallow")
	if !ok {
		t.Fatalf("fidelity queue = %#v, want shallow source", report.FidelityQueue)
	}
	if candidate.Score >= report.Summary.FidelityBaselineScore {
		t.Fatalf("shallow score = %d, want below baseline %d", candidate.Score, report.Summary.FidelityBaselineScore)
	}
	if !hasQuestion(report, "shallow", "fidelity") {
		t.Fatalf("questions = %#v, want shallow fidelity question", report.Questions)
	}
}

func TestFamilyHasCollectionShapeAcceptsMapRecords(t *testing.T) {
	family := connectordefinitions.ResourceFamily{
		ID:   "columns",
		Path: "/v1/connections/{connection_id}/columns",
		Read: &connectordefinitions.ResourceReadSpec{
			MapRecords: map[string]string{"data.columns": "config"},
		},
	}
	if !familyHasCollectionShape(family) {
		t.Fatal("familyHasCollectionShape() = false, want true for map_records")
	}
}

func TestReviewAnalysisBuildsRuntimeDepthQueue(t *testing.T) {
	analysis := Analysis{
		Summary: Summary{Total: 3, Generateable: 3},
		Entries: []Entry{
			{
				Path:         "devops/github.yaml",
				Status:       StatusGenerateable,
				Generateable: true,
				Definition:   reviewDefinition("github", "GitHub", []connectordefinitions.ResourceFamily{reviewDetailedFamily("audit", "audit_event")}),
			},
			{
				Path:         "devops/generated.yaml",
				Status:       StatusGenerateable,
				Generateable: true,
				Definition:   reviewDefinition("generated", "Generated", []connectordefinitions.ResourceFamily{reviewDetailedFamily("users", "identity_user")}),
			},
			{
				Path:         "identity/catalog_only.yaml",
				Status:       StatusGenerateable,
				Generateable: true,
				Definition:   reviewDefinition("catalog_only", "Catalog Only", []connectordefinitions.ResourceFamily{reviewDetailedFamily("users", "identity_user")}),
			},
		},
	}
	inventory := RuntimeDepthInventory{
		"github": scoredRuntimeDepth(RuntimeDepth{
			SourceID:                "github",
			PackagePath:             "sources/github",
			HasSourcePackage:        true,
			HasSourceCatalog:        true,
			HasSourceImplementation: true,
			HasSourceTests:          true,
			HasReadFixtures:         true,
			HasDiscoverFixtures:     true,
			HasFixturePair:          true,
			HasDeployManifest:       true,
			HasProjectorTests:       true,
			HasEventContracts:       true,
			HasCoverageContract:     true,
			ProviderAPI: RuntimeProviderAPIDepth{
				HasContract:         true,
				HasMapping:          true,
				HasRuntimeTransport: true,
				HasProof:            true,
				ProofScore:          providerAPIProofThreshold,
				ProofLevel:          "verified",
				Status:              "verified",
				Transport:           "rest",
				Auth:                "github_app",
				BaseURL:             "https://api.github.com",
				References:          []string{"https://docs.github.com/rest"},
				MappedFamilies:      []string{"audit"},
			},
			RuntimeFamilies: []string{"audit"},
		}),
		"generated": scoredRuntimeDepth(RuntimeDepth{
			SourceID:                "generated",
			PackagePath:             "sources/generated",
			HasSourcePackage:        true,
			HasSourceCatalog:        true,
			HasSourceImplementation: true,
			HasSourceTests:          true,
			HasReadFixtures:         true,
			HasDeployManifest:       true,
			HasEventContracts:       true,
			HasCoverageContract:     true,
			ProviderAPI: RuntimeProviderAPIDepth{
				HasContract:         true,
				HasRuntimeTransport: true,
				ProofScore:          35,
				ProofLevel:          "needs_proof",
				ProofGaps:           []string{"provider_api:basis", "provider_api:machine_readable_spec"},
				Transport:           "rest",
			},
			RuntimeFamilies: []string{"users"},
		}),
	}

	report := ReviewAnalysisWithRuntimeDepth(analysis, inventory)

	if report.Summary.RuntimeDepth == nil {
		t.Fatal("runtime depth summary = nil, want runtime depth summary")
	}
	if report.Summary.RuntimeDepth.ReferenceRuntimeSources != 1 {
		t.Fatalf("reference runtime sources = %d, want 1", report.Summary.RuntimeDepth.ReferenceRuntimeSources)
	}
	if report.Summary.RuntimeDepth.NeedsRuntimeDepth != 2 {
		t.Fatalf("needs runtime depth = %d, want 2", report.Summary.RuntimeDepth.NeedsRuntimeDepth)
	}
	if report.Summary.RuntimeDepth.SourcesWithReadFixtures != 2 {
		t.Fatalf("sources with read fixtures = %d, want 2", report.Summary.RuntimeDepth.SourcesWithReadFixtures)
	}
	if report.Summary.RuntimeDepth.SourcesWithDiscoverFixtures != 1 {
		t.Fatalf("sources with discover fixtures = %d, want 1", report.Summary.RuntimeDepth.SourcesWithDiscoverFixtures)
	}
	if report.Summary.RuntimeDepth.SourcesWithRuntimeFixtures != 1 {
		t.Fatalf("sources with runtime fixture pairs = %d, want 1", report.Summary.RuntimeDepth.SourcesWithRuntimeFixtures)
	}
	if report.Summary.RuntimeDepth.SourcesWithProviderAPIProof != 1 {
		t.Fatalf("sources with provider API proof = %d, want 1", report.Summary.RuntimeDepth.SourcesWithProviderAPIProof)
	}
	if report.Summary.RuntimeDepth.NeedsProviderAPIProof != 1 {
		t.Fatalf("needs provider API proof = %d, want 1", report.Summary.RuntimeDepth.NeedsProviderAPIProof)
	}
	if _, ok := runtimeDepthFor(report, "github"); ok {
		t.Fatalf("runtime depth queue = %#v, did not expect github source", report.RuntimeDepthQueue)
	}
	if _, ok := runtimeDepthFor(report, "generated"); !ok {
		t.Fatalf("runtime depth queue = %#v, want generated source", report.RuntimeDepthQueue)
	}
	if _, ok := apiDiscoveryFor(report, "generated"); !ok {
		t.Fatalf("api discovery queue = %#v, want generated source", report.APIDiscoveryQueue)
	}
	if _, ok := apiProofFor(report, "generated"); !ok {
		t.Fatalf("provider API proof queue = %#v, want generated source", report.ProviderAPIProofQueue)
	}
	candidate, ok := runtimeDepthFor(report, "catalog_only")
	if !ok {
		t.Fatalf("runtime depth queue = %#v, want catalog_only source", report.RuntimeDepthQueue)
	}
	if !containsString(candidate.Missing, "runtime:source_package") {
		t.Fatalf("catalog_only missing = %v, want runtime:source_package", candidate.Missing)
	}
	if !hasQuestion(report, "catalog_only", "runtime_depth") {
		t.Fatalf("questions = %#v, want runtime_depth question", report.Questions)
	}
	if !hasQuestion(report, "catalog_only", "provider_api_discovery") {
		t.Fatalf("questions = %#v, want provider_api_discovery question", report.Questions)
	}
	if !hasQuestion(report, "generated", "provider_api_proof") {
		t.Fatalf("questions = %#v, want provider_api_proof question", report.Questions)
	}
	if !hasQueue(report, "runtime_depth", "generated") {
		t.Fatalf("promotion queues = %#v, want generated in runtime_depth queue", report.PromotionQueues)
	}
	if hasQueue(report, "sourcegen_ready", "generated") {
		t.Fatalf("promotion queues = %#v, did not expect generated in sourcegen_ready queue", report.PromotionQueues)
	}
	if hasQueue(report, "sourcegen_ready", "github") || hasQueue(report, "runtime_depth", "github") {
		t.Fatalf("promotion queues = %#v, did not expect reference runtime github in promotion queues", report.PromotionQueues)
	}
}

func scoredRuntimeDepth(depth RuntimeDepth) RuntimeDepth {
	depth.Score, depth.Missing = runtimeDepthScore(depth)
	return depth
}

func reviewDefinition(sourceID string, displayName string, families []connectordefinitions.ResourceFamily) connectordefinitions.Definition {
	return connectordefinitions.Definition{
		SourceID:         sourceID,
		DisplayName:      displayName,
		Runtime:          connectordefinitions.RuntimeJSONAPI,
		Auth:             connectordefinitions.AuthSpec{Model: "bearer_token"},
		Transport:        &connectordefinitions.TransportSpec{Verification: &connectordefinitions.VerificationSpec{Path: "/healthz"}},
		ResourceFamilies: families,
	}
}

func reviewDetailedFamily(id string, template string) connectordefinitions.ResourceFamily {
	return connectordefinitions.ResourceFamily{
		ID:             id,
		Label:          id,
		Path:           "/v1/" + id,
		Method:         "GET",
		RecordSelector: "$.data[*]",
		IDField:        "id",
		NameField:      "name",
		Event: connectordefinitions.EventMappingSpec{
			Kind:                  "deep." + id,
			SchemaRef:             "deep/" + id + "/v1",
			URNKind:               "deep_" + id,
			RequiredPayloadFields: []string{"id"},
		},
		Projection: &connectordefinitions.ProjectionSpec{
			Template: template,
			Fields: map[string]string{
				"id":   "id",
				"name": "name",
			},
		},
		Coverage: []connectordefinitions.CoverageDimensionSpec{{
			ID:             id,
			Type:           "entity_family",
			Title:          id,
			Families:       []string{id},
			Support:        "partial",
			HighValue:      true,
			EvidenceTypes:  []string{"source_snapshot"},
			ControlDomains: []string{"asset_inventory"},
		}},
		Pagination: &connectordefinitions.PaginationSpec{
			Type:           "cursor",
			CursorParam:    "cursor",
			CursorJSONPath: "$.next_cursor",
			PageSizeParam:  "limit",
			PageSize:       100,
		},
		DefaultEnabled: true,
	}
}

func reviewFamily(id string, template string, highValue bool) connectordefinitions.ResourceFamily {
	return connectordefinitions.ResourceFamily{
		ID: id,
		Projection: &connectordefinitions.ProjectionSpec{
			Template: template,
		},
		Coverage: []connectordefinitions.CoverageDimensionSpec{{
			Type:      "entity_family",
			Support:   "partial",
			HighValue: highValue,
		}},
	}
}

func hasCleanupFinding(report ReviewReport, sourceID string, category string) bool {
	for _, finding := range report.CleanupFindings {
		if finding.SourceID == sourceID && finding.Category == category {
			return true
		}
	}
	return false
}

func fidelityFor(report ReviewReport, sourceID string) (FidelityCandidate, bool) {
	for _, candidate := range report.FidelityQueue {
		if candidate.SourceID == sourceID {
			return candidate, true
		}
	}
	return FidelityCandidate{}, false
}

func runtimeDepthFor(report ReviewReport, sourceID string) (RuntimeDepthCandidate, bool) {
	for _, candidate := range report.RuntimeDepthQueue {
		if candidate.SourceID == sourceID {
			return candidate, true
		}
	}
	return RuntimeDepthCandidate{}, false
}

func apiDiscoveryFor(report ReviewReport, sourceID string) (APIDiscoveryCandidate, bool) {
	for _, candidate := range report.APIDiscoveryQueue {
		if candidate.SourceID == sourceID {
			return candidate, true
		}
	}
	return APIDiscoveryCandidate{}, false
}

func apiProofFor(report ReviewReport, sourceID string) (ProviderAPIProofCandidate, bool) {
	for _, candidate := range report.ProviderAPIProofQueue {
		if candidate.SourceID == sourceID {
			return candidate, true
		}
	}
	return ProviderAPIProofCandidate{}, false
}

func hasQueue(report ReviewReport, queueID string, sourceID string) bool {
	for _, queue := range report.PromotionQueues {
		if queue.ID != queueID {
			continue
		}
		for _, candidate := range queue.Entries {
			if candidate.SourceID == sourceID {
				return true
			}
		}
	}
	return false
}

func hasQuestion(report ReviewReport, sourceID string, category string) bool {
	_, ok := questionFor(report, sourceID, category)
	return ok
}

func questionFor(report ReviewReport, sourceID string, category string) (ReviewQuestion, bool) {
	for _, question := range report.Questions {
		if question.SourceID == sourceID && question.Category == category {
			return question, true
		}
	}
	return ReviewQuestion{}, false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
