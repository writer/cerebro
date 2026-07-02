package connectorcatalog

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/connectordefinitions"
)

// ReviewReport is the repository-level maintenance view for the connector
// catalog. It turns validation output into promotion queues, cleanup actions,
// and review questions that can be published by CI without mutating catalog
// files.
type ReviewReport struct {
	Summary            ReviewSummary           `json:"summary"`
	PromotionQueues    []PromotionQueue        `json:"promotion_queues,omitempty"`
	FidelityQueue      []FidelityCandidate     `json:"fidelity_queue,omitempty"`
	RuntimeDepthQueue  []RuntimeDepthCandidate `json:"runtime_depth_queue,omitempty"`
	APIDiscoveryQueue  []APIDiscoveryCandidate `json:"api_discovery_queue,omitempty"`
	CleanupFindings    []ReviewFinding         `json:"cleanup_findings,omitempty"`
	Questions          []ReviewQuestion        `json:"questions,omitempty"`
	SourceReviews      []SourceReview          `json:"source_reviews,omitempty"`
	ProjectionCoverage []ProjectionCoverage    `json:"projection_coverage,omitempty"`
}

type ReviewSummary struct {
	Total                    int                  `json:"total"`
	Generateable             int                  `json:"generateable"`
	CatalogReady             int                  `json:"catalog_ready"`
	NeedsAuthExtension       int                  `json:"needs_auth_extension"`
	NeedsBespokeRuntime      int                  `json:"needs_bespoke_runtime"`
	FidelityBaselineScore    int                  `json:"fidelity_baseline_score"`
	HighFidelitySources      int                  `json:"high_fidelity_sources"`
	NeedsFidelityReview      int                  `json:"needs_fidelity_review"`
	RuntimeDepth             *RuntimeDepthSummary `json:"runtime_depth,omitempty"`
	ResourceFamilies         int                  `json:"resource_families"`
	ProjectedFamilies        int                  `json:"projected_families"`
	HighValueFamilies        int                  `json:"high_value_families"`
	CoverageDimensions       int                  `json:"coverage_dimensions"`
	ProjectionTemplates      int                  `json:"projection_templates"`
	SourcesWithProjection    int                  `json:"sources_with_projection"`
	SourcesWithProjectionGap int                  `json:"sources_with_projection_gap"`
	CleanupFindings          int                  `json:"cleanup_findings"`
	Questions                int                  `json:"questions"`
	ByStatus                 map[string]int       `json:"by_status,omitempty"`
	ByProjectionTemplate     map[string]int       `json:"by_projection_template,omitempty"`
}

type RuntimeDepthSummary struct {
	BaselineScore                    int `json:"baseline_score"`
	RuntimeBackedSources             int `json:"runtime_backed_sources"`
	ReferenceRuntimeSources          int `json:"reference_runtime_sources"`
	NeedsRuntimeDepth                int `json:"needs_runtime_depth"`
	SourcesWithReadFixtures          int `json:"sources_with_read_fixtures"`
	SourcesWithDiscoverFixtures      int `json:"sources_with_discover_fixtures"`
	NeedsProviderAPIDiscovery        int `json:"needs_provider_api_discovery"`
	SourcesWithProviderAPIContract   int `json:"sources_with_provider_api_contract"`
	SourcesWithProviderAPIMapping    int `json:"sources_with_provider_api_mapping"`
	SourcesWithRuntimeTransportMatch int `json:"sources_with_runtime_transport_match"`
	SourcesWithRuntimeFixtures       int `json:"sources_with_runtime_fixtures"`
	SourcesWithDeployManifest        int `json:"sources_with_deploy_manifest"`
	SourcesWithProjectorTests        int `json:"sources_with_projector_tests"`
}

type PromotionQueue struct {
	ID      string               `json:"id"`
	Label   string               `json:"label"`
	Count   int                  `json:"count"`
	Entries []PromotionCandidate `json:"entries,omitempty"`
}

type PromotionCandidate struct {
	SourceID    string `json:"source_id"`
	DisplayName string `json:"display_name,omitempty"`
	Path        string `json:"path,omitempty"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	NextAction  string `json:"next_action"`
}

type FidelityCandidate struct {
	SourceID    string   `json:"source_id"`
	DisplayName string   `json:"display_name,omitempty"`
	Path        string   `json:"path,omitempty"`
	Score       int      `json:"score"`
	Missing     []string `json:"missing,omitempty"`
	NextAction  string   `json:"next_action"`
}

type RuntimeDepthCandidate struct {
	SourceID    string   `json:"source_id"`
	DisplayName string   `json:"display_name,omitempty"`
	Path        string   `json:"path,omitempty"`
	PackagePath string   `json:"package_path,omitempty"`
	Score       int      `json:"score"`
	Missing     []string `json:"missing,omitempty"`
	NextAction  string   `json:"next_action"`
}

type APIDiscoveryCandidate struct {
	SourceID           string   `json:"source_id"`
	DisplayName        string   `json:"display_name,omitempty"`
	Path               string   `json:"path,omitempty"`
	PackagePath        string   `json:"package_path,omitempty"`
	RuntimeFamilies    []string `json:"runtime_families,omitempty"`
	MissingFamilies    []string `json:"missing_families,omitempty"`
	ExistingReferences []string `json:"existing_references,omitempty"`
	Transport          string   `json:"transport,omitempty"`
	Auth               string   `json:"auth,omitempty"`
	BaseURL            string   `json:"base_url,omitempty"`
	Endpoint           string   `json:"endpoint,omitempty"`
	SearchQueries      []string `json:"search_queries,omitempty"`
	NextAction         string   `json:"next_action"`
}

type ReviewFinding struct {
	Level      string `json:"level"`
	SourceID   string `json:"source_id,omitempty"`
	Path       string `json:"path,omitempty"`
	Category   string `json:"category"`
	Message    string `json:"message"`
	NextAction string `json:"next_action"`
}

type ReviewQuestion struct {
	ID         string `json:"id"`
	SourceID   string `json:"source_id,omitempty"`
	Path       string `json:"path,omitempty"`
	Category   string `json:"category"`
	Question   string `json:"question"`
	Answer     string `json:"answer"`
	NextAction string `json:"next_action"`
}

type SourceReview struct {
	SourceID           string `json:"source_id"`
	DisplayName        string `json:"display_name,omitempty"`
	Path               string `json:"path,omitempty"`
	Status             string `json:"status"`
	ClassifierOutput   string `json:"classifier_output,omitempty"`
	ResourceFamilies   int    `json:"resource_families"`
	ProjectedFamilies  int    `json:"projected_families"`
	HighValueFamilies  int    `json:"high_value_families"`
	CoverageDimensions int    `json:"coverage_dimensions"`
	SourceFidelityFields
	RuntimeDepthFields
	SourceFamilyReadinessFields
	ProjectionTemplates   []string `json:"projection_templates,omitempty"`
	PromotionQueue        string   `json:"promotion_queue,omitempty"`
	NextAction            string   `json:"next_action,omitempty"`
	ReviewQuestionCount   int      `json:"review_question_count"`
	CleanupFindingCount   int      `json:"cleanup_finding_count"`
	SourcegenDryRun       bool     `json:"sourcegen_dry_run,omitempty"`
	SourcegenError        string   `json:"sourcegen_error,omitempty"`
	VerificationPath      string   `json:"verification_path,omitempty"`
	ResourceFamilyIDs     []string `json:"resource_family_ids,omitempty"`
	ProjectionGapFamilies []string `json:"projection_gap_families,omitempty"`
}

type SourceFidelityFields struct {
	FidelityScore int      `json:"fidelity_score"`
	FidelityLevel string   `json:"fidelity_level,omitempty"`
	FidelityGaps  []string `json:"fidelity_gaps,omitempty"`
}

type RuntimeDepthFields struct {
	RuntimeDepthScore          int      `json:"runtime_depth_score,omitempty"`
	RuntimeDepthLevel          string   `json:"runtime_depth_level,omitempty"`
	RuntimeDepthGaps           []string `json:"runtime_depth_gaps,omitempty"`
	RuntimePackagePath         string   `json:"runtime_package_path,omitempty"`
	HasRuntimePackage          bool     `json:"has_runtime_package,omitempty"`
	HasRuntimeCatalog          bool     `json:"has_runtime_catalog,omitempty"`
	HasRuntimeImplementation   bool     `json:"has_runtime_implementation,omitempty"`
	HasRuntimeTests            bool     `json:"has_runtime_tests,omitempty"`
	HasRuntimeReadFixtures     bool     `json:"has_runtime_read_fixtures,omitempty"`
	HasRuntimeDiscoverFixtures bool     `json:"has_runtime_discover_fixtures,omitempty"`
	HasRuntimeFixtures         bool     `json:"has_runtime_fixtures,omitempty"`
	HasDeployManifest          bool     `json:"has_deploy_manifest,omitempty"`
	HasProjectorTests          bool     `json:"has_projector_tests,omitempty"`
	HasProviderAPIContract     bool     `json:"has_provider_api_contract,omitempty"`
	HasProviderAPIMapping      bool     `json:"has_provider_api_mapping,omitempty"`
	HasRuntimeTransportMatch   bool     `json:"has_runtime_transport_match,omitempty"`
	ProviderAPIReviewFields
	RuntimeFamilies []string `json:"runtime_families,omitempty"`
}

type ProviderAPIReviewFields struct {
	ProviderAPIStatus          string   `json:"provider_api_status,omitempty"`
	ProviderAPITransport       string   `json:"provider_api_transport,omitempty"`
	ProviderAPIAuth            string   `json:"provider_api_auth,omitempty"`
	ProviderAPIBaseURL         string   `json:"provider_api_base_url,omitempty"`
	ProviderAPIEndpoint        string   `json:"provider_api_endpoint,omitempty"`
	ProviderAPIReferences      []string `json:"provider_api_references,omitempty"`
	ProviderAPIMappedFamilies  []string `json:"provider_api_mapped_families,omitempty"`
	ProviderAPIMissingFamilies []string `json:"provider_api_missing_families,omitempty"`
}

type SourceFamilyReadinessFields struct {
	FamiliesWithEvents    int `json:"families_with_events"`
	FamiliesWithFieldMaps int `json:"families_with_field_maps"`
	FamiliesWithEvidence  int `json:"families_with_evidence"`
	FamiliesWithControls  int `json:"families_with_controls"`
	FamiliesWithScopes    int `json:"families_with_scopes"`
}

type ProjectionCoverage struct {
	Template string `json:"template"`
	Sources  int    `json:"sources"`
	Families int    `json:"families"`
}

const fidelityReviewThreshold = 90
const runtimeDepthReviewThreshold = 100

// ReviewAnalysis builds a deterministic maintenance report from a catalog
// analysis. It does not re-read files or run source generation.
func ReviewAnalysis(analysis Analysis) ReviewReport {
	return reviewAnalysis(analysis, nil, false)
}

// ReviewAnalysisWithRuntimeDepth builds a deterministic maintenance report and
// folds in source package evidence gathered from the repository checkout.
func ReviewAnalysisWithRuntimeDepth(analysis Analysis, runtimeInventory RuntimeDepthInventory) ReviewReport {
	return reviewAnalysis(analysis, runtimeInventory, true)
}

func reviewAnalysis(analysis Analysis, runtimeInventory RuntimeDepthInventory, includeRuntimeDepth bool) ReviewReport {
	review := ReviewReport{
		Summary: ReviewSummary{
			ByStatus:              map[string]int{},
			ByProjectionTemplate:  map[string]int{},
			FidelityBaselineScore: fidelityReviewThreshold,
		},
	}
	if includeRuntimeDepth {
		review.Summary.RuntimeDepth = &RuntimeDepthSummary{
			BaselineScore: runtimeDepthReviewThreshold,
		}
	}
	sourceIDs := map[string]Entry{}
	displayNames := map[string][]Entry{}
	templateSources := map[string]map[string]struct{}{}
	queueEntries := map[string][]PromotionCandidate{}
	findingsBySource := map[string]int{}
	questionsBySource := map[string]int{}

	for _, entry := range analysis.Entries {
		sourceID := strings.TrimSpace(entry.Definition.SourceID)
		if sourceID != "" {
			sourceIDs[sourceID] = entry
		}
		if key := normalizedDisplayName(entry.Definition.DisplayName); key != "" {
			displayNames[key] = append(displayNames[key], entry)
		}

		sourceReview := buildSourceReview(entry, runtimeInventory[entry.Definition.SourceID], includeRuntimeDepth)
		review.SourceReviews = append(review.SourceReviews, sourceReview)
		review.Summary.Total++
		review.Summary.ResourceFamilies += sourceReview.ResourceFamilies
		review.Summary.ProjectedFamilies += sourceReview.ProjectedFamilies
		review.Summary.HighValueFamilies += sourceReview.HighValueFamilies
		review.Summary.CoverageDimensions += sourceReview.CoverageDimensions
		review.Summary.ByStatus[entry.Status]++
		if sourceReview.FidelityScore >= fidelityReviewThreshold {
			review.Summary.HighFidelitySources++
		} else {
			review.Summary.NeedsFidelityReview++
			review.FidelityQueue = append(review.FidelityQueue, FidelityCandidate{
				SourceID:    sourceReview.SourceID,
				DisplayName: sourceReview.DisplayName,
				Path:        sourceReview.Path,
				Score:       sourceReview.FidelityScore,
				Missing:     append([]string(nil), sourceReview.FidelityGaps...),
				NextAction:  fidelityNextAction(),
			})
		}
		if includeRuntimeDepth {
			if sourceReview.HasRuntimePackage {
				review.Summary.RuntimeDepth.RuntimeBackedSources++
			}
			if sourceReview.RuntimeDepthScore >= runtimeDepthReviewThreshold {
				review.Summary.RuntimeDepth.ReferenceRuntimeSources++
			} else {
				review.Summary.RuntimeDepth.NeedsRuntimeDepth++
				review.RuntimeDepthQueue = append(review.RuntimeDepthQueue, RuntimeDepthCandidate{
					SourceID:    sourceReview.SourceID,
					DisplayName: sourceReview.DisplayName,
					Path:        sourceReview.Path,
					PackagePath: sourceReview.RuntimePackagePath,
					Score:       sourceReview.RuntimeDepthScore,
					Missing:     append([]string(nil), sourceReview.RuntimeDepthGaps...),
					NextAction:  runtimeDepthNextAction(),
				})
			}
			if sourceReview.HasRuntimeFixtures {
				review.Summary.RuntimeDepth.SourcesWithRuntimeFixtures++
			}
			if sourceReview.HasRuntimeReadFixtures {
				review.Summary.RuntimeDepth.SourcesWithReadFixtures++
			}
			if sourceReview.HasRuntimeDiscoverFixtures {
				review.Summary.RuntimeDepth.SourcesWithDiscoverFixtures++
			}
			if sourceReview.HasProviderAPIContract {
				review.Summary.RuntimeDepth.SourcesWithProviderAPIContract++
			}
			if sourceReview.HasProviderAPIMapping {
				review.Summary.RuntimeDepth.SourcesWithProviderAPIMapping++
			}
			if sourceReview.HasProviderAPIContract && sourceReview.HasRuntimeTransportMatch {
				review.Summary.RuntimeDepth.SourcesWithRuntimeTransportMatch++
			}
			if sourceReview.HasDeployManifest {
				review.Summary.RuntimeDepth.SourcesWithDeployManifest++
			}
			if sourceReview.HasProjectorTests {
				review.Summary.RuntimeDepth.SourcesWithProjectorTests++
			}
			if needsProviderAPIDiscovery(sourceReview) {
				review.Summary.RuntimeDepth.NeedsProviderAPIDiscovery++
				review.APIDiscoveryQueue = append(review.APIDiscoveryQueue, providerAPIDiscoveryCandidate(entry, sourceReview))
			}
		}
		if sourceReview.ProjectedFamilies > 0 {
			review.Summary.SourcesWithProjection++
		}
		if len(sourceReview.ProjectionGapFamilies) > 0 {
			review.Summary.SourcesWithProjectionGap++
		}
		for _, template := range sourceReview.ProjectionTemplates {
			review.Summary.ByProjectionTemplate[template] += countTemplateFamilies(entry, template)
			if templateSources[template] == nil {
				templateSources[template] = map[string]struct{}{}
			}
			templateSources[template][sourceID] = struct{}{}
		}

		queueID, candidate := promotionCandidate(entry, sourceReview)
		if queueID != "" {
			queueEntries[queueID] = append(queueEntries[queueID], candidate)
		}
		for _, question := range sourceQuestions(sourceReview, entry, includeRuntimeDepth) {
			review.Questions = append(review.Questions, question)
			questionsBySource[question.SourceID]++
		}
	}

	review.CleanupFindings = append(review.CleanupFindings, duplicateRootFindings(sourceIDs)...)
	review.CleanupFindings = append(review.CleanupFindings, duplicateDisplayNameFindings(displayNames)...)
	review.CleanupFindings = append(review.CleanupFindings, sourceIdentityFindings(analysis.Entries, sourceIDs)...)
	for _, finding := range review.CleanupFindings {
		findingsBySource[finding.SourceID]++
		review.Questions = append(review.Questions, cleanupQuestion(finding))
		questionsBySource[finding.SourceID]++
	}
	for i := range review.SourceReviews {
		sourceID := review.SourceReviews[i].SourceID
		review.SourceReviews[i].CleanupFindingCount = findingsBySource[sourceID]
		review.SourceReviews[i].ReviewQuestionCount = questionsBySource[sourceID]
	}

	review.PromotionQueues = promotionQueues(queueEntries)
	review.ProjectionCoverage = projectionCoverage(review.Summary.ByProjectionTemplate, templateSources)
	review.Summary.ProjectionTemplates = len(review.Summary.ByProjectionTemplate)
	review.Summary.CleanupFindings = len(review.CleanupFindings)
	review.Summary.Questions = len(review.Questions)
	review.Summary.Generateable = analysis.Summary.Generateable
	review.Summary.CatalogReady = analysis.Summary.CatalogReady
	review.Summary.NeedsAuthExtension = analysis.Summary.NeedsAuthExtension
	review.Summary.NeedsBespokeRuntime = analysis.Summary.NeedsBespokeRuntime
	sortReview(&review)
	return review
}

func buildSourceReview(entry Entry, runtimeDepth RuntimeDepth, includeRuntimeDepth bool) SourceReview {
	review := SourceReview{
		SourceID:          entry.Definition.SourceID,
		DisplayName:       entry.Definition.DisplayName,
		Path:              entry.Path,
		Status:            entry.Status,
		ClassifierOutput:  entry.ClassifierOutput,
		SourcegenDryRun:   entry.SourcegenDryRun,
		SourcegenError:    entry.SourcegenError,
		VerificationPath:  entry.VerificationPath,
		ResourceFamilyIDs: append([]string(nil), entry.ResourceFamilyIDs...),
	}
	templates := map[string]struct{}{}
	for _, family := range entry.Definition.ResourceFamilies {
		review.ResourceFamilies++
		if family.Projection != nil && strings.TrimSpace(family.Projection.Template) != "" {
			review.ProjectedFamilies++
			templates[strings.TrimSpace(family.Projection.Template)] = struct{}{}
		} else if strings.TrimSpace(family.ID) != "" {
			review.ProjectionGapFamilies = append(review.ProjectionGapFamilies, family.ID)
		}
		if familyHasHighValueCoverage(family) {
			review.HighValueFamilies++
		}
		review.CoverageDimensions += len(family.Coverage)
	}
	for template := range templates {
		review.ProjectionTemplates = append(review.ProjectionTemplates, template)
	}
	review.FidelityScore, review.FidelityGaps = sourceFidelity(entry)
	if review.FidelityScore >= fidelityReviewThreshold {
		review.FidelityLevel = "reference"
	} else {
		review.FidelityLevel = "needs_review"
	}
	review.FamiliesWithEvents = countFamilies(entry, familyHasEventContract)
	review.FamiliesWithFieldMaps = countFamilies(entry, familyHasProjectionFields)
	review.FamiliesWithEvidence = countFamilies(entry, familyHasCoverageEvidence)
	review.FamiliesWithControls = countFamilies(entry, familyHasCoverageControls)
	review.FamiliesWithScopes = countFamilies(entry, func(family connectordefinitions.ResourceFamily) bool {
		return familyHasScopeOption(entry.Definition.ScopeOptions, family.ID)
	})
	if includeRuntimeDepth {
		review.RuntimeDepthScore = runtimeDepth.Score
		review.RuntimeDepthGaps = append([]string(nil), runtimeDepth.Missing...)
		review.RuntimePackagePath = runtimeDepth.PackagePath
		review.HasRuntimePackage = runtimeDepth.HasSourcePackage
		review.HasRuntimeCatalog = runtimeDepth.HasSourceCatalog
		review.HasRuntimeImplementation = runtimeDepth.HasSourceImplementation
		review.HasRuntimeTests = runtimeDepth.HasSourceTests
		review.HasRuntimeReadFixtures = runtimeDepth.HasReadFixtures
		review.HasRuntimeDiscoverFixtures = runtimeDepth.HasDiscoverFixtures
		review.HasRuntimeFixtures = runtimeDepth.HasFixturePair
		review.HasDeployManifest = runtimeDepth.HasDeployManifest
		review.HasProjectorTests = runtimeDepth.HasProjectorTests
		review.HasProviderAPIContract = runtimeDepth.ProviderAPI.HasContract
		review.HasProviderAPIMapping = runtimeDepth.ProviderAPI.HasMapping
		review.HasRuntimeTransportMatch = runtimeDepth.ProviderAPI.HasRuntimeTransport
		review.ProviderAPIStatus = runtimeDepth.ProviderAPI.Status
		review.ProviderAPITransport = runtimeDepth.ProviderAPI.Transport
		review.ProviderAPIAuth = runtimeDepth.ProviderAPI.Auth
		review.ProviderAPIBaseURL = runtimeDepth.ProviderAPI.BaseURL
		review.ProviderAPIEndpoint = runtimeDepth.ProviderAPI.Endpoint
		review.ProviderAPIReferences = append([]string(nil), runtimeDepth.ProviderAPI.References...)
		review.ProviderAPIMappedFamilies = append([]string(nil), runtimeDepth.ProviderAPI.MappedFamilies...)
		review.ProviderAPIMissingFamilies = append([]string(nil), runtimeDepth.ProviderAPI.MissingFamilyMappings...)
		review.RuntimeFamilies = append([]string(nil), runtimeDepth.RuntimeFamilies...)
		switch {
		case review.RuntimeDepthScore >= runtimeDepthReviewThreshold:
			review.RuntimeDepthLevel = "reference_runtime"
		case review.HasRuntimePackage:
			review.RuntimeDepthLevel = "runtime_package"
		default:
			review.RuntimeDepthLevel = "catalog_only"
			if len(review.RuntimeDepthGaps) == 0 {
				review.RuntimeDepthGaps = []string{"runtime:source_package"}
			}
		}
	}
	sort.Strings(review.ProjectionTemplates)
	sort.Strings(review.ProjectionGapFamilies)
	sort.Strings(review.ProviderAPIReferences)
	sort.Strings(review.ProviderAPIMappedFamilies)
	sort.Strings(review.ProviderAPIMissingFamilies)
	sort.Strings(review.RuntimeFamilies)
	sort.Strings(review.RuntimeDepthGaps)
	review.PromotionQueue, review.NextAction = promotionQueueAndAction(entry, review)
	return review
}

func sourceQuestions(source SourceReview, entry Entry, includeRuntimeDepth bool) []ReviewQuestion {
	var questions []ReviewQuestion
	if source.ResourceFamilies > 0 {
		questions = append(questions, ReviewQuestion{
			ID:         questionID(source.SourceID, "graph_projection"),
			SourceID:   source.SourceID,
			Path:       source.Path,
			Category:   "graph_projection",
			Question:   fmt.Sprintf("Do %s resource families project into the graph items operators use?", displayName(source)),
			Answer:     fmt.Sprintf("%d of %d families project through %s.", source.ProjectedFamilies, source.ResourceFamilies, listOrNone(source.ProjectionTemplates)),
			NextAction: "Open the source detail data view after activation and confirm the projected graph items match the intended evidence and inventory use cases.",
		})
	}
	if len(source.ProjectionGapFamilies) > 0 {
		questions = append(questions, ReviewQuestion{
			ID:         questionID(source.SourceID, "projection_gap"),
			SourceID:   source.SourceID,
			Path:       source.Path,
			Category:   "projection_gap",
			Question:   "Which collected families should stay collection-only, and which need graph templates?",
			Answer:     "Families without graph templates: " + strings.Join(source.ProjectionGapFamilies, ", ") + ".",
			NextAction: "Add projection templates for graph-worthy families or mark the family as intentionally collection-only in the source review notes.",
		})
	}
	if source.HighValueFamilies == 0 {
		questions = append(questions, ReviewQuestion{
			ID:         questionID(source.SourceID, "coverage_value"),
			SourceID:   source.SourceID,
			Path:       source.Path,
			Category:   "coverage_value",
			Question:   "Which collected family carries the highest evidence value?",
			Answer:     "No resource family has high-value coverage in the catalog entry.",
			NextAction: "Mark the primary evidence or inventory family as high value and include evidence types plus control domains.",
		})
	}
	familiesWithoutCoverage := 0
	for _, family := range entry.Definition.ResourceFamilies {
		if len(family.Coverage) == 0 {
			familiesWithoutCoverage++
		}
	}
	if familiesWithoutCoverage > 0 {
		questions = append(questions, ReviewQuestion{
			ID:         questionID(source.SourceID, "coverage_depth"),
			SourceID:   source.SourceID,
			Path:       source.Path,
			Category:   "coverage_depth",
			Question:   "Does every collected family explain why it matters?",
			Answer:     fmt.Sprintf("%d of %d families have no coverage dimensions.", familiesWithoutCoverage, source.ResourceFamilies),
			NextAction: "Add coverage dimensions for each family that should appear in evidence, inventory, access, or finding workflows.",
		})
	}
	if strings.HasPrefix(entry.Definition.Auth.Model, "oauth_") && len(entry.Definition.Auth.Scopes) == 0 {
		questions = append(questions, ReviewQuestion{
			ID:         questionID(source.SourceID, "oauth_scope"),
			SourceID:   source.SourceID,
			Path:       source.Path,
			Category:   "auth_scope",
			Question:   "Which OAuth scopes are required for read-only collection?",
			Answer:     "The auth model is " + entry.Definition.Auth.Model + " and the catalog entry does not list scopes.",
			NextAction: "Declare the narrow read scopes required for setup, or document why scopes are tenant-specific.",
		})
	}
	if source.PromotionQueue != "" {
		questions = append(questions, ReviewQuestion{
			ID:         questionID(source.SourceID, "promotion"),
			SourceID:   source.SourceID,
			Path:       source.Path,
			Category:   "promotion",
			Question:   "What is the next promotion step for this source?",
			Answer:     source.NextAction,
			NextAction: source.NextAction,
		})
	}
	if source.FidelityScore < fidelityReviewThreshold {
		questions = append(questions, ReviewQuestion{
			ID:         questionID(source.SourceID, "fidelity"),
			SourceID:   source.SourceID,
			Path:       source.Path,
			Category:   "fidelity",
			Question:   "Does this source meet the reference catalog depth baseline?",
			Answer:     fmt.Sprintf("Score %d of 100. Missing: %s.", source.FidelityScore, listOrNone(limitStrings(source.FidelityGaps, 8))),
			NextAction: fidelityNextAction(),
		})
	}
	if includeRuntimeDepth && source.RuntimeDepthScore < runtimeDepthReviewThreshold {
		questions = append(questions, ReviewQuestion{
			ID:         questionID(source.SourceID, "runtime_depth"),
			SourceID:   source.SourceID,
			Path:       source.Path,
			Category:   "runtime_depth",
			Question:   "Does this source have a source package at the reference runtime bar?",
			Answer:     fmt.Sprintf("Score %d of 100. Level: %s. Missing: %s.", source.RuntimeDepthScore, source.RuntimeDepthLevel, listOrNone(limitStrings(source.RuntimeDepthGaps, 8))),
			NextAction: runtimeDepthNextAction(),
		})
	}
	if includeRuntimeDepth && needsProviderAPIDiscovery(source) {
		questions = append(questions, ReviewQuestion{
			ID:         questionID(source.SourceID, "provider_api_discovery"),
			SourceID:   source.SourceID,
			Path:       source.Path,
			Category:   "provider_api_discovery",
			Question:   "Which provider-owned API source proves the runtime mappings?",
			Answer:     fmt.Sprintf("Missing provider API coverage for families: %s.", listOrNoFamilies(providerAPIMissingFamilies(source, entry))),
			NextAction: providerAPIDiscoveryNextAction(source.SourceID),
		})
	}
	return questions
}

func sourceFidelity(entry Entry) (int, []string) {
	definition := entry.Definition
	score := 0
	var missing []string
	if wordCount(definition.Description) >= 18 {
		score += 10
	} else {
		missing = append(missing, "source:description")
	}
	if sourceHasVerification(definition) {
		score += 10
	} else {
		missing = append(missing, "source:verification")
	}
	if sourceHasScopeOptions(definition) {
		score += 10
	} else {
		missing = append(missing, "source:scope_options")
	}

	familyScore := 0
	for _, family := range definition.ResourceFamilies {
		familyID := strings.TrimSpace(family.ID)
		if familyID == "" {
			familyID = "unnamed"
		}
		if familyHasRequestShape(family) {
			familyScore += 10
		} else {
			missing = append(missing, "family:"+familyID+":request_shape")
		}
		if familyHasEventContract(family) {
			familyScore += 15
		} else {
			missing = append(missing, "family:"+familyID+":event_contract")
		}
		if familyHasProjectionFields(family) {
			familyScore += 15
		} else {
			missing = append(missing, "family:"+familyID+":projection_mapping")
		}
		if familyHasCoverageEvidence(family) && familyHasCoverageControls(family) {
			familyScore += 20
		} else {
			missing = append(missing, "family:"+familyID+":coverage_context")
		}
		if familyHasCollectionShape(family) {
			familyScore += 10
		} else {
			missing = append(missing, "family:"+familyID+":collection_shape")
		}
	}
	if len(definition.ResourceFamilies) > 0 {
		score += familyScore / len(definition.ResourceFamilies)
	}
	return score, missing
}

func sourceHasVerification(definition connectordefinitions.Definition) bool {
	if definition.Transport == nil || definition.Transport.Verification == nil {
		return false
	}
	verification := definition.Transport.Verification
	return strings.TrimSpace(verification.Path) != "" && len(verification.ExpectStatus) > 0
}

func sourceHasScopeOptions(definition connectordefinitions.Definition) bool {
	if len(definition.ResourceFamilies) == 0 {
		return false
	}
	for _, family := range definition.ResourceFamilies {
		if !familyHasScopeOption(definition.ScopeOptions, family.ID) {
			return false
		}
	}
	return true
}

func familyHasScopeOption(options []connectordefinitions.ScopeOption, familyID string) bool {
	familyID = strings.TrimSpace(familyID)
	if familyID == "" {
		return false
	}
	for _, option := range options {
		for _, optionFamily := range option.Families {
			if strings.TrimSpace(optionFamily) == familyID {
				return true
			}
		}
	}
	return false
}

func familyHasRequestShape(family connectordefinitions.ResourceFamily) bool {
	return strings.TrimSpace(family.Path) != "" &&
		strings.TrimSpace(family.Method) != "" &&
		strings.TrimSpace(family.IDField) != "" &&
		(strings.TrimSpace(family.RecordSelector) != "" || strings.TrimSpace(family.ListKey) != "" || family.Singleton || family.Read != nil)
}

func familyHasEventContract(family connectordefinitions.ResourceFamily) bool {
	return strings.TrimSpace(family.Event.Kind) != "" &&
		strings.TrimSpace(family.Event.SchemaRef) != "" &&
		strings.TrimSpace(family.Event.URNKind) != "" &&
		len(family.Event.RequiredPayloadFields) > 0
}

func familyHasProjectionFields(family connectordefinitions.ResourceFamily) bool {
	if family.Projection == nil || strings.TrimSpace(family.Projection.Template) == "" {
		return false
	}
	return len(family.Projection.Fields) >= 2 || family.Projection.Entity != nil || len(family.Projection.Relationships) > 0
}

func familyHasCoverageEvidence(family connectordefinitions.ResourceFamily) bool {
	for _, dimension := range family.Coverage {
		if len(dimension.EvidenceTypes) > 0 {
			return true
		}
	}
	return false
}

func familyHasCoverageControls(family connectordefinitions.ResourceFamily) bool {
	for _, dimension := range family.Coverage {
		if len(dimension.ControlDomains) > 0 || len(dimension.ControlRefs) > 0 {
			return true
		}
	}
	return false
}

func familyHasCollectionShape(family connectordefinitions.ResourceFamily) bool {
	if family.Pagination != nil || family.Incremental != nil || family.Singleton {
		return true
	}
	return family.Read != nil && (family.Read.Singleton || strings.TrimSpace(family.Read.DetailPath) != "")
}

func countFamilies(entry Entry, predicate func(connectordefinitions.ResourceFamily) bool) int {
	count := 0
	for _, family := range entry.Definition.ResourceFamilies {
		if predicate(family) {
			count++
		}
	}
	return count
}

func wordCount(value string) int {
	return len(strings.Fields(value))
}

func fidelityNextAction() string {
	return "Raise the source to the reference connector baseline: add source verification, scope options, event schema fields, graph projection mappings, coverage evidence, control domains, and collection behavior for each family."
}

func runtimeDepthNextAction() string {
	return "Complete runtime depth: add a Source CDK package when missing, then add read and discover fixtures for every family, projector tests for every emitted kind, deploy manifest coverage, and source package validation."
}

func providerAPIDiscoveryNextAction(sourceID string) string {
	packagePath := "sources/" + strings.TrimSpace(sourceID)
	if strings.TrimSpace(sourceID) == "" {
		packagePath = "the source package"
	}
	return "Find a provider-owned API spec or reference, add provider_api status/auth/base_url/references under " + packagePath + "/catalog.yaml, and map every runtime family to the documented method/path or operation before adding fixtures."
}

func needsProviderAPIDiscovery(source SourceReview) bool {
	return !source.HasProviderAPIContract || !source.HasProviderAPIMapping
}

func providerAPIDiscoveryCandidate(entry Entry, source SourceReview) APIDiscoveryCandidate {
	families := providerAPIRuntimeFamilies(source, entry)
	missingFamilies := providerAPIMissingFamilies(source, entry)
	baseURL := strings.TrimSpace(source.ProviderAPIBaseURL)
	if baseURL == "" && entry.Definition.Transport != nil {
		baseURL = strings.TrimSpace(entry.Definition.Transport.BaseURL)
	}
	auth := strings.TrimSpace(source.ProviderAPIAuth)
	if auth == "" {
		auth = strings.TrimSpace(entry.Definition.Auth.Model)
	}
	return APIDiscoveryCandidate{
		SourceID:           source.SourceID,
		DisplayName:        source.DisplayName,
		Path:               source.Path,
		PackagePath:        source.RuntimePackagePath,
		RuntimeFamilies:    families,
		MissingFamilies:    missingFamilies,
		ExistingReferences: append([]string(nil), source.ProviderAPIReferences...),
		Transport:          strings.TrimSpace(source.ProviderAPITransport),
		Auth:               auth,
		BaseURL:            baseURL,
		Endpoint:           strings.TrimSpace(source.ProviderAPIEndpoint),
		SearchQueries:      providerAPISearchQueries(entry, source, families),
		NextAction:         providerAPIDiscoveryNextAction(source.SourceID),
	}
}

func providerAPIMissingFamilies(source SourceReview, entry Entry) []string {
	if len(source.ProviderAPIMissingFamilies) > 0 {
		return append([]string(nil), source.ProviderAPIMissingFamilies...)
	}
	if !source.HasProviderAPIContract || !source.HasProviderAPIMapping {
		return providerAPIRuntimeFamilies(source, entry)
	}
	return nil
}

func providerAPIRuntimeFamilies(source SourceReview, entry Entry) []string {
	if len(source.RuntimeFamilies) > 0 {
		return append([]string(nil), source.RuntimeFamilies...)
	}
	if len(entry.ResourceFamilyIDs) > 0 {
		return append([]string(nil), entry.ResourceFamilyIDs...)
	}
	families := make([]string, 0, len(entry.Definition.ResourceFamilies))
	for _, family := range entry.Definition.ResourceFamilies {
		if id := strings.TrimSpace(family.ID); id != "" {
			families = append(families, id)
		}
	}
	sort.Strings(families)
	return families
}

func providerAPISearchQueries(entry Entry, source SourceReview, families []string) []string {
	display := strings.TrimSpace(entry.Definition.DisplayName)
	if display == "" {
		display = displayName(source)
	}
	sourceID := strings.TrimSpace(entry.Definition.SourceID)
	if sourceID == "" {
		sourceID = strings.TrimSpace(source.SourceID)
	}
	familyHint := strings.Join(limitSearchTerms(families, 4), " ")
	values := []string{
		"gh search code " + shellQuote(display+" openapi") + " --filename openapi.yaml --limit 20",
		"gh search code " + shellQuote(display+" openapi") + " --filename openapi.json --limit 20",
		"gh search code " + shellQuote(display+" swagger") + " --limit 20",
		"gh search repos " + shellQuote(display+" api sdk") + " --limit 20",
	}
	if sourceID != "" && sourceID != normalizedDisplayName(display) {
		values = append(values,
			"gh search code "+shellQuote(sourceID+" openapi")+" --limit 20",
			"gh search repos "+shellQuote(sourceID+" api sdk")+" --limit 20",
		)
	}
	if familyHint != "" {
		values = append(values, "web search: "+display+" API reference "+familyHint)
	} else {
		values = append(values, "web search: "+display+" API reference")
	}
	return normalizedOrderedList(values)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func normalizedOrderedList(values []string) []string {
	seen := map[string]struct{}{}
	ordered := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		ordered = append(ordered, value)
	}
	return ordered
}

func familyHasHighValueCoverage(family connectordefinitions.ResourceFamily) bool {
	for _, dimension := range family.Coverage {
		if dimension.HighValue {
			return true
		}
	}
	return false
}

func countTemplateFamilies(entry Entry, template string) int {
	count := 0
	for _, family := range entry.Definition.ResourceFamilies {
		if family.Projection != nil && strings.TrimSpace(family.Projection.Template) == template {
			count++
		}
	}
	return count
}

func promotionCandidate(entry Entry, source SourceReview) (string, PromotionCandidate) {
	queueID, nextAction := promotionQueueAndAction(entry, source)
	if queueID == "" {
		return "", PromotionCandidate{}
	}
	return queueID, PromotionCandidate{
		SourceID:    entry.Definition.SourceID,
		DisplayName: entry.Definition.DisplayName,
		Path:        entry.Path,
		Status:      entry.Status,
		Reason:      promotionReason(entry),
		NextAction:  nextAction,
	}
}

func promotionQueueAndAction(entry Entry, source SourceReview) (string, string) {
	switch entry.Status {
	case StatusGenerateable:
		if source.HasRuntimePackage {
			if source.RuntimeDepthScore >= runtimeDepthReviewThreshold {
				return "", "Reference runtime package is present."
			}
			return "runtime_depth", runtimeDepthNextAction()
		}
		return "sourcegen_ready", "Generate the runtime package, add source package fixtures, then enable setup when runtime validation passes."
	case StatusNeedsAuthExtension:
		return "auth_extension", "Add or select the auth adapter required by this provider, then rerun sourcegen and catalog checks."
	case StatusNeedsBespokeRuntime:
		return "bespoke_runtime", "Plan a bespoke runtime or trim unsupported transport and projection features before promotion."
	case StatusCatalogReady:
		return "catalog_ready", "Keep the catalog entry reviewed and promote after sourcegen support is available."
	default:
		return "review", "Review classifier status and decide whether this source belongs in the catalog."
	}
}

func promotionReason(entry Entry) string {
	if entry.SourcegenError != "" {
		return entry.SourcegenError
	}
	switch entry.Status {
	case StatusGenerateable:
		return "Sourcegen dry run passed."
	case StatusNeedsAuthExtension:
		return "Classifier or sourcegen requires auth support before runtime generation."
	case StatusNeedsBespokeRuntime:
		return "Transport, pagination, projection, or runtime behavior exceeds the generic engine."
	default:
		return "Cataloged but not yet runtime-promoted."
	}
}

func promotionQueues(entries map[string][]PromotionCandidate) []PromotionQueue {
	labels := map[string]string{
		"sourcegen_ready": "Sourcegen ready",
		"runtime_depth":   "Needs runtime depth",
		"auth_extension":  "Needs auth extension",
		"bespoke_runtime": "Needs bespoke runtime",
		"catalog_ready":   "Catalog ready",
		"review":          "Needs review",
	}
	order := []string{"sourcegen_ready", "runtime_depth", "auth_extension", "bespoke_runtime", "catalog_ready", "review"}
	queues := make([]PromotionQueue, 0, len(entries))
	for _, id := range order {
		candidates := entries[id]
		if len(candidates) == 0 {
			continue
		}
		sort.SliceStable(candidates, func(i int, j int) bool {
			return candidates[i].SourceID < candidates[j].SourceID
		})
		queues = append(queues, PromotionQueue{
			ID:      id,
			Label:   labels[id],
			Count:   len(candidates),
			Entries: candidates,
		})
	}
	return queues
}

func duplicateRootFindings(sourceIDs map[string]Entry) []ReviewFinding {
	var findings []ReviewFinding
	for sourceID, entry := range sourceIDs {
		root, ok := sourceIDSuffixRoot(sourceID)
		if !ok {
			continue
		}
		if _, exists := sourceIDs[root]; !exists {
			continue
		}
		findings = append(findings, ReviewFinding{
			Level:      "action",
			SourceID:   sourceID,
			Path:       entry.Path,
			Category:   "source_id_cleanup",
			Message:    fmt.Sprintf("source_id %q shares provider root %q with an existing connector", sourceID, root),
			NextAction: "Consolidate under the existing provider connector unless this file represents a distinct product surface with separate auth and data ownership.",
		})
	}
	return findings
}

func duplicateDisplayNameFindings(displayNames map[string][]Entry) []ReviewFinding {
	var findings []ReviewFinding
	for _, entries := range displayNames {
		if len(entries) < 2 {
			continue
		}
		sort.SliceStable(entries, func(i int, j int) bool {
			return entries[i].Definition.SourceID < entries[j].Definition.SourceID
		})
		ids := make([]string, 0, len(entries))
		for _, entry := range entries {
			ids = append(ids, entry.Definition.SourceID)
		}
		for _, entry := range entries {
			findings = append(findings, ReviewFinding{
				Level:      "question",
				SourceID:   entry.Definition.SourceID,
				Path:       entry.Path,
				Category:   "display_name_cleanup",
				Message:    fmt.Sprintf("display name %q is shared by source IDs: %s", entry.Definition.DisplayName, strings.Join(ids, ", ")),
				NextAction: "Confirm these are distinct products. Rename variants or consolidate duplicate catalog entries.",
			})
		}
	}
	return findings
}

func sourceIdentityFindings(entries []Entry, sourceIDs map[string]Entry) []ReviewFinding {
	var findings []ReviewFinding
	for _, entry := range entries {
		sourceID := strings.TrimSpace(entry.Definition.SourceID)
		displayName := strings.TrimSpace(entry.Definition.DisplayName)
		if sourceIDLooksDomainQualified(sourceID, displayName) {
			hasRootConnector := false
			if root, ok := sourceIDSuffixRoot(sourceID); ok {
				if _, exists := sourceIDs[root]; exists {
					hasRootConnector = true
				}
			}
			if !hasRootConnector {
				findings = append(findings, ReviewFinding{
					Level:      "action",
					SourceID:   sourceID,
					Path:       entry.Path,
					Category:   "source_id_cleanup",
					Message:    fmt.Sprintf("source_id %q looks like a scraped domain instead of the product connector key", sourceID),
					NextAction: "Use the product connector key unless the product brand includes the domain suffix and the display name uses that brand.",
				})
			}
		}
		if displayNameLooksLikeDocs(displayName) {
			findings = append(findings, ReviewFinding{
				Level:      "action",
				SourceID:   sourceID,
				Path:       entry.Path,
				Category:   "display_name_cleanup",
				Message:    fmt.Sprintf("display name %q looks like an API documentation title instead of a product name", displayName),
				NextAction: "Rename the source to the product name users select during setup.",
			})
		}
	}
	return findings
}

func cleanupQuestion(finding ReviewFinding) ReviewQuestion {
	return ReviewQuestion{
		ID:         questionID(finding.SourceID, finding.Category, cleanupQuestionFingerprint(finding)),
		SourceID:   finding.SourceID,
		Path:       finding.Path,
		Category:   finding.Category,
		Question:   "Should this catalog entry remain separate?",
		Answer:     finding.Message,
		NextAction: finding.NextAction,
	}
}

func cleanupQuestionFingerprint(finding ReviewFinding) string {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(finding.Message))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(finding.NextAction))
	return fmt.Sprintf("%08x", hash.Sum32())
}

func projectionCoverage(familyCounts map[string]int, sources map[string]map[string]struct{}) []ProjectionCoverage {
	coverage := make([]ProjectionCoverage, 0, len(familyCounts))
	for template, families := range familyCounts {
		coverage = append(coverage, ProjectionCoverage{
			Template: template,
			Sources:  len(sources[template]),
			Families: families,
		})
	}
	sort.SliceStable(coverage, func(i int, j int) bool {
		if coverage[i].Families != coverage[j].Families {
			return coverage[i].Families > coverage[j].Families
		}
		return coverage[i].Template < coverage[j].Template
	})
	return coverage
}

func sortReview(review *ReviewReport) {
	sort.SliceStable(review.FidelityQueue, func(i int, j int) bool {
		if review.FidelityQueue[i].Score != review.FidelityQueue[j].Score {
			return review.FidelityQueue[i].Score < review.FidelityQueue[j].Score
		}
		return review.FidelityQueue[i].SourceID < review.FidelityQueue[j].SourceID
	})
	sort.SliceStable(review.RuntimeDepthQueue, func(i int, j int) bool {
		if review.RuntimeDepthQueue[i].Score != review.RuntimeDepthQueue[j].Score {
			return review.RuntimeDepthQueue[i].Score < review.RuntimeDepthQueue[j].Score
		}
		return review.RuntimeDepthQueue[i].SourceID < review.RuntimeDepthQueue[j].SourceID
	})
	sort.SliceStable(review.APIDiscoveryQueue, func(i int, j int) bool {
		if len(review.APIDiscoveryQueue[i].MissingFamilies) != len(review.APIDiscoveryQueue[j].MissingFamilies) {
			return len(review.APIDiscoveryQueue[i].MissingFamilies) > len(review.APIDiscoveryQueue[j].MissingFamilies)
		}
		return review.APIDiscoveryQueue[i].SourceID < review.APIDiscoveryQueue[j].SourceID
	})
	sort.SliceStable(review.CleanupFindings, func(i int, j int) bool {
		if review.CleanupFindings[i].SourceID != review.CleanupFindings[j].SourceID {
			return review.CleanupFindings[i].SourceID < review.CleanupFindings[j].SourceID
		}
		return review.CleanupFindings[i].Category < review.CleanupFindings[j].Category
	})
	sort.SliceStable(review.Questions, func(i int, j int) bool {
		if review.Questions[i].SourceID != review.Questions[j].SourceID {
			return review.Questions[i].SourceID < review.Questions[j].SourceID
		}
		if review.Questions[i].Category != review.Questions[j].Category {
			return review.Questions[i].Category < review.Questions[j].Category
		}
		return review.Questions[i].ID < review.Questions[j].ID
	})
	sort.SliceStable(review.SourceReviews, func(i int, j int) bool {
		if review.SourceReviews[i].CleanupFindingCount != review.SourceReviews[j].CleanupFindingCount {
			return review.SourceReviews[i].CleanupFindingCount > review.SourceReviews[j].CleanupFindingCount
		}
		if review.SourceReviews[i].FidelityScore != review.SourceReviews[j].FidelityScore {
			return review.SourceReviews[i].FidelityScore < review.SourceReviews[j].FidelityScore
		}
		if review.SourceReviews[i].ProjectedFamilies != review.SourceReviews[j].ProjectedFamilies {
			return review.SourceReviews[i].ProjectedFamilies > review.SourceReviews[j].ProjectedFamilies
		}
		return review.SourceReviews[i].SourceID < review.SourceReviews[j].SourceID
	})
}

func sourceIDSuffixRoot(sourceID string) (string, bool) {
	for _, suffix := range []string{"_com", "_io", "_ai", "_app", "_cloud", "_net"} {
		if strings.HasSuffix(sourceID, suffix) && len(sourceID) > len(suffix) {
			return strings.TrimSuffix(sourceID, suffix), true
		}
	}
	return "", false
}

func sourceIDLooksDomainQualified(sourceID string, displayName string) bool {
	displayName = strings.ToLower(displayName)
	for _, suffix := range []string{"_com", "_io", "_app"} {
		if !strings.HasSuffix(sourceID, suffix) || len(sourceID) <= len(suffix) {
			continue
		}
		if strings.Contains(displayName, strings.Replace(suffix, "_", ".", 1)) {
			return false
		}
		return true
	}
	return false
}

func displayNameLooksLikeDocs(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	for _, marker := range []string{
		"api documentation",
		"api reference",
		"api specification",
		"developer documentation",
		"rest api",
		"swagger spec",
		"connect api",
		"merchant api",
		"management api",
		"project api",
		"gateway rest api",
		"apiv2",
		"api v2",
	} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func normalizedDisplayName(value string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(value) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func questionID(sourceID string, category string, suffixes ...string) string {
	parts := append([]string{sourceID, category}, suffixes...)
	id := strings.Trim(strings.ToLower(strings.Join(parts, "_")), "_")
	id = strings.NewReplacer(" ", "_", "-", "_", ".", "_", "/", "_").Replace(id)
	return id
}

func displayName(source SourceReview) string {
	if strings.TrimSpace(source.DisplayName) != "" {
		return source.DisplayName
	}
	return source.SourceID
}

func listOrNone(values []string) string {
	if len(values) == 0 {
		return "no graph templates"
	}
	return strings.Join(values, ", ")
}

func listOrNoFamilies(values []string) string {
	if len(values) == 0 {
		return "no runtime families"
	}
	return strings.Join(values, ", ")
}

func limitStrings(values []string, maxItems int) []string {
	if maxItems <= 0 || len(values) <= maxItems {
		return values
	}
	limited := append([]string(nil), values[:maxItems]...)
	limited = append(limited, fmt.Sprintf("%d more", len(values)-maxItems))
	return limited
}

func limitSearchTerms(values []string, maxItems int) []string {
	if maxItems <= 0 || len(values) <= maxItems {
		return append([]string(nil), values...)
	}
	return append([]string(nil), values[:maxItems]...)
}
