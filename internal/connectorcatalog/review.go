package connectorcatalog

import (
	"fmt"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/connectordefinitions"
)

// ReviewReport is the repository-level maintenance view for the connector
// catalog. It turns validation output into promotion queues, cleanup actions,
// and review questions that can be published by CI without mutating catalog
// files.
type ReviewReport struct {
	Summary            ReviewSummary        `json:"summary"`
	PromotionQueues    []PromotionQueue     `json:"promotion_queues,omitempty"`
	CleanupFindings    []ReviewFinding      `json:"cleanup_findings,omitempty"`
	Questions          []ReviewQuestion     `json:"questions,omitempty"`
	SourceReviews      []SourceReview       `json:"source_reviews,omitempty"`
	ProjectionCoverage []ProjectionCoverage `json:"projection_coverage,omitempty"`
}

type ReviewSummary struct {
	Total                    int            `json:"total"`
	Generateable             int            `json:"generateable"`
	CatalogReady             int            `json:"catalog_ready"`
	NeedsAuthExtension       int            `json:"needs_auth_extension"`
	NeedsBespokeRuntime      int            `json:"needs_bespoke_runtime"`
	ResourceFamilies         int            `json:"resource_families"`
	ProjectedFamilies        int            `json:"projected_families"`
	HighValueFamilies        int            `json:"high_value_families"`
	CoverageDimensions       int            `json:"coverage_dimensions"`
	ProjectionTemplates      int            `json:"projection_templates"`
	SourcesWithProjection    int            `json:"sources_with_projection"`
	SourcesWithProjectionGap int            `json:"sources_with_projection_gap"`
	CleanupFindings          int            `json:"cleanup_findings"`
	Questions                int            `json:"questions"`
	ByStatus                 map[string]int `json:"by_status,omitempty"`
	ByProjectionTemplate     map[string]int `json:"by_projection_template,omitempty"`
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
	SourceID              string   `json:"source_id"`
	DisplayName           string   `json:"display_name,omitempty"`
	Path                  string   `json:"path,omitempty"`
	Status                string   `json:"status"`
	ClassifierOutput      string   `json:"classifier_output,omitempty"`
	ResourceFamilies      int      `json:"resource_families"`
	ProjectedFamilies     int      `json:"projected_families"`
	HighValueFamilies     int      `json:"high_value_families"`
	CoverageDimensions    int      `json:"coverage_dimensions"`
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

type ProjectionCoverage struct {
	Template string `json:"template"`
	Sources  int    `json:"sources"`
	Families int    `json:"families"`
}

// ReviewAnalysis builds a deterministic maintenance report from a catalog
// analysis. It does not re-read files or run source generation.
func ReviewAnalysis(analysis Analysis) ReviewReport {
	review := ReviewReport{
		Summary: ReviewSummary{
			ByStatus:             map[string]int{},
			ByProjectionTemplate: map[string]int{},
		},
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

		sourceReview := buildSourceReview(entry)
		review.SourceReviews = append(review.SourceReviews, sourceReview)
		review.Summary.Total++
		review.Summary.ResourceFamilies += sourceReview.ResourceFamilies
		review.Summary.ProjectedFamilies += sourceReview.ProjectedFamilies
		review.Summary.HighValueFamilies += sourceReview.HighValueFamilies
		review.Summary.CoverageDimensions += sourceReview.CoverageDimensions
		review.Summary.ByStatus[entry.Status]++
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

		queueID, candidate := promotionCandidate(entry)
		if queueID != "" {
			queueEntries[queueID] = append(queueEntries[queueID], candidate)
		}
		for _, question := range sourceQuestions(sourceReview, entry) {
			review.Questions = append(review.Questions, question)
			questionsBySource[question.SourceID]++
		}
	}

	review.CleanupFindings = append(review.CleanupFindings, duplicateRootFindings(sourceIDs)...)
	review.CleanupFindings = append(review.CleanupFindings, duplicateDisplayNameFindings(displayNames)...)
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

func buildSourceReview(entry Entry) SourceReview {
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
	sort.Strings(review.ProjectionTemplates)
	sort.Strings(review.ProjectionGapFamilies)
	review.PromotionQueue, review.NextAction = promotionQueueAndAction(entry)
	return review
}

func sourceQuestions(source SourceReview, entry Entry) []ReviewQuestion {
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
	return questions
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

func promotionCandidate(entry Entry) (string, PromotionCandidate) {
	queueID, nextAction := promotionQueueAndAction(entry)
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

func promotionQueueAndAction(entry Entry) (string, string) {
	switch entry.Status {
	case StatusGenerateable:
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
		"auth_extension":  "Needs auth extension",
		"bespoke_runtime": "Needs bespoke runtime",
		"catalog_ready":   "Catalog ready",
		"review":          "Needs review",
	}
	order := []string{"sourcegen_ready", "auth_extension", "bespoke_runtime", "catalog_ready", "review"}
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

func cleanupQuestion(finding ReviewFinding) ReviewQuestion {
	return ReviewQuestion{
		ID:         questionID(finding.SourceID, finding.Category),
		SourceID:   finding.SourceID,
		Path:       finding.Path,
		Category:   finding.Category,
		Question:   "Should this catalog entry remain separate?",
		Answer:     finding.Message,
		NextAction: finding.NextAction,
	}
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

func normalizedDisplayName(value string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(value) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func questionID(sourceID string, category string) string {
	id := strings.Trim(strings.ToLower(sourceID+"_"+category), "_")
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
