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
					reviewFamily("groups", "identity_group", true),
				}),
			},
			{
				Path:             "identity/azure_com.yaml",
				Status:           StatusNeedsAuthExtension,
				ClassifierOutput: "supported",
				SourcegenError:   "auth model requires an extension",
				Definition: reviewDefinition("azure_com", "Azure", []connectordefinitions.ResourceFamily{
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
		Questions: []ReviewQuestion{{
			SourceID:   "okta",
			Category:   "graph_projection",
			Question:   "Do users project?",
			Answer:     "1 of 1 families project through identity_user.",
			NextAction: "Open the source detail data view.",
		}},
	}

	markdown := RenderReviewMarkdown(report, 10)
	for _, want := range []string{"# Connector Catalog Review", "## Promotion Queues", "## Review Q&A", "Do users project?"} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("markdown missing %q:\n%s", want, markdown)
		}
	}
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
	for _, question := range report.Questions {
		if question.SourceID == sourceID && question.Category == category {
			return true
		}
	}
	return false
}
