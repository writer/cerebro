package connectorcatalog

import (
	"fmt"
	"strings"
)

// RenderReviewMarkdown renders a compact maintenance report for GitHub job
// summaries and artifacts. maxItems limits long source queues; zero means the
// default limit.
func RenderReviewMarkdown(report ReviewReport, maxItems int) string {
	if maxItems <= 0 {
		maxItems = 40
	}
	var b strings.Builder
	b.WriteString("# Connector Catalog Review\n\n")
	b.WriteString("## Summary\n\n")
	b.WriteString("| Metric | Count |\n| --- | ---: |\n")
	writeMetric(&b, "Sources", report.Summary.Total)
	writeMetric(&b, "Sourcegen-ready definitions", report.Summary.Generateable)
	writeMetric(&b, "Needs auth extension", report.Summary.NeedsAuthExtension)
	writeMetric(&b, "Needs bespoke runtime", report.Summary.NeedsBespokeRuntime)
	writeMetric(&b, "Reference catalog sources", report.Summary.HighFidelitySources)
	writeMetric(&b, "Needs fidelity review", report.Summary.NeedsFidelityReview)
	if report.Summary.RuntimeDepth != nil {
		writeMetric(&b, "Runtime-backed sources", report.Summary.RuntimeDepth.RuntimeBackedSources)
		writeMetric(&b, "Reference-runtime sources", report.Summary.RuntimeDepth.ReferenceRuntimeSources)
		writeMetric(&b, "Needs runtime depth", report.Summary.RuntimeDepth.NeedsRuntimeDepth)
		writeMetric(&b, "Sources with read fixtures", report.Summary.RuntimeDepth.SourcesWithReadFixtures)
		writeMetric(&b, "Sources with discover fixtures", report.Summary.RuntimeDepth.SourcesWithDiscoverFixtures)
		writeMetric(&b, "Needs provider API discovery", report.Summary.RuntimeDepth.NeedsProviderAPIDiscovery)
		writeMetric(&b, "Sources with provider API contract", report.Summary.RuntimeDepth.SourcesWithProviderAPIContract)
		writeMetric(&b, "Sources with provider API family mapping", report.Summary.RuntimeDepth.SourcesWithProviderAPIMapping)
		writeMetric(&b, "Sources with provider API proof", report.Summary.RuntimeDepth.SourcesWithProviderAPIProof)
		writeMetric(&b, "Needs provider API proof", report.Summary.RuntimeDepth.NeedsProviderAPIProof)
		writeMetric(&b, "Sources with matching runtime transport", report.Summary.RuntimeDepth.SourcesWithRuntimeTransportMatch)
		writeMetric(&b, "Sources with runtime fixtures", report.Summary.RuntimeDepth.SourcesWithRuntimeFixtures)
		writeMetric(&b, "Sources with deploy manifest", report.Summary.RuntimeDepth.SourcesWithDeployManifest)
		writeMetric(&b, "Sources with projector tests", report.Summary.RuntimeDepth.SourcesWithProjectorTests)
	}
	writeMetric(&b, "Resource families", report.Summary.ResourceFamilies)
	writeMetric(&b, "Projected families", report.Summary.ProjectedFamilies)
	writeMetric(&b, "Graph item types", report.Summary.ProjectionTemplates)
	writeMetric(&b, "High-value families", report.Summary.HighValueFamilies)
	writeMetric(&b, "Coverage dimensions", report.Summary.CoverageDimensions)
	writeMetric(&b, "Cleanup findings", report.Summary.CleanupFindings)
	writeMetric(&b, "Review questions", report.Summary.Questions)

	b.WriteString("\n## Promotion Queues\n\n")
	if len(report.PromotionQueues) == 0 {
		b.WriteString("No promotion queues are populated.\n")
	} else {
		for _, queue := range report.PromotionQueues {
			fmt.Fprintf(&b, "### %s (%d)\n\n", queue.Label, queue.Count)
			b.WriteString("| Source | Status | Next action |\n| --- | --- | --- |\n")
			for i, candidate := range queue.Entries {
				if i >= maxItems {
					fmt.Fprintf(&b, "| ... | ... | %d more |\n", len(queue.Entries)-maxItems)
					break
				}
				fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n", escapeCell(candidate.SourceID), escapeCell(candidate.Status), escapeCell(candidate.NextAction))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("## Fidelity Queue\n\n")
	if len(report.FidelityQueue) == 0 {
		b.WriteString("No sources need fidelity review.\n\n")
	} else {
		fmt.Fprintf(&b, "Reference baseline: %d/100.\n\n", report.Summary.FidelityBaselineScore)
		b.WriteString("| Source | Score | Missing | Next action |\n| --- | ---: | --- | --- |\n")
		for i, candidate := range report.FidelityQueue {
			if i >= maxItems {
				fmt.Fprintf(&b, "| ... | ... | ... | %d more |\n", len(report.FidelityQueue)-maxItems)
				break
			}
			fmt.Fprintf(&b, "| `%s` | %d | %s | %s |\n", escapeCell(candidate.SourceID), candidate.Score, escapeCell(strings.Join(limitStrings(candidate.Missing, 6), ", ")), escapeCell(candidate.NextAction))
		}
		b.WriteString("\n")
	}

	if report.Summary.RuntimeDepth != nil || len(report.RuntimeDepthQueue) > 0 {
		b.WriteString("## Runtime Depth Queue\n\n")
		if len(report.RuntimeDepthQueue) == 0 {
			b.WriteString("No sources need runtime-depth review.\n\n")
		} else {
			baseline := runtimeDepthReviewThreshold
			if report.Summary.RuntimeDepth != nil {
				baseline = report.Summary.RuntimeDepth.BaselineScore
			}
			fmt.Fprintf(&b, "Reference runtime baseline: %d/100.\n\n", baseline)
			b.WriteString("| Source | Score | Package | Missing | Next action |\n| --- | ---: | --- | --- | --- |\n")
			for i, candidate := range report.RuntimeDepthQueue {
				if i >= maxItems {
					fmt.Fprintf(&b, "| ... | ... | ... | ... | %d more |\n", len(report.RuntimeDepthQueue)-maxItems)
					break
				}
				fmt.Fprintf(&b, "| `%s` | %d | %s | %s | %s |\n", escapeCell(candidate.SourceID), candidate.Score, inlineCodeOrDash(candidate.PackagePath), escapeCell(strings.Join(limitStrings(candidate.Missing, 6), ", ")), escapeCell(candidate.NextAction))
			}
			b.WriteString("\n")
		}
	}

	if report.Summary.RuntimeDepth != nil || len(report.APIDiscoveryQueue) > 0 {
		b.WriteString("## Provider API Discovery Queue\n\n")
		if len(report.APIDiscoveryQueue) == 0 {
			b.WriteString("No sources need provider API discovery.\n\n")
		} else {
			b.WriteString("| Source | Families | Existing references | Search starting point | Next action |\n| --- | --- | --- | --- | --- |\n")
			for i, candidate := range report.APIDiscoveryQueue {
				if i >= maxItems {
					fmt.Fprintf(&b, "| ... | ... | ... | ... | %d more |\n", len(report.APIDiscoveryQueue)-maxItems)
					break
				}
				search := ""
				if len(candidate.SearchQueries) > 0 {
					search = candidate.SearchQueries[0]
				}
				fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n",
					escapeCell(candidate.SourceID),
					escapeCell(strings.Join(limitStrings(candidate.MissingFamilies, 6), ", ")),
					escapeCell(strings.Join(limitStrings(candidate.ExistingReferences, 2), ", ")),
					escapeCell(search),
					escapeCell(candidate.NextAction),
				)
			}
			b.WriteString("\n")
		}
	}

	if report.Summary.RuntimeDepth != nil || len(report.ProviderAPIProofQueue) > 0 {
		b.WriteString("## Provider API Proof Queue\n\n")
		if len(report.ProviderAPIProofQueue) == 0 {
			b.WriteString("No sources need provider API proof updates.\n\n")
		} else {
			b.WriteString("| Source | Score | Spec | Missing | Next action |\n| --- | ---: | --- | --- | --- |\n")
			for i, candidate := range report.ProviderAPIProofQueue {
				if i >= maxItems {
					fmt.Fprintf(&b, "| ... | ... | ... | ... | %d more |\n", len(report.ProviderAPIProofQueue)-maxItems)
					break
				}
				fmt.Fprintf(&b, "| `%s` | %d | %s | %s | %s |\n",
					escapeCell(candidate.SourceID),
					candidate.Score,
					inlineCodeOrDash(candidate.SpecURL),
					escapeCell(strings.Join(limitStrings(candidate.Missing, 6), ", ")),
					escapeCell(candidate.NextAction),
				)
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("## Graph Coverage\n\n")
	if len(report.ProjectionCoverage) == 0 {
		b.WriteString("No projection templates are advertised.\n\n")
	} else {
		b.WriteString("| Graph item | Sources | Families |\n| --- | ---: | ---: |\n")
		for i, coverage := range report.ProjectionCoverage {
			if i >= maxItems {
				fmt.Fprintf(&b, "| ... | ... | %d more |\n", len(report.ProjectionCoverage)-maxItems)
				break
			}
			fmt.Fprintf(&b, "| `%s` | %d | %d |\n", escapeCell(coverage.Template), coverage.Sources, coverage.Families)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Cleanup Queue\n\n")
	if len(report.CleanupFindings) == 0 {
		b.WriteString("No cleanup findings.\n\n")
	} else {
		b.WriteString("| Source | Category | Finding | Next action |\n| --- | --- | --- | --- |\n")
		for i, finding := range report.CleanupFindings {
			if i >= maxItems {
				fmt.Fprintf(&b, "| ... | ... | ... | %d more |\n", len(report.CleanupFindings)-maxItems)
				break
			}
			fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s |\n", escapeCell(finding.SourceID), escapeCell(finding.Category), escapeCell(finding.Message), escapeCell(finding.NextAction))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Review Q&A\n\n")
	if len(report.Questions) == 0 {
		b.WriteString("No review questions.\n")
	} else {
		for i, question := range report.Questions {
			if i >= maxItems {
				fmt.Fprintf(&b, "\n%d more questions in the JSON artifact.\n", len(report.Questions)-maxItems)
				break
			}
			fmt.Fprintf(&b, "### `%s` %s\n\n", escapeCell(question.SourceID), escapeText(question.Category))
			fmt.Fprintf(&b, "**Question:** %s\n\n", escapeText(question.Question))
			fmt.Fprintf(&b, "**Answer from catalog:** %s\n\n", escapeText(question.Answer))
			fmt.Fprintf(&b, "**Next action:** %s\n\n", escapeText(question.NextAction))
		}
	}
	return b.String()
}

func writeMetric(b *strings.Builder, label string, value int) {
	fmt.Fprintf(b, "| %s | %d |\n", label, value)
}

func escapeCell(value string) string {
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "|", "\\|")
	return value
}

func inlineCodeOrDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return "`" + escapeCell(value) + "`"
}

func escapeText(value string) string {
	return strings.TrimSpace(strings.ReplaceAll(value, "\n", " "))
}
