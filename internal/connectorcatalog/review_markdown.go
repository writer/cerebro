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
	writeMetric(&b, "Sourcegen ready", report.Summary.Generateable)
	writeMetric(&b, "Needs auth extension", report.Summary.NeedsAuthExtension)
	writeMetric(&b, "Needs bespoke runtime", report.Summary.NeedsBespokeRuntime)
	writeMetric(&b, "Reference-depth sources", report.Summary.HighFidelitySources)
	writeMetric(&b, "Needs fidelity review", report.Summary.NeedsFidelityReview)
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

func escapeText(value string) string {
	return strings.TrimSpace(strings.ReplaceAll(value, "\n", " "))
}
