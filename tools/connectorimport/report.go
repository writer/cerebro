// Funnel report rendering (JSON + Markdown) and stdout summary.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/connectorimport"
)

func writeReport(path string, summary connectorimport.Summary, outcomes []connectorimport.Outcome) error {
	report := struct {
		Summary  connectorimport.Summary   `json:"summary"`
		Outcomes []connectorimport.Outcome `json:"outcomes"`
	}{Summary: summary, Outcomes: outcomes}
	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(payload, '\n'), 0o600); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return os.WriteFile(strings.TrimSuffix(path, filepath.Ext(path))+".md", []byte(renderReportMarkdown(summary, outcomes)), 0o600)
}

func renderReportMarkdown(summary connectorimport.Summary, outcomes []connectorimport.Outcome) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Connector import funnel\n\n")
	fmt.Fprintf(&b, "- Targets: %d\n", summary.Targets)
	fmt.Fprintf(&b, "- Supported (catalog-ready, zero-code live): %d\n", summary.Supported)
	fmt.Fprintf(&b, "- Extension required: %d\n", summary.ExtensionNeeded)
	fmt.Fprintf(&b, "- Bespoke required: %d\n", summary.BespokeNeeded)
	fmt.Fprintf(&b, "- Runtime unsupported (classifier-ok, runtime-blocked): %d\n", summary.RuntimeUnsupported)
	fmt.Fprintf(&b, "- Proof-gate failed (runtime-ok, catalog-gate-blocked): %d\n", summary.ProofGateFailed)
	fmt.Fprintf(&b, "- Generation errors: %d\n", summary.GenerationError)
	fmt.Fprintf(&b, "- Yield: %.1f%%\n\n", summary.YieldPercent)
	if len(summary.BlockingReasons) > 0 {
		fmt.Fprintf(&b, "## Top blocking reasons (grammar/intake roadmap)\n\n")
		for _, kv := range sortedCounts(summary.BlockingReasons) {
			fmt.Fprintf(&b, "- `%s`: %d\n", kv.key, kv.count)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "## Per-target outcomes\n\n")
	fmt.Fprintf(&b, "| source_id | domain | verdict | families | note |\n")
	fmt.Fprintf(&b, "| --- | --- | --- | --- | --- |\n")
	for _, outcome := range outcomes {
		note := outcome.Error
		if note == "" && len(outcome.MissingFeatures) > 0 {
			note = strings.Join(outcome.MissingFeatures, ", ")
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %s |\n", outcome.SourceID, outcome.Domain, outcome.Verdict, outcome.FamilyCount, truncate(note, 80))
	}
	return b.String()
}

func printSummary(summary connectorimport.Summary, outcomes []connectorimport.Outcome) {
	fmt.Printf("connector-import: targets=%d supported=%d extension=%d bespoke=%d runtime_unsupported=%d proof_gate=%d error=%d yield=%.1f%%\n",
		summary.Targets, summary.Supported, summary.ExtensionNeeded, summary.BespokeNeeded, summary.RuntimeUnsupported, summary.ProofGateFailed, summary.GenerationError, summary.YieldPercent)
	for _, kv := range sortedCounts(summary.BlockingReasons) {
		fmt.Printf("  blocked-by %s: %d\n", kv.key, kv.count)
	}
}

type countEntry struct {
	key   string
	count int
}

func sortedCounts(counts map[string]int) []countEntry {
	entries := make([]countEntry, 0, len(counts))
	for key, count := range counts {
		entries = append(entries, countEntry{key: key, count: count})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return entries[i].key < entries[j].key
	})
	return entries
}

func truncate(value string, max int) string {
	value = strings.ReplaceAll(value, "\n", " ")
	if len(value) <= max {
		return value
	}
	return value[:max-1] + "…"
}
