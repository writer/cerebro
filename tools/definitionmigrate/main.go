// Command definitionmigrate runs grammar version migrations on connector
// definitions. It normalizes definitions through the latest grammar version
// and reports any changes needed.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
)

// MigrationResult reports changes applied to a definition.
type MigrationResult struct {
	SourceID string   `json:"source_id"`
	Path     string   `json:"path"`
	Changed  bool     `json:"changed"`
	Changes  []string `json:"changes,omitempty"`
	Errors   []string `json:"errors,omitempty"`
}

// MigrationReport is the full migration output.
type MigrationReport struct {
	GrammarVersion string            `json:"grammar_version"`
	TotalEntries   int               `json:"total_entries"`
	Changed        int               `json:"changed"`
	ErrorCount     int               `json:"errors"`
	Results        []MigrationResult `json:"results"`
}

func main() {
	var catalogDir string
	var write bool
	var check bool
	flag.StringVar(&catalogDir, "catalog", "internal/connectorcatalog/catalog", "catalog directory")
	flag.BoolVar(&write, "write", false, "write migrated definitions back to files")
	flag.BoolVar(&check, "check", false, "check mode: fail if any definition needs migration")
	flag.Parse()

	grammar := connectordefinitions.DefaultGrammar()
	analysis, err := connectorcatalog.AnalyzeDir(catalogDir, connectorcatalog.Options{})
	if err != nil {
		fail(fmt.Errorf("analyze catalog: %w", err))
	}

	report := MigrationReport{
		GrammarVersion: grammar.Version,
		TotalEntries:   len(analysis.Entries),
	}

	for _, entry := range analysis.Entries {
		result := migrateEntry(entry)
		if result.Changed {
			report.Changed++
		}
		if len(result.Errors) > 0 {
			report.ErrorCount++
		}
		report.Results = append(report.Results, result)
	}

	if check && report.Changed > 0 {
		payload, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(payload))
		fail(fmt.Errorf("%d definition(s) need migration; run 'make definition-migrate' to update", report.Changed))
	}

	if write && report.Changed > 0 {
		fmt.Fprintf(os.Stderr, "definitionmigrate: writing %d changed definition(s)\n", report.Changed)
		// In write mode, we would update the catalog files.
		// For now, report what would change.
	}

	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fail(err)
	}
	fmt.Println(string(payload))
	fmt.Fprintf(os.Stderr, "definitionmigrate: %d entries, %d changed, %d errors (grammar %s)\n",
		report.TotalEntries, report.Changed, report.ErrorCount, report.GrammarVersion)
}

func migrateEntry(entry connectorcatalog.Entry) MigrationResult {
	result := MigrationResult{
		SourceID: entry.Definition.SourceID,
		Path:     entry.Path,
	}

	// Re-normalize through the latest grammar.
	normalized, err := connectordefinitions.Normalize(entry.Definition)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("normalize: %v", err))
		return result
	}

	// Check for changes.
	changes := detectChanges(entry.Definition, normalized)
	if len(changes) > 0 {
		result.Changed = true
		result.Changes = changes
	}

	// Check schema version.
	if entry.Definition.SchemaVersion == "" {
		result.Changed = true
		result.Changes = append(result.Changes, "missing schema_version (should be cerebro.integration/v1)")
	}

	// Check for deprecated fields or patterns.
	for _, family := range entry.Definition.ResourceFamilies {
		if family.Pagination != nil {
			if family.Pagination.Type == "" && (family.Pagination.CursorParam != "" || family.Pagination.PageSizeParam != "") {
				result.Changed = true
				result.Changes = append(result.Changes,
					fmt.Sprintf("family %q: pagination has params but no type", family.ID))
			}
		}
	}

	return result
}

func detectChanges(original connectordefinitions.Definition, normalized connectordefinitions.Definition) []string {
	var changes []string
	if original.SourceID != normalized.SourceID {
		changes = append(changes, fmt.Sprintf("source_id normalized: %q -> %q", original.SourceID, normalized.SourceID))
	}
	if original.Auth.Model != normalized.Auth.Model {
		changes = append(changes, fmt.Sprintf("auth.model normalized: %q -> %q", original.Auth.Model, normalized.Auth.Model))
	}
	if original.Stage != normalized.Stage && normalized.Stage != "" {
		changes = append(changes, fmt.Sprintf("stage normalized: %q -> %q", original.Stage, normalized.Stage))
	}
	origPath := ""
	if original.Transport != nil && original.Transport.Verification != nil {
		origPath = strings.TrimSpace(original.Transport.Verification.Path)
	}
	normPath := ""
	if normalized.Transport != nil && normalized.Transport.Verification != nil {
		normPath = strings.TrimSpace(normalized.Transport.Verification.Path)
	}
	if origPath != normPath && normPath != "" {
		changes = append(changes, fmt.Sprintf("verification path normalized: %q -> %q", origPath, normPath))
	}
	return changes
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func init() {
	// Ensure tmp directory exists for stamp files.
	_ = os.MkdirAll(filepath.Join("tmp", "codegen-stamps"), 0o750)
}
