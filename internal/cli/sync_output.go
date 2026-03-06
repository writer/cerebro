package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	nativesync "github.com/evalops/cerebro/internal/sync"
)

type syncPreflightCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type syncPreflightReport struct {
	Mode      string               `json:"mode"`
	Provider  string               `json:"provider"`
	AuthMode  string               `json:"auth_mode"`
	AuthChain string               `json:"auth_chain,omitempty"`
	StartedAt time.Time            `json:"started_at"`
	Duration  string               `json:"duration"`
	Success   bool                 `json:"success"`
	Checks    []syncPreflightCheck `json:"checks"`
}

type syncSummary struct {
	Provider      string             `json:"provider"`
	StartedAt     time.Time          `json:"started_at"`
	Duration      string             `json:"duration"`
	TotalSynced   int                `json:"total_synced"`
	TotalErrors   int                `json:"total_errors"`
	TotalAdded    int                `json:"total_added"`
	TotalModified int                `json:"total_modified"`
	TotalRemoved  int                `json:"total_removed"`
	Results       []syncTableSummary `json:"results"`
}

type syncTableSummary struct {
	Table    string           `json:"table"`
	Region   string           `json:"region,omitempty"`
	Synced   int              `json:"synced"`
	Errors   int              `json:"errors"`
	Error    string           `json:"error,omitempty"`
	Duration string           `json:"duration"`
	Changes  *syncChangeStats `json:"changes,omitempty"`
}

type syncChangeStats struct {
	Added    int `json:"added"`
	Modified int `json:"modified"`
	Removed  int `json:"removed"`
}

func printSyncPreflightReport(report syncPreflightReport) error {
	if err := writeSyncReport(report); err != nil {
		return err
	}

	if syncOutput == FormatJSON {
		return JSONOutput(report)
	}

	fmt.Println()
	fmt.Printf("%s Preflight Results:\n", strings.ToUpper(report.Provider))
	fmt.Println("─────────────────────────────────────────")
	fmt.Printf("  Auth mode:  %s\n", report.AuthMode)
	if strings.TrimSpace(report.AuthChain) != "" {
		fmt.Printf("  Auth chain: %s\n", report.AuthChain)
	}
	fmt.Println()
	for _, check := range report.Checks {
		status := "✓"
		if check.Status != "passed" {
			status = "✗"
		}
		fmt.Printf("  %s %-30s %s\n", status, check.Name, check.Detail)
	}
	fmt.Println("─────────────────────────────────────────")
	fmt.Printf("  Duration: %s\n", report.Duration)
	if report.Success {
		Success("Preflight completed successfully")
	} else {
		Warning("Preflight detected failures")
	}
	return nil
}

func summarizeSyncRunErrors(scope string, errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%s completed with %d error(s): %w", scope, len(errs), errors.Join(errs...))
}

func handleSyncRunResults(results []nativesync.SyncResult, start time.Time, provider string, syncErr error) error {
	if len(results) > 0 || syncErr == nil {
		if err := printSyncResults(results, start, provider); err != nil {
			return err
		}
	}
	if syncErr != nil {
		return fmt.Errorf("sync failed: %w", syncErr)
	}
	return nil
}

func printSyncResults(results []nativesync.SyncResult, start time.Time, provider string) error {
	summary := buildSyncSummary(results, start, provider)
	if err := writeSyncReport(summary); err != nil {
		return err
	}

	if syncOutput == FormatJSON {
		if err := JSONOutput(summary); err != nil {
			return err
		}
		return strictSyncSummaryError(summary)
	}

	fmt.Println()
	fmt.Printf("%s Sync Results:\n", provider)
	fmt.Println("─────────────────────────────────────────")

	for _, r := range results {
		status := "✓"
		if r.Errors > 0 {
			status = "✗"
		}

		changeInfo := ""
		if r.Changes != nil && r.Changes.HasChanges() {
			changeInfo = fmt.Sprintf(" [%s]", r.Changes.Summary())
		}

		name := r.Table
		if r.Region != "" {
			name = fmt.Sprintf("%s (%s)", r.Table, r.Region)
		}
		errorInfo := fmt.Sprintf(", errors=%d", r.Errors)
		fmt.Printf("  %s %-30s %4d resources (%s%s)%s\n", status, name, r.Synced, r.Duration.Round(time.Millisecond), errorInfo, changeInfo)
	}

	fmt.Println("─────────────────────────────────────────")
	fmt.Printf("  Total: %d resources synced in %s\n", summary.TotalSynced, time.Since(start).Round(time.Second))

	if summary.TotalAdded > 0 || summary.TotalModified > 0 || summary.TotalRemoved > 0 {
		fmt.Printf("  Changes: +%d added, ~%d modified, -%d removed\n", summary.TotalAdded, summary.TotalModified, summary.TotalRemoved)
	}

	if summary.TotalErrors > 0 {
		Warning("%d tables had errors", summary.TotalErrors)
	} else {
		Success("Sync completed successfully")
	}

	return strictSyncSummaryError(summary)
}

func buildSyncSummary(results []nativesync.SyncResult, start time.Time, provider string) syncSummary {
	summary := syncSummary{
		Provider:  provider,
		StartedAt: start,
		Duration:  time.Since(start).String(),
	}

	for _, r := range results {
		row := syncTableSummary{
			Table:    r.Table,
			Region:   r.Region,
			Synced:   r.Synced,
			Errors:   r.Errors,
			Error:    r.Error,
			Duration: r.Duration.String(),
		}
		if r.Changes != nil {
			row.Changes = &syncChangeStats{
				Added:    len(r.Changes.Added),
				Modified: len(r.Changes.Modified),
				Removed:  len(r.Changes.Removed),
			}
			summary.TotalAdded += row.Changes.Added
			summary.TotalModified += row.Changes.Modified
			summary.TotalRemoved += row.Changes.Removed
		}

		summary.Results = append(summary.Results, row)
		summary.TotalSynced += r.Synced
		summary.TotalErrors += r.Errors
	}

	return summary
}

func strictSyncSummaryError(summary syncSummary) error {
	if !syncStrictExit || summary.TotalErrors == 0 {
		return nil
	}
	return fmt.Errorf("strict-exit enabled: %d table errors reported", summary.TotalErrors)
}

func writeSyncReport(report interface{}) error {
	path := strings.TrimSpace(syncReportFile)
	if path == "" {
		return nil
	}

	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sync report: %w", err)
	}
	payload = append(payload, '\n')

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create report directory %q: %w", dir, err)
		}
	}

	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write sync report %q: %w", path, err)
	}
	Info("Wrote sync report: %s", path)
	return nil
}
