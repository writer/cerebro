package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/evalops/cerebro/internal/app"
	apiclient "github.com/evalops/cerebro/internal/client"
	"github.com/evalops/cerebro/internal/findings"
)

var findingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "Manage security findings",
	Long:  `List, filter, and manage security findings discovered by policy evaluation.`,
}

var findingsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List findings",
	Long: `List security findings with optional filtering.

Examples:
  cerebro findings list
  cerebro findings list --severity critical,high
  cerebro findings list --status open --limit 50
  cerebro findings list -o json`,
	RunE: runFindingsList,
}

var findingsStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show findings statistics",
	RunE:  runFindingsStats,
}

var findingsResolveCmd = &cobra.Command{
	Use:   "resolve [finding-id]",
	Short: "Mark a finding as resolved",
	Args:  cobra.ExactArgs(1),
	RunE:  runFindingsResolve,
}

var findingsSuppressCmd = &cobra.Command{
	Use:   "suppress [finding-id]",
	Short: "Suppress a finding (false positive)",
	Args:  cobra.ExactArgs(1),
	RunE:  runFindingsSuppress,
}

var findingsExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export findings in CSV or JSON format",
	Long: `Export findings to CSV or JSON format.

Examples:
  cerebro findings export --format csv > findings.csv
  cerebro findings export --format json --pretty > findings.json
  cerebro findings export --severity critical,high --format csv`,
	RunE: runFindingsExport,
}

var (
	findingsSeverity   string
	findingsStatus     string
	findingsPolicyID   string
	findingsLimit      int
	findingsOutput     string
	findingsExportFmt  string
	findingsExportFile string
	findingsPretty     bool
)

var (
	runFindingsListDirectFn     = runFindingsListDirect
	runFindingsStatsDirectFn    = runFindingsStatsDirect
	runFindingsResolveDirectFn  = runFindingsResolveDirect
	runFindingsSuppressDirectFn = runFindingsSuppressDirect
	runFindingsExportDirectFn   = runFindingsExportDirect
)

func init() {
	findingsCmd.AddCommand(findingsListCmd)
	findingsCmd.AddCommand(findingsStatsCmd)
	findingsCmd.AddCommand(findingsResolveCmd)
	findingsCmd.AddCommand(findingsSuppressCmd)
	findingsCmd.AddCommand(findingsExportCmd)

	findingsListCmd.Flags().StringVarP(&findingsSeverity, "severity", "s", "", "Filter by severity (critical,high,medium,low)")
	findingsListCmd.Flags().StringVar(&findingsStatus, "status", "OPEN", "Filter by status (OPEN,RESOLVED,SUPPRESSED)")
	findingsListCmd.Flags().StringVarP(&findingsPolicyID, "policy", "p", "", "Filter by policy ID")
	findingsListCmd.Flags().IntVarP(&findingsLimit, "limit", "l", 100, "Maximum number of findings to show")
	findingsListCmd.Flags().StringVarP(&findingsOutput, "output", "o", "table", "Output format (table,json,csv,wide)")

	findingsExportCmd.Flags().StringVarP(&findingsExportFmt, "format", "f", "csv", "Export format (csv,json)")
	findingsExportCmd.Flags().StringVarP(&findingsExportFile, "output", "o", "", "Output file (default: stdout)")
	findingsExportCmd.Flags().BoolVar(&findingsPretty, "pretty", false, "Pretty print JSON output")
	findingsExportCmd.Flags().StringVarP(&findingsSeverity, "severity", "s", "", "Filter by severity")
	findingsExportCmd.Flags().StringVar(&findingsStatus, "status", "", "Filter by status")
}

func runFindingsList(cmd *cobra.Command, args []string) error {
	ctx := commandContextOrBackground(cmd)
	mode, err := loadCLIExecutionMode()
	if err != nil {
		return err
	}

	filter := findingsListFilter()
	if mode != cliExecutionModeDirect {
		apiClient, err := newCLIAPIClient()
		if err != nil {
			if mode == cliExecutionModeAPI {
				return err
			}
			Warning("API client configuration invalid; using direct mode: %v", err)
		} else {
			list, err := apiClient.ListFindings(ctx, filter)
			if err == nil {
				return renderFindingsList(list)
			}
			if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, err) {
				return fmt.Errorf("list findings via api: %w", err)
			}
			Warning("API unavailable; using direct mode: %v", err)
		}
	}

	return runFindingsListDirectFn(cmd, args)
}

func runFindingsStats(cmd *cobra.Command, args []string) error {
	ctx := commandContextOrBackground(cmd)
	mode, err := loadCLIExecutionMode()
	if err != nil {
		return err
	}

	if mode != cliExecutionModeDirect {
		apiClient, err := newCLIAPIClient()
		if err != nil {
			if mode == cliExecutionModeAPI {
				return err
			}
			Warning("API client configuration invalid; using direct mode: %v", err)
		} else {
			stats, err := apiClient.FindingsStats(ctx)
			if err == nil {
				return renderFindingsStats(stats)
			}
			if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, err) {
				return fmt.Errorf("load findings stats via api: %w", err)
			}
			Warning("API unavailable; using direct mode: %v", err)
		}
	}

	return runFindingsStatsDirectFn(cmd, args)
}

func runFindingsResolve(cmd *cobra.Command, args []string) error {
	ctx := commandContextOrBackground(cmd)
	findingID := args[0]

	mode, err := loadCLIExecutionMode()
	if err != nil {
		return err
	}

	if mode != cliExecutionModeDirect {
		apiClient, err := newCLIAPIClient()
		if err != nil {
			if mode == cliExecutionModeAPI {
				return err
			}
			Warning("API client configuration invalid; using direct mode: %v", err)
		} else {
			err := apiClient.ResolveFinding(ctx, findingID)
			if err == nil {
				Success("Finding %s marked as resolved", findingID)
				return nil
			}
			if apiclient.IsAPIErrorStatus(err, http.StatusNotFound) {
				return fmt.Errorf("finding not found: %s", findingID)
			}
			if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, err) {
				return fmt.Errorf("resolve finding via api: %w", err)
			}
			Warning("API unavailable; using direct mode: %v", err)
		}
	}

	return runFindingsResolveDirectFn(cmd, args)
}

func runFindingsSuppress(cmd *cobra.Command, args []string) error {
	ctx := commandContextOrBackground(cmd)
	findingID := args[0]

	mode, err := loadCLIExecutionMode()
	if err != nil {
		return err
	}

	if mode != cliExecutionModeDirect {
		apiClient, err := newCLIAPIClient()
		if err != nil {
			if mode == cliExecutionModeAPI {
				return err
			}
			Warning("API client configuration invalid; using direct mode: %v", err)
		} else {
			err := apiClient.SuppressFinding(ctx, findingID)
			if err == nil {
				Success("Finding %s suppressed", findingID)
				return nil
			}
			if apiclient.IsAPIErrorStatus(err, http.StatusNotFound) {
				return fmt.Errorf("finding not found: %s", findingID)
			}
			if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, err) {
				return fmt.Errorf("suppress finding via api: %w", err)
			}
			Warning("API unavailable; using direct mode: %v", err)
		}
	}

	return runFindingsSuppressDirectFn(cmd, args)
}

func runFindingsExport(cmd *cobra.Command, args []string) error {
	ctx := commandContextOrBackground(cmd)
	mode, err := loadCLIExecutionMode()
	if err != nil {
		return err
	}

	filter := findings.FindingFilter{
		Severity: findingsSeverity,
		Status:   findingsStatus,
		PolicyID: findingsPolicyID,
	}
	format := normalizeFindingsExportFormat(findingsExportFmt)

	if mode != cliExecutionModeDirect {
		apiClient, err := newCLIAPIClient()
		if err != nil {
			if mode == cliExecutionModeAPI {
				return err
			}
			Warning("API client configuration invalid; using direct mode: %v", err)
		} else {
			data, _, err := apiClient.ExportFindings(ctx, filter, format, findingsPretty)
			if err == nil {
				return writeFindingsExportData(data, 0)
			}
			if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, err) {
				return fmt.Errorf("export findings via api: %w", err)
			}
			Warning("API unavailable; using direct mode: %v", err)
		}
	}

	return runFindingsExportDirectFn(cmd, args)
}

func runFindingsListDirect(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	defer func() { _ = application.Close() }()

	list := application.Findings.List(findingsListFilter())
	return renderFindingsList(list)
}

func runFindingsStatsDirect(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	defer func() { _ = application.Close() }()

	return renderFindingsStats(application.Findings.Stats())
}

func runFindingsResolveDirect(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	findingID := args[0]

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	defer func() { _ = application.Close() }()

	if application.Findings.Resolve(findingID) {
		Success("Finding %s marked as resolved", findingID)
		return nil
	}
	return fmt.Errorf("finding not found: %s", findingID)
}

func runFindingsSuppressDirect(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	findingID := args[0]

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	defer func() { _ = application.Close() }()

	if application.Findings.Suppress(findingID) {
		Success("Finding %s suppressed", findingID)
		return nil
	}
	return fmt.Errorf("finding not found: %s", findingID)
}

func runFindingsExportDirect(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	defer func() { _ = application.Close() }()

	filter := findings.FindingFilter{
		Severity: findingsSeverity,
		Status:   findingsStatus,
		PolicyID: findingsPolicyID,
	}

	list := application.Findings.List(filter)
	for _, f := range list {
		findings.EnrichFinding(f)
	}

	var data []byte
	switch normalizeFindingsExportFormat(findingsExportFmt) {
	case "json":
		exporter := findings.NewJSONExporter(findingsPretty)
		data, err = exporter.Export(list)
	default:
		exporter := findings.NewCSVExporter()
		data, err = exporter.Export(list)
	}
	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	return writeFindingsExportData(data, len(list))
}

func findingsListFilter() findings.FindingFilter {
	return findings.FindingFilter{
		Severity: findingsSeverity,
		Status:   findingsStatus,
		PolicyID: findingsPolicyID,
		Limit:    findingsLimit,
	}
}

func renderFindingsList(list []*findings.Finding) error {
	if findingsLimit > 0 && len(list) > findingsLimit {
		list = list[:findingsLimit]
	}

	switch findingsOutput {
	case FormatJSON:
		return JSONOutput(map[string]interface{}{
			"findings": list,
			"count":    len(list),
		})
	case FormatCSV:
		columns := []string{"ID", "Severity", "Status", "Policy", "Resource", "First Seen"}
		rows := make([][]string, len(list))
		for i, f := range list {
			rows[i] = []string{
				f.ID,
				f.Severity,
				f.Status,
				f.PolicyID,
				f.ResourceID,
				f.FirstSeen.Format(time.RFC3339),
			}
		}
		return CSVOutput(columns, rows)
	case FormatWide:
		tw := NewTableWriter(os.Stdout, "ID", "Severity", "Status", "Policy", "Resource", "Description", "First Seen")
		for _, f := range list {
			tw.AddRow(
				shortFindingID(f.ID),
				severityColor(f.Severity),
				statusColor(f.Status),
				f.PolicyID,
				truncateStr(f.ResourceID, 30),
				truncateStr(f.Description, 40),
				timeAgo(f.FirstSeen),
			)
		}
		tw.Render()
	default:
		tw := NewTableWriter(os.Stdout, "ID", "Severity", "Status", "Policy", "Resource")
		for _, f := range list {
			tw.AddRow(
				shortFindingID(f.ID),
				severityColor(f.Severity),
				statusColor(f.Status),
				truncateStr(f.PolicyID, 25),
				truncateStr(f.ResourceID, 35),
			)
		}
		tw.Render()
	}

	fmt.Printf("\n%d findings shown\n", len(list))
	return nil
}

func renderFindingsStats(stats findings.Stats) error {
	if findingsOutput == FormatJSON {
		return JSONOutput(stats)
	}

	fmt.Println(bold("Findings Summary"))
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("Total:      %d\n", stats.Total)
	fmt.Println()

	fmt.Println(bold("By Severity"))
	fmt.Printf("  %s  %d\n", severityColor("critical"), stats.BySeverity["critical"])
	fmt.Printf("  %s      %d\n", severityColor("high"), stats.BySeverity["high"])
	fmt.Printf("  %s    %d\n", severityColor("medium"), stats.BySeverity["medium"])
	fmt.Printf("  %s       %d\n", severityColor("low"), stats.BySeverity["low"])
	fmt.Println()

	fmt.Println(bold("By Status"))
	fmt.Printf("  %s        %d\n", statusColor("OPEN"), stats.ByStatus["OPEN"])
	fmt.Printf("  %s    %d\n", statusColor("RESOLVED"), stats.ByStatus["RESOLVED"])
	fmt.Printf("  %s  %d\n", statusColor("SUPPRESSED"), stats.ByStatus["SUPPRESSED"])

	return nil
}

func writeFindingsExportData(data []byte, count int) error {
	if findingsExportFile != "" {
		if err := os.WriteFile(findingsExportFile, data, 0o600); err != nil {
			return fmt.Errorf("write file: %w", err)
		}
		if count > 0 {
			Success("Exported %d findings to %s", count, findingsExportFile)
		} else {
			Success("Exported findings to %s", findingsExportFile)
		}
		return nil
	}

	fmt.Print(string(data))
	return nil
}

func normalizeFindingsExportFormat(format string) string {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		return "csv"
	}
	return format
}

func shortFindingID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

func commandContextOrBackground(cmd *cobra.Command) context.Context {
	if cmd != nil && cmd.Context() != nil {
		return cmd.Context()
	}
	return context.Background()
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func timeAgo(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m ago"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d.Hours())) + "h ago"
	case d < 7*24*time.Hour:
		return strconv.Itoa(int(d.Hours()/24)) + "d ago"
	default:
		return t.Format("Jan 02")
	}
}
