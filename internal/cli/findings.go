package cli

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/writerinternal/cerebro/internal/app"
	"github.com/writerinternal/cerebro/internal/findings"
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

var (
	findingsSeverity string
	findingsStatus   string
	findingsPolicyID string
	findingsLimit    int
	findingsOutput   string
)

func init() {
	findingsCmd.AddCommand(findingsListCmd)
	findingsCmd.AddCommand(findingsStatsCmd)
	findingsCmd.AddCommand(findingsResolveCmd)
	findingsCmd.AddCommand(findingsSuppressCmd)

	findingsListCmd.Flags().StringVarP(&findingsSeverity, "severity", "s", "", "Filter by severity (critical,high,medium,low)")
	findingsListCmd.Flags().StringVar(&findingsStatus, "status", "open", "Filter by status (open,resolved,suppressed)")
	findingsListCmd.Flags().StringVarP(&findingsPolicyID, "policy", "p", "", "Filter by policy ID")
	findingsListCmd.Flags().IntVarP(&findingsLimit, "limit", "l", 100, "Maximum number of findings to show")
	findingsListCmd.Flags().StringVarP(&findingsOutput, "output", "o", "table", "Output format (table,json,csv,wide)")
}

func runFindingsList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	defer application.Close()

	filter := findings.FindingFilter{
		Severity: findingsSeverity,
		Status:   findingsStatus,
		PolicyID: findingsPolicyID,
	}

	list := application.Findings.List(filter)

	// Apply limit
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
				f.ID[:8],
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
				f.ID[:8],
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

func runFindingsStats(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	defer application.Close()

	stats := application.Findings.Stats()

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
	fmt.Printf("  %s        %d\n", statusColor("open"), stats.ByStatus["open"])
	fmt.Printf("  %s    %d\n", statusColor("resolved"), stats.ByStatus["resolved"])
	fmt.Printf("  %s  %d\n", statusColor("suppressed"), stats.ByStatus["suppressed"])

	return nil
}

func runFindingsResolve(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	findingID := args[0]

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	defer application.Close()

	if application.Findings.Resolve(findingID) {
		Success("Finding %s marked as resolved", findingID)
		return nil
	}
	return fmt.Errorf("finding not found: %s", findingID)
}

func runFindingsSuppress(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	findingID := args[0]

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	defer application.Close()

	if application.Findings.Suppress(findingID) {
		Success("Finding %s suppressed", findingID)
		return nil
	}
	return fmt.Errorf("finding not found: %s", findingID)
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
