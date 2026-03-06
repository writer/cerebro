package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/evalops/cerebro/internal/app"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show system status and health",
	Long: `Display the current status of Cerebro, including:
- Snowflake connection status
- Loaded policies count
- Findings summary
- Registered agents and providers`,
	RunE: runStatus,
}

var statusOutput string

func init() {
	statusCmd.Flags().StringVarP(&statusOutput, "output", "o", "table", "Output format (table,json)")
}

func runStatus(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	defer func() { _ = application.Close() }()

	status := map[string]interface{}{
		"version":   "1.0.0",
		"timestamp": time.Now().UTC(),
	}

	// Snowflake status
	sfStatus := map[string]interface{}{"configured": false}
	if application.Snowflake != nil {
		sfStatus["configured"] = true
		start := time.Now()
		if err := application.Snowflake.Ping(ctx); err != nil {
			sfStatus["status"] = "unhealthy"
			sfStatus["error"] = err.Error()
		} else {
			sfStatus["status"] = "healthy"
			sfStatus["latency_ms"] = time.Since(start).Milliseconds()
		}
	}
	status["snowflake"] = sfStatus

	// Policies
	policies := application.Policy.ListPolicies()
	status["policies"] = map[string]interface{}{
		"loaded": len(policies),
		"path":   application.Config.PoliciesPath,
	}

	// Findings
	fStats := application.Findings.Stats()
	status["findings"] = map[string]interface{}{
		"total":    fStats.Total,
		"open":     fStats.ByStatus["OPEN"],
		"critical": fStats.BySeverity["critical"],
		"high":     fStats.BySeverity["high"],
	}

	// Agents
	agents := application.Agents.ListAgents()
	status["agents"] = map[string]interface{}{
		"registered": len(agents),
	}

	// Providers
	providers := application.Providers.List()
	status["providers"] = map[string]interface{}{
		"registered": len(providers),
	}

	if statusOutput == FormatJSON {
		return JSONOutput(status)
	}

	// Table output
	fmt.Println(bold("Cerebro Status"))
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println()

	// Snowflake
	fmt.Println(bold("Snowflake"))
	if sf, ok := status["snowflake"].(map[string]interface{}); ok {
		configured, _ := sf["configured"].(bool)
		if configured {
			if sf["status"] == "healthy" {
				fmt.Printf("  Status:   %s\n", statusColor("healthy"))
				fmt.Printf("  Latency:  %dms\n", sf["latency_ms"])
			} else {
				fmt.Printf("  Status:   %s\n", statusColor("unhealthy"))
				fmt.Printf("  Error:    %s\n", sf["error"])
			}
		} else {
			fmt.Printf("  Status:   %s\n", color(colorYellow, "not configured"))
		}
	}
	fmt.Println()

	// Policies
	fmt.Println(bold("Policies"))
	if p, ok := status["policies"].(map[string]interface{}); ok {
		fmt.Printf("  Loaded:   %d\n", p["loaded"])
		fmt.Printf("  Path:     %s\n", p["path"])
	}
	fmt.Println()

	// Findings
	fmt.Println(bold("Findings"))
	if f, ok := status["findings"].(map[string]interface{}); ok {
		fmt.Printf("  Total:    %d\n", f["total"])
		fmt.Printf("  Open:     %d\n", f["open"])
		critical, _ := f["critical"].(int)
		high, _ := f["high"].(int)
		if critical > 0 {
			fmt.Printf("  Critical: %s\n", color(colorRed, fmt.Sprintf("%d", critical)))
		} else {
			fmt.Printf("  Critical: %d\n", critical)
		}
		if high > 0 {
			fmt.Printf("  High:     %s\n", color(colorRed, fmt.Sprintf("%d", high)))
		} else {
			fmt.Printf("  High:     %d\n", high)
		}
	}
	fmt.Println()

	// Components
	fmt.Println(bold("Components"))
	tw := NewTableWriter(os.Stdout, "Component", "Status", "Count")
	tw.AddRow("Agents", statusColor("healthy"), fmt.Sprintf("%d registered", len(agents)))
	tw.AddRow("Providers", statusColor("healthy"), fmt.Sprintf("%d registered", len(providers)))
	tw.Render()

	return nil
}
