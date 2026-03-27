package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/writer/cerebro/internal/app"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show system status and health",
	Long: `Display the current status of Cerebro, including:
- Warehouse connection status
- Loaded policies count
- Findings summary
- Registered agents and providers`,
	RunE: runStatus,
}

var statusOutput string

func init() {
	statusCmd.Flags().StringVarP(&statusOutput, "output", "o", "table", "Output format (table,json)")
}

var runStatusDirectFn = runStatusDirect

func runStatus(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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
			status, err := apiClient.AdminHealth(ctx)
			if err == nil {
				return renderStatus(status)
			}
			if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, err) {
				return fmt.Errorf("status via api failed: %w", err)
			}
			Warning("API unavailable; using direct mode: %v", err)
		}
	}

	return runStatusDirectFn(cmd, args)
}

func runStatusDirect(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	defer func() { _ = application.Close() }()

	status := map[string]interface{}{
		"version":   Version,
		"timestamp": time.Now().UTC(),
	}

	// Warehouse status
	warehouseStatus := map[string]interface{}{"configured": false}
	if application.Warehouse != nil && application.Warehouse.DB() != nil {
		warehouseStatus["configured"] = true
		start := time.Now()
		if err := application.Warehouse.DB().PingContext(ctx); err != nil {
			warehouseStatus["status"] = "unhealthy"
			warehouseStatus["error"] = err.Error()
		} else {
			warehouseStatus["status"] = "healthy"
			warehouseStatus["latency_ms"] = time.Since(start).Milliseconds()
		}
	}
	status["warehouse"] = warehouseStatus

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

	return renderStatus(status)
}

func renderStatus(status map[string]interface{}) error {
	status = withStatusDefaults(status)
	if statusOutput == FormatJSON {
		return JSONOutput(status)
	}

	fmt.Println(bold("Cerebro Status"))
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println()

	fmt.Println(bold("Warehouse"))
	sf := statusSection(status, "warehouse")
	sfStatus := strings.ToLower(strings.TrimSpace(statusString(sf["status"])))
	configured := statusBool(sf["configured"]) || (sfStatus != "" && sfStatus != "not_configured")
	if configured {
		if sfStatus == "healthy" {
			fmt.Printf("  Status:   %s\n", statusColor("healthy"))
			fmt.Printf("  Latency:  %dms\n", statusInt(sf["latency_ms"]))
		} else {
			fmt.Printf("  Status:   %s\n", statusColor("unhealthy"))
			fmt.Printf("  Error:    %s\n", statusString(sf["error"]))
		}
	} else {
		fmt.Printf("  Status:   %s\n", color(colorYellow, "not configured"))
	}
	fmt.Println()

	fmt.Println(bold("Policies"))
	policies := statusSection(status, "policies")
	fmt.Printf("  Loaded:   %d\n", statusInt(policies["loaded"]))
	path := statusString(policies["path"])
	if strings.TrimSpace(path) == "" {
		path = "n/a"
	}
	fmt.Printf("  Path:     %s\n", path)
	fmt.Println()

	fmt.Println(bold("Findings"))
	findings := statusSection(status, "findings")
	fmt.Printf("  Total:    %d\n", statusInt(findings["total"]))
	fmt.Printf("  Open:     %d\n", statusInt(findings["open"]))
	critical := statusInt(findings["critical"])
	high := statusInt(findings["high"])
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
	fmt.Println()

	agents := statusSection(status, "agents")
	providers := statusSection(status, "providers")
	fmt.Println(bold("Components"))
	tw := NewTableWriter(os.Stdout, "Component", "Status", "Count")
	tw.AddRow("Agents", statusColor("healthy"), fmt.Sprintf("%d registered", statusInt(agents["registered"])))
	tw.AddRow("Providers", statusColor("healthy"), fmt.Sprintf("%d registered", statusInt(providers["registered"])))
	tw.Render()

	return nil
}

func withStatusDefaults(status map[string]interface{}) map[string]interface{} {
	if status == nil {
		status = map[string]interface{}{}
	}
	if _, ok := status["version"]; !ok {
		status["version"] = Version
	}
	if _, ok := status["timestamp"]; !ok {
		status["timestamp"] = time.Now().UTC()
	}
	if _, ok := status["policies"]; !ok {
		status["policies"] = map[string]interface{}{}
	}
	if _, ok := status["findings"]; !ok {
		status["findings"] = map[string]interface{}{}
	}
	if _, ok := status["agents"]; !ok {
		status["agents"] = map[string]interface{}{}
	}
	if _, ok := status["providers"]; !ok {
		status["providers"] = map[string]interface{}{}
	}
	return status
}

func statusSection(status map[string]interface{}, key string) map[string]interface{} {
	value, ok := status[key]
	if !ok {
		return map[string]interface{}{}
	}
	if section, ok := value.(map[string]interface{}); ok {
		return section
	}
	return map[string]interface{}{}
}

func statusString(value interface{}) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprintf("%v", value)
	}
}

func statusBool(value interface{}) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true")
	default:
		return false
	}
}

func statusInt(value interface{}) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int8:
		return int(typed)
	case int16:
		return int(typed)
	case int32:
		return int(typed)
	case int64:
		return int(typed)
	case float32:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		v, err := typed.Int64()
		if err == nil {
			return int(v)
		}
		f, err := typed.Float64()
		if err == nil {
			return int(f)
		}
		return 0
	default:
		return 0
	}
}
