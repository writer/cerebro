package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/writer/cerebro/internal/policy"
)

var policyOutput string

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Policy management commands",
}

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all policies",
	RunE:  runPolicyList,
}

var policyValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate policy files",
	Long: `Validate all policy files in the policies directory.

Checks that:
- All policy files are valid JSON/YAML
- Required fields (id, name, severity, resource) are present
- Severity values are valid (critical, high, medium, low)
- No duplicate policy IDs exist

Examples:
  cerebro policy validate
  CEDAR_POLICIES_PATH=/custom/path cerebro policy validate`,
	RunE: runPolicyValidate,
}

var policyTestCmd = &cobra.Command{
	Use:   "test [policy-id] [asset-file]",
	Short: "Test a policy against an asset",
	Args:  cobra.ExactArgs(2),
	RunE:  runPolicyTest,
}

var (
	policyValidateOutput string
	policyTestOutput     string
)

func init() {
	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyValidateCmd)
	policyCmd.AddCommand(policyTestCmd)

	policyListCmd.Flags().StringVarP(&policyOutput, "output", "o", "table", "Output format (table,json,wide)")
	policyValidateCmd.Flags().StringVarP(&policyValidateOutput, "output", "o", "text", "Output format (text,json)")
	policyTestCmd.Flags().StringVarP(&policyTestOutput, "output", "o", "text", "Output format (text,json)")
}

func policiesPath() string {
	if path := os.Getenv("POLICIES_PATH"); path != "" {
		return path
	}
	if path := os.Getenv("CEDAR_POLICIES_PATH"); path != "" {
		return path
	}
	return "policies"
}

func runPolicyList(cmd *cobra.Command, args []string) error {
	engine := policy.NewEngine()

	if err := engine.LoadPolicies(policiesPath()); err != nil {
		return fmt.Errorf("load policies: %w", err)
	}

	policies := engine.ListPolicies()

	switch policyOutput {
	case FormatJSON:
		return JSONOutput(map[string]interface{}{
			"policies": policies,
			"count":    len(policies),
		})
	case FormatWide:
		tw := NewTableWriter(os.Stdout, "ID", "Name", "Severity", "Resource", "Tags")
		for _, p := range policies {
			tw.AddRow(
				p.ID,
				truncateStr(p.Name, 35),
				severityColor(p.Severity),
				p.Resource,
				strings.Join(p.Tags, ", "),
			)
		}
		tw.Render()
	default:
		tw := NewTableWriter(os.Stdout, "ID", "Name", "Severity", "Tags")
		for _, p := range policies {
			tw.AddRow(
				p.ID,
				truncateStr(p.Name, 40),
				severityColor(p.Severity),
				strings.Join(p.Tags, ", "),
			)
		}
		tw.Render()
	}

	fmt.Printf("\n%d policies loaded\n", len(policies))
	return nil
}

func runPolicyValidate(cmd *cobra.Command, args []string) error {
	engine := policy.NewEngine()

	if err := engine.LoadPolicies(policiesPath()); err != nil {
		if policyValidateOutput == FormatJSON {
			if jsonErr := JSONOutput(map[string]interface{}{
				"valid": false,
				"error": err.Error(),
			}); jsonErr != nil {
				return jsonErr
			}
			return err
		}
		Error("Validation failed: %v", err)
		return err
	}

	policies := engine.ListPolicies()

	// Additional validation checks
	severityCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, p := range policies {
		if count, ok := severityCounts[p.Severity]; ok {
			severityCounts[p.Severity] = count + 1
		}
	}

	if policyValidateOutput == FormatJSON {
		return JSONOutput(map[string]interface{}{
			"valid":           true,
			"count":           len(policies),
			"severity_counts": severityCounts,
		})
	}

	Success("Validated %d policies", len(policies))
	fmt.Printf("  Critical: %d, High: %d, Medium: %d, Low: %d\n",
		severityCounts["critical"], severityCounts["high"],
		severityCounts["medium"], severityCounts["low"])
	return nil
}

func runPolicyTest(cmd *cobra.Command, args []string) error {
	policyID := args[0]
	assetFile := args[1]

	engine := policy.NewEngine()

	jsonError := func(err error, extra map[string]interface{}) error {
		if policyTestOutput != FormatJSON {
			return err
		}
		payload := map[string]interface{}{
			"passed":    false,
			"policy_id": policyID,
			"asset":     assetFile,
			"error":     err.Error(),
		}
		for k, v := range extra {
			payload[k] = v
		}
		if jsonErr := JSONOutput(payload); jsonErr != nil {
			return jsonErr
		}
		return err
	}

	if err := engine.LoadPolicies(policiesPath()); err != nil {
		return jsonError(fmt.Errorf("load policies: %w", err), nil)
	}

	p, ok := engine.GetPolicy(policyID)
	if !ok {
		return jsonError(fmt.Errorf("policy not found: %s", policyID), nil)
	}

	data, err := os.ReadFile(assetFile) // #nosec G304 -- asset path is explicitly provided by the caller for policy testing
	if err != nil {
		return jsonError(fmt.Errorf("read asset file: %w", err), map[string]interface{}{"policy": p.Name})
	}

	var asset map[string]interface{}
	if parseErr := json.Unmarshal(data, &asset); parseErr != nil {
		return jsonError(fmt.Errorf("parse asset: %w", parseErr), map[string]interface{}{"policy": p.Name})
	}

	testFindings, err := engine.EvaluateAsset(cmd.Context(), asset)
	if err != nil {
		return jsonError(fmt.Errorf("evaluate: %w", err), map[string]interface{}{"policy": p.Name})
	}

	passed := len(testFindings) == 0

	if policyTestOutput == FormatJSON {
		violations := make([]string, 0, len(testFindings))
		for _, f := range testFindings {
			violations = append(violations, f.Description)
		}
		return JSONOutput(map[string]interface{}{
			"policy_id":  policyID,
			"policy":     p.Name,
			"asset":      assetFile,
			"passed":     passed,
			"violations": violations,
		})
	}

	fmt.Printf("Policy: %s\n", p.Name)
	fmt.Printf("Asset:  %s\n\n", assetFile)

	if passed {
		fmt.Println("Result: PASS (no violations)")
	} else {
		fmt.Println("Result: FAIL")
		for _, f := range testFindings {
			fmt.Printf("  - %s\n", f.Description)
		}
	}

	return nil
}
