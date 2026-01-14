package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/writerinternal/cerebro/internal/config"
	"github.com/writerinternal/cerebro/internal/policy"
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
	RunE:  runPolicyValidate,
}

var policyTestCmd = &cobra.Command{
	Use:   "test [policy-id] [asset-file]",
	Short: "Test a policy against an asset",
	Args:  cobra.ExactArgs(2),
	RunE:  runPolicyTest,
}

func init() {
	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyValidateCmd)
	policyCmd.AddCommand(policyTestCmd)

	policyListCmd.Flags().StringVarP(&policyOutput, "output", "o", "table", "Output format (table,json,wide)")
}

func runPolicyList(cmd *cobra.Command, args []string) error {
	cfg := config.Load()
	engine := policy.NewEngine()

	if err := engine.LoadPolicies(cfg.CedarPoliciesPath); err != nil {
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
	cfg := config.Load()
	engine := policy.NewEngine()

	if err := engine.LoadPolicies(cfg.CedarPoliciesPath); err != nil {
		fmt.Printf("Validation FAILED: %v\n", err)
		os.Exit(1)
	}

	policies := engine.ListPolicies()
	fmt.Printf("Validated %d policies successfully\n", len(policies))
	return nil
}

func runPolicyTest(cmd *cobra.Command, args []string) error {
	policyID := args[0]
	assetFile := args[1]

	cfg := config.Load()
	engine := policy.NewEngine()

	if err := engine.LoadPolicies(cfg.CedarPoliciesPath); err != nil {
		return fmt.Errorf("load policies: %w", err)
	}

	p, ok := engine.GetPolicy(policyID)
	if !ok {
		return fmt.Errorf("policy not found: %s", policyID)
	}

	data, err := os.ReadFile(assetFile)
	if err != nil {
		return fmt.Errorf("read asset file: %w", err)
	}

	var asset map[string]interface{}
	if parseErr := json.Unmarshal(data, &asset); parseErr != nil {
		return fmt.Errorf("parse asset: %w", parseErr)
	}

	findings, err := engine.EvaluateAsset(cmd.Context(), asset)
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}

	fmt.Printf("Policy: %s\n", p.Name)
	fmt.Printf("Asset:  %s\n\n", assetFile)

	if len(findings) == 0 {
		fmt.Println("Result: PASS (no violations)")
	} else {
		fmt.Println("Result: FAIL")
		for _, f := range findings {
			fmt.Printf("  - %s\n", f.Description)
		}
	}

	return nil
}
