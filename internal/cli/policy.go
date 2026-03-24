package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	apiclient "github.com/writer/cerebro/internal/client"
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

var policyDiffCmd = &cobra.Command{
	Use:   "diff [policy-id] [candidate-file]",
	Short: "Preview semantic and behavioral impact of a policy change",
	Long: `Diff a candidate policy against the currently loaded version.

Optionally provide --assets with a JSON object/array to run a dry-run impact
analysis without persisting any findings.

Examples:
  cerebro policy diff aws-s3-no-public ./candidate.json
  cerebro policy diff aws-s3-no-public ./candidate.json --assets ./assets.json --output json`,
	Args: cobra.ExactArgs(2),
	RunE: runPolicyDiff,
}

var (
	policyValidateOutput string
	policyTestOutput     string
	policyDiffOutput     string
	policyDiffAssetFile  string
)

var runPolicyListDirectFn = runPolicyListDirect
var runPolicyValidateDirectFn = runPolicyValidateDirect
var runPolicyTestDirectFn = runPolicyTestDirect
var runPolicyDiffDirectFn = runPolicyDiffDirect

func init() {
	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyValidateCmd)
	policyCmd.AddCommand(policyTestCmd)
	policyCmd.AddCommand(policyDiffCmd)

	policyListCmd.Flags().StringVarP(&policyOutput, "output", "o", "table", "Output format (table,json,wide)")
	policyValidateCmd.Flags().StringVarP(&policyValidateOutput, "output", "o", "text", "Output format (text,json)")
	policyTestCmd.Flags().StringVarP(&policyTestOutput, "output", "o", "text", "Output format (text,json)")
	policyDiffCmd.Flags().StringVarP(&policyDiffOutput, "output", "o", "text", "Output format (text,json)")
	policyDiffCmd.Flags().StringVar(&policyDiffAssetFile, "assets", "", "Optional JSON asset fixture (object or array) for dry-run impact preview")
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
			policies, err := apiClient.ListPolicies(ctx, 0, 0)
			if err == nil {
				return renderPolicyList(policies)
			}
			if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, err) {
				return fmt.Errorf("list policies via api: %w", err)
			}
			Warning("API unavailable; using direct mode: %v", err)
		}
	}

	return runPolicyListDirectFn(cmd, args)
}

func runPolicyListDirect(cmd *cobra.Command, args []string) error {
	engine := policy.NewEngine()

	if err := engine.LoadPolicies(policiesPath()); err != nil {
		return fmt.Errorf("load policies: %w", err)
	}

	policies := engine.ListPolicies()
	return renderPolicyList(policies)
}

func renderPolicyList(policies []*policy.Policy) error {
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
	mode, err := loadCLIExecutionMode()
	if err != nil {
		return err
	}

	if mode != cliExecutionModeDirect {
		if apiErr := runPolicyValidateViaAPI(cmd); apiErr == nil {
			return nil
		} else if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, apiErr) {
			return fmt.Errorf("policy validate via api failed: %w", apiErr)
		} else {
			Warning("API unavailable; using direct mode: %v", apiErr)
		}
	}

	return runPolicyValidateDirectFn(cmd, args)
}

func runPolicyValidateViaAPI(cmd *cobra.Command) error {
	apiClient, err := newCLIAPIClient()
	if err != nil {
		return err
	}

	policies, err := apiClient.ListPolicies(commandContextOrBackground(cmd), 0, 0)
	if err != nil {
		return fmt.Errorf("list policies: %w", err)
	}

	return renderPolicyValidateResult(len(policies), summarizePolicySeverities(policies))
}

func runPolicyValidateDirect(cmd *cobra.Command, args []string) error {
	engine := policy.NewEngine()

	if err := engine.LoadPolicies(policiesPath()); err != nil {
		return renderPolicyValidateFailure(err)
	}

	policies := engine.ListPolicies()
	return renderPolicyValidateResult(len(policies), summarizePolicySeverities(policies))
}

func renderPolicyValidateFailure(err error) error {
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

func summarizePolicySeverities(policies []*policy.Policy) map[string]int {
	severityCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, p := range policies {
		if count, ok := severityCounts[p.Severity]; ok {
			severityCounts[p.Severity] = count + 1
		}
	}
	return severityCounts
}

func renderPolicyValidateResult(policyCount int, severityCounts map[string]int) error {
	if policyValidateOutput == FormatJSON {
		return JSONOutput(map[string]interface{}{
			"valid":           true,
			"count":           policyCount,
			"severity_counts": severityCounts,
		})
	}

	Success("Validated %d policies", policyCount)
	fmt.Printf("  Critical: %d, High: %d, Medium: %d, Low: %d\n",
		severityCounts["critical"], severityCounts["high"],
		severityCounts["medium"], severityCounts["low"])
	return nil
}

func runPolicyTest(cmd *cobra.Command, args []string) error {
	mode, err := loadCLIExecutionMode()
	if err != nil {
		return err
	}

	if mode != cliExecutionModeDirect {
		if apiErr := runPolicyTestViaAPI(cmd, args); apiErr == nil {
			return nil
		} else if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, apiErr) {
			return fmt.Errorf("policy test via api failed: %w", apiErr)
		} else {
			Warning("API unavailable; using direct mode: %v", apiErr)
		}
	}

	return runPolicyTestDirectFn(cmd, args)
}

func runPolicyTestViaAPI(cmd *cobra.Command, args []string) error {
	policyID := args[0]
	assetFile := args[1]

	asset, err := loadPolicyTestAsset(assetFile)
	if err != nil {
		return err
	}

	apiClient, err := newCLIAPIClient()
	if err != nil {
		return err
	}

	p, err := apiClient.GetPolicy(commandContextOrBackground(cmd), policyID)
	if err != nil {
		if apiclient.IsAPIErrorStatus(err, 404) {
			return fmt.Errorf("policy not found: %s", policyID)
		}
		return fmt.Errorf("get policy: %w", err)
	}

	dryRun, err := apiClient.DryRunPolicyChange(commandContextOrBackground(cmd), policyID, *p, []map[string]interface{}{asset}, 1)
	if err != nil {
		return fmt.Errorf("dry-run policy test: %w", err)
	}

	violations := []string{}
	if dryRun.Impact != nil && dryRun.Impact.AfterMatches > 0 {
		violations = append(violations, "policy conditions matched asset")
	}
	return renderPolicyTestResult(policyID, p.Name, assetFile, violations)
}

func runPolicyTestDirect(cmd *cobra.Command, args []string) error {
	policyID := args[0]
	assetFile := args[1]

	engine := policy.NewEngine()
	if err := engine.LoadPolicies(policiesPath()); err != nil {
		return fmt.Errorf("load policies: %w", err)
	}

	p, ok := engine.GetPolicy(policyID)
	if !ok {
		return fmt.Errorf("policy not found: %s", policyID)
	}

	asset, err := loadPolicyTestAsset(assetFile)
	if err != nil {
		return err
	}

	testFindings, err := engine.EvaluateAsset(cmd.Context(), asset)
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}

	violations := make([]string, 0, len(testFindings))
	for _, f := range testFindings {
		if strings.TrimSpace(f.PolicyID) != policyID {
			continue
		}
		violations = append(violations, f.Description)
	}

	return renderPolicyTestResult(policyID, p.Name, assetFile, violations)
}

func loadPolicyTestAsset(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- asset path is explicitly provided by the caller for policy testing
	if err != nil {
		return nil, fmt.Errorf("read asset file: %w", err)
	}

	var asset map[string]interface{}
	if err := json.Unmarshal(data, &asset); err != nil {
		return nil, fmt.Errorf("parse asset: %w", err)
	}
	return asset, nil
}

func renderPolicyTestResult(policyID, policyName, assetFile string, violations []string) error {
	passed := len(violations) == 0
	if policyTestOutput == FormatJSON {
		return JSONOutput(map[string]interface{}{
			"policy_id":  policyID,
			"policy":     policyName,
			"asset":      assetFile,
			"passed":     passed,
			"violations": violations,
		})
	}

	fmt.Printf("Policy: %s\n", policyName)
	fmt.Printf("Asset:  %s\n\n", assetFile)

	if passed {
		fmt.Println("Result: PASS (no violations)")
		return nil
	}

	fmt.Println("Result: FAIL")
	for _, violation := range violations {
		fmt.Printf("  - %s\n", violation)
	}
	return nil
}

func runPolicyDiff(cmd *cobra.Command, args []string) error {
	mode, err := loadCLIExecutionMode()
	if err != nil {
		return err
	}

	if mode != cliExecutionModeDirect {
		if err := runPolicyDiffViaAPI(cmd, args, mode); err == nil {
			return nil
		} else if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, err) {
			return err
		}
	}

	return runPolicyDiffDirectFn(cmd, args)
}

func runPolicyDiffViaAPI(cmd *cobra.Command, args []string, mode cliExecutionMode) error {
	ctx := commandContextOrBackground(cmd)
	policyID := strings.TrimSpace(args[0])
	candidatePath := strings.TrimSpace(args[1])
	if policyID == "" {
		return fmt.Errorf("policy id is required")
	}
	if candidatePath == "" {
		return fmt.Errorf("candidate file is required")
	}

	apiClient, err := newCLIAPIClient()
	if err != nil {
		return err
	}

	data, err := os.ReadFile(candidatePath) // #nosec G304 -- candidate policy path is explicitly provided by caller
	if err != nil {
		return fmt.Errorf("read candidate policy: %w", err)
	}
	var candidate policy.Policy
	if err := json.Unmarshal(data, &candidate); err != nil {
		return fmt.Errorf("parse candidate policy: %w", err)
	}
	candidate.ID = policyID

	var assets []map[string]interface{}
	if assetsPath := strings.TrimSpace(policyDiffAssetFile); assetsPath != "" {
		loaded, err := loadPolicyDiffAssets(assetsPath)
		if err != nil {
			return err
		}
		assets = loaded
	}

	dryRun, err := apiClient.DryRunPolicyChange(ctx, policyID, candidate, assets, 0)
	if err != nil {
		return fmt.Errorf("policy dry-run via api: %w", err)
	}

	response := map[string]interface{}{
		"policy_id":      policyID,
		"candidate_file": candidatePath,
		"changed":        dryRun.Diff.Changed,
		"diff":           dryRun.Diff,
	}

	if assetsPath := strings.TrimSpace(policyDiffAssetFile); assetsPath != "" {
		response["assets_file"] = assetsPath
	}
	if dryRun.Impact != nil {
		response["impact"] = dryRun.Impact
	}

	if policyDiffOutput == FormatJSON {
		return JSONOutput(response)
	}

	fmt.Printf("Policy: %s\n", policyID)
	fmt.Printf("Candidate: %s\n", candidatePath)
	if !dryRun.Diff.Changed {
		fmt.Println("Diff: no semantic changes")
	} else {
		fmt.Printf("Diff: %d changed fields\n", len(dryRun.Diff.FieldDiffs))
		for _, field := range dryRun.Diff.FieldDiffs {
			fmt.Printf("  - %s\n", field.Field)
		}
	}

	if impactAny, ok := response["impact"]; ok {
		impact := impactAny.(*policy.PolicyDryRunImpact)
		fmt.Println("\nDry-run impact:")
		fmt.Printf("  Assets:         %d\n", impact.AssetCount)
		fmt.Printf("  Matches before: %d\n", impact.BeforeMatches)
		fmt.Printf("  Matches after:  %d\n", impact.AfterMatches)
		fmt.Printf("  Added findings: %d\n", len(impact.AddedFindingIDs))
		fmt.Printf("  Removed findings: %d\n", len(impact.RemovedFindingIDs))
	}

	return nil
}

func runPolicyDiffDirect(cmd *cobra.Command, args []string) error {
	policyID := strings.TrimSpace(args[0])
	candidatePath := strings.TrimSpace(args[1])
	if policyID == "" {
		return fmt.Errorf("policy id is required")
	}
	if candidatePath == "" {
		return fmt.Errorf("candidate file is required")
	}

	engine := policy.NewEngine()
	if err := engine.LoadPolicies(policiesPath()); err != nil {
		return fmt.Errorf("load policies: %w", err)
	}

	current, ok := engine.GetPolicy(policyID)
	if !ok {
		return fmt.Errorf("policy not found: %s", policyID)
	}

	data, err := os.ReadFile(candidatePath) // #nosec G304 -- candidate policy path is explicitly provided by caller
	if err != nil {
		return fmt.Errorf("read candidate policy: %w", err)
	}
	var candidate policy.Policy
	if err := json.Unmarshal(data, &candidate); err != nil {
		return fmt.Errorf("parse candidate policy: %w", err)
	}
	candidate.ID = policyID

	diff := policy.DiffPolicies(current, &candidate)
	response := map[string]interface{}{
		"policy_id":      policyID,
		"candidate_file": candidatePath,
		"changed":        diff.Changed,
		"diff":           diff,
	}

	if assetsPath := strings.TrimSpace(policyDiffAssetFile); assetsPath != "" {
		assets, err := loadPolicyDiffAssets(assetsPath)
		if err != nil {
			return err
		}
		impact, err := engine.DryRunPolicyChange(cmd.Context(), current, &candidate, assets)
		if err != nil {
			return err
		}
		response["assets_file"] = assetsPath
		response["impact"] = impact
	}

	if policyDiffOutput == FormatJSON {
		return JSONOutput(response)
	}

	fmt.Printf("Policy: %s\n", policyID)
	fmt.Printf("Candidate: %s\n", candidatePath)
	if !diff.Changed {
		fmt.Println("Diff: no semantic changes")
	} else {
		fmt.Printf("Diff: %d changed fields\n", len(diff.FieldDiffs))
		for _, field := range diff.FieldDiffs {
			fmt.Printf("  - %s\n", field.Field)
		}
	}

	if impactAny, ok := response["impact"]; ok {
		impact := impactAny.(*policy.PolicyDryRunImpact)
		fmt.Println("\nDry-run impact:")
		fmt.Printf("  Assets:         %d\n", impact.AssetCount)
		fmt.Printf("  Matches before: %d\n", impact.BeforeMatches)
		fmt.Printf("  Matches after:  %d\n", impact.AfterMatches)
		fmt.Printf("  Added findings: %d\n", len(impact.AddedFindingIDs))
		fmt.Printf("  Removed findings: %d\n", len(impact.RemovedFindingIDs))
	}

	return nil
}

func loadPolicyDiffAssets(path string) ([]map[string]interface{}, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is explicitly provided by caller
	if err != nil {
		return nil, fmt.Errorf("read assets file: %w", err)
	}

	var list []map[string]interface{}
	if err := json.Unmarshal(data, &list); err == nil {
		return list, nil
	}

	var single map[string]interface{}
	if err := json.Unmarshal(data, &single); err == nil {
		return []map[string]interface{}{single}, nil
	}

	return nil, fmt.Errorf("assets file must contain a JSON object or array")
}
