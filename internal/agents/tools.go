package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/writerinternal/cerebro/internal/findings"
	"github.com/writerinternal/cerebro/internal/policy"
	"github.com/writerinternal/cerebro/internal/scm"
	"github.com/writerinternal/cerebro/internal/snowflake"
)

// SecurityTools provides investigation tools for agents
type SecurityTools struct {
	snowflake *snowflake.Client
	findings  findings.FindingStore
	policies  *policy.Engine
	scm       scm.Client
}

func NewSecurityTools(sf *snowflake.Client, fs findings.FindingStore, pe *policy.Engine, sc scm.Client) *SecurityTools {
	return &SecurityTools{
		snowflake: sf,
		findings:  fs,
		policies:  pe,
		scm:       sc,
	}
}

func (st *SecurityTools) GetTools() []Tool {
	return []Tool{
		{
			Name:        "analyze_repo",
			Description: "Clone and analyze a source code repository for security vulnerabilities",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"repo_url": map[string]interface{}{
						"type":        "string",
						"description": "URL of the repository to analyze",
					},
					"file_path": map[string]interface{}{
						"type":        "string",
						"description": "Specific file path to read (optional)",
					},
				},
				"required": []string{"repo_url"},
			},
			Handler: st.analyzeRepo,
		},
		{
			Name:        "query_assets",
			Description: "Query cloud assets from the security data lake using SQL",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "SQL query to execute against the asset database",
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of results to return",
						"default":     100,
					},
				},
				"required": []string{"query"},
			},
			Handler: st.queryAssets,
		},
		{
			Name:        "get_finding",
			Description: "Get details about a specific security finding",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"finding_id": map[string]interface{}{
						"type":        "string",
						"description": "The ID of the finding to retrieve",
					},
				},
				"required": []string{"finding_id"},
			},
			Handler: st.getFinding,
		},
		{
			Name:        "list_findings",
			Description: "List security findings with optional filters",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"severity": map[string]interface{}{
						"type":        "string",
						"description": "Filter by severity (critical, high, medium, low)",
					},
					"status": map[string]interface{}{
						"type":        "string",
						"description": "Filter by status (open, resolved, suppressed)",
					},
					"policy_id": map[string]interface{}{
						"type":        "string",
						"description": "Filter by policy ID",
					},
				},
			},
			Handler: st.listFindings,
		},
		{
			Name:        "get_asset_context",
			Description: "Get contextual information about an asset including related resources",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"asset_type": map[string]interface{}{
						"type":        "string",
						"description": "The type of asset (e.g., aws_s3_buckets, aws_iam_users)",
					},
					"asset_id": map[string]interface{}{
						"type":        "string",
						"description": "The ID of the asset",
					},
				},
				"required": []string{"asset_type", "asset_id"},
			},
			Handler: st.getAssetContext,
		},
		{
			Name:        "evaluate_policy",
			Description: "Evaluate a security policy against a specific asset",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"policy_id": map[string]interface{}{
						"type":        "string",
						"description": "The policy to evaluate",
					},
					"asset": map[string]interface{}{
						"type":        "object",
						"description": "The asset data to evaluate",
					},
				},
				"required": []string{"policy_id", "asset"},
			},
			Handler: st.evaluatePolicy,
		},
		{
			Name:             "resolve_finding",
			Description:      "Mark a finding as resolved",
			RequiresApproval: true,
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"finding_id": map[string]interface{}{
						"type":        "string",
						"description": "The ID of the finding to resolve",
					},
					"reason": map[string]interface{}{
						"type":        "string",
						"description": "Reason for resolving the finding",
					},
				},
				"required": []string{"finding_id", "reason"},
			},
			Handler: st.resolveFinding,
		},
		{
			Name:             "create_ticket",
			Description:      "Create a ticket in the integrated ticketing system",
			RequiresApproval: true,
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"title": map[string]interface{}{
						"type":        "string",
						"description": "Ticket title",
					},
					"description": map[string]interface{}{
						"type":        "string",
						"description": "Ticket description",
					},
					"priority": map[string]interface{}{
						"type":        "string",
						"description": "Ticket priority (critical, high, medium, low)",
					},
					"finding_ids": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Associated finding IDs",
					},
				},
				"required": []string{"title", "description"},
			},
			Handler: st.createTicket,
		},
	}
}

func (st *SecurityTools) queryAssets(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Query string `json:"query"`
		Limit int    `json:"limit"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", err
	}

	if st.snowflake == nil {
		return "", fmt.Errorf("snowflake not configured")
	}

	result, err := st.snowflake.Query(ctx, params.Query)
	if err != nil {
		return "", err
	}

	output, _ := json.Marshal(result)
	return string(output), nil
}

func (st *SecurityTools) getFinding(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		FindingID string `json:"finding_id"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", err
	}

	finding, ok := st.findings.Get(params.FindingID)
	if !ok {
		return "", fmt.Errorf("finding not found: %s", params.FindingID)
	}

	output, _ := json.Marshal(finding)
	return string(output), nil
}

func (st *SecurityTools) listFindings(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Severity string `json:"severity"`
		Status   string `json:"status"`
		PolicyID string `json:"policy_id"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", err
	}

	list := st.findings.List(findings.FindingFilter{
		Severity: params.Severity,
		Status:   params.Status,
		PolicyID: params.PolicyID,
	})

	output, _ := json.Marshal(list)
	return string(output), nil
}

func (st *SecurityTools) getAssetContext(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		AssetType string `json:"asset_type"`
		AssetID   string `json:"asset_id"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", err
	}

	if st.snowflake == nil {
		return "", fmt.Errorf("snowflake not configured")
	}

	asset, err := st.snowflake.GetAssetByID(ctx, params.AssetType, params.AssetID)
	if err != nil {
		return "", err
	}

	output, _ := json.Marshal(asset)
	return string(output), nil
}

func (st *SecurityTools) evaluatePolicy(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		PolicyID string                 `json:"policy_id"`
		Asset    map[string]interface{} `json:"asset"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", err
	}

	findings, err := st.policies.EvaluateAsset(ctx, params.Asset)
	if err != nil {
		return "", err
	}

	output, _ := json.Marshal(findings)
	return string(output), nil
}

func (st *SecurityTools) resolveFinding(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		FindingID string `json:"finding_id"`
		Reason    string `json:"reason"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", err
	}

	if st.findings.Resolve(params.FindingID) {
		return fmt.Sprintf("Finding %s resolved: %s", params.FindingID, params.Reason), nil
	}
	return "", fmt.Errorf("finding not found: %s", params.FindingID)
}

func (st *SecurityTools) createTicket(ctx context.Context, args json.RawMessage) (string, error) {
	// This will be implemented with ticketing integration
	return "Ticket creation requires ticketing integration to be configured", nil
}

func (st *SecurityTools) analyzeRepo(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		RepoURL  string `json:"repo_url"`
		FilePath string `json:"file_path"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", err
	}

	if st.scm == nil {
		return "", fmt.Errorf("SCM integration not configured")
	}

	// Temporary workspace for cloning
	tempDir, err := os.MkdirTemp("", "cerebro-repo-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Clone the repo (or simulate cloning)
	if err := st.scm.Clone(ctx, params.RepoURL, tempDir); err != nil {
		return "", fmt.Errorf("failed to clone repo: %w", err)
	}

	// If specific file requested, return content
	if params.FilePath != "" {
		content, err := st.scm.GetFileContent(ctx, params.RepoURL, params.FilePath)
		if err != nil {
			return "", err
		}
		// Truncate if too long
		if len(content) > 10000 {
			content = content[:10000] + "...(truncated)"
		}
		return fmt.Sprintf("File content for %s:\n%s", params.FilePath, content), nil
	}

	return fmt.Sprintf("Repository %s is accessible. Use file_path to read specific files.", params.RepoURL), nil
}
