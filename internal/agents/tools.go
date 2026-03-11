package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/scm"
	"github.com/writer/cerebro/internal/snowflake"
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

func cloudInspectEnabled() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("CEREBRO_CLOUD_INSPECT_ENABLED")))
	switch raw {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
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
			Name:        "aws_inspect",
			Description: "Inspect AWS resources using live API calls (read-only)",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"service": map[string]interface{}{
						"type":        "string",
						"description": "AWS Service (s3, lambda, ecs, iam)",
						"enum":        []string{"s3", "lambda", "ecs", "iam"},
					},
					"action": map[string]interface{}{
						"type":        "string",
						"description": "Action to perform (e.g., list-buckets, get-function)",
					},
					"params": map[string]interface{}{
						"type":        "object",
						"description": "Parameters for the action (e.g., Bucket for s3:list-objects)",
					},
				},
				"required": []string{"service", "action"},
			},
			Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
				if !cloudInspectEnabled() {
					return "", fmt.Errorf("direct cloud inspection is disabled by default; set CEREBRO_CLOUD_INSPECT_ENABLED=true to enable")
				}
				return st.awsInspect(ctx, args)
			},
		},
		{
			Name:        "gcp_inspect",
			Description: "Inspect GCP resources using live API calls (read-only)",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"service": map[string]interface{}{
						"type":        "string",
						"description": "GCP Service (storage, compute, iam, resourcemanager)",
						"enum":        []string{"storage", "compute", "iam", "resourcemanager"},
					},
					"action": map[string]interface{}{
						"type":        "string",
						"description": "Action to perform (e.g., list-buckets, list-instances)",
					},
					"project": map[string]interface{}{
						"type":        "string",
						"description": "GCP Project ID",
					},
					"params": map[string]interface{}{
						"type":        "object",
						"description": "Parameters for the action (e.g., zone for compute)",
					},
				},
				"required": []string{"service", "action", "project"},
			},
			Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
				if !cloudInspectEnabled() {
					return "", fmt.Errorf("direct cloud inspection is disabled by default; set CEREBRO_CLOUD_INSPECT_ENABLED=true to enable")
				}
				return st.gcpInspect(ctx, args)
			},
		},
		{
			Name:        "inspect_cloud_resource",
			Description: "Inspect a specific cloud resource by identifier (auto-detects AWS or GCP)",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"resource": map[string]interface{}{
						"type":        "string",
						"description": "Resource identifier (ARN, s3://bucket, gs://bucket, etc.)",
					},
					"provider": map[string]interface{}{
						"type":        "string",
						"description": "Optional override for provider (aws or gcp)",
						"enum":        []string{"aws", "gcp"},
					},
					"service": map[string]interface{}{
						"type":        "string",
						"description": "Optional override for service (s3, lambda, ecs, iam, storage, compute, resourcemanager)",
					},
					"identifier": map[string]interface{}{
						"type":        "string",
						"description": "Optional override for resource identifier",
					},
					"account": map[string]interface{}{
						"type":        "string",
						"description": "AWS account ID for cross-account inspection (used when resource identifier does not contain an account, e.g. s3://bucket)",
					},
					"project": map[string]interface{}{
						"type":        "string",
						"description": "GCP project ID (required for GCP inspection unless encoded in resource)",
					},
					"region": map[string]interface{}{
						"type":        "string",
						"description": "AWS region override",
					},
					"cluster": map[string]interface{}{
						"type":        "string",
						"description": "ECS cluster name for service inspection",
					},
					"zone": map[string]interface{}{
						"type":        "string",
						"description": "GCP zone for compute instance inspection",
					},
					"action": map[string]interface{}{
						"type":        "string",
						"description": "Optional action override (runs single action instead of full inspection)",
					},
					"params": map[string]interface{}{
						"type":        "object",
						"description": "Parameters for action override",
					},
				},
				"required": []string{"resource"},
			},
			Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
				if !cloudInspectEnabled() {
					return "", fmt.Errorf("direct cloud inspection is disabled by default; set CEREBRO_CLOUD_INSPECT_ENABLED=true to enable")
				}
				return st.inspectCloudResource(ctx, args)
			},
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
					"timeout_seconds": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum query execution time in seconds (1-60, default 15)",
						"default":     15,
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
					"signal_type": map[string]interface{}{
						"type":        "string",
						"description": "Filter by signal type (security, business, operational, compliance)",
					},
					"domain": map[string]interface{}{
						"type":        "string",
						"description": "Filter by signal domain (infra, revenue, customer_health, pipeline, sla, financial)",
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
		Query          string `json:"query"`
		Limit          int    `json:"limit"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", err
	}

	boundedQuery, boundedLimit, err := snowflake.BuildReadOnlyLimitedQuery(params.Query, params.Limit)
	if err != nil {
		return "", err
	}

	if st.snowflake == nil {
		return "", fmt.Errorf("snowflake not configured")
	}

	queryCtx, cancel := context.WithTimeout(ctx, snowflake.ClampReadOnlyQueryTimeout(params.TimeoutSeconds))
	defer cancel()

	result, err := st.snowflake.Query(queryCtx, boundedQuery)
	if err != nil {
		return "", err
	}

	if result != nil && result.Count > boundedLimit {
		result.Rows = result.Rows[:boundedLimit]
		result.Count = len(result.Rows)
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
		Severity   string `json:"severity"`
		Status     string `json:"status"`
		PolicyID   string `json:"policy_id"`
		SignalType string `json:"signal_type"`
		Domain     string `json:"domain"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", err
	}

	list := st.findings.List(findings.FindingFilter{
		Severity:   params.Severity,
		Status:     params.Status,
		PolicyID:   params.PolicyID,
		SignalType: params.SignalType,
		Domain:     params.Domain,
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

	analysis, err := st.analyzeRepository(ctx, params.RepoURL)
	if err != nil {
		return "", err
	}

	output, _ := json.MarshalIndent(analysis, "", "  ")
	return string(output), nil
}

func (st *SecurityTools) analyzeRepository(ctx context.Context, repoURL string) (*RepoAnalysis, error) {
	if st.scm == nil {
		return nil, fmt.Errorf("SCM integration not configured")
	}

	// Temporary workspace for cloning
	tempDir, err := os.MkdirTemp("", "cerebro-repo-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	if cloneErr := st.scm.Clone(ctx, repoURL, tempDir); cloneErr != nil {
		return nil, fmt.Errorf("failed to clone repo: %w", cloneErr)
	}

	analysis, err := scanRepositoryForResources(tempDir, repoURL)
	if err != nil {
		return nil, err
	}

	return analysis, nil
}

func (st *SecurityTools) AnalyzeRepository(ctx context.Context, repoURL string) (*RepoAnalysis, error) {
	return st.analyzeRepository(ctx, repoURL)
}
