package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/agentsdk"
	"github.com/writer/cerebro/internal/app"
)

const (
	goSDKPath        = "sdk/go/cerebro/client.go"
	pythonInitPath   = "sdk/python/cerebro_sdk/__init__.py"
	pythonClientPath = "sdk/python/cerebro_sdk/client.py"
	pythonPyproject  = "sdk/python/pyproject.toml"
	tsIndexPath      = "sdk/typescript/src/index.ts"
	tsPackagePath    = "sdk/typescript/package.json"
	tsConfigPath     = "sdk/typescript/tsconfig.json"
	docsPath         = "docs/AGENT_SDK_PACKAGES_AUTOGEN.md"
	backtickToken    = "__BACKTICK__"
)

type templateData struct {
	Catalog        agentsdk.Catalog
	MethodBindings []methodBinding
	PythonAll      []string
}

type methodBinding struct {
	ToolID       string
	SDKMethod    string
	GoMethodName string
	PythonName   string
	TSMethodName string
	Description  string
}

func main() {
	catalog := agentsdk.BuildCatalog(agentSDKTools(), agentsdk.ZeroGeneratedAt())
	bindings := buildMethodBindings(catalog)

	data := templateData{
		Catalog:        catalog,
		MethodBindings: bindings,
		PythonAll:      []string{"APIError", "Client"},
	}

	mustWriteTemplate(goSDKPath, goSDKTemplate, data)
	mustWrite(pythonInitPath, renderPythonInit(data.PythonAll))
	mustWriteTemplate(pythonClientPath, pythonSDKTemplate, data)
	mustWrite(pythonPyproject, pythonPyprojectTOML)
	mustWriteTemplate(tsIndexPath, tsSDKTemplate, data)
	mustWrite(tsPackagePath, tsPackageJSON)
	mustWrite(tsConfigPath, tsConfigJSON)
	mustWrite(docsPath, renderDocs(data))
}

func agentSDKTools() []agents.Tool {
	application := &app.App{Config: &app.Config{}}
	return application.AgentSDKTools()
}

func buildMethodBindings(catalog agentsdk.Catalog) []methodBinding {
	counts := make(map[string]int)
	for _, tool := range catalog.Tools {
		name := normalizeMethodName(tool.SDKMethod)
		if name == "" {
			name = normalizeMethodName(strings.TrimPrefix(tool.ID, "cerebro_"))
		}
		counts[name]++
	}
	bindings := make([]methodBinding, 0, len(catalog.Tools))
	seen := make(map[string]int)
	used := make(map[string]struct{})
	for _, tool := range catalog.Tools {
		base := normalizeMethodName(tool.SDKMethod)
		if base == "" {
			base = normalizeMethodName(strings.TrimPrefix(tool.ID, "cerebro_"))
		}
		if base == "" {
			base = normalizeMethodName(tool.ID)
		}
		name := base
		if counts[base] > 1 {
			seen[base]++
			name = normalizeMethodName(strings.TrimPrefix(tool.ID, "cerebro_"))
			if name == "" {
				name = fmt.Sprintf("%s_%d", base, seen[base])
			}
		}
		name = uniqueMethodBindingName(name, base, used)
		bindings = append(bindings, methodBinding{
			ToolID:       tool.ID,
			SDKMethod:    firstNonEmpty(tool.SDKMethod, name),
			GoMethodName: goExportedName(name),
			PythonName:   pythonName(name),
			TSMethodName: tsMethodName(name),
			Description:  strings.TrimSpace(tool.Description),
		})
	}
	sort.Slice(bindings, func(i, j int) bool {
		return bindings[i].ToolID < bindings[j].ToolID
	})
	return bindings
}

func uniqueMethodBindingName(name, fallback string, used map[string]struct{}) string {
	name = normalizeMethodName(name)
	if name == "" {
		name = normalizeMethodName(fallback)
	}
	if name == "" {
		name = "invoke"
	}
	candidate := name
	for i := 2; ; i++ {
		if _, exists := used[candidate]; !exists {
			used[candidate] = struct{}{}
			return candidate
		}
		candidate = fmt.Sprintf("%s_%d", name, i)
	}
}

func normalizeMethodName(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	var b strings.Builder
	lastUnderscore := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastUnderscore = false
		default:
			if !lastUnderscore {
				b.WriteRune('_')
				lastUnderscore = true
			}
		}
	}
	return strings.Trim(b.String(), "_")
}

func goExportedName(value string) string {
	parts := strings.Split(normalizeMethodName(value), "_")
	var b strings.Builder
	for _, part := range parts {
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]))
		if len(part) > 1 {
			b.WriteString(part[1:])
		}
	}
	if b.Len() == 0 {
		return "Invoke"
	}
	return b.String()
}

func pythonName(value string) string {
	name := normalizeMethodName(value)
	if name == "" {
		return "invoke"
	}
	return name
}

func tsMethodName(value string) string {
	parts := strings.Split(normalizeMethodName(value), "_")
	if len(parts) == 0 {
		return "invoke"
	}
	first := parts[0]
	var b strings.Builder
	b.WriteString(first)
	for _, part := range parts[1:] {
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]))
		if len(part) > 1 {
			b.WriteString(part[1:])
		}
	}
	name := b.String()
	if name == "" {
		return "invoke"
	}
	return name
}

func renderPythonInit(values []string) string {
	var b strings.Builder
	b.WriteString("from .client import APIError, Client\n\n")
	b.WriteString("__all__ = [\n")
	for _, value := range values {
		fmt.Fprintf(&b, "    %q,\n", value)
	}
	b.WriteString("]\n")
	return b.String()
}

func renderDocs(data templateData) string {
	var b strings.Builder
	b.WriteString("# Agent SDK Package Auto-Generation\n\n")
	b.WriteString("Generated from `docs/AGENT_SDK_CONTRACTS.json` via `go run ./scripts/generate_agent_sdk_packages/main.go`.\n\n")
	fmt.Fprintf(&b, "- Tool bindings: **%d**\n", len(data.MethodBindings))
	b.WriteString("- Package paths:\n")
	b.WriteString("  - `sdk/go/cerebro`\n")
	b.WriteString("  - `sdk/python/cerebro_sdk`\n")
	b.WriteString("  - `sdk/python/pyproject.toml`\n")
	b.WriteString("  - `sdk/typescript`\n\n")
	b.WriteString("## Convenience Methods\n\n")
	b.WriteString("| Tool ID | Go | Python | TypeScript |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, binding := range data.MethodBindings {
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` |\n", binding.ToolID, binding.GoMethodName, binding.PythonName, binding.TSMethodName)
	}
	b.WriteString("\n## Notes\n\n")
	b.WriteString("- The generated SDKs keep a single generic tool-call surface plus per-tool convenience methods.\n")
	b.WriteString("- Report run streaming is exposed for both MCP and platform report SSE endpoints.\n")
	b.WriteString("- Admin SDK credential lifecycle methods target the managed `/api/v1/admin/agent-sdk/credentials*` surface.\n")
	return b.String()
}

func mustWriteTemplate(path, tmpl string, data templateData) {
	parsed := template.Must(template.New(filepath.Base(path)).Parse(strings.ReplaceAll(tmpl, backtickToken, "`")))
	var buf bytes.Buffer
	if err := parsed.Execute(&buf, data); err != nil {
		fatalf("render %s: %v", path, err)
	}
	mustWrite(path, buf.String())
}

func mustWrite(path, content string) {
	// #nosec G301 -- generated SDK/docs directories are checked into the repo and should remain readable.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fatalf("create dir for %s: %v", path, err)
	}
	// #nosec G306 -- generated SDK/docs files are repository artifacts, not secret material.
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		fatalf("write %s: %v", path, err)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

const goSDKTemplate = `package cerebro

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ClientConfig struct {
	BaseURL    string
	APIKey     string
	Timeout    time.Duration
	UserAgent  string
	HTTPClient *http.Client
}

type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
	apiKey     string
	userAgent  string
}

type APIError struct {
	StatusCode int    ` + "`json:\"-\"`" + `
	Message    string ` + "`json:\"error\"`" + `
	Code       string ` + "`json:\"code,omitempty\"`" + `
}

func (e *APIError) Error() string {
	message := strings.TrimSpace(e.Message)
	if message == "" {
		message = http.StatusText(e.StatusCode)
	}
	if strings.TrimSpace(e.Code) == "" {
		return fmt.Sprintf("api request failed (%d): %s", e.StatusCode, message)
	}
	return fmt.Sprintf("api request failed (%d %s): %s", e.StatusCode, e.Code, message)
}

type ToolDefinition struct {
	ID                 string         ` + "`json:\"id\"`" + `
	Version            string         ` + "`json:\"version\"`" + `
	ToolName           string         ` + "`json:\"tool_name\"`" + `
	SDKMethod          string         ` + "`json:\"sdk_method,omitempty\"`" + `
	Title              string         ` + "`json:\"title,omitempty\"`" + `
	Description        string         ` + "`json:\"description\"`" + `
	Category           string         ` + "`json:\"category,omitempty\"`" + `
	HTTPMethod         string         ` + "`json:\"http_method,omitempty\"`" + `
	HTTPPath           string         ` + "`json:\"http_path,omitempty\"`" + `
	RequiredPermission string         ` + "`json:\"required_permission,omitempty\"`" + `
	InputSchema        map[string]any ` + "`json:\"input_schema,omitempty\"`" + `
	ExampleInput       map[string]any ` + "`json:\"example_input,omitempty\"`" + `
	RequiresApproval   bool           ` + "`json:\"requires_approval,omitempty\"`" + `
	ExecutionKind      string         ` + "`json:\"execution_kind,omitempty\"`" + `
	SupportsAsync      bool           ` + "`json:\"supports_async,omitempty\"`" + `
	SupportsProgress   bool           ` + "`json:\"supports_progress,omitempty\"`" + `
	StatusResource     string         ` + "`json:\"status_resource,omitempty\"`" + `
}

type ToolCallResponse struct {
	ToolID           string ` + "`json:\"tool_id\"`" + `
	ToolName         string ` + "`json:\"tool_name,omitempty\"`" + `
	SDKMethod        string ` + "`json:\"sdk_method,omitempty\"`" + `
	Result           any    ` + "`json:\"result,omitempty\"`" + `
	RawResult        any    ` + "`json:\"raw_result,omitempty\"`" + `
	InvokedAt        string ` + "`json:\"invoked_at,omitempty\"`" + `
	Approval         bool   ` + "`json:\"approval,omitempty\"`" + `
	HTTPMethod       string ` + "`json:\"http_method,omitempty\"`" + `
	HTTPPath         string ` + "`json:\"http_path,omitempty\"`" + `
	ExecutionKind    string ` + "`json:\"execution_kind,omitempty\"`" + `
	SupportsAsync    bool   ` + "`json:\"supports_async,omitempty\"`" + `
	SupportsProgress bool   ` + "`json:\"supports_progress,omitempty\"`" + `
	StatusResource   string ` + "`json:\"status_resource,omitempty\"`" + `
}

type ReportParameterValue struct {
	Name           string     ` + "`json:\"name\"`" + `
	StringValue    string     ` + "`json:\"string_value,omitempty\"`" + `
	IntegerValue   *int64     ` + "`json:\"integer_value,omitempty\"`" + `
	NumberValue    *float64   ` + "`json:\"number_value,omitempty\"`" + `
	BooleanValue   *bool      ` + "`json:\"boolean_value,omitempty\"`" + `
	TimestampValue *time.Time ` + "`json:\"timestamp_value,omitempty\"`" + `
}

type ReportRetryPolicy struct {
	MaxAttempts   int   ` + "`json:\"max_attempts,omitempty\"`" + `
	BaseBackoffMS int64 ` + "`json:\"base_backoff_ms,omitempty\"`" + `
	MaxBackoffMS  int64 ` + "`json:\"max_backoff_ms,omitempty\"`" + `
}

type ReportRequest struct {
	ReportID          string                 ` + "`json:\"report_id,omitempty\"`" + `
	ExecutionMode     string                 ` + "`json:\"execution_mode,omitempty\"`" + `
	MaterializeResult *bool                  ` + "`json:\"materialize_result,omitempty\"`" + `
	Parameters        []ReportParameterValue ` + "`json:\"parameters,omitempty\"`" + `
	RetryPolicy       *ReportRetryPolicy     ` + "`json:\"retry_policy,omitempty\"`" + `
}

type ReportSectionResult struct {
	Key             string                        ` + "`json:\"key\"`" + `
	Title           string                        ` + "`json:\"title\"`" + `
	Kind            string                        ` + "`json:\"kind\"`" + `
	EnvelopeKind    string                        ` + "`json:\"envelope_kind,omitempty\"`" + `
	Present         bool                          ` + "`json:\"present\"`" + `
	ContentType     string                        ` + "`json:\"content_type,omitempty\"`" + `
	ItemCount       int                           ` + "`json:\"item_count,omitempty\"`" + `
	FieldCount      int                           ` + "`json:\"field_count,omitempty\"`" + `
	FieldKeys       []string                      ` + "`json:\"field_keys,omitempty\"`" + `
	MeasureIDs      []string                      ` + "`json:\"measure_ids,omitempty\"`" + `
	Lineage         *ReportSectionLineage         ` + "`json:\"lineage,omitempty\"`" + `
	Materialization *ReportSectionMaterialization ` + "`json:\"materialization,omitempty\"`" + `
	Telemetry       *ReportSectionTelemetry       ` + "`json:\"telemetry,omitempty\"`" + `
}

type ReportSectionLineage struct {
	ReferencedNodeCount int       ` + "`json:\"referenced_node_count,omitempty\"`" + `
	ReferencedNodeIDs   []string  ` + "`json:\"referenced_node_ids,omitempty\"`" + `
	ClaimCount          int       ` + "`json:\"claim_count,omitempty\"`" + `
	ClaimIDs            []string  ` + "`json:\"claim_ids,omitempty\"`" + `
	EvidenceCount       int       ` + "`json:\"evidence_count,omitempty\"`" + `
	EvidenceIDs         []string  ` + "`json:\"evidence_ids,omitempty\"`" + `
	SourceCount         int       ` + "`json:\"source_count,omitempty\"`" + `
	SourceIDs           []string  ` + "`json:\"source_ids,omitempty\"`" + `
	SupportingEdgeCount int       ` + "`json:\"supporting_edge_count,omitempty\"`" + `
	SupportingEdgeIDs   []string  ` + "`json:\"supporting_edge_ids,omitempty\"`" + `
	ValidAt             *time.Time ` + "`json:\"valid_at,omitempty\"`" + `
	RecordedAt          *time.Time ` + "`json:\"recorded_at,omitempty\"`" + `
	IDsTruncated        bool      ` + "`json:\"ids_truncated,omitempty\"`" + `
}

type ReportSectionMaterialization struct {
	Truncated         bool     ` + "`json:\"truncated,omitempty\"`" + `
	TruncationSignals []string ` + "`json:\"truncation_signals,omitempty\"`" + `
}

type ReportSectionTelemetry struct {
	MaterializationDurationMS int64  ` + "`json:\"materialization_duration_ms\"`" + `
	CacheStatus              string ` + "`json:\"cache_status,omitempty\"`" + `
	CacheSourceRunID         string ` + "`json:\"cache_source_run_id,omitempty\"`" + `
	RetryBackoffMS           int64  ` + "`json:\"retry_backoff_ms,omitempty\"`" + `
}

type ReportSectionEmission struct {
	Sequence        int                 ` + "`json:\"sequence\"`" + `
	EmittedAt       time.Time           ` + "`json:\"emitted_at\"`" + `
	ProgressPercent int                 ` + "`json:\"progress_percent,omitempty\"`" + `
	Section         ReportSectionResult ` + "`json:\"section\"`" + `
	Payload         any                 ` + "`json:\"payload,omitempty\"`" + `
}

type ReportStreamEvent struct {
	Type      string                 ` + "`json:\"type\"`" + `
	RunID     string                 ` + "`json:\"run_id\"`" + `
	ReportID  string                 ` + "`json:\"report_id\"`" + `
	Status    string                 ` + "`json:\"status,omitempty\"`" + `
	EventType string                 ` + "`json:\"event_type,omitempty\"`" + `
	Timestamp time.Time              ` + "`json:\"timestamp\"`" + `
	Progress  int                    ` + "`json:\"progress,omitempty\"`" + `
	Data      map[string]any         ` + "`json:\"data,omitempty\"`" + `
	Section   *ReportSectionEmission ` + "`json:\"section,omitempty\"`" + `
}

type ReportRun struct {
	ID               string                ` + "`json:\"id\"`" + `
	ReportID         string                ` + "`json:\"report_id\"`" + `
	Status           string                ` + "`json:\"status\"`" + `
	ExecutionMode    string                ` + "`json:\"execution_mode\"`" + `
	CacheStatus      string                ` + "`json:\"cache_status,omitempty\"`" + `
	CacheSourceRunID string                ` + "`json:\"cache_source_run_id,omitempty\"`" + `
	StatusURL        string                ` + "`json:\"status_url\"`" + `
	Sections         []ReportSectionResult ` + "`json:\"sections,omitempty\"`" + `
	Result           map[string]any        ` + "`json:\"result,omitempty\"`" + `
	Error            string                ` + "`json:\"error,omitempty\"`" + `
}

type ProtectedResourceMetadata struct {
	Resource               string   ` + "`json:\"resource\"`" + `
	AuthorizationServers   []string ` + "`json:\"authorization_servers,omitempty\"`" + `
	ScopesSupported        []string ` + "`json:\"scopes_supported,omitempty\"`" + `
	BearerMethodsSupported []string ` + "`json:\"bearer_methods_supported,omitempty\"`" + `
	ResourceDocumentation  string   ` + "`json:\"resource_documentation,omitempty\"`" + `
	AgentSDKEndpoint       string   ` + "`json:\"agent_sdk_endpoint,omitempty\"`" + `
	MCPEndpoint            string   ` + "`json:\"mcp_endpoint,omitempty\"`" + `
	MCPProtocolVersion     string   ` + "`json:\"mcp_protocol_version,omitempty\"`" + `
}

type ManagedCredential struct {
	ID               string            ` + "`json:\"id\"`" + `
	Name             string            ` + "`json:\"name,omitempty\"`" + `
	UserID           string            ` + "`json:\"user_id,omitempty\"`" + `
	Kind             string            ` + "`json:\"kind,omitempty\"`" + `
	Surface          string            ` + "`json:\"surface,omitempty\"`" + `
	ClientID         string            ` + "`json:\"client_id,omitempty\"`" + `
	Scopes           []string          ` + "`json:\"scopes,omitempty\"`" + `
	RateLimitBucket  string            ` + "`json:\"rate_limit_bucket,omitempty\"`" + `
	TenantID         string            ` + "`json:\"tenant_id,omitempty\"`" + `
	Enabled          bool              ` + "`json:\"enabled\"`" + `
	Metadata         map[string]string ` + "`json:\"metadata,omitempty\"`" + `
	Managed          bool              ` + "`json:\"managed\"`" + `
	Mutable          bool              ` + "`json:\"mutable\"`" + `
	CreatedAt        *time.Time        ` + "`json:\"created_at,omitempty\"`" + `
	RotatedAt        *time.Time        ` + "`json:\"rotated_at,omitempty\"`" + `
	RevokedAt        *time.Time        ` + "`json:\"revoked_at,omitempty\"`" + `
	ExpiresAt        *time.Time        ` + "`json:\"expires_at,omitempty\"`" + `
	RevocationReason string            ` + "`json:\"revocation_reason,omitempty\"`" + `
	SecretPreview    string            ` + "`json:\"secret_preview,omitempty\"`" + `
}

type ManagedCredentialCollection struct {
	Count       int                 ` + "`json:\"count\"`" + `
	Credentials []ManagedCredential ` + "`json:\"credentials\"`" + `
}

type ManagedCredentialSecretResponse struct {
	Credential ManagedCredential ` + "`json:\"credential\"`" + `
	APIKey     string            ` + "`json:\"api_key\"`" + `
}

type MCPRequest struct {
	JSONRPC string          ` + "`json:\"jsonrpc\"`" + `
	ID      any             ` + "`json:\"id,omitempty\"`" + `
	Method  string          ` + "`json:\"method\"`" + `
	Params  json.RawMessage ` + "`json:\"params,omitempty\"`" + `
}

type MCPError struct {
	Code    int    ` + "`json:\"code\"`" + `
	Message string ` + "`json:\"message\"`" + `
}

type MCPResponse struct {
	JSONRPC string         ` + "`json:\"jsonrpc\"`" + `
	ID      any            ` + "`json:\"id,omitempty\"`" + `
	Result  any            ` + "`json:\"result,omitempty\"`" + `
	Error   *MCPError      ` + "`json:\"error,omitempty\"`" + `
	Method  string         ` + "`json:\"method,omitempty\"`" + `
	Params  map[string]any ` + "`json:\"params,omitempty\"`" + `
}

func NewClient(cfg ClientConfig) (*Client, error) {
	baseURL := strings.TrimSpace(cfg.BaseURL)
	if baseURL == "" {
		return nil, fmt.Errorf("base URL is required")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid base URL %q", baseURL)
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	} else if httpClient.Timeout <= 0 {
		httpClient.Timeout = timeout
	}
	userAgent := strings.TrimSpace(cfg.UserAgent)
	if userAgent == "" {
		userAgent = "cerebro-sdk-go"
	}
	return &Client{baseURL: parsed, httpClient: httpClient, apiKey: strings.TrimSpace(cfg.APIKey), userAgent: userAgent}, nil
}

func (c *Client) ListTools(ctx context.Context) ([]ToolDefinition, error) {
	var tools []ToolDefinition
	if _, err := c.requestJSON(ctx, http.MethodGet, "/api/v1/agent-sdk/tools", nil, nil, &tools); err != nil {
		return nil, err
	}
	if tools == nil {
		tools = []ToolDefinition{}
	}
	return tools, nil
}

func (c *Client) CallTool(ctx context.Context, toolID string, args any) (*ToolCallResponse, error) {
	var response ToolCallResponse
	if _, err := c.requestJSON(ctx, http.MethodPost, "/api/v1/agent-sdk/tools/"+url.PathEscape(strings.TrimSpace(toolID))+":call", args, nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) RunReport(ctx context.Context, req ReportRequest) (*ReportRun, error) {
	var run ReportRun
	if _, err := c.requestJSON(ctx, http.MethodPost, "/api/v1/agent-sdk/report", req, nil, &run); err != nil {
		return nil, err
	}
	return &run, nil
}

func (c *Client) GetProtectedResourceMetadata(ctx context.Context) (*ProtectedResourceMetadata, error) {
	var metadata ProtectedResourceMetadata
	if _, err := c.requestJSON(ctx, http.MethodGet, "/.well-known/oauth-protected-resource", nil, nil, &metadata); err != nil {
		return nil, err
	}
	return &metadata, nil
}

func (c *Client) ListManagedCredentials(ctx context.Context) (*ManagedCredentialCollection, error) {
	var collection ManagedCredentialCollection
	if _, err := c.requestJSON(ctx, http.MethodGet, "/api/v1/admin/agent-sdk/credentials", nil, nil, &collection); err != nil {
		return nil, err
	}
	return &collection, nil
}

func (c *Client) GetManagedCredential(ctx context.Context, credentialID string) (*ManagedCredential, error) {
	var credential ManagedCredential
	if _, err := c.requestJSON(ctx, http.MethodGet, "/api/v1/admin/agent-sdk/credentials/"+url.PathEscape(strings.TrimSpace(credentialID)), nil, nil, &credential); err != nil {
		return nil, err
	}
	return &credential, nil
}

func (c *Client) CreateManagedCredential(ctx context.Context, body map[string]any) (*ManagedCredentialSecretResponse, error) {
	var response ManagedCredentialSecretResponse
	if _, err := c.requestJSON(ctx, http.MethodPost, "/api/v1/admin/agent-sdk/credentials", body, nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) RotateManagedCredential(ctx context.Context, credentialID string, body map[string]any) (*ManagedCredentialSecretResponse, error) {
	var response ManagedCredentialSecretResponse
	if _, err := c.requestJSON(ctx, http.MethodPost, "/api/v1/admin/agent-sdk/credentials/"+url.PathEscape(strings.TrimSpace(credentialID))+":rotate", body, nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) RevokeManagedCredential(ctx context.Context, credentialID string, body map[string]any) (*ManagedCredential, error) {
	var response ManagedCredential
	if _, err := c.requestJSON(ctx, http.MethodPost, "/api/v1/admin/agent-sdk/credentials/"+url.PathEscape(strings.TrimSpace(credentialID))+":revoke", body, nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) MCP(ctx context.Context, sessionID string, req MCPRequest) (*MCPResponse, string, error) {
	headers := http.Header{}
	if strings.TrimSpace(sessionID) != "" {
		headers.Set("Mcp-Session-Id", strings.TrimSpace(sessionID))
	}
	var response MCPResponse
	responseHeaders, err := c.requestJSON(ctx, http.MethodPost, "/api/v1/mcp", req, headers, &response)
	if err != nil {
		return nil, "", err
	}
	return &response, strings.TrimSpace(responseHeaders.Get("Mcp-Session-Id")), nil
}

func (c *Client) OpenMCPStream(ctx context.Context, sessionID string) (io.ReadCloser, string, error) {
	headers := http.Header{}
	headers.Set("Accept", "text/event-stream")
	if strings.TrimSpace(sessionID) != "" {
		headers.Set("Mcp-Session-Id", strings.TrimSpace(sessionID))
	}
	resp, err := c.requestRaw(ctx, http.MethodGet, "/api/v1/mcp", nil, headers)
	if err != nil {
		return nil, "", err
	}
	return resp.Body, strings.TrimSpace(resp.Header.Get("Mcp-Session-Id")), nil
}

func (c *Client) OpenReportRunStream(ctx context.Context, statusPath string) (io.ReadCloser, error) {
	statusPath = strings.TrimSpace(statusPath)
	if statusPath == "" {
		return nil, fmt.Errorf("status path is required")
	}
	resp, err := c.requestRaw(ctx, http.MethodGet, statusPath+"/stream", nil, http.Header{"Accept": []string{"text/event-stream"}})
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

{{range .MethodBindings}}
func (c *Client) {{.GoMethodName}}(ctx context.Context, args any) (*ToolCallResponse, error) {
	return c.CallTool(ctx, {{printf "%q" .ToolID}}, args)
}
{{end}}

func (c *Client) requestJSON(ctx context.Context, method, path string, body any, headers http.Header, out any) (http.Header, error) {
	resp, err := c.requestRaw(ctx, method, path, body, headers)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return nil, err
		}
	} else {
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	return resp.Header.Clone(), nil
}

func (c *Client) requestRaw(ctx context.Context, method, path string, body any, headers http.Header) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpointURL(path), reader)
	if err != nil {
		return nil, err
	}
	if reader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	for key, values := range headers {
		req.Header.Del(key)
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, nil
	}
	defer func() { _ = resp.Body.Close() }()
	var apiErr APIError
	apiErr.StatusCode = resp.StatusCode
	bodyBytes, _ := io.ReadAll(resp.Body)
	if len(bodyBytes) > 0 {
		if err := json.Unmarshal(bodyBytes, &apiErr); err != nil || strings.TrimSpace(apiErr.Message) == "" {
			apiErr.Message = strings.TrimSpace(string(bodyBytes))
		}
	}
	if strings.TrimSpace(apiErr.Message) == "" {
		apiErr.Message = http.StatusText(resp.StatusCode)
	}
	return nil, &apiErr
}

func (c *Client) endpointURL(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	base := *c.baseURL
	base.Path = strings.TrimSuffix(c.baseURL.Path, "/") + path
	return base.String()
}
`

const pythonSDKTemplate = `import json
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from urllib import error, parse, request


class APIError(Exception):
    def __init__(self, status_code: int, message: str, code: str = "") -> None:
        super().__init__(f"api request failed ({status_code}{' ' + code if code else ''}): {message}")
        self.status_code = status_code
        self.message = message
        self.code = code


@dataclass
class Client:
    base_url: str
    api_key: Optional[str] = None
    timeout: float = 15.0
    user_agent: str = "cerebro-sdk-python"

    def list_tools(self) -> Any:
        payload, _ = self._request_json("GET", "/api/v1/agent-sdk/tools")
        return payload

    def call_tool(self, tool_id: str, args: Any) -> Any:
        payload, _ = self._request_json("POST", f"/api/v1/agent-sdk/tools/{parse.quote(tool_id)}:call", args)
        return payload

    def run_report(self, payload: Dict[str, Any]) -> Any:
        result, _ = self._request_json("POST", "/api/v1/agent-sdk/report", payload)
        return result

    def get_protected_resource_metadata(self) -> Any:
        result, _ = self._request_json("GET", "/.well-known/oauth-protected-resource")
        return result

    def list_managed_credentials(self) -> Any:
        result, _ = self._request_json("GET", "/api/v1/admin/agent-sdk/credentials")
        return result

    def get_managed_credential(self, credential_id: str) -> Any:
        result, _ = self._request_json("GET", f"/api/v1/admin/agent-sdk/credentials/{parse.quote(credential_id)}")
        return result

    def create_managed_credential(self, payload: Dict[str, Any]) -> Any:
        result, _ = self._request_json("POST", "/api/v1/admin/agent-sdk/credentials", payload)
        return result

    def rotate_managed_credential(self, credential_id: str, payload: Optional[Dict[str, Any]] = None) -> Any:
        result, _ = self._request_json("POST", f"/api/v1/admin/agent-sdk/credentials/{parse.quote(credential_id)}:rotate", payload or {})
        return result

    def revoke_managed_credential(self, credential_id: str, payload: Optional[Dict[str, Any]] = None) -> Any:
        result, _ = self._request_json("POST", f"/api/v1/admin/agent-sdk/credentials/{parse.quote(credential_id)}:revoke", payload or {})
        return result

    def mcp(self, payload: Dict[str, Any], session_id: str = "") -> Tuple[Any, str]:
        headers = {}
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        response, response_headers = self._request_json("POST", "/api/v1/mcp", payload, headers)
        return response, response_headers.get("Mcp-Session-Id", "")

    def open_mcp_stream(self, session_id: str = ""):
        headers = {"Accept": "text/event-stream"}
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        return self._request_raw("GET", "/api/v1/mcp", None, headers)

    def open_report_run_stream(self, status_path: str):
        return self._request_raw("GET", f"{status_path}/stream", None, {"Accept": "text/event-stream"})

{{range .MethodBindings}}
    def {{.PythonName}}(self, args: Any) -> Any:
        return self.call_tool({{printf "%q" .ToolID}}, args)

{{end}}
    def _request_json(self, method: str, path: str, body: Optional[Any] = None, headers: Optional[Dict[str, str]] = None):
        response = self._request_raw(method, path, body, headers or {})
        try:
            payload = response.read().decode("utf-8")
            return json.loads(payload) if payload else None, dict(response.headers)
        finally:
            response.close()

    def _request_raw(self, method: str, path: str, body: Optional[Any], headers: Dict[str, str]):
        url = self.base_url.rstrip("/") + (path if path.startswith("/") else "/" + path)
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        headers.setdefault("Accept", "application/json")
        headers.setdefault("User-Agent", self.user_agent)
        if self.api_key:
            headers.setdefault("Authorization", f"Bearer {self.api_key}")
        req = request.Request(url, data=data, headers=headers, method=method)
        try:
            return request.urlopen(req, timeout=self.timeout)
        except error.HTTPError as exc:
            payload = exc.read().decode("utf-8")
            try:
                decoded = json.loads(payload)
                raise APIError(exc.code, decoded.get("error", payload), decoded.get("code", "")) from exc
            except json.JSONDecodeError:
                raise APIError(exc.code, payload or exc.reason, "") from exc
`

const tsSDKTemplate = `export interface ToolDefinition {
  id: string;
  version: string;
  tool_name: string;
  sdk_method?: string;
  title?: string;
  description: string;
  category?: string;
  http_method?: string;
  http_path?: string;
  required_permission?: string;
  input_schema?: Record<string, unknown>;
  example_input?: Record<string, unknown>;
  requires_approval?: boolean;
  execution_kind?: string;
  supports_async?: boolean;
  supports_progress?: boolean;
  status_resource?: string;
}

export interface ToolCallResponse {
  tool_id: string;
  tool_name?: string;
  sdk_method?: string;
  result?: unknown;
  raw_result?: unknown;
  invoked_at?: string;
  approval?: boolean;
  http_method?: string;
  http_path?: string;
  execution_kind?: string;
  supports_async?: boolean;
  supports_progress?: boolean;
  status_resource?: string;
}

export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers?: string[];
  scopes_supported?: string[];
  bearer_methods_supported?: string[];
  resource_documentation?: string;
  agent_sdk_endpoint?: string;
  mcp_endpoint?: string;
  mcp_protocol_version?: string;
}

export interface ClientConfig {
  baseUrl: string;
  apiKey?: string;
  userAgent?: string;
  fetchImpl?: typeof fetch;
}

export class APIError extends Error {
  statusCode: number;
  code?: string;

  constructor(statusCode: number, message: string, code?: string) {
    super(__BACKTICK__api request failed (${statusCode}${code ? __BACKTICK__ ${code}__BACKTICK__ : ""}): ${message}__BACKTICK__);
    this.statusCode = statusCode;
    this.code = code;
  }
}

export class Client {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly userAgent: string;
  private readonly fetchImpl: typeof fetch;

  constructor(config: ClientConfig) {
    if (!config.baseUrl) {
      throw new Error("baseUrl is required");
    }
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.apiKey = config.apiKey;
    this.userAgent = config.userAgent ?? "cerebro-sdk-typescript";
    this.fetchImpl = config.fetchImpl ?? fetch;
  }

  async listTools(): Promise<ToolDefinition[]> {
    return this.requestJson<ToolDefinition[]>("GET", "/api/v1/agent-sdk/tools");
  }

  async callTool(toolId: string, args: unknown): Promise<ToolCallResponse> {
    return this.requestJson<ToolCallResponse>("POST", __BACKTICK__/api/v1/agent-sdk/tools/${encodeURIComponent(toolId)}:call__BACKTICK__, args);
  }

  async runReport(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>("POST", "/api/v1/agent-sdk/report", payload);
  }

  async getProtectedResourceMetadata(): Promise<ProtectedResourceMetadata> {
    return this.requestJson<ProtectedResourceMetadata>("GET", "/.well-known/oauth-protected-resource");
  }

  async listManagedCredentials(): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>("GET", "/api/v1/admin/agent-sdk/credentials");
  }

  async getManagedCredential(credentialId: string): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>("GET", __BACKTICK__/api/v1/admin/agent-sdk/credentials/${encodeURIComponent(credentialId)}__BACKTICK__);
  }

  async createManagedCredential(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>("POST", "/api/v1/admin/agent-sdk/credentials", payload);
  }

  async rotateManagedCredential(credentialId: string, payload: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>("POST", __BACKTICK__/api/v1/admin/agent-sdk/credentials/${encodeURIComponent(credentialId)}:rotate__BACKTICK__, payload);
  }

  async revokeManagedCredential(credentialId: string, payload: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>("POST", __BACKTICK__/api/v1/admin/agent-sdk/credentials/${encodeURIComponent(credentialId)}:revoke__BACKTICK__, payload);
  }

  async mcp(payload: Record<string, unknown>, sessionId = ""): Promise<{ response: Record<string, unknown>; sessionId: string }> {
    const headers: Record<string, string> = {};
    if (sessionId) {
      headers["Mcp-Session-Id"] = sessionId;
    }
    const { payload: response, headers: responseHeaders } = await this.requestJsonWithHeaders<Record<string, unknown>>("POST", "/api/v1/mcp", payload, headers);
    return { response, sessionId: responseHeaders.get("Mcp-Session-Id") ?? "" };
  }

  async openMCPStream(sessionId = ""): Promise<Response> {
    const headers: Record<string, string> = { Accept: "text/event-stream" };
    if (sessionId) {
      headers["Mcp-Session-Id"] = sessionId;
    }
    return this.requestRaw("GET", "/api/v1/mcp", undefined, headers);
  }

  async openReportRunStream(statusPath: string): Promise<Response> {
    return this.requestRaw("GET", __BACKTICK__${statusPath}/stream__BACKTICK__, undefined, { Accept: "text/event-stream" });
  }

{{range .MethodBindings}}
  async {{.TSMethodName}}(args: unknown): Promise<ToolCallResponse> {
    return this.callTool({{printf "%q" .ToolID}}, args);
  }

{{end}}
  private async requestJson<T>(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
    const { payload } = await this.requestJsonWithHeaders<T>(method, path, body, headers);
    return payload;
  }

  private async requestJsonWithHeaders<T>(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<{ payload: T; headers: Headers }> {
    const response = await this.requestRaw(method, path, body, headers);
    const text = await response.text();
    return { payload: (text ? JSON.parse(text) : null) as T, headers: response.headers };
  }

  private async requestRaw(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<Response> {
    const initHeaders = new Headers(headers);
    initHeaders.set("Accept", initHeaders.get("Accept") ?? "application/json");
    initHeaders.set("User-Agent", initHeaders.get("User-Agent") ?? this.userAgent);
    if (this.apiKey) {
      initHeaders.set("Authorization", __BACKTICK__Bearer ${this.apiKey}__BACKTICK__);
    }
    let requestBody: BodyInit | undefined;
    if (body !== undefined) {
      initHeaders.set("Content-Type", initHeaders.get("Content-Type") ?? "application/json");
      requestBody = JSON.stringify(body);
    }
    const response = await this.fetchImpl(__BACKTICK__${this.baseUrl}${path.startsWith("/") ? path : __BACKTICK__/${path}__BACKTICK__}__BACKTICK__, {
      method,
      headers: initHeaders,
      body: requestBody,
    });
    if (!response.ok) {
      const text = await response.text();
      try {
        const decoded = text ? JSON.parse(text) : {};
        throw new APIError(response.status, decoded.error ?? text, decoded.code);
      } catch (error) {
        if (error instanceof APIError) {
          throw error;
        }
        throw new APIError(response.status, text || response.statusText);
      }
    }
    return response;
  }
}
`

const tsPackageJSON = `{
  "name": "@writer/cerebro-sdk",
  "version": "0.1.0",
  "type": "module",
  "main": "./src/index.ts",
  "exports": {
    ".": "./src/index.ts"
  }
}
`

const pythonPyprojectTOML = `[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "cerebro-sdk"
version = "0.1.0"
description = "Generated Python SDK for the Cerebro Agent SDK and report runtime"
requires-python = ">=3.10"

[tool.setuptools.packages.find]
where = ["."]
include = ["cerebro_sdk*"]
`

const tsConfigJSON = `{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ES2022",
    "moduleResolution": "Bundler",
    "strict": true,
    "noEmit": true,
    "lib": ["ES2022", "DOM"]
  },
  "include": ["src/**/*.ts"]
}
`
