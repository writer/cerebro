package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/writer/cerebro/internal/agentsdk"
	"github.com/writer/cerebro/internal/graph"
)

type AgentSDKToolCallResponse struct {
	ToolID           string `json:"tool_id"`
	ToolName         string `json:"tool_name,omitempty"`
	SDKMethod        string `json:"sdk_method,omitempty"`
	Result           any    `json:"result,omitempty"`
	RawResult        any    `json:"raw_result,omitempty"`
	InvokedAt        string `json:"invoked_at,omitempty"`
	Approval         bool   `json:"approval,omitempty"`
	HTTPMethod       string `json:"http_method,omitempty"`
	HTTPPath         string `json:"http_path,omitempty"`
	ExecutionKind    string `json:"execution_kind,omitempty"`
	SupportsAsync    bool   `json:"supports_async,omitempty"`
	SupportsProgress bool   `json:"supports_progress,omitempty"`
	StatusResource   string `json:"status_resource,omitempty"`
	APICredentialID  string `json:"api_credential_id,omitempty"`
	APIClientID      string `json:"api_client_id,omitempty"`
	Traceparent      string `json:"traceparent,omitempty"`
}

type AgentSDKReportRequest struct {
	ReportID          string                       `json:"report_id,omitempty"`
	ExecutionMode     string                       `json:"execution_mode,omitempty"`
	MaterializeResult *bool                        `json:"materialize_result,omitempty"`
	Parameters        []graph.ReportParameterValue `json:"parameters,omitempty"`
	RetryPolicy       *graph.ReportRetryPolicy     `json:"retry_policy,omitempty"`
}

type AgentSDKMCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type AgentSDKMCPResponse struct {
	JSONRPC string            `json:"jsonrpc"`
	ID      any               `json:"id,omitempty"`
	Result  any               `json:"result,omitempty"`
	Error   *AgentSDKMCPError `json:"error,omitempty"`
	Method  string            `json:"method,omitempty"`
	Params  map[string]any    `json:"params,omitempty"`
}

type AgentSDKMCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *AgentSDKMCPError) Error() string {
	if e == nil {
		return "mcp request failed"
	}
	return fmt.Sprintf("mcp request failed (%d): %s", e.Code, strings.TrimSpace(e.Message))
}

func (c *Client) ListAgentSDKTools(ctx context.Context) ([]agentsdk.ToolDefinition, error) {
	var tools []agentsdk.ToolDefinition
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/agent-sdk/tools", nil, nil, &tools); err != nil {
		return nil, err
	}
	if tools == nil {
		tools = []agentsdk.ToolDefinition{}
	}
	return tools, nil
}

func (c *Client) CallAgentSDKTool(ctx context.Context, toolID string, args any) (*AgentSDKToolCallResponse, error) {
	toolID = strings.TrimSpace(toolID)
	if toolID == "" {
		return nil, fmt.Errorf("tool_id is required")
	}
	var resp AgentSDKToolCallResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/agent-sdk/tools/"+url.PathEscape(toolID)+":call", nil, args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ExecuteAgentSDKReport(ctx context.Context, req AgentSDKReportRequest) (*graph.ReportRun, error) {
	var run graph.ReportRun
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/agent-sdk/report", nil, req, &run); err != nil {
		return nil, err
	}
	return &run, nil
}

func (c *Client) MCP(ctx context.Context, sessionID string, req AgentSDKMCPRequest) (*AgentSDKMCPResponse, string, error) {
	headers := http.Header{}
	if strings.TrimSpace(sessionID) != "" {
		headers.Set("Mcp-Session-Id", strings.TrimSpace(sessionID))
	}
	var resp AgentSDKMCPResponse
	responseHeaders, err := c.doJSONResponseHeaders(ctx, http.MethodPost, "/api/v1/mcp", nil, headers, req, &resp)
	if err != nil {
		return nil, "", err
	}
	if resp.Error != nil {
		return nil, strings.TrimSpace(responseHeaders.Get("Mcp-Session-Id")), resp.Error
	}
	return &resp, strings.TrimSpace(responseHeaders.Get("Mcp-Session-Id")), nil
}

func (c *Client) OpenMCPStream(ctx context.Context, sessionID string) (io.ReadCloser, string, error) {
	headers := http.Header{}
	headers.Set("Accept", "text/event-stream")
	if strings.TrimSpace(sessionID) != "" {
		headers.Set("Mcp-Session-Id", strings.TrimSpace(sessionID))
	}
	resp, err := c.doWithHeaders(ctx, http.MethodGet, "/api/v1/mcp", nil, headers, nil)
	if err != nil {
		return nil, "", err
	}
	return resp.Body, strings.TrimSpace(resp.Header.Get("Mcp-Session-Id")), nil
}

func (c *Client) doJSONResponseHeaders(ctx context.Context, method, endpoint string, query url.Values, headers http.Header, body interface{}, out interface{}) (http.Header, error) {
	resp, err := c.doWithHeaders(ctx, method, endpoint, query, headers, body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
	} else {
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	return resp.Header.Clone(), nil
}
