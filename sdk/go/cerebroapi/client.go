package cerebroapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const defaultUserAgent = "cerebro-go-sdk"

type Client struct {
	baseURL    *url.URL
	apiKey     string
	tenantID   string
	userAgent  string
	httpClient *http.Client
}

type Option func(*Client)

func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		if httpClient != nil {
			c.httpClient = httpClient
		}
	}
}

func New(config Config, options ...Option) (*Client, error) {
	baseURL, err := parseBaseURL(config.BaseURL)
	if err != nil {
		return nil, err
	}
	apiKey := strings.TrimSpace(config.APIKey)
	if apiKey == "" {
		return nil, errors.New("cerebro API key is required")
	}
	tenantID := strings.TrimSpace(config.TenantID)
	if tenantID == "" {
		return nil, errors.New("cerebro tenant id is required")
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}
	userAgent := strings.TrimSpace(config.UserAgent)
	if userAgent == "" {
		userAgent = defaultUserAgent
	}
	client := &Client{
		baseURL:   baseURL,
		apiKey:    apiKey,
		tenantID:  tenantID,
		userAgent: userAgent,
		httpClient: &http.Client{
			Timeout:       timeout,
			CheckRedirect: blockRedirects,
		},
	}
	for _, option := range options {
		option(client)
	}
	if client.httpClient.CheckRedirect == nil {
		transportClient := *client.httpClient
		transportClient.CheckRedirect = blockRedirects
		client.httpClient = &transportClient
	}
	return client, nil
}

func (c Config) MCPServerURL() string {
	if strings.TrimSpace(c.MCPURL) != "" {
		mcpURL, err := parseBaseURL(c.MCPURL)
		if err != nil {
			return ""
		}
		return mcpURL.String()
	}
	baseURL, err := parseBaseURL(c.BaseURL)
	if err != nil {
		return ""
	}
	value := *baseURL
	value.Path, value.RawPath = mcpPathFromBase(value.Path, value.EscapedPath())
	value.RawQuery = ""
	value.Fragment = ""
	return value.String()
}

func (c *Client) GetSourceRuntime(ctx context.Context, runtimeID string) (*SourceRuntime, error) {
	runtimeID = strings.TrimSpace(runtimeID)
	if runtimeID == "" {
		return nil, errors.New("cerebro runtime id is required")
	}
	var response sourceRuntimeResponse
	if err := c.doJSON(ctx, http.MethodGet, c.runtimeURL(runtimeID), nil, &response); err != nil {
		return nil, err
	}
	return runtimeFromResponse(response)
}

func (c *Client) PutSourceRuntime(ctx context.Context, runtime SourceRuntime) (*SourceRuntime, error) {
	runtime.ID = strings.TrimSpace(runtime.ID)
	if runtime.ID == "" {
		return nil, errors.New("cerebro runtime id is required")
	}
	if strings.TrimSpace(runtime.TenantID) == "" {
		runtime.TenantID = c.tenantID
	}
	if strings.TrimSpace(runtime.SourceID) == "" {
		return nil, errors.New("cerebro source id is required")
	}
	var response sourceRuntimeResponse
	body := map[string]SourceRuntime{"runtime": runtime}
	if err := c.doJSON(ctx, http.MethodPut, c.runtimeURL(runtime.ID), body, &response); err != nil {
		return nil, err
	}
	return runtimeFromResponse(response)
}

func (c *Client) EnsureDefaultRuntime(ctx context.Context, config Config) (*SourceRuntime, error) {
	return c.PutSourceRuntime(ctx, config.DefaultRuntime())
}

func (c *Client) ListClaims(ctx context.Context, request ListClaimsRequest) (*ListClaimsResponse, error) {
	request.RuntimeID = strings.TrimSpace(request.RuntimeID)
	if request.RuntimeID == "" {
		return nil, errors.New("cerebro runtime id is required")
	}
	query := url.Values{}
	addQuery(query, "claim_id", request.ClaimID)
	addQuery(query, "subject_urn", request.SubjectURN)
	addQuery(query, "predicate", request.Predicate)
	addQuery(query, "object_urn", request.ObjectURN)
	addQuery(query, "object_value", request.ObjectValue)
	addQuery(query, "claim_type", request.ClaimType)
	addQuery(query, "status", request.Status)
	addQuery(query, "source_event_id", request.SourceEventID)
	if request.Limit > 0 {
		query.Set("limit", strconv.FormatUint(uint64(request.Limit), 10))
	}
	var response ListClaimsResponse
	if err := c.doJSON(ctx, http.MethodGet, withQuery(c.runtimeURL(request.RuntimeID, "claims"), query), nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) WriteClaims(ctx context.Context, request WriteClaimsRequest) (*WriteClaimsResponse, error) {
	request.RuntimeID = strings.TrimSpace(request.RuntimeID)
	if request.RuntimeID == "" {
		return nil, errors.New("cerebro runtime id is required")
	}
	if len(request.Claims) == 0 {
		return nil, errors.New("at least one cerebro claim is required")
	}
	var response WriteClaimsResponse
	if err := c.doJSON(ctx, http.MethodPost, c.runtimeURL(request.RuntimeID, "claims"), request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) GetEntityNeighborhood(ctx context.Context, rootURN string, limit uint32) (*EntityNeighborhood, error) {
	rootURN = strings.TrimSpace(rootURN)
	if rootURN == "" {
		return nil, errors.New("cerebro graph root urn is required")
	}
	query := url.Values{"root_urn": []string{rootURN}}
	if limit > 0 {
		query.Set("limit", strconv.FormatUint(uint64(limit), 10))
	}
	var response EntityNeighborhood
	if err := c.doJSON(ctx, http.MethodGet, withQuery(c.urlFor("platform", "graph", "neighborhood"), query), nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) doJSON(ctx context.Context, method string, endpoint string, body any, target any) error {
	var bodyReader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("X-Cerebro-Tenant", c.tenantID)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return newHTTPError(resp)
	}
	if target == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("decode cerebro response: %w", err)
	}
	return nil
}

func (c *Client) runtimeURL(runtimeID string, suffix ...string) string {
	segments := []string{"source-runtimes", strings.TrimSpace(runtimeID)}
	segments = append(segments, suffix...)
	return c.urlFor(segments...)
}

func (c *Client) urlFor(segments ...string) string {
	value := *c.baseURL
	pathPrefix := strings.TrimRight(value.Path, "/")
	rawPathPrefix := strings.TrimRight(value.EscapedPath(), "/")
	escaped := make([]string, 0, len(segments))
	for _, segment := range segments {
		escaped = append(escaped, url.PathEscape(segment))
	}
	value.Path = pathPrefix + "/" + strings.Join(segments, "/")
	value.RawPath = rawPathPrefix + "/" + strings.Join(escaped, "/")
	value.RawQuery = ""
	value.Fragment = ""
	return value.String()
}

func parseBaseURL(raw string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("cerebro base url is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("parse cerebro base url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("cerebro base url must use http or https")
	}
	if parsed.Host == "" {
		return nil, errors.New("cerebro base url must include a host")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("cerebro base url must not include credentials, query, or fragment")
	}
	return parsed, nil
}

func mcpPathFromBase(path string, rawPath string) (string, string) {
	path = strings.TrimRight(path, "/")
	rawPath = strings.TrimRight(rawPath, "/")
	suffix := "/api/v1/mcp"
	if strings.HasSuffix(path, "/api") {
		suffix = "/v1/mcp"
	} else if hasVersionedAPISuffix(path) {
		suffix = "/mcp"
	}
	return path + suffix, rawPath + suffix
}

func hasVersionedAPISuffix(path string) bool {
	versionStart := strings.LastIndex(path, "/")
	if versionStart < 0 || !strings.HasSuffix(path[:versionStart], "/api") {
		return false
	}
	version := path[versionStart+1:]
	if len(version) < 2 || version[0] != 'v' {
		return false
	}
	for _, ch := range version[1:] {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func addQuery(query url.Values, key string, value string) {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		query.Set(key, trimmed)
	}
}

func withQuery(endpoint string, query url.Values) string {
	if len(query) == 0 {
		return endpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func blockRedirects(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func runtimeFromResponse(response sourceRuntimeResponse) (*SourceRuntime, error) {
	if response.Runtime == nil {
		return nil, errors.New("cerebro response missing runtime")
	}
	return response.Runtime, nil
}

type HTTPError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e HTTPError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("cerebro http error: %d %s", e.StatusCode, e.Status)
	}
	return fmt.Sprintf("cerebro http error: %d %s: %s", e.StatusCode, e.Status, e.Body)
}

func newHTTPError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return HTTPError{
		StatusCode: resp.StatusCode,
		Status:     strings.TrimSpace(resp.Status),
		Body:       strings.TrimSpace(string(body)),
	}
}
