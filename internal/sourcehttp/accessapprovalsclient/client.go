package accessapprovalsclient

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

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphactions"
)

const defaultMaxErrorBodyBytes int64 = 4096

type Client struct {
	baseURL    *url.URL
	bearer     string
	httpClient *http.Client
}

type Option func(*Client)

func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) {
		if client != nil {
			c.httpClient = client
		}
	}
}

func New(cfg config.AccessApprovalsActionConfig, opts ...Option) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	bearer := strings.TrimSpace(cfg.BearerToken)
	if base == "" || bearer == "" {
		return nil, graphactions.ErrNotConfigured
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("%w: base URL is invalid", graphactions.ErrInvalidRequest)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := &Client{
		baseURL: parsed,
		bearer:  bearer,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
	for _, opt := range opts {
		opt(client)
	}
	return client, nil
}

func (c *Client) SuspendOktaUser(ctx context.Context, request graphactions.AccessApprovalsUserActionRequest) (*graphactions.AccessApprovalsUserAction, error) {
	return c.createAction(ctx, graphactions.AccessApprovalsActionSuspend, request)
}

func (c *Client) UnsuspendOktaUser(ctx context.Context, request graphactions.AccessApprovalsUserActionRequest) (*graphactions.AccessApprovalsUserAction, error) {
	return c.createAction(ctx, graphactions.AccessApprovalsActionUnsuspend, request)
}

func (c *Client) ActionURL(actionID string) string {
	if c == nil || c.baseURL == nil {
		return ""
	}
	actionID = strings.TrimSpace(actionID)
	if actionID == "" {
		return ""
	}
	return c.resolvePath("/admin/okta-jail/actions/" + url.PathEscape(actionID))
}

func (c *Client) createAction(ctx context.Context, action string, request graphactions.AccessApprovalsUserActionRequest) (*graphactions.AccessApprovalsUserAction, error) {
	if c == nil || c.baseURL == nil || c.httpClient == nil || strings.TrimSpace(c.bearer) == "" {
		return nil, graphactions.ErrNotConfigured
	}
	request.EmailOrUserID = strings.TrimSpace(request.EmailOrUserID)
	if request.EmailOrUserID == "" {
		return nil, fmt.Errorf("%w: email_or_user_id is required", graphactions.ErrInvalidRequest)
	}
	path := "/admin/okta-jail/suspend"
	if strings.TrimSpace(action) == graphactions.AccessApprovalsActionUnsuspend {
		path = "/admin/okta-jail/unsuspend"
	} else if strings.TrimSpace(action) != graphactions.AccessApprovalsActionSuspend {
		return nil, fmt.Errorf("%w: unsupported action %q", graphactions.ErrInvalidRequest, action)
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("%w: encode request: %w", graphactions.ErrInvalidRequest, err)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.resolvePath(path), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", graphactions.ErrInvalidRequest, err)
	}
	httpRequest.Header.Set("Authorization", "Bearer "+c.bearer)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", graphactions.ErrRemote, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, remoteStatusError(response)
	}
	var actionResponse graphactions.AccessApprovalsUserAction
	if err := json.NewDecoder(response.Body).Decode(&actionResponse); err != nil {
		return nil, fmt.Errorf("%w: decode response: %w", graphactions.ErrRemote, err)
	}
	if strings.TrimSpace(actionResponse.ID) == "" {
		return nil, fmt.Errorf("%w: response missing action id", graphactions.ErrRemote)
	}
	return &actionResponse, nil
}

func (c *Client) resolvePath(path string) string {
	resolved := *c.baseURL
	basePath := strings.TrimRight(resolved.Path, "/")
	resolved.Path = basePath + "/" + strings.TrimLeft(path, "/")
	resolved.RawQuery = ""
	resolved.Fragment = ""
	return resolved.String()
}

func remoteStatusError(response *http.Response) error {
	message := strings.TrimSpace(http.StatusText(response.StatusCode))
	if response.Body != nil {
		body, _ := io.ReadAll(io.LimitReader(response.Body, defaultMaxErrorBodyBytes))
		var payload struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &payload); err == nil && strings.TrimSpace(payload.Error) != "" {
			message = strings.TrimSpace(payload.Error)
		}
	}
	if message == "" {
		message = "request failed"
	}
	return fmt.Errorf("%w: status %d: %s", graphactions.ErrRemote, response.StatusCode, message)
}
