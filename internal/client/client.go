package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultTimeout   = 15 * time.Second
	defaultUserAgent = "cerebro-cli"
	maxErrorBodySize = 1 << 20
)

type Config struct {
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
	StatusCode int    `json:"-"`
	Message    string `json:"error"`
	Code       string `json:"code,omitempty"`
	Details    string `json:"details,omitempty"`
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

func New(cfg Config) (*Client, error) {
	rawBaseURL := strings.TrimSpace(cfg.BaseURL)
	if rawBaseURL == "" {
		return nil, errors.New("api base URL is required")
	}

	baseURL, err := url.Parse(rawBaseURL)
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return nil, fmt.Errorf("invalid api base URL %q", rawBaseURL)
	}
	baseURL.Path = strings.TrimSuffix(baseURL.Path, "/")

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	} else if httpClient.Timeout <= 0 {
		httpClient.Timeout = timeout
	}

	userAgent := strings.TrimSpace(cfg.UserAgent)
	if userAgent == "" {
		userAgent = defaultUserAgent
	}

	return &Client{
		baseURL:    baseURL,
		httpClient: httpClient,
		apiKey:     strings.TrimSpace(cfg.APIKey),
		userAgent:  userAgent,
	}, nil
}

func (c *Client) doJSON(ctx context.Context, method, endpoint string, query url.Values, body interface{}, out interface{}) error {
	return c.doJSONWithHeaders(ctx, method, endpoint, query, nil, body, out)
}

func (c *Client) doJSONWithHeaders(ctx context.Context, method, endpoint string, query url.Values, headers http.Header, body interface{}, out interface{}) error {
	resp, err := c.doWithHeaders(ctx, method, endpoint, query, headers, body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func (c *Client) doBytes(ctx context.Context, method, endpoint string, query url.Values, body interface{}) ([]byte, http.Header, error) {
	return c.doBytesWithHeaders(ctx, method, endpoint, query, nil, body)
}

func (c *Client) doBytesWithHeaders(ctx context.Context, method, endpoint string, query url.Values, headers http.Header, body interface{}) ([]byte, http.Header, error) {
	resp, err := c.doWithHeaders(ctx, method, endpoint, query, headers, body)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}

	return data, resp.Header.Clone(), nil
}

func (c *Client) doWithHeaders(ctx context.Context, method, endpoint string, query url.Values, headers http.Header, body interface{}) (*http.Response, error) {
	bodyReader := io.Reader(nil)
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.endpointURL(endpoint, query), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
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

	apiErr := decodeAPIError(resp)
	_ = resp.Body.Close()
	return nil, apiErr
}

func (c *Client) endpointURL(endpoint string, query url.Values) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		endpoint = "/"
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}

	u := *c.baseURL
	u.Path = strings.TrimSuffix(c.baseURL.Path, "/") + endpoint
	u.RawQuery = query.Encode()
	return u.String()
}

func decodeAPIError(resp *http.Response) error {
	apiErr := &APIError{StatusCode: resp.StatusCode}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
	if err != nil {
		apiErr.Message = strings.TrimSpace(resp.Status)
		return apiErr
	}

	if len(body) > 0 {
		var decoded APIError
		if json.Unmarshal(body, &decoded) == nil && strings.TrimSpace(decoded.Message) != "" {
			apiErr.Message = decoded.Message
			apiErr.Code = decoded.Code
			apiErr.Details = decoded.Details
			return apiErr
		}
		apiErr.Message = strings.TrimSpace(string(body))
	}

	if strings.TrimSpace(apiErr.Message) == "" {
		apiErr.Message = strings.TrimSpace(resp.Status)
	}
	return apiErr
}

func IsAPIErrorStatus(err error, statusCode int) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == statusCode
}

func IsTransportError(err error) bool {
	if err == nil {
		return false
	}

	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return false
	}

	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	var urlErr *url.Error
	return errors.As(err, &urlErr)
}
