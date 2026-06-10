package bootstrap

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type InvestigationBriefClientRequest struct {
	BaseURL   string
	APIKey    string
	FindingID string
	Limit     int
	SkipGraph bool
}

func FetchInvestigationBrief(ctx context.Context, request InvestigationBriefClientRequest) ([]byte, error) {
	endpoint, err := url.Parse(strings.TrimRight(request.BaseURL, "/") + "/findings/" + url.PathEscape(request.FindingID) + "/investigation-brief")
	if err != nil {
		return nil, fmt.Errorf("build investigation brief URL: %w", err)
	}
	query := endpoint.Query()
	if request.Limit > 0 {
		query.Set("limit", strconv.Itoa(request.Limit))
	}
	if request.SkipGraph {
		query.Set("skip_graph", "true")
	}
	endpoint.RawQuery = query.Encode()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create investigation brief request: %w", err)
	}
	if strings.TrimSpace(request.APIKey) != "" {
		httpReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(request.APIKey))
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("fetch investigation brief: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read investigation brief response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch investigation brief: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}
