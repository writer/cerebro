package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/evalops/cerebro/internal/findings"
)

type listFindingsResponse struct {
	Findings []*findings.Finding `json:"findings"`
	Count    int                 `json:"count"`
}

func (c *Client) ListFindings(ctx context.Context, filter findings.FindingFilter) ([]*findings.Finding, error) {
	query := findingsFilterQuery(filter)
	var resp listFindingsResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/findings/", query, nil, &resp); err != nil {
		return nil, err
	}
	if resp.Findings == nil {
		return []*findings.Finding{}, nil
	}
	return resp.Findings, nil
}

func (c *Client) FindingsStats(ctx context.Context) (findings.Stats, error) {
	var stats findings.Stats
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/findings/stats", nil, nil, &stats); err != nil {
		return findings.Stats{}, err
	}
	return stats, nil
}

func (c *Client) ResolveFinding(ctx context.Context, id string) error {
	path := "/api/v1/findings/" + url.PathEscape(strings.TrimSpace(id)) + "/resolve"
	return c.doJSON(ctx, http.MethodPost, path, nil, nil, nil)
}

func (c *Client) SuppressFinding(ctx context.Context, id string) error {
	path := "/api/v1/findings/" + url.PathEscape(strings.TrimSpace(id)) + "/suppress"
	return c.doJSON(ctx, http.MethodPost, path, nil, nil, nil)
}

func (c *Client) ExportFindings(ctx context.Context, filter findings.FindingFilter, format string, pretty bool) ([]byte, string, error) {
	query := findingsFilterQuery(filter)
	if format != "" {
		query.Set("format", strings.ToLower(strings.TrimSpace(format)))
	}
	if pretty {
		query.Set("pretty", "true")
	}

	data, headers, err := c.doBytes(ctx, http.MethodGet, "/api/v1/findings/export", query, nil)
	if err != nil {
		return nil, "", err
	}
	return data, headers.Get("Content-Type"), nil
}

func findingsFilterQuery(filter findings.FindingFilter) url.Values {
	query := url.Values{}
	if severity := strings.TrimSpace(filter.Severity); severity != "" {
		query.Set("severity", severity)
	}
	if status := strings.TrimSpace(filter.Status); status != "" {
		query.Set("status", status)
	}
	if policyID := strings.TrimSpace(filter.PolicyID); policyID != "" {
		query.Set("policy_id", policyID)
	}
	if signalType := strings.TrimSpace(filter.SignalType); signalType != "" {
		query.Set("signal_type", signalType)
	}
	if domain := strings.TrimSpace(filter.Domain); domain != "" {
		query.Set("domain", domain)
	}
	if filter.Limit > 0 {
		query.Set("limit", strconv.Itoa(filter.Limit))
	}
	if filter.Offset > 0 {
		query.Set("offset", strconv.Itoa(filter.Offset))
	}
	return query
}
