package client

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

type ScanResultTable struct {
	Table      string `json:"table"`
	Scanned    int64  `json:"scanned"`
	Violations int64  `json:"violations"`
	Duration   string `json:"duration"`
}

type ScanTableResponse struct {
	Scanned    int64                    `json:"scanned"`
	Violations int64                    `json:"violations"`
	Duration   string                   `json:"duration"`
	Findings   []map[string]interface{} `json:"findings"`
	Tables     []ScanResultTable        `json:"tables"`
}

func (c *Client) ScanFindings(ctx context.Context, table string, limit int) (*ScanTableResponse, error) {
	table = strings.TrimSpace(table)
	if table == "" {
		return nil, fmt.Errorf("table is required")
	}
	req := map[string]interface{}{
		"table": table,
	}
	if limit > 0 {
		req["limit"] = limit
	}

	return c.scanFindings(ctx, req)
}

func (c *Client) ScanFindingsTables(ctx context.Context, tables []string, limit int) (*ScanTableResponse, error) {
	normalized := normalizeScanTables(tables)
	if len(normalized) == 0 {
		return nil, fmt.Errorf("at least one table is required")
	}

	req := map[string]interface{}{
		"tables": normalized,
	}
	if limit > 0 {
		req["limit"] = limit
	}

	return c.scanFindings(ctx, req)
}

func (c *Client) scanFindings(ctx context.Context, req map[string]interface{}) (*ScanTableResponse, error) {
	var resp ScanTableResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/findings/scan", nil, req, &resp); err != nil {
		return nil, err
	}
	if resp.Findings == nil {
		resp.Findings = []map[string]interface{}{}
	}
	if resp.Tables == nil {
		resp.Tables = []ScanResultTable{}
	}
	return &resp, nil
}

func normalizeScanTables(tables []string) []string {
	if len(tables) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(tables))
	seen := make(map[string]struct{}, len(tables))
	for _, table := range tables {
		candidate := strings.TrimSpace(strings.ToLower(table))
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		normalized = append(normalized, candidate)
	}

	return normalized
}
