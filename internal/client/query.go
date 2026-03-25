package client

import (
	"context"
	"net/http"

	"github.com/writer/cerebro/internal/warehouse"
)

type QueryRequest struct {
	Query          string `json:"query"`
	Limit          int    `json:"limit,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

func (c *Client) Query(ctx context.Context, req QueryRequest) (*warehouse.QueryResult, error) {
	var resp warehouse.QueryResult
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/query", nil, req, &resp); err != nil {
		return nil, err
	}
	if resp.Columns == nil {
		resp.Columns = []string{}
	}
	if resp.Rows == nil {
		resp.Rows = []map[string]interface{}{}
	}
	return &resp, nil
}
