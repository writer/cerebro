package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

type tablesResponse struct {
	Tables []string `json:"tables"`
}

func (c *Client) ListTables(ctx context.Context, limit, offset int) ([]string, error) {
	query := url.Values{}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	if offset > 0 {
		query.Set("offset", strconv.Itoa(offset))
	}

	var resp tablesResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/tables", query, nil, &resp); err != nil {
		return nil, err
	}
	if resp.Tables == nil {
		resp.Tables = []string{}
	}
	return resp.Tables, nil
}
