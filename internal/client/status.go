package client

import (
	"context"
	"net/http"
)

func (c *Client) AdminHealth(ctx context.Context) (map[string]interface{}, error) {
	var resp map[string]interface{}
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/admin/health", nil, nil, &resp); err != nil {
		return nil, err
	}
	if resp == nil {
		resp = map[string]interface{}{}
	}
	return resp, nil
}
