package client

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/evalops/cerebro/internal/providers"
)

func (c *Client) SyncProvider(ctx context.Context, name string) (*providers.SyncResult, error) {
	path := "/api/v1/providers/" + url.PathEscape(strings.TrimSpace(name)) + "/sync"
	var result providers.SyncResult
	if err := c.doJSON(ctx, http.MethodPost, path, nil, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
