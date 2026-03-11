package client

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/writer/cerebro/internal/providers"
)

func (c *Client) SyncProvider(ctx context.Context, name string) (*providers.SyncResult, error) {
	return c.SyncProviderWithOptions(ctx, name, ProviderSyncOptions{})
}

type ProviderSyncOptions struct {
	FullSync *bool
	Tables   []string
}

func (c *Client) SyncProviderWithOptions(ctx context.Context, name string, opts ProviderSyncOptions) (*providers.SyncResult, error) {
	path := "/api/v1/providers/" + url.PathEscape(strings.TrimSpace(name)) + "/sync"

	var reqBody map[string]interface{}
	if opts.FullSync != nil {
		reqBody = map[string]interface{}{
			"full_sync": *opts.FullSync,
		}
	}
	if len(opts.Tables) > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["tables"] = opts.Tables
	}

	var result providers.SyncResult
	if err := c.doJSON(ctx, http.MethodPost, path, nil, reqBody, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
