package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

type listNotifiersResponse struct {
	Notifiers []string `json:"notifiers"`
	Count     int      `json:"count"`
}

type NotificationTestResponse struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

func (c *Client) ListNotifiers(ctx context.Context, limit, offset int) ([]string, error) {
	query := url.Values{}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	if offset > 0 {
		query.Set("offset", strconv.Itoa(offset))
	}

	var resp listNotifiersResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/notifications/", query, nil, &resp); err != nil {
		return nil, err
	}
	if resp.Notifiers == nil {
		return []string{}, nil
	}
	return resp.Notifiers, nil
}

func (c *Client) TestNotifications(ctx context.Context, message, severity string) (*NotificationTestResponse, error) {
	req := map[string]interface{}{
		"message":  message,
		"severity": severity,
	}

	var resp NotificationTestResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/notifications/test", nil, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
