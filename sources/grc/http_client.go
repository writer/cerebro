package grc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
)

type pageResponse struct {
	Results struct {
		PageInfo pageInfo          `json:"pageInfo"`
		Data     []json.RawMessage `json:"data"`
	} `json:"results"`
}

type pageInfo struct {
	EndCursor   string `json:"endCursor"`
	HasNextPage bool   `json:"hasNextPage"`
}

// New constructs the GRC source.

func (s *Source) list(ctx context.Context, settings settings, path string, cursor string, pageSize int) ([]grcRecord, string, error) {
	token, err := s.token(ctx, settings)
	if err != nil {
		return nil, "", err
	}
	response, err := s.listPage(ctx, settings, path, cursor, pageSize, token)
	if err != nil && sourcecdk.IsHTTPStatus(err, http.StatusUnauthorized) {
		s.invalidateToken(settings)
		token, tokenErr := s.token(ctx, settings)
		if tokenErr != nil {
			return nil, "", tokenErr
		}
		response, err = s.listPage(ctx, settings, path, cursor, pageSize, token)
	}
	if err != nil {
		return nil, "", err
	}
	records := make([]grcRecord, 0, len(response.Results.Data))
	for _, raw := range response.Results.Data {
		record, err := parseRecord(settings.family, raw)
		if err != nil {
			return nil, "", err
		}
		records = append(records, record)
	}
	if response.Results.PageInfo.HasNextPage {
		return records, strings.TrimSpace(response.Results.PageInfo.EndCursor), nil
	}
	return records, "", nil
}

func (s *Source) listPage(ctx context.Context, settings settings, path string, cursor string, pageSize int, token string) (pageResponse, error) {
	query := url.Values{}
	query.Set("pageSize", strconv.Itoa(pageSize))
	if strings.TrimSpace(cursor) != "" {
		query.Set("pageCursor", strings.TrimSpace(cursor))
	}
	endpoint := settings.baseURL + path
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return pageResponse{}, fmt.Errorf("build request %s: %w", path, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	var response pageResponse
	if err := s.doJSON(req, &response); err != nil {
		return pageResponse{}, err
	}
	return response, nil
}

func (s *Source) doJSON(req *http.Request, target any) error {
	if s == nil {
		return fmt.Errorf("grc source is required")
	}
	client := s.client
	cloned := sourcehttp.HardenClient(client, sourcehttp.ClientOptions{
		SourceID:      "grc",
		Timeout:       httpTimeout,
		AllowLoopback: s.allowLoopbackBaseURL,
		LookupIPAddrs: lookupIPAddrs(s),
	})
	resp, err := cloned.Do(req) // #nosec G704 -- requests are constructed from normalized GRC source URLs before this call.
	if err != nil {
		return fmt.Errorf("request %s: %w", req.URL.Path, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := sourcehttp.ReadLimitedBodyWithLimit(resp.Body, maxBodyBytes)
	if err != nil {
		return fmt.Errorf("read %s response: %w", req.URL.Path, err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return decodeResponseError(resp.StatusCode, body)
	}
	if target == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode %s response: %w", req.URL.Path, err)
	}
	return nil
}

func lookupIPAddrs(source *Source) func(context.Context, string) ([]net.IPAddr, error) {
	if source != nil && source.lookupIPAddrs != nil {
		return source.lookupIPAddrs
	}
	return net.DefaultResolver.LookupIPAddr
}

func decodeResponseError(statusCode int, body []byte) error {
	message := strings.TrimSpace(string(body))
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err == nil {
		for _, key := range []string{"message", "error_description", "error"} {
			if value := valueString(payload[key]); value != "" {
				message = value
				break
			}
		}
	}
	if message == "" {
		message = http.StatusText(statusCode)
	}
	return &sourcecdk.HTTPStatusError{Code: statusCode, Message: message}
}
