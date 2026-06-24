package sentinelone

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
)

const (
	httpTimeout  = 30 * time.Second
	maxBodyBytes = 8 << 20
)

type listResponse struct {
	Data       json.RawMessage `json:"data"`
	Pagination paginationInfo  `json:"pagination"`
}

type paginationInfo struct {
	NextCursor string `json:"nextCursor"`
	TotalItems int    `json:"totalItems"`
}

type apiError struct {
	Errors []apiErrorDetail `json:"errors"`
}

type apiErrorDetail struct {
	Code   int    `json:"code"`
	Detail string `json:"detail"`
	Title  string `json:"title"`
}

type responseError struct {
	statusCode int
	message    string
}

func (e *responseError) Error() string {
	return e.message
}

func (e *responseError) StatusCode() int {
	return e.statusCode
}

func (s *Source) getJSON(ctx context.Context, settings settings, requestPath string, query url.Values, target any) error {
	endpoint := settings.baseURL + requestPath
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build request %s: %w", requestPath, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "ApiToken "+settings.token)

	client := s.client
	if client == nil {
		client = httpClientNoRedirect(nil, s != nil && s.allowLoopbackBaseURL, lookupIPAddrs(s))
	} else {
		client = httpClientNoRedirect(client, s != nil && s.allowLoopbackBaseURL, lookupIPAddrs(s))
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", requestPath, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := sourcehttp.ReadLimitedBodyWithLimit(resp.Body, maxBodyBytes)
	if err != nil {
		return fmt.Errorf("read %s response: %w", requestPath, err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return decodeResponseError(resp.StatusCode, body)
	}
	if target == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode %s response: %w", requestPath, err)
	}
	return nil
}

func httpClientNoRedirect(client *http.Client, allowLoopback bool, lookupIPAddrs func(context.Context, string) ([]net.IPAddr, error)) *http.Client {
	return sourcehttp.HardenSourceClient(client, "sentinelone", httpTimeout, allowLoopback, lookupIPAddrs)
}

func lookupIPAddrs(source *Source) func(context.Context, string) ([]net.IPAddr, error) {
	if source != nil && source.lookupIPAddrs != nil {
		return source.lookupIPAddrs
	}
	return net.DefaultResolver.LookupIPAddr
}

func decodeResponseError(statusCode int, body []byte) error {
	message := http.StatusText(statusCode)
	var apiErr apiError
	if err := json.Unmarshal(body, &apiErr); err == nil && len(apiErr.Errors) > 0 {
		first := apiErr.Errors[0]
		title := strings.TrimSpace(first.Title)
		detail := strings.TrimSpace(first.Detail)
		switch {
		case title != "" && detail != "":
			message = fmt.Sprintf("%s: %s", title, detail)
		case detail != "":
			message = detail
		case title != "":
			message = title
		}
	}
	return &responseError{
		statusCode: statusCode,
		message:    fmt.Sprintf("sentinelone API returned %d: %s", statusCode, message),
	}
}

func listJSONRecords[T any, P interface {
	*T
	rawCarrier
}](ctx context.Context, source *Source, settings settings, requestPath string, query url.Values) ([]T, string, error) {
	var resp listResponse
	if err := source.getJSON(ctx, settings, requestPath, query, &resp); err != nil {
		return nil, "", err
	}
	items, pagination, err := sourcecdk.DecodeListResponseData(resp.Data, requestPath, "activities", "agents", "applications", "exclusions", "groups", "sites", "threats")
	if err != nil {
		return nil, "", err
	}
	records := make([]T, 0, len(items))
	for _, item := range items {
		var record T
		if err := json.Unmarshal(item, &record); err != nil {
			return nil, "", fmt.Errorf("decode %s record: %w", requestPath, err)
		}
		P(&record).setRaw(cloneRaw(item))
		records = append(records, record)
	}
	return records, strings.TrimSpace(firstNonEmpty(pagination.NextCursor, resp.Pagination.NextCursor)), nil
}
