package cosmo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
)

const (
	httpTimeout  = 30 * time.Second
	maxBodyBytes = 8 << 20
)

type record struct {
	Raw    json.RawMessage
	Values map[string]any
	ID     string
}

type listResponse struct {
	OK       bool              `json:"ok"`
	Count    int               `json:"count"`
	Sessions []json.RawMessage `json:"sessions"`
	Facts    []json.RawMessage `json:"facts"`
	Messages []json.RawMessage `json:"messages"`
	Feedback []json.RawMessage `json:"feedback"`
}

func (s *Source) getJSON(ctx context.Context, settings settings, method string, requestPath string, query url.Values, body []byte, target any) error {
	endpoint := settings.baseURL + requestPath
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return fmt.Errorf("build request %s: %w", requestPath, err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if settings.family == familySurveyFeedback && settings.webhookSecret != "" {
		req.Header.Set("X-Webhook-Secret", settings.webhookSecret)
	} else {
		req.Header.Set("Authorization", "Bearer "+settings.token)
	}
	if settings.family == familyMessage {
		req.Header.Set("X-Cosmo-Client", settings.clientID)
		req.Header.Set("X-Cerebro-Export-Secret", settings.exportSecret)
	}

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

	payload, err := sourcehttp.ReadLimitedBodyWithLimit(resp.Body, maxBodyBytes)
	if err != nil {
		return fmt.Errorf("read %s response: %w", requestPath, err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return decodeResponseError(resp.StatusCode, payload)
	}
	if target == nil || len(payload) == 0 {
		return nil
	}
	if err := json.Unmarshal(payload, target); err != nil {
		return fmt.Errorf("decode %s response: %w", requestPath, err)
	}
	return nil
}

func (s *Source) listMemory(ctx context.Context, settings settings, path string, collection string, offset int, limit int) ([]record, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	query.Set("offset", strconv.Itoa(offset))
	sourcecdk.AddQueryParam(query, "q", settings.query)
	sourcecdk.AddQueryParam(query, "user", settings.user)
	sourcecdk.AddQueryParam(query, "status", settings.status)
	sourcecdk.AddQueryParam(query, "category", settings.category)

	var response listResponse
	if err := s.getJSON(ctx, settings, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := responseRecords(response, collection, settings.family)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(records) == limit {
		next = strconv.Itoa(offset + limit)
	}
	return records, next, nil
}

func (s *Source) listMessages(ctx context.Context, settings settings, window messageWindow, limit int) ([]record, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	query.Set("offset", strconv.Itoa(window.offset))
	query.Set("event_type", settings.eventTypes[window.eventTypeIndex])
	query.Set("since", window.since.Format(time.RFC3339Nano))
	query.Set("until", window.until.Format(time.RFC3339Nano))

	var response listResponse
	if err := s.getJSON(ctx, settings, http.MethodGet, "/api/cerebro/messages", query, nil, &response); err != nil {
		return nil, err
	}
	records, err := responseRecords(response, "messages", familyMessage)
	if err != nil {
		return nil, err
	}
	return records, nil
}

func (s *Source) listSurveyFeedback(ctx context.Context, settings settings) ([]record, error) {
	var response listResponse
	if settings.token != "" {
		if err := s.getJSON(ctx, settings, http.MethodGet, "/api/ui/memory/survey-results", nil, nil, &response); err != nil {
			return nil, err
		}
	} else {
		if err := s.getJSON(ctx, settings, http.MethodPost, "/api/survey-results", nil, []byte("{}"), &response); err != nil {
			return nil, err
		}
	}
	return responseRecords(response, "feedback", familySurveyFeedback)
}

func responseRecords(response listResponse, collection string, family string) ([]record, error) {
	var rawRecords []json.RawMessage
	switch collection {
	case "sessions":
		rawRecords = response.Sessions
	case "facts":
		rawRecords = response.Facts
	case "messages":
		rawRecords = response.Messages
	case "feedback":
		rawRecords = response.Feedback
	default:
		return nil, fmt.Errorf("unsupported cosmo collection %q", collection)
	}
	records := make([]record, 0, len(rawRecords))
	for _, raw := range rawRecords {
		record, err := parseRecord(family, raw)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func parseRecord(family string, raw json.RawMessage) (record, error) {
	var values map[string]any
	if err := json.Unmarshal(raw, &values); err != nil {
		return record{}, fmt.Errorf("decode cosmo %s record: %w", family, err)
	}
	return record{Raw: cloneRaw(raw), Values: values, ID: recordID(family, values)}, nil
}

func recordID(family string, values map[string]any) string {
	switch family {
	case familySession:
		return firstValueString(values, "thread_key", "ticket_id", "id")
	case familyFact:
		return firstValueString(values, "key", "id")
	case familyMessage:
		return firstNonEmpty(firstValueString(values, "id"), stableID(
			firstValueString(values, "ticket_id"),
			firstValueString(values, "event_type"),
			firstValueString(values, "created_at"),
		))
	case familySurveyFeedback:
		return firstNonEmpty(firstValueString(values, "key"), stableID(
			firstValueString(values, "ticketId"),
			firstValueString(values, "messageTs"),
			firstValueString(values, "userId"),
		))
	default:
		return firstValueString(values, "id", "key")
	}
}

func httpClientNoRedirect(client *http.Client, allowLoopback bool, lookupIPAddrs func(context.Context, string) ([]net.IPAddr, error)) *http.Client {
	return sourcehttp.HardenClient(client, sourcehttp.ClientOptions{
		SourceID:      "cosmo",
		Timeout:       httpTimeout,
		AllowLoopback: allowLoopback,
		LookupIPAddrs: lookupIPAddrs,
	})
}

func lookupIPAddrs(source *Source) func(context.Context, string) ([]net.IPAddr, error) {
	if source != nil && source.lookupIPAddrs != nil {
		return source.lookupIPAddrs
	}
	return net.DefaultResolver.LookupIPAddr
}

func decodeResponseError(statusCode int, body []byte) error {
	message := http.StatusText(statusCode)
	var apiErr struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &apiErr); err == nil && strings.TrimSpace(apiErr.Error) != "" {
		message = strings.TrimSpace(apiErr.Error)
	}
	return &responseError{
		statusCode: statusCode,
		message:    fmt.Sprintf("cosmo API returned %d: %s", statusCode, message),
	}
}

func firstValueString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := valueString(valueAt(values, key)); value != "" {
			return value
		}
	}
	return ""
}

func valueAt(values map[string]any, path string) any {
	current := any(values)
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = object[part]
	}
	return current
}

func valueString(value any) string {
	return sourcecdk.JSONScalar{Value: value}.Flattened()
}

func cloneRaw(raw json.RawMessage) json.RawMessage {
	return append(json.RawMessage(nil), raw...)
}

func stableID(parts ...string) string {
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			values = append(values, value)
		}
	}
	return strings.Join(values, ":")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
