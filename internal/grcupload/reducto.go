package grcupload

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/sourcehttp"
)

const (
	defaultReductoBaseURL           = "https://platform.reducto.ai"
	defaultReductoTimeout           = 30 * time.Second
	maxReductoErrorBodyBytes  int64 = 8192
	maxReductoBodyBytes       int64 = 8 << 20
	maxReductoResultURLBytes  int64 = 16 << 20
	maxParsedTextPreviewChars       = 1200
)

type Parser interface {
	Parse(ctx context.Context, fileName string, contentType string, contents io.Reader) (ParsedDocument, error)
}

type ReductoConfig struct {
	APIKey  string
	BaseURL string
	Timeout time.Duration
}

type ReductoClient struct {
	baseURL    *url.URL
	apiKey     string
	httpClient *http.Client
}

type ReductoOption func(*ReductoClient)

func WithReductoHTTPClient(client *http.Client) ReductoOption {
	return func(c *ReductoClient) {
		if client != nil {
			c.httpClient = client
		}
	}
}

func NewReductoClient(cfg ReductoConfig, opts ...ReductoOption) (*ReductoClient, error) {
	apiKey := strings.TrimSpace(cfg.APIKey)
	if apiKey == "" {
		return nil, fmt.Errorf("%w: CEREBRO_REDUCTO_API_KEY is required", ErrRuntimeUnavailable)
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		base = defaultReductoBaseURL
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("%w: Reducto base URL is invalid", ErrInvalidRequest)
	}
	if !allowedReductoURL(parsed) {
		return nil, fmt.Errorf("%w: Reducto base URL must use https unless it targets loopback", ErrInvalidRequest)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultReductoTimeout
	}
	client := &ReductoClient{
		baseURL: parsed,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
	for _, opt := range opts {
		opt(client)
	}
	return client, nil
}

func (c *ReductoClient) Parse(ctx context.Context, fileName string, contentType string, contents io.Reader) (ParsedDocument, error) {
	if c == nil || c.baseURL == nil || c.httpClient == nil || strings.TrimSpace(c.apiKey) == "" {
		return ParsedDocument{}, ErrRuntimeUnavailable
	}
	fileID, err := c.upload(ctx, fileName, contentType, contents)
	if err != nil {
		return ParsedDocument{}, err
	}
	parsed, err := c.parse(ctx, fileID)
	if err != nil {
		return ParsedDocument{}, err
	}
	parsed.ProviderFileID = firstNonEmpty(parsed.ProviderFileID, fileID)
	return parsed, nil
}

func (c *ReductoClient) upload(ctx context.Context, fileName string, contentType string, contents io.Reader) (string, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", firstNonEmpty(fileName, "document"))
	if err != nil {
		return "", fmt.Errorf("%w: build Reducto upload request: %w", ErrInvalidRequest, err)
	}
	if _, err := io.Copy(part, contents); err != nil {
		_ = writer.Close()
		return "", fmt.Errorf("%w: read upload file: %w", ErrInvalidRequest, err)
	}
	if contentType != "" {
		_ = writer.WriteField("content_type", contentType)
	}
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("%w: close Reducto upload request: %w", ErrInvalidRequest, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.resolvePath("/upload"), &body)
	if err != nil {
		return "", fmt.Errorf("%w: build Reducto upload request: %w", ErrInvalidRequest, err)
	}
	request.Header.Set("Authorization", "Bearer "+c.apiKey)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response, err := c.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("%w: upload request: %w", ErrRemote, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", reductoStatusError("upload", response)
	}
	payload, err := readJSON(response.Body, maxReductoBodyBytes)
	if err != nil {
		return "", fmt.Errorf("%w: decode Reducto upload response: %w", ErrRemote, err)
	}
	fileID := lookupFirstString(payload, "file_id", "document_url", "url", "id", "reducto_file_id")
	if fileID == "" {
		return "", fmt.Errorf("%w: Reducto upload response missing file_id", ErrRemote)
	}
	return fileID, nil
}

func (c *ReductoClient) parse(ctx context.Context, fileID string) (ParsedDocument, error) {
	body, err := json.Marshal(map[string]any{"input": fileID})
	if err != nil {
		return ParsedDocument{}, fmt.Errorf("%w: encode Reducto parse request: %w", ErrInvalidRequest, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.resolvePath("/parse"), bytes.NewReader(body))
	if err != nil {
		return ParsedDocument{}, fmt.Errorf("%w: build Reducto parse request: %w", ErrInvalidRequest, err)
	}
	request.Header.Set("Authorization", "Bearer "+c.apiKey)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return ParsedDocument{}, fmt.Errorf("%w: parse request: %w", ErrRemote, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ParsedDocument{}, reductoStatusError("parse", response)
	}
	payload, err := readJSON(response.Body, maxReductoBodyBytes)
	if err != nil {
		return ParsedDocument{}, fmt.Errorf("%w: decode Reducto parse response: %w", ErrRemote, err)
	}
	parsed := parsedDocumentFromPayload(payload)
	if resultURL := lookupFirstString(payload, "result_url", "download_url", "url"); parsed.ChunkCount == 0 && resultURL != "" {
		if resultPayload, err := c.fetchResultURL(ctx, resultURL); err == nil {
			parsed = mergeParsedDocument(parsed, parsedDocumentFromPayload(resultPayload))
		}
	}
	parsed.ProviderFileID = firstNonEmpty(parsed.ProviderFileID, fileID)
	return parsed, nil
}

func (c *ReductoClient) fetchResultURL(ctx context.Context, rawURL string) (any, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("%w: Reducto result URL is invalid", ErrRemote)
	}
	if !allowedReductoURL(parsed) {
		return nil, fmt.Errorf("%w: Reducto result URL must use https unless it targets loopback", ErrRemote)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build Reducto result request: %w", ErrRemote, err)
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: result request: %w", ErrRemote, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, reductoStatusError("result", response)
	}
	return readJSON(response.Body, maxReductoResultURLBytes)
}

func parsedDocumentFromPayload(payload any) ParsedDocument {
	chunks := lookupArray(payload, "chunks")
	texts := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		texts = append(texts, contentStrings(chunk)...)
	}
	if len(texts) == 0 {
		texts = contentStrings(lookupValue(payload, "result"))
	}
	if len(texts) == 0 {
		texts = contentStrings(payload)
	}
	preview := truncateRunes(compactWhitespace(strings.Join(texts, " ")), maxParsedTextPreviewChars)
	return ParsedDocument{
		ProviderFileID: lookupFirstString(payload, "file_id", "document_url", "input", "reducto_file_id"),
		ParseID:        lookupFirstString(payload, "parse_id", "job_id", "id"),
		Status:         firstNonEmpty(lookupFirstString(payload, "status"), "parsed"),
		TextPreview:    preview,
		ChunkCount:     len(chunks),
		PageCount:      lookupFirstInt(payload, "page_count", "pages"),
	}
}

func mergeParsedDocument(left ParsedDocument, right ParsedDocument) ParsedDocument {
	if left.ProviderFileID == "" {
		left.ProviderFileID = right.ProviderFileID
	}
	if left.ParseID == "" {
		left.ParseID = right.ParseID
	}
	if left.Status == "" {
		left.Status = right.Status
	}
	if left.TextPreview == "" {
		left.TextPreview = right.TextPreview
	}
	if left.ChunkCount == 0 {
		left.ChunkCount = right.ChunkCount
	}
	if left.PageCount == 0 {
		left.PageCount = right.PageCount
	}
	return left
}

func readJSON(reader io.Reader, maxBytes int64) (any, error) {
	var payload any
	if err := json.NewDecoder(io.LimitReader(reader, maxBytes)).Decode(&payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func reductoStatusError(action string, response *http.Response) error {
	message := strings.TrimSpace(http.StatusText(response.StatusCode))
	if response.Body != nil {
		body, _ := io.ReadAll(io.LimitReader(response.Body, maxReductoErrorBodyBytes))
		if detail := errorMessage(body); detail != "" {
			message = detail
		}
	}
	if message == "" {
		message = "request failed"
	}
	return fmt.Errorf("%w: Reducto %s returned %d: %s", ErrRemote, action, response.StatusCode, message)
}

func errorMessage(body []byte) string {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err == nil {
		for _, key := range []string{"error", "message", "detail"} {
			if value, ok := payload[key].(string); ok && strings.TrimSpace(value) != "" {
				return truncateRunes(strings.TrimSpace(value), 300)
			}
		}
	}
	return truncateRunes(strings.TrimSpace(string(body)), 300)
}

func lookupFirstString(value any, keys ...string) string {
	for _, key := range keys {
		if found := lookupString(value, key); found != "" {
			return found
		}
	}
	return ""
}

func lookupString(value any, key string) string {
	switch typed := value.(type) {
	case map[string]any:
		for rawKey, rawValue := range typed {
			if strings.EqualFold(rawKey, key) {
				if text, ok := rawValue.(string); ok {
					return strings.TrimSpace(text)
				}
				if number, ok := rawValue.(json.Number); ok {
					return number.String()
				}
			}
		}
		for _, rawValue := range typed {
			if found := lookupString(rawValue, key); found != "" {
				return found
			}
		}
	case []any:
		for _, rawValue := range typed {
			if found := lookupString(rawValue, key); found != "" {
				return found
			}
		}
	}
	return ""
}

func lookupFirstInt(value any, keys ...string) int {
	for _, key := range keys {
		if found := lookupInt(value, key); found > 0 {
			return found
		}
	}
	return 0
}

func lookupInt(value any, key string) int {
	switch typed := value.(type) {
	case map[string]any:
		for rawKey, rawValue := range typed {
			if strings.EqualFold(rawKey, key) {
				switch v := rawValue.(type) {
				case float64:
					if v > 0 {
						return int(v)
					}
				case int:
					return v
				}
			}
		}
		for _, rawValue := range typed {
			if found := lookupInt(rawValue, key); found > 0 {
				return found
			}
		}
	case []any:
		for _, rawValue := range typed {
			if found := lookupInt(rawValue, key); found > 0 {
				return found
			}
		}
	}
	return 0
}

func lookupArray(value any, key string) []any {
	switch typed := value.(type) {
	case map[string]any:
		for rawKey, rawValue := range typed {
			if strings.EqualFold(rawKey, key) {
				if values, ok := rawValue.([]any); ok {
					return values
				}
			}
		}
		for _, rawValue := range typed {
			if found := lookupArray(rawValue, key); len(found) > 0 {
				return found
			}
		}
	case []any:
		for _, rawValue := range typed {
			if found := lookupArray(rawValue, key); len(found) > 0 {
				return found
			}
		}
	}
	return nil
}

func lookupValue(value any, key string) any {
	switch typed := value.(type) {
	case map[string]any:
		for rawKey, rawValue := range typed {
			if strings.EqualFold(rawKey, key) {
				return rawValue
			}
		}
		for _, rawValue := range typed {
			if found := lookupValue(rawValue, key); found != nil {
				return found
			}
		}
	case []any:
		for _, rawValue := range typed {
			if found := lookupValue(rawValue, key); found != nil {
				return found
			}
		}
	}
	return nil
}

func contentStrings(value any) []string {
	switch typed := value.(type) {
	case map[string]any:
		texts := []string{}
		for key, rawValue := range typed {
			normalizedKey := strings.ToLower(strings.TrimSpace(key))
			switch normalizedKey {
			case "text", "content", "markdown":
				if text, ok := rawValue.(string); ok && strings.TrimSpace(text) != "" {
					texts = append(texts, strings.TrimSpace(text))
					continue
				}
			}
			texts = append(texts, contentStrings(rawValue)...)
		}
		return texts
	case []any:
		texts := []string{}
		for _, rawValue := range typed {
			texts = append(texts, contentStrings(rawValue)...)
		}
		return texts
	case string:
		value := strings.TrimSpace(typed)
		if value != "" && len(value) > 20 {
			return []string{value}
		}
	}
	return nil
}

func truncateRunes(value string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return value
	}
	return string(runes[:maxRunes])
}

func (c *ReductoClient) resolvePath(path string) string {
	resolved := *c.baseURL
	basePath := strings.TrimRight(resolved.Path, "/")
	resolved.Path = basePath + "/" + strings.TrimLeft(path, "/")
	resolved.RawQuery = ""
	resolved.Fragment = ""
	return resolved.String()
}

func allowedReductoURL(value *url.URL) bool {
	if value == nil {
		return false
	}
	if value.Scheme == "https" {
		return true
	}
	return value.Scheme == "http" && sourcehttp.IsLoopbackHost(value.Hostname())
}
