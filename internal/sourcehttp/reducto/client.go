package reducto

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/grcupload"
	"github.com/writer/cerebro/internal/sourcehttp"
)

const (
	reductoSourceID                 = "reducto"
	defaultReductoBaseURL           = "https://platform.reducto.ai"
	defaultReductoTimeout           = 30 * time.Second
	maxReductoErrorBodyBytes  int64 = 8192
	maxReductoBodyBytes       int64 = 8 << 20
	maxReductoResultURLBytes  int64 = 16 << 20
	maxParsedTextPreviewChars       = 1200
	grcUploadStructureSchema        = "grc_upload_v1"
)

type Config struct {
	APIKey  string
	BaseURL string
	Timeout time.Duration
}

type Client struct {
	baseURL     *url.URL
	apiKey      string
	httpClient  *http.Client
	httpOptions sourcehttp.ClientOptions
}

type Option func(*Client)

func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) {
		if client != nil {
			c.httpClient = sourcehttp.HardenClient(client, c.httpOptions)
		}
	}
}

func NewClient(cfg Config, opts ...Option) (*Client, error) {
	apiKey := strings.TrimSpace(cfg.APIKey)
	if apiKey == "" {
		return nil, fmt.Errorf("%w: CEREBRO_REDUCTO_API_KEY is required", grcupload.ErrRuntimeUnavailable)
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		base = defaultReductoBaseURL
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("%w: Reducto base URL is invalid", grcupload.ErrInvalidRequest)
	}
	if !allowedReductoURL(parsed) {
		return nil, fmt.Errorf("%w: Reducto base URL must use https unless it targets loopback", grcupload.ErrInvalidRequest)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultReductoTimeout
	}
	httpOptions := sourcehttp.ClientOptions{
		SourceID:      reductoSourceID,
		Timeout:       timeout,
		AllowLoopback: parsed.Scheme == "http" && sourcehttp.IsLoopbackHost(parsed.Hostname()),
	}
	client := &Client{
		baseURL:     parsed,
		apiKey:      apiKey,
		httpClient:  sourcehttp.NewClient(httpOptions),
		httpOptions: httpOptions,
	}
	for _, opt := range opts {
		opt(client)
	}
	return client, nil
}

func (c *Client) Parse(ctx context.Context, fileName string, contentType string, contents io.Reader) (grcupload.ParsedDocument, error) {
	if c == nil || c.baseURL == nil || c.httpClient == nil || strings.TrimSpace(c.apiKey) == "" {
		return grcupload.ParsedDocument{}, grcupload.ErrRuntimeUnavailable
	}
	fileID, err := c.upload(ctx, fileName, contentType, contents)
	if err != nil {
		return grcupload.ParsedDocument{}, err
	}
	parsed, err := c.extract(ctx, fileID)
	if err != nil {
		return grcupload.ParsedDocument{}, err
	}
	parsed.ProviderFileID = firstNonEmpty(parsed.ProviderFileID, fileID)
	return parsed, nil
}

func (c *Client) upload(ctx context.Context, fileName string, contentType string, contents io.Reader) (string, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", firstNonEmpty(fileName, "document"))
	if err != nil {
		return "", fmt.Errorf("%w: build Reducto upload request: %w", grcupload.ErrInvalidRequest, err)
	}
	if _, err := io.Copy(part, contents); err != nil {
		_ = writer.Close()
		return "", fmt.Errorf("%w: read upload file: %w", grcupload.ErrInvalidRequest, err)
	}
	if contentType != "" {
		_ = writer.WriteField("content_type", contentType)
	}
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("%w: close Reducto upload request: %w", grcupload.ErrInvalidRequest, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.resolvePath("/upload"), &body)
	if err != nil {
		return "", fmt.Errorf("%w: build Reducto upload request: %w", grcupload.ErrInvalidRequest, err)
	}
	request.Header.Set("Authorization", "Bearer "+c.apiKey)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response, err := c.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("%w: upload request: %w", grcupload.ErrRemote, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", reductoStatusError("upload", response)
	}
	payload, err := readJSON(response.Body, maxReductoBodyBytes)
	if err != nil {
		return "", fmt.Errorf("%w: decode Reducto upload response: %w", grcupload.ErrRemote, err)
	}
	fileID := lookupTopString(payload, "file_id", "document_url", "url", "id", "reducto_file_id")
	if fileID == "" {
		fileID = lookupTopString(lookupTopValue(payload, "result"), "file_id", "document_url", "reducto_file_id")
	}
	if fileID == "" {
		return "", fmt.Errorf("%w: Reducto upload response missing file_id", grcupload.ErrRemote)
	}
	return fileID, nil
}

func (c *Client) extract(ctx context.Context, fileID string) (grcupload.ParsedDocument, error) {
	body, err := json.Marshal(grcUploadExtractRequest(fileID))
	if err != nil {
		return grcupload.ParsedDocument{}, fmt.Errorf("%w: encode Reducto extract request: %w", grcupload.ErrInvalidRequest, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.resolvePath("/extract"), bytes.NewReader(body))
	if err != nil {
		return grcupload.ParsedDocument{}, fmt.Errorf("%w: build Reducto extract request: %w", grcupload.ErrInvalidRequest, err)
	}
	request.Header.Set("Authorization", "Bearer "+c.apiKey)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return grcupload.ParsedDocument{}, fmt.Errorf("%w: extract request: %w", grcupload.ErrRemote, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return grcupload.ParsedDocument{}, reductoStatusError("extract", response)
	}
	payload, err := readJSON(response.Body, maxReductoBodyBytes)
	if err != nil {
		return grcupload.ParsedDocument{}, fmt.Errorf("%w: decode Reducto extract response: %w", grcupload.ErrRemote, err)
	}
	parsed := parsedDocumentFromPayload(payload)
	if resultURL := lookupTopString(payload, "result_url", "download_url", "url"); parsed.ChunkCount == 0 && resultURL != "" {
		resultPayload, err := c.fetchResultURL(ctx, resultURL)
		if err != nil {
			return grcupload.ParsedDocument{}, err
		}
		parsed = mergeParsedDocument(parsed, parsedDocumentFromPayload(resultPayload))
	}
	parsed.ProviderFileID = firstNonEmpty(parsed.ProviderFileID, fileID)
	parsed.StructureSchema = firstNonEmpty(parsed.StructureSchema, grcUploadStructureSchema)
	return parsed, nil
}

func grcUploadExtractRequest(fileID string) map[string]any {
	return map[string]any{
		"input": fileID,
		"parsing": map[string]any{
			"enhance": map[string]any{
				"agentic":              []string{},
				"intelligent_ordering": true,
				"summarize_figures":    true,
			},
		},
		"instructions": map[string]any{
			"schema":        grcUploadExtractionSchema(),
			"system_prompt": "Extract GRC document fields for policy and vendor evidence review. Return only facts present in the document.",
		},
		"settings": map[string]any{
			"include_images":       false,
			"optimize_for_latency": false,
			"array_extract":        false,
			"deep_extract":         false,
			"citations": map[string]any{
				"enabled":              false,
				"numerical_confidence": true,
				"parent_block":         "full",
			},
		},
	}
}

func grcUploadExtractionSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"document_title":  map[string]any{"type": "string"},
			"document_type":   map[string]any{"type": "string"},
			"summary":         map[string]any{"type": "string"},
			"policy_name":     map[string]any{"type": "string"},
			"vendor_name":     map[string]any{"type": "string"},
			"owner":           map[string]any{"type": "string"},
			"effective_date":  map[string]any{"type": "string"},
			"review_due_date": map[string]any{"type": "string"},
			"controls":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"requirements":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"risks":           map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		},
	}
}

func (c *Client) fetchResultURL(ctx context.Context, rawURL string) (any, error) {
	resultURL, err := sourcehttp.SameOriginAbsoluteURL(reductoSourceID, c.baseURL.String(), rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: Reducto result URL is invalid: %w", grcupload.ErrRemote, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resultURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build Reducto result request: %w", grcupload.ErrRemote, err)
	}
	request.Header.Set("Authorization", "Bearer "+c.apiKey)
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: result request: %w", grcupload.ErrRemote, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, reductoStatusError("result", response)
	}
	return readJSON(response.Body, maxReductoResultURLBytes)
}

func parsedDocumentFromPayload(payload any) grcupload.ParsedDocument {
	result := lookupTopValue(payload, "result")
	chunks := lookupTopArray(payload, "chunks")
	if len(chunks) == 0 {
		chunks = lookupArray(result, "chunks")
	}
	texts := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		texts = append(texts, contentStrings(chunk)...)
	}
	if len(texts) == 0 {
		texts = contentStrings(result)
	}
	if len(texts) == 0 {
		texts = contentStrings(payload)
	}
	pageCount := lookupTopInt(payload, "page_count", "pages")
	if pageCount == 0 {
		pageCount = lookupFirstInt(result, "page_count", "pages")
	}
	preview := truncateRunes(compactWhitespace(strings.Join(texts, " ")), maxParsedTextPreviewChars)
	structuredFields := structuredFieldsFromPayload(payload)
	structuredSummary := structuredSummaryFromFields(structuredFields)
	return grcupload.ParsedDocument{
		ProviderFileID:    lookupTopString(payload, "file_id", "document_url", "input", "reducto_file_id"),
		ParseID:           lookupTopString(payload, "parse_id", "job_id", "id"),
		Status:            firstNonEmpty(lookupTopString(payload, "status"), "parsed"),
		TextPreview:       preview,
		ChunkCount:        len(chunks),
		PageCount:         pageCount,
		StructureStatus:   firstNonEmpty(lookupTopString(payload, "structure_status", "extract_status"), lookupTopString(payload, "status"), "structured"),
		StructureSchema:   grcUploadStructureSchema,
		StructuredSummary: structuredSummary,
		StructuredFields:  structuredFields,
	}
}

func mergeParsedDocument(left grcupload.ParsedDocument, right grcupload.ParsedDocument) grcupload.ParsedDocument {
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
	if left.StructureStatus == "" {
		left.StructureStatus = right.StructureStatus
	}
	if left.StructureSchema == "" {
		left.StructureSchema = right.StructureSchema
	}
	if left.StructuredSummary == "" {
		left.StructuredSummary = right.StructuredSummary
	}
	if len(left.StructuredFields) == 0 {
		left.StructuredFields = right.StructuredFields
	}
	return left
}

func readJSON(reader io.Reader, maxBytes int64) (any, error) {
	var payload any
	decoder := json.NewDecoder(io.LimitReader(reader, maxBytes))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
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
	return fmt.Errorf("%w: Reducto %s returned %d: %s", grcupload.ErrRemote, action, response.StatusCode, message)
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

func lookupTopString(value any, keys ...string) string {
	for _, key := range keys {
		if found := scalarString(lookupTopValue(value, key)); found != "" {
			return found
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

func lookupTopInt(value any, keys ...string) int {
	for _, key := range keys {
		if found := scalarInt(lookupTopValue(value, key)); found > 0 {
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
				if found := scalarInt(rawValue); found > 0 {
					return found
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

func lookupTopArray(value any, key string) []any {
	if values, ok := lookupTopValue(value, key).([]any); ok {
		return values
	}
	return nil
}

func lookupTopValue(value any, key string) any {
	typed, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	for rawKey, rawValue := range typed {
		if strings.EqualFold(rawKey, key) {
			return rawValue
		}
	}
	return nil
}

func structuredFieldsFromPayload(payload any) []grcupload.StructuredField {
	candidates := []any{
		lookupTopValue(payload, "extraction"),
		lookupTopValue(payload, "structured"),
		lookupTopValue(payload, "structured_data"),
		lookupTopValue(payload, "data"),
		lookupTopValue(lookupTopValue(payload, "result"), "extraction"),
		lookupTopValue(lookupTopValue(payload, "result"), "structured"),
		lookupTopValue(lookupTopValue(payload, "result"), "data"),
		lookupTopValue(payload, "result"),
	}
	for _, candidate := range candidates {
		fields := structuredFieldsFromValue(candidate, "")
		if len(fields) > 0 {
			return fields
		}
	}
	return nil
}

func structuredFieldsFromValue(value any, prefix string) []grcupload.StructuredField {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			if !skipStructuredFieldKey(key) {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		fields := []grcupload.StructuredField{}
		for _, key := range keys {
			rawValue := typed[key]
			fieldKey := key
			if prefix != "" {
				fieldKey = prefix + "." + key
			}
			if scalar := scalarString(rawValue); scalar != "" {
				fields = append(fields, grcupload.StructuredField{Key: fieldKey, Label: labelForFieldKey(fieldKey), Value: scalar})
				continue
			}
			if values := scalarStrings(rawValue); len(values) > 0 {
				fields = append(fields, grcupload.StructuredField{Key: fieldKey, Label: labelForFieldKey(fieldKey), Value: strings.Join(values, "; ")})
				continue
			}
			fields = append(fields, structuredFieldsFromValue(rawValue, fieldKey)...)
		}
		return fields
	case []any:
		values := scalarStrings(typed)
		if len(values) > 0 && prefix != "" {
			return []grcupload.StructuredField{{Key: prefix, Label: labelForFieldKey(prefix), Value: strings.Join(values, "; ")}}
		}
		fields := []grcupload.StructuredField{}
		for _, rawValue := range typed {
			fields = append(fields, structuredFieldsFromValue(rawValue, prefix)...)
		}
		return fields
	}
	return nil
}

func scalarStrings(value any) []string {
	switch typed := value.(type) {
	case []any:
		values := []string{}
		for _, rawValue := range typed {
			if scalar := scalarString(rawValue); scalar != "" {
				values = append(values, scalar)
			}
		}
		return values
	case []string:
		values := []string{}
		for _, rawValue := range typed {
			if scalar := strings.TrimSpace(rawValue); scalar != "" {
				values = append(values, scalar)
			}
		}
		return values
	}
	return nil
}

func structuredSummaryFromFields(fields []grcupload.StructuredField) string {
	for _, key := range []string{"summary", "document_summary"} {
		for _, field := range fields {
			if strings.EqualFold(field.Key, key) {
				return field.Value
			}
		}
	}
	return ""
}

func skipStructuredFieldKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "", "chunks", "blocks", "pages", "page_count", "content", "text", "markdown", "result_url", "download_url", "url", "status", "parse_id", "job_id", "id", "input", "file_id":
		return true
	default:
		return false
	}
}

func labelForFieldKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	key = strings.ReplaceAll(key, "_", " ")
	key = strings.ReplaceAll(key, ".", " ")
	return strings.Join(strings.Fields(key), " ")
}

func scalarString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return strings.TrimSpace(typed.String())
	case float64:
		return strings.TrimSpace(strconv.FormatFloat(typed, 'f', -1, 64))
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	}
	return ""
}

func scalarInt(value any) int {
	switch typed := value.(type) {
	case json.Number:
		if parsed, err := typed.Int64(); err == nil && parsed > 0 {
			return int(parsed)
		}
		if parsed, err := strconv.ParseFloat(typed.String(), 64); err == nil && parsed > 0 {
			return int(parsed)
		}
	case float64:
		if typed > 0 {
			return int(typed)
		}
	case int:
		return typed
	case int64:
		if typed > 0 {
			return int(typed)
		}
	}
	return 0
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
			switch rawValue.(type) {
			case map[string]any, []any:
				texts = append(texts, contentStrings(rawValue)...)
			}
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

func compactWhitespace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func (c *Client) resolvePath(path string) string {
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
