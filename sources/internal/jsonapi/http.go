package jsonapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
	cerebrourn "github.com/writer/cerebro/internal/urn"
)

type record struct {
	Raw      json.RawMessage
	Values   map[string]any
	ID       string
	Identity string
}

func (s *Source) list(ctx context.Context, family Family, settings settings, cursor string, pageSize int) ([]record, string, error) {
	query := url.Values{}
	for key, value := range family.Config.StaticQuery {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			query.Set(strings.TrimSpace(key), strings.TrimSpace(value))
		}
	}
	for key, values := range settings.request.query {
		for _, value := range values {
			query.Add(key, value)
		}
	}
	if !family.DisablePageSize {
		for _, param := range pageSizeParams(family) {
			query.Set(param, strconv.Itoa(pageSize))
		}
	}
	pageCursor := strings.TrimSpace(cursor)
	if pageCursor == "" {
		pageCursor = strings.TrimSpace(family.PageFirstCursor)
	}
	useNextURL := isAbsoluteHTTPURL(pageCursor)
	if pageCursor != "" && !useNextURL {
		query.Set(cursorParam(family), pageCursor)
	}
	var body json.RawMessage
	var headers http.Header
	var err error
	if useNextURL {
		headers, err = s.doRequest(ctx, settings, pageCursor, nil, &body, nil)
	} else {
		headers, err = s.getJSONWithHeader(ctx, settings, query, &body)
	}
	if err != nil {
		return nil, "", err
	}
	items, next, err := parseListResponse(family, body)
	if err != nil {
		return nil, "", fmt.Errorf("%s %s: %w", s.options.SourceID, settings.family, err)
	}
	if next == "" {
		next = linkHeaderCursor(family, headers)
	}
	next = synthesizePageCursor(family, pageCursor, pageSize, len(items), next)
	records := make([]record, 0, len(items))
	for _, item := range items {
		item, err = rawWithPathParams(item, settings.request.pathParams)
		if err != nil {
			return nil, "", fmt.Errorf("%s %s: %w", s.options.SourceID, settings.family, err)
		}
		record, err := recordFromRaw(family, item)
		if err != nil {
			return nil, "", fmt.Errorf("%s %s: %w", s.options.SourceID, settings.family, err)
		}
		if record.ID != "" {
			records = append(records, record)
		}
	}
	if strings.TrimSpace(family.DetailPath) != "" {
		var err error
		records, err = s.enrichRecords(ctx, family, settings, records)
		if err != nil {
			return nil, "", err
		}
	}
	return records, next, nil
}

func (s *Source) enrichRecords(ctx context.Context, family Family, settings settings, records []record) ([]record, error) {
	enriched := make([]record, 0, len(records))
	for _, original := range records {
		path, err := resolveRecordPath(s.options.SourceID, family.DetailPath, settings.request.pathParams, original.Values)
		if err != nil {
			enriched = append(enriched, original)
			continue
		}
		detailSettings := settings
		detailSettings.path = path
		var body json.RawMessage
		if err := s.getJSON(ctx, detailSettings, url.Values{}, &body); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			enriched = append(enriched, original)
			continue
		}
		raw, err := detailRecordRaw(body, family.AllowBareDetailRecord)
		if err != nil {
			enriched = append(enriched, original)
			continue
		}
		next, err := mergedRecord(family, original, raw)
		if err != nil {
			enriched = append(enriched, original)
			continue
		}
		enriched = append(enriched, next)
	}
	return enriched, nil
}

func pageSizeParams(family Family) []string {
	if len(family.PageSizeParams) == 0 {
		return []string{"limit", "per_page"}
	}
	params := make([]string, 0, len(family.PageSizeParams))
	for _, param := range family.PageSizeParams {
		if param = strings.TrimSpace(param); param != "" {
			params = append(params, param)
		}
	}
	if len(params) == 0 {
		return []string{"limit", "per_page"}
	}
	return params
}

func cursorParam(family Family) string {
	if param := strings.TrimSpace(family.CursorParam); param != "" {
		return param
	}
	return "cursor"
}

func isAbsoluteHTTPURL(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	return parsed.IsAbs() && parsed.Host != "" && (strings.EqualFold(parsed.Scheme, "http") || strings.EqualFold(parsed.Scheme, "https"))
}

func synthesizePageCursor(family Family, cursor string, pageSize int, itemCount int, next string) string {
	if strings.TrimSpace(family.PageFirstCursor) == "" || strings.TrimSpace(next) != "" || pageSize < 1 || itemCount < pageSize {
		return next
	}
	current := strings.TrimSpace(cursor)
	if current == "" {
		current = strings.TrimSpace(family.PageFirstCursor)
	}
	page, err := strconv.Atoi(current)
	if err != nil {
		return next
	}
	return strconv.Itoa(page + 1)
}

func queryFromConfig(cfg sourcecdk.Config, configQuery map[string]string) url.Values {
	query := url.Values{}
	for queryKey, configKey := range configQuery {
		queryKey = strings.TrimSpace(queryKey)
		configKey = strings.TrimSpace(configKey)
		if queryKey == "" || configKey == "" {
			continue
		}
		if value := strings.TrimSpace(sourcecdk.ConfigValue(cfg, configKey)); value != "" {
			for _, item := range queryValues(value, strings.HasSuffix(queryKey, "[]")) {
				query.Add(queryKey, item)
			}
		}
	}
	return query
}

func queryValues(value string, split bool) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if !split {
		return []string{value}
	}
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			values = append(values, part)
		}
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

func (s *Source) getJSON(ctx context.Context, settings settings, query url.Values, target any) error {
	_, err := s.getJSONWithHeader(ctx, settings, query, target)
	return err
}

func (s *Source) getJSONWithHeader(ctx context.Context, settings settings, query url.Values, target any) (http.Header, error) {
	return s.doRequest(ctx, settings, settings.path, query, target, nil)
}

func (s *Source) doRequest(ctx context.Context, settings settings, path string, query url.Values, target any, expectStatuses []int) (http.Header, error) {
	endpoint, err := requestEndpoint(s.options.SourceID, settings.baseURL, settings.path, path)
	if err != nil {
		return nil, fmt.Errorf("build %s request: %w", s.options.SourceID, err)
	}
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	method := http.MethodGet
	if familyMethod := strings.TrimSpace(settings.familyMethod); familyMethod != "" {
		method = familyMethod
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build %s request: %w", s.options.SourceID, err)
	}
	req.Header.Set("Accept", "application/json")
	for key, value := range s.options.StaticHeaders {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			req.Header.Set(strings.TrimSpace(key), strings.TrimSpace(value))
		}
	}
	for key, value := range settings.request.headers {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			req.Header.Set(strings.TrimSpace(key), strings.TrimSpace(value))
		}
	}
	if err := s.authorizeRequest(ctx, settings, req); err != nil {
		return nil, err
	}
	client := s.client
	if client == nil {
		client = sourcehttp.NewClient(sourcehttp.ClientOptions{
			SourceID:                 s.options.SourceID,
			AllowLoopback:            s.AllowLoopbackBaseURL,
			PrivateEndpointAllowlist: settings.privateEndpointAllowlist,
			LookupIPAddrs:            lookupIPAddrs(s),
		})
	}
	resp, err := sourcehttp.DoWithRetry(ctx, client, req, sourcehttp.RetryOptions{})
	if err != nil {
		return nil, err
	}
	if len(expectStatuses) != 0 {
		for _, status := range expectStatuses {
			if resp.StatusCode == status {
				return resp.Header, nil
			}
		}
		return resp.Header, decodeResponseError(s.options.SourceID, resp.StatusCode, resp.Body)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.Header, decodeResponseError(s.options.SourceID, resp.StatusCode, resp.Body)
	}
	if target == nil {
		return resp.Header, nil
	}
	if err := json.Unmarshal(resp.Body, target); err != nil {
		return resp.Header, fmt.Errorf("decode %s response: %w", s.options.SourceID, err)
	}
	return resp.Header, nil
}

func requestEndpoint(sourceID string, baseURL string, defaultPath string, path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return baseURL + defaultPath, nil
	}
	parsed, err := url.Parse(path)
	if err != nil {
		return "", err
	}
	if !parsed.IsAbs() {
		return baseURL + path, nil
	}
	return sourcehttp.SameOriginAbsoluteURL(sourceID, baseURL, path)
}

func parseListResponse(family Family, raw json.RawMessage) ([]json.RawMessage, string, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err == nil {
		return items, "", nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, "", err
	}
	if family.Singleton {
		item, err := singletonRecord(raw, family.Name)
		if err != nil {
			return nil, "", err
		}
		return []json.RawMessage{item}, responseCursor(family, object), nil
	}
	for _, key := range responseListKeys(family) {
		if value, ok := object[key]; ok {
			if err := json.Unmarshal(value, &items); err == nil {
				return items, responseCursor(family, object), nil
			}
		}
	}
	for objectKey, valueKey := range family.MapRecords {
		if value, ok := object[objectKey]; ok {
			items, err := recordsFromObjectMap(value, valueKey)
			if err != nil {
				return nil, "", err
			}
			return items, responseCursor(family, object), nil
		}
	}
	return nil, "", fmt.Errorf("response did not contain a record list")
}

func responseListKeys(family Family) []string {
	keys := make([]string, 0, max(len(family.ListKeys), 0)+8)
	for _, key := range family.ListKeys {
		if key = strings.TrimSpace(key); key != "" {
			keys = append(keys, key)
		}
	}
	normalized := strings.TrimSpace(family.Name)
	compact := strings.ReplaceAll(normalized, "_", "")
	keys = append(keys, "data", "items", "results", "records", normalized, normalized+"s", compact, compact+"s")
	return keys
}

func recordsFromObjectMap(raw json.RawMessage, valueKey string) ([]json.RawMessage, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, err
	}
	if strings.TrimSpace(valueKey) == "" {
		valueKey = "value"
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	items := make([]json.RawMessage, 0, len(keys))
	for _, key := range keys {
		record := map[string]json.RawMessage{
			"id":   json.RawMessage(strconv.Quote(key)),
			"name": json.RawMessage(strconv.Quote(key)),
		}
		record[valueKey] = values[key]
		rawRecord, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		items = append(items, rawRecord)
	}
	return items, nil
}

func singletonRecord(raw json.RawMessage, fallbackID string) (json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	if _, ok := object["id"]; !ok && strings.TrimSpace(fallbackID) != "" {
		object["id"] = json.RawMessage(strconv.Quote(strings.TrimSpace(fallbackID)))
	}
	return json.Marshal(object)
}

func responseCursor(family Family, object map[string]json.RawMessage) string {
	if value := offsetResponseCursor(family, object); value != "" {
		return value
	}
	if !responseHasMore(family, object) {
		return ""
	}
	for _, key := range responseCursorKeys(family) {
		if value := rawStringAtPath(object, key); value != "" {
			return value
		}
	}
	for _, key := range []string{"pagination", "page", "pageInfo", "meta", "result_info", "resultInfo"} {
		var nested map[string]any
		if err := json.Unmarshal(object[key], &nested); err != nil {
			continue
		}
		for _, nestedKey := range responseCursorKeys(family) {
			if value := valueString(nested[nestedKey]); value != "" {
				return value
			}
		}
		if value := nextPageCursor(nested); value != "" {
			return value
		}
	}
	return ""
}

func rawStringAtPath(object map[string]json.RawMessage, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if !strings.Contains(path, ".") {
		return rawString(object[path])
	}
	parts := strings.Split(path, ".")
	current := object
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return ""
		}
		raw := current[part]
		if len(raw) == 0 {
			return ""
		}
		if i == len(parts)-1 {
			return rawString(raw)
		}
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(raw, &nested); err != nil {
			return ""
		}
		current = nested
	}
	return ""
}

func linkHeaderCursor(family Family, headers http.Header) string {
	headerName := strings.TrimSpace(family.LinkHeader)
	if headerName == "" {
		return ""
	}
	raw := strings.TrimSpace(headers.Get(headerName))
	if raw == "" {
		return ""
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) && !strings.Contains(part, "rel=next") {
			continue
		}
		start := strings.Index(part, "<")
		end := strings.Index(part, ">")
		if start < 0 || end <= start+1 {
			continue
		}
		parsed, err := url.Parse(part[start+1 : end])
		if err != nil {
			continue
		}
		if value := strings.TrimSpace(parsed.Query().Get(cursorParam(family))); value != "" {
			return value
		}
	}
	return ""
}

func offsetResponseCursor(family Family, object map[string]json.RawMessage) string {
	if cursorParam(family) != "offset" {
		return ""
	}
	total, ok := intValueFromRaw(firstRaw(object, "totalCount", "total_count", "total"))
	if !ok || total <= 0 {
		return ""
	}
	offset, offsetOK := intValueFromRaw(firstRaw(object, "offset"))
	limit, limitOK := intValueFromRaw(firstRaw(object, "limit"))
	if pagination := object["pagination"]; len(pagination) != 0 {
		var nested map[string]any
		if err := json.Unmarshal(pagination, &nested); err == nil {
			if parsed, ok := intValue(nested["offset"]); ok {
				offset = parsed
				offsetOK = true
			}
			if parsed, ok := intValue(nested["limit"]); ok {
				limit = parsed
				limitOK = true
			}
		}
	}
	if !offsetOK || !limitOK || limit <= 0 {
		return ""
	}
	next := offset + limit
	if next >= total {
		return ""
	}
	return strconv.Itoa(next)
}

func responseHasMore(family Family, object map[string]json.RawMessage) bool {
	key := strings.TrimSpace(family.HasMoreKey)
	if key == "" {
		return true
	}
	value, ok := object[key]
	if !ok {
		return false
	}
	raw := strings.ToLower(rawString(value))
	return raw == "true" || raw == "1" || raw == "yes"
}

func firstRaw(object map[string]json.RawMessage, keys ...string) json.RawMessage {
	for _, key := range keys {
		if value := object[key]; len(value) != 0 {
			return value
		}
	}
	return nil
}

func intValueFromRaw(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return 0, false
	}
	return intValue(value)
}

func responseCursorKeys(family Family) []string {
	keys := make([]string, 0, max(len(family.NextCursorKeys), 0)+8)
	for _, key := range family.NextCursorKeys {
		if key = strings.TrimSpace(key); key != "" {
			keys = append(keys, key)
		}
	}
	keys = append(keys, "nextCursor", "next_cursor", "cursor", "next", "nextPageToken", "next_page_token", "next_page")
	return keys
}

func nextPageCursor(values map[string]any) string {
	page, ok := intValue(values["page"])
	if !ok {
		return ""
	}
	totalPages, ok := intValue(firstAny(values["total_pages"], values["totalPages"]))
	if !ok || page < 1 || page >= totalPages {
		return ""
	}
	return strconv.Itoa(page + 1)
}

func firstAny(values ...any) any {
	for _, value := range values {
		if valueString(value) != "" {
			return value
		}
	}
	return nil
}

func intValue(value any) (int, bool) {
	switch typed := value.(type) {
	case json.Number:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed.String()))
		return parsed, err == nil
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		return parsed, err == nil
	case float64:
		parsed := int(typed)
		return parsed, typed == float64(parsed)
	case float32:
		parsed := int(typed)
		return parsed, typed == float32(parsed)
	case int:
		return typed, true
	case int64, int32, uint, uint64, uint32:
		parsed, err := strconv.Atoi(fmt.Sprint(typed))
		return parsed, err == nil
	default:
		return 0, false
	}
}

func recordFromRaw(family Family, raw json.RawMessage) (record, error) {
	values := map[string]any{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&values); err != nil {
		return record{}, fmt.Errorf("decode record: %w", err)
	}
	id := firstValueString(values, family.IDKeys...)
	if id == "" {
		if family.RequireID {
			return record{}, fmt.Errorf("%s id is required", family.Name)
		}
		id = stableID(string(raw))
	}
	return record{Raw: cloneRaw(raw), Values: values, ID: id, Identity: recordIdentity(id, values)}, nil
}

func rawWithPathParams(raw json.RawMessage, pathParams map[string]string) (json.RawMessage, error) {
	if len(pathParams) == 0 {
		return raw, nil
	}
	object := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	changed := false
	for key, value := range pathParams {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || len(object[key]) != 0 {
			continue
		}
		object[key] = json.RawMessage(strconv.Quote(value))
		changed = true
	}
	if !changed {
		return raw, nil
	}
	merged, err := json.Marshal(object)
	if err != nil {
		return nil, err
	}
	return merged, nil
}

func detailRecordRaw(raw json.RawMessage, allowBareObject bool) (json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	for _, key := range []string{"result", "data", "item", "record"} {
		value := object[key]
		if len(value) == 0 {
			continue
		}
		var nested map[string]any
		if err := json.Unmarshal(value, &nested); err == nil {
			return cloneRaw(value), nil
		}
	}
	if _, ok := object["id"]; ok {
		return cloneRaw(raw), nil
	}
	if allowBareObject && len(object) != 0 {
		return cloneRaw(raw), nil
	}
	return nil, fmt.Errorf("response did not contain a detail record")
}

func mergedRecord(family Family, original record, raw json.RawMessage) (record, error) {
	detailValues := map[string]any{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&detailValues); err != nil {
		return record{}, fmt.Errorf("decode detail record: %w", err)
	}
	merged := cloneValues(original.Values)
	for key, value := range detailValues {
		merged[key] = value
	}
	mergedRaw, err := json.Marshal(merged)
	if err != nil {
		return record{}, fmt.Errorf("marshal merged detail record: %w", err)
	}
	return recordFromRaw(family, mergedRaw)
}

func urnsFor(settings settings, family Family, records []record) ([]sourcecdk.URN, error) {
	kind := firstNonEmpty(family.URNKind, family.Name)
	urns := make([]sourcecdk.URN, 0, len(records))
	for _, record := range dedupeRecords(records) {
		recordID := record.ID
		if family.Config.EncodeURNID {
			recordID = cerebrourn.EncodeSegment(recordID)
		}
		urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:%s:%s", settings.tenantID, kind, recordID))
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func pullFromRecords(sourceID string, settings settings, family Family, records []record, next string) (sourcecdk.Pull, error) {
	records = dedupeEventRecords(records)
	if len(records) == 0 {
		pull := sourcecdk.Pull{}
		if next := strings.TrimSpace(next); next != "" {
			pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
		}
		return pull, nil
	}
	events := make([]*primitives.Event, 0, len(records))
	for _, record := range records {
		events = append(events, eventFromRecord(sourceID, settings, family, record))
	}
	last := events[len(events)-1]
	pull := sourcecdk.Pull{
		Events: events,
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    last.OccurredAt,
			CursorOpaque: firstNonEmpty(next, records[len(records)-1].ID),
		},
	}
	if next := strings.TrimSpace(next); next != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
	}
	return pull, nil
}

func eventFromRecord(sourceID string, settings settings, family Family, record record) *primitives.Event {
	occurredAt := occurredAtFor(record.Values, family.TimestampKeys)
	return &primitives.Event{
		Id:         eventID(sourceID, settings.tenantID, settings.baseURL, settings.path, family.Name, record.Identity),
		TenantId:   settings.tenantID,
		SourceId:   sourceID,
		Kind:       sourceID + "." + family.Name,
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  sourceID + "/" + family.Name + "/v1",
		Payload:    cloneRaw(record.Raw),
		Attributes: attributesFor(sourceID, settings, family, record),
	}
}

func eventID(sourceID string, tenantID string, baseURL string, path string, family string, recordID string) string {
	scope := sha256.Sum256([]byte(baseURL + "\x00" + path))
	parts := []string{sourceID, normalizeID(tenantID), hex.EncodeToString(scope[:])[:12], normalizeID(family), normalizeID(recordID)}
	return strings.Join(parts, "-")
}

func attributesFor(sourceID string, settings settings, family Family, record record) map[string]string {
	attrs := map[string]string{
		"external_id":     record.ID,
		"family":          family.Name,
		"provider":        sourceID,
		"source_provider": sourceID,
	}
	for key, value := range settings.request.pathParams {
		addAttribute(attrs, key, value)
	}
	for key, value := range family.StaticAttributes {
		addAttribute(attrs, key, value)
	}
	for key, value := range settings.request.configAttributes {
		addAttribute(attrs, key, value)
	}
	for attr, path := range family.Attributes {
		addAttribute(attrs, attr, firstValueString(record.Values, path))
	}
	trimEmptyAttributes(attrs)
	return attrs
}

func occurredAtFor(values map[string]any, keys []string) time.Time {
	candidates := append([]string{}, keys...)
	candidates = append(candidates, "updated_at", "updatedAt", "last_seen_at", "lastSeenAt", "last_check_in", "lastCheckIn", "created_at", "createdAt", "timestamp")
	for _, key := range candidates {
		if parsed, ok := parseTime(firstValueString(values, key)); ok {
			return parsed
		}
	}
	return time.Now().UTC()
}

func parseTime(raw string) (time.Time, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, false
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 {
		return time.Unix(seconds, 0).UTC(), true
	}
	if seconds, err := strconv.ParseFloat(value, 64); err == nil && seconds > 0 {
		whole, fraction := math.Modf(seconds)
		return time.Unix(int64(whole), int64(fraction*1_000_000_000)).UTC(), true
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func lookupIPAddrs(source *Source) func(context.Context, string) ([]net.IPAddr, error) {
	if source != nil && source.lookupIPAddrs != nil {
		return source.lookupIPAddrs
	}
	return net.DefaultResolver.LookupIPAddr
}

type responseError struct {
	statusCode int
	message    string
}

func (e *responseError) Error() string { return e.message }

type pathParamError struct {
	sourceID string
	param    string
}

func (e *pathParamError) Error() string {
	return fmt.Sprintf("%s path parameter %q is required", e.sourceID, e.param)
}

func decodeResponseError(sourceID string, statusCode int, body []byte) error {
	message := strings.TrimSpace(string(body))
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err == nil {
		for _, key := range []string{"message", "error_description", "error", "detail"} {
			if value := valueString(payload[key]); value != "" {
				message = value
				break
			}
		}
	}
	if message == "" {
		message = http.StatusText(statusCode)
	}
	return &responseError{statusCode: statusCode, message: fmt.Sprintf("%s API returned %d: %s", sourceID, statusCode, message)}
}

func familyByName(options Options, name string) (Family, bool) {
	for _, family := range options.Families {
		if strings.TrimSpace(family.Name) == strings.TrimSpace(name) {
			return family, true
		}
	}
	return Family{}, false
}

func familyNames(options Options) []string {
	names := make([]string, 0, len(options.Families))
	for _, family := range options.Families {
		names = append(names, strings.TrimSpace(family.Name))
	}
	return names
}

func resolvePathParams(sourceID string, path string, cfg sourcecdk.Config, params []string) (string, map[string]string, error) {
	resolved := strings.TrimSpace(path)
	values := map[string]string{}
	for _, param := range params {
		param = strings.TrimSpace(param)
		if param == "" {
			continue
		}
		token := "{" + param + "}"
		value := sourcecdk.ConfigValue(cfg, param)
		if value != "" {
			values[param] = value
		}
		if !strings.Contains(resolved, token) {
			continue
		}
		if value == "" {
			return "", nil, &pathParamError{sourceID: sourceID, param: param}
		}
		resolved = strings.ReplaceAll(resolved, token, url.PathEscape(value))
	}
	if len(params) > 0 && strings.Contains(resolved, "{") && strings.Contains(resolved, "}") {
		return "", nil, fmt.Errorf("%s path contains unresolved path parameter in %q", sourceID, resolved)
	}
	return resolved, values, nil
}

const maxConfigTemplateExpansions = 32

func resolveConfigTemplate(sourceID string, value string, cfg sourcecdk.Config) (string, error) {
	resolved := strings.TrimSpace(value)
	for expansions := 0; ; expansions++ {
		start := strings.Index(resolved, "${config.")
		if start < 0 {
			return resolved, nil
		}
		if expansions >= maxConfigTemplateExpansions {
			return "", fmt.Errorf("%s config template exceeded %d expansions in %q", sourceID, maxConfigTemplateExpansions, value)
		}
		end := strings.Index(resolved[start:], "}")
		if end < 0 {
			return "", fmt.Errorf("%s config template is missing closing brace in %q", sourceID, value)
		}
		key := strings.TrimSpace(resolved[start+len("${config.") : start+end])
		if key == "" {
			return "", fmt.Errorf("%s config template contains an empty key in %q", sourceID, value)
		}
		replacement := sourcecdk.ConfigValue(cfg, key)
		if replacement == "" {
			return "", fmt.Errorf("%s config key %q is required", sourceID, key)
		}
		resolved = resolved[:start] + replacement + resolved[start+end+1:]
	}
}

func normalizeRequestPathWithQuery(sourceID string, raw string) (string, url.Values, error) {
	value := strings.TrimSpace(raw)
	parsed, err := url.Parse(value)
	if err != nil {
		return "", nil, fmt.Errorf("parse %s request path: %w", sourceID, err)
	}
	if parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Fragment != "" {
		return "", nil, fmt.Errorf("%s request path must be an absolute path without fragment", sourceID)
	}
	path, err := sourcehttp.NormalizeRequestPath(sourceID, parsed.Path)
	if err != nil {
		return "", nil, err
	}
	return path, parsed.Query(), nil
}

func resolveRecordPath(sourceID string, path string, pathParams map[string]string, values map[string]any) (string, error) {
	resolved := strings.TrimSpace(path)
	for {
		start := strings.Index(resolved, "{")
		if start < 0 {
			break
		}
		end := strings.Index(resolved[start:], "}")
		if end < 0 {
			return "", fmt.Errorf("%s path contains unresolved path parameter in %q", sourceID, resolved)
		}
		param := strings.TrimSpace(resolved[start+1 : start+end])
		if param == "" {
			return "", fmt.Errorf("%s path contains empty path parameter in %q", sourceID, resolved)
		}
		value := firstNonEmpty(pathParams[param], firstValueString(values, param))
		if value == "" {
			return "", &pathParamError{sourceID: sourceID, param: param}
		}
		resolved = resolved[:start] + url.PathEscape(value) + resolved[start+end+1:]
	}
	return sourcehttp.NormalizeRequestPath(sourceID, resolved)
}

func rawString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return ""
	}
	return valueString(value)
}

func firstValueString(values map[string]any, paths ...string) string {
	for _, path := range paths {
		for _, candidate := range attributePaths(path) {
			if value := valueString(valueAt(values, candidate)); value != "" {
				return value
			}
		}
	}
	return ""
}

func attributePaths(path string) []string {
	parts := strings.Split(path, "|")
	paths := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			paths = append(paths, trimmed)
		}
	}
	return paths
}

func cloneValues(values map[string]any) map[string]any {
	cloned := make(map[string]any, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func dedupeRecords(records []record) []record {
	seen := map[string]struct{}{}
	out := make([]record, 0, len(records))
	for _, record := range records {
		key := strings.TrimSpace(record.ID)
		if key == "" {
			key = stableID(string(record.Raw))
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, record)
	}
	return out
}

func dedupeEventRecords(records []record) []record {
	seen := map[string]struct{}{}
	out := make([]record, 0, len(records))
	for _, record := range records {
		key := strings.TrimSpace(record.Identity)
		if key == "" {
			key = strings.TrimSpace(record.ID)
		}
		if key == "" {
			key = stableID(string(record.Raw))
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, record)
	}
	return out
}

func recordIdentity(id string, values map[string]any) string {
	parts := []string{strings.TrimSpace(id)}
	for _, key := range []string{
		"device_id",
		"device.id",
		"serial_number",
		"agent_id",
		"agent.uuid",
		"device_uuid",
		"installed_version",
		"version",
	} {
		if value := firstValueString(values, key); value != "" {
			parts = append(parts, key+"="+value)
		}
	}
	parts = nonEmpty(parts)
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return parts[0] + "-" + stableID(strings.Join(parts, "\x00"))
}

func nonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func valueAt(values map[string]any, path string) any {
	if len(values) == 0 {
		return nil
	}
	parts := strings.Split(strings.TrimSpace(path), ".")
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			return nil
		}
	}
	value, _ := valueAtParts(values, parts)
	return value
}

func valueAtParts(current any, parts []string) (any, bool) {
	if len(parts) == 0 {
		return current, true
	}
	object, ok := current.(map[string]any)
	if !ok {
		return nil, false
	}
	for i := 1; i <= len(parts); i++ {
		key := strings.Join(parts[:i], ".")
		next, ok := object[key]
		if !ok {
			continue
		}
		if value, ok := valueAtParts(next, parts[i:]); ok {
			return value, true
		}
	}
	return nil, false
}

func valueString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return strings.TrimSpace(typed.String())
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case float64, float32, int, int64, int32, uint, uint64, uint32:
		return strings.TrimSpace(fmt.Sprint(typed))
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			if part := valueString(item); part != "" {
				parts = append(parts, part)
			}
		}
		return strings.Join(parts, ",")
	case map[string]any:
		raw, err := json.Marshal(typed)
		if err != nil {
			return ""
		}
		return string(raw)
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func addAttribute(attrs map[string]string, key string, value string) {
	if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
		return
	}
	attrs[strings.TrimSpace(key)] = strings.TrimSpace(value)
}

func trimEmptyAttributes(attrs map[string]string) {
	for key, value := range attrs {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			delete(attrs, key)
		}
	}
}

func cloneRaw(raw json.RawMessage) json.RawMessage {
	if raw == nil {
		return nil
	}
	return append(json.RawMessage(nil), raw...)
}

func stableID(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:24]
}

func normalizeID(value string) string {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(" ", "-", "/", "-", ":", "-", "\t", "-", "\n", "-")
	return replacer.Replace(normalized)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
