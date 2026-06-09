package jsonapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourcehttp"
)

const (
	defaultPageSize = 100
	maxPageSize     = 500
)

// Family describes one JSON API collection exposed by a first-class source.
type Family struct {
	Name             string
	Path             string
	URNKind          string
	IDKeys           []string
	TimestampKeys    []string
	Attributes       map[string]string
	StaticAttributes map[string]string
	StaticQuery      map[string]string
	ConfigQuery      map[string]string
	PageSizeParams   []string
	RequireID        bool
}

// Options configures a JSON API-backed source adapter.
type Options struct {
	SourceID                          string
	DefaultBaseURL                    string
	DefaultFamily                     string
	RequireTenantID                   bool
	TokenScheme                       string
	DiscoverURNScope                  string
	PrivateEndpointAllowlistConfigKey string
	Families                          []Family
}

// Source is a small, safe JSON API source implementation used by endpoint
// adapters whose APIs expose paged REST collections.
type Source struct {
	spec                 *cerebrov1.SourceSpec
	options              Options
	client               *http.Client
	families             *sourcecdk.FamilyEngine[settings]
	AllowLoopbackBaseURL bool
	lookupIPAddrs        func(context.Context, string) ([]net.IPAddr, error)
}

type settings struct {
	tenantID                 string
	family                   string
	baseURL                  string
	host                     string
	token                    string
	path                     string
	query                    url.Values
	perPage                  int
	privateEndpointAllowlist []string
}

type record struct {
	Raw      json.RawMessage
	Values   map[string]any
	ID       string
	Identity string
}

// New constructs a JSON API-backed source.
func New(spec *cerebrov1.SourceSpec, options Options) (*Source, error) {
	if spec == nil {
		return nil, fmt.Errorf("source spec is required")
	}
	if strings.TrimSpace(options.SourceID) == "" {
		return nil, fmt.Errorf("source id is required")
	}
	source := &Source{
		spec:          spec,
		options:       options,
		lookupIPAddrs: net.DefaultResolver.LookupIPAddr,
	}
	families, err := source.newFamilyEngine()
	if err != nil {
		return nil, err
	}
	source.families = families
	return source, nil
}

// Spec returns static source metadata.
func (s *Source) Spec() *cerebrov1.SourceSpec { return s.spec }

// Check validates that the configured family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

// Discover returns URNs for the configured family.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read pages records for the configured family.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	families := make([]sourcecdk.Family[settings], 0, len(s.options.Families))
	for _, family := range s.options.Families {
		family := family
		if strings.TrimSpace(family.Name) == "" {
			return nil, fmt.Errorf("family name is required")
		}
		families = append(families, sourcecdk.Family[settings]{
			Name: family.Name,
			Check: func(ctx context.Context, settings settings) error {
				_, _, err := s.list(ctx, family, settings, "", 1)
				return err
			},
			Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
				records, _, err := s.list(ctx, family, settings, "", settings.perPage)
				if err != nil {
					return nil, err
				}
				return urnsFor(settings, family, records)
			},
			Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
				records, next, err := s.list(ctx, family, settings, strings.TrimSpace(cursor.GetOpaque()), settings.perPage)
				if err != nil {
					return sourcecdk.Pull{}, err
				}
				return pullFromRecords(s.options.SourceID, settings, family, records, next)
			},
		})
	}
	return sourcecdk.NewFamilyEngine(s.parseSettings, func(settings settings) string { return settings.family }, families...)
}

func (s *Source) parseSettings(cfg sourcecdk.Config) (settings, error) {
	if s == nil {
		return settings{}, fmt.Errorf("jsonapi source is required")
	}
	resolved := settings{
		tenantID: firstNonEmpty(configValue(cfg, "tenant_id"), configValue(cfg, sourceconfig.RuntimeTenantIDKey)),
		family:   strings.TrimSpace(configValue(cfg, "family")),
		baseURL:  strings.TrimSpace(configValue(cfg, "base_url")),
		token:    firstNonEmpty(configValue(cfg, "token"), configValue(cfg, "api_token")),
		perPage:  defaultPageSize,
	}
	if resolved.family == "" {
		resolved.family = strings.TrimSpace(s.options.DefaultFamily)
	}
	family, ok := familyByName(s.options, resolved.family)
	if !ok {
		return resolved, fmt.Errorf("%s family must be one of %s", s.options.SourceID, strings.Join(familyNames(s.options), ", "))
	}
	if s.options.RequireTenantID && resolved.tenantID == "" {
		return resolved, fmt.Errorf("%s tenant_id is required", s.options.SourceID)
	}
	if resolved.baseURL == "" {
		resolved.baseURL = strings.TrimSpace(s.options.DefaultBaseURL)
	}
	if resolved.baseURL == "" {
		return resolved, fmt.Errorf("%s base_url is required", s.options.SourceID)
	}
	if key := strings.TrimSpace(s.options.PrivateEndpointAllowlistConfigKey); key != "" {
		allowlist, err := sourcehttp.ParsePrivateEndpointAllowlist(s.options.SourceID, configValue(cfg, key))
		if err != nil {
			return resolved, err
		}
		resolved.privateEndpointAllowlist = allowlist
	}
	baseURL, host, err := sourcehttp.NormalizeBaseURLWithOptions(s.options.SourceID, resolved.baseURL, sourcehttp.URLValidationOptions{
		AllowLoopback:            s.AllowLoopbackBaseURL,
		PrivateEndpointAllowlist: resolved.privateEndpointAllowlist,
	})
	if err != nil {
		return resolved, err
	}
	resolved.baseURL = baseURL
	resolved.host = host
	if resolved.tenantID == "" {
		resolved.tenantID = host
	}
	if resolved.token == "" {
		return resolved, fmt.Errorf("%s token is required", s.options.SourceID)
	}
	if rawPerPage := strings.TrimSpace(configValue(cfg, "per_page")); rawPerPage != "" {
		perPage, err := strconv.Atoi(rawPerPage)
		if err != nil {
			return resolved, fmt.Errorf("parse %s per_page: %w", s.options.SourceID, err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return resolved, fmt.Errorf("%s per_page must be between 1 and %d", s.options.SourceID, maxPageSize)
		}
		resolved.perPage = perPage
	}
	path := firstNonEmpty(configValue(cfg, resolved.family+"_path"), configValue(cfg, "path"), family.Path)
	resolved.path, err = sourcehttp.NormalizeRequestPath(s.options.SourceID, path)
	if err != nil {
		return resolved, err
	}
	resolved.query = queryFromConfig(cfg, family.ConfigQuery)
	return resolved, nil
}

func (s *Source) list(ctx context.Context, family Family, settings settings, cursor string, pageSize int) ([]record, string, error) {
	query := url.Values{}
	for key, value := range family.StaticQuery {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			query.Set(strings.TrimSpace(key), strings.TrimSpace(value))
		}
	}
	for key, values := range settings.query {
		for _, value := range values {
			query.Add(key, value)
		}
	}
	for _, param := range pageSizeParams(family) {
		query.Set(param, strconv.Itoa(pageSize))
	}
	if cursor := strings.TrimSpace(cursor); cursor != "" {
		query.Set("cursor", cursor)
	}
	var body json.RawMessage
	if err := s.getJSON(ctx, settings, query, &body); err != nil {
		return nil, "", err
	}
	items, next, err := parseListResponse(settings.family, body)
	if err != nil {
		return nil, "", fmt.Errorf("%s %s: %w", s.options.SourceID, settings.family, err)
	}
	records := make([]record, 0, len(items))
	for _, item := range items {
		record, err := recordFromRaw(family, item)
		if err != nil {
			return nil, "", fmt.Errorf("%s %s: %w", s.options.SourceID, settings.family, err)
		}
		if record.ID != "" {
			records = append(records, record)
		}
	}
	return records, next, nil
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

func queryFromConfig(cfg sourcecdk.Config, configQuery map[string]string) url.Values {
	query := url.Values{}
	for queryKey, configKey := range configQuery {
		queryKey = strings.TrimSpace(queryKey)
		configKey = strings.TrimSpace(configKey)
		if queryKey == "" || configKey == "" {
			continue
		}
		if value := strings.TrimSpace(configValue(cfg, configKey)); value != "" {
			query.Set(queryKey, value)
		}
	}
	return query
}

func (s *Source) getJSON(ctx context.Context, settings settings, query url.Values, target any) error {
	endpoint := settings.baseURL + settings.path
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build %s request: %w", s.options.SourceID, err)
	}
	tokenScheme := strings.TrimSpace(s.options.TokenScheme)
	if tokenScheme == "" {
		tokenScheme = "Bearer"
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", tokenScheme+" "+settings.token)
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
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decodeResponseError(s.options.SourceID, resp.StatusCode, resp.Body)
	}
	if target == nil {
		return nil
	}
	if err := json.Unmarshal(resp.Body, target); err != nil {
		return fmt.Errorf("decode %s response: %w", s.options.SourceID, err)
	}
	return nil
}

func parseListResponse(family string, raw json.RawMessage) ([]json.RawMessage, string, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err == nil {
		return items, "", nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, "", err
	}
	for _, key := range listKeys(family) {
		if value, ok := object[key]; ok {
			if err := json.Unmarshal(value, &items); err == nil {
				return items, responseCursor(object), nil
			}
		}
	}
	return nil, "", fmt.Errorf("response did not contain a record list")
}

func listKeys(family string) []string {
	normalized := strings.TrimSpace(family)
	compact := strings.ReplaceAll(normalized, "_", "")
	return []string{"data", "items", "results", "records", normalized, normalized + "s", compact, compact + "s"}
}

func responseCursor(object map[string]json.RawMessage) string {
	for _, key := range []string{"nextCursor", "next_cursor", "cursor", "next", "nextPageToken", "next_page_token"} {
		if value := rawString(object[key]); value != "" {
			return value
		}
	}
	for _, key := range []string{"pagination", "page", "pageInfo", "meta"} {
		var nested map[string]any
		if err := json.Unmarshal(object[key], &nested); err != nil {
			continue
		}
		for _, nestedKey := range []string{"nextCursor", "next_cursor", "cursor", "next", "nextPageToken", "next_page_token"} {
			if value := valueString(nested[nestedKey]); value != "" {
				return value
			}
		}
	}
	return ""
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

func urnsFor(settings settings, family Family, records []record) ([]sourcecdk.URN, error) {
	kind := firstNonEmpty(family.URNKind, family.Name)
	urns := make([]sourcecdk.URN, 0, len(records))
	for _, record := range dedupeRecords(records) {
		urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:%s:%s", settings.tenantID, kind, record.ID))
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
		Id:         eventID(sourceID, settings, family.Name, record.Identity),
		TenantId:   settings.tenantID,
		SourceId:   sourceID,
		Kind:       sourceID + "." + family.Name,
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  sourceID + "/" + family.Name + "/v1",
		Payload:    cloneRaw(record.Raw),
		Attributes: attributesFor(sourceID, family, record),
	}
}

func eventID(sourceID string, settings settings, family string, recordID string) string {
	scope := sha256.Sum256([]byte(settings.baseURL + "\x00" + settings.path))
	parts := []string{sourceID, normalizeID(settings.tenantID), hex.EncodeToString(scope[:])[:12], normalizeID(family), normalizeID(recordID)}
	return strings.Join(parts, "-")
}

func attributesFor(sourceID string, family Family, record record) map[string]string {
	attrs := map[string]string{
		"external_id":     record.ID,
		"family":          family.Name,
		"provider":        sourceID,
		"source_provider": sourceID,
	}
	for key, value := range family.StaticAttributes {
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

func configValue(cfg sourcecdk.Config, key string) string {
	value, ok := cfg.Lookup(key)
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
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
