package oktaasset

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

const (
	KindAPIToken            = "api_token"
	KindAuthorizationServer = "authorization_server"
	KindAuthenticator       = "authenticator"
	KindBrand               = "brand"
	KindDeviceAssurance     = "device_assurance"
	KindEventHook           = "event_hook"
	KindIdentityProvider    = "identity_provider"
	KindInlineHook          = "inline_hook"
	KindLogStream           = "log_stream"
	KindNetworkZone         = "network_zone"
	KindTrustedOrigin       = "trusted_origin"
)

type Settings struct {
	Domain  string
	Filter  string
	Q       string
	PerPage int
}

type Record struct {
	Raw    json.RawMessage
	Values map[string]any
}

func (r *Record) UnmarshalJSON(raw []byte) error {
	r.Raw = append(json.RawMessage(nil), raw...)
	return json.Unmarshal(raw, &r.Values)
}

type Lister[S any] func(context.Context, S, string, url.Values, string) ([]Record, string, error)

type FamilyOptions[S any] struct {
	Name        string
	Label       string
	Path        string
	URNFamily   string
	Kind        string
	Settings    func(S) Settings
	List        Lister[S]
	QueryParams bool
}

type OAuthRedirectSettings struct {
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
}

func Family[S any](options FamilyOptions[S]) sourcecdk.Family[S] {
	return sourcecdk.Family[S]{
		Name: options.Name, IncrementalWatermark: true,
		Check: func(ctx context.Context, settings S) error {
			assetSettings := options.Settings(settings)
			_, _, err := list(ctx, settings, assetSettings, "", 1, options)
			return wrapLookupError(options.Label, assetSettings, err)
		},
		Discover: func(ctx context.Context, settings S) ([]sourcecdk.URN, error) {
			assetSettings := options.Settings(settings)
			records, _, err := list(ctx, settings, assetSettings, "", assetSettings.PerPage, options)
			if err != nil {
				return nil, wrapLookupError(options.Label, assetSettings, err)
			}
			urns := make([]sourcecdk.URN, 0, len(records))
			for _, record := range records {
				urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:%s:%s", assetSettings.Domain, options.URNFamily, record.String("id")))
				if err != nil {
					return nil, err
				}
				urns = append(urns, urn)
			}
			return urns, nil
		},
		Read: func(ctx context.Context, settings S, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			assetSettings := options.Settings(settings)
			records, next, err := list(ctx, settings, assetSettings, sourcecdk.CursorToken(cursor), assetSettings.PerPage, options)
			if err != nil {
				return sourcecdk.Pull{}, wrapLookupError(options.Label, assetSettings, err)
			}
			return pull(assetSettings, options.Kind, records, next)
		},
	}
}

func list[S any](ctx context.Context, sourceSettings S, assetSettings Settings, after string, limit int, options FamilyOptions[S]) ([]Record, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	sourcecdk.AddQueryParam(query, "after", after)
	if options.QueryParams {
		sourcecdk.AddQueryParam(query, "q", assetSettings.Q)
		sourcecdk.AddQueryParam(query, "filter", assetSettings.Filter)
	}
	return options.List(ctx, sourceSettings, options.Path, query, strings.TrimSpace(options.Label))
}

func pull(settings Settings, kind string, records []Record, next string) (sourcecdk.Pull, error) {
	if len(records) == 0 {
		return sourcecdk.Pull{}, nil
	}
	events := make([]*primitives.Event, 0, len(records))
	for _, record := range records {
		event, err := Event(settings, kind, record)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	last := events[len(events)-1]
	result := sourcecdk.Pull{
		Events: events,
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    last.OccurredAt,
			CursorOpaque: firstNonEmpty(next, records[len(records)-1].String("id"), last.OccurredAt.AsTime().UTC().Format(time.RFC3339Nano)),
		},
	}
	if strings.TrimSpace(next) != "" {
		result.NextCursor = &cerebrov1.SourceCursor{Opaque: strings.TrimSpace(next)}
	}
	return result, nil
}

func Event(settings Settings, kind string, record Record) (*primitives.Event, error) {
	occurredAt := firstRecordTime(record.Time("lastUpdated"), record.Time("created"))
	payload, err := payload(settings, kind, record)
	if err != nil {
		return nil, err
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("okta-%s-%s-%d", strings.ReplaceAll(kind, "_", "-"), record.String("id"), occurredAt.UnixMilli()),
		TenantId:   settings.Domain,
		SourceId:   "okta",
		Kind:       "okta." + kind,
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "okta/" + kind + "/v1",
		Payload:    payload,
		Attributes: Attributes(settings, kind, record),
	}, nil
}

func payload(settings Settings, kind string, record Record) ([]byte, error) {
	raw := map[string]any{}
	if err := json.Unmarshal(record.Raw, &raw); err != nil {
		return nil, fmt.Errorf("decode okta asset raw payload: %w", err)
	}
	values := map[string]any{
		"domain": settings.Domain,
		"id":     record.String("id"),
		"name":   record.String("name"),
	}
	for _, key := range []string{"key", "origin", "policy", "protocol", "scopes", "status", "type"} {
		if value, ok := record.Values[key]; ok {
			values[key] = value
		}
	}
	if value, ok := record.Values["domain"]; ok {
		values["domain_value"] = value
	}
	if !sensitivePayloadKind(kind) {
		values["raw"] = raw
	}
	return json.Marshal(values)
}

func Attributes(settings Settings, kind string, record Record) map[string]string {
	switch kind {
	case KindAPIToken:
		return apiTokenAttributes(settings, record)
	case KindAuthorizationServer:
		return authorizationServerAttributes(settings, record)
	case KindAuthenticator:
		return authenticatorAttributes(settings, record)
	case KindBrand:
		return brandAttributes(settings, record)
	case KindDeviceAssurance:
		return deviceAssuranceAttributes(settings, record)
	case KindEventHook:
		return eventHookAttributes(settings, record)
	case KindIdentityProvider:
		return identityProviderAttributes(settings, record)
	case KindInlineHook:
		return inlineHookAttributes(settings, record)
	case KindLogStream:
		return logStreamAttributes(settings, record)
	case KindNetworkZone:
		return networkZoneAttributes(settings, record)
	case KindTrustedOrigin:
		return trustedOriginAttributes(settings, record)
	default:
		return map[string]string{"domain": settings.Domain, "family": kind, "resource_id": record.String("id")}
	}
}

func (r Record) String(key string) string {
	value, ok := r.Values[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}

func (r Record) Time(key string) *time.Time {
	value := r.String(key)
	if value == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil
	}
	return &parsed
}

func (r Record) mapValue(key string) map[string]any {
	return nestedMap(r.Values, key)
}

func (r Record) mapSlice(key string) []map[string]any {
	items, ok := r.Values[key].([]any)
	if !ok {
		return nil
	}
	values := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if value, ok := item.(map[string]any); ok {
			values = append(values, value)
		}
	}
	return values
}

func (r Record) anySlice(key string) []any {
	items, ok := r.Values[key].([]any)
	if !ok {
		return nil
	}
	return items
}

func trustedOriginScopeTypes(scopes []map[string]any) []string {
	values := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if value := firstNonEmpty(stringMap(scope, "type"), stringMap(scope, "scope")); value != "" {
			values = append(values, strings.ToUpper(value))
		}
	}
	sort.Strings(values)
	return values
}

func zoneEntryValues(entries []map[string]any) []string {
	values := make([]string, 0, len(entries))
	for _, entry := range entries {
		if value := firstNonEmpty(stringMap(entry, "value"), stringMap(entry, "network"), stringMap(entry, "cidr")); value != "" {
			values = append(values, value)
		}
	}
	sort.Strings(values)
	return values
}

func nonEmptyAnyStrings(values []any) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		if text := strings.TrimSpace(fmt.Sprint(value)); text != "" {
			result = append(result, text)
		}
	}
	sort.Strings(result)
	return result
}

func stringSliceContainsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

func firstRecordTime(values ...*time.Time) time.Time {
	for _, value := range values {
		if value != nil && !value.IsZero() {
			return value.UTC()
		}
	}
	return time.Now().UTC()
}

func addAttribute(attributes map[string]string, key string, value string) {
	if strings.TrimSpace(value) != "" {
		attributes[key] = strings.TrimSpace(value)
	}
}

func addCSVAttribute(attributes map[string]string, key string, values []string) {
	addAttribute(attributes, key, strings.Join(uniqueSortedStrings(values), ","))
}

func nestedMap(values map[string]any, key string) map[string]any {
	value, ok := values[key]
	if !ok {
		return nil
	}
	child, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return child
}

func stringMap(values map[string]any, key string) string {
	value, ok := values[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}

func conditionIDs(values map[string]any, key string) []string {
	if len(values) == 0 {
		return nil
	}
	return valueIDs(values[key])
}

func valueIDs(value any) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		return []string{typed}
	case []string:
		return typed
	case map[string]any:
		return []string{stringMap(typed, "id")}
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			values = append(values, valueIDs(item)...)
		}
		return values
	default:
		return nil
	}
}

func platformTypes(platform map[string]any) []string {
	items, ok := platform["include"].([]any)
	if !ok {
		return nil
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		if entry, ok := item.(map[string]any); ok {
			values = append(values, strings.ToUpper(stringMap(entry, "type")))
		}
	}
	return values
}

func uniqueSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := []string{}
	for _, value := range values {
		text := strings.TrimSpace(value)
		if text == "" {
			continue
		}
		if _, ok := seen[text]; ok {
			continue
		}
		seen[text] = struct{}{}
		result = append(result, text)
	}
	sort.Strings(result)
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func urlHosts(values []string) []string {
	seen := map[string]struct{}{}
	hosts := []string{}
	for _, value := range values {
		host := urlHost(value)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}

func urlHost(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err == nil && parsed.Hostname() != "" {
		return normalizeURLHost(parsed.Hostname())
	}
	parsed, err = url.Parse("https://" + value)
	if err == nil && parsed.Hostname() != "" {
		return normalizeURLHost(parsed.Hostname())
	}
	return ""
}

func normalizeURLHost(host string) string {
	normalized := strings.ToLower(strings.Trim(strings.TrimSpace(host), "."))
	return strings.TrimPrefix(normalized, "*.")
}

func wrapLookupError(label string, settings Settings, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s for %s: %w", strings.TrimSpace(label), settings.Domain, err)
}
