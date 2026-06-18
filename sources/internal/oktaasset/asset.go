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
	addQuery(query, "after", after)
	if options.QueryParams {
		addQuery(query, "q", assetSettings.Q)
		addQuery(query, "filter", assetSettings.Filter)
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

func sensitivePayloadKind(kind string) bool {
	switch kind {
	case KindAPIToken, KindEventHook, KindInlineHook, KindLogStream:
		return true
	default:
		return false
	}
}

func AddOAuthRedirectAttributes(attributes map[string]string, settings OAuthRedirectSettings) {
	addAttribute(attributes, "redirect_uri_count", strconv.Itoa(len(settings.RedirectURIs)))
	addAttribute(attributes, "redirect_uri_hosts", strings.Join(urlHosts(settings.RedirectURIs), ","))
	addAttribute(attributes, "post_logout_redirect_uri_count", strconv.Itoa(len(settings.PostLogoutRedirectURIs)))
	addAttribute(attributes, "post_logout_redirect_uri_hosts", strings.Join(urlHosts(settings.PostLogoutRedirectURIs), ","))
}

func AddPolicyRuleConditionAttributes(raw json.RawMessage, attrs map[string]string) {
	var rule map[string]any
	if err := json.Unmarshal(raw, &rule); err != nil {
		return
	}
	conditions := nestedMap(rule, "conditions")
	network := nestedMap(conditions, "network")
	risk := nestedMap(conditions, "risk")
	platform := nestedMap(conditions, "platform")
	people := nestedMap(conditions, "people")
	identityProvider := nestedMap(conditions, "identityProvider")

	addAttribute(attrs, "network_connection", strings.ToUpper(stringMap(network, "connection")))
	addAttribute(attrs, "risk_level", strings.ToUpper(stringMap(risk, "level")))
	addCSVAttribute(attrs, "platform_types", platformTypes(platform))
	addCSVAttribute(attrs, "network_zone_include_ids", conditionIDs(network, "include"))
	addCSVAttribute(attrs, "network_zone_exclude_ids", conditionIDs(network, "exclude"))
	addCSVAttribute(attrs, "group_include_ids", append(conditionIDs(nestedMap(conditions, "groups"), "include"), conditionIDs(nestedMap(people, "groups"), "include")...))
	addCSVAttribute(attrs, "group_exclude_ids", append(conditionIDs(nestedMap(conditions, "groups"), "exclude"), conditionIDs(nestedMap(people, "groups"), "exclude")...))
	addCSVAttribute(attrs, "user_include_ids", append(conditionIDs(nestedMap(conditions, "users"), "include"), conditionIDs(nestedMap(people, "users"), "include")...))
	addCSVAttribute(attrs, "user_exclude_ids", append(conditionIDs(nestedMap(conditions, "users"), "exclude"), conditionIDs(nestedMap(people, "users"), "exclude")...))
	addCSVAttribute(attrs, "idp_ids", valueIDs(identityProvider["idpIds"]))
	addAttribute(attrs, "idp_provider", stringMap(identityProvider, "provider"))
	addCSVAttribute(attrs, "app_include_ids", append(conditionIDs(nestedMap(conditions, "apps"), "include"), conditionIDs(nestedMap(conditions, "app"), "include")...))
	addCSVAttribute(attrs, "app_exclude_ids", append(conditionIDs(nestedMap(conditions, "apps"), "exclude"), conditionIDs(nestedMap(conditions, "app"), "exclude")...))
	addCSVAttribute(attrs, "client_include_ids", conditionIDs(nestedMap(conditions, "clients"), "include"))
}

func authenticatorAttributes(settings Settings, record Record) map[string]string {
	return map[string]string{
		"authenticator_id": record.String("id"),
		"domain":           settings.Domain,
		"family":           KindAuthenticator,
		"key":              record.String("key"),
		"name":             record.String("name"),
		"resource_id":      record.String("id"),
		"resource_type":    "Authenticator",
		"status":           record.String("status"),
		"type":             record.String("type"),
	}
}

func apiTokenAttributes(settings Settings, record Record) map[string]string {
	network := record.mapValue("network")
	attrs := map[string]string{
		"api_token_id":             record.String("id"),
		"client_name":              record.String("clientName"),
		"created_at":               record.String("created"),
		"domain":                   settings.Domain,
		"expires_at":               record.String("expiresAt"),
		"family":                   KindAPIToken,
		"last_updated_at":          record.String("lastUpdated"),
		"name":                     record.String("name"),
		"network_connection":       stringMap(network, "connection"),
		"network_zone_exclude_ids": strings.Join(valueIDs(network["exclude"]), ","),
		"network_zone_include_ids": strings.Join(valueIDs(network["include"]), ","),
		"resource_id":              record.String("id"),
		"resource_type":            "ApiToken",
		"token_id":                 record.String("id"),
		"user_id":                  record.String("userId"),
	}
	trimEmptyAttributes(attrs)
	return attrs
}

func authorizationServerAttributes(settings Settings, record Record) map[string]string {
	signing := nestedMap(record.mapValue("credentials"), "signing")
	audiences := nonEmptyAnyStrings(record.anySlice("audiences"))
	attrs := map[string]string{
		"audience_count":          strconv.Itoa(len(audiences)),
		"audiences":               strings.Join(audiences, ","),
		"authorization_server_id": record.String("id"),
		"created_at":              record.String("created"),
		"description":             record.String("description"),
		"domain":                  settings.Domain,
		"family":                  KindAuthorizationServer,
		"issuer":                  record.String("issuer"),
		"issuer_host":             urlHost(record.String("issuer")),
		"issuer_mode":             record.String("issuerMode"),
		"jwks_uri_host":           urlHost(record.String("jwks_uri")),
		"kid":                     stringMap(signing, "kid"),
		"last_updated_at":         record.String("lastUpdated"),
		"name":                    record.String("name"),
		"next_rotation_at":        stringMap(signing, "nextRotation"),
		"resource_id":             record.String("id"),
		"resource_type":           "AuthorizationServer",
		"rotation_mode":           stringMap(signing, "rotationMode"),
		"signing_last_rotated_at": stringMap(signing, "lastRotated"),
		"status":                  record.String("status"),
	}
	trimEmptyAttributes(attrs)
	return attrs
}

func brandAttributes(settings Settings, record Record) map[string]string {
	attrs := map[string]string{
		"brand_id":                   record.String("id"),
		"custom_privacy_policy_url":  record.String("customPrivacyPolicyUrl"),
		"custom_privacy_policy_host": urlHost(record.String("customPrivacyPolicyUrl")),
		"domain":                     settings.Domain,
		"email_domain_id":            record.String("emailDomainId"),
		"family":                     KindBrand,
		"is_default":                 boolAttribute(record.Values["isDefault"]),
		"locale":                     record.String("locale"),
		"name":                       record.String("name"),
		"remove_powered_by_okta":     boolAttribute(record.Values["removePoweredByOkta"]),
		"resource_id":                record.String("id"),
		"resource_type":              "Brand",
	}
	trimEmptyAttributes(attrs)
	return attrs
}

func deviceAssuranceAttributes(settings Settings, record Record) map[string]string {
	attrs := map[string]string{
		"created_at":               record.String("createdDate"),
		"created_by":               record.String("createdBy"),
		"device_assurance_id":      record.String("id"),
		"display_remediation_mode": record.String("displayRemediationMode"),
		"domain":                   settings.Domain,
		"family":                   KindDeviceAssurance,
		"last_updated_at":          record.String("lastUpdate"),
		"last_updated_by":          record.String("lastUpdatedBy"),
		"name":                     record.String("name"),
		"platform":                 record.String("platform"),
		"resource_id":              record.String("id"),
		"resource_type":            "DeviceAssurance",
		"screen_lock_required":     boolAttribute(record.Values["screenLockType"] != nil),
		"secure_hardware_present":  boolAttribute(record.Values["secureHardwarePresent"]),
	}
	trimEmptyAttributes(attrs)
	return attrs
}

func eventHookAttributes(settings Settings, record Record) map[string]string {
	channel := record.mapValue("channel")
	config := nestedMap(channel, "config")
	events := record.mapValue("events")
	attrs := map[string]string{
		"channel_type":            stringMap(channel, "type"),
		"channel_version":         stringMap(channel, "version"),
		"created_at":              record.String("created"),
		"created_by":              record.String("createdBy"),
		"description":             record.String("description"),
		"domain":                  settings.Domain,
		"event_count":             strconv.Itoa(len(valueIDs(events["items"]))),
		"event_hook_id":           record.String("id"),
		"event_subscription_type": stringMap(events, "type"),
		"family":                  KindEventHook,
		"last_updated_at":         record.String("lastUpdated"),
		"name":                    record.String("name"),
		"resource_id":             record.String("id"),
		"resource_type":           "EventHook",
		"status":                  record.String("status"),
		"uri":                     stringMap(config, "uri"),
		"uri_host":                urlHost(stringMap(config, "uri")),
		"verification_status":     record.String("verificationStatus"),
	}
	addAttribute(attrs, "method", stringMap(config, "method"))
	trimEmptyAttributes(attrs)
	return attrs
}

func identityProviderAttributes(settings Settings, record Record) map[string]string {
	protocol := record.mapValue("protocol")
	credentials := nestedMap(protocol, "credentials")
	trust := nestedMap(credentials, "trust")
	client := nestedMap(credentials, "client")
	endpoints := nestedMap(protocol, "endpoints")
	sso := nestedMap(endpoints, "sso")
	acs := nestedMap(endpoints, "acs")
	attrs := map[string]string{
		"domain":               settings.Domain,
		"family":               KindIdentityProvider,
		"idp_id":               record.String("id"),
		"identity_provider_id": record.String("id"),
		"idp_name":             record.String("name"),
		"idp_type":             record.String("type"),
		"name":                 record.String("name"),
		"resource_id":          record.String("id"),
		"resource_type":        "IdentityProvider",
		"status":               record.String("status"),
		"type":                 record.String("type"),
	}
	addAttribute(attrs, "protocol_type", stringMap(protocol, "type"))
	addAttribute(attrs, "issuer", stringMap(trust, "issuer"))
	addAttribute(attrs, "audience", stringMap(trust, "audience"))
	addAttribute(attrs, "kid", stringMap(trust, "kid"))
	addAttribute(attrs, "client_id", stringMap(client, "client_id"))
	addAttribute(attrs, "sso_url_host", urlHost(firstNonEmpty(stringMap(sso, "url"), stringMap(sso, "href"))))
	addAttribute(attrs, "sso_binding", stringMap(sso, "binding"))
	addAttribute(attrs, "acs_type", stringMap(acs, "type"))
	return attrs
}

func inlineHookAttributes(settings Settings, record Record) map[string]string {
	channel := record.mapValue("channel")
	config := nestedMap(channel, "config")
	attrs := map[string]string{
		"channel_type":    stringMap(channel, "type"),
		"channel_version": stringMap(channel, "version"),
		"created_at":      record.String("created"),
		"domain":          settings.Domain,
		"family":          KindInlineHook,
		"inline_hook_id":  record.String("id"),
		"last_updated_at": record.String("lastUpdated"),
		"method":          stringMap(config, "method"),
		"name":            record.String("name"),
		"resource_id":     record.String("id"),
		"resource_type":   "InlineHook",
		"status":          record.String("status"),
		"type":            record.String("type"),
		"uri":             stringMap(config, "uri"),
		"uri_host":        urlHost(stringMap(config, "uri")),
		"version":         record.String("version"),
	}
	trimEmptyAttributes(attrs)
	return attrs
}

func logStreamAttributes(settings Settings, record Record) map[string]string {
	streamSettings := record.mapValue("settings")
	attrs := map[string]string{
		"aws_account_id":        stringMap(streamSettings, "accountId"),
		"aws_event_source_name": stringMap(streamSettings, "eventSourceName"),
		"aws_region":            stringMap(streamSettings, "region"),
		"created_at":            record.String("created"),
		"domain":                settings.Domain,
		"family":                KindLogStream,
		"last_updated_at":       record.String("lastUpdated"),
		"log_stream_id":         record.String("id"),
		"name":                  record.String("name"),
		"resource_id":           record.String("id"),
		"resource_type":         "LogStream",
		"splunk_edition":        stringMap(streamSettings, "edition"),
		"splunk_host":           stringMap(streamSettings, "host"),
		"splunk_host_host":      urlHost(stringMap(streamSettings, "host")),
		"status":                record.String("status"),
		"type":                  record.String("type"),
	}
	trimEmptyAttributes(attrs)
	return attrs
}

func networkZoneAttributes(settings Settings, record Record) map[string]string {
	gateways := record.mapSlice("gateways")
	proxies := record.mapSlice("proxies")
	asns := nonEmptyAnyStrings(record.anySlice("asns"))
	attrs := map[string]string{
		"asn_count":       strconv.Itoa(len(asns)),
		"domain":          settings.Domain,
		"family":          KindNetworkZone,
		"gateway_count":   strconv.Itoa(len(gateways)),
		"location_count":  strconv.Itoa(len(record.mapSlice("locations"))),
		"name":            record.String("name"),
		"network_zone_id": record.String("id"),
		"proxy_count":     strconv.Itoa(len(proxies)),
		"resource_id":     record.String("id"),
		"resource_type":   "NetworkZone",
		"status":          record.String("status"),
		"type":            record.String("type"),
		"usage":           record.String("usage"),
		"zone_id":         record.String("id"),
		"zone_type":       record.String("type"),
	}
	addAttribute(attrs, "asns", strings.Join(asns, ","))
	addAttribute(attrs, "gateway_values", strings.Join(zoneEntryValues(gateways), ","))
	addAttribute(attrs, "proxy_values", strings.Join(zoneEntryValues(proxies), ","))
	if value, ok := record.Values["system"].(bool); ok {
		attrs["system"] = strconv.FormatBool(value)
	}
	return attrs
}

func trimEmptyAttributes(attributes map[string]string) {
	for key, value := range attributes {
		if strings.TrimSpace(value) == "" {
			delete(attributes, key)
		}
	}
}

func boolAttribute(value any) string {
	boolean, ok := value.(bool)
	if !ok {
		return ""
	}
	return strconv.FormatBool(boolean)
}

func trustedOriginAttributes(settings Settings, record Record) map[string]string {
	scopeTypes := trustedOriginScopeTypes(record.mapSlice("scopes"))
	attrs := map[string]string{
		"cors":              strconv.FormatBool(stringSliceContainsFold(scopeTypes, "CORS")),
		"domain":            settings.Domain,
		"family":            KindTrustedOrigin,
		"name":              record.String("name"),
		"origin":            record.String("origin"),
		"origin_host":       urlHost(record.String("origin")),
		"redirect":          strconv.FormatBool(stringSliceContainsFold(scopeTypes, "REDIRECT")),
		"resource_id":       record.String("id"),
		"resource_type":     "TrustedOrigin",
		"scope_count":       strconv.Itoa(len(scopeTypes)),
		"scope_types":       strings.Join(scopeTypes, ","),
		"status":            record.String("status"),
		"trusted_origin_id": record.String("id"),
		"wildcard_origin":   strconv.FormatBool(strings.Contains(record.String("origin"), "*")),
	}
	return attrs
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

func addQuery(query url.Values, key string, value string) {
	if strings.TrimSpace(value) != "" {
		query.Set(key, value)
	}
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
