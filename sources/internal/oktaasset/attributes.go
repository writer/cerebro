package oktaasset

import (
	"encoding/json"
	"strconv"
	"strings"
)

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
	metadataLink := nestedMap(record.mapValue("_links"), "metadata")
	jwksLink := nestedMap(record.mapValue("_links"), "jwks")
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
		"jwks_uri_host":           urlHost(firstNonEmpty(record.String("jwks_uri"), stringMap(jwksLink, "href"), stringMap(metadataLink, "href"))),
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
