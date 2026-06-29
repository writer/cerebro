package sourceprojection

import (
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func oktaAuthenticatorProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	domain := strings.TrimSpace(attributes["domain"])
	authID := strings.TrimSpace(attributes["authenticator_id"])

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "okta_org", domain)
	if domain != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: orgURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "okta.org", Label: domain,
			Attributes: map[string]string{"domain": domain},
		})
	}

	authURN := projectionURN(tenantID, "okta_authenticator", authID)
	if authID != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: authURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "okta.authenticator", Label: firstNonEmpty(attributes["name"], authID),
			Attributes: map[string]string{
				"authenticator_id": authID,
				"key":              strings.TrimSpace(attributes["key"]),
				"name":             strings.TrimSpace(attributes["name"]),
				"status":           strings.TrimSpace(attributes["status"]),
				"type":             strings.TrimSpace(attributes["type"]),
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), authURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func oktaThreatInsightProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	domain := strings.TrimSpace(attributes["domain"])

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "okta_org", domain)
	if domain != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: orgURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "okta.org", Label: domain,
			Attributes: map[string]string{"domain": domain},
		})
	}

	tiURN := projectionURN(tenantID, "okta_threat_insight", domain)
	if domain != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: tiURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "okta.threat_insight", Label: "ThreatInsight",
			Attributes: map[string]string{
				"action":             strings.TrimSpace(attributes["action"]),
				"exclude_zone_count": strings.TrimSpace(attributes["exclude_zone_count"]),
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), tiURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		for _, zoneID := range oktaThreatInsightExcludeZoneIDs(event) {
			zoneURN := projectionURN(tenantID, "okta_network_zone", zoneID)
			addEntity(entities, &ports.ProjectedEntity{
				URN:        zoneURN,
				TenantID:   tenantID,
				SourceID:   event.GetSourceId(),
				EntityType: "okta.network_zone",
				Label:      zoneID,
				Attributes: map[string]string{"network_zone_id": zoneID, "zone_id": zoneID},
			})
			addLink(links, projectedLink(tenantID, event.GetSourceId(), tiURN, zoneURN, relationDependsOn, map[string]string{
				"condition_scope": "exclude",
				"event_id":        event.GetId(),
				"match_type":      "okta_threat_insight_network_zone",
			}))
			addIdentityOrgMembershipLink(links, tenantID, event, zoneURN, orgURN)
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func oktaThreatInsightExcludeZoneIDs(event *cerebrov1.EventEnvelope) []string {
	seen := map[string]struct{}{}
	ids := []string{}
	add := func(raw string) {
		for _, value := range splitCSV(raw) {
			zoneID := durableIdentityConditionReferenceID(value)
			if zoneID == "" {
				continue
			}
			if _, ok := seen[zoneID]; ok {
				continue
			}
			seen[zoneID] = struct{}{}
			ids = append(ids, zoneID)
		}
	}
	add(event.GetAttributes()["exclude_zones"])
	payload := payloadMap(event)
	if values, ok := payload["exclude_zones"].([]any); ok {
		for _, value := range values {
			if zoneID, ok := value.(string); ok {
				add(zoneID)
			}
		}
	}
	return ids
}

type oktaAssetProjectionOptions struct {
	urnKind         string
	entityType      string
	idAttributes    []string
	labelAttributes []string
	copyAttributes  []string
	hostAttributes  []string
}

func oktaAPITokenProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return oktaAssetProjections(event, oktaAssetProjectionOptions{
		urnKind: "okta_api_token", entityType: "okta.api_token",
		idAttributes:    []string{"api_token_id", "token_id", "resource_id"},
		labelAttributes: []string{"name", "api_token_id", "token_id"},
		copyAttributes:  []string{"api_token_id", "client_name", "created_at", "expires_at", "last_updated_at", "name", "network_connection", "network_zone_exclude_ids", "network_zone_include_ids", "token_id", "user_id"},
	})
}

func oktaAuthorizationServerProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return oktaAssetProjections(event, oktaAssetProjectionOptions{
		urnKind: "okta_authorization_server", entityType: "okta.authorization_server",
		idAttributes:    []string{"authorization_server_id", "resource_id"},
		labelAttributes: []string{"name", "authorization_server_id"},
		copyAttributes:  []string{"audience_count", "audiences", "authorization_server_id", "created_at", "description", "issuer", "issuer_host", "issuer_mode", "jwks_uri_host", "kid", "last_updated_at", "name", "next_rotation_at", "rotation_mode", "signing_last_rotated_at", "status"},
		hostAttributes:  []string{"issuer_host", "jwks_uri_host"},
	})
}

func oktaBrandProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return oktaAssetProjections(event, oktaAssetProjectionOptions{
		urnKind: "okta_brand", entityType: "okta.brand",
		idAttributes:    []string{"brand_id", "resource_id"},
		labelAttributes: []string{"name", "brand_id"},
		copyAttributes:  []string{"brand_id", "custom_privacy_policy_host", "custom_privacy_policy_url", "email_domain_id", "is_default", "locale", "name", "remove_powered_by_okta"},
		hostAttributes:  []string{"custom_privacy_policy_host"},
	})
}

func oktaDeviceAssuranceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return oktaAssetProjections(event, oktaAssetProjectionOptions{
		urnKind: "okta_device_assurance", entityType: "okta.device_assurance",
		idAttributes:    []string{"device_assurance_id", "resource_id"},
		labelAttributes: []string{"name", "device_assurance_id"},
		copyAttributes:  []string{"created_at", "created_by", "device_assurance_id", "display_remediation_mode", "last_updated_at", "last_updated_by", "name", "platform", "screen_lock_required", "secure_hardware_present"},
	})
}

func oktaEventHookProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return oktaAssetProjections(event, oktaAssetProjectionOptions{
		urnKind: "okta_event_hook", entityType: "okta.event_hook",
		idAttributes:    []string{"event_hook_id", "resource_id"},
		labelAttributes: []string{"name", "event_hook_id"},
		copyAttributes:  []string{"channel_type", "channel_version", "created_at", "created_by", "description", "event_count", "event_hook_id", "event_subscription_type", "last_updated_at", "method", "name", "status", "uri", "uri_host", "verification_status"},
		hostAttributes:  []string{"uri_host"},
	})
}

func oktaInlineHookProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return oktaAssetProjections(event, oktaAssetProjectionOptions{
		urnKind: "okta_inline_hook", entityType: "okta.inline_hook",
		idAttributes:    []string{"inline_hook_id", "resource_id"},
		labelAttributes: []string{"name", "inline_hook_id"},
		copyAttributes:  []string{"channel_type", "channel_version", "created_at", "inline_hook_id", "last_updated_at", "method", "name", "status", "type", "uri", "uri_host", "version"},
		hostAttributes:  []string{"uri_host"},
	})
}

func oktaLogStreamProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return oktaAssetProjections(event, oktaAssetProjectionOptions{
		urnKind: "okta_log_stream", entityType: "okta.log_stream",
		idAttributes:    []string{"log_stream_id", "resource_id"},
		labelAttributes: []string{"name", "log_stream_id"},
		copyAttributes:  []string{"aws_account_id", "aws_event_source_name", "aws_region", "created_at", "last_updated_at", "log_stream_id", "name", "splunk_edition", "splunk_host", "splunk_host_host", "status", "type"},
		hostAttributes:  []string{"splunk_host_host"},
	})
}

func oktaAssetProjections(event *cerebrov1.EventEnvelope, options oktaAssetProjectionOptions) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	domain := strings.TrimSpace(attrs["domain"])
	assetID := firstNonEmpty(attributeValues(attrs, options.idAttributes)...)
	if assetID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	orgURN := projectionURN(tenantID, "okta_org", domain)
	if domain != "" {
		addEntity(entities, &ports.ProjectedEntity{URN: orgURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "okta.org", Label: domain, Attributes: map[string]string{"domain": domain}})
	}
	assetURN := projectionURN(tenantID, options.urnKind, assetID)
	assetAttrs := map[string]string{}
	for _, key := range options.copyAttributes {
		addProjectedAttribute(assetAttrs, key, attrs[key])
	}
	addEntity(entities, &ports.ProjectedEntity{URN: assetURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: options.entityType, Label: firstNonEmpty(attributeValues(attrs, options.labelAttributes)...), Attributes: assetAttrs})
	if orgURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), assetURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
	}
	addOktaAssetHostLinks(entities, links, tenantID, event, assetURN, options.entityType, attrs, options.hostAttributes)
	addOktaAPITokenOwnerLinks(entities, links, tenantID, event, assetURN, orgURN, attrs)
	addOktaAPITokenNetworkZoneLinks(entities, links, tenantID, event, assetURN, orgURN, attrs)
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func attributeValues(attrs map[string]string, keys []string) []string {
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, attrs[key])
	}
	return values
}

func addOktaAssetHostLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, assetURN string, entityType string, attrs map[string]string, hostKeys []string) {
	for _, key := range hostKeys {
		host := strings.TrimSpace(attrs[key])
		if host == "" {
			continue
		}
		matchType := strings.ReplaceAll(entityType, ".", "_") + "_" + key
		addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, assetURN, relationHasIdentifier, host, matchType, "0.95")
		addInternetHostDomainLink(entities, links, tenantID, event.GetSourceId(), event, host, matchType+"_domain", "0.95")
	}
}

func addOktaAPITokenOwnerLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, tokenURN string, orgURN string, attrs map[string]string) {
	userID := strings.TrimSpace(attrs["user_id"])
	if strings.TrimSpace(attrs["api_token_id"]) == "" || userID == "" {
		return
	}
	userURN := identityUserURN(tenantID, "okta", userID, "")
	addEntity(entities, &ports.ProjectedEntity{URN: userURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "okta.user", Label: userID, Attributes: map[string]string{"user_id": userID}})
	addLink(links, projectedLink(tenantID, event.GetSourceId(), userURN, tokenURN, relationAssignedTo, map[string]string{"event_id": event.GetId(), "match_type": "okta_api_token_creator"}))
	addIdentityOrgMembershipLink(links, tenantID, event, userURN, orgURN)
}

func addOktaAPITokenNetworkZoneLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, tokenURN string, orgURN string, attrs map[string]string) {
	if strings.TrimSpace(attrs["api_token_id"]) == "" {
		return
	}
	for _, item := range []struct {
		values string
		scope  string
	}{
		{attrs["network_zone_include_ids"], "include"},
		{attrs["network_zone_exclude_ids"], "exclude"},
	} {
		for _, zoneID := range splitCSV(item.values) {
			zoneID = durableIdentityConditionReferenceID(zoneID)
			if zoneID == "" {
				continue
			}
			zoneURN := projectionURN(tenantID, "okta_network_zone", zoneID)
			addEntity(entities, &ports.ProjectedEntity{URN: zoneURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "okta.network_zone", Label: zoneID, Attributes: map[string]string{"network_zone_id": zoneID, "zone_id": zoneID}})
			addLink(links, projectedLink(tenantID, event.GetSourceId(), tokenURN, zoneURN, relationDependsOn, map[string]string{"condition_scope": item.scope, "event_id": event.GetId(), "match_type": "okta_api_token_network_zone"}))
			addIdentityOrgMembershipLink(links, tenantID, event, zoneURN, orgURN)
		}
	}
}

func oktaIdentityProviderProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	domain := strings.TrimSpace(attributes["domain"])
	idpID := strings.TrimSpace(firstNonEmpty(attributes["idp_id"], attributes["identity_provider_id"]))

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "okta_org", domain)
	if domain != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: orgURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "okta.org", Label: domain,
			Attributes: map[string]string{"domain": domain},
		})
	}

	idpURN := projectionURN(tenantID, "okta_identity_provider", idpID)
	if idpID != "" {
		idpAttrs := map[string]string{
			"idp_id":               idpID,
			"identity_provider_id": idpID,
			"name":                 strings.TrimSpace(firstNonEmpty(attributes["name"], attributes["idp_name"])),
			"status":               strings.TrimSpace(attributes["status"]),
			"type":                 strings.TrimSpace(firstNonEmpty(attributes["type"], attributes["idp_type"])),
		}
		for _, key := range []string{"acs_type", "audience", "client_id", "issuer", "kid", "protocol_type", "sso_binding", "sso_url_host"} {
			addProjectedAttribute(idpAttrs, key, attributes[key])
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        idpURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.identity_provider",
			Label:      firstNonEmpty(idpAttrs["name"], idpID),
			Attributes: idpAttrs,
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), idpURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, idpURN, relationHasIdentifier, attributes["issuer"], "okta_identity_provider_issuer_host", "0.95")
		addInternetHostDomainLink(entities, links, tenantID, event.GetSourceId(), event, attributes["issuer"], "okta_identity_provider_issuer_domain", "0.95")
		addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, idpURN, relationHasIdentifier, attributes["sso_url_host"], "okta_identity_provider_sso_host", "0.90")
		addInternetHostDomainLink(entities, links, tenantID, event.GetSourceId(), event, attributes["sso_url_host"], "okta_identity_provider_sso_domain", "0.90")
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func oktaNetworkZoneProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	domain := strings.TrimSpace(attributes["domain"])
	zoneID := strings.TrimSpace(firstNonEmpty(attributes["zone_id"], attributes["network_zone_id"]))

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "okta_org", domain)
	if domain != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: orgURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "okta.org", Label: domain,
			Attributes: map[string]string{"domain": domain},
		})
	}

	zoneURN := projectionURN(tenantID, "okta_network_zone", zoneID)
	if zoneID != "" {
		zoneAttrs := map[string]string{
			"name":            strings.TrimSpace(attributes["name"]),
			"network_zone_id": zoneID,
			"status":          strings.TrimSpace(attributes["status"]),
			"type":            strings.TrimSpace(firstNonEmpty(attributes["type"], attributes["zone_type"])),
			"usage":           strings.TrimSpace(attributes["usage"]),
			"zone_id":         zoneID,
		}
		for _, key := range []string{"asn_count", "asns", "gateway_count", "gateway_values", "location_count", "proxy_count", "proxy_values", "system"} {
			addProjectedAttribute(zoneAttrs, key, attributes[key])
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        zoneURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.network_zone",
			Label:      firstNonEmpty(zoneAttrs["name"], zoneID),
			Attributes: zoneAttrs,
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), zoneURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func oktaTrustedOriginProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	domain := strings.TrimSpace(attributes["domain"])
	originID := strings.TrimSpace(attributes["trusted_origin_id"])

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "okta_org", domain)
	if domain != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: orgURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "okta.org", Label: domain,
			Attributes: map[string]string{"domain": domain},
		})
	}

	originURN := projectionURN(tenantID, "okta_trusted_origin", originID)
	if originID != "" {
		originAttrs := map[string]string{
			"name":              strings.TrimSpace(attributes["name"]),
			"origin":            strings.TrimSpace(attributes["origin"]),
			"origin_host":       strings.TrimSpace(attributes["origin_host"]),
			"status":            strings.TrimSpace(attributes["status"]),
			"trusted_origin_id": originID,
		}
		for _, key := range []string{"cors", "redirect", "scope_count", "scope_types", "wildcard_origin"} {
			addProjectedAttribute(originAttrs, key, attributes[key])
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        originURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.trusted_origin",
			Label:      firstNonEmpty(originAttrs["name"], originAttrs["origin"], originID),
			Attributes: originAttrs,
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), originURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, originURN, relationHasIdentifier, firstNonEmpty(originAttrs["origin_host"], originAttrs["origin"]), "okta_trusted_origin_host", "0.95")
		addInternetHostDomainLink(entities, links, tenantID, event.GetSourceId(), event, firstNonEmpty(originAttrs["origin_host"], originAttrs["origin"]), "okta_trusted_origin_domain", "0.95")
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func oktaUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	payload := payloadMap(event)
	domain := strings.TrimSpace(attributes["domain"])
	userID := strings.TrimSpace(attributes["user_id"])
	email := strings.TrimSpace(attributes["email"])
	login := strings.TrimSpace(attributes["login"])

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "okta_org", domain)
	if domain != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        orgURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.org",
			Label:      domain,
			Attributes: map[string]string{"domain": domain},
		})
	}

	userURN := oktaUserURN(tenantID, userID)
	if userURN != "" {
		userAttrs := map[string]string{
			"email":           email,
			"event_kind":      event.GetKind(),
			"login":           login,
			"source_event_id": event.GetId(),
			"status":          strings.TrimSpace(attributes["status"]),
		}
		for _, key := range []string{
			"activated_at",
			"created_at",
			"department",
			"employee_number",
			"job_title",
			"last_login_at",
			"last_updated_at",
			"manager",
			"manager_id",
			"mfa_enrolled",
			"mfa_factor_count",
			"mfa_factor_types",
			"mfa_phishing_resistant",
			"organization",
			"password_changed_at",
			"status_changed_at",
			"user_type",
		} {
			if v := firstNonEmpty(attributes[key], nestedString(payload, "timestamps."+key)); v != "" {
				userAttrs[key] = v
			}
		}
		if observedAt := eventObservedAt(event); observedAt != "" {
			userAttrs["observed_at"] = observedAt
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        userURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.user",
			Label:      firstNonEmpty(email, login, userID),
			Attributes: userAttrs,
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), userURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		// observedAt is the time this projection ran, not the event's
		// OccurredAt. okta.user events derive OccurredAt from profile-history
		// fields (LastUpdated/Created/Activated/StatusChanged/LastLogin/
		// PasswordChanged) in sources/okta/source.go's userOccurredAt, so any
		// user whose profile has been static for longer than the graph-rule
		// recency window would have its represents_identity edges restamped
		// with an already-stale `at` on every fresh sync. Identity-aware rules
		// (e.g. the deprovisioned-Okta-active-in-GitHub graph rule) treat
		// stale-`at` rows as evidence the identifier link is no longer
		// asserted and drop them, which silently swallows offboarding gaps for
		// long-static accounts. Stamping with the projection's own clock
		// instead means any current inventory link is always recent, while
		// edges that stop being re-asserted (e.g. a renamed email) still age
		// out naturally because subsequent syncs no longer refresh them.
		observedAt := timestamppb.New(time.Now().UTC())
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), userURN, email, observedAt)
		if !sameIdentifier(email, login) {
			addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), userURN, login, observedAt)
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func oktaAuditProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	domain := strings.TrimSpace(attributes["domain"])
	actorID := strings.TrimSpace(attributes["actor_id"])
	actorType := strings.TrimSpace(attributes["actor_type"])
	actorAlternateID := strings.TrimSpace(attributes["actor_alternate_id"])
	actorDisplayName := strings.TrimSpace(attributes["actor_display_name"])
	resourceID := strings.TrimSpace(attributes["resource_id"])
	resourceType := strings.TrimSpace(attributes["resource_type"])
	targetType := strings.TrimSpace(attributes["target_type"])
	targetAlternateID := strings.TrimSpace(attributes["target_alternate_id"])
	targetAppID := firstNonEmpty(attributes["target_app_id"], attributes["app_id"])
	targetAppLabel := firstNonEmpty(attributes["target_app_label"], attributes["target_display_name"], targetAppID)
	oauthClientID := firstNonEmpty(attributes["oauth_client_id"], attributes["client_id"])
	oauthClientLabel := firstNonEmpty(attributes["oauth_client_label"], attributes["actor_display_name"], oauthClientID)

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "okta_org", domain)
	if domain != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        orgURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.org",
			Label:      domain,
			Attributes: map[string]string{"domain": domain},
		})
	}

	suppressResource := oktaEphemeralOAuthRuntimeResource(resourceType, attributes)
	resourceURN := ""
	if !suppressResource {
		resourceURN = oktaResourceURN(tenantID, resourceType, resourceID)
	}
	if resourceURN != "" {
		entityType := "okta.resource"
		if strings.EqualFold(resourceType, "user") {
			entityType = "okta.user"
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: entityType,
			Label:      firstNonEmpty(resourceID, resourceType),
			Attributes: map[string]string{
				"resource_id":   resourceID,
				"resource_type": resourceType,
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		if oktaAuditTargetUser(resourceType, targetType) {
			addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), resourceURN, targetAlternateID, event.GetOccurredAt())
		}
	}

	targetAppURN := oktaApplicationURN(tenantID, targetAppID)
	if targetAppURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        targetAppURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.application",
			Label:      targetAppLabel,
			Attributes: map[string]string{
				"app_id":    targetAppID,
				"app_label": targetAppLabel,
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), targetAppURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	oauthClientURN := oktaApplicationURN(tenantID, oauthClientID)
	if oauthClientURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        oauthClientURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.application",
			Label:      oauthClientLabel,
			Attributes: map[string]string{
				"app_id":               oauthClientID,
				"client_id":            oauthClientID,
				"oauth_client_type":    strings.TrimSpace(attributes["oauth_client_type"]),
				"oauth_event_category": strings.TrimSpace(attributes["oauth_event_category"]),
				"grant_type":           strings.TrimSpace(attributes["grant_type"]),
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), oauthClientURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		if resourceURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), oauthClientURN, resourceURN, relationActedOn, oktaOAuthRelationAttributes(event, attributes)))
		}
	}

	actorURN := oktaActorURN(tenantID, actorType, actorID)
	if actorURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        actorURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: oktaActorEntityType(actorType),
			Label:      firstNonEmpty(actorAlternateID, actorDisplayName, actorID),
			Attributes: map[string]string{
				"actor_id":           actorID,
				"actor_type":         actorType,
				"actor_alternate_id": actorAlternateID,
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		if resourceURN != "" && resourceURN != actorURN {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, resourceURN, relationActedOn, oktaAuditRelationAttributes(event, attributes, nil)))
		}
		if targetAppURN != "" && targetAppURN != actorURN && targetAppURN != resourceURN {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, targetAppURN, relationActedOn, oktaAuditRelationAttributes(event, attributes, map[string]string{
				"target_app_id":    targetAppID,
				"target_app_label": targetAppLabel,
			})))
		}
		if suppressResource && oauthClientURN != "" && oauthClientURN != actorURN {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, oauthClientURN, relationActedOn, oktaOAuthRelationAttributes(event, attributes)))
		}
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), actorURN, actorAlternateID, event.GetOccurredAt())
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func oktaAuditRelationAttributes(event *cerebrov1.EventEnvelope, attributes map[string]string, extra map[string]string) map[string]string {
	relationAttrs := map[string]string{
		"event_id":   event.GetId(),
		"event_type": strings.TrimSpace(attributes["event_type"]),
	}
	addProjectedAttribute(relationAttrs, "outcome_result", strings.TrimSpace(attributes["outcome_result"]))
	addProjectedAttribute(relationAttrs, "outcome_reason", strings.TrimSpace(attributes["outcome_reason"]))
	addProjectedAttribute(relationAttrs, "transaction_id", strings.TrimSpace(attributes["transaction_id"]))
	addProjectedAttribute(relationAttrs, "client_ip", strings.TrimSpace(attributes["client_ip"]))
	addProjectedAttribute(relationAttrs, "source_runtime_id", strings.TrimSpace(attributes["source_runtime_id"]))
	if occurredAt := event.GetOccurredAt(); occurredAt != nil && occurredAt.IsValid() {
		relationAttrs["at"] = occurredAt.AsTime().UTC().Format(time.RFC3339)
	}
	for key, value := range extra {
		addProjectedAttribute(relationAttrs, key, strings.TrimSpace(value))
	}
	return relationAttrs
}

func oktaOAuthRelationAttributes(event *cerebrov1.EventEnvelope, attributes map[string]string) map[string]string {
	return oktaAuditRelationAttributes(event, attributes, map[string]string{
		"oauth_event_category": attributes["oauth_event_category"],
		"grant_type":           attributes["grant_type"],
	})
}

func oktaEphemeralOAuthRuntimeResource(resourceType string, attributes map[string]string) bool {
	if !oktaRuntimeGrant(attributes) {
		return false
	}
	switch compactOktaResourceType(resourceType) {
	case "accesstoken", "refreshtoken", "authorizationcode", "idtoken", "code":
		return true
	default:
		return false
	}
}

func oktaEphemeralOAuthRuntimeResourceURNPrefixes(tenantID string) []string {
	resourceTypes := []string{
		"access_token",
		"accesstoken",
		"access-token",
		"access token",
		"refresh_token",
		"refreshtoken",
		"refresh-token",
		"refresh token",
		"authorization_code",
		"authorizationcode",
		"authorization-code",
		"authorization code",
		"id_token",
		"idtoken",
		"id-token",
		"id token",
		"code",
	}
	prefixes := make([]string, 0, len(resourceTypes))
	for _, resourceType := range resourceTypes {
		prefix := projectionURN(tenantID, "okta_resource", resourceType)
		if prefix != "" {
			prefixes = append(prefixes, prefix+":")
		}
	}
	return prefixes
}

func oktaRuntimeGrant(attributes map[string]string) bool {
	if strings.EqualFold(strings.TrimSpace(attributes["oauth_event_category"]), "runtime_grant") {
		return true
	}
	eventType := strings.ToLower(strings.TrimSpace(attributes["event_type"]))
	switch eventType {
	case "app.oauth2.authorize.code", "app.oauth2.as.authorize.code":
		return true
	default:
		return strings.HasPrefix(eventType, "app.oauth2.token.grant.") ||
			strings.HasPrefix(eventType, "app.oauth2.as.token.grant.")
	}
}

func compactOktaResourceType(resourceType string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		case r >= '0' && r <= '9':
			return r
		default:
			return -1
		}
	}, strings.TrimSpace(resourceType))
}

func oktaUserURN(tenantID string, userID string) string {
	value := strings.TrimSpace(userID)
	if value == "" {
		return ""
	}
	return projectionURN(tenantID, "okta_user", value)
}

func oktaApplicationURN(tenantID string, appID string) string {
	value := strings.TrimSpace(appID)
	if value == "" {
		return ""
	}
	return projectionURN(tenantID, "okta_application", value)
}

func oktaActorURN(tenantID string, actorType string, actorID string) string {
	switch {
	case strings.EqualFold(actorType, "user"):
		return oktaUserURN(tenantID, actorID)
	case strings.TrimSpace(actorID) == "":
		return ""
	default:
		return projectionURN(tenantID, "okta_actor", normalizeIdentifier(actorType), strings.TrimSpace(actorID))
	}
}

func oktaActorEntityType(actorType string) string {
	if strings.EqualFold(actorType, "user") {
		return "okta.user"
	}
	if strings.TrimSpace(actorType) == "" {
		return "okta.actor"
	}
	return "okta." + normalizeIdentifier(actorType)
}

func oktaResourceURN(tenantID string, resourceType string, resourceID string) string {
	if strings.TrimSpace(resourceID) == "" {
		return ""
	}
	if strings.EqualFold(resourceType, "user") {
		return oktaUserURN(tenantID, resourceID)
	}
	return projectionURN(tenantID, "okta_resource", normalizeIdentifier(resourceType), strings.TrimSpace(resourceID))
}

func oktaAuditTargetUser(resourceType string, targetType string) bool {
	return strings.EqualFold(resourceType, "user") || strings.EqualFold(targetType, "user")
}
