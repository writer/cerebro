package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type endpointProjectionProfile struct {
	Provider          string
	EndpointKind      string
	EndpointType      string
	EndpointIDKeys    []string
	EndpointLabelKeys []string
	PackageScope      string
}

var (
	kolideEndpointProfile = endpointProjectionProfile{
		Provider:          "kolide",
		EndpointKind:      "kolide_device",
		EndpointType:      "kolide.device",
		EndpointIDKeys:    []string{"device_id", "device_uuid", "serial_number", "asset_id", "external_id"},
		EndpointLabelKeys: []string{"device_name", "hostname", "computer_name", "serial_number"},
		PackageScope:      "osquery",
	}
	kandjiEndpointProfile = endpointProjectionProfile{
		Provider:          "kandji",
		EndpointKind:      "kandji_device",
		EndpointType:      "kandji.device",
		EndpointIDKeys:    []string{"device_id", "device_uuid", "serial_number", "asset_id", "external_id"},
		EndpointLabelKeys: []string{"device_name", "hostname", "computer_name", "serial_number"},
		PackageScope:      "macos",
	}
)

func kolideUserDeviceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return endpointDeviceProjections(event, kolideEndpointProfile)
}

func kolideSoftwareProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return endpointSoftwareInventoryProjections(event, kolideEndpointProfile)
}

func kandjiApplicationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return endpointSoftwareInventoryProjections(event, kandjiEndpointProfile)
}

func kolideCheckProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	checkID := firstAttribute(attrs, "check_id", "external_id", "slug", "name")
	checkURN := projectionURN(tenantID, "kolide_check", checkID)
	if checkURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        checkURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "kolide.check",
			Label:      firstAttribute(attrs, "title", "name", "slug", "check_id"),
			Attributes: map[string]string{
				"check_id":          checkID,
				"slug":              strings.TrimSpace(attrs["slug"]),
				"status":            strings.TrimSpace(attrs["status"]),
				"result":            strings.TrimSpace(attrs["result"]),
				"severity":          strings.TrimSpace(attrs["severity"]),
				"compliance_status": strings.TrimSpace(attrs["compliance_status"]),
				"remediation":       strings.TrimSpace(attrs["remediation"]),
				"source_product":    "kolide",
				"event_id":          event.GetId(),
				"at":                eventObservedAt(event),
			},
		})
	}
	endpointProfile := kolideEndpointProfile
	endpointProfile.EndpointIDKeys = endpointCorrelationIDKeys(kolideEndpointProfile.EndpointIDKeys)
	endpointURN := addEndpointEntity(entities, tenantID, event.GetSourceId(), attrs, endpointProfile)
	if endpointURN != "" && checkURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), endpointURN, checkURN, relationHasEvidence, map[string]string{
			"event_id": event.GetId(),
			"status":   strings.TrimSpace(attrs["status"]),
			"result":   strings.TrimSpace(attrs["result"]),
			"at":       eventObservedAt(event),
		}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), checkURN, endpointURN, relationObservedOn, map[string]string{"event_id": event.GetId(), "at": eventObservedAt(event)}))
	}
	addEndpointOwnerLinks(entities, links, tenantID, event.GetSourceId(), event, endpointURN, attrs)
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func endpointDeviceProjections(event *cerebrov1.EventEnvelope, profile endpointProjectionProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	endpointURN := addEndpointEntity(entities, tenantID, event.GetSourceId(), attrs, profile)
	addEndpointOwnerLinks(entities, links, tenantID, event.GetSourceId(), event, endpointURN, attrs)
	addEndpointIdentifierLinks(entities, links, tenantID, event.GetSourceId(), event, endpointURN, attrs)
	addKandjiBlueprintLink(entities, links, tenantID, event.GetSourceId(), event, endpointURN, attrs, profile)
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func endpointSoftwareInventoryProjections(event *cerebrov1.EventEnvelope, profile endpointProjectionProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	endpointProfile := profile
	endpointProfile.EndpointIDKeys = endpointCorrelationIDKeys(profile.EndpointIDKeys)
	endpointURN := addEndpointEntity(entities, tenantID, event.GetSourceId(), attrs, endpointProfile)
	addEndpointOwnerLinks(entities, links, tenantID, event.GetSourceId(), event, endpointURN, attrs)
	packageURN := vulnerabilityPackageURN(tenantID, attrs, profile.PackageScope)
	canonicalPackageURN := addCanonicalPackageEntity(entities, tenantID, event.GetSourceId(), attrs, profile.PackageScope)
	if packageURN != "" {
		addVulnerablePackageEntity(entities, tenantID, event.GetSourceId(), packageURN, attrs, profile.PackageScope)
		if endpointURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), endpointURN, packageURN, relationContains, map[string]string{"event_id": event.GetId(), "at": eventObservedAt(event)}))
		}
	}
	if packageURN != "" && canonicalPackageURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, canonicalPackageURN, relationRepresents, packageIdentityAttributes(event, attrs, profile.PackageScope)))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func endpointCorrelationIDKeys(keys []string) []string {
	filtered := make([]string, 0, len(keys))
	for _, key := range keys {
		if strings.TrimSpace(key) == "external_id" {
			continue
		}
		filtered = append(filtered, key)
	}
	return filtered
}

func addEndpointEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, attrs map[string]string, profile endpointProjectionProfile) string {
	endpointID := firstAttribute(attrs, profile.EndpointIDKeys...)
	endpointURN := projectionURN(tenantID, profile.EndpointKind, endpointID)
	if endpointURN == "" {
		return ""
	}
	sourceProduct := strings.TrimSpace(profile.Provider)
	if sourceProduct == "" {
		sourceProduct = firstAttribute(attrs, "source_product", "provider", "source_provider")
	}
	endpointAttrs := map[string]string{
		"device_id": endpointID,
	}
	addEndpointAttribute(endpointAttrs, "source_product", sourceProduct)
	addEndpointAttribute(endpointAttrs, "device_uuid", attrs["device_uuid"])
	addEndpointAttribute(endpointAttrs, "hostname", attrs["hostname"])
	addEndpointAttribute(endpointAttrs, "serial_number", attrs["serial_number"])
	addEndpointAttribute(endpointAttrs, "platform", attrs["platform"])
	addEndpointAttribute(endpointAttrs, "os", firstAttribute(attrs, "os", "os_name"))
	addEndpointAttribute(endpointAttrs, "os_version", attrs["os_version"])
	addEndpointAttribute(endpointAttrs, "status", attrs["status"])
	addEndpointAttribute(endpointAttrs, "compliance_status", attrs["compliance_status"])
	addEntity(entities, &ports.ProjectedEntity{
		URN:        endpointURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: profile.EndpointType,
		Label:      firstAttribute(attrs, profile.EndpointLabelKeys...),
		Attributes: endpointAttrs,
	})
	return endpointURN
}

func addEndpointAttribute(attrs map[string]string, key string, value string) {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		attrs[key] = trimmed
	}
}

func addKandjiBlueprintLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, endpointURN string, attrs map[string]string, profile endpointProjectionProfile) {
	blueprintID := firstAttribute(attrs, "blueprint_id")
	if profile.Provider != "kandji" || endpointURN == "" || blueprintID == "" {
		return
	}
	blueprintURN := projectionURN(tenantID, "kandji_blueprint", blueprintID)
	if blueprintURN == "" {
		return
	}
	blueprintName := firstAttribute(attrs, "blueprint_name")
	blueprintAttrs := map[string]string{"blueprint_id": blueprintID}
	addEndpointAttribute(blueprintAttrs, "blueprint_name", blueprintName)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        blueprintURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "kandji.blueprint",
		Label:      firstNonEmpty(blueprintName, blueprintID),
		Attributes: blueprintAttrs,
	})
	addLink(links, projectedLink(tenantID, sourceID, endpointURN, blueprintURN, relationBelongsTo, map[string]string{
		"event_id":   event.GetId(),
		"match_type": "kandji_blueprint",
	}))
}

func addEndpointOwnerLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, endpointURN string, attrs map[string]string) {
	if endpointURN == "" {
		return
	}
	for _, identifier := range []string{
		firstAttribute(attrs, "owner_email"),
		firstAttribute(attrs, "user_email"),
		firstAttribute(attrs, "primary_email"),
		firstAttribute(attrs, "assigned_user"),
	} {
		if strings.TrimSpace(identifier) == "" {
			continue
		}
		addIdentifierLink(entities, links, tenantID, sourceID, event.GetId(), endpointURN, identifier, event.GetOccurredAt())
		identityURN, _ := canonicalIdentityURN(tenantID, identifier)
		if identityURN != "" {
			addLink(links, projectedLink(tenantID, sourceID, endpointURN, identityURN, relationOwnedBy, map[string]string{
				"event_id":   event.GetId(),
				"at":         eventObservedAt(event),
				"match_type": "endpoint_owner_identifier",
			}))
		}
	}
	for _, identifier := range []struct {
		kind  string
		value string
	}{
		{"owner_id", firstAttribute(attrs, "owner_id")},
		{"user_id", firstAttribute(attrs, "user_id")},
	} {
		identifierType := identifier.kind
		if normalizedSourceID := normalizeIdentifier(sourceID); normalizedSourceID != "" {
			identifierType = normalizedSourceID + "_" + identifier.kind
		}
		addEndpointIdentifierLink(entities, links, tenantID, sourceID, event, endpointURN, identifierType, identifier.value, "0.75")
	}
}

func endpointOwnerIDRetractions(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedLink, error) {
	profile, correlationOnly, ok := endpointOwnerIDRetractionProfile(event.GetKind())
	if !ok {
		return nil, nil
	}
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, err
	}
	attrs := event.GetAttributes()
	endpointIDKeys := profile.EndpointIDKeys
	if correlationOnly {
		endpointIDKeys = endpointCorrelationIDKeys(endpointIDKeys)
	}
	endpointURN := projectionURN(tenantID, profile.EndpointKind, firstAttribute(attrs, endpointIDKeys...))
	if endpointURN == "" {
		return nil, nil
	}
	links := map[string]*ports.ProjectedLink{}
	for _, raw := range []string{firstAttribute(attrs, "owner_id"), firstAttribute(attrs, "user_id")} {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		identityURN, _ := canonicalIdentityURN(tenantID, raw)
		if identityURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), endpointURN, identityURN, relationRepresentsIdentity, map[string]string{"event_id": event.GetId(), "retraction": "endpoint_owner_id"}))
			addLink(links, projectedLink(tenantID, event.GetSourceId(), endpointURN, identityURN, relationOwnedBy, map[string]string{"event_id": event.GetId(), "retraction": "endpoint_owner_id"}))
		}
		identifierURNValue, _, _ := identifierURN(tenantID, raw)
		if identifierURNValue != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), endpointURN, identifierURNValue, relationHasIdentifier, map[string]string{"event_id": event.GetId(), "retraction": "endpoint_owner_id"}))
		}
	}
	_, projectedLinks := entitiesAndLinks(nil, links)
	return projectedLinks, nil
}

func endpointOwnerIDRetractionProfile(kind string) (endpointProjectionProfile, bool, bool) {
	switch strings.TrimSpace(kind) {
	case "kolide.device", "kolide.user_device":
		return kolideEndpointProfile, false, true
	case "kolide.software", "kolide.check", "kolide.issue":
		return kolideEndpointProfile, true, true
	case "kandji.device":
		return kandjiEndpointProfile, false, true
	case "kandji.application":
		return kandjiEndpointProfile, true, true
	case "grc.monitored_computer":
		return grcMonitoredComputerEndpointProfile, false, true
	default:
		return endpointProjectionProfile{}, false, false
	}
}

func addEndpointIdentifierLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, endpointURN string, attrs map[string]string) {
	if endpointURN == "" {
		return
	}
	addEndpointIdentifierLink(entities, links, tenantID, sourceID, event, endpointURN, "serial_number", firstAttribute(attrs, "serial_number", "hardware_serial"), "0.95")
	addEndpointIdentifierLink(entities, links, tenantID, sourceID, event, endpointURN, "hostname", firstAttribute(attrs, "hostname", "device_name", "computer_name"), "0.80")
	addEndpointIdentifierLink(entities, links, tenantID, sourceID, event, endpointURN, "device_uuid", firstAttribute(attrs, "device_uuid", "agent_uuid"), "0.95")
}

func addEndpointIdentifierLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, endpointURN string, identifierType string, rawValue string, confidence string) {
	value := strings.TrimSpace(rawValue)
	if value == "" {
		return
	}
	normalized := normalizeIdentifier(value)
	identifierURN := projectionURN(tenantID, "endpoint_identifier", identifierType, normalized)
	if identifierURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        identifierURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "endpoint.identifier",
		Label:      value,
		Attributes: map[string]string{
			"identifier_type":  identifierType,
			"identifier_value": normalized,
			"value":            value,
		},
	})
	addLink(links, projectedLink(tenantID, sourceID, endpointURN, identifierURN, relationHasIdentifier, map[string]string{
		"at":                eventObservedAt(event),
		"confidence":        confidence,
		"event_id":          event.GetId(),
		"identifier_type":   identifierType,
		"identifier_value":  normalized,
		"match_type":        "endpoint_identifier",
		"source_event_kind": event.GetKind(),
	}))
}
