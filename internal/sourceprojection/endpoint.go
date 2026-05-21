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

func kolideDeviceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return endpointDeviceProjections(event, kolideEndpointProfile)
}

func kolideUserDeviceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return endpointDeviceProjections(event, kolideEndpointProfile)
}

func kandjiDeviceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return endpointDeviceProjections(event, kandjiEndpointProfile)
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
	endpointAttrs := map[string]string{
		"device_id":      endpointID,
		"source_product": profile.Provider,
	}
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

func addEndpointOwnerLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, endpointURN string, attrs map[string]string) {
	if endpointURN == "" {
		return
	}
	for _, identifier := range []string{
		firstAttribute(attrs, "owner_email"),
		firstAttribute(attrs, "owner_id"),
		firstAttribute(attrs, "user_email"),
		firstAttribute(attrs, "user_id"),
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
