package sourceprojection

import (
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var grcMonitoredComputerEndpointProfile = endpointProjectionProfile{
	EndpointKind:      "grc_monitored_computer",
	EndpointType:      "grc.monitored_computer",
	EndpointIDKeys:    []string{"device_id", "computer_id", "device_uuid", "serial_number", "external_id"},
	EndpointLabelKeys: []string{"hostname", "owner_display_name", "serial_number", "device_uuid", "computer_id"},
}

func grcMonitoredComputerProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	computerID := firstAttribute(attrs, grcMonitoredComputerEndpointProfile.EndpointIDKeys...)
	if computerID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	endpointURN := addEndpointEntity(entities, tenantID, event.GetSourceId(), attrs, grcMonitoredComputerEndpointProfile)
	addEndpointOwnerLinks(entities, links, tenantID, event.GetSourceId(), event, endpointURN, attrs)
	addEndpointIdentifierLinks(entities, links, tenantID, event.GetSourceId(), event, endpointURN, attrs)
	if integrationID := firstAttribute(attrs, "integration_id"); endpointURN != "" && integrationID != "" {
		integrationURN := grcIntegrationURN(tenantID, provider, integrationID)
		addEntity(entities, grcIntegrationReferenceEntity(tenantID, event.GetSourceId(), integrationURN, integrationID, provider))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), endpointURN, integrationURN, relationBelongsTo, map[string]string{
			"event_id":   event.GetId(),
			"match_type": "grc_monitored_computer_integration",
		}))
	}
	for _, check := range []struct {
		ID     string
		Title  string
		Status string
	}{
		{ID: "screenlock", Title: "Screen lock", Status: firstAttribute(attrs, "screenlock_status")},
		{ID: "disk_encryption", Title: "Disk encryption", Status: firstAttribute(attrs, "disk_encryption_status")},
		{ID: "password_manager", Title: "Password manager", Status: firstAttribute(attrs, "password_manager_status")},
		{ID: "antivirus", Title: "Antivirus", Status: firstAttribute(attrs, "antivirus_status")},
	} {
		addGRCMonitoredComputerPostureEvidence(entities, links, tenantID, event.GetSourceId(), event, endpointURN, provider, computerID, check.ID, check.Title, check.Status)
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func addGRCMonitoredComputerPostureEvidence(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, endpointURN string, provider string, computerID string, checkID string, title string, status string) {
	status = strings.TrimSpace(status)
	if endpointURN == "" || computerID == "" || checkID == "" || status == "" {
		return
	}
	evidenceURN := projectionURN(tenantID, "evidence", provider, "monitored_computer", computerID, checkID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        evidenceURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "evidence",
		Label:      fmt.Sprintf("%s posture: %s", title, computerID),
		Attributes: grcAttributes(nil, map[string]string{
			"computer_id":        computerID,
			"evidence_type":      "device_posture",
			"posture_check":      checkID,
			"posture_check_name": title,
			"source_system":      provider,
			"status":             status,
		}),
	})
	linkAttrs := map[string]string{
		"event_id":       event.GetId(),
		"match_type":     "grc_monitored_computer_posture",
		"posture_check":  checkID,
		"posture_status": status,
	}
	addLink(links, projectedLink(tenantID, sourceID, endpointURN, evidenceURN, relationHasEvidence, linkAttrs))
	addLink(links, projectedLink(tenantID, sourceID, evidenceURN, endpointURN, relationObservedOn, linkAttrs))
}
