package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func panopticonAlertProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := panopticonProjectionAttributes(event, "alert_id", "severity", "status", "title")
	alertID := firstAttribute(attrs, "alert_id")
	if alertID == "" {
		return nil, nil, nil
	}
	entity := &ports.ProjectedEntity{
		URN:        projectionURN(tenantID, "panopticon_alert", alertID),
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "panopticon.alert",
		Label:      firstAttribute(attrs, "title", "alert_id"),
		Attributes: compactAttributes(map[string]string{
			"alert_id": alertID,
			"severity": firstAttribute(attrs, "severity"),
			"status":   firstAttribute(attrs, "status"),
			"title":    firstAttribute(attrs, "title"),
			"event_id": event.GetId(),
		}),
	}
	return []*ports.ProjectedEntity{entity}, nil, nil
}

func panopticonCaseProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := panopticonProjectionAttributes(event, "case_id", "status", "title")
	caseID := firstAttribute(attrs, "case_id")
	if caseID == "" {
		return nil, nil, nil
	}
	entity := &ports.ProjectedEntity{
		URN:        projectionURN(tenantID, "panopticon_case", caseID),
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "panopticon.case",
		Label:      firstAttribute(attrs, "title", "case_id"),
		Attributes: compactAttributes(map[string]string{
			"case_id":  caseID,
			"status":   firstAttribute(attrs, "status"),
			"title":    firstAttribute(attrs, "title"),
			"event_id": event.GetId(),
		}),
	}
	return []*ports.ProjectedEntity{entity}, nil, nil
}

func panopticonIOCProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := panopticonProjectionAttributes(event, "ioc_id", "ioc_type", "value")
	iocID := firstAttribute(attrs, "ioc_id")
	value := firstAttribute(attrs, "value")
	if iocID == "" && value == "" {
		return nil, nil, nil
	}
	entity := &ports.ProjectedEntity{
		URN:        projectionURN(tenantID, "panopticon_ioc", firstNonEmpty(iocID, value)),
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "panopticon.ioc",
		Label:      firstNonEmpty(value, iocID),
		Attributes: compactAttributes(map[string]string{
			"ioc_id":   iocID,
			"ioc_type": firstAttribute(attrs, "ioc_type"),
			"value":    value,
			"event_id": event.GetId(),
		}),
	}
	return []*ports.ProjectedEntity{entity}, nil, nil
}

func panopticonProjectionAttributes(event *cerebrov1.EventEnvelope, keys ...string) map[string]string {
	attrs := make(map[string]string, len(event.GetAttributes())+len(keys))
	for key, value := range event.GetAttributes() {
		key = strings.TrimSpace(key)
		if key != "" {
			attrs[key] = value
		}
	}
	payload := payloadMap(event)
	for _, key := range keys {
		if firstAttribute(attrs, key) != "" {
			continue
		}
		if value := stringValue(payload, key); value != "" {
			attrs[key] = value
		}
	}
	return attrs
}
