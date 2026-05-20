package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func cosmoSessionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	payload := payloadMap(event)
	sessionID := firstNonEmpty(attrs["ticket_id"], attrs["thread_key"], attrs["record_id"], stringValue(payload, "ticket_id"), stringValue(payload, "thread_key"), stringValue(payload, "id"))
	if sessionID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	sessionURN := cosmoSessionURN(tenantID, sessionID)
	addEntity(entities, cosmoEntity(event, sessionURN, "cosmo.session", firstNonEmpty(attrs["ticket_id"], attrs["thread_key"], attrs["record_id"], sessionID), cosmoAttributes(attrs, map[string]string{
		"record_id":  attrs["record_id"],
		"ticket_id":  firstNonEmpty(attrs["ticket_id"], stringValue(payload, "ticket_id")),
		"thread_key": firstNonEmpty(attrs["thread_key"], stringValue(payload, "thread_key")),
		"user":       firstNonEmpty(attrs["user"], stringValue(payload, "user")),
		"agent_type": attrs["agent_type"],
		"status":     attrs["status"],
		"source":     attrs["source"],
	})))
	if user := firstNonEmpty(attrs["user"], stringValue(payload, "user")); user != "" {
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), sessionURN, user, event.GetOccurredAt())
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func cosmoFactProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	payload := payloadMap(event)
	factID := firstNonEmpty(attrs["key"], attrs["record_id"], stringValue(payload, "key"), stringValue(payload, "id"))
	if factID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	factURN := projectionURN(tenantID, "cosmo_fact", factID)
	addEntity(entities, cosmoEntity(event, factURN, "cosmo.fact", factID, cosmoAttributes(attrs, map[string]string{
		"record_id":  attrs["record_id"],
		"key":        firstNonEmpty(attrs["key"], stringValue(payload, "key")),
		"category":   attrs["category"],
		"source":     attrs["source"],
		"confidence": attrs["confidence"],
	})))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, nil)
	return projectedEntities, projectedLinks, nil
}

func cosmoMessageProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	payload := payloadMap(event)
	messageID := firstNonEmpty(attrs["record_id"], stringValue(payload, "id"))
	if messageID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	messageURN := projectionURN(tenantID, "cosmo_message", messageID)
	addEntity(entities, cosmoEntity(event, messageURN, "cosmo.message", firstNonEmpty(attrs["event_type"], attrs["role"], messageID), cosmoAttributes(attrs, map[string]string{
		"record_id":  attrs["record_id"],
		"ticket_id":  firstNonEmpty(attrs["ticket_id"], stringValue(payload, "ticket_id")),
		"event_type": attrs["event_type"],
		"role":       attrs["role"],
		"tool_name":  attrs["tool_name"],
		"agent_type": attrs["agent_type"],
		"run_url":    attrs["run_url"],
	})))
	addCosmoSessionLink(entities, links, event, tenantID, messageURN, firstNonEmpty(attrs["ticket_id"], stringValue(payload, "ticket_id")))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func cosmoSurveyFeedbackProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	payload := payloadMap(event)
	feedbackID := firstNonEmpty(attrs["record_id"], stringValue(payload, "key"))
	if feedbackID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	feedbackURN := projectionURN(tenantID, "cosmo_survey_feedback", feedbackID)
	addEntity(entities, cosmoEntity(event, feedbackURN, "cosmo.survey_feedback", firstNonEmpty(attrs["sentiment"], attrs["reaction"], feedbackID), cosmoAttributes(attrs, map[string]string{
		"record_id":        attrs["record_id"],
		"ticket_id":        firstNonEmpty(attrs["ticket_id"], stringValue(payload, "ticketId")),
		"channel":          attrs["channel"],
		"user_id":          firstNonEmpty(attrs["user_id"], stringValue(payload, "userId")),
		"reaction":         attrs["reaction"],
		"sentiment":        attrs["sentiment"],
		"workflow_run_url": attrs["workflow_run_url"],
	})))
	addCosmoSessionLink(entities, links, event, tenantID, feedbackURN, firstNonEmpty(attrs["ticket_id"], stringValue(payload, "ticketId")))
	if user := firstNonEmpty(attrs["user_id"], stringValue(payload, "userId")); user != "" {
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), feedbackURN, user, event.GetOccurredAt())
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func cosmoEntity(event *cerebrov1.EventEnvelope, urn string, entityType string, label string, attrs map[string]string) *ports.ProjectedEntity {
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   event.GetTenantId(),
		SourceID:   event.GetSourceId(),
		EntityType: entityType,
		Label:      firstNonEmpty(label, urn),
		Attributes: attrs,
	}
}

func cosmoAttributes(eventAttrs map[string]string, attrs map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range attrs {
		addProjectedAttribute(out, key, value)
	}
	for key, value := range eventAttrs {
		if strings.HasPrefix(key, "source_") {
			addProjectedAttribute(out, key, value)
		}
	}
	return out
}

func cosmoSessionURN(tenantID string, sessionID string) string {
	if strings.TrimSpace(sessionID) == "" {
		return ""
	}
	return projectionURN(tenantID, "cosmo_session", sessionID)
}

func addCosmoSessionLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, event *cerebrov1.EventEnvelope, tenantID string, fromURN string, sessionID string) {
	sessionURN := cosmoSessionURN(tenantID, sessionID)
	if sessionURN == "" {
		return
	}
	addEntity(entities, cosmoEntity(event, sessionURN, "cosmo.session", sessionID, map[string]string{"ticket_id": strings.TrimSpace(sessionID)}))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), fromURN, sessionURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
}
