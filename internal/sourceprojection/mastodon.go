package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func mastodonAccountProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, identityProjectionProfile{Provider: "mastodon"})
}

func mastodonActivityProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, identityProjectionProfile{Provider: "mastodon"})
}

func mastodonVerifyCredentialProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return mastodonGenericSecretProjections(event)
}

func mastodonNotificationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return mastodonGenericAlertProjections(event)
}

func mastodonGenericSecretProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	secretID := firstNonEmpty(attributes["secret_id"], event.GetId())
	secretURN := projectionURN(tenantID, "secret", secretID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{URN: secretURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "secret", Label: firstNonEmpty(attributes["secret_name"], secretID), Attributes: map[string]string{"secret_id": secretID, "secret_type": strings.TrimSpace(attributes["secret_type"]), "secret_status": strings.TrimSpace(attributes["secret_status"]), "secret_rotation_enabled": strings.TrimSpace(attributes["secret_rotation_enabled"]), "secret_last_rotated_at": strings.TrimSpace(attributes["secret_last_rotated_at"]), "source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})
	if evidenceID := strings.TrimSpace(attributes["evidence_id"]); evidenceID != "" {
		evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
		addEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "runtime_evidence", Label: evidenceID, Attributes: map[string]string{"evidence_id": evidenceID, "evidence_cas_uri": strings.TrimSpace(attributes["evidence_cas_uri"]), "evidence_cas_digest": strings.TrimSpace(attributes["evidence_cas_digest"])}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), secretURN, evidenceURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
	}
	return identityProjectionResult(entities, links)
}

func mastodonGenericAlertProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	alertID := firstNonEmpty(attributes["alert_id"], event.GetId())
	alertURN := projectionURN(tenantID, "alert", alertID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{URN: alertURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "alert", Label: firstNonEmpty(attributes["alert_name"], alertID), Attributes: map[string]string{"alert_id": alertID, "alert_severity": strings.TrimSpace(attributes["alert_severity"]), "alert_status": strings.TrimSpace(attributes["alert_status"]), "alert_type": strings.TrimSpace(attributes["alert_type"]), "alert_source": strings.TrimSpace(attributes["alert_source"]), "alert_fired_at": strings.TrimSpace(attributes["alert_fired_at"]), "alert_resolved_at": strings.TrimSpace(attributes["alert_resolved_at"]), "source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})
	if evidenceID := strings.TrimSpace(attributes["evidence_id"]); evidenceID != "" {
		evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
		addEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "runtime_evidence", Label: evidenceID, Attributes: map[string]string{"evidence_id": evidenceID, "evidence_cas_uri": strings.TrimSpace(attributes["evidence_cas_uri"]), "evidence_cas_digest": strings.TrimSpace(attributes["evidence_cas_digest"])}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, evidenceURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
	}
	return identityProjectionResult(entities, links)
}
