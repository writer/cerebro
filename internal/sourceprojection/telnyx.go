package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func telnyxCallEventProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, identityProjectionProfile{Provider: "telnyx"})
}

func telnyxBillingGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, identityProjectionProfile{Provider: "telnyx"})
}

func telnyxCredentialConnectionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return telnyxGenericSecretProjections(event)
}

func telnyxManagedAccountProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, identityProjectionProfile{Provider: "telnyx"})
}

func telnyxCallControlApplicationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return telnyxGenericPolicyProjections(event)
}

func telnyxNotificationChannelProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return telnyxGenericAlertProjections(event)
}

func telnyxDetailRecordsReportProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return telnyxGenericAssetProjections(event)
}

func telnyxNotificationEventProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, identityProjectionProfile{Provider: "telnyx"})
}

func telnyxNotificationEventConditionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, identityProjectionProfile{Provider: "telnyx"})
}

func telnyxWirelessConnectivityLogProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, identityProjectionProfile{Provider: "telnyx"})
}

func telnyxSimCardGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, identityProjectionProfile{Provider: "telnyx"})
}

func telnyxSimCardGroupActionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, identityProjectionProfile{Provider: "telnyx"})
}

func telnyxGenericAssetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["external_id"], event.GetId())
	resourceType := firstNonEmpty(attributes["resource_type"], attributes["schema"], "asset")
	resourceURN := firstNonEmpty(attributes["resource_urn"], projectionURN(tenantID, "runtime_"+normalizeCloudType(resourceType), resourceID))
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{URN: resourceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "runtime." + strings.ReplaceAll(normalizeCloudType(resourceType), "_", "."), Label: firstNonEmpty(attributes["resource_name"], resourceID), Attributes: map[string]string{"resource_id": resourceID, "resource_type": resourceType, "source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})
	if evidenceID := strings.TrimSpace(attributes["evidence_id"]); evidenceID != "" {
		evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
		addEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "runtime.evidence", Label: evidenceID, Attributes: map[string]string{"evidence_id": evidenceID, "evidence_cas_uri": strings.TrimSpace(attributes["evidence_cas_uri"]), "evidence_cas_digest": strings.TrimSpace(attributes["evidence_cas_digest"])}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, evidenceURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
	}
	return identityProjectionResult(entities, links)
}

func telnyxGenericSecretProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
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

func telnyxGenericPolicyProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	policyID := firstNonEmpty(attributes["policy_id"], event.GetId())
	policyURN := projectionURN(tenantID, "policy", policyID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{URN: policyURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "policy", Label: firstNonEmpty(attributes["policy_name"], policyID), Attributes: map[string]string{"policy_id": policyID, "policy_type": strings.TrimSpace(attributes["policy_type"]), "policy_status": strings.TrimSpace(attributes["policy_status"]), "policy_severity": strings.TrimSpace(attributes["policy_severity"]), "source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID])}})
	if evidenceID := strings.TrimSpace(attributes["evidence_id"]); evidenceID != "" {
		evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
		addEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "runtime_evidence", Label: evidenceID, Attributes: map[string]string{"evidence_id": evidenceID, "evidence_cas_uri": strings.TrimSpace(attributes["evidence_cas_uri"]), "evidence_cas_digest": strings.TrimSpace(attributes["evidence_cas_digest"])}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), policyURN, evidenceURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
	}
	return identityProjectionResult(entities, links)
}
func telnyxGenericAlertProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
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
