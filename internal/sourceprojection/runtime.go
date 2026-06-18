package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func runtimeEvidenceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	isEvidenceCAS := runtimeEvidenceIsEvidenceCAS(event)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	evidenceID := firstNonEmpty(attributes["evidence_id"], event.GetId())
	evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
	resourceURN := firstNonEmpty(attributes["resource_urn"], attributes["workload_urn"])
	explicitResourceURN := resourceURN != ""
	resourceLinkStatusInput := strings.ToLower(strings.TrimSpace(attributes["resource_link_status"]))
	resourceUnresolved := strings.EqualFold(strings.TrimSpace(attributes["unresolved_resource_context"]), "true") || resourceLinkStatusInput == "missing"
	if resourceURN == "" && !isEvidenceCAS && !resourceUnresolved {
		resourceURN = projectionURN(tenantID, "runtime_"+normalizeCloudType(firstNonEmpty(attributes["resource_type"], "resource")), firstNonEmpty(attributes["resource_id"], attributes["resource_name"], evidenceID))
	}
	resourceLinkStatus := "missing"
	if resourceURN != "" && !resourceUnresolved && (!isEvidenceCAS || resourceLinkStatusInput == "linked") {
		resourceLinkStatus = "linked"
	}
	caseID := strings.TrimSpace(attributes["case_id"])
	caseURN := ""
	caseLinkStatus := "not_supplied"
	if caseID != "" {
		caseLinkStatusInput := strings.ToLower(strings.TrimSpace(attributes["case_link_status"]))
		caseLinkStatus = "missing"
		if strings.EqualFold(strings.TrimSpace(attributes["unresolved_case_context"]), "true") || caseLinkStatusInput == "missing" {
			caseLinkStatus = "missing"
		} else if !isEvidenceCAS || caseLinkStatusInput == "linked" {
			caseLinkStatus = "linked"
			caseURN = firstNonEmpty(attributes["case_urn"], projectionURN(tenantID, "case", caseID))
		}
	}
	evidenceLinkState := "linked"
	if resourceLinkStatus == "missing" || caseLinkStatus == "missing" {
		evidenceLinkState = "unresolved"
	}
	if evidenceURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        evidenceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "runtime.evidence",
			Label:      firstNonEmpty(attributes["evidence_type"], attributes["detector_id"], evidenceID),
			Attributes: map[string]string{
				"case_id":                       caseID,
				"case_link_status":              caseLinkStatus,
				"evidence_link_state":           evidenceLinkState,
				"confidence":                    strings.TrimSpace(attributes["confidence"]),
				"detector_id":                   strings.TrimSpace(attributes["detector_id"]),
				"evidence_cas_blocks_count":     strings.TrimSpace(attributes["evidence_cas_blocks_count"]),
				"evidence_cas_commit_id":        strings.TrimSpace(attributes["evidence_cas_commit_id"]),
				"evidence_cas_content_type":     strings.TrimSpace(attributes["evidence_cas_content_type"]),
				"evidence_cas_digest":           strings.TrimSpace(attributes["evidence_cas_digest"]),
				"evidence_cas_manifest_version": strings.TrimSpace(attributes["evidence_cas_manifest_version"]),
				"evidence_cas_merkle_root":      strings.TrimSpace(attributes["evidence_cas_merkle_root"]),
				"evidence_cas_ref_type":         strings.TrimSpace(attributes["evidence_cas_ref_type"]),
				"evidence_cas_size_bytes":       strings.TrimSpace(attributes["evidence_cas_size_bytes"]),
				"evidence_cas_uri":              strings.TrimSpace(attributes["evidence_cas_uri"]),
				"evidence_id":                   evidenceID,
				"evidence_type":                 strings.TrimSpace(attributes["evidence_type"]),
				"occurred_at":                   strings.TrimSpace(attributes["occurred_at"]),
				"observed_at":                   strings.TrimSpace(attributes["observed_at"]),
				"process_name":                  strings.TrimSpace(attributes["process_name"]),
				"request_id":                    strings.TrimSpace(attributes["request_id"]),
				"resource_link_status":          resourceLinkStatus,
				"resource_urn":                  strings.TrimSpace(attributes["resource_urn"]),
				"source_event_id":               strings.TrimSpace(attributes["source_event_id"]),
				"source_runtime_id":             strings.TrimSpace(attributes["source_runtime_id"]),
				"source_system":                 strings.TrimSpace(attributes["source_system"]),
				"tenant_id":                     tenantID,
				"trace_id":                      strings.TrimSpace(attributes["trace_id"]),
				"traceparent":                   strings.TrimSpace(attributes["traceparent"]),
				"unresolved_case_context":       strings.TrimSpace(attributes["unresolved_case_context"]),
				"unresolved_resource_context":   strings.TrimSpace(attributes["unresolved_resource_context"]),
				"verdict":                       strings.TrimSpace(attributes["verdict"]),
			},
		})
	}
	if resourceURN != "" && resourceLinkStatus == "linked" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: firstNonEmpty(attributes["resource_entity_type"], "runtime."+strings.ReplaceAll(normalizeCloudType(firstNonEmpty(attributes["resource_type"], "resource")), "_", ".")),
			Label:      firstNonEmpty(attributes["resource_name"], attributes["resource_id"], resourceURN),
			Attributes: map[string]string{"resource_id": strings.TrimSpace(attributes["resource_id"]), "resource_type": strings.TrimSpace(attributes["resource_type"])},
		})
	}
	if resourceURN != "" && resourceLinkStatus == "linked" && evidenceURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, evidenceURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), evidenceURN, resourceURN, relationObservedOn, map[string]string{"event_id": event.GetId()}))
	}
	if caseURN != "" && evidenceURN != "" && caseURN != resourceURN {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        caseURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "case",
			Label:      caseID,
			Attributes: map[string]string{"case_id": caseID},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), caseURN, evidenceURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), evidenceURN, caseURN, relationAssociatedWith, map[string]string{"event_id": event.GetId()}))
	}
	if findingID := strings.TrimSpace(attributes["finding_id"]); findingID != "" && evidenceURN != "" {
		findingURN := projectionURN(tenantID, "finding", findingID)
		addEntity(entities, &ports.ProjectedEntity{URN: findingURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "finding", Label: findingID})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), evidenceURN, findingURN, relationSupports, map[string]string{"event_id": event.GetId()}))
	}
	if isEvidenceCAS && !explicitResourceURN && resourceURN == "" {
		delete(entities, projectionURN(tenantID, "runtime_resource", evidenceID))
	}
	return identityProjectionResult(entities, links)
}

func runtimeEvidenceIsEvidenceCAS(event *cerebrov1.EventEnvelope) bool {
	if event == nil {
		return false
	}
	return strings.TrimSpace(event.GetKind()) == "evidence_cas.object" || strings.TrimSpace(event.GetSourceId()) == "evidence_cas"
}
