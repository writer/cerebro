package sourceprojection

import (
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func addGRCVendorAssociationLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, provider string, attrs map[string]string) {
	vendorID := firstAttribute(attrs, "vendor_id", "third_party_id", "supplier_id")
	if fromURN == "" || vendorID == "" {
		return
	}
	vendorURN := projectionURN(tenantID, "vendor", provider, vendorID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        vendorURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "vendor",
		Label:      firstAttribute(attrs, "vendor_name", "third_party_name", "supplier_name", "vendor_id"),
		Attributes: grcAttributes(nil, map[string]string{"vendor_id": vendorID, "source_system": provider}),
	})
	addLink(links, projectedLink(tenantID, sourceID, fromURN, vendorURN, relationAssociatedWith, map[string]string{
		"event_id":   event.GetId(),
		"match_type": "grc_vendor_reference",
		"vendor_id":  vendorID,
	}))
}

func addGRCTargetReferenceLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, provider string, attrs map[string]string, relation string, relationshipBy string) {
	targetID := firstAttribute(attrs, "target_id", "resource_id", "asset_id", "service_id", "system_id")
	targetURN := grcTargetURN(tenantID, provider, targetID)
	if fromURN == "" || targetURN == "" {
		return
	}
	addEntity(entities, grcTargetEntity(tenantID, sourceID, targetURN, targetID, attrs, provider))
	addLink(links, projectedLink(tenantID, sourceID, fromURN, targetURN, relation, map[string]string{
		"event_id":         event.GetId(),
		"relationship":     relation,
		"relationship_by":  relationshipBy,
		"source_reference": "grc_target",
		"target_id":        targetID,
	}))
}

func addGRCEvidenceLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, provider string, attrs map[string]string) {
	evidenceID := firstAttribute(attrs, "evidence_id", "evidence_cas_id", "artifact_id")
	if evidenceID == "" {
		evidenceID = grcDerivedID(firstAttribute(attrs, "evidence_cas_uri", "cas_uri"))
	}
	if fromURN == "" || evidenceID == "" {
		return
	}
	evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        evidenceURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "runtime.evidence",
		Label:      firstAttribute(attrs, "evidence_type", "evidence_id", "artifact_id"),
		Attributes: grcAttributes(nil, map[string]string{
			"evidence_cas_uri": firstAttribute(attrs, "evidence_cas_uri", "cas_uri"),
			"evidence_id":      evidenceID,
			"evidence_type":    firstAttribute(attrs, "evidence_type", "artifact_type"),
			"resource_urn":     fromURN,
			"source_system":    provider,
			"tenant_id":        tenantID,
		}),
	})
	addLink(links, projectedLink(tenantID, sourceID, fromURN, evidenceURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
	addLink(links, projectedLink(tenantID, sourceID, evidenceURN, fromURN, relationObservedOn, map[string]string{"event_id": event.GetId()}))
}
