package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func addGRCAssuranceArtifactLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, artifactURN string, provider string, attrs map[string]string, targetRelation string, targetRelationshipBy string, urlMatchType string, artifactKind grcAssuranceArtifactKind, tagValues string) {
	if strings.TrimSpace(artifactURN) == "" {
		return
	}
	addGRCUserOwnerLink(entities, links, tenantID, sourceID, event, artifactURN, provider, firstAttribute(attrs, "owner_id", "reviewer_user_id", "assignee_user_id", "business_owner_user_id", "security_owner_user_id", "uploaded_by_user_id"))
	addGRCVendorAssociationLink(entities, links, tenantID, sourceID, event, artifactURN, provider, attrs)
	addGRCCustomerTrustAccountLink(entities, links, tenantID, sourceID, event, artifactURN, provider, attrs)
	if strings.TrimSpace(targetRelation) != "" {
		addGRCTargetReferenceLink(entities, links, tenantID, sourceID, event, artifactURN, provider, attrs, targetRelation, targetRelationshipBy)
	}
	addGRCControlSupportLinks(entities, links, tenantID, sourceID, event, artifactURN, provider)
	addGRCEvidenceLink(entities, links, tenantID, sourceID, event, artifactURN, provider, attrs)
	addInternetHostLink(entities, links, tenantID, sourceID, event, artifactURN, relationHasIdentifier, firstAttribute(attrs, "url", "document_url", "report_url", "artifact_url", "download_url", "external_url"), urlMatchType, "0.90")
	addGRCAssetTagLinks(entities, links, tenantID, sourceID, event, artifactURN, artifactKind.String(), tagValues)
}

func addGRCCustomerTrustAccountLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, provider string, attrs map[string]string) {
	accountID := firstAttribute(attrs, "customer_trust_account_id", "customer_account_id", "account_id")
	if strings.TrimSpace(fromURN) == "" || accountID == "" {
		return
	}
	accountURN := projectionURN(tenantID, "customer_trust_account", provider, accountID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        accountURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "customer_trust.account",
		Label:      firstAttribute(attrs, "customer_trust_account_name", "customer_account_name", "account_name", "customer_name", "customer_trust_account_id", "customer_account_id", "account_id"),
		Attributes: grcAttributes(nil, map[string]string{
			"account_id":                accountID,
			"customer_trust_account_id": accountID,
			"source_system":             provider,
		}),
	})
	addLink(links, projectedLink(tenantID, sourceID, fromURN, accountURN, relationAssociatedWith, map[string]string{
		"account_id":  accountID,
		"event_id":    event.GetId(),
		"match_type":  "grc_customer_trust_account_reference",
		"source_type": "customer_trust_account",
	}))
}

func firstGRCAttributeMatch(attrs map[string]string, keys ...string) (string, string) {
	for _, key := range keys {
		if value := strings.TrimSpace(attrs[key]); value != "" {
			return key, value
		}
	}
	return "", ""
}

func addGRCRelatedAssuranceArtifactLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, provider string, attrs map[string]string, currentKind grcAssuranceArtifactKind) {
	if strings.TrimSpace(fromURN) == "" {
		return
	}
	for _, kind := range grcAssuranceArtifactKinds {
		if kind == currentKind {
			continue
		}
		sourceReference, relatedID := firstGRCAttributeMatch(attrs, kind.candidateIDAttributes(currentKind)...)
		if relatedID == "" {
			continue
		}
		relatedURN := projectionURN(tenantID, kind.String(), provider, relatedID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        relatedURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: kind.entityType(),
			Label:      relatedID,
			Attributes: grcAttributes(nil, map[string]string{
				kind.idAttribute(): relatedID,
				"source_system":    provider,
			}),
		})
		addLink(links, projectedLink(tenantID, sourceID, fromURN, relatedURN, relationAssociatedWith, map[string]string{
			"event_id":         event.GetId(),
			"match_type":       kind.relatedMatchType(),
			"related_id":       relatedID,
			"related_family":   kind.String(),
			"source_reference": sourceReference,
		}))
	}
}

func addGRCPenetrationTestFindingLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, testURN string, provider string, attrs map[string]string) {
	if strings.TrimSpace(testURN) == "" {
		return
	}
	for _, findingID := range grcAttributeSequence(strings.Join([]string{attrs["finding_id"], attrs["finding_ids"]}, ",")) {
		findingURN := projectionURN(tenantID, "finding", findingID)
		if findingURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        findingURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: "finding",
			Label:      firstNonEmpty(firstAttribute(attrs, "finding_name"), findingID),
			Attributes: grcAttributes(nil, map[string]string{"finding_id": findingID, "source_system": provider}),
		})
		addLink(links, projectedLink(tenantID, sourceID, testURN, findingURN, relationAssociatedWith, map[string]string{
			"event_id":   event.GetId(),
			"finding_id": findingID,
			"match_type": "grc_penetration_test_finding",
		}))
	}
	for _, vulnerabilityID := range grcAttributeSequence(strings.Join([]string{attrs["vulnerability_id"], attrs["vulnerability_ids"]}, ",")) {
		referenceAttrs := grcProjectionAttrsWith(attrs, "vulnerability_id", vulnerabilityID)
		delete(referenceAttrs, "name")
		delete(referenceAttrs, "title")
		vulnerabilityURN := grcProviderVulnerabilityURN(tenantID, provider, vulnerabilityID)
		if vulnerabilityURN == "" {
			continue
		}
		addEntity(entities, grcProviderVulnerabilityEntity(tenantID, sourceID, vulnerabilityURN, provider, referenceAttrs))
		addLink(links, projectedLink(tenantID, sourceID, testURN, vulnerabilityURN, relationAssociatedWith, map[string]string{
			"event_id":         event.GetId(),
			"match_type":       "grc_penetration_test_vulnerability",
			"vulnerability_id": vulnerabilityID,
		}))
	}
}
