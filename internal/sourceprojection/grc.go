package sourceprojection

import (
	"encoding/json"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func grcFrameworkProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return grcPolicyLikeProjections(event, "framework", "framework_id", []string{"display_name", "name", "framework_id"})
}

func grcControlProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return grcPolicyLikeProjections(event, "control", "control_id", []string{"control_external_id", "name", "control_id"})
}

func grcPolicyProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return grcPolicyLikeProjections(event, "policy", "policy_id", []string{"name", "policy_id"})
}

func grcControlTestProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	testID := firstAttribute(attrs, "test_id", "external_id")
	if testID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	testURN := projectionURN(tenantID, "evidence", provider, "control_test", testID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        testURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "evidence",
		Label:      firstAttribute(attrs, "name", "test_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"evidence_type": "grc_control_test",
			"source_system": provider,
			"status":        firstAttribute(attrs, "status"),
		}),
	})
	addGRCControlSupportLinks(entities, links, tenantID, event.GetSourceId(), event, testURN, provider)
	addGRCUserOwnerLink(entities, links, tenantID, event.GetSourceId(), event, testURN, provider, firstAttribute(attrs, "owner_id"))
	addGRCIntegrationLinks(entities, links, tenantID, event.GetSourceId(), event, testURN, provider, firstAttribute(attrs, "integrations"), "grc_control_test")
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, testURN, "grc_category", firstAttribute(attrs, "category"))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func addGRCControlSupportLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, provider string) {
	if fromURN == "" {
		return
	}
	for _, controlRef := range grcControlReferences(event.GetAttributes()) {
		controlURN := projectionURN(tenantID, "policy", provider, "control", controlRef.id)
		if controlURN == "" {
			continue
		}
		if controlRef.externalID != "" || !controlRef.paired {
			controlAttrs := map[string]string{"control_id": controlRef.id, "policy_id": controlRef.id, "policy_type": "control", "source_system": provider}
			if controlRef.externalID != "" {
				controlAttrs["control_external_id"] = controlRef.externalID
			}
			addEntity(entities, &ports.ProjectedEntity{
				URN:        controlURN,
				TenantID:   tenantID,
				SourceID:   sourceID,
				EntityType: "policy",
				Label:      firstNonEmpty(controlRef.externalID, controlRef.id),
				Attributes: controlAttrs,
			})
		}
		addLink(links, projectedLink(tenantID, sourceID, fromURN, controlURN, relationSupports, map[string]string{"event_id": event.GetId()}))
	}
}

type grcControlReference struct {
	id         string
	externalID string
	paired     bool
}

func grcControlReferences(attrs map[string]string) []grcControlReference {
	if refs := grcPairedControlReferences(attrs["control_references"]); len(refs) > 0 {
		return refs
	}
	ids := grcAttributeList(attrs["control_id"] + "," + attrs["control_ids"])
	externalIDs := grcAttributeList(attrs["control_external_id"] + "," + attrs["control_external_ids"])
	if len(ids) == 0 {
		ids = externalIDs
	}
	refs := make([]grcControlReference, 0, len(ids))
	for index, id := range ids {
		ref := grcControlReference{id: id}
		if index < len(externalIDs) {
			ref.externalID = externalIDs[index]
		}
		refs = append(refs, ref)
	}
	return refs
}

func grcPairedControlReferences(raw string) []grcControlReference {
	refs := []grcControlReference{}
	seen := map[string]struct{}{}
	for _, item := range strings.Split(raw, ";") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		id, externalID, _ := strings.Cut(item, "=")
		ref := grcControlReference{id: strings.TrimSpace(id), externalID: strings.TrimSpace(externalID), paired: true}
		if ref.id == "" {
			ref.id = ref.externalID
		}
		if ref.id == "" {
			continue
		}
		key := ref.id + "\x00" + ref.externalID
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, ref)
	}
	return refs
}

func grcAttributeList(value string) []string {
	values := []string{}
	seen := map[string]struct{}{}
	for _, part := range strings.Split(value, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		values = append(values, trimmed)
		seen[trimmed] = struct{}{}
	}
	return values
}

func grcAttributeSequence(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t'
	})
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func grcJoinedAttributeValues(attrs map[string]string, keys ...string) string {
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		if value := strings.TrimSpace(attrs[key]); value != "" {
			values = append(values, value)
		}
	}
	return strings.Join(values, ",")
}

func stringAt(values []string, index int) string {
	if index < 0 || index >= len(values) {
		return ""
	}
	return values[index]
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func maxInt(values ...int) int {
	max := 0
	for _, value := range values {
		if value > max {
			max = value
		}
	}
	return max
}

type grcAssuranceArtifactKind string

const (
	grcAssuranceArtifactSecurityReview        grcAssuranceArtifactKind = "security_review"
	grcAssuranceArtifactSecurityQuestionnaire grcAssuranceArtifactKind = "security_questionnaire"
	grcAssuranceArtifactPenetrationTest       grcAssuranceArtifactKind = "penetration_test"
	grcAssuranceArtifactDocument              grcAssuranceArtifactKind = "assurance_document"
)

var grcAssuranceArtifactKinds = []grcAssuranceArtifactKind{
	grcAssuranceArtifactSecurityReview,
	grcAssuranceArtifactSecurityQuestionnaire,
	grcAssuranceArtifactPenetrationTest,
	grcAssuranceArtifactDocument,
}

func (kind grcAssuranceArtifactKind) String() string {
	return string(kind)
}

func (kind grcAssuranceArtifactKind) entityType() string {
	switch kind {
	case grcAssuranceArtifactSecurityReview:
		return "security.review"
	case grcAssuranceArtifactSecurityQuestionnaire:
		return "security.questionnaire"
	case grcAssuranceArtifactPenetrationTest:
		return "penetration.test"
	case grcAssuranceArtifactDocument:
		return "assurance.document"
	default:
		return ""
	}
}

func (kind grcAssuranceArtifactKind) idAttribute() string {
	switch kind {
	case grcAssuranceArtifactSecurityReview:
		return "security_review_id"
	case grcAssuranceArtifactSecurityQuestionnaire:
		return "security_questionnaire_id"
	case grcAssuranceArtifactPenetrationTest:
		return "penetration_test_id"
	case grcAssuranceArtifactDocument:
		return "assurance_document_id"
	default:
		return ""
	}
}

func (kind grcAssuranceArtifactKind) relatedIDAttributes() []string {
	switch kind {
	case grcAssuranceArtifactSecurityReview:
		return []string{"related_security_review_id", "security_review_id", "review_id"}
	case grcAssuranceArtifactSecurityQuestionnaire:
		return []string{"related_security_questionnaire_id", "security_questionnaire_id", "questionnaire_id"}
	case grcAssuranceArtifactPenetrationTest:
		return []string{"related_penetration_test_id", "penetration_test_id", "pentest_id"}
	case grcAssuranceArtifactDocument:
		return []string{"related_assurance_document_id", "assurance_document_id"}
	default:
		return nil
	}
}

func (kind grcAssuranceArtifactKind) candidateIDAttributes(currentKind grcAssuranceArtifactKind) []string {
	if kind == grcAssuranceArtifactDocument && currentKind == grcAssuranceArtifactSecurityQuestionnaire {
		return append(kind.relatedIDAttributes(), "document_id", "upload_id")
	}
	return kind.relatedIDAttributes()
}

func (kind grcAssuranceArtifactKind) relatedMatchType() string {
	if kind == "" {
		return ""
	}
	return "grc_related_" + kind.String()
}

func grcDocumentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	documentID := firstAttribute(attrs, "document_id", "external_id")
	if documentID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	documentURN := projectionURN(tenantID, "document", provider, documentID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        documentURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "document",
		Label:      firstAttribute(attrs, "title", "document_id"),
		Attributes: grcAttributes(attrs, map[string]string{"document_id": documentID, "source_system": provider}),
	})
	if ownerID := firstAttribute(attrs, "owner_id"); ownerID != "" {
		addGRCUserOwnerLink(entities, links, tenantID, event.GetSourceId(), event, documentURN, provider, ownerID)
	}
	addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, documentURN, relationHasIdentifier, firstAttribute(attrs, "url"), "grc_document_url_host", "0.9")
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, documentURN, "grc_category", firstAttribute(attrs, "category"))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcContractProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	contractID := firstAttribute(attrs, "contract_id", "external_id")
	if contractID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	contractURN := projectionURN(tenantID, "contract", provider, contractID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        contractURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "contract",
		Label:      firstAttribute(attrs, "name", "title", "vendor_name", "contract_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"contract_id":   contractID,
			"contract_type": firstAttribute(attrs, "contract_type", "agreement_type"),
			"source_system": provider,
			"status":        firstAttribute(attrs, "status"),
		}),
	})
	addGRCUserOwnerLink(entities, links, tenantID, event.GetSourceId(), event, contractURN, provider, firstAttribute(attrs, "owner_id", "business_owner_user_id"))
	addGRCVendorAssociationLink(entities, links, tenantID, event.GetSourceId(), event, contractURN, provider, attrs)
	addGRCTargetReferenceLink(entities, links, tenantID, event.GetSourceId(), event, contractURN, provider, attrs, relationAssociatedWith, "grc_contract")
	addGRCControlSupportLinks(entities, links, tenantID, event.GetSourceId(), event, contractURN, provider)
	addGRCEvidenceLink(entities, links, tenantID, event.GetSourceId(), event, contractURN, provider, attrs)
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, contractURN, "grc_contract_category", firstAttribute(attrs, "category"))
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, contractURN, "grc_contract_tag", strings.Join([]string{attrs["tags"], attrs["data_types"], attrs["jurisdictions"]}, ","))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcSecurityReviewProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	reviewID := firstAttribute(attrs, "security_review_id", "review_id", "assessment_id", "external_id")
	if reviewID == "" {
		reviewID = grcDerivedID(firstAttribute(attrs, "vendor_id", "third_party_id"), firstAttribute(attrs, "review_type", "assessment_type"), firstAttribute(attrs, "started_at", "completed_at", "created_at"))
	}
	if reviewID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	reviewKind := grcAssuranceArtifactSecurityReview
	reviewURN := projectionURN(tenantID, reviewKind.String(), provider, reviewID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        reviewURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: reviewKind.entityType(),
		Label:      firstAttribute(attrs, "name", "title", "review_type", "assessment_type", "security_review_id", "review_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"review_type":        firstAttribute(attrs, "review_type", "assessment_type"),
			"risk_level":         firstAttribute(attrs, "risk_level", "inherent_risk_level", "residual_risk_level"),
			"security_review_id": reviewID,
			"source_system":      provider,
			"status":             firstAttribute(attrs, "status", "review_status", "assessment_status"),
		}),
	})
	addGRCAssuranceArtifactLinks(entities, links, tenantID, event.GetSourceId(), event, reviewURN, provider, attrs, relationAssociatedWith, "grc_security_review", "grc_security_review_url_host", reviewKind,
		grcJoinedAttributeValues(attrs, "review_type", "assessment_type", "status", "review_status", "risk_level", "inherent_risk_level", "residual_risk_level"))
	addGRCRelatedAssuranceArtifactLinks(entities, links, tenantID, event.GetSourceId(), event, reviewURN, provider, attrs, reviewKind)
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcSecurityQuestionnaireProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	questionnaireID := firstAttribute(attrs, "security_questionnaire_id", "questionnaire_id", "external_id")
	if questionnaireID == "" {
		questionnaireID = grcDerivedID(firstAttribute(attrs, "customer_trust_account_id", "account_id", "vendor_id"), firstAttribute(attrs, "questionnaire_type"), firstAttribute(attrs, "submitted_at", "created_at"))
	}
	if questionnaireID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	questionnaireKind := grcAssuranceArtifactSecurityQuestionnaire
	questionnaireURN := projectionURN(tenantID, questionnaireKind.String(), provider, questionnaireID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        questionnaireURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: questionnaireKind.entityType(),
		Label:      firstAttribute(attrs, "name", "title", "questionnaire_type", "security_questionnaire_id", "questionnaire_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"questionnaire_type":        firstAttribute(attrs, "questionnaire_type", "assessment_type"),
			"security_questionnaire_id": questionnaireID,
			"source_system":             provider,
			"status":                    firstAttribute(attrs, "status", "questionnaire_status", "response_status"),
		}),
	})
	addGRCAssuranceArtifactLinks(entities, links, tenantID, event.GetSourceId(), event, questionnaireURN, provider, attrs, relationAssociatedWith, "grc_security_questionnaire", "grc_security_questionnaire_url_host", questionnaireKind,
		grcJoinedAttributeValues(attrs, "questionnaire_type", "assessment_type", "status", "questionnaire_status", "response_status"))
	addGRCRelatedAssuranceArtifactLinks(entities, links, tenantID, event.GetSourceId(), event, questionnaireURN, provider, attrs, questionnaireKind)
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcPenetrationTestProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	testID := firstAttribute(attrs, "penetration_test_id", "pentest_id", "test_id", "external_id")
	if testID == "" {
		testID = grcDerivedID(firstAttribute(attrs, "target_id", "resource_id", "asset_id", "system_id"), firstAttribute(attrs, "test_type", "assessment_type"), firstAttribute(attrs, "started_at", "completed_at"))
	}
	if testID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	testKind := grcAssuranceArtifactPenetrationTest
	testURN := projectionURN(tenantID, testKind.String(), provider, testID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        testURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: testKind.entityType(),
		Label:      firstAttribute(attrs, "name", "title", "test_type", "penetration_test_id", "pentest_id", "test_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"penetration_test_id": testID,
			"source_system":       provider,
			"status":              firstAttribute(attrs, "status", "test_status", "assessment_status"),
			"test_type":           firstAttribute(attrs, "test_type", "assessment_type"),
		}),
	})
	addGRCAssuranceArtifactLinks(entities, links, tenantID, event.GetSourceId(), event, testURN, provider, attrs, relationTargeted, "grc_penetration_test", "grc_penetration_test_url_host", testKind,
		grcJoinedAttributeValues(attrs, "test_type", "assessment_type", "status", "test_status", "scope", "severity"))
	addGRCPenetrationTestFindingLinks(entities, links, tenantID, event.GetSourceId(), event, testURN, provider, attrs)
	addGRCRelatedAssuranceArtifactLinks(entities, links, tenantID, event.GetSourceId(), event, testURN, provider, attrs, testKind)
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcAssuranceDocumentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	documentID := firstAttribute(attrs, "assurance_document_id", "document_id", "upload_id", "external_id")
	if documentID == "" {
		documentID = grcDerivedID(firstAttribute(attrs, "url", "document_url", "download_url"), firstAttribute(attrs, "title", "name"))
	}
	if documentID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	documentKind := grcAssuranceArtifactDocument
	documentURN := projectionURN(tenantID, documentKind.String(), provider, documentID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        documentURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: documentKind.entityType(),
		Label:      firstAttribute(attrs, "title", "name", "document_type", "assurance_document_id", "document_id", "upload_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"assurance_document_id": documentID,
			"document_type":         firstAttribute(attrs, "document_type", "artifact_type", "evidence_type"),
			"source_system":         provider,
			"status":                firstAttribute(attrs, "status", "upload_status", "review_status"),
		}),
	})
	addGRCAssuranceArtifactLinks(entities, links, tenantID, event.GetSourceId(), event, documentURN, provider, attrs, relationAssociatedWith, "grc_assurance_document", "grc_assurance_document_url_host", documentKind,
		grcJoinedAttributeValues(attrs, "document_type", "artifact_type", "evidence_type", "category", "status", "upload_status", "tags"))
	addGRCUserActionLink(entities, links, tenantID, event.GetSourceId(), event, provider, firstAttribute(attrs, "uploaded_by_user_id", "uploader_user_id"), documentURN, "uploaded")
	addGRCRelatedAssuranceArtifactLinks(entities, links, tenantID, event.GetSourceId(), event, documentURN, provider, attrs, documentKind)
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcDiscoveredVendorProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	discoveryID := firstAttribute(attrs, "discovered_vendor_id", "vendor_id", "external_id")
	if discoveryID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	discoveryURN := projectionURN(tenantID, "vendor_discovery", provider, discoveryID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        discoveryURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "vendor.discovery",
		Label:      firstAttribute(attrs, "name", "normalized_name", "discovered_vendor_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"discovered_vendor_id": discoveryID,
			"source_system":        provider,
			"status":               discoveredVendorStatus(attrs),
		}),
	})
	addVendorAliasLink(entities, links, tenantID, event.GetSourceId(), event, discoveryURN, firstAttribute(attrs, "name"), "grc_discovered_vendor_name", "0.90")
	addVendorAliasLink(entities, links, tenantID, event.GetSourceId(), event, discoveryURN, firstAttribute(attrs, "normalized_name"), "grc_discovered_vendor_normalized_name", "0.95")
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, discoveryURN, "vendor_category", firstAttribute(attrs, "category"))
	addGRCUserActionLink(entities, links, tenantID, event.GetSourceId(), event, provider, firstAttribute(attrs, "ignored_by_user_id"), discoveryURN, "ignored")
	addGRCUserActionLink(entities, links, tenantID, event.GetSourceId(), event, provider, firstAttribute(attrs, "rejected_by_user_id"), discoveryURN, "rejected")
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcEventLogProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	eventLogID := firstAttribute(attrs, "event_log_id", "external_id")
	if eventLogID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	eventURN := projectionURN(tenantID, "grc_audit_event", provider, eventLogID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        eventURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "audit.event",
		Label:      firstAttribute(attrs, "action", "event_log_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"action":        firstAttribute(attrs, "action"),
			"event_log_id":  eventLogID,
			"source_system": provider,
		}),
	})
	if actorURN := grcEventActorURN(tenantID, provider, attrs); actorURN != "" {
		addEntity(entities, grcEventActorEntity(tenantID, event.GetSourceId(), actorURN, provider, attrs))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, eventURN, relationActedOn, map[string]string{
			"action":     firstAttribute(attrs, "action"),
			"actor_id":   firstAttribute(attrs, "actor_id"),
			"actor_type": grcEventActorType(attrs),
			"event_id":   event.GetId(),
		}))
	}
	for _, target := range grcEventTargets(attrs["targets"]) {
		targetURN := projectionURN(tenantID, "grc_audit_target", provider, target.typ, target.id)
		if targetURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        targetURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "audit.target",
			Label:      eventActorLabel(target.typ, target.id),
			Attributes: grcAttributes(nil, map[string]string{
				"source_system": provider,
				"target_id":     target.id,
				"target_type":   target.typ,
			}),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), eventURN, targetURN, relationObservedOn, map[string]string{
			"action":      firstAttribute(attrs, "action"),
			"event_id":    event.GetId(),
			"match_type":  "grc_audit_event_target",
			"target_id":   target.id,
			"target_type": target.typ,
		}))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	groupID := firstAttribute(attrs, "group_id", "external_id")
	if groupID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	groupURN := projectionURN(tenantID, "grc_group", provider, groupID)
	entities := map[string]*ports.ProjectedEntity{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        groupURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "group",
		Label:      firstAttribute(attrs, "group_name", "name", "group_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"group_id":      groupID,
			"group_name":    firstAttribute(attrs, "group_name", "name"),
			"source_system": provider,
		}),
	})
	projectedEntities, projectedLinks := entitiesAndLinks(entities, nil)
	return projectedEntities, projectedLinks, nil
}

func grcVendorRiskAttributeProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	attributeID := firstAttribute(attrs, "vendor_risk_attribute_id", "external_id")
	if attributeID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	attributeURN := projectionURN(tenantID, "vendor_risk_attribute", provider, attributeID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        attributeURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "vendor.risk_attribute",
		Label:      firstAttribute(attrs, "name", "vendor_risk_attribute_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"enabled":                  firstAttribute(attrs, "enabled"),
			"risk_level":               firstAttribute(attrs, "risk_level"),
			"source_system":            provider,
			"vendor_risk_attribute_id": attributeID,
		}),
	})
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, attributeURN, "vendor_category", firstAttribute(attrs, "vendor_categories"))
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, attributeURN, "vendor_risk_level", firstAttribute(attrs, "risk_level"))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcRegulatoryNotificationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	notificationID := firstAttribute(attrs, "notification_id", "external_id")
	if notificationID == "" {
		notificationID = grcDerivedID(firstAttribute(attrs, "framework"), firstAttribute(attrs, "incident_id", "case_id"), firstAttribute(attrs, "notification_type", "report_type"))
	}
	if notificationID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	notificationURN := projectionURN(tenantID, "regulatory_notification", provider, notificationID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        notificationURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "regulatory.notification",
		Label:      firstAttribute(attrs, "title", "notification_type", "report_type", "notification_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"incident_id":       firstAttribute(attrs, "incident_id", "case_id"),
			"notification_id":   notificationID,
			"notification_type": firstAttribute(attrs, "notification_type", "report_type"),
			"source_system":     provider,
			"status":            firstAttribute(attrs, "status", "notification_status"),
		}),
	})
	if incidentID := firstAttribute(attrs, "incident_id", "case_id"); incidentID != "" {
		incidentURN := projectionURN(tenantID, "incident", provider, incidentID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        incidentURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "incident",
			Label:      firstAttribute(attrs, "incident_title", "incident_name", "incident_id", "case_id"),
			Attributes: grcAttributes(nil, map[string]string{"incident_id": incidentID, "source_system": provider}),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), notificationURN, incidentURN, relationObservedOn, map[string]string{"event_id": event.GetId()}))
	}
	addGRCUserOwnerLink(entities, links, tenantID, event.GetSourceId(), event, notificationURN, provider, firstAttribute(attrs, "owner_id"))
	addGRCControlSupportLinks(entities, links, tenantID, event.GetSourceId(), event, notificationURN, provider)
	addGRCEvidenceLink(entities, links, tenantID, event.GetSourceId(), event, notificationURN, provider, attrs)
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, notificationURN, "regulatory_notification", strings.Join([]string{attrs["framework"], attrs["regulator"], attrs["notification_type"], attrs["report_type"]}, ","))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcRecoveryObjectiveProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	objectiveID := firstAttribute(attrs, "recovery_objective_id", "objective_id", "bia_id", "external_id")
	if objectiveID == "" {
		objectiveID = grcDerivedID(firstAttribute(attrs, "service_id", "target_id", "resource_id", "asset_id"), firstAttribute(attrs, "business_process"), firstAttribute(attrs, "rto_minutes"), firstAttribute(attrs, "rpo_minutes"))
	}
	if objectiveID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	objectiveURN := projectionURN(tenantID, "resilience_recovery_objective", provider, objectiveID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        objectiveURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "resilience.recovery_objective",
		Label:      firstAttribute(attrs, "name", "business_process", "service_id", "objective_id", "recovery_objective_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"recovery_objective_id": objectiveID,
			"source_system":         provider,
			"status":                firstAttribute(attrs, "status"),
		}),
	})
	if processName := firstAttribute(attrs, "business_process", "process_name"); processName != "" {
		processID := grcDerivedID(processName)
		processURN := projectionURN(tenantID, "business_process", provider, processID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        processURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "business.process",
			Label:      processName,
			Attributes: grcAttributes(nil, map[string]string{"business_process": processName, "source_system": provider}),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), objectiveURN, processURN, relationSupports, map[string]string{"event_id": event.GetId()}))
	}
	addGRCUserOwnerLink(entities, links, tenantID, event.GetSourceId(), event, objectiveURN, provider, firstAttribute(attrs, "owner_id"))
	addGRCTargetReferenceLink(entities, links, tenantID, event.GetSourceId(), event, objectiveURN, provider, attrs, relationTargeted, "grc_recovery_objective")
	addGRCControlSupportLinks(entities, links, tenantID, event.GetSourceId(), event, objectiveURN, provider)
	addGRCEvidenceLink(entities, links, tenantID, event.GetSourceId(), event, objectiveURN, provider, attrs)
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, objectiveURN, "resilience_tier", strings.Join([]string{attrs["impact_tier"], attrs["criticality"], attrs["recovery_priority"]}, ","))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcAuthorizationPackageProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	packageID := firstAttribute(attrs, "authorization_package_id", "package_id", "ato_id", "ssp_id", "external_id")
	if packageID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	packageURN := projectionURN(tenantID, "authorization_package", provider, packageID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        packageURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "authorization.package",
		Label:      firstAttribute(attrs, "name", "system_name", "package_name", "package_id", "authorization_package_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"authorization_package_id": packageID,
			"framework":                firstAttribute(attrs, "framework"),
			"impact_level":             firstAttribute(attrs, "impact_level"),
			"source_system":            provider,
			"status":                   firstAttribute(attrs, "status", "authorization_status"),
		}),
	})
	addGRCUserOwnerLink(entities, links, tenantID, event.GetSourceId(), event, packageURN, provider, firstAttribute(attrs, "owner_id", "system_owner_user_id"))
	addGRCTargetReferenceLink(entities, links, tenantID, event.GetSourceId(), event, packageURN, provider, attrs, relationTargeted, "grc_authorization_package")
	addGRCControlSupportLinks(entities, links, tenantID, event.GetSourceId(), event, packageURN, provider)
	addGRCEvidenceLink(entities, links, tenantID, event.GetSourceId(), event, packageURN, provider, attrs)
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, packageURN, "authorization_package", strings.Join([]string{attrs["framework"], attrs["impact_level"], attrs["status"], attrs["authorization_status"]}, ","))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcPOAMItemProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	itemID := firstAttribute(attrs, "poam_item_id", "weakness_id", "finding_id", "external_id")
	if itemID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	itemURN := projectionURN(tenantID, "poam_item", provider, itemID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        itemURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "poam.item",
		Label:      firstAttribute(attrs, "title", "weakness_name", "finding_name", "poam_item_id", "weakness_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"poam_item_id":  itemID,
			"risk_rating":   firstAttribute(attrs, "risk_rating", "severity"),
			"source_system": provider,
			"status":        firstAttribute(attrs, "status"),
			"weakness_id":   firstAttribute(attrs, "weakness_id"),
		}),
	})
	if findingID := firstAttribute(attrs, "finding_id"); findingID != "" {
		findingURN := projectionURN(tenantID, "finding", findingID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        findingURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "finding",
			Label:      firstAttribute(attrs, "finding_name", "title", "finding_id"),
			Attributes: grcAttributes(nil, map[string]string{"finding_id": findingID, "source_system": provider}),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), itemURN, findingURN, relationAssociatedWith, map[string]string{"event_id": event.GetId()}))
	}
	addGRCUserOwnerLink(entities, links, tenantID, event.GetSourceId(), event, itemURN, provider, firstAttribute(attrs, "owner_id"))
	addGRCTargetReferenceLink(entities, links, tenantID, event.GetSourceId(), event, itemURN, provider, attrs, relationTargeted, "grc_poam_item")
	addGRCControlSupportLinks(entities, links, tenantID, event.GetSourceId(), event, itemURN, provider)
	addGRCEvidenceLink(entities, links, tenantID, event.GetSourceId(), event, itemURN, provider, attrs)
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, itemURN, "poam_risk", strings.Join([]string{attrs["risk_rating"], attrs["severity"], attrs["status"]}, ","))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcTrainingAttestationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	attestationID := firstAttribute(attrs, "attestation_id", "training_attestation_id", "external_id")
	if attestationID == "" {
		attestationID = grcDerivedID(firstAttribute(attrs, "person_id", "user_id", "email"), firstAttribute(attrs, "course_id", "training_type"), firstAttribute(attrs, "completed_at", "expires_at"))
	}
	if attestationID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	attestationURN := projectionURN(tenantID, "training_attestation", provider, attestationID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        attestationURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "training.attestation",
		Label:      firstAttribute(attrs, "course_name", "training_type", "course_id", "attestation_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"attestation_id": attestationID,
			"source_system":  provider,
			"status":         firstAttribute(attrs, "status"),
		}),
	})
	if personID := firstAttribute(attrs, "person_id"); personID != "" {
		personURN := projectionURN(tenantID, "person", provider, personID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        personURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "person",
			Label:      firstAttribute(attrs, "person_name", "email", "person_id"),
			Attributes: grcAttributes(nil, map[string]string{"person_id": personID, "source_system": provider}),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), personURN, attestationURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), attestationURN, personURN, relationObservedOn, map[string]string{"event_id": event.GetId()}))
	}
	if userID := firstAttribute(attrs, "user_id"); userID != "" {
		userURN := grcUserURN(tenantID, provider, userID)
		addEntity(entities, grcUserEntity(tenantID, event.GetSourceId(), userURN, firstAttribute(attrs, "display_name", "email", "user_id"), grcAttributes(nil, map[string]string{"user_id": userID, "source_system": provider})))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), userURN, attestationURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), attestationURN, userURN, relationObservedOn, map[string]string{"event_id": event.GetId()}))
	}
	addGRCControlSupportLinks(entities, links, tenantID, event.GetSourceId(), event, attestationURN, provider)
	addGRCEvidenceLink(entities, links, tenantID, event.GetSourceId(), event, attestationURN, provider, attrs)
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, attestationURN, "training_type", firstAttribute(attrs, "training_type", "course_type"))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcVendorProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	vendorID := firstAttribute(attrs, "vendor_id", "external_id")
	if vendorID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	vendorURN := projectionURN(tenantID, "vendor", provider, vendorID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        vendorURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "vendor",
		Label:      firstAttribute(attrs, "name", "vendor_id"),
		Attributes: grcAttributes(attrs, map[string]string{"vendor_id": vendorID, "source_system": provider}),
	})
	addVendorAliasLink(entities, links, tenantID, event.GetSourceId(), event, vendorURN, firstAttribute(attrs, "name"), "grc_vendor_name_alias", "0.90")
	addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, vendorURN, relationHasIdentifier, firstAttribute(attrs, "website_url", "website", "url", "domain"), "grc_vendor_website_host", "0.95")
	for _, ownerID := range []string{firstAttribute(attrs, "security_owner_user_id"), firstAttribute(attrs, "business_owner_user_id")} {
		if ownerID == "" {
			continue
		}
		ownerURN := grcUserURN(tenantID, provider, ownerID)
		addEntity(entities, grcUserEntity(tenantID, event.GetSourceId(), ownerURN, ownerID, map[string]string{"user_id": ownerID, "source_system": provider}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), vendorURN, ownerURN, relationOwnedBy, map[string]string{"event_id": event.GetId()}))
	}
	addSecurityContactEmailLink(entities, links, tenantID, event.GetSourceId(), event, vendorURN, firstAttribute(attrs, "account_manager_email", "security_contact_email", "contact_email"), "account_manager")
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcVulnerabilityProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	vulnerabilityURN := addCanonicalVulnerabilityEntity(entities, tenantID, event.GetSourceId(), attrs)
	if vulnerabilityURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        vulnerabilityURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "vulnerability",
			Label:      firstAttribute(attrs, "name", "vulnerability_id"),
			Attributes: map[string]string{"source_system": provider},
		})
	}
	integrationID := firstAttribute(attrs, "integration_id")
	integrationURN := grcIntegrationURN(tenantID, provider, integrationID)
	if integrationURN != "" {
		addEntity(entities, grcIntegrationReferenceEntity(tenantID, event.GetSourceId(), integrationURN, integrationID, provider))
	}
	targetID := firstAttribute(attrs, "target_id", "resource_id", "asset_id", "endpoint_id")
	targetURN := grcTargetURN(tenantID, provider, targetID)
	if targetURN != "" {
		addEntity(entities, grcTargetEntity(tenantID, event.GetSourceId(), targetURN, targetID, attrs, provider))
		addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, targetURN, relationRepresents, grcTargetHost(attrs), "grc_target_host", "0.95")
		if vulnerabilityURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, vulnerabilityURN, relationAffectedBy, vulnerabilityEvidenceAttributes(event, attrs)))
		}
		if integrationURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, integrationURN, relationBelongsTo, grcIntegrationLinkAttributes(event, integrationID)))
		}
	}
	packageURN := vulnerabilityPackageURN(tenantID, attrs, "grc")
	canonicalPackageURN := addCanonicalPackageEntity(entities, tenantID, event.GetSourceId(), attrs, "grc")
	if packageURN != "" {
		addVulnerablePackageEntity(entities, tenantID, event.GetSourceId(), packageURN, attrs, "grc")
		if targetURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, packageURN, relationContains, grcPackageTargetAttributes(event, attrs)))
		}
		if vulnerabilityURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, vulnerabilityURN, relationAffectedBy, vulnerabilityEvidenceAttributes(event, attrs)))
		}
	}
	if packageURN != "" && canonicalPackageURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, canonicalPackageURN, relationRepresents, packageIdentityAttributes(event, attrs, "grc")))
	}
	if canonicalPackageURN != "" && vulnerabilityURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), canonicalPackageURN, vulnerabilityURN, relationAffectedBy, vulnerabilityEvidenceAttributes(event, attrs)))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcVulnerabilityRemediationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	remediationID := firstAttribute(attrs, "remediation_id", "external_id")
	if remediationID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	remediationURN := projectionURN(tenantID, "vulnerability_remediation", provider, remediationID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        remediationURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "vulnerability.remediation",
		Label:      firstAttribute(attrs, "name", "title", "remediation_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"remediation_id":      remediationID,
			"severity":            firstAttribute(attrs, "severity"),
			"source_system":       provider,
			"status":              remediationStatus(attrs),
			"vulnerability_id":    firstAttribute(attrs, "vulnerability_id"),
			"vulnerable_asset_id": firstAttribute(attrs, "vulnerable_asset_id", "asset_id", "target_id"),
		}),
	})
	vulnerabilityURN := grcProviderVulnerabilityURN(tenantID, provider, firstAttribute(attrs, "vulnerability_id"))
	if vulnerabilityURN != "" {
		addEntity(entities, grcProviderVulnerabilityEntity(tenantID, event.GetSourceId(), vulnerabilityURN, provider, attrs))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), remediationURN, vulnerabilityURN, relationAssociatedWith, map[string]string{
			"event_id":         event.GetId(),
			"match_type":       "grc_vulnerability_remediation",
			"vulnerability_id": firstAttribute(attrs, "vulnerability_id"),
		}))
	}
	if canonicalURN := addCanonicalVulnerabilityEntity(entities, tenantID, event.GetSourceId(), attrs); canonicalURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), remediationURN, canonicalURN, relationAssociatedWith, map[string]string{
			"event_id":   event.GetId(),
			"match_type": "grc_vulnerability_remediation_canonical",
		}))
		if vulnerabilityURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), vulnerabilityURN, canonicalURN, relationRepresents, map[string]string{
				"event_id":   event.GetId(),
				"match_type": "grc_vulnerability_identifier",
			}))
		}
	}
	targetID := firstAttribute(attrs, "vulnerable_asset_id", "asset_id", "target_id")
	targetURN := grcTargetURN(tenantID, provider, targetID)
	if targetURN != "" {
		addEntity(entities, grcTargetEntity(tenantID, event.GetSourceId(), targetURN, targetID, attrs, provider))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), remediationURN, targetURN, relationTargeted, map[string]string{
			"event_id":   event.GetId(),
			"match_type": "grc_vulnerability_remediation_target",
			"target_id":  targetID,
		}))
		if vulnerabilityURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, vulnerabilityURN, relationAffectedBy, map[string]string{
				"event_id":         event.GetId(),
				"severity":         firstAttribute(attrs, "severity"),
				"vulnerability_id": firstAttribute(attrs, "vulnerability_id"),
			}))
		}
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcVulnerableAssetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	targetID := firstAttribute(attrs, "target_id", "asset_id", "resource_id", "endpoint_id", "external_id")
	targetURN := grcTargetURN(tenantID, provider, targetID)
	if targetURN == "" {
		return nil, nil, nil
	}
	addEntity(entities, grcTargetEntity(tenantID, event.GetSourceId(), targetURN, targetID, attrs, provider))
	for _, host := range grcTargetHosts(attrs) {
		addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, targetURN, relationRepresents, host, "grc_vulnerable_asset_host", "0.95")
	}
	for _, ip := range grcTargetIPs(attrs) {
		addInternetIPLink(entities, links, tenantID, event.GetSourceId(), event, targetURN, ip, "grc_vulnerable_asset_ip", "0.95")
	}
	addGRCPlatformAssetLinks(entities, links, tenantID, event.GetSourceId(), event, targetURN, attrs)

	integrationID := firstAttribute(attrs, "integration_id")
	if integrationURN := grcIntegrationURN(tenantID, provider, integrationID); integrationURN != "" {
		addEntity(entities, grcIntegrationReferenceEntity(tenantID, event.GetSourceId(), integrationURN, integrationID, provider))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, integrationURN, relationBelongsTo, grcIntegrationLinkAttributes(event, integrationID)))
	}

	referenceAttrsList := grcVulnerableAssetReferenceAttrs(attrs)
	if len(referenceAttrsList) > 0 {
		for _, referenceAttrs := range referenceAttrsList {
			vulnerabilityURN := addCanonicalVulnerabilityEntity(entities, tenantID, event.GetSourceId(), referenceAttrs)
			if vulnerabilityURN != "" {
				addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, vulnerabilityURN, relationAffectedBy, vulnerabilityEvidenceAttributes(event, referenceAttrs)))
			}
			for _, packageAttrs := range grcVulnerableAssetPackageAttrs(referenceAttrs) {
				packageURN := vulnerabilityPackageURN(tenantID, packageAttrs, "grc")
				canonicalPackageURN := addCanonicalPackageEntity(entities, tenantID, event.GetSourceId(), packageAttrs, "grc")
				if packageURN != "" {
					addVulnerablePackageEntity(entities, tenantID, event.GetSourceId(), packageURN, packageAttrs, "grc")
					addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, packageURN, relationContains, grcPackageTargetAttributes(event, packageAttrs)))
					if vulnerabilityURN != "" {
						addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, vulnerabilityURN, relationAffectedBy, vulnerabilityEvidenceAttributes(event, packageAttrs)))
					}
				}
				if packageURN != "" && canonicalPackageURN != "" {
					addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, canonicalPackageURN, relationRepresents, packageIdentityAttributes(event, packageAttrs, "grc")))
				}
				if canonicalPackageURN != "" && vulnerabilityURN != "" {
					addLink(links, projectedLink(tenantID, event.GetSourceId(), canonicalPackageURN, vulnerabilityURN, relationAffectedBy, vulnerabilityEvidenceAttributes(event, packageAttrs)))
				}
			}
		}
		projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
		return projectedEntities, projectedLinks, nil
	}

	for _, vulnerabilityAttrs := range grcVulnerableAssetVulnerabilityAttrs(attrs) {
		vulnerabilityURN := addCanonicalVulnerabilityEntity(entities, tenantID, event.GetSourceId(), vulnerabilityAttrs)
		if vulnerabilityURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, vulnerabilityURN, relationAffectedBy, vulnerabilityEvidenceAttributes(event, vulnerabilityAttrs)))
		}
	}
	for _, packageAttrs := range grcVulnerableAssetPackageAttrs(attrs) {
		packageURN := vulnerabilityPackageURN(tenantID, packageAttrs, "grc")
		canonicalPackageURN := addCanonicalPackageEntity(entities, tenantID, event.GetSourceId(), packageAttrs, "grc")
		if packageURN != "" {
			addVulnerablePackageEntity(entities, tenantID, event.GetSourceId(), packageURN, packageAttrs, "grc")
			addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, packageURN, relationContains, grcPackageTargetAttributes(event, packageAttrs)))
		}
		if packageURN != "" && canonicalPackageURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, canonicalPackageURN, relationRepresents, packageIdentityAttributes(event, packageAttrs, "grc")))
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcVulnerableAssetReferenceAttrs(attrs map[string]string) []map[string]string {
	rawReferences := strings.TrimSpace(attrs["vulnerability_package_refs"])
	if rawReferences == "" {
		return grcVulnerableAssetFlatReferenceAttrs(attrs)
	}
	var references []struct {
		VulnerabilityID   string `json:"vulnerability_id"`
		VulnerabilityName string `json:"vulnerability_name"`
		PackageIdentifier string `json:"package_identifier"`
	}
	if err := json.Unmarshal([]byte(rawReferences), &references); err != nil {
		return grcVulnerableAssetFlatReferenceAttrs(attrs)
	}
	vulnerabilityIDs := grcAttributeSequence(attrs["vulnerability_ids"])
	vulnerabilityNames := grcAttributeSequence(attrs["vulnerability_names"])
	packageIdentifiers := grcAttributeSequence(attrs["package_identifiers"])
	result := make([]map[string]string, 0, len(references))
	for i, reference := range references {
		referenceAttrs := grcVulnerableAssetCleanReferenceAttrs(attrs)
		if vulnerabilityID := firstNonEmptyString(reference.VulnerabilityID, stringAt(vulnerabilityIDs, i)); vulnerabilityID != "" {
			referenceAttrs["vulnerability_id"] = vulnerabilityID
		}
		if vulnerabilityName := firstNonEmptyString(reference.VulnerabilityName, stringAt(vulnerabilityNames, i)); vulnerabilityName != "" {
			referenceAttrs["name"] = vulnerabilityName
		}
		if packageIdentifier := firstNonEmptyString(reference.PackageIdentifier, stringAt(packageIdentifiers, i)); packageIdentifier != "" {
			referenceAttrs["package"] = packageIdentifier
			referenceAttrs["package_purl"] = packageIdentifier
		}
		result = append(result, referenceAttrs)
	}
	for i := len(references); i < maxInt(len(vulnerabilityIDs), len(vulnerabilityNames), len(packageIdentifiers)); i++ {
		referenceAttrs := grcVulnerableAssetCleanReferenceAttrs(attrs)
		if vulnerabilityID := stringAt(vulnerabilityIDs, i); vulnerabilityID != "" {
			referenceAttrs["vulnerability_id"] = vulnerabilityID
		}
		if vulnerabilityName := stringAt(vulnerabilityNames, i); vulnerabilityName != "" {
			referenceAttrs["name"] = vulnerabilityName
		}
		if packageIdentifier := stringAt(packageIdentifiers, i); packageIdentifier != "" {
			referenceAttrs["package"] = packageIdentifier
			referenceAttrs["package_purl"] = packageIdentifier
		}
		result = append(result, referenceAttrs)
	}
	if len(result) == 0 {
		return grcVulnerableAssetFlatReferenceAttrs(attrs)
	}
	return result
}

func grcVulnerableAssetFlatReferenceAttrs(attrs map[string]string) []map[string]string {
	vulnerabilityIDs := grcAttributeSequence(attrs["vulnerability_ids"])
	vulnerabilityNames := grcAttributeSequence(attrs["vulnerability_names"])
	packageIdentifiers := grcAttributeSequence(attrs["package_identifiers"])
	if (len(vulnerabilityIDs) == 0 && len(vulnerabilityNames) == 0) || len(packageIdentifiers) == 0 {
		return nil
	}
	total := maxInt(len(vulnerabilityIDs), len(vulnerabilityNames), len(packageIdentifiers))
	result := make([]map[string]string, 0, total)
	for i := 0; i < total; i++ {
		referenceAttrs := grcVulnerableAssetCleanReferenceAttrs(attrs)
		if vulnerabilityID := stringAt(vulnerabilityIDs, i); vulnerabilityID != "" {
			referenceAttrs["vulnerability_id"] = vulnerabilityID
		}
		if vulnerabilityName := stringAt(vulnerabilityNames, i); vulnerabilityName != "" {
			referenceAttrs["name"] = vulnerabilityName
		}
		if packageIdentifier := stringAt(packageIdentifiers, i); packageIdentifier != "" {
			referenceAttrs["package"] = packageIdentifier
			referenceAttrs["package_purl"] = packageIdentifier
		}
		result = append(result, referenceAttrs)
	}
	return result
}

func grcVulnerableAssetCleanReferenceAttrs(attrs map[string]string) map[string]string {
	referenceAttrs := grcProjectionAttrsWith(attrs)
	for _, key := range []string{
		"cve_id",
		"ghsa_id",
		"identifier",
		"name",
		"package",
		"package_identifiers",
		"package_purl",
		"title",
		"vulnerability_id",
		"vulnerability_ids",
		"vulnerability_names",
		"vulnerability_package_refs",
	} {
		delete(referenceAttrs, key)
	}
	return referenceAttrs
}

func grcVulnerableAssetVulnerabilityAttrs(attrs map[string]string) []map[string]string {
	vulnerabilityIDs := grcAttributeSequence(attrs["vulnerability_ids"])
	vulnerabilityNames := grcAttributeSequence(attrs["vulnerability_names"])
	if len(vulnerabilityIDs) == 0 && len(vulnerabilityNames) == 0 && canonicalVulnerabilityIdentifier(attrs) != "" {
		return []map[string]string{attrs}
	}
	total := maxInt(len(vulnerabilityIDs), len(vulnerabilityNames))
	result := make([]map[string]string, 0, total)
	for i := 0; i < total; i++ {
		referenceAttrs := grcVulnerableAssetCleanReferenceAttrs(attrs)
		if vulnerabilityID := stringAt(vulnerabilityIDs, i); vulnerabilityID != "" {
			referenceAttrs["vulnerability_id"] = vulnerabilityID
		}
		if vulnerabilityName := stringAt(vulnerabilityNames, i); vulnerabilityName != "" {
			referenceAttrs["name"] = vulnerabilityName
		}
		if canonicalVulnerabilityIdentifier(referenceAttrs) != "" {
			result = append(result, referenceAttrs)
		}
	}
	return result
}

func grcVulnerableAssetPackageAttrs(attrs map[string]string) []map[string]string {
	packages := grcAttributeList(strings.Join([]string{attrs["package_identifiers"], attrs["package"], attrs["package_purl"]}, ","))
	if len(packages) == 0 && vulnerablePackageName(attrs) != "" {
		return []map[string]string{attrs}
	}
	result := make([]map[string]string, 0, len(packages))
	for _, pkg := range packages {
		result = append(result, grcProjectionAttrsWith(attrs, "package", pkg, "package_purl", pkg))
	}
	return result
}

func grcProjectionAttrsWith(attrs map[string]string, pairs ...string) map[string]string {
	copy := make(map[string]string, len(attrs)+len(pairs)/2)
	for key, value := range attrs {
		copy[key] = value
	}
	for i := 0; i+1 < len(pairs); i += 2 {
		copy[pairs[i]] = pairs[i+1]
	}
	return copy
}

func grcTargetURN(tenantID string, provider string, targetID string) string {
	if strings.TrimSpace(targetID) == "" {
		return ""
	}
	return projectionURN(tenantID, "grc_target", provider, targetID)
}

func grcTargetEntity(tenantID string, sourceID string, urn string, targetID string, attrs map[string]string, provider string) *ports.ProjectedEntity {
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "grc.target",
		Label:      firstAttribute(attrs, "target_name", "resource_name", "hostname", "target_id", "resource_id"),
		Attributes: grcAttributes(nil, map[string]string{
			"host":           grcTargetHost(attrs),
			"integration_id": firstAttribute(attrs, "integration_id"),
			"source_system":  provider,
			"target_id":      targetID,
			"target_type":    firstAttribute(attrs, "target_type", "resource_type", "asset_type"),
		}),
	}
}

func grcTargetHost(attrs map[string]string) string {
	if host := internetHost(firstAttribute(attrs, "hostname", "host", "target_url", "resource_url", "external_url", "url", "website_url")); host != "" {
		return host
	}
	return internetHostIfLikely(firstAttribute(attrs, "target_id", "resource_id", "asset_id", "endpoint_id"))
}

func grcTargetHosts(attrs map[string]string) []string {
	values := splitCloudAttributeList(strings.Join([]string{
		grcTargetHost(attrs),
		attrs["hostnames"],
		attrs["hosts"],
	}, ","))
	hosts := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		host := internetHost(value)
		if host == "" {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	return hosts
}

func grcTargetIPs(attrs map[string]string) []string {
	values := splitCloudAttributeList(strings.Join([]string{
		attrs["ip"],
		attrs["ip_address"],
		attrs["ip_addresses"],
		attrs["public_ip"],
		attrs["public_ips"],
		attrs["private_ip"],
		attrs["private_ips"],
	}, ","))
	ips := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		ip := internetIP(value)
		if ip == "" {
			continue
		}
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}
		ips = append(ips, ip)
	}
	return ips
}

type grcPlatformAssetReference struct {
	Provider          string `json:"provider"`
	ResourceID        string `json:"resource_id"`
	ResourceName      string `json:"resource_name"`
	ResourceType      string `json:"resource_type"`
	ScannerResourceID string `json:"scanner_resource_id"`
	Hostnames         string `json:"hostnames"`
	IPs               string `json:"ips"`
}

func addGRCPlatformAssetLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, targetURN string, attrs map[string]string) {
	grcProviderName := grcProvider(attrs)
	integrationID := firstAttribute(attrs, "integration_id")
	integrationURN := grcIntegrationURN(tenantID, grcProviderName, integrationID)
	for _, ref := range grcPlatformAssetReferences(attrs) {
		provider := grcPlatformProvider(ref.Provider, ref.ResourceID)
		resourceID := strings.TrimSpace(ref.ResourceID)
		if provider == "" || provider == "vanta" || resourceID == "" {
			continue
		}
		resourceType := grcPlatformResourceType(provider, resourceID, ref.ResourceType)
		resourceURN := projectionURN(tenantID, provider+"_"+resourceType, resourceID)
		if resourceURN == "" {
			continue
		}
		// Prefer a human-readable label over the URN so the dashboard, finding
		// reports, and ask-the-graph traces are interpretable. Falling back to
		// the resource id keeps the label stable when the source omits a name.
		label := firstNonEmptyString(strings.TrimSpace(ref.ResourceName), strings.TrimSpace(ref.ScannerResourceID), resourceID)
		entityAttrs := map[string]string{
			"provider":      provider,
			"resource_id":   resourceID,
			"resource_type": resourceType,
			"resource_name": strings.TrimSpace(ref.ResourceName),
		}
		ownerLogin := githubRepositoryOwnerLogin(provider, resourceType, ref.ResourceName)
		if ownerLogin != "" {
			entityAttrs["owner_login"] = ownerLogin
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   provider,
			EntityType: provider + "." + strings.ReplaceAll(resourceType, "_", "."),
			Label:      label,
			Attributes: entityAttrs,
		})
		addLink(links, projectedLink(tenantID, sourceID, targetURN, resourceURN, relationRepresents, map[string]string{
			"confidence":           "0.99",
			"event_id":             event.GetId(),
			"match_type":           "grc_vulnerable_asset_platform_resource",
			"platform_provider":    provider,
			"platform_resource_id": resourceID,
			"resource_type":        resourceType,
		}))
		// Connect the platform resource to the GRC integration that surfaced
		// it. Without this edge a github.code.repository or aws.* node has no
		// outgoing path back to the source/integration it was discovered
		// through, which leaves it dangling whenever the parent grc.target is
		// not the query starting point.
		if integrationURN != "" {
			addEntity(entities, grcIntegrationReferenceEntity(tenantID, sourceID, integrationURN, integrationID, grcProviderName))
			addLink(links, projectedLink(tenantID, sourceID, resourceURN, integrationURN, relationBelongsTo, grcIntegrationLinkAttributes(event, integrationID)))
		}
		addGRCGitHubRepositoryOrgLink(entities, links, tenantID, sourceID, event, resourceURN, ownerLogin)
		addGRCPlatformNetworkLinks(entities, links, tenantID, sourceID, event, resourceURN, ref)
	}
}

func addGRCPlatformNetworkLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, resourceURN string, ref grcPlatformAssetReference) {
	resourceURN = strings.TrimSpace(resourceURN)
	if resourceURN == "" {
		return
	}
	for _, rawHost := range splitCloudAttributeList(ref.Hostnames) {
		addInternetHostLink(entities, links, tenantID, sourceID, event, resourceURN, relationRepresents, rawHost, "grc_platform_resource_host", "0.90")
	}
	for _, rawIP := range splitCloudAttributeList(ref.IPs) {
		addInternetIPLink(entities, links, tenantID, sourceID, event, resourceURN, rawIP, "grc_platform_resource_ip", "0.90")
	}
}

func addGRCGitHubRepositoryOrgLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, repositoryURN string, ownerLogin string) {
	ownerLogin = strings.TrimSpace(ownerLogin)
	repositoryURN = strings.TrimSpace(repositoryURN)
	if ownerLogin == "" || repositoryURN == "" {
		return
	}
	orgURN := projectionURN(tenantID, "github_org", ownerLogin)
	if orgURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        orgURN,
		TenantID:   tenantID,
		SourceID:   "github",
		EntityType: "github.org",
		Label:      ownerLogin,
		Attributes: map[string]string{"org": ownerLogin, "owner_login": ownerLogin},
	})
	addLink(links, projectedLink(tenantID, sourceID, repositoryURN, orgURN, relationBelongsTo, map[string]string{
		"event_id":     event.GetId(),
		"match_type":   "grc_platform_repository_owner",
		"owner_login":  ownerLogin,
		"source_scope": "platform_asset_ref",
	}))
}

func githubRepositoryOwnerLogin(provider string, resourceType string, resourceName string) string {
	if provider != "github" || resourceType != "code_repository" {
		return ""
	}
	owner, _, ok := strings.Cut(strings.TrimSpace(resourceName), "/")
	if !ok {
		return ""
	}
	return strings.TrimSpace(owner)
}

func grcPlatformAssetReferences(attrs map[string]string) []grcPlatformAssetReference {
	if raw := strings.TrimSpace(attrs["platform_asset_refs"]); raw != "" {
		var refs []grcPlatformAssetReference
		if err := json.Unmarshal([]byte(raw), &refs); err == nil {
			return refs
		}
	}
	resourceID := firstAttribute(attrs, "platform_resource_id", "cloud_resource_id", "cloud_resource_arn", "target_arn", "resource_arn")
	if resourceID == "" {
		return nil
	}
	return []grcPlatformAssetReference{{
		Provider:          firstAttribute(attrs, "platform_provider", "cloud_provider", "integration_id"),
		ResourceID:        resourceID,
		ResourceName:      firstAttribute(attrs, "platform_resource_name", "resource_name", "target_name"),
		ResourceType:      firstAttribute(attrs, "platform_resource_type", "cloud_resource_type", "resource_type", "asset_type"),
		ScannerResourceID: firstAttribute(attrs, "scanner_resource_id"),
		Hostnames:         firstAttribute(attrs, "hostnames", "hostname", "host"),
		IPs:               firstAttribute(attrs, "ip_addresses", "ip", "ip_address", "public_ip"),
	}}
}

func grcPlatformProvider(provider string, resourceID string) string {
	provider = normalizeIdentifier(provider)
	if provider != "" && provider != "vanta" {
		return provider
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(resourceID)), "arn:aws") {
		return "aws"
	}
	return provider
}

func grcPlatformResourceType(provider string, resourceID string, fallback string) string {
	if provider == "aws" {
		if resourceType := grcAWSResourceTypeFromARN(resourceID); resourceType != "" {
			return resourceType
		}
	}
	if resourceType := normalizeCloudType(fallback); resourceType != "" {
		return resourceType
	}
	return "resource"
}

func grcAWSResourceTypeFromARN(resourceID string) string {
	_, service, _, _, resource, ok := grcAWSARNParts(resourceID)
	if !ok {
		return ""
	}
	resourceType := strings.TrimLeft(resource, "/")
	if before, _, ok := strings.Cut(resourceType, "/"); ok {
		resourceType = before
	}
	if before, _, ok := strings.Cut(resourceType, ":"); ok {
		resourceType = before
	}
	switch service {
	case "ec2":
		switch resourceType {
		case "security-group":
			return "security_group"
		case "network-interface":
			return "network_interface"
		case "instance":
			return "ec2_instance"
		default:
			return normalizeCloudType(resourceType)
		}
	case "elasticloadbalancing":
		switch {
		case strings.HasPrefix(resource, "loadbalancer/app/"):
			return "application_load_balancer"
		case strings.HasPrefix(resource, "loadbalancer/net/"):
			return "network_load_balancer"
		default:
			return "load_balancer"
		}
	case "cloudfront":
		if resourceType == "distribution" {
			return "cloudfront_distribution"
		}
	case "apigateway":
		if resourceType == "domainname" || resourceType == "domainnames" {
			return "apigateway_domain"
		}
	}
	if resourceType != "" {
		return normalizeCloudType(service + "_" + resourceType)
	}
	return normalizeCloudType(service)
}

func grcAWSARNParts(resourceID string) (partition string, service string, region string, accountID string, resource string, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(resourceID), ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || !strings.HasPrefix(parts[1], "aws") {
		return "", "", "", "", "", false
	}
	return parts[1], parts[2], parts[3], parts[4], parts[5], true
}

func grcIntegrationURN(tenantID string, provider string, integrationID string) string {
	if strings.TrimSpace(integrationID) == "" {
		return ""
	}
	return projectionURN(tenantID, "source", provider, "integration", integrationID)
}

func grcIntegrationEntity(tenantID string, sourceID string, urn string, integrationID string, attrs map[string]string, provider string) *ports.ProjectedEntity {
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "source",
		Label:      firstAttribute(attrs, "display_name", "integration_name", "integration_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"canonical_name": integrationID,
			"source_system":  provider,
			"source_type":    "grc_integration",
		}),
	}
}

func grcIntegrationReferenceEntity(tenantID string, sourceID string, urn string, integrationID string, provider string) *ports.ProjectedEntity {
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "source",
		Attributes: grcAttributes(nil, map[string]string{
			"canonical_name": integrationID,
			"source_system":  provider,
			"source_type":    "grc_integration",
		}),
	}
}

func grcIntegrationLinkAttributes(event *cerebrov1.EventEnvelope, integrationID string) map[string]string {
	return map[string]string{
		"event_id":        event.GetId(),
		"integration_id":  integrationID,
		"relationship":    relationBelongsTo,
		"relationship_by": "grc_vulnerability",
	}
}

func grcPackageTargetAttributes(event *cerebrov1.EventEnvelope, attrs map[string]string) map[string]string {
	return map[string]string{
		"event_id":      event.GetId(),
		"package":       vulnerablePackageName(attrs),
		"target_id":     firstAttribute(attrs, "target_id", "resource_id", "asset_id", "endpoint_id"),
		"version":       firstAttribute(attrs, "version", "package_version", "application_version", "installed_version"),
		"source_system": firstAttribute(attrs, "source_system", "provider", "source_provider"),
	}
}

func grcRiskScenarioProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	riskID := firstAttribute(attrs, "risk_id", "external_id")
	if riskID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	riskURN := projectionURN(tenantID, "claim", provider, "risk_scenario", riskID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        riskURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "claim",
		Label:      firstAttribute(attrs, "description", "risk_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"claim_type":    "risk_scenario",
			"predicate":     firstAttribute(attrs, "description"),
			"source_system": provider,
			"status":        firstAttribute(attrs, "review_status"),
		}),
	})
	if owner := firstAttribute(attrs, "owner"); owner != "" {
		ownerURN := projectionURN(tenantID, "contact", provider, "owner", owner)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        ownerURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "contact",
			Label:      owner,
			Attributes: map[string]string{"source_system": provider, "owner": owner},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), riskURN, ownerURN, relationAssignedTo, map[string]string{"event_id": event.GetId()}))
		addGRCRiskOwnerEmailLink(entities, links, tenantID, event.GetSourceId(), event, ownerURN, owner)
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcPersonProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	personID := firstAttribute(attrs, "person_id", "user_id", "email", "external_id")
	if personID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	personURN := projectionURN(tenantID, "person", provider, personID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        personURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "person",
		Label:      firstAttribute(attrs, "email", "job_title", "person_id"),
		Attributes: grcAttributes(attrs, map[string]string{"person_id": personID, "source_system": provider}),
	})
	observedAt := timestamppb.New(time.Now().UTC())
	email := firstAttribute(attrs, "email")
	addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), personURN, email, observedAt)
	addSameActorEmailLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), personURN, email, observedAt)
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	userID := firstAttribute(attrs, "user_id", "email", "external_id")
	if userID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	userURN := grcUserURN(tenantID, provider, userID)
	addEntity(entities, grcUserEntity(tenantID, event.GetSourceId(), userURN, firstAttribute(attrs, "display_name", "email", "user_id"), grcAttributes(attrs, map[string]string{"user_id": userID, "source_system": provider})))
	email := firstAttribute(attrs, "email")
	addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), userURN, email, event.GetOccurredAt())
	addSameActorEmailLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), userURN, email, event.GetOccurredAt())
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcIntegrationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	integrationID := firstAttribute(attrs, "integration_id", "external_id")
	if integrationID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	sourceURN := grcIntegrationURN(tenantID, provider, integrationID)
	addEntity(entities, grcIntegrationEntity(tenantID, event.GetSourceId(), sourceURN, integrationID, attrs, provider))
	links := map[string]*ports.ProjectedLink{}
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, sourceURN, "grc_resource_kind", firstAttribute(attrs, "resource_kinds"))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcPolicyLikeProjections(event *cerebrov1.EventEnvelope, policyType string, idKey string, labelKeys []string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	id := firstAttribute(attrs, idKey, "external_id")
	if id == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	label := firstAttribute(attrs, labelKeys...)
	policyURN := projectionURN(tenantID, "policy", provider, policyType, id)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        policyURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "policy",
		Label:      label,
		Attributes: grcAttributes(attrs, map[string]string{
			"policy_id":     id,
			"policy_type":   policyType,
			"source_system": provider,
		}),
	})
	links := map[string]*ports.ProjectedLink{}
	if policyType == "control" {
		addGRCUserOwnerLink(entities, links, tenantID, event.GetSourceId(), event, policyURN, provider, firstAttribute(attrs, "owner_id"))
		addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, policyURN, "grc_domain", firstAttribute(attrs, "domains"))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func discoveredVendorStatus(attrs map[string]string) string {
	switch {
	case firstAttribute(attrs, "rejected_at", "rejected_reason", "rejected_by_user_id") != "":
		return "rejected"
	case firstAttribute(attrs, "ignored_at", "ignored_reason", "ignored_by_user_id") != "":
		return "ignored"
	default:
		return "discovered"
	}
}

func remediationStatus(attrs map[string]string) string {
	if status := firstAttribute(attrs, "remediation_status", "vulnerability_status", "status"); status != "" {
		return status
	}
	if firstAttribute(attrs, "remediated_at", "remediation_date") != "" {
		return "remediated"
	}
	return "open"
}

func addGRCUserActionLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, provider string, userID string, toURN string, action string) {
	userID = strings.TrimSpace(userID)
	if userID == "" || strings.TrimSpace(toURN) == "" {
		return
	}
	userURN := grcUserURN(tenantID, provider, userID)
	addEntity(entities, grcUserEntity(tenantID, sourceID, userURN, userID, map[string]string{"source_system": provider, "user_id": userID}))
	addLink(links, projectedLink(tenantID, sourceID, userURN, toURN, relationActedOn, map[string]string{
		"action":   strings.TrimSpace(action),
		"event_id": event.GetId(),
		"user_id":  userID,
	}))
}

type grcEventTarget struct {
	typ string
	id  string
}

func grcEventTargets(raw string) []grcEventTarget {
	targets := []grcEventTarget{}
	seen := map[string]struct{}{}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		targetType, targetID, found := strings.Cut(part, ":")
		if !found {
			targetType = "resource"
			targetID = part
		}
		target := grcEventTarget{typ: strings.TrimSpace(targetType), id: strings.TrimSpace(targetID)}
		if target.id == "" {
			continue
		}
		key := target.typ + "\x00" + target.id
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, target)
	}
	return targets
}

func grcEventActorURN(tenantID string, provider string, attrs map[string]string) string {
	actorID := firstAttribute(attrs, "actor_id")
	if actorID == "" {
		return ""
	}
	actorType := grcEventActorType(attrs)
	if strings.EqualFold(actorType, "user") {
		return grcUserURN(tenantID, provider, actorID)
	}
	return projectionURN(tenantID, "grc_audit_actor", provider, actorType, actorID)
}

func grcEventActorEntity(tenantID string, sourceID string, actorURN string, provider string, attrs map[string]string) *ports.ProjectedEntity {
	actorType := grcEventActorType(attrs)
	actorID := firstAttribute(attrs, "actor_id")
	entityType := "audit.actor"
	if strings.EqualFold(actorType, "user") {
		entityType = "user"
	}
	attributes := map[string]string{
		"actor_id":      actorID,
		"actor_type":    actorType,
		"source_system": provider,
	}
	if entityType == "user" {
		attributes["user_id"] = actorID
	}
	return &ports.ProjectedEntity{
		URN:        actorURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: entityType,
		Label:      eventActorLabel(actorType, actorID),
		Attributes: grcAttributes(nil, attributes),
	}
}

func grcEventActorType(attrs map[string]string) string {
	return firstNonEmpty(firstAttribute(attrs, "actor_type"), "resource")
}

func eventActorLabel(actorType string, actorID string) string {
	if strings.TrimSpace(actorType) == "" || strings.TrimSpace(actorType) == "resource" {
		return strings.TrimSpace(actorID)
	}
	return strings.TrimSpace(actorType) + ":" + strings.TrimSpace(actorID)
}

func grcProviderVulnerabilityURN(tenantID string, provider string, vulnerabilityID string) string {
	if strings.TrimSpace(vulnerabilityID) == "" {
		return ""
	}
	return projectionURN(tenantID, "grc_vulnerability", provider, vulnerabilityID)
}

func grcProviderVulnerabilityEntity(tenantID string, sourceID string, vulnerabilityURN string, provider string, attrs map[string]string) *ports.ProjectedEntity {
	vulnerabilityID := firstAttribute(attrs, "vulnerability_id")
	return &ports.ProjectedEntity{
		URN:        vulnerabilityURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "vulnerability",
		Label:      firstAttribute(attrs, "name", "title", "vulnerability_id"),
		Attributes: grcAttributes(nil, map[string]string{
			"source_system":    provider,
			"vulnerability_id": vulnerabilityID,
		}),
	}
}

func grcAttributes(attrs map[string]string, extra map[string]string) map[string]string {
	merged := make(map[string]string, len(attrs)+len(extra))
	for key, value := range attrs {
		if strings.TrimSpace(value) != "" {
			merged[key] = strings.TrimSpace(value)
		}
	}
	for key, value := range extra {
		if strings.TrimSpace(value) != "" {
			merged[key] = strings.TrimSpace(value)
		}
	}
	return merged
}

func grcProvider(attrs map[string]string) string {
	return firstNonEmpty(attrs["provider"], attrs["source_provider"], "grc")
}

func grcUserURN(tenantID string, provider string, userID string) string {
	return projectionURN(tenantID, "user", provider, userID)
}

func grcUserEntity(tenantID string, sourceID string, urn string, label string, attrs map[string]string) *ports.ProjectedEntity {
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "user",
		Label:      label,
		Attributes: attrs,
	}
}

func addGRCUserOwnerLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, provider string, ownerID string) {
	ownerID = strings.TrimSpace(ownerID)
	if fromURN == "" || ownerID == "" {
		return
	}
	ownerURN := grcUserURN(tenantID, provider, ownerID)
	addEntity(entities, grcUserEntity(tenantID, sourceID, ownerURN, ownerID, map[string]string{"user_id": ownerID, "source_system": provider}))
	addLink(links, projectedLink(tenantID, sourceID, fromURN, ownerURN, relationOwnedBy, map[string]string{"event_id": event.GetId()}))
}

func addGRCRiskOwnerEmailLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, contactURN string, owner string) {
	addSecurityContactEmailLink(entities, links, tenantID, sourceID, event, contactURN, owner, "owner")
}

func addSecurityContactEmailLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, email string, contactType string) {
	normalizedEmail := normalizeIdentifier(extractEmailIdentifier(email))
	fromURN = strings.TrimSpace(fromURN)
	if fromURN == "" || normalizedEmail == "" {
		return
	}
	identityURN := projectionURN(tenantID, "identity", "email", normalizedEmail)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        identityURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "identity.email",
		Label:      normalizedEmail,
		Attributes: map[string]string{"value": normalizedEmail},
	})
	linkAttrs := map[string]string{
		"confidence":   "0.90",
		"contact_type": strings.TrimSpace(contactType),
		"event_id":     event.GetId(),
		"match_type":   "contact_email",
	}
	addProjectedAttribute(linkAttrs, "at", eventObservedAt(event))
	addLink(links, projectedLink(tenantID, sourceID, fromURN, identityURN, relationAssociatedWith, linkAttrs))
}

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
		Label:      firstAttribute(attrs, "customer_trust_account_name", "customer_account_name", "account_name", "customer_name", "account_id"),
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
			Label:      firstAttribute(attrs, "finding_name", "title", "name", "finding_id"),
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

func addGRCIntegrationLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, provider string, rawIntegrations string, relationshipBy string) {
	if fromURN == "" {
		return
	}
	for _, integrationID := range grcAttributeSequence(rawIntegrations) {
		integrationURN := grcIntegrationURN(tenantID, provider, integrationID)
		if integrationURN == "" {
			continue
		}
		addEntity(entities, grcIntegrationReferenceEntity(tenantID, sourceID, integrationURN, integrationID, provider))
		addLink(links, projectedLink(tenantID, sourceID, fromURN, integrationURN, relationBelongsTo, map[string]string{
			"event_id":         event.GetId(),
			"integration_id":   integrationID,
			"relationship":     relationBelongsTo,
			"relationship_by":  relationshipBy,
			"source_reference": "integrations",
		}))
	}
}

func addGRCAssetTagLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, namespace string, rawValues string) {
	if fromURN == "" {
		return
	}
	for _, value := range grcAttributeSequence(rawValues) {
		tagID := grcAssetTagID(value)
		if tagID == "" {
			continue
		}
		tagURN := projectionURN(tenantID, "asset_tag", namespace, tagID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        tagURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: "asset.tag",
			Label:      value,
			Attributes: map[string]string{
				"tag":           tagID,
				"tag_namespace": namespace,
				"tag_value":     value,
			},
		})
		addLink(links, projectedLink(tenantID, sourceID, fromURN, tagURN, relationTaggedAs, map[string]string{
			"event_id":      event.GetId(),
			"tag_namespace": namespace,
			"tag_value":     value,
		}))
	}
}

func grcAssetTagID(value string) string {
	normalized := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		case r >= '0' && r <= '9':
			return r
		default:
			return '_'
		}
	}, strings.TrimSpace(value))
	normalized = strings.Trim(normalized, "_")
	for strings.Contains(normalized, "__") {
		normalized = strings.ReplaceAll(normalized, "__", "_")
	}
	return normalized
}

func grcDerivedID(parts ...string) string {
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	if len(values) == 0 {
		return ""
	}
	return grcAssetTagID(strings.Join(values, "_"))
}
