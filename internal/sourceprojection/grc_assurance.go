package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

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
