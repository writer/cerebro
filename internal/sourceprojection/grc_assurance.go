package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func grcDocumentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	documentID := firstAttribute(ctx.attrs, "document_id", "external_id")
	if documentID == "" {
		return nil, nil, nil
	}
	documentURN := ctx.resourceURN("document", documentID)
	ctx.addResourceEntity(
		documentURN,
		"document",
		firstAttribute(ctx.attrs, "title", "document_id"),
		map[string]string{"document_id": documentID, "source_system": ctx.provider},
	)
	addGRCUserOwnerLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, documentURN, ctx.provider, firstAttribute(ctx.attrs, "owner_id"))
	addInternetHostLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, documentURN, relationHasIdentifier, firstAttribute(ctx.attrs, "url"), "grc_document_url_host", "0.9")
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, documentURN, "grc_category", firstAttribute(ctx.attrs, "category"))
	entities, links := ctx.done()
	return entities, links, nil
}

func grcContractProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	contractID := firstAttribute(ctx.attrs, "contract_id", "external_id")
	if contractID == "" {
		return nil, nil, nil
	}
	contractURN := ctx.resourceURN("contract", contractID)
	ctx.addResourceEntity(
		contractURN,
		"contract",
		firstAttribute(ctx.attrs, "name", "title", "vendor_name", "contract_id"),
		map[string]string{
			"contract_id":   contractID,
			"contract_type": firstAttribute(ctx.attrs, "contract_type", "agreement_type"),
			"source_system": ctx.provider,
			"status":        firstAttribute(ctx.attrs, "status"),
		},
	)
	addGRCUserOwnerLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, contractURN, ctx.provider, firstAttribute(ctx.attrs, "owner_id", "business_owner_user_id"))
	addGRCVendorAssociationLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, contractURN, ctx.provider, ctx.attrs)
	addGRCTargetReferenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, contractURN, ctx.provider, ctx.attrs, relationAssociatedWith, "grc_contract")
	addGRCControlSupportLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, contractURN, ctx.provider)
	addGRCEvidenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, contractURN, ctx.provider, ctx.attrs)
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, contractURN, "grc_contract_category", firstAttribute(ctx.attrs, "category"))
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, contractURN, "grc_contract_tag", strings.Join([]string{ctx.attrs["tags"], ctx.attrs["data_types"], ctx.attrs["jurisdictions"]}, ","))
	entities, links := ctx.done()
	return entities, links, nil
}

func grcSecurityReviewProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	reviewID := firstAttribute(ctx.attrs, "security_review_id", "review_id", "assessment_id", "external_id")
	if reviewID == "" {
		reviewID = grcDerivedID(firstAttribute(ctx.attrs, "vendor_id", "third_party_id"), firstAttribute(ctx.attrs, "review_type", "assessment_type"), firstAttribute(ctx.attrs, "started_at", "completed_at", "created_at"))
	}
	if reviewID == "" {
		return nil, nil, nil
	}
	reviewKind := grcAssuranceArtifactSecurityReview
	reviewURN := ctx.resourceURN(reviewKind.String(), reviewID)
	ctx.addResourceEntity(
		reviewURN,
		reviewKind.entityType(),
		firstAttribute(ctx.attrs, "name", "title", "review_type", "assessment_type", "security_review_id", "review_id"),
		map[string]string{
			"review_type":        firstAttribute(ctx.attrs, "review_type", "assessment_type"),
			"risk_level":         firstAttribute(ctx.attrs, "risk_level", "inherent_risk_level", "residual_risk_level"),
			"security_review_id": reviewID,
			"source_system":      ctx.provider,
			"status":             firstAttribute(ctx.attrs, "status", "review_status", "assessment_status"),
		},
	)
	addGRCAssuranceArtifactLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, reviewURN, ctx.provider, ctx.attrs, relationAssociatedWith, "grc_security_review", "grc_security_review_url_host", reviewKind,
		grcJoinedAttributeValues(ctx.attrs, "review_type", "assessment_type", "status", "review_status", "risk_level", "inherent_risk_level", "residual_risk_level"))
	addGRCRelatedAssuranceArtifactLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, reviewURN, ctx.provider, ctx.attrs, reviewKind)
	entities, links := ctx.done()
	return entities, links, nil
}

func grcSecurityQuestionnaireProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	questionnaireID := firstAttribute(ctx.attrs, "security_questionnaire_id", "questionnaire_id", "external_id")
	if questionnaireID == "" {
		questionnaireID = grcDerivedID(firstAttribute(ctx.attrs, "customer_trust_account_id", "account_id", "vendor_id"), firstAttribute(ctx.attrs, "questionnaire_type"), firstAttribute(ctx.attrs, "submitted_at", "created_at"))
	}
	if questionnaireID == "" {
		return nil, nil, nil
	}
	questionnaireKind := grcAssuranceArtifactSecurityQuestionnaire
	questionnaireURN := ctx.resourceURN(questionnaireKind.String(), questionnaireID)
	ctx.addResourceEntity(
		questionnaireURN,
		questionnaireKind.entityType(),
		firstAttribute(ctx.attrs, "name", "title", "questionnaire_type", "security_questionnaire_id", "questionnaire_id"),
		map[string]string{
			"questionnaire_type":        firstAttribute(ctx.attrs, "questionnaire_type", "assessment_type"),
			"security_questionnaire_id": questionnaireID,
			"source_system":             ctx.provider,
			"status":                    firstAttribute(ctx.attrs, "status", "questionnaire_status", "response_status"),
		},
	)
	addGRCAssuranceArtifactLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, questionnaireURN, ctx.provider, ctx.attrs, relationAssociatedWith, "grc_security_questionnaire", "grc_security_questionnaire_url_host", questionnaireKind,
		grcJoinedAttributeValues(ctx.attrs, "questionnaire_type", "assessment_type", "status", "questionnaire_status", "response_status"))
	addGRCRelatedAssuranceArtifactLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, questionnaireURN, ctx.provider, ctx.attrs, questionnaireKind)
	entities, links := ctx.done()
	return entities, links, nil
}

func grcPenetrationTestProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	testID := firstAttribute(ctx.attrs, "penetration_test_id", "pentest_id", "test_id", "external_id")
	if testID == "" {
		testID = grcDerivedID(firstAttribute(ctx.attrs, "target_id", "resource_id", "asset_id", "system_id"), firstAttribute(ctx.attrs, "test_type", "assessment_type"), firstAttribute(ctx.attrs, "started_at", "completed_at"))
	}
	if testID == "" {
		return nil, nil, nil
	}
	testKind := grcAssuranceArtifactPenetrationTest
	testURN := ctx.resourceURN(testKind.String(), testID)
	ctx.addResourceEntity(
		testURN,
		testKind.entityType(),
		firstAttribute(ctx.attrs, "name", "title", "test_type", "penetration_test_id", "pentest_id", "test_id"),
		map[string]string{
			"penetration_test_id": testID,
			"source_system":       ctx.provider,
			"status":              firstAttribute(ctx.attrs, "status", "test_status", "assessment_status"),
			"test_type":           firstAttribute(ctx.attrs, "test_type", "assessment_type"),
		},
	)
	addGRCAssuranceArtifactLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, testURN, ctx.provider, ctx.attrs, relationTargeted, "grc_penetration_test", "grc_penetration_test_url_host", testKind,
		grcJoinedAttributeValues(ctx.attrs, "test_type", "assessment_type", "status", "test_status", "scope", "severity"))
	addGRCPenetrationTestFindingLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, testURN, ctx.provider, ctx.attrs)
	addGRCRelatedAssuranceArtifactLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, testURN, ctx.provider, ctx.attrs, testKind)
	entities, links := ctx.done()
	return entities, links, nil
}

func grcAssuranceDocumentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	documentID := firstAttribute(ctx.attrs, "assurance_document_id", "document_id", "upload_id", "external_id")
	if documentID == "" {
		documentID = grcDerivedID(firstAttribute(ctx.attrs, "url", "document_url", "download_url"), firstAttribute(ctx.attrs, "title", "name"))
	}
	if documentID == "" {
		return nil, nil, nil
	}
	documentKind := grcAssuranceArtifactDocument
	documentURN := ctx.resourceURN(documentKind.String(), documentID)
	ctx.addResourceEntity(
		documentURN,
		documentKind.entityType(),
		firstAttribute(ctx.attrs, "title", "name", "document_type", "assurance_document_id", "document_id", "upload_id"),
		map[string]string{
			"assurance_document_id": documentID,
			"document_type":         firstAttribute(ctx.attrs, "document_type", "artifact_type", "evidence_type"),
			"source_system":         ctx.provider,
			"status":                firstAttribute(ctx.attrs, "status", "upload_status", "review_status"),
		},
	)
	addGRCAssuranceArtifactLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, documentURN, ctx.provider, ctx.attrs, relationAssociatedWith, "grc_assurance_document", "grc_assurance_document_url_host", documentKind,
		grcJoinedAttributeValues(ctx.attrs, "document_type", "artifact_type", "evidence_type", "category", "status", "upload_status", "tags"))
	addGRCUserActionLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ctx.provider, firstAttribute(ctx.attrs, "uploaded_by_user_id", "uploader_user_id"), documentURN, "uploaded")
	addGRCRelatedAssuranceArtifactLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, documentURN, ctx.provider, ctx.attrs, documentKind)
	entities, links := ctx.done()
	return entities, links, nil
}
