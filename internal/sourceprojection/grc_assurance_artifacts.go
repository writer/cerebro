package sourceprojection

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
