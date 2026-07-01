package questionnaire

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/writer/cerebro/internal/fabriccontract"
	"github.com/writer/cerebro/internal/ports"
)

func TestBuildGraphProjectionLinksQuestionnaireWork(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	dueAt := now.Add(24 * time.Hour)
	record := ports.QuestionnaireRunRecord{
		QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{TenantID: "writer", RunID: "run-1", Title: "Core SSO review"},
		QuestionnaireRunSource: ports.QuestionnaireRunSource{
			Direction: ports.QuestionnaireDirectionVendorReview,
			VendorURN: "urn:cerebro:writer:vendor:core-sso",
			VendorID:  "core-sso",
			SourceID:  "grc",
			RuntimeID: "runtime-1",
		},
		QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{
			Status:           ports.QuestionnaireStatusReadyForApproval,
			OwnerID:          "security@example.com",
			ReadyAnswerCount: 1,
		},
		QuestionnaireRunContent: ports.QuestionnaireRunContent{
			Questions: []ports.QuestionnaireQuestion{{
				ID:             "q-1",
				Question:       "Do you enforce MFA?",
				MappedControls: []string{"SOC2-CC6.1"},
				RequiredSlots:  []string{"identity_mfa"},
				OwnerID:        "security@example.com",
				SourceLocator: &ports.QuestionnaireSourceLocator{
					SourceFormat: "xlsx",
					SheetName:    "sheet1",
					RowNumber:    2,
					Cell:         "B2",
				},
			}},
			Answers: []ports.QuestionnaireRunAnswer{{
				ID:          "a-1",
				QuestionID:  "q-1",
				AnswerState: ports.QuestionnaireAnswerSupported,
				Controls:    []string{"SOC2-CC6.1"},
				EvidenceSlots: []ports.QuestionnaireEvidenceSlot{{
					ID:          "identity_mfa",
					Label:       "MFA",
					State:       "satisfied",
					Required:    true,
					CitationIDs: []string{"evidence-1"},
				}},
				Citations: []ports.QuestionnaireCitation{{
					ID:               "evidence-1",
					Label:            "MFA configuration",
					SourceID:         "okta",
					RuntimeID:        "okta-prod",
					EvidenceID:       "evidence-1",
					EvidencePacketID: "packet-1",
					EvidenceType:     "identity_mfa",
					ControlID:        "SOC2-CC6.1",
					FreshnessStatus:  "current",
					SourceEventIDs:   []string{"event-1"},
					GraphRootURNs:    []string{"urn:cerebro:writer:okta_application:core-sso"},
					GraphPathIDs:     []string{"path-1"},
				}},
				MissingEvidence: []ports.QuestionnaireEvidenceGap{{
					ID:          "gap-1",
					Code:        "stale_evidence",
					Reason:      "Refresh MFA export before approval.",
					SlotID:      "identity_mfa",
					ControlID:   "SOC2-CC6.1",
					PacketID:    "packet-1",
					ReviewState: ports.QuestionnaireReviewNeedsReview,
				}},
				Freshness: ports.QuestionnaireFreshness{Status: "current"},
			}},
			Assignments: []ports.QuestionnaireAssignment{{
				ID:         "assignment-1",
				QuestionID: "q-1",
				GapID:      "gap-1",
				OwnerID:    "evidence@example.com",
				Status:     "open",
				DueAt:      &dueAt,
			}},
		},
		QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{
			Attributes: map[string]string{
				QuestionnaireAttributeSourceArtifactURN: "urn:cerebro:writer:assurance_document:intake-sheet",
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
	}

	projection, err := BuildGraphProjection(record, nil, now)
	if err != nil {
		t.Fatalf("BuildGraphProjection() error = %v", err)
	}
	questionnaireURN := projection.Record.Attributes[QuestionnaireAttributeQuestionnaireURN]
	if !strings.HasPrefix(questionnaireURN, "urn:cerebro:writer:security_questionnaire:questionnaire_run:run-1") {
		t.Fatalf("questionnaire urn = %q, want stable security questionnaire urn", questionnaireURN)
	}
	if len(projection.Entities) < 4 {
		t.Fatalf("entities = %d, want questionnaire, owner, control, and evidence entities", len(projection.Entities))
	}
	for _, entityType := range []string{
		"questionnaire.question",
		"questionnaire.answer",
		"questionnaire.evidence_slot",
		"questionnaire.evidence_gap",
	} {
		if !hasProjectedEntityType(projection.Entities, entityType) {
			t.Fatalf("missing %s entity in %#v", entityType, projection.Entities)
		}
	}
	if !hasAssociatedProjectedLink(projection.Links, questionnaireURN, "urn:cerebro:writer:vendor:core-sso") {
		t.Fatalf("missing vendor association link in %#v", projection.Links)
	}
	if !hasProjectedLinkToRelation(projection.Links, fabriccontract.RelationOwnedBy) {
		t.Fatalf("missing owner link in %#v", projection.Links)
	}
	if !hasProjectedLinkToRelation(projection.Links, fabriccontract.RelationSupports) {
		t.Fatalf("missing control support link in %#v", projection.Links)
	}
	if !hasProjectedLinkToRelation(projection.Links, fabriccontract.RelationHasEvidence) {
		t.Fatalf("missing evidence link in %#v", projection.Links)
	}
	if got := projection.Entities[0].Attributes["ready_answer_count"]; got != "1" {
		t.Fatalf("ready answer count attr = %q, want 1", got)
	}

	questionURN := questionnaireQuestionURN("writer", "run-1", "q-1")
	answerURN := questionnaireAnswerURN("writer", "run-1", "q-1", "a-1")
	slotURN := questionnaireSlotURN("writer", "run-1", "q-1", "identity_mfa")
	gapURN := questionnaireGapURN("writer", "run-1", "q-1", "gap-1")
	evidenceURN := citationResourceURN("writer", record.Answers[0].Citations[0])
	controlURN := controlEntityURN("writer", "SOC2-CC6.1")
	ownerURN := ownerEntityURN("writer", "evidence@example.com")
	if !hasProjectedLink(projection.Links, questionnaireURN, fabriccontract.RelationContains, questionURN) {
		t.Fatalf("missing run contains question link in %#v", projection.Links)
	}
	if !hasProjectedLink(projection.Links, answerURN, fabriccontract.RelationAttachedTo, questionURN) {
		t.Fatalf("missing answer attached-to question link in %#v", projection.Links)
	}
	if !hasProjectedLink(projection.Links, slotURN, fabriccontract.RelationHasEvidence, evidenceURN) {
		t.Fatalf("missing slot evidence link in %#v", projection.Links)
	}
	if !hasProjectedLink(projection.Links, questionURN, fabriccontract.RelationSupports, controlURN) {
		t.Fatalf("missing question control link in %#v", projection.Links)
	}
	if !hasProjectedLink(projection.Links, questionURN, fabriccontract.RelationHasContext, "urn:cerebro:writer:assurance_document:intake-sheet") {
		t.Fatalf("missing question source-artifact context link in %#v", projection.Links)
	}
	if !hasProjectedLink(projection.Links, answerURN, fabriccontract.RelationHasContext, "urn:cerebro:writer:okta_application:core-sso") {
		t.Fatalf("missing answer graph-root context link in %#v", projection.Links)
	}
	if !hasProjectedLink(projection.Links, gapURN, fabriccontract.RelationAssignedTo, ownerURN) {
		t.Fatalf("missing gap assignment link in %#v", projection.Links)
	}
}

func TestProjectionAttributeValueTruncatesAtUTF8Boundary(t *testing.T) {
	value := strings.Repeat("a", 511) + "界" + "tail"

	got := projectionAttributeValue(value)

	if !utf8.ValidString(got) {
		t.Fatalf("projectionAttributeValue returned invalid UTF-8: %q", got)
	}
	if len(got) > 512 {
		t.Fatalf("projectionAttributeValue length = %d, want at most 512 bytes", len(got))
	}
	if strings.Contains(got, "\uFFFD") {
		t.Fatalf("projectionAttributeValue inserted replacement character: %q", got)
	}
}

func TestBuildGraphProjectionRemovesStaleLinks(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	previous := ports.QuestionnaireRunRecord{
		QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{TenantID: "writer", RunID: "run-1", Title: "Vendor review"},
		QuestionnaireRunSource: ports.QuestionnaireRunSource{
			Direction: ports.QuestionnaireDirectionVendorReview,
			VendorURN: "urn:cerebro:writer:vendor:old",
			SourceID:  "grc",
		},
		QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{Status: ports.QuestionnaireStatusNeedsInput},
		QuestionnaireRunContent: ports.QuestionnaireRunContent{
			Questions: []ports.QuestionnaireQuestion{{ID: "q-1", Question: "Do you encrypt data?", MappedControls: []string{"old-control"}}},
			Answers: []ports.QuestionnaireRunAnswer{{
				ID:          "a-1",
				QuestionID:  "q-1",
				AnswerState: ports.QuestionnaireAnswerSupported,
				Controls:    []string{"old-control"},
				Citations:   []ports.QuestionnaireCitation{{ID: "old-evidence", EvidenceID: "old-evidence"}},
				Freshness:   ports.QuestionnaireFreshness{Status: "current"},
			}},
		},
		QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{CreatedAt: now, UpdatedAt: now},
	}
	current := previous
	current.Questions = append([]ports.QuestionnaireQuestion(nil), previous.Questions...)
	current.Answers = append([]ports.QuestionnaireRunAnswer(nil), previous.Answers...)
	current.VendorURN = "urn:cerebro:writer:vendor:new"
	current.Questions[0].MappedControls = []string{"new-control"}
	current.Answers[0].Controls = []string{"new-control"}
	current.Answers[0].Citations = []ports.QuestionnaireCitation{{ID: "new-evidence", EvidenceID: "new-evidence"}}

	projection, err := BuildGraphProjection(current, &previous, now)
	if err != nil {
		t.Fatalf("BuildGraphProjection() error = %v", err)
	}
	questionnaireURN := projection.Record.Attributes[QuestionnaireAttributeQuestionnaireURN]
	if !hasAssociatedProjectedLink(projection.RemovedLinks, questionnaireURN, "urn:cerebro:writer:vendor:old") {
		t.Fatalf("removed links missing old vendor link: %#v", projection.RemovedLinks)
	}
	if !hasProjectedLinkToRelation(projection.RemovedLinks, fabriccontract.RelationSupports) {
		t.Fatalf("removed links missing stale control link: %#v", projection.RemovedLinks)
	}
	if !hasProjectedLinkToRelation(projection.RemovedLinks, fabriccontract.RelationHasEvidence) {
		t.Fatalf("removed links missing stale evidence link: %#v", projection.RemovedLinks)
	}
	oldQuestionURN := questionnaireQuestionURN("writer", "run-1", "q-1")
	oldControlURN := controlEntityURN("writer", "old-control")
	if !hasProjectedLink(projection.RemovedLinks, oldQuestionURN, fabriccontract.RelationSupports, oldControlURN) {
		t.Fatalf("removed links missing stale question control link: %#v", projection.RemovedLinks)
	}
	if hasAssociatedProjectedLink(projection.RemovedLinks, questionnaireURN, "urn:cerebro:writer:vendor:new") {
		t.Fatalf("removed links include current vendor link: %#v", projection.RemovedLinks)
	}
}

func TestEnsureGraphIdentityOverwritesUserProvidedQuestionnaireURN(t *testing.T) {
	record := ports.QuestionnaireRunRecord{
		QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{TenantID: "writer", RunID: "run-1"},
		QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{Attributes: map[string]string{
			QuestionnaireAttributeQuestionnaireURN: "urn:cerebro:writer:vendor:core-sso",
		}},
	}

	normalized, err := EnsureGraphIdentity(record)
	if err != nil {
		t.Fatalf("EnsureGraphIdentity() error = %v", err)
	}
	if got := normalized.Attributes[QuestionnaireAttributeQuestionnaireURN]; got != "urn:cerebro:writer:security_questionnaire:questionnaire_run:run-1" {
		t.Fatalf("questionnaire urn = %q, want minted questionnaire urn", got)
	}
	if got := record.Attributes[QuestionnaireAttributeQuestionnaireURN]; got != "urn:cerebro:writer:vendor:core-sso" {
		t.Fatalf("original attributes mutated to %q", got)
	}
}

func TestBuildGraphProjectionOnlyLinksValidSourceArtifactURNs(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	record := ports.QuestionnaireRunRecord{
		QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{TenantID: "writer", RunID: "run-1"},
		QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{Attributes: map[string]string{
			QuestionnaireAttributeSourceArtifactURN: "urn:cerebro:writer:assurance_document:soc2",
		}},
	}

	projection, err := BuildGraphProjection(record, nil, now)
	if err != nil {
		t.Fatalf("BuildGraphProjection() error = %v", err)
	}
	questionnaireURN := projection.Record.Attributes[QuestionnaireAttributeQuestionnaireURN]
	if !hasAssociatedProjectedLink(projection.Links, questionnaireURN, "urn:cerebro:writer:assurance_document:soc2") {
		t.Fatalf("missing source artifact link in %#v", projection.Links)
	}

	record.Attributes[QuestionnaireAttributeSourceArtifactURN] = "urn:cerebro:writer:vendor:core-sso"
	projection, err = BuildGraphProjection(record, nil, now)
	if err != nil {
		t.Fatalf("BuildGraphProjection() error = %v", err)
	}
	if hasAssociatedProjectedLink(projection.Links, projection.Record.Attributes[QuestionnaireAttributeQuestionnaireURN], "urn:cerebro:writer:vendor:core-sso") {
		t.Fatalf("source artifact link accepted wrong-kind urn: %#v", projection.Links)
	}

	record.Attributes[QuestionnaireAttributeSourceArtifactURN] = "urn:cerebro:other:assurance_document:soc2"
	projection, err = BuildGraphProjection(record, nil, now)
	if err != nil {
		t.Fatalf("BuildGraphProjection() error = %v", err)
	}
	if hasAssociatedProjectedLink(projection.Links, projection.Record.Attributes[QuestionnaireAttributeQuestionnaireURN], "urn:cerebro:other:assurance_document:soc2") {
		t.Fatalf("source artifact link accepted cross-tenant urn: %#v", projection.Links)
	}
}

func TestControlEntityURNOnlyPassesThroughSameTenantControlURNs(t *testing.T) {
	if got := controlEntityURN("writer", "SOC2-CC6.1"); got != "urn:cerebro:writer:control:questionnaire:SOC2-CC6.1" {
		t.Fatalf("controlEntityURN() = %q, want minted control urn", got)
	}
	if got := controlEntityURN("writer", "urn:cerebro:writer:control:soc2-cc6.1"); got != "urn:cerebro:writer:control:soc2-cc6.1" {
		t.Fatalf("controlEntityURN() = %q, want same-tenant control urn passthrough", got)
	}
	if got := controlEntityURN("writer", "urn:cerebro:writer:grc_user:security"); got != "" {
		t.Fatalf("controlEntityURN() = %q, want wrong-kind urn skipped", got)
	}
	if got := controlEntityURN("writer", "urn:cerebro:other:control:soc2-cc6.1"); got != "" {
		t.Fatalf("controlEntityURN() = %q, want cross-tenant urn skipped", got)
	}
}

func TestCitationResourceURNOnlyPassesThroughRuntimeEvidenceURNs(t *testing.T) {
	got := citationResourceURN("writer", ports.QuestionnaireCitation{
		ResourceURN: "urn:cerebro:writer:vendor:core-sso",
		EvidenceID:  "evidence-1",
	})
	if got != "urn:cerebro:writer:runtime_evidence:evidence-1" {
		t.Fatalf("citationResourceURN() = %q, want minted runtime evidence urn", got)
	}

	got = citationResourceURN("writer", ports.QuestionnaireCitation{
		ResourceURN: "urn:cerebro:writer:runtime_evidence:evidence-2",
		EvidenceID:  "evidence-1",
	})
	if got != "urn:cerebro:writer:runtime_evidence:evidence-2" {
		t.Fatalf("citationResourceURN() = %q, want existing runtime evidence urn", got)
	}

	got = citationResourceURN("writer", ports.QuestionnaireCitation{
		EvidenceID: "urn:cerebro:writer:vendor:core-sso",
	})
	if got != "" {
		t.Fatalf("citationResourceURN() = %q, want non-evidence urn ignored", got)
	}
}

func hasAssociatedProjectedLink(links []*ports.ProjectedLink, fromURN string, toURN string) bool {
	for _, link := range links {
		if link.FromURN == fromURN && link.Relation == fabriccontract.RelationAssociatedWith && link.ToURN == toURN {
			return true
		}
	}
	return false
}

func hasProjectedLinkToRelation(links []*ports.ProjectedLink, relation string) bool {
	for _, link := range links {
		if link.Relation == relation {
			return true
		}
	}
	return false
}

func hasProjectedLink(links []*ports.ProjectedLink, fromURN string, relation string, toURN string) bool {
	for _, link := range links {
		if link.FromURN == fromURN && link.Relation == relation && link.ToURN == toURN {
			return true
		}
	}
	return false
}

func hasProjectedEntityType(entities []*ports.ProjectedEntity, entityType string) bool {
	for _, entity := range entities {
		if entity.EntityType == entityType {
			return true
		}
	}
	return false
}
