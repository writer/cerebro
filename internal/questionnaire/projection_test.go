package questionnaire

import (
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/fabriccontract"
	"github.com/writer/cerebro/internal/ports"
)

func TestBuildGraphProjectionLinksQuestionnaireWork(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
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
			}},
			Answers: []ports.QuestionnaireRunAnswer{{
				ID:          "a-1",
				QuestionID:  "q-1",
				AnswerState: ports.QuestionnaireAnswerSupported,
				Controls:    []string{"SOC2-CC6.1"},
				Citations: []ports.QuestionnaireCitation{{
					ID:               "evidence-1",
					Label:            "MFA configuration",
					EvidenceID:       "evidence-1",
					EvidencePacketID: "packet-1",
					EvidenceType:     "identity_mfa",
					FreshnessStatus:  "current",
				}},
				Freshness: ports.QuestionnaireFreshness{Status: "current"},
			}},
		},
		QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{CreatedAt: now, UpdatedAt: now},
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
	if !hasProjectedLink(projection.Links, questionnaireURN, fabriccontract.RelationAssociatedWith, "urn:cerebro:writer:vendor:core-sso") {
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
	if !hasProjectedLink(projection.RemovedLinks, questionnaireURN, fabriccontract.RelationAssociatedWith, "urn:cerebro:writer:vendor:old") {
		t.Fatalf("removed links missing old vendor link: %#v", projection.RemovedLinks)
	}
	if !hasProjectedLinkToRelation(projection.RemovedLinks, fabriccontract.RelationSupports) {
		t.Fatalf("removed links missing stale control link: %#v", projection.RemovedLinks)
	}
	if !hasProjectedLinkToRelation(projection.RemovedLinks, fabriccontract.RelationHasEvidence) {
		t.Fatalf("removed links missing stale evidence link: %#v", projection.RemovedLinks)
	}
	if hasProjectedLink(projection.RemovedLinks, questionnaireURN, fabriccontract.RelationAssociatedWith, "urn:cerebro:writer:vendor:new") {
		t.Fatalf("removed links include current vendor link: %#v", projection.RemovedLinks)
	}
}

func hasProjectedLink(links []*ports.ProjectedLink, fromURN string, relation string, toURN string) bool {
	for _, link := range links {
		if link.FromURN == fromURN && link.Relation == relation && link.ToURN == toURN {
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
