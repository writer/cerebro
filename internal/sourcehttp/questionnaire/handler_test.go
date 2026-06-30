package questionnaire

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/evidencepackets"
	"github.com/writer/cerebro/internal/ports"
)

func TestCreateRunParsesCSVIntakeText(t *testing.T) {
	store := &processRunStore{}
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: firstNonEmpty(r.URL.Query().Get("tenant_id"), "tenant-1"), Limit: 25}, nil
		},
		Actor: func(context.Context) string { return "grc@example.com" },
	})
	body := `{
		"tenant_id": "tenant-1",
		"direction": "customer_security_review",
		"title": "Acme security review",
		"customer_name": "Acme",
		"source_format": "csv",
		"intake_text": "section,question,required_evidence_slots,mapped_controls,owner\nAccess,Do you enforce MFA?,identity_mfa,SOC2-CC6.1,security@example.com\nAudit,Attach SOC 2 report.,audit_report,SOC2-CC7.2,security@example.com"
	}`
	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs", strings.NewReader(body))
	recorder := httptest.NewRecorder()

	handler.CreateRun(recorder, req)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	if len(store.saved.Questions) != 2 {
		t.Fatalf("questions = %d, want 2: %#v", len(store.saved.Questions), store.saved.Questions)
	}
	if store.saved.Questions[0].Question == "" || store.saved.Questions[0].OwnerID != "security@example.com" {
		t.Fatalf("first question not mapped from CSV: %#v", store.saved.Questions[0])
	}
}

func TestCommentRunRecordsComment(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := &processRunStore{
		record: ports.QuestionnaireRunRecord{
			QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{TenantID: "tenant-1", RunID: "run-1", Title: "Customer review"},
			QuestionnaireRunSource:   ports.QuestionnaireRunSource{Direction: ports.QuestionnaireDirectionCustomerSecurityReview},
			QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{Status: ports.QuestionnaireStatusNeedsInput},
			QuestionnaireRunContent: ports.QuestionnaireRunContent{
				Questions: []ports.QuestionnaireQuestion{{ID: "q-1", Question: "Attach SOC 2 report."}},
			},
			QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{CreatedAt: now, UpdatedAt: now},
		},
	}
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: firstNonEmpty(r.URL.Query().Get("tenant_id"), "tenant-1"), Limit: 25}, nil
		},
		Actor: func(context.Context) string { return "security@example.com" },
	})
	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs/run-1/comments", strings.NewReader(`{"question_id":"q-1","body":"SOC 2 request sent to the owner."}`))
	req.SetPathValue("runID", "run-1")
	recorder := httptest.NewRecorder()

	handler.CommentRun(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if len(store.saved.Comments) != 1 || store.saved.Comments[0].Body != "SOC 2 request sent to the owner." {
		t.Fatalf("comments = %#v, want recorded comment", store.saved.Comments)
	}
	if store.saved.Comments[0].ActorID != "security@example.com" {
		t.Fatalf("comment actor = %q, want authenticated actor", store.saved.Comments[0].ActorID)
	}
	var response runResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Run.Comments) != 1 {
		t.Fatalf("response comments = %#v, want recorded comment", response.Run.Comments)
	}
}

func TestCommentRunRejectsForgedActorAndUnknownQuestion(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := &processRunStore{
		record: ports.QuestionnaireRunRecord{
			QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{TenantID: "tenant-1", RunID: "run-1", Title: "Customer review"},
			QuestionnaireRunSource:   ports.QuestionnaireRunSource{Direction: ports.QuestionnaireDirectionCustomerSecurityReview},
			QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{Status: ports.QuestionnaireStatusNeedsInput},
			QuestionnaireRunContent: ports.QuestionnaireRunContent{
				Questions: []ports.QuestionnaireQuestion{{ID: "q-1", Question: "Attach SOC 2 report."}},
			},
			QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{CreatedAt: now, UpdatedAt: now},
		},
	}
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: firstNonEmpty(r.URL.Query().Get("tenant_id"), "tenant-1"), Limit: 25}, nil
		},
		Actor: func(context.Context) string { return "security@example.com" },
	})

	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs/run-1/comments", strings.NewReader(`{"question_id":"q-1","body":"Forged.","actor_id":"attacker@example.com"}`))
	req.SetPathValue("runID", "run-1")
	recorder := httptest.NewRecorder()
	handler.CommentRun(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("forged actor status = %d, want 400: %s", recorder.Code, recorder.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs/run-1/comments", strings.NewReader(`{"question_id":"missing","body":"No row."}`))
	req.SetPathValue("runID", "run-1")
	recorder = httptest.NewRecorder()
	handler.CommentRun(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown question status = %d, want 400: %s", recorder.Code, recorder.Body.String())
	}
}

func TestAssignRunRejectsEmptyOwnerAndNestedBody(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := &processRunStore{
		record: ports.QuestionnaireRunRecord{
			QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{TenantID: "tenant-1", RunID: "run-1", Title: "Customer review"},
			QuestionnaireRunSource:   ports.QuestionnaireRunSource{Direction: ports.QuestionnaireDirectionCustomerSecurityReview},
			QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{Status: ports.QuestionnaireStatusNeedsInput},
			QuestionnaireRunContent: ports.QuestionnaireRunContent{
				Questions: []ports.QuestionnaireQuestion{{ID: "q-1", Question: "Attach SOC 2 report."}},
			},
			QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{CreatedAt: now, UpdatedAt: now},
		},
	}
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: firstNonEmpty(r.URL.Query().Get("tenant_id"), "tenant-1"), Limit: 25}, nil
		},
		Actor: func(context.Context) string { return "security@example.com" },
	})

	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs/run-1/assignments", strings.NewReader(`{"question_id":"q-1","reason":"No owner"}`))
	req.SetPathValue("runID", "run-1")
	recorder := httptest.NewRecorder()
	handler.AssignRun(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("empty owner status = %d, want 400: %s", recorder.Code, recorder.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs/run-1/assignments", strings.NewReader(`{"assignment":{"question_id":"q-1","owner_id":"security@example.com"}}`))
	req.SetPathValue("runID", "run-1")
	recorder = httptest.NewRecorder()
	handler.AssignRun(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("nested assignment status = %d, want 400: %s", recorder.Code, recorder.Body.String())
	}
}

func TestCreateRunRejectsDelimitedIntakeWithoutQuestionHeader(t *testing.T) {
	store := &processRunStore{}
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: firstNonEmpty(r.URL.Query().Get("tenant_id"), "tenant-1"), Limit: 25}, nil
		},
		Actor: func(context.Context) string { return "grc@example.com" },
	})
	body := `{
		"tenant_id": "tenant-1",
		"direction": "customer_security_review",
		"title": "Acme security review",
		"source_format": "csv",
		"intake_text": "section,prompt_text\nAccess,Do you enforce MFA?"
	}`
	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs", strings.NewReader(body))
	recorder := httptest.NewRecorder()

	handler.CreateRun(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
	}
}

func TestProcessRunPassesScopedRequestToEvidenceResolver(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := &processRunStore{
		record: ports.QuestionnaireRunRecord{
			QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{
				TenantID: "tenant-body",
				RunID:    "run-1",
				Title:    "Customer review",
			},
			QuestionnaireRunSource: ports.QuestionnaireRunSource{
				Direction: ports.QuestionnaireDirectionCustomerSecurityReview,
				SourceID:  "source-okta",
				RuntimeID: "runtime-okta",
				VendorURN: "urn:cerebro:tenant-body:vendor:okta",
			},
			QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{
				Status: ports.QuestionnaireStatusIntake,
			},
			QuestionnaireRunContent: ports.QuestionnaireRunContent{
				Questions: []ports.QuestionnaireQuestion{{
					ID:       "q-1",
					Question: "Do you enforce MFA?",
				}},
			},
			QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
	}
	var evidenceRequestTenant string
	var evidenceScopeTenant string
	var evidenceRequestSource string
	var evidenceRequestRuntime string
	var evidenceRequestVendor string
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: r.URL.Query().Get("tenant_id"), SourceID: r.URL.Query().Get("source_id"), RuntimeID: r.URL.Query().Get("runtime_id"), Limit: 25}, nil
		},
		Evidence: func(r *http.Request, scope Scope) ([]evidencepackets.QuestionnaireAnswer, error) {
			evidenceRequestTenant = r.URL.Query().Get("tenant_id")
			evidenceScopeTenant = scope.TenantID
			evidenceRequestSource = r.URL.Query().Get("source_id")
			evidenceRequestRuntime = r.URL.Query().Get("runtime_id")
			evidenceRequestVendor = r.URL.Query().Get("vendor_urn")
			return nil, nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs/run-1/process", strings.NewReader(`{"tenant_id":"tenant-body"}`))
	req.SetPathValue("runID", "run-1")
	recorder := httptest.NewRecorder()

	handler.ProcessRun(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if evidenceRequestTenant != "tenant-body" || evidenceScopeTenant != "tenant-body" {
		t.Fatalf("evidence tenant request/scope = %q/%q, want tenant-body/tenant-body", evidenceRequestTenant, evidenceScopeTenant)
	}
	if evidenceRequestSource != "source-okta" || evidenceRequestRuntime != "runtime-okta" || evidenceRequestVendor == "" {
		t.Fatalf("evidence scope source/runtime/vendor = %q/%q/%q, want saved run context", evidenceRequestSource, evidenceRequestRuntime, evidenceRequestVendor)
	}
}

type processRunStore struct {
	ports.StateStore
	record ports.QuestionnaireRunRecord
	saved  ports.QuestionnaireRunRecord
}

func (s *processRunStore) UpsertQuestionnaireRun(_ context.Context, record ports.QuestionnaireRunRecord, _ ports.QuestionnaireRunEventRecord) (*ports.QuestionnaireRunRecord, error) {
	s.saved = record
	return &s.saved, nil
}

func (s *processRunStore) GetQuestionnaireRun(_ context.Context, filter ports.QuestionnaireRunFilter) (*ports.QuestionnaireRunRecord, error) {
	if filter.TenantID != s.record.TenantID || filter.RunID != s.record.RunID {
		return nil, ports.ErrQuestionnaireRunNotFound
	}
	record := s.record
	return &record, nil
}

func (s *processRunStore) ListQuestionnaireRuns(context.Context, ports.QuestionnaireRunFilter) ([]*ports.QuestionnaireRunRecord, error) {
	return nil, nil
}

func (s *processRunStore) ListQuestionnaireRunEvents(context.Context, ports.QuestionnaireRunEventFilter) ([]*ports.QuestionnaireRunEventRecord, error) {
	return nil, nil
}
