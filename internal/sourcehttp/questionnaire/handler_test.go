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

func TestUpdateQuestionMapsRequiredEvidenceSlots(t *testing.T) {
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
	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs/run-1/questions", strings.NewReader(`{"question_id":"q-1","required_evidence_slots":["audit_report"],"mapped_controls":["SOC2-CC7.2"],"owner_id":"security@example.com","reason":"Mapped from intake review."}`))
	req.SetPathValue("runID", "run-1")
	recorder := httptest.NewRecorder()

	handler.UpdateQuestion(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if got := store.saved.Questions[0].RequiredSlots; len(got) != 1 || got[0] != "audit_report" {
		t.Fatalf("required slots = %#v, want audit_report", got)
	}
	if got := store.saved.Questions[0].MappedControls; len(got) != 1 || got[0] != "SOC2-CC7.2" {
		t.Fatalf("mapped controls = %#v, want SOC2-CC7.2", got)
	}
	if store.saved.Questions[0].OwnerID != "security@example.com" {
		t.Fatalf("owner = %q, want security@example.com", store.saved.Questions[0].OwnerID)
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

func TestListRunsIncludesAnswerRowsAndQueueSummary(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := &processRunStore{
		listRecords: []*ports.QuestionnaireRunRecord{{
			QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{TenantID: "tenant-1", RunID: "run-1", Title: "Customer review"},
			QuestionnaireRunSource:   ports.QuestionnaireRunSource{Direction: ports.QuestionnaireDirectionCustomerSecurityReview, CustomerName: "Acme"},
			QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{Status: ports.QuestionnaireStatusNeedsInput, BlockedAnswerCount: 1, MissingEvidence: 1, UnassignedCount: 1},
			QuestionnaireRunContent: ports.QuestionnaireRunContent{
				Questions: []ports.QuestionnaireQuestion{{ID: "q-1", Question: "Attach SOC 2 report.", RequiredSlots: []string{"audit_report"}}},
				Answers: []ports.QuestionnaireRunAnswer{{
					ID:          "answer-1",
					QuestionID:  "q-1",
					Question:    "Attach SOC 2 report.",
					AnswerState: ports.QuestionnaireAnswerBlocked,
					ReviewState: ports.QuestionnaireReviewBlocked,
				}},
			},
			QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{CreatedAt: now, UpdatedAt: now},
		}},
		summary: ports.QuestionnaireRunSummary{TotalRuns: 5, BlockedAnswers: 4, MissingEvidence: 3, UnassignedQuestions: 2},
	}
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: "tenant-1", Limit: 25}, nil
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/grc/questionnaire-runs", nil)
	recorder := httptest.NewRecorder()

	handler.ListRuns(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var response runsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Summary.TotalRuns != 5 || response.Summary.BlockedAnswers != 4 {
		t.Fatalf("summary = %#v, want store aggregate", response.Summary)
	}
	if len(response.Runs) != 1 || len(response.Runs[0].Answers) != 1 || response.Runs[0].Answers[0].QuestionID != "q-1" {
		t.Fatalf("list response answers = %#v, want answer rows", response.Runs)
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

	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs/run-1/process?tenant_id=query-tenant&source_id=query-source&runtime_id=query-runtime&vendor_urn=urn:cerebro:query-tenant:vendor:bad", strings.NewReader(`{"tenant_id":"tenant-body"}`))
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

func TestProcessRunClearsCallerScopeWhenRunScopeIsEmpty(t *testing.T) {
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
	var evidenceRequestSource string
	var evidenceRequestRuntime string
	var evidenceRequestVendor string
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: r.URL.Query().Get("tenant_id"), SourceID: r.URL.Query().Get("source_id"), RuntimeID: r.URL.Query().Get("runtime_id"), VendorURN: r.URL.Query().Get("vendor_urn"), Limit: 25}, nil
		},
		Evidence: func(r *http.Request, scope Scope) ([]evidencepackets.QuestionnaireAnswer, error) {
			evidenceRequestSource = r.URL.Query().Get("source_id")
			evidenceRequestRuntime = r.URL.Query().Get("runtime_id")
			evidenceRequestVendor = r.URL.Query().Get("vendor_urn")
			if scope.SourceID != "" || scope.RuntimeID != "" || scope.VendorURN != "" {
				t.Fatalf("scope = source %q runtime %q vendor %q, want empty run scope", scope.SourceID, scope.RuntimeID, scope.VendorURN)
			}
			return nil, nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs/run-1/process?tenant_id=query-tenant&source_id=query-source&runtime_id=query-runtime&vendor_urn=urn:cerebro:query-tenant:vendor:bad", strings.NewReader(`{"tenant_id":"tenant-body"}`))
	req.SetPathValue("runID", "run-1")
	recorder := httptest.NewRecorder()

	handler.ProcessRun(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if evidenceRequestSource != "" || evidenceRequestRuntime != "" || evidenceRequestVendor != "" {
		t.Fatalf("request scope source/runtime/vendor = %q/%q/%q, want empty", evidenceRequestSource, evidenceRequestRuntime, evidenceRequestVendor)
	}
}

func TestSummarizeViewsCountsOnlyOpenDueRuns(t *testing.T) {
	dueAt := time.Now().Add(-time.Hour)

	summary := summarizeViews([]runView{
		{runViewWorkflow: runViewWorkflow{Status: ports.QuestionnaireStatusApproved, DueAt: &dueAt}, runViewCounts: runViewCounts{BlockedAnswerCount: 10}},
		{runViewWorkflow: runViewWorkflow{Status: ports.QuestionnaireStatusRejected, DueAt: &dueAt}, runViewCounts: runViewCounts{BlockedAnswerCount: 10}},
		{runViewWorkflow: runViewWorkflow{Status: ports.QuestionnaireStatusNeedsInput, DueAt: &dueAt}, runViewCounts: runViewCounts{BlockedAnswerCount: 1}},
	})

	if summary.DueRuns != 1 || summary.BlockedAnswers != 1 {
		t.Fatalf("summary = %#v, want one open due run and one blocked answer", summary)
	}
}

func TestRunViewJSONStaysFlat(t *testing.T) {
	payload, err := json.Marshal(runView{
		runViewIdentity: runViewIdentity{ID: "run-1", RunID: "run-1", TenantID: "tenant-1", Title: "Customer review", Direction: ports.QuestionnaireDirectionCustomerSecurityReview},
		runViewParties:  runViewParties{Requester: "sales@example.com", CustomerName: "Acme", OwnerID: "security@example.com"},
		runViewWorkflow: runViewWorkflow{Status: ports.QuestionnaireStatusNeedsInput},
		runViewCounts:   runViewCounts{QuestionCount: 1, MissingEvidenceCount: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"run_id", "tenant_id", "customer_name", "owner_id", "status", "question_count", "missing_evidence_count"} {
		if _, ok := body[key]; !ok {
			t.Fatalf("missing flat JSON key %q in %s", key, payload)
		}
	}
}

type processRunStore struct {
	ports.StateStore
	record      ports.QuestionnaireRunRecord
	listRecords []*ports.QuestionnaireRunRecord
	summary     ports.QuestionnaireRunSummary
	saved       ports.QuestionnaireRunRecord
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
	return s.listRecords, nil
}

func (s *processRunStore) SummarizeQuestionnaireRuns(context.Context, ports.QuestionnaireRunFilter) (ports.QuestionnaireRunSummary, error) {
	return s.summary, nil
}

func (s *processRunStore) ListQuestionnaireRunEvents(context.Context, ports.QuestionnaireRunEventFilter) ([]*ports.QuestionnaireRunEventRecord, error) {
	return nil, nil
}
