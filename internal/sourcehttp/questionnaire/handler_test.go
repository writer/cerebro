package questionnaire

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/evidencepackets"
	"github.com/writer/cerebro/internal/fabriccontract"
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
	locator := store.saved.Questions[0].SourceLocator
	if locator == nil || locator.SourceFormat != "csv" || locator.RowNumber != 2 || locator.ColumnName != "question" {
		t.Fatalf("CSV source locator = %#v, want row 2 question column", locator)
	}
}

func TestCreateRunParsesXLSXIntakeFile(t *testing.T) {
	store := &processRunStore{}
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: firstNonEmpty(r.URL.Query().Get("tenant_id"), "tenant-1"), Limit: 25}, nil
		},
		Actor: func(context.Context) string { return "grc@example.com" },
	})
	body := mustJSON(t, map[string]any{
		"tenant_id":           "tenant-1",
		"direction":           "customer_security_review",
		"title":               "Acme security review",
		"customer_name":       "Acme",
		"source_filename":     "security-questionnaire.xlsx",
		"source_format":       "xlsx",
		"intake_format":       "xlsx",
		"intake_content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"intake_file_base64":  base64.StdEncoding.EncodeToString(testXLSXWorkbook(t)),
	})
	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs", strings.NewReader(body))
	recorder := httptest.NewRecorder()

	handler.CreateRun(recorder, req)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	if len(store.saved.Questions) != 2 {
		t.Fatalf("questions = %d, want 2: %#v", len(store.saved.Questions), store.saved.Questions)
	}
	if store.saved.Questions[0].Question != "Do you enforce MFA?" || store.saved.Questions[0].Section != "Access" {
		t.Fatalf("first question = %#v, want mapped XLSX question", store.saved.Questions[0])
	}
	if got := store.saved.Questions[0].RequiredSlots; len(got) != 1 || got[0] != "identity_mfa" {
		t.Fatalf("required slots = %#v, want identity_mfa", got)
	}
	locator := store.saved.Questions[0].SourceLocator
	if locator == nil || locator.SourceFormat != "xlsx" || locator.SourceFilename != "security-questionnaire.xlsx" || locator.SheetName != "sheet1" || locator.RowNumber != 2 || locator.Cell != "B2" {
		t.Fatalf("XLSX source locator = %#v, want sheet1 row 2 cell B2", locator)
	}
	if store.saved.Attributes["intake_file_attached"] != "true" || store.saved.Attributes["intake_format"] != "xlsx" {
		t.Fatalf("attributes = %#v, want xlsx attachment metadata", store.saved.Attributes)
	}
}

func TestCreateRunAttributesIgnoreReservedGraphAttributes(t *testing.T) {
	attrs := createRunAttributes(createRequest{
		Attributes: map[string]string{
			"questionnaire_urn":   "urn:cerebro:tenant-1:vendor:core-sso",
			"source_artifact_urn": "urn:cerebro:tenant-1:vendor:core-sso",
			"business_unit":       "enterprise",
		},
	}, 1)
	if _, ok := attrs["questionnaire_urn"]; ok {
		t.Fatalf("attributes = %#v, want questionnaire_urn filtered", attrs)
	}
	if _, ok := attrs["source_artifact_urn"]; ok {
		t.Fatalf("attributes = %#v, want source_artifact_urn filtered", attrs)
	}
	if attrs["business_unit"] != "enterprise" {
		t.Fatalf("attributes = %#v, want non-reserved attributes retained", attrs)
	}
}

func TestCreateRunSucceedsWhenProjectionFailsAfterSave(t *testing.T) {
	store := &processRunStore{}
	var bumpedTenant string
	projectionAttempted := make(chan struct{}, 1)
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: firstNonEmpty(r.URL.Query().Get("tenant_id"), "tenant-1"), Limit: 25}, nil
		},
		Actor:           func(context.Context) string { return "grc@example.com" },
		BumpCache:       func(_ context.Context, tenantID string) { bumpedTenant = tenantID },
		ProjectionState: failingQuestionnaireProjectionStore{attempted: projectionAttempted},
	})
	body := `{
		"tenant_id": "tenant-1",
		"direction": "customer_security_review",
		"title": "Acme security review",
		"source_format": "csv",
		"intake_text": "question\nDo you enforce MFA?"
	}`
	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs", strings.NewReader(body))
	recorder := httptest.NewRecorder()

	handler.CreateRun(recorder, req)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	if store.saved.RunID == "" {
		t.Fatalf("saved run is empty: %#v", store.saved)
	}
	if bumpedTenant != "tenant-1" {
		t.Fatalf("bumped tenant = %q, want tenant-1", bumpedTenant)
	}
	select {
	case <-projectionAttempted:
	case <-time.After(time.Second):
		t.Fatal("projection writer was not called")
	}
}

func TestCreateRunDoesNotWaitForProjection(t *testing.T) {
	store := &processRunStore{}
	releaseProjection := make(chan struct{})
	defer close(releaseProjection)
	projectionStarted := make(chan struct{}, 1)
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: firstNonEmpty(r.URL.Query().Get("tenant_id"), "tenant-1"), Limit: 25}, nil
		},
		Actor: func(context.Context) string { return "grc@example.com" },
		ProjectionState: blockingQuestionnaireProjectionStore{
			started: projectionStarted,
			release: releaseProjection,
		},
	})
	body := `{
		"tenant_id": "tenant-1",
		"direction": "customer_security_review",
		"title": "Acme security review",
		"source_format": "csv",
		"intake_text": "question\nDo you enforce MFA?"
	}`
	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	done := make(chan struct{})

	go func() {
		handler.CreateRun(recorder, req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("CreateRun waited for projection writer")
	}
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	select {
	case <-projectionStarted:
	case <-time.After(time.Second):
		t.Fatal("projection writer was not called")
	}
}

func TestCreateRunInfersXLSXFromFilenameWhenMimeTypeIsGeneric(t *testing.T) {
	store := &processRunStore{}
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: firstNonEmpty(r.URL.Query().Get("tenant_id"), "tenant-1"), Limit: 25}, nil
		},
		Actor: func(context.Context) string { return "grc@example.com" },
	})
	body := mustJSON(t, map[string]any{
		"tenant_id":           "tenant-1",
		"direction":           "customer_security_review",
		"title":               "Acme security review",
		"source_filename":     "security-questionnaire.xlsx",
		"intake_content_type": "application/octet-stream",
		"intake_file_base64":  base64.StdEncoding.EncodeToString(testXLSXWorkbook(t)),
	})
	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs", strings.NewReader(body))
	recorder := httptest.NewRecorder()

	handler.CreateRun(recorder, req)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	if len(store.saved.Questions) != 2 {
		t.Fatalf("questions = %d, want 2: %#v", len(store.saved.Questions), store.saved.Questions)
	}
	if store.saved.Attributes["intake_format"] != "xlsx" {
		t.Fatalf("intake format attribute = %q, want xlsx", store.saved.Attributes["intake_format"])
	}
	locator := store.saved.Questions[0].SourceLocator
	if locator == nil || locator.SourceFormat != "xlsx" || locator.Cell != "B2" {
		t.Fatalf("inferred XLSX source locator = %#v, want workbook cell context", locator)
	}
}

func TestCreateRunParsesPDFIntakeFile(t *testing.T) {
	store := &processRunStore{}
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: firstNonEmpty(r.URL.Query().Get("tenant_id"), "tenant-1"), Limit: 25}, nil
		},
		Actor: func(context.Context) string { return "grc@example.com" },
	})
	body := mustJSON(t, map[string]any{
		"tenant_id":           "tenant-1",
		"direction":           "customer_security_review",
		"title":               "Acme security review",
		"source_filename":     "security-questionnaire.pdf",
		"source_format":       "pdf",
		"intake_format":       "pdf",
		"intake_content_type": "application/pdf",
		"intake_file_base64":  base64.StdEncoding.EncodeToString(testPDFWithPrompts()),
	})
	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs", strings.NewReader(body))
	recorder := httptest.NewRecorder()

	handler.CreateRun(recorder, req)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	if len(store.saved.Questions) != 2 {
		t.Fatalf("questions = %d, want 2: %#v", len(store.saved.Questions), store.saved.Questions)
	}
	if store.saved.Questions[0].Question != "Do you enforce MFA?" || store.saved.Questions[1].Question != "Attach SOC 2 report." {
		t.Fatalf("questions = %#v, want extracted PDF prompts", store.saved.Questions)
	}
	locator := store.saved.Questions[0].SourceLocator
	if locator == nil || locator.SourceFormat != "pdf" || locator.SourceFilename != "security-questionnaire.pdf" || locator.LineNumber == 0 {
		t.Fatalf("PDF source locator = %#v, want file and line context", locator)
	}
}

func TestCreateRunStoresPortalMetadataAndParsesPortalText(t *testing.T) {
	store := &processRunStore{}
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: firstNonEmpty(r.URL.Query().Get("tenant_id"), "tenant-1"), Limit: 25}, nil
		},
		Actor: func(context.Context) string { return "grc@example.com" },
	})
	body := mustJSON(t, map[string]any{
		"tenant_id":           "tenant-1",
		"direction":           "customer_security_review",
		"title":               "Portal review",
		"source_format":       "portal",
		"intake_format":       "portal",
		"portal_url":          "https://portal.example.test/review/123",
		"portal_instructions": "Use SSO and route missing access to sales ops.",
		"intake_text":         "Access:\nQuestion 1: Do you enforce MFA?\nSave\nAudit:\nQuestion: Attach SOC 2 report.",
	})
	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs", strings.NewReader(body))
	recorder := httptest.NewRecorder()

	handler.CreateRun(recorder, req)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	if len(store.saved.Questions) != 2 {
		t.Fatalf("questions = %d, want 2: %#v", len(store.saved.Questions), store.saved.Questions)
	}
	if store.saved.Questions[0].Section != "Access" || store.saved.Questions[1].Section != "Audit" {
		t.Fatalf("sections = %#v, want portal sections", store.saved.Questions)
	}
	if store.saved.Attributes["portal_url"] != "https://portal.example.test/review/123" ||
		store.saved.Attributes["portal_status"] != "questions_captured" ||
		store.saved.Attributes["portal_instructions"] != "Use SSO and route missing access to sales ops." {
		t.Fatalf("attributes = %#v, want portal metadata", store.saved.Attributes)
	}
	locator := store.saved.Questions[0].SourceLocator
	if locator == nil || locator.SourceFormat != "portal" || locator.PortalURL != "https://portal.example.test/review/123" || locator.LineNumber == 0 {
		t.Fatalf("portal source locator = %#v, want portal URL and line context", locator)
	}
}

func TestCreateRunAllowsPortalCaptureWithoutQuestions(t *testing.T) {
	store := &processRunStore{}
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: firstNonEmpty(r.URL.Query().Get("tenant_id"), "tenant-1"), Limit: 25}, nil
		},
		Actor: func(context.Context) string { return "grc@example.com" },
	})
	body := mustJSON(t, map[string]any{
		"tenant_id":           "tenant-1",
		"direction":           "customer_security_review",
		"title":               "Portal review",
		"source_format":       "portal",
		"intake_format":       "portal",
		"portal_url":          "https://portal.example.test/review/123",
		"portal_instructions": "Capture questions after account access is granted.",
	})
	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs", strings.NewReader(body))
	recorder := httptest.NewRecorder()

	handler.CreateRun(recorder, req)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	if len(store.saved.Questions) != 0 {
		t.Fatalf("questions = %#v, want none before portal capture", store.saved.Questions)
	}
	if store.saved.Status != ports.QuestionnaireStatusIntake {
		t.Fatalf("status = %q, want intake", store.saved.Status)
	}
	if store.saved.Attributes["portal_status"] != "needs_capture" || store.saved.Attributes["portal_url"] == "" {
		t.Fatalf("attributes = %#v, want portal capture metadata", store.saved.Attributes)
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

func TestCommentRunAllowsRunLevelComment(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := &processRunStore{
		record: ports.QuestionnaireRunRecord{
			QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{TenantID: "tenant-1", RunID: "run-1", Title: "Portal review"},
			QuestionnaireRunSource:   ports.QuestionnaireRunSource{Direction: ports.QuestionnaireDirectionCustomerSecurityReview},
			QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{Status: ports.QuestionnaireStatusIntake},
			QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{
				Attributes: map[string]string{"portal_status": "needs_capture"},
				CreatedAt:  now,
				UpdatedAt:  now,
			},
		},
	}
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: firstNonEmpty(r.URL.Query().Get("tenant_id"), "tenant-1"), Limit: 25}, nil
		},
		Actor: func(context.Context) string { return "security@example.com" },
	})
	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs/run-1/comments", strings.NewReader(`{"body":"Portal access requested from account owner."}`))
	req.SetPathValue("runID", "run-1")
	recorder := httptest.NewRecorder()

	handler.CommentRun(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if len(store.saved.Comments) != 1 || store.saved.Comments[0].QuestionID != "" {
		t.Fatalf("comments = %#v, want run-level comment", store.saved.Comments)
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

func TestCommentRunRejectsOversizedBody(t *testing.T) {
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
			return Scope{TenantID: "tenant-1", Limit: 25}, nil
		},
		Actor: func(context.Context) string { return "security@example.com" },
	})
	body := `{"question_id":"q-1","body":"` + strings.Repeat("a", 600<<10) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs/run-1/comments", strings.NewReader(body))
	req.SetPathValue("runID", "run-1")
	recorder := httptest.NewRecorder()

	handler.CommentRun(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
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

func TestAssignRunAllowsRunLevelAssignment(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := &processRunStore{
		record: ports.QuestionnaireRunRecord{
			QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{TenantID: "tenant-1", RunID: "run-1", Title: "Portal review"},
			QuestionnaireRunSource:   ports.QuestionnaireRunSource{Direction: ports.QuestionnaireDirectionCustomerSecurityReview},
			QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{Status: ports.QuestionnaireStatusIntake},
			QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{
				Attributes: map[string]string{"portal_status": "needs_capture"},
				CreatedAt:  now,
				UpdatedAt:  now,
			},
		},
	}
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: firstNonEmpty(r.URL.Query().Get("tenant_id"), "tenant-1"), Limit: 25}, nil
		},
		Actor: func(context.Context) string { return "security@example.com" },
	})
	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs/run-1/assignments", strings.NewReader(`{"owner_id":"sales-ops@example.com","reason":"Capture portal questions."}`))
	req.SetPathValue("runID", "run-1")
	recorder := httptest.NewRecorder()

	handler.AssignRun(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if len(store.saved.Assignments) != 1 || store.saved.Assignments[0].QuestionID != "" || store.saved.Assignments[0].OwnerID != "sales-ops@example.com" {
		t.Fatalf("assignments = %#v, want run-level assignment", store.saved.Assignments)
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

func TestUpdateQuestionRemovesStaleControlProjectionLinks(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	deletedLinks := make(chan *ports.ProjectedLink, 4)
	store := &processRunStore{
		record: ports.QuestionnaireRunRecord{
			QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{TenantID: "tenant-1", RunID: "run-1", Title: "Customer review"},
			QuestionnaireRunSource:   ports.QuestionnaireRunSource{Direction: ports.QuestionnaireDirectionCustomerSecurityReview},
			QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{Status: ports.QuestionnaireStatusNeedsInput},
			QuestionnaireRunContent: ports.QuestionnaireRunContent{
				Questions: []ports.QuestionnaireQuestion{{
					ID:             "q-1",
					Question:       "Attach SOC 2 report.",
					MappedControls: []string{"SOC2-CC6.1"},
					AnswerState:    ports.QuestionnaireAnswerNeedsReview,
					ReviewState:    ports.QuestionnaireReviewNeedsReview,
				}},
			},
			QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{CreatedAt: now, UpdatedAt: now},
		},
	}
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: firstNonEmpty(r.URL.Query().Get("tenant_id"), "tenant-1"), Limit: 25}, nil
		},
		Actor:           func(context.Context) string { return "security@example.com" },
		ProjectionState: recordingQuestionnaireProjectionStore{deleted: deletedLinks},
	})
	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs/run-1/questions", strings.NewReader(`{"question_id":"q-1","mapped_controls":["SOC2-CC7.2"],"reason":"Remapped from review."}`))
	req.SetPathValue("runID", "run-1")
	recorder := httptest.NewRecorder()

	handler.UpdateQuestion(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if got := store.record.Questions[0].MappedControls; len(got) != 1 || got[0] != "SOC2-CC6.1" {
		t.Fatalf("stored baseline controls = %#v, want original control", got)
	}
	if got := store.saved.Questions[0].MappedControls; len(got) != 1 || got[0] != "SOC2-CC7.2" {
		t.Fatalf("saved controls = %#v, want remapped control", got)
	}
	for {
		select {
		case link := <-deletedLinks:
			if link.Relation == fabriccontract.RelationSupports && link.Attributes["control_id"] == "SOC2-CC6.1" {
				return
			}
		case <-time.After(time.Second):
			t.Fatal("stale control projection link was not removed")
		}
	}
}

func TestLinkVendorAttachesVendorContext(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := &processRunStore{
		record: ports.QuestionnaireRunRecord{
			QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{TenantID: "tenant-1", RunID: "run-1", Title: "Vendor diligence"},
			QuestionnaireRunSource:   ports.QuestionnaireRunSource{Direction: ports.QuestionnaireDirectionCustomerSecurityReview},
			QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{Status: ports.QuestionnaireStatusNeedsInput},
			QuestionnaireRunContent: ports.QuestionnaireRunContent{
				Questions: []ports.QuestionnaireQuestion{{ID: "q-1", Question: "Attach vendor SOC 2 report."}},
			},
			QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{Attributes: map[string]string{"source": "portal"}, CreatedAt: now, UpdatedAt: now},
		},
	}
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: firstNonEmpty(r.URL.Query().Get("tenant_id"), "tenant-1"), Limit: 25}, nil
		},
		Actor: func(context.Context) string { return "risk@example.com" },
	})
	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs/run-1/vendor-link", strings.NewReader(`{"vendor_urn":"urn:cerebro:tenant-1:vendor:okta","vendor_id":"okta","reason":"Matched intake requester."}`))
	req.SetPathValue("runID", "run-1")
	recorder := httptest.NewRecorder()

	handler.LinkVendor(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if store.saved.Direction != ports.QuestionnaireDirectionVendorReview || store.saved.VendorURN != "urn:cerebro:tenant-1:vendor:okta" || store.saved.VendorID != "okta" {
		t.Fatalf("saved source = %#v, want linked vendor review", store.saved.QuestionnaireRunSource)
	}
	if store.saved.Attributes["linked_vendor_urn"] != "urn:cerebro:tenant-1:vendor:okta" || store.saved.Attributes["vendor_link_status"] != "linked" {
		t.Fatalf("attributes = %#v, want linked vendor metadata", store.saved.Attributes)
	}
	if len(store.saved.Timeline) == 0 || store.saved.Timeline[len(store.saved.Timeline)-1].EventType != ports.QuestionnaireEventVendorLinked {
		t.Fatalf("timeline = %#v, want vendor link event", store.saved.Timeline)
	}
	if store.savedEvent.EventType != ports.QuestionnaireEventVendorLinked || store.savedEvent.Payload["vendor_urn"] == "" {
		t.Fatalf("event = %#v, want persisted vendor link event", store.savedEvent)
	}
}

func TestLinkVendorRemovesVendorContext(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := &processRunStore{
		record: ports.QuestionnaireRunRecord{
			QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{TenantID: "tenant-1", RunID: "run-1", Title: "Vendor diligence"},
			QuestionnaireRunSource:   ports.QuestionnaireRunSource{Direction: ports.QuestionnaireDirectionVendorReview, VendorURN: "urn:cerebro:tenant-1:vendor:okta", VendorID: "okta"},
			QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{Status: ports.QuestionnaireStatusNeedsInput},
			QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{
				Attributes: map[string]string{
					"linked_vendor_urn":              "urn:cerebro:tenant-1:vendor:okta",
					"linked_vendor_id":               "okta",
					"vendor_link_previous_direction": ports.QuestionnaireDirectionCustomerSecurityReview,
					"vendor_link_reason":             "Matched intake requester.",
					"vendor_link_status":             "linked",
				},
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
	}
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: firstNonEmpty(r.URL.Query().Get("tenant_id"), "tenant-1"), Limit: 25}, nil
		},
		Actor: func(context.Context) string { return "risk@example.com" },
	})
	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs/run-1/vendor-link", strings.NewReader(`{"unlink":true}`))
	req.SetPathValue("runID", "run-1")
	recorder := httptest.NewRecorder()

	handler.LinkVendor(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if store.saved.VendorURN != "" || store.saved.VendorID != "" {
		t.Fatalf("vendor context = %q/%q, want cleared", store.saved.VendorURN, store.saved.VendorID)
	}
	if store.saved.Direction != ports.QuestionnaireDirectionCustomerSecurityReview {
		t.Fatalf("direction = %q, want customer_security_review", store.saved.Direction)
	}
	if store.saved.Attributes["linked_vendor_urn"] != "" ||
		store.saved.Attributes["vendor_link_previous_direction"] != "" ||
		store.saved.Attributes["vendor_link_reason"] != "" ||
		store.saved.Attributes["vendor_link_status"] != "unlinked" {
		t.Fatalf("attributes = %#v, want unlinked vendor metadata", store.saved.Attributes)
	}
}

func TestLinkVendorRejectsMissingVendorURN(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := &processRunStore{
		record: ports.QuestionnaireRunRecord{
			QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{TenantID: "tenant-1", RunID: "run-1", Title: "Vendor diligence"},
			QuestionnaireRunSource:   ports.QuestionnaireRunSource{Direction: ports.QuestionnaireDirectionCustomerSecurityReview},
			QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{Status: ports.QuestionnaireStatusNeedsInput},
			QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{CreatedAt: now, UpdatedAt: now},
		},
	}
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: firstNonEmpty(r.URL.Query().Get("tenant_id"), "tenant-1"), Limit: 25}, nil
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/grc/questionnaire-runs/run-1/vendor-link", strings.NewReader(`{"reason":"No selected vendor."}`))
	req.SetPathValue("runID", "run-1")
	recorder := httptest.NewRecorder()

	handler.LinkVendor(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
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

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func testXLSXWorkbook(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	writeZipFile(t, writer, "xl/worksheets/sheet1.xml", `<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1">
      <c r="A1" t="inlineStr"><is><t>section</t></is></c>
      <c r="B1" t="inlineStr"><is><t>question</t></is></c>
      <c r="C1" t="inlineStr"><is><t>required_evidence_slots</t></is></c>
      <c r="D1" t="inlineStr"><is><t>mapped_controls</t></is></c>
      <c r="E1" t="inlineStr"><is><t>owner_id</t></is></c>
    </row>
    <row r="2">
      <c r="A2" t="inlineStr"><is><t>Access</t></is></c>
      <c r="B2" t="inlineStr"><is><t>Do you enforce MFA?</t></is></c>
      <c r="C2" t="inlineStr"><is><t>identity_mfa</t></is></c>
      <c r="D2" t="inlineStr"><is><t>SOC2-CC6.1</t></is></c>
      <c r="E2" t="inlineStr"><is><t>security@example.com</t></is></c>
    </row>
    <row r="3">
      <c r="A3" t="inlineStr"><is><t>Audit</t></is></c>
      <c r="B3" t="inlineStr"><is><t>Attach SOC 2 report.</t></is></c>
      <c r="C3" t="inlineStr"><is><t>audit_report</t></is></c>
      <c r="D3" t="inlineStr"><is><t>SOC2-CC7.2</t></is></c>
      <c r="E3" t="inlineStr"><is><t>security@example.com</t></is></c>
    </row>
  </sheetData>
</worksheet>`)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func writeZipFile(t *testing.T, writer *zip.Writer, name string, body string) {
	t.Helper()
	file, err := writer.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
}

func testPDFWithPrompts() []byte {
	return []byte(`%PDF-1.4
1 0 obj
<< /Length 66 >>
stream
BT (Do you enforce MFA?) Tj (Attach SOC 2 report.) Tj ET
endstream
endobj
%%EOF`)
}

type processRunStore struct {
	ports.StateStore
	record      ports.QuestionnaireRunRecord
	listRecords []*ports.QuestionnaireRunRecord
	summary     ports.QuestionnaireRunSummary
	saved       ports.QuestionnaireRunRecord
	savedEvent  ports.QuestionnaireRunEventRecord
}

func (s *processRunStore) UpsertQuestionnaireRun(_ context.Context, record ports.QuestionnaireRunRecord, event ports.QuestionnaireRunEventRecord) (*ports.QuestionnaireRunRecord, error) {
	s.saved = record
	s.savedEvent = event
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

func (s *processRunStore) ListQuestionnaireVendorRollups(context.Context, ports.QuestionnaireVendorRollupFilter) ([]ports.QuestionnaireVendorRollupRecord, error) {
	return nil, nil
}

func (s *processRunStore) ListQuestionnaireRunEvents(context.Context, ports.QuestionnaireRunEventFilter) ([]*ports.QuestionnaireRunEventRecord, error) {
	return nil, nil
}

type failingQuestionnaireProjectionStore struct {
	ports.StateStore
	attempted chan struct{}
}

func (s failingQuestionnaireProjectionStore) UpsertProjectedEntity(context.Context, *ports.ProjectedEntity) error {
	s.signal()
	return errors.New("projection unavailable")
}

func (s failingQuestionnaireProjectionStore) UpsertProjectedLink(context.Context, *ports.ProjectedLink) error {
	s.signal()
	return errors.New("projection unavailable")
}

func (s failingQuestionnaireProjectionStore) signal() {
	if s.attempted == nil {
		return
	}
	select {
	case s.attempted <- struct{}{}:
	default:
	}
}

type blockingQuestionnaireProjectionStore struct {
	ports.StateStore
	started chan struct{}
	release chan struct{}
}

func (s blockingQuestionnaireProjectionStore) UpsertProjectedEntity(ctx context.Context, _ *ports.ProjectedEntity) error {
	if s.started != nil {
		select {
		case s.started <- struct{}{}:
		default:
		}
	}
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s blockingQuestionnaireProjectionStore) UpsertProjectedLink(context.Context, *ports.ProjectedLink) error {
	return nil
}

type recordingQuestionnaireProjectionStore struct {
	ports.StateStore
	deleted chan *ports.ProjectedLink
}

func (s recordingQuestionnaireProjectionStore) UpsertProjectedEntity(context.Context, *ports.ProjectedEntity) error {
	return nil
}

func (s recordingQuestionnaireProjectionStore) UpsertProjectedLink(context.Context, *ports.ProjectedLink) error {
	return nil
}

func (s recordingQuestionnaireProjectionStore) DeleteProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if s.deleted == nil {
		return nil
	}
	select {
	case s.deleted <- link:
	default:
	}
	return nil
}
