package questionnaire

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/evidencepackets"
	"github.com/writer/cerebro/internal/ports"
)

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
	handler := NewHandler(store, Options{
		Scope: func(r *http.Request) (Scope, error) {
			return Scope{TenantID: r.URL.Query().Get("tenant_id"), Limit: 25}, nil
		},
		Evidence: func(r *http.Request, scope Scope) ([]evidencepackets.QuestionnaireAnswer, error) {
			evidenceRequestTenant = r.URL.Query().Get("tenant_id")
			evidenceScopeTenant = scope.TenantID
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
