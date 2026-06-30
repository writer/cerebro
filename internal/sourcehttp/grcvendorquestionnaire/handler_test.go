package grcvendorquestionnaire

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/grcvendor"
	"github.com/writer/cerebro/internal/ports"
)

func TestApproveGRCVendorQuestionnaireReviewUsesAuthenticatedActor(t *testing.T) {
	store := newFakeGRCVendorQuestionnaireStore()
	store.record.Approvals = []ports.GRCVendorQuestionnaireApproval{{ID: "approval-fixed", Team: "security", ActorID: "prior-user", Decision: "approved"}}
	handler := newTestHandler(store)
	body := `{"approval":{"id":"approval-fixed","actor_id":"spoofed-user","decision":"approved","team":"security"},"approver":"body-approver"}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/grc/vendor/questionnaire/reviews/approve?review_id=review-1", strings.NewReader(body))

	handler.ApproveGRCVendorQuestionnaireReview(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if store.saved == nil || len(store.saved.Approvals) != 2 {
		t.Fatalf("saved approvals = %#v", store.saved)
	}
	approval := store.saved.Approvals[1]
	if approval.ActorID != "authenticated-user" {
		t.Fatalf("approval actor = %q", approval.ActorID)
	}
	if approval.ID == "approval-fixed" {
		t.Fatalf("approval ID was not regenerated for duplicate input")
	}
	if store.saved.Status != ports.GRCVendorQuestionnaireStatusApproved || store.saved.Decision != ports.GRCVendorQuestionnaireDecisionApprove {
		t.Fatalf("workflow = %q/%q", store.saved.Status, store.saved.Decision)
	}
	if len(store.events) != 1 || store.events[0].ActorID != "authenticated-user" {
		t.Fatalf("events = %#v", store.events)
	}
}

func TestApproveGRCVendorQuestionnaireReviewRejectsInvalidDecision(t *testing.T) {
	store := newFakeGRCVendorQuestionnaireStore()
	handler := newTestHandler(store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/grc/vendor/questionnaire/reviews/approve?review_id=review-1", strings.NewReader(`{"state":"not_allowed"}`))

	handler.ApproveGRCVendorQuestionnaireReview(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if store.saved != nil || len(store.events) != 0 {
		t.Fatalf("unexpected persisted mutation: saved=%#v events=%#v", store.saved, store.events)
	}
}

func TestCommentGRCVendorQuestionnaireReviewUsesAuthenticatedActor(t *testing.T) {
	store := newFakeGRCVendorQuestionnaireStore()
	store.record.Comments = []ports.GRCVendorQuestionnaireComment{{ID: "comment-fixed", ActorID: "prior-user", Body: "Existing note"}}
	handler := newTestHandler(store)
	body := `{"comment":{"id":"comment-fixed","actor_id":"spoofed-user","body":"Needs vendor owner follow-up.","scope":"owner"},"author":"body-author"}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/grc/vendor/questionnaire/reviews/comment?review_id=review-1", strings.NewReader(body))

	handler.CommentGRCVendorQuestionnaireReview(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if store.saved == nil || len(store.saved.Comments) != 2 {
		t.Fatalf("saved comments = %#v", store.saved)
	}
	comment := store.saved.Comments[1]
	if comment.ActorID != "authenticated-user" {
		t.Fatalf("comment actor = %q", comment.ActorID)
	}
	if comment.ID == "comment-fixed" {
		t.Fatalf("comment ID was not regenerated for duplicate input")
	}
}

func TestGRCVendorQuestionnaireAssignmentViewDoesNotInventQuestionID(t *testing.T) {
	views := grcVendorQuestionnaireAssignmentViews([]ports.GRCVendorQuestionnaireAssignment{
		{ID: "assignment-review-1-security", Team: "security", OwnerID: "security-owner"},
	})
	if len(views) != 1 {
		t.Fatalf("views = %#v", views)
	}
	if views[0].QuestionID != "" {
		t.Fatalf("question_id = %q", views[0].QuestionID)
	}
}

func newTestHandler(store *fakeGRCVendorQuestionnaireStore) *Handler {
	return NewHandler(store, Options{
		Scope: func(*http.Request) (Scope, error) {
			return Scope{TenantID: "tenant-1"}, nil
		},
		Actor: func(context.Context) string {
			return "authenticated-user"
		},
		WriteErr: func(w http.ResponseWriter, err error) {
			if errors.Is(err, grcvendor.ErrInvalidRequest) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
		},
	})
}

func newFakeGRCVendorQuestionnaireStore() *fakeGRCVendorQuestionnaireStore {
	now := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	return &fakeGRCVendorQuestionnaireStore{
		record: ports.GRCVendorQuestionnaireReviewRecord{
			GRCVendorQuestionnaireReviewIdentity: ports.GRCVendorQuestionnaireReviewIdentity{
				TenantID:  "tenant-1",
				ReviewID:  "review-1",
				VendorURN: "urn:cerebro:tenant-1:vendor:source:vendor-1",
				Title:     "Vendor questionnaire",
			},
			GRCVendorQuestionnaireReviewWorkflow: ports.GRCVendorQuestionnaireReviewWorkflow{
				Status:   ports.GRCVendorQuestionnaireStatusReadyForApproval,
				Decision: ports.GRCVendorQuestionnaireDecisionNeedsReview,
			},
			GRCVendorQuestionnaireReviewMetadata: ports.GRCVendorQuestionnaireReviewMetadata{
				Attributes: map[string]string{},
				CreatedAt:  now,
				UpdatedAt:  now,
			},
		},
	}
}

type fakeGRCVendorQuestionnaireStore struct {
	record ports.GRCVendorQuestionnaireReviewRecord
	saved  *ports.GRCVendorQuestionnaireReviewRecord
	events []*ports.GRCVendorQuestionnaireReviewEventRecord
}

func (s *fakeGRCVendorQuestionnaireStore) Ping(context.Context) error {
	return nil
}

func (s *fakeGRCVendorQuestionnaireStore) UpsertGRCVendorQuestionnaireReview(_ context.Context, record ports.GRCVendorQuestionnaireReviewRecord, event ports.GRCVendorQuestionnaireReviewEventRecord) (*ports.GRCVendorQuestionnaireReviewRecord, error) {
	copied := record
	s.record = copied
	s.saved = &copied
	event.Version = len(s.events) + 1
	s.events = append(s.events, &event)
	return &copied, nil
}

func (s *fakeGRCVendorQuestionnaireStore) GetGRCVendorQuestionnaireReview(_ context.Context, filter ports.GRCVendorQuestionnaireReviewFilter) (*ports.GRCVendorQuestionnaireReviewRecord, error) {
	if filter.TenantID != "" && filter.TenantID != s.record.TenantID {
		return nil, ports.ErrGRCVendorQuestionnaireReviewNotFound
	}
	if filter.ReviewID != "" && filter.ReviewID != s.record.ReviewID {
		return nil, ports.ErrGRCVendorQuestionnaireReviewNotFound
	}
	copied := s.record
	return &copied, nil
}

func (s *fakeGRCVendorQuestionnaireStore) ListGRCVendorQuestionnaireReviews(context.Context, ports.GRCVendorQuestionnaireReviewFilter) ([]*ports.GRCVendorQuestionnaireReviewRecord, error) {
	copied := s.record
	return []*ports.GRCVendorQuestionnaireReviewRecord{&copied}, nil
}

func (s *fakeGRCVendorQuestionnaireStore) ListGRCVendorQuestionnaireReviewEvents(context.Context, ports.GRCVendorQuestionnaireReviewEventFilter) ([]*ports.GRCVendorQuestionnaireReviewEventRecord, error) {
	return append([]*ports.GRCVendorQuestionnaireReviewEventRecord{}, s.events...), nil
}
