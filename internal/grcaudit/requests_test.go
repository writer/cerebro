package grcaudit

import (
	"errors"
	"testing"
	"time"
)

func TestEvidenceRequestSubmissionPreservesRevisionLineage(t *testing.T) {
	createdAt := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	input := testEvidenceRequestRevisionInput(createdAt)
	request, first, err := NewEvidenceRequest(CreateEvidenceRequestRequest{
		ID:           "request-a",
		TenantID:     "tenant-a",
		EngagementID: "engagement-a",
		Revision:     input,
		CreatedBy:    "auditor-a",
		CreatedAt:    createdAt,
	})
	if err != nil {
		t.Fatalf("NewEvidenceRequest() error = %v", err)
	}
	updated, submission, err := RecordEvidenceSubmission(request, 1, EvidenceSubmissionInput{
		ClaimIDs:           []string{"claim-b", "claim-a", "claim-a"},
		ArtifactVersionIDs: []string{"artifact-r1"},
		Message:            "Evidence for review.",
	}, "owner-a", createdAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("RecordEvidenceSubmission() error = %v", err)
	}
	if request.Version != 1 || request.Status != EvidenceRequestStatusOpen {
		t.Fatalf("original request mutated: %+v", request)
	}
	if updated.Version != 2 || updated.CurrentRevision != 1 || updated.CurrentRevisionID != first.ID || updated.Status != EvidenceRequestStatusSubmitted {
		t.Fatalf("submitted request = %+v", updated)
	}
	if len(submission.ClaimIDs) != 2 || submission.ClaimIDs[0] != "claim-a" || submission.ClaimIDs[1] != "claim-b" || submission.SubmissionHash == "" {
		t.Fatalf("submission = %+v", submission)
	}
	input.Status = EvidenceRequestStatusAccepted
	input.ChangeSummary = "Accept submitted evidence."
	accepted, second, err := ReviseEvidenceRequest(updated, 2, input, "auditor-a", createdAt.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("ReviseEvidenceRequest(accepted) error = %v", err)
	}
	if accepted.Version != 3 || accepted.CurrentRevision != 2 || second.Revision != 2 || second.PredecessorID != first.ID {
		t.Fatalf("accepted request/revision = %+v / %+v", accepted, second)
	}
	if _, _, err := RecordEvidenceSubmission(accepted, 3, EvidenceSubmissionInput{ClaimIDs: []string{"claim-c"}}, "owner-a", createdAt.Add(3*time.Hour)); err == nil {
		t.Fatal("RecordEvidenceSubmission(accepted) error = nil, want invalid state")
	}
}

func TestAuthorizeEvidenceRequestAccessDeniesMismatchedEngagement(t *testing.T) {
	engagement, _, err := NewEngagement(testCreateEngagementRequest())
	if err != nil {
		t.Fatalf("NewEngagement() error = %v", err)
	}
	request := EvidenceRequest{ID: "request-a", TenantID: "tenant-a", EngagementID: "engagement-b"}
	err = AuthorizeEvidenceRequestAccess(Principal{TenantID: "tenant-a", ID: "auditor-a"}, engagement, request, EngagementPermissionRead)
	if !errors.Is(err, ErrEvidenceRequestNotFound) {
		t.Fatalf("AuthorizeEvidenceRequestAccess() error = %v, want ErrEvidenceRequestNotFound", err)
	}
}

func testEvidenceRequestRevisionInput(start time.Time) EvidenceRequestRevisionInput {
	return EvidenceRequestRevisionInput{
		ObjectiveID:          "objective-a",
		SubjectIDs:           []string{"subject-b", "subject-a"},
		PeriodStart:          start,
		PeriodEnd:            start.AddDate(0, 1, 0),
		RequesterPrincipalID: "auditor-a",
		OwnerPrincipalID:     "owner-a",
		DueAt:                start.AddDate(0, 0, 14),
		ExpectedFormats:      []string{"application/json"},
		Instructions:         "Provide selected evidence claims.",
		Status:               EvidenceRequestStatusOpen,
	}
}
