package grcaudit

import (
	"errors"
	"testing"
	"time"
)

func TestAuthorizeEngagementAccessDeniesSameTenantForeignEngagement(t *testing.T) {
	engagement, _, err := NewEngagement(testCreateEngagementRequest())
	if err != nil {
		t.Fatalf("NewEngagement() error = %v", err)
	}
	if err := AuthorizeEngagementAccess(Principal{TenantID: "tenant-a", ID: "auditor-a"}, engagement, EngagementPermissionRead); err != nil {
		t.Fatalf("assigned auditor read error = %v", err)
	}
	if err := AuthorizeEngagementAccess(Principal{TenantID: "tenant-a", ID: "auditor-b"}, engagement, EngagementPermissionRead); !errors.Is(err, ErrEngagementNotFound) {
		t.Fatalf("same-tenant foreign engagement error = %v, want ErrEngagementNotFound", err)
	}
	if err := AuthorizeEngagementAccess(Principal{TenantID: "tenant-b", ID: "auditor-a"}, engagement, EngagementPermissionRead); !errors.Is(err, ErrEngagementNotFound) {
		t.Fatalf("foreign tenant engagement error = %v, want ErrEngagementNotFound", err)
	}
	if err := AuthorizeEngagementAccess(Principal{TenantID: "tenant-a", ID: "manager", TenantWide: true}, engagement, EngagementPermissionManage); err != nil {
		t.Fatalf("tenant-wide manager error = %v", err)
	}
	if err := AuthorizeEngagementAccess(Principal{TenantID: "tenant-a", ID: "auditor-a"}, engagement, EngagementPermissionDeliver); !errors.Is(err, ErrEngagementNotFound) {
		t.Fatalf("auditor delivery error = %v, want non-disclosing not found", err)
	}
}

func TestEngagementRevisionsAreImmutableAcrossParticipantAndScopeChanges(t *testing.T) {
	request := testCreateEngagementRequest()
	engagement, first, err := NewEngagement(request)
	if err != nil {
		t.Fatalf("NewEngagement() error = %v", err)
	}
	withOwner, participant, err := GrantParticipant(engagement, 1, ParticipantInput{PrincipalID: "owner-a", Role: ParticipantRoleClientOwner}, request.CreatedAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("GrantParticipant() error = %v", err)
	}
	if engagement.Version != 1 || engagement.CurrentRevision != 1 || len(engagement.Participants) != 1 {
		t.Fatalf("original engagement mutated: %+v", engagement)
	}
	if withOwner.Version != 2 || withOwner.CurrentRevision != 1 || participant.Version != 1 {
		t.Fatalf("participant update = engagement %+v participant %+v", withOwner, participant)
	}
	frameworks := []string{"framework-r2", "framework-r1"}
	nextInput := request.Revision
	nextInput.FrameworkRevisionIDs = frameworks
	nextInput.Status = EngagementStatusFieldwork
	nextInput.ChangeSummary = "Start fieldwork."
	revised, second, err := ReviseEngagement(withOwner, 2, nextInput, "lead-a", request.CreatedAt.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("ReviseEngagement() error = %v", err)
	}
	frameworks[0] = "mutated-after-call"
	if first.Revision != 1 || first.PredecessorID != "" || first.RevisionHash == "" {
		t.Fatalf("first revision changed or incomplete: %+v", first)
	}
	if revised.Version != 3 || revised.CurrentRevision != 2 || revised.CurrentRevisionID != second.ID {
		t.Fatalf("revised engagement = %+v", revised)
	}
	if engagement.Status != EngagementStatusPlanning || revised.Status != EngagementStatusFieldwork {
		t.Fatalf("engagement status pointers = original %q revised %q", engagement.Status, revised.Status)
	}
	if second.PredecessorID != first.ID || second.Revision != 2 {
		t.Fatalf("second revision lineage = %+v", second)
	}
	if len(second.FrameworkRevisionIDs) != 2 || second.FrameworkRevisionIDs[0] != "framework-r1" || second.FrameworkRevisionIDs[1] != "framework-r2" {
		t.Fatalf("second revision frameworks = %#v", second.FrameworkRevisionIDs)
	}
	if len(revised.Participants) != 2 || len(withOwner.Participants) != 2 {
		t.Fatalf("participant assignments were not preserved: revised=%+v previous=%+v", revised.Participants, withOwner.Participants)
	}
	if _, _, err := ReviseEngagement(revised, 2, nextInput, "lead-a", request.CreatedAt.Add(3*time.Hour)); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale engagement revision error = %v, want ErrVersionConflict", err)
	}
}

func TestEngagementLifecycleAndParticipantRemoval(t *testing.T) {
	request := testCreateEngagementRequest()
	engagement, _, err := NewEngagement(request)
	if err != nil {
		t.Fatalf("NewEngagement() error = %v", err)
	}
	invalid := request.Revision
	invalid.Status = EngagementStatusComplete
	if _, _, err := ReviseEngagement(engagement, engagement.Version, invalid, "lead-a", request.CreatedAt.Add(time.Hour)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("planning to complete error = %v, want ErrInvalidRequest", err)
	}
	removedEngagement, removed, err := RemoveParticipant(engagement, engagement.Version, "auditor-a", request.CreatedAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("RemoveParticipant() error = %v", err)
	}
	if removed.Status != ParticipantStatusRemoved || removed.Version != 2 || removedEngagement.Version != 2 || engagement.Participants[0].Status != ParticipantStatusActive {
		t.Fatalf("participant removal = engagement %+v participant %+v original %+v", removedEngagement, removed, engagement)
	}
	if err := AuthorizeEngagementAccess(Principal{TenantID: "tenant-a", ID: "auditor-a"}, removedEngagement, EngagementPermissionRead); !errors.Is(err, ErrEngagementNotFound) {
		t.Fatalf("removed participant access error = %v, want ErrEngagementNotFound", err)
	}
	if err := AuthorizeEngagementAccess(Principal{TenantID: "tenant-a", ID: "manager", TenantWide: true}, engagement, EngagementPermission("unknown")); !errors.Is(err, ErrEngagementNotFound) {
		t.Fatalf("unknown tenant-wide permission error = %v, want ErrEngagementNotFound", err)
	}
}

func testCreateEngagementRequest() CreateEngagementRequest {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return CreateEngagementRequest{
		ID:       "engagement-a",
		TenantID: "tenant-a",
		Revision: EngagementRevisionInput{
			ProgramID:            "program-a",
			ProgramScopeRevision: "scope-r1",
			FrameworkRevisionIDs: []string{"framework-r1"},
			PlanRevisionID:       "plan-r1",
			PeriodStart:          start,
			PeriodEnd:            start.AddDate(0, 3, 0),
			Deadline:             start.AddDate(0, 4, 0),
			DisclosurePolicyID:   "disclosure-r1",
			Status:               EngagementStatusPlanning,
		},
		Participants: []ParticipantInput{{PrincipalID: "auditor-a", Role: ParticipantRoleAuditor}},
		CreatedBy:    "lead-a",
		CreatedAt:    start,
	}
}
