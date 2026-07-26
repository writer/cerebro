package verifiedaccessactionexecution

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/verifiedaccessaction"
)

func TestExecuteClaimsBeforeCallingProvider(t *testing.T) {
	t.Parallel()

	store, record, proposalDigest := approvedAction(t)
	clock := record.Approval.ApprovedAt.Add(time.Minute)
	executor := &stubExecutor{execute: successfulExecution(clock.Add(time.Minute))}
	service := Service{Store: store, Executor: executor, Clock: func() time.Time { return clock }}
	input := executionRequest(record, proposalDigest)

	const contenders = 50
	start := make(chan struct{})
	results := make(chan *Result, contenders)
	errs := make(chan error, contenders)
	var wait sync.WaitGroup
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			result, err := service.Execute(context.Background(), input)
			results <- result
			errs <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errs)

	successes := 0
	for result := range results {
		if result != nil {
			successes++
			if result.Record.Status != verifiedaccessaction.StatusExecuted {
				t.Errorf("status = %q, want %q", result.Record.Status, verifiedaccessaction.StatusExecuted)
			}
		}
	}
	if successes != 1 {
		t.Fatalf("successful callers = %d, want 1", successes)
	}
	for err := range errs {
		if err == nil {
			continue
		}
		if !errors.Is(err, ErrClaimNotAcquired) &&
			!errors.Is(err, verifiedaccessaction.ErrState) {
			t.Errorf("losing caller error = %v", err)
		}
	}
	if calls := executor.calls.Load(); calls != 1 {
		t.Fatalf("provider calls = %d, want 1", calls)
	}
	if !executor.lastInput.Approved {
		t.Fatal("provider transport did not receive the post-claim approval marker")
	}
	if executor.lastInput.FindingID != record.FindingID {
		t.Fatalf("finding_id = %q, want %q", executor.lastInput.FindingID, record.FindingID)
	}

	persisted, err := store.GetAccessAction(context.Background(), record.TenantID, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Status != verifiedaccessaction.StatusExecuted ||
		persisted.ExecutionClaim == nil || persisted.Execution == nil {
		t.Fatalf("persisted record did not retain claim and execution receipts: %+v", persisted)
	}
}

func TestExecuteRecordsAmbiguousSubmissionForReconciliation(t *testing.T) {
	t.Parallel()

	store, record, proposalDigest := approvedAction(t)
	clock := record.Approval.ApprovedAt.Add(time.Minute)
	executor := &stubExecutor{err: context.DeadlineExceeded}
	service := Service{
		Store:          store,
		Executor:       executor,
		Clock:          func() time.Time { return clock },
		ReconcileDelay: 10 * time.Minute,
	}

	result, err := service.Execute(context.Background(), executionRequest(record, proposalDigest))
	if result != nil {
		t.Fatalf("result = %+v, want nil", result)
	}
	if !errors.Is(err, ErrSubmissionUnknown) ||
		!errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Execute() error = %v, want submission unknown and deadline exceeded", err)
	}
	if calls := executor.calls.Load(); calls != 1 {
		t.Fatalf("provider calls = %d, want 1", calls)
	}

	persisted, getErr := store.GetAccessAction(context.Background(), record.TenantID, record.ID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if persisted.Status != verifiedaccessaction.StatusUnknown ||
		persisted.ExecutionClaim == nil || persisted.SubmissionUnknown == nil {
		t.Fatalf("persisted record did not retain the ambiguous submission: %+v", persisted)
	}
	if persisted.SubmissionUnknown.ErrorClass != verifiedaccessaction.SubmissionErrorTransportTimeout {
		t.Fatalf(
			"error_class = %q, want %q",
			persisted.SubmissionUnknown.ErrorClass,
			verifiedaccessaction.SubmissionErrorTransportTimeout,
		)
	}
	wantReconcileAt := clock.Add(10 * time.Minute)
	if !persisted.SubmissionUnknown.NextReconcileAt.Equal(wantReconcileAt) {
		t.Fatalf(
			"next_reconcile_at = %s, want %s",
			persisted.SubmissionUnknown.NextReconcileAt,
			wantReconcileAt,
		)
	}
}

func TestExecuteReturnsDefinitiveProviderFailureWithoutRecordingAmbiguity(t *testing.T) {
	t.Parallel()

	store, record, proposalDigest := approvedAction(t)
	clock := record.Approval.ApprovedAt.Add(time.Minute)
	execution := successfulExecution(clock.Add(time.Minute))
	execution.Action.Status = graphactions.ActionStatusFailed
	execution.Action.ExternalStatus = graphactions.ActionStatusFailed
	execution.Action.ExternalStatusReason = "provider denied the request"
	execution.Action.LastError = "account is protected"
	service := Service{
		Store:    store,
		Executor: &stubExecutor{execute: execution},
		Clock:    func() time.Time { return clock },
	}

	result, err := service.Execute(
		context.Background(),
		executionRequest(record, proposalDigest),
	)
	if result == nil || result.Action == nil {
		t.Fatalf("result = %+v, want the rejected provider receipt", result)
	}
	if !errors.Is(err, ErrProviderReceipt) ||
		!errors.Is(err, verifiedaccessaction.ErrVerificationMismatch) ||
		errors.Is(err, ErrSubmissionUnknown) {
		t.Fatalf("Execute() error = %v, want rejected receipt without submission ambiguity", err)
	}
	if result.Action.ExternalStatusReason != "provider denied the request" ||
		result.Action.LastError != "account is protected" {
		t.Fatalf("provider failure details were not preserved: %+v", result.Action)
	}

	persisted, getErr := store.GetAccessAction(context.Background(), record.TenantID, record.ID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if persisted.Status != verifiedaccessaction.StatusClaimed ||
		persisted.SubmissionUnknown != nil {
		t.Fatalf("definitive failure was persisted as ambiguous: %+v", persisted)
	}
}

func TestExecuteDistinguishesValidatedProviderSuccessFromPersistenceFailure(t *testing.T) {
	t.Parallel()

	store, record, proposalDigest := approvedAction(t)
	clock := record.Approval.ApprovedAt.Add(time.Minute)
	persistErr := errors.New("database unavailable")
	service := Service{
		Store: &failExecutedAppendStore{
			Store: store,
			err:   persistErr,
		},
		Executor: &stubExecutor{execute: successfulExecution(clock.Add(time.Minute))},
		Clock:    func() time.Time { return clock },
	}

	result, err := service.Execute(
		context.Background(),
		executionRequest(record, proposalDigest),
	)
	if result == nil || result.Action == nil {
		t.Fatalf("result = %+v, want the validated provider receipt", result)
	}
	if !errors.Is(err, ErrExecutionPersistence) ||
		!errors.Is(err, persistErr) ||
		errors.Is(err, ErrSubmissionUnknown) {
		t.Fatalf(
			"Execute() error = %v, want execution persistence without submission ambiguity",
			err,
		)
	}
	if result.Record.Status != verifiedaccessaction.StatusClaimed {
		t.Fatalf(
			"result status = %q, want last durable status %q",
			result.Record.Status,
			verifiedaccessaction.StatusClaimed,
		)
	}

	persisted, getErr := store.GetAccessAction(context.Background(), record.TenantID, record.ID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if persisted.Status != verifiedaccessaction.StatusClaimed ||
		persisted.Execution != nil ||
		persisted.SubmissionUnknown != nil {
		t.Fatalf("persistence failure changed durable state: %+v", persisted)
	}
}

func TestExecuteRejectsMismatchedProviderMetadataBeforeFillingDefaults(t *testing.T) {
	t.Parallel()

	store, record, proposalDigest := approvedAction(t)
	clock := record.Approval.ApprovedAt.Add(time.Minute)
	execution := successfulExecution(clock.Add(time.Minute))
	execution.Action.Metadata = map[string]string{"tenant_id": "tenant-other"}
	service := Service{
		Store:    store,
		Executor: &stubExecutor{execute: execution},
		Clock:    func() time.Time { return clock },
	}

	result, err := service.Execute(
		context.Background(),
		executionRequest(record, proposalDigest),
	)
	if result == nil || result.Action == nil {
		t.Fatalf("result = %+v, want the rejected provider receipt", result)
	}
	if !errors.Is(err, ErrProviderReceipt) ||
		!errors.Is(err, verifiedaccessaction.ErrStale) {
		t.Fatalf("Execute() error = %v, want stale provider metadata", err)
	}
	if result.Action.Metadata["tenant_id"] != "tenant-other" {
		t.Fatalf("provider tenant metadata was overwritten: %+v", result.Action.Metadata)
	}

	persisted, getErr := store.GetAccessAction(context.Background(), record.TenantID, record.ID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if persisted.Status != verifiedaccessaction.StatusClaimed ||
		persisted.Execution != nil ||
		persisted.SubmissionUnknown != nil {
		t.Fatalf("mismatched receipt changed durable state: %+v", persisted)
	}
}

func TestExecuteRejectsStaleProposalBeforeCallingProvider(t *testing.T) {
	t.Parallel()

	store, record, _ := approvedAction(t)
	executor := &stubExecutor{}
	service := Service{
		Store:    store,
		Executor: executor,
		Clock:    func() time.Time { return record.Approval.ApprovedAt.Add(time.Minute) },
	}
	input := executionRequest(record, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	result, err := service.Execute(context.Background(), input)
	if result != nil {
		t.Fatalf("result = %+v, want nil", result)
	}
	if !errors.Is(err, verifiedaccessaction.ErrStale) {
		t.Fatalf("Execute() error = %v, want ErrStale", err)
	}
	if calls := executor.calls.Load(); calls != 0 {
		t.Fatalf("provider calls = %d, want 0", calls)
	}
}

type failExecutedAppendStore struct {
	verifiedaccessaction.Store
	err error
}

func (s *failExecutedAppendStore) AppendAccessAction(
	ctx context.Context,
	outcome verifiedaccessaction.Outcome,
) (bool, error) {
	if outcome.Record.Status == verifiedaccessaction.StatusExecuted {
		return false, s.err
	}
	return s.Store.AppendAccessAction(ctx, outcome)
}

type stubExecutor struct {
	calls     atomic.Int64
	mu        sync.Mutex
	lastInput graphactions.Input
	execute   *graphactions.Result
	err       error
}

func (s *stubExecutor) Execute(_ context.Context, input graphactions.Input) (*graphactions.Result, error) {
	s.calls.Add(1)
	s.mu.Lock()
	s.lastInput = input
	s.mu.Unlock()
	return s.execute, s.err
}

func successfulExecution(completedAt time.Time) *graphactions.Result {
	return &graphactions.Result{Action: &graphactions.GraphAction{
		ID:              "provider-receipt-one",
		ExternalID:      "provider-receipt-one",
		Action:          graphactions.ActionIdentityOktaSuspendUser,
		Provider:        graphactions.ProviderAccessApprovals,
		Status:          graphactions.ActionStatusSucceeded,
		ExternalStatus:  graphactions.ActionStatusSucceeded,
		Target:          "provider-user-1",
		IdempotencyKey:  "access-revocation-one",
		ActorType:       "service",
		ActorSubject:    "provider-executor",
		CreatedAtUnix:   completedAt.Add(-time.Minute).Unix(),
		UpdatedAtUnix:   completedAt.Unix(),
		CompletedAtUnix: completedAt.Unix(),
	}}
}

func executionRequest(record verifiedaccessaction.Record, proposalDigest string) Input {
	return Input{
		TenantID:       record.TenantID,
		ActionID:       record.ID,
		ProposalDigest: proposalDigest,
		Worker:         verifiedaccessaction.Actor{Type: "service", ID: "action-worker"},
	}
}

func approvedAction(
	t *testing.T,
) (*verifiedaccessaction.MemoryStore, verifiedaccessaction.Record, string) {
	t.Helper()

	at := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	proposal, err := verifiedaccessaction.Propose(verifiedaccessaction.ProposalInput{
		TenantID:  "tenant-one",
		FindingID: "finding-one",
		Definition: verifiedaccessaction.ActionDefinition{
			Metadata: graphactions.ActionMetadata{
				ID:             graphactions.ActionIdentityOktaSuspendUser,
				Provider:       graphactions.ProviderAccessApprovals,
				ProviderAction: graphactions.AccessApprovalsActionSuspend,
				TargetKind:     graphactions.TargetKindOktaUser,
				Effect:         "deny_access",
				Destructive:    true,
				ReversibleBy:   graphactions.ActionIdentityOktaUnsuspendUser,
			},
			Version: "2026-07-25",
		},
		Binding: verifiedaccessaction.TargetBinding{
			TargetID:         "provider-user-1",
			SubjectURN:       "urn:cerebro:tenant-one:identity:user-1",
			SubjectRevision:  "subject-revision-1",
			ResourceURN:      "urn:cerebro:tenant-one:application:one",
			ResourceRevision: "resource-revision-1",
			SourceRuntimeID:  "runtime-one",
			SourceRevision:   "source-revision-1",
		},
		Parameters:     map[string]string{"session_policy": "revoke_active"},
		Proposer:       verifiedaccessaction.Actor{Type: "human", ID: "operator-one"},
		IdempotencyKey: "access-revocation-one",
		Rollback: verifiedaccessaction.RollbackPlan{
			ActionID:          graphactions.ActionIdentityOktaUnsuspendUser,
			DefinitionVersion: "2026-07-25",
			Parameters:        map[string]string{"restore": "previous_state"},
			Steps:             []string{"Confirm the original access decision remains valid.", "Restore the provider account state."},
		},
		Reason:     "Confirmed offboarding access remains active.",
		ProposedAt: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	proposalDigest := proposal.Record.Digest
	store := verifiedaccessaction.NewMemoryStore()
	if applied, createErr := store.CreateAccessAction(context.Background(), proposal); createErr != nil || !applied {
		t.Fatalf("CreateAccessAction() = %t, %v", applied, createErr)
	}

	preflight, err := verifiedaccessaction.Preflight(
		proposal.Record,
		verifiedaccessaction.PreflightInput{
			ProposalDigest:   proposalDigest,
			Binding:          proposal.Record.Binding,
			ParametersDigest: verifiedaccessaction.ParametersDigest(proposal.Record.Parameters),
			RollbackDigest:   verifiedaccessaction.RollbackPlanDigest(proposal.Record.Rollback),
			Actor:            verifiedaccessaction.Actor{Type: "service", ID: "access-preflight"},
			ExpectedEffect:   proposal.Record.Definition.Metadata.Effect,
			TargetExists:     true,
			WouldChange:      true,
			SourceHealthy:    true,
			ProviderMutation: false,
			SimulatedAt:      at.Add(time.Minute),
			ValidUntil:       at.Add(time.Hour),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if applied, appendErr := store.AppendAccessAction(context.Background(), preflight); appendErr != nil || !applied {
		t.Fatalf("AppendAccessAction(preflight) = %t, %v", applied, appendErr)
	}

	approval, err := verifiedaccessaction.Approve(
		preflight.Record,
		verifiedaccessaction.ApprovalInput{
			ProposalDigest:  proposalDigest,
			PreflightDigest: preflight.Record.Preflight.Digest,
			Actor:           verifiedaccessaction.Actor{Type: "human", ID: "approver-one"},
			Reason:          "The exact target, change, and rollback were reviewed.",
			ApprovedAt:      at.Add(2 * time.Minute),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if applied, appendErr := store.AppendAccessAction(context.Background(), approval); appendErr != nil || !applied {
		t.Fatalf("AppendAccessAction(approval) = %t, %v", applied, appendErr)
	}
	return store, approval.Record, proposalDigest
}
