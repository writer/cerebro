package verifiedaccessaction

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graphactions"
)

func TestAccessRevocationLifecycleClosesAndReopensWithDurableReceipts(t *testing.T) {
	t.Parallel()
	proposed := mustPropose(t)
	preflighted := mustPreflight(t, proposed.Record)
	approved := mustApprove(t, proposed.Record.Digest, preflighted.Record)
	executed := mustExecute(t, proposed.Record.Digest, approved.Record)
	closed := mustVerify(t, executed.Record)

	if closed.Record.Status != StatusClosed || !closed.Metrics.VerificationClosed || closed.Metrics.ResultCode != ResultVerifiedClosed {
		t.Fatalf("closed = %#v", closed)
	}
	transitions := []TransitionReceipt{proposed.Transition, preflighted.Transition, approved.Transition, executed.Transition, closed.Transition}
	for i := 1; i < len(transitions); i++ {
		if transitions[i].PreviousTransitionDigest != transitions[i-1].Digest {
			t.Fatalf("transition %d previous = %q, want %q", i, transitions[i].PreviousTransitionDigest, transitions[i-1].Digest)
		}
	}
	if err := VerifyTransition(closed.Record, closed.Transition); err != nil {
		t.Fatalf("VerifyTransition() error = %v", err)
	}
	tampered := closed.Transition
	tampered.ResultCode = "changed"
	if err := VerifyTransition(closed.Record, tampered); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered VerifyTransition() error = %v", err)
	}

	recheck := verificationInput(closed.Record, "source-revision-3", "subject-revision-3", closed.Record.Verification.VerifiedAt.Add(time.Hour))
	recheck.Effective = false
	reopened, err := Reverify(closed.Record, recheck)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Record.Status != StatusReopened || !reopened.Metrics.Reopened || reopened.Metrics.ResultCode != ResultReopenedMismatch {
		t.Fatalf("reopened = %#v", reopened)
	}
}

func TestLifecycleIsDeterministicAndDoesNotReachProvider(t *testing.T) {
	t.Parallel()
	first := mustPropose(t)
	second := mustPropose(t)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("deterministic proposal mismatch\nfirst=%#v\nsecond=%#v", first, second)
	}
	preflightOne := mustPreflight(t, first.Record)
	preflightTwo := mustPreflight(t, second.Record)
	if !reflect.DeepEqual(preflightOne, preflightTwo) {
		t.Fatalf("deterministic preflight mismatch")
	}
}

func TestExportedReceiptDigestHelpersMatchLifecycleBindings(t *testing.T) {
	t.Parallel()
	proposed := mustPropose(t)
	proposalDigest, err := ProposalRecordDigest(proposed.Record)
	if err != nil {
		t.Fatal(err)
	}
	if proposalDigest != proposed.Record.Digest {
		t.Fatalf("ProposalRecordDigest() = %q, want %q", proposalDigest, proposed.Record.Digest)
	}
	preflight := preflightInput(proposed.Record)
	if preflight.ParametersDigest != ParametersDigest(proposed.Record.Parameters) {
		t.Fatalf("ParametersDigest() = %q, want %q", ParametersDigest(proposed.Record.Parameters), preflight.ParametersDigest)
	}
	if preflight.RollbackDigest != RollbackPlanDigest(proposed.Record.Rollback) {
		t.Fatalf("RollbackPlanDigest() = %q, want %q", RollbackPlanDigest(proposed.Record.Rollback), preflight.RollbackDigest)
	}
	preflighted := mustPreflight(t, proposed.Record)
	approved := mustApprove(t, proposed.Record.Digest, preflighted.Record)
	execution := executionInput(proposed.Record.Digest, approved.Record)
	if execution.ProviderReceiptDigest != GraphActionReceiptDigest(execution.GraphAction) {
		t.Fatalf("GraphActionReceiptDigest() = %q, want %q", GraphActionReceiptDigest(execution.GraphAction), execution.ProviderReceiptDigest)
	}

	tampered := proposed.Record
	tampered.Reason = "changed"
	if _, err := ProposalRecordDigest(tampered); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered ProposalRecordDigest() error = %v, want ErrInvalid", err)
	}
}

func TestProposalFailsClosedWithoutRollback(t *testing.T) {
	t.Parallel()
	input := proposalInput()
	input.Rollback = RollbackPlan{}
	if _, err := Propose(input); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Propose() error = %v, want ErrInvalid", err)
	}
}

func TestPreflightRejectsStaleUnhealthyOrMutatingSimulation(t *testing.T) {
	t.Parallel()
	proposed := mustPropose(t)
	input := preflightInput(proposed.Record)
	input.Binding.SourceRevision = "stale-revision"
	if _, err := Preflight(proposed.Record, input); !errors.Is(err, ErrStale) {
		t.Fatalf("stale Preflight() error = %v", err)
	}
	input = preflightInput(proposed.Record)
	input.SourceHealthy = false
	if _, err := Preflight(proposed.Record, input); !errors.Is(err, ErrSourceUnhealthy) {
		t.Fatalf("unhealthy Preflight() error = %v", err)
	}
	input = preflightInput(proposed.Record)
	input.ProviderMutation = true
	if _, err := Preflight(proposed.Record, input); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mutating Preflight() error = %v", err)
	}
}

func TestApprovalRejectsSelfApprovalAndExpiredPreflight(t *testing.T) {
	t.Parallel()
	proposed := mustPropose(t)
	preflighted := mustPreflight(t, proposed.Record)
	input := approvalInput(proposed.Record.Digest, preflighted.Record)
	input.Actor = preflighted.Record.Proposer
	if _, err := Approve(preflighted.Record, input); !errors.Is(err, ErrSeparationOfDuty) {
		t.Fatalf("self Approve() error = %v", err)
	}
	input = approvalInput(proposed.Record.Digest, preflighted.Record)
	input.ApprovedAt = preflighted.Record.Preflight.ValidUntil.Add(time.Second)
	if _, err := Approve(preflighted.Record, input); !errors.Is(err, ErrStale) {
		t.Fatalf("expired Approve() error = %v", err)
	}
}

func TestExecutionReceiptRejectsTargetRevisionAndActorMismatch(t *testing.T) {
	t.Parallel()
	proposed := mustPropose(t)
	preflighted := mustPreflight(t, proposed.Record)
	approved := mustApprove(t, proposed.Record.Digest, preflighted.Record)
	input := executionInput(proposed.Record.Digest, approved.Record)
	input.GraphAction.Metadata["source_revision"] = "changed-after-approval"
	input.ProviderReceiptDigest = digestGraphAction(input.GraphAction)
	if _, err := IngestExecution(approved.Record, input); !errors.Is(err, ErrStale) {
		t.Fatalf("stale IngestExecution() error = %v", err)
	}
	input = executionInput(proposed.Record.Digest, approved.Record)
	input.GraphAction.ActorSubject = "different-executor"
	input.ProviderReceiptDigest = digestGraphAction(input.GraphAction)
	if _, err := IngestExecution(approved.Record, input); !errors.Is(err, ErrVerificationMismatch) {
		t.Fatalf("actor IngestExecution() error = %v", err)
	}
}

func TestExecutionReceiptRejectsOccurrenceTimeOutsideProviderReceipt(t *testing.T) {
	t.Parallel()
	proposed := mustPropose(t)
	preflighted := mustPreflight(t, proposed.Record)
	approved := mustApprove(t, proposed.Record.Digest, preflighted.Record)
	input := executionInput(proposed.Record.Digest, approved.Record)
	input.GraphAction.CompletedAtUnix = approved.Record.Approval.ApprovedAt.Add(-time.Minute).Unix()
	input.ProviderReceiptDigest = digestGraphAction(input.GraphAction)
	input.OccurredAt = approved.Record.Approval.ApprovedAt.Add(time.Minute)
	if _, err := IngestExecution(approved.Record, input); !errors.Is(err, ErrStale) {
		t.Fatalf("IngestExecution() error = %v, want ErrStale for caller time outside provider receipt", err)
	}
	input = executionInput(proposed.Record.Digest, approved.Record)
	input.OccurredAt = input.OccurredAt.Add(500 * time.Millisecond)
	if _, err := IngestExecution(approved.Record, input); err != nil {
		t.Fatalf("IngestExecution() error = %v for subsecond occurrence precision", err)
	}
}

func TestVerificationRejectsSelfVerificationUnhealthySourceAndMismatch(t *testing.T) {
	t.Parallel()
	proposed := mustPropose(t)
	preflighted := mustPreflight(t, proposed.Record)
	approved := mustApprove(t, proposed.Record.Digest, preflighted.Record)
	executed := mustExecute(t, proposed.Record.Digest, approved.Record)
	input := verificationInput(executed.Record, "source-revision-2", "subject-revision-2", executed.Record.Execution.OccurredAt.Add(time.Hour))
	input.Actor = executed.Record.Approval.Actor
	if _, err := VerifyClosure(executed.Record, input); !errors.Is(err, ErrSeparationOfDuty) {
		t.Fatalf("self VerifyClosure() error = %v", err)
	}
	input = verificationInput(executed.Record, "source-revision-2", "subject-revision-2", executed.Record.Execution.OccurredAt.Add(time.Hour))
	input.SourceHealthy = false
	if _, err := VerifyClosure(executed.Record, input); !errors.Is(err, ErrSourceUnhealthy) {
		t.Fatalf("unhealthy VerifyClosure() error = %v", err)
	}
	input = verificationInput(executed.Record, "source-revision-2", "subject-revision-2", executed.Record.Execution.OccurredAt.Add(time.Hour))
	input.Effective = false
	if _, err := VerifyClosure(executed.Record, input); !errors.Is(err, ErrVerificationMismatch) {
		t.Fatalf("mismatch VerifyClosure() error = %v", err)
	}
}

func TestClosedActionReopensWhenSourceBecomesUnhealthy(t *testing.T) {
	t.Parallel()
	proposed := mustPropose(t)
	preflighted := mustPreflight(t, proposed.Record)
	approved := mustApprove(t, proposed.Record.Digest, preflighted.Record)
	executed := mustExecute(t, proposed.Record.Digest, approved.Record)
	closed := mustVerify(t, executed.Record)
	input := verificationInput(closed.Record, "source-revision-3", "subject-revision-3", closed.Record.Verification.VerifiedAt.Add(time.Hour))
	input.SourceHealthy = false
	reopened, err := Reverify(closed.Record, input)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Metrics.ResultCode != ResultReopenedSourceUnhealthy || reopened.Record.Status != StatusReopened {
		t.Fatalf("reopened = %#v", reopened)
	}
}

func mustPropose(t *testing.T) Outcome {
	t.Helper()
	outcome, err := Propose(proposalInput())
	if err != nil {
		t.Fatal(err)
	}
	return outcome
}

func mustPreflight(t *testing.T, record Record) Outcome {
	t.Helper()
	outcome, err := Preflight(record, preflightInput(record))
	if err != nil {
		t.Fatal(err)
	}
	return outcome
}

func mustApprove(t *testing.T, proposalDigest string, record Record) Outcome {
	t.Helper()
	outcome, err := Approve(record, approvalInput(proposalDigest, record))
	if err != nil {
		t.Fatal(err)
	}
	return outcome
}

func mustExecute(t *testing.T, proposalDigest string, record Record) Outcome {
	t.Helper()
	outcome, err := IngestExecution(record, executionInput(proposalDigest, record))
	if err != nil {
		t.Fatal(err)
	}
	return outcome
}

func mustVerify(t *testing.T, record Record) Outcome {
	t.Helper()
	input := verificationInput(record, "source-revision-2", "subject-revision-2", record.Execution.OccurredAt.Add(time.Hour))
	outcome, err := VerifyClosure(record, input)
	if err != nil {
		t.Fatal(err)
	}
	return outcome
}

func proposalInput() ProposalInput {
	at := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	return ProposalInput{
		TenantID:   "tenant-one",
		Definition: ActionDefinition{Metadata: graphactions.ActionMetadata{ID: graphactions.ActionIdentityOktaSuspendUser, Provider: graphactions.ProviderAccessApprovals, ProviderAction: graphactions.AccessApprovalsActionSuspend, TargetKind: graphactions.TargetKindOktaUser, Effect: "deny_access", Destructive: true, ReversibleBy: graphactions.ActionIdentityOktaUnsuspendUser}, Version: "2026-07-14"},
		Binding:    TargetBinding{TargetID: "provider-user-1", SubjectURN: "urn:cerebro:tenant-one:identity:user-1", SubjectRevision: "subject-revision-1", ResourceURN: "urn:cerebro:tenant-one:application:one", ResourceRevision: "resource-revision-1", SourceRuntimeID: "runtime-one", SourceRevision: "source-revision-1"},
		Parameters: map[string]string{"session_policy": "revoke_active"}, Proposer: Actor{Type: "human", ID: "operator-one"}, IdempotencyKey: "access-revocation-one",
		Rollback: RollbackPlan{ActionID: graphactions.ActionIdentityOktaUnsuspendUser, DefinitionVersion: "2026-07-14", Parameters: map[string]string{"restore": "previous_state"}, Steps: []string{"Confirm the original access decision remains valid.", "Restore the provider account state."}},
		Reason:   "Confirmed offboarding access remains active.", ProposedAt: at,
	}
}

func preflightInput(record Record) PreflightInput {
	return PreflightInput{ProposalDigest: record.Digest, Binding: record.Binding, ParametersDigest: digestValue(record.Parameters), RollbackDigest: digestValue(record.Rollback), Actor: Actor{Type: "service", ID: "access-preflight"}, ExpectedEffect: record.Definition.Metadata.Effect, TargetExists: true, WouldChange: true, SourceHealthy: true, ProviderMutation: false, SimulatedAt: record.ProposedAt.Add(time.Minute), ValidUntil: record.ProposedAt.Add(time.Hour)}
}

func approvalInput(proposalDigest string, record Record) ApprovalInput {
	return ApprovalInput{ProposalDigest: proposalDigest, PreflightDigest: record.Preflight.Digest, Actor: Actor{Type: "human", ID: "approver-one"}, Reason: "The exact target, change, and rollback were reviewed.", ApprovedAt: record.Preflight.SimulatedAt.Add(time.Minute)}
}

func executionInput(proposalDigest string, record Record) ExecutionInput {
	action := graphactions.GraphAction{ID: "provider-receipt-one", ExternalID: "provider-receipt-one", Action: record.Definition.Metadata.ID, Provider: record.Definition.Metadata.Provider, Status: graphactions.ActionStatusSucceeded, ExternalStatus: graphactions.ActionStatusSucceeded, Target: record.Binding.TargetID, IdempotencyKey: record.IdempotencyKey, ActorType: "human", ActorSubject: "executor-one", CreatedAtUnix: record.Approval.ApprovedAt.Add(time.Minute).Unix(), UpdatedAtUnix: record.Approval.ApprovedAt.Add(2 * time.Minute).Unix(), CompletedAtUnix: record.Approval.ApprovedAt.Add(2 * time.Minute).Unix(), Metadata: map[string]string{"tenant_id": record.TenantID, "subject_urn": record.Binding.SubjectURN, "resource_urn": record.Binding.ResourceURN, "source_runtime_id": record.Binding.SourceRuntimeID, "source_revision": record.Binding.SourceRevision, "definition_version": record.Definition.Version}}
	return ExecutionInput{GraphAction: action, DefinitionVersion: record.Definition.Version, ProposalDigest: proposalDigest, PreflightDigest: record.Preflight.Digest, ApprovalDigest: record.Approval.Digest, ParametersDigest: digestValue(record.Parameters), Binding: record.Binding, ExecutedBy: Actor{Type: "human", ID: "executor-one"}, IngestedBy: Actor{Type: "service", ID: "receipt-ingestor"}, ProviderReceiptDigest: digestGraphAction(action), OccurredAt: time.Unix(action.CompletedAtUnix, 0).UTC()}
}

func verificationInput(record Record, sourceRevision, subjectRevision string, at time.Time) VerificationInput {
	binding := record.Binding
	binding.SourceRevision, binding.SubjectRevision = sourceRevision, subjectRevision
	return VerificationInput{ExecutionDigest: record.Execution.Digest, PreviousSourceRevision: record.Binding.SourceRevision, Binding: binding, ExpectedEffect: record.Definition.Metadata.Effect, Effective: true, SourceHealthy: true, Evidence: []EvidenceReference{{ID: "source-observation-one", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}, Actor: Actor{Type: "human", ID: "verifier-one"}, VerifiedAt: at}
}
