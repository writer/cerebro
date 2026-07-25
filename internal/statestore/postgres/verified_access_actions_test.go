package postgres

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/verifiedaccessaction"
)

func TestVerifiedAccessActionSchemaIsTenantScopedAndCASReady(t *testing.T) {
	joined := strings.Join(ensureVerifiedAccessActionStatements, "\n")
	for _, table := range []string{
		"verified_access_actions",
		"verified_access_action_transitions",
	} {
		if !strings.Contains(joined, "CREATE TABLE IF NOT EXISTS "+table) {
			t.Fatalf("schema is missing table %q", table)
		}
	}
	for _, fragment := range []string{
		"PRIMARY KEY (tenant_id, action_id)",
		"UNIQUE (tenant_id, idempotency_key)",
		"UNIQUE (tenant_id, transition_digest)",
		"FOREIGN KEY (tenant_id, action_id)",
		"previous_transition_digest TEXT NOT NULL",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("schema is missing %q", fragment)
		}
	}
}

func TestVerifiedAccessActionPostgresGrantsOneExecutionClaim(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run verified access action persistence integration test")
	}
	store, err := Open(config.StateStoreConfig{
		Driver:      config.StateStoreDriverPostgres,
		PostgresDSN: dsn,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	ctx := context.Background()
	tenantID := fmt.Sprintf("verified-access-action-test-%d", time.Now().UnixNano())
	defer func() {
		_, _ = store.db.ExecContext(ctx,
			`DELETE FROM verified_access_actions WHERE tenant_id = $1`,
			tenantID,
		)
	}()

	proposed := postgresTestProposal(t, tenantID)
	preflighted := postgresTestPreflight(t, proposed.Record)
	approved := postgresTestApproval(t, proposed.Record.Digest, preflighted.Record)
	for _, outcome := range []verifiedaccessaction.Outcome{proposed, preflighted, approved} {
		var applied bool
		if outcome.Record.Status == verifiedaccessaction.StatusProposed {
			applied, err = store.CreateAccessAction(ctx, outcome)
		} else {
			applied, err = store.AppendAccessAction(ctx, outcome)
		}
		if err != nil || !applied {
			t.Fatalf("persist %s = %v, %v", outcome.Record.Status, applied, err)
		}
	}
	claimInput := postgresTestClaimInput(proposed.Record.Digest, approved.Record)
	claim, err := verifiedaccessaction.ClaimExecution(approved.Record, claimInput)
	if err != nil {
		t.Fatal(err)
	}

	var applied atomic.Int32
	var failed atomic.Int32
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			won, appendErr := store.AppendAccessAction(ctx, claim)
			if appendErr != nil {
				failed.Add(1)
				return
			}
			if won {
				applied.Add(1)
			}
		}()
	}
	wait.Wait()
	if applied.Load() != 1 || failed.Load() != 0 {
		t.Fatalf("claim applied=%d failed=%d", applied.Load(), failed.Load())
	}
	record, err := store.GetAccessAction(ctx, tenantID, proposed.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != verifiedaccessaction.StatusClaimed {
		t.Fatalf("record status = %q", record.Status)
	}
	transitions, err := store.ListAccessActionTransitions(ctx, tenantID, proposed.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(transitions) != 4 {
		t.Fatalf("transition count = %d, want 4", len(transitions))
	}
}

func postgresTestProposal(t *testing.T, tenantID string) verifiedaccessaction.Outcome {
	t.Helper()
	at := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	outcome, err := verifiedaccessaction.Propose(verifiedaccessaction.ProposalInput{
		TenantID:  tenantID,
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
			TargetID: "provider-user-1", SubjectURN: "urn:cerebro:test:identity:user-1",
			SubjectRevision: "subject-revision-1", ResourceURN: "urn:cerebro:test:application:one",
			ResourceRevision: "resource-revision-1", SourceRuntimeID: "runtime-one",
			SourceRevision: "source-revision-1",
		},
		Parameters:     map[string]string{"session_policy": "revoke_active"},
		Proposer:       verifiedaccessaction.Actor{Type: "human", ID: "operator-one"},
		IdempotencyKey: "access-revocation-one",
		Rollback: verifiedaccessaction.RollbackPlan{
			ActionID:          graphactions.ActionIdentityOktaUnsuspendUser,
			DefinitionVersion: "2026-07-25",
			Parameters:        map[string]string{"restore": "previous_state"},
			Steps:             []string{"Confirm the access decision.", "Restore the provider account state."},
		},
		Reason: "Confirmed offboarding access remains active.", ProposedAt: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	return outcome
}

func postgresTestPreflight(t *testing.T, record verifiedaccessaction.Record) verifiedaccessaction.Outcome {
	t.Helper()
	outcome, err := verifiedaccessaction.Preflight(record, verifiedaccessaction.PreflightInput{
		ProposalDigest: record.Digest, Binding: record.Binding,
		ParametersDigest: verifiedaccessaction.ParametersDigest(record.Parameters),
		RollbackDigest:   verifiedaccessaction.RollbackPlanDigest(record.Rollback),
		Actor:            verifiedaccessaction.Actor{Type: "service", ID: "access-preflight"},
		ExpectedEffect:   record.Definition.Metadata.Effect,
		TargetExists:     true, WouldChange: true, SourceHealthy: true,
		ProviderMutation: false, SimulatedAt: record.ProposedAt.Add(time.Minute),
		ValidUntil: record.ProposedAt.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return outcome
}

func postgresTestApproval(
	t *testing.T,
	proposalDigest string,
	record verifiedaccessaction.Record,
) verifiedaccessaction.Outcome {
	t.Helper()
	outcome, err := verifiedaccessaction.Approve(record, verifiedaccessaction.ApprovalInput{
		ProposalDigest: proposalDigest, PreflightDigest: record.Preflight.Digest,
		Actor:      verifiedaccessaction.Actor{Type: "human", ID: "approver-one"},
		Reason:     "The target, change, and rollback were reviewed.",
		ApprovedAt: record.Preflight.SimulatedAt.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	return outcome
}

func postgresTestClaimInput(
	proposalDigest string,
	record verifiedaccessaction.Record,
) verifiedaccessaction.ExecutionClaimInput {
	return verifiedaccessaction.ExecutionClaimInput{
		ProposalDigest: proposalDigest, PreflightDigest: record.Preflight.Digest,
		ApprovalDigest:   record.Approval.Digest,
		ParametersDigest: verifiedaccessaction.ParametersDigest(record.Parameters),
		Binding:          record.Binding, DefinitionVersion: record.Definition.Version,
		Actor:     verifiedaccessaction.Actor{Type: "service", ID: "action-executor"},
		ClaimedAt: record.Approval.ApprovedAt.Add(time.Minute),
	}
}
