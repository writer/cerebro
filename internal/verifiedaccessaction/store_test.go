package verifiedaccessaction

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryStorePersistsImmutableTransitionChain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()
	proposed := mustPropose(t)
	if applied, err := store.CreateAccessAction(ctx, proposed); err != nil || !applied {
		t.Fatalf("CreateAccessAction() = %v, %v", applied, err)
	}
	if applied, err := store.CreateAccessAction(ctx, proposed); err != nil || applied {
		t.Fatalf("idempotent CreateAccessAction() = %v, %v", applied, err)
	}

	preflighted := mustPreflight(t, proposed.Record)
	approved := mustApprove(t, proposed.Record.Digest, preflighted.Record)
	for _, outcome := range []Outcome{preflighted, approved} {
		if applied, err := store.AppendAccessAction(ctx, outcome); err != nil || !applied {
			t.Fatalf("AppendAccessAction(%s) = %v, %v", outcome.Record.Status, applied, err)
		}
	}

	record, err := store.GetAccessAction(ctx, proposed.Record.TenantID, proposed.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Digest != approved.Record.Digest || record.Status != StatusApproved {
		t.Fatalf("record = %#v", record)
	}
	record.Parameters["session_policy"] = "changed"
	reloaded, err := store.GetAccessAction(ctx, proposed.Record.TenantID, proposed.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Parameters["session_policy"] == "changed" {
		t.Fatal("GetAccessAction returned mutable store state")
	}

	transitions, err := store.ListAccessActionTransitions(ctx, proposed.Record.TenantID, proposed.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(transitions) != 3 ||
		transitions[2].PreviousTransitionDigest != transitions[1].Digest {
		t.Fatalf("transitions = %#v", transitions)
	}
}

func TestMemoryStoreListsBoundedFindingActionsWithinTenant(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()
	for index, fixture := range []struct {
		tenantID  string
		findingID string
	}{
		{tenantID: "tenant-one", findingID: "finding-one"},
		{tenantID: "tenant-one", findingID: "finding-one"},
		{tenantID: "tenant-one", findingID: "finding-two"},
		{tenantID: "tenant-two", findingID: "finding-one"},
	} {
		input := proposalInput()
		input.TenantID = fixture.tenantID
		input.FindingID = fixture.findingID
		input.IdempotencyKey = input.IdempotencyKey + "-" + string(rune('a'+index))
		input.ProposedAt = input.ProposedAt.Add(time.Duration(index) * time.Minute)
		outcome, err := Propose(input)
		if err != nil {
			t.Fatal(err)
		}
		if applied, createErr := store.CreateAccessAction(ctx, outcome); createErr != nil || !applied {
			t.Fatalf("CreateAccessAction() = %t, %v", applied, createErr)
		}
	}

	records, err := store.ListAccessActionsByFinding(ctx, "tenant-one", "finding-one", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 ||
		records[0].TenantID != "tenant-one" ||
		records[0].FindingID != "finding-one" ||
		records[0].IdempotencyKey != "access-revocation-one-b" {
		t.Fatalf("records = %+v", records)
	}
	if _, err := store.ListAccessActionsByFinding(
		ctx,
		"tenant-one",
		"finding-one",
		MaxListLimit+1,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized list error = %v, want ErrInvalid", err)
	}
}

func TestMemoryStoreGrantsExactlyOneExecutionClaim(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()
	proposed := mustPropose(t)
	preflighted := mustPreflight(t, proposed.Record)
	approved := mustApprove(t, proposed.Record.Digest, preflighted.Record)
	for _, outcome := range []Outcome{proposed, preflighted, approved} {
		var err error
		if outcome.Record.Status == StatusProposed {
			_, err = store.CreateAccessAction(ctx, outcome)
		} else {
			_, err = store.AppendAccessAction(ctx, outcome)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	claim, err := ClaimExecution(approved.Record, executionClaimInput(proposed.Record.Digest, approved.Record))
	if err != nil {
		t.Fatal(err)
	}

	var applied atomic.Int32
	var failed atomic.Int32
	var wait sync.WaitGroup
	for range 32 {
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
}

func TestMemoryStoreRejectsCompetingTransitionFromSamePredecessor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()
	proposed := mustPropose(t)
	preflighted := mustPreflight(t, proposed.Record)
	approved := mustApprove(t, proposed.Record.Digest, preflighted.Record)
	if _, err := store.CreateAccessAction(ctx, proposed); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendAccessAction(ctx, preflighted); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendAccessAction(ctx, approved); err != nil {
		t.Fatal(err)
	}

	firstInput := executionClaimInput(proposed.Record.Digest, approved.Record)
	first, err := ClaimExecution(approved.Record, firstInput)
	if err != nil {
		t.Fatal(err)
	}
	secondInput := firstInput
	secondInput.Actor.ID = "action-executor-two"
	second, err := ClaimExecution(approved.Record, secondInput)
	if err != nil {
		t.Fatal(err)
	}
	if applied, err := store.AppendAccessAction(ctx, first); err != nil || !applied {
		t.Fatalf("first claim = %v, %v", applied, err)
	}
	if applied, err := store.AppendAccessAction(ctx, second); !errors.Is(err, ErrConflict) || applied {
		t.Fatalf("competing claim = %v, %v", applied, err)
	}
}
