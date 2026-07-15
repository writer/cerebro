package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestPutFindingEvaluationRunRejectsNilRun(t *testing.T) {
	store := &Store{}
	if err := store.PutFindingEvaluationRun(context.Background(), nil); err == nil {
		t.Fatal("PutFindingEvaluationRun() error = nil, want non-nil")
	}
}

func TestPutFindingEvaluationRunRejectsMissingRuleID(t *testing.T) {
	store := &Store{}
	err := store.PutFindingEvaluationRun(context.Background(), &cerebrov1.FindingEvaluationRun{
		Id:        "finding-eval-run-1",
		RuntimeId: "writer-okta-audit",
		Status:    "completed",
		StartedAt: timestamppb.New(time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)),
	})
	if err == nil {
		t.Fatal("PutFindingEvaluationRun() error = nil, want non-nil")
	}
}

func TestGetFindingEvaluationRunRejectsUnconfiguredStore(t *testing.T) {
	store := &Store{}
	if _, err := store.GetFindingEvaluationRun(context.Background(), "finding-eval-run-1"); err == nil {
		t.Fatal("GetFindingEvaluationRun() error = nil, want non-nil")
	}
}

func TestListFindingEvaluationRunsRejectsUnconfiguredStore(t *testing.T) {
	store := &Store{}
	if _, err := store.ListFindingEvaluationRuns(context.Background(), ports.ListFindingEvaluationRunsRequest{RuntimeID: "writer-okta-audit"}); err == nil {
		t.Fatal("ListFindingEvaluationRuns() error = nil, want non-nil")
	}
}

func TestFindingEvaluationRunTimeTreatsNilAsZero(t *testing.T) {
	if got := findingEvaluationRunTime(nil); !got.IsZero() {
		t.Fatalf("findingEvaluationRunTime(nil) = %v, want zero", got)
	}
}

func TestFindingEvaluationRunListQueryIncludesOptionalFilters(t *testing.T) {
	cutoff := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	query, args, err := findingEvaluationRunListQuery(ports.ListFindingEvaluationRunsRequest{
		RuntimeID:          "writer-okta-audit",
		RuleID:             "identity-okta-policy-rule-lifecycle-tampering",
		Status:             "completed",
		FinishedAtOrBefore: cutoff,
		Limit:              25,
	})
	if err != nil {
		t.Fatalf("findingEvaluationRunListQuery() error = %v", err)
	}
	for _, fragment := range []string{
		"runtime_id = $1",
		"rule_id = $2",
		"status = $3",
		"finished_at <= $4",
		"ORDER BY finished_at DESC, started_at DESC, id",
		"LIMIT $5",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("findingEvaluationRunListQuery() query missing %q: %s", fragment, query)
		}
	}
	if got := len(args); got != 5 {
		t.Fatalf("len(findingEvaluationRunListQuery().args) = %d, want 5", got)
	}
	if got := args[0]; got != "writer-okta-audit" {
		t.Fatalf("findingEvaluationRunListQuery().args[0] = %#v, want writer-okta-audit", got)
	}
	if got := args[1]; got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("findingEvaluationRunListQuery().args[1] = %#v, want rule id", got)
	}
	if got := args[2]; got != "completed" {
		t.Fatalf("findingEvaluationRunListQuery().args[2] = %#v, want completed", got)
	}
	if got := args[3]; got != cutoff {
		t.Fatalf("findingEvaluationRunListQuery().args[3] = %#v, want %v", got, cutoff)
	}
	if got := args[4]; got != int64(25) {
		t.Fatalf("findingEvaluationRunListQuery().args[4] = %#v, want 25", got)
	}
}
