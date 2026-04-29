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

func TestFindingEvaluationRunListQueryIncludesOptionalFilters(t *testing.T) {
	query, args, err := findingEvaluationRunListQuery(ports.ListFindingEvaluationRunsRequest{
		RuntimeID: "writer-okta-audit",
		RuleID:    "identity-okta-policy-rule-lifecycle-tampering",
		Status:    "completed",
		Limit:     25,
	})
	if err != nil {
		t.Fatalf("findingEvaluationRunListQuery() error = %v", err)
	}
	for _, fragment := range []string{
		"runtime_id = $1",
		"rule_id = $2",
		"status = $3",
		"LIMIT $4",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("findingEvaluationRunListQuery() query missing %q: %s", fragment, query)
		}
	}
	if got := len(args); got != 4 {
		t.Fatalf("len(findingEvaluationRunListQuery().args) = %d, want 4", got)
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
	if got := args[3]; got != int64(25) {
		t.Fatalf("findingEvaluationRunListQuery().args[3] = %#v, want 25", got)
	}
}

func TestFindingEvaluationRunTimeReturnsZeroForNilTimestamp(t *testing.T) {
	if got := findingEvaluationRunTime((*timestamppb.Timestamp)(nil)); !got.IsZero() {
		t.Fatalf("findingEvaluationRunTime(nil) = %v, want zero time", got)
	}
}

func TestNullableTimeReturnsNilForNilFindingEvaluationRunTimestamp(t *testing.T) {
	if got := nullableTime(findingEvaluationRunTime((*timestamppb.Timestamp)(nil))); got != nil {
		t.Fatalf("nullableTime(findingEvaluationRunTime(nil)) = %#v, want nil", got)
	}
}
