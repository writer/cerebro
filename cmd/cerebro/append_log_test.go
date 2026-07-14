package main

import (
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestNewAppendLogDeadLetterReplayClaimIsOpaqueAndUnique(t *testing.T) {
	firstOwner, firstToken, err := newAppendLogDeadLetterReplayClaim()
	if err != nil {
		t.Fatalf("newAppendLogDeadLetterReplayClaim() error = %v", err)
	}
	secondOwner, secondToken, err := newAppendLogDeadLetterReplayClaim()
	if err != nil {
		t.Fatalf("newAppendLogDeadLetterReplayClaim() second error = %v", err)
	}
	if !strings.HasPrefix(firstOwner, "cerebro-cli:") || len(firstToken) != 64 {
		t.Fatalf("claim = (%q, %q), want opaque CLI owner and 256-bit token", firstOwner, firstToken)
	}
	if firstOwner == secondOwner || firstToken == secondToken {
		t.Fatal("consecutive replay claims must be unique")
	}
}

func TestAppendLogDeadLetterSummaryShowsClaimWithoutToken(t *testing.T) {
	record := ports.AppendLogDeadLetter{
		ID: "apdl_1",
		Replay: ports.AppendLogDeadLetterReplayState{
			Owner: "cerebro-cli:owner", Token: "secret-token",
			LeaseExpiresAt: time.Now().Add(time.Minute), AttemptCount: 2,
			LastErrorCategory: "append_failed",
		},
	}
	summary := appendLogDeadLetterSummaryFor(record)
	if !summary.ReplayClaimed || summary.ReplayOwner != record.Replay.Owner || summary.ReplayAttemptCount != 2 {
		t.Fatalf("appendLogDeadLetterSummaryFor() = %#v, want active claim metadata", summary)
	}
	if strings.Contains(summary.ReplayOwner, record.Replay.Token) {
		t.Fatal("operator summary exposed replay token")
	}
}

func TestParseAppendLogDeadLetterCleanupArgs(t *testing.T) {
	request, err := parseAppendLogDeadLetterCleanupArgs([]string{
		"terminal_before=2026-07-01T00:00:00Z",
		"actor=oncall@example.com",
		"reason=retention-policy-30d",
		"after_id=apdl_10",
		"limit=75",
	})
	if err != nil {
		t.Fatalf("parseAppendLogDeadLetterCleanupArgs() error = %v", err)
	}
	if got := request.TerminalBefore.UTC().Format(time.RFC3339); got != "2026-07-01T00:00:00Z" {
		t.Fatalf("TerminalBefore = %q", got)
	}
	if request.Actor != "oncall@example.com" || request.Reason != "retention-policy-30d" || request.AfterID != "apdl_10" || request.Limit != 75 {
		t.Fatalf("request = %#v", request)
	}
}

func TestParseAppendLogDeadLetterCleanupArgsRequiresAuditContext(t *testing.T) {
	_, err := parseAppendLogDeadLetterCleanupArgs([]string{"terminal_before=2026-07-01T00:00:00Z"})
	if err == nil {
		t.Fatal("parseAppendLogDeadLetterCleanupArgs() error = nil, want actor and reason requirement")
	}
}

func TestAppendLogDeadLetterBacklogResponseDoesNotContainPayload(t *testing.T) {
	response := appendLogDeadLetterBacklogResponse(ports.AppendLogDeadLetterBacklog{
		PendingRecords:      3,
		TerminalRecords:     8,
		PendingPayloadBytes: 512,
		OldestPendingAt:     time.Date(2026, time.July, 1, 2, 3, 4, 0, time.FixedZone("offset", -7*60*60)),
	})
	if response.PendingRecords != 3 || response.TerminalRecords != 8 || response.PendingPayloadBytes != 512 {
		t.Fatalf("response = %#v", response)
	}
	if response.OldestPendingAt != "2026-07-01T09:03:04Z" {
		t.Fatalf("OldestPendingAt = %q", response.OldestPendingAt)
	}
}
