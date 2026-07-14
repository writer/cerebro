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
