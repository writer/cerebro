package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
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

func TestParseAppendLogDeadLetterActionArgsRequiresActorAndReason(t *testing.T) {
	id, actor, reason, err := parseAppendLogDeadLetterActionArgs("replay", []string{"apdl_1", "actor=oncall@example.com", "reason=INC-123"})
	if err != nil {
		t.Fatalf("parseAppendLogDeadLetterActionArgs() error = %v", err)
	}
	if id != "apdl_1" || actor != "oncall@example.com" || reason != "INC-123" {
		t.Fatalf("action args = %q, %q, %q", id, actor, reason)
	}
	if _, _, _, err := parseAppendLogDeadLetterActionArgs("replay", []string{"apdl_1", "reason=INC-123"}); err == nil {
		t.Fatal("parseAppendLogDeadLetterActionArgs() missing actor error = nil")
	}
}

func TestParseAppendLogDeadLetterCleanupArgsAllowsConfiguredRetentionCutoff(t *testing.T) {
	request, err := parseAppendLogDeadLetterCleanupArgs([]string{"actor=oncall@example.com", "reason=scheduled-retention"})
	if err != nil {
		t.Fatalf("parseAppendLogDeadLetterCleanupArgs() error = %v", err)
	}
	if !request.TerminalBefore.IsZero() {
		t.Fatalf("TerminalBefore = %v, want command to apply configured retention", request.TerminalBefore)
	}
}

func TestAppendLogDeadLetterBacklogResponseDoesNotContainPayload(t *testing.T) {
	response := appendLogDeadLetterBacklogResponse(ports.AppendLogDeadLetterBacklog{
		PendingRecords:      3,
		TerminalRecords:     8,
		PendingPayloadBytes: 512,
		OldestPendingAt:     time.Date(2026, time.July, 1, 2, 3, 4, 0, time.FixedZone("offset", -7*60*60)),
		PendingRetention:    7 * 24 * time.Hour,
		TerminalRetention:   30 * 24 * time.Hour,
		WarningRecords:      10,
		HardRecords:         100,
		WarningBytes:        1024,
		HardBytes:           2048,
	})
	if response.PendingRecords != 3 || response.TerminalRecords != 8 || response.PendingPayloadBytes != 512 {
		t.Fatalf("response = %#v", response)
	}
	if response.OldestPendingAt != "2026-07-01T09:03:04Z" {
		t.Fatalf("OldestPendingAt = %q", response.OldestPendingAt)
	}
	if response.PendingRetentionSeconds != int64((7*24*time.Hour).Seconds()) || response.TerminalRetentionSeconds != int64((30*24*time.Hour).Seconds()) {
		t.Fatalf("retention seconds = %d/%d", response.PendingRetentionSeconds, response.TerminalRetentionSeconds)
	}
}

func TestRunWithDeadLetterReplayLeasePreservesSuccessfulAppend(t *testing.T) {
	renewErr := errors.New("renewal canceled")
	store := &replayLeaseTestStore{renewErr: renewErr}
	appendLog := &replayLeaseTestAppendLog{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := runWithDeadLetterReplayLease(ctx, store, "dead-letter-1", "token-1", time.Millisecond, func(replayCtx context.Context) error {
		return appendLog.Append(replayCtx, &cerebrov1.EventEnvelope{})
	})
	if err != nil {
		t.Fatalf("runWithDeadLetterReplayLease() error = %v, want successful append", err)
	}
	if store.renewCalls != 1 {
		t.Fatalf("renew calls = %d, want 1", store.renewCalls)
	}
}

func TestRunWithDeadLetterReplayLeaseJoinsAppendAndRenewalFailures(t *testing.T) {
	appendErr := errors.New("append failed")
	renewErr := errors.New("renewal canceled")
	store := &replayLeaseTestStore{renewErr: renewErr}
	appendLog := &replayLeaseTestAppendLog{err: appendErr}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := runWithDeadLetterReplayLease(ctx, store, "dead-letter-1", "token-1", time.Millisecond, func(replayCtx context.Context) error {
		return appendLog.Append(replayCtx, &cerebrov1.EventEnvelope{})
	})
	if !errors.Is(err, appendErr) || !errors.Is(err, renewErr) {
		t.Fatalf("runWithDeadLetterReplayLease() error = %v, want append and renewal failures", err)
	}
}

func TestAppendLogDeadLetterBacklogResponseHardLimitUsesEnforcementBoundary(t *testing.T) {
	atLimit := appendLogDeadLetterBacklogResponse(ports.AppendLogDeadLetterBacklog{
		PendingRecords: 10, HardRecords: 10,
		PendingPayloadBytes: 100, HardBytes: 100,
	})
	if atLimit.HardLimitReached {
		t.Fatal("HardLimitReached = true at the configured limit")
	}

	aboveLimit := appendLogDeadLetterBacklogResponse(ports.AppendLogDeadLetterBacklog{
		PendingRecords: 11, HardRecords: 10,
		PendingPayloadBytes: 100, HardBytes: 100,
	})
	if !aboveLimit.HardLimitReached {
		t.Fatal("HardLimitReached = false above the configured limit")
	}
}

type replayLeaseTestAppendLog struct {
	ports.AppendLog
	err error
}

func (l *replayLeaseTestAppendLog) Append(ctx context.Context, _ *cerebrov1.EventEnvelope) error {
	<-ctx.Done()
	return l.err
}

type replayLeaseTestStore struct {
	ports.AppendLogDeadLetterStore
	renewErr   error
	renewCalls int
}

func (s *replayLeaseTestStore) RenewAppendLogDeadLetterReplay(context.Context, string, string, time.Duration) error {
	s.renewCalls++
	return s.renewErr
}

type replayDeadLetterTestStore struct {
	ports.AppendLogDeadLetterStore
	record          ports.AppendLogDeadLetter
	claims          int
	completed       int
	releasedReasons []string
}

func (s *replayDeadLetterTestStore) GetAppendLogDeadLetter(context.Context, string) (ports.AppendLogDeadLetter, error) {
	return s.record, nil
}

func (s *replayDeadLetterTestStore) ClaimAppendLogDeadLetterReplay(context.Context, string, string, string, time.Duration) (ports.AppendLogDeadLetter, error) {
	s.claims++
	return s.record, nil
}

func (s *replayDeadLetterTestStore) RenewAppendLogDeadLetterReplay(context.Context, string, string, time.Duration) error {
	return nil
}

func (s *replayDeadLetterTestStore) CompleteAppendLogDeadLetterReplay(context.Context, string, string, string, string) error {
	s.completed++
	return nil
}

func (s *replayDeadLetterTestStore) ReleaseAppendLogDeadLetterReplay(_ context.Context, _ string, _ string, category string) error {
	s.releasedReasons = append(s.releasedReasons, category)
	return nil
}

type replayRecordingAppendLog struct {
	ports.AppendLog
	appended []*cerebrov1.EventEnvelope
}

func (l *replayRecordingAppendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	l.appended = append(l.appended, event)
	return nil
}

type replayRecordingProjector struct {
	err       error
	projected []*cerebrov1.EventEnvelope
}

func (p *replayRecordingProjector) Project(_ context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	p.projected = append(p.projected, event)
	return ports.ProjectionResult{}, p.err
}

type replayRejectedProjectionError struct{}

func (replayRejectedProjectionError) Error() string               { return "rejected" }
func (replayRejectedProjectionError) ProjectionErrorCode() string { return "invalid_legacy_projection" }
func (replayRejectedProjectionError) Is(target error) bool {
	return target == ports.ErrSourceProjectionRecordRejected
}

func replayTestDeadLetter(operation string) ports.AppendLogDeadLetter {
	return ports.AppendLogDeadLetter{
		ID:        "apdl_1",
		Status:    ports.AppendLogDeadLetterStatusPending,
		Operation: operation,
		Event:     &cerebrov1.EventEnvelope{Id: "event-1", Kind: "okta.user"},
	}
}

func TestReplayAppendLogDeadLetterReprojectsSourceProjectionRecords(t *testing.T) {
	store := &replayDeadLetterTestStore{record: replayTestDeadLetter(ports.AppendLogDeadLetterOperationSourceProjection)}
	appendLog := &replayRecordingAppendLog{}
	projector := &replayRecordingProjector{}

	record, err := replayAppendLogDeadLetter(context.Background(), store, appendLog, projector, "apdl_1", "oncall@example.com", "INC-1")
	if err != nil {
		t.Fatalf("replayAppendLogDeadLetter() error = %v", err)
	}
	if record.ID != "apdl_1" || len(projector.projected) != 1 || len(appendLog.appended) != 0 {
		t.Fatalf("projected/appended = %d/%d, want 1/0", len(projector.projected), len(appendLog.appended))
	}
	if store.completed != 1 || len(store.releasedReasons) != 0 {
		t.Fatalf("completed/released = %d/%v, want 1/[]", store.completed, store.releasedReasons)
	}
}

func TestReplayAppendLogDeadLetterReleasesRejectedReprojection(t *testing.T) {
	store := &replayDeadLetterTestStore{record: replayTestDeadLetter(ports.AppendLogDeadLetterOperationSourceProjection)}
	appendLog := &replayRecordingAppendLog{}
	projector := &replayRecordingProjector{err: replayRejectedProjectionError{}}

	_, err := replayAppendLogDeadLetter(context.Background(), store, appendLog, projector, "apdl_1", "oncall@example.com", "INC-1")
	if !errors.Is(err, ports.ErrSourceProjectionRecordRejected) {
		t.Fatalf("replayAppendLogDeadLetter() error = %v, want record rejection", err)
	}
	if len(appendLog.appended) != 0 || store.completed != 0 {
		t.Fatalf("appended/completed = %d/%d, want 0/0", len(appendLog.appended), store.completed)
	}
	if len(store.releasedReasons) != 1 || store.releasedReasons[0] != "invalid_legacy_projection" {
		t.Fatalf("released reasons = %v, want [invalid_legacy_projection]", store.releasedReasons)
	}
}

func TestReplayAppendLogDeadLetterRequiresProjectorForSourceProjection(t *testing.T) {
	store := &replayDeadLetterTestStore{record: replayTestDeadLetter(ports.AppendLogDeadLetterOperationSourceProjection)}
	appendLog := &replayRecordingAppendLog{}

	_, err := replayAppendLogDeadLetter(context.Background(), store, appendLog, nil, "apdl_1", "oncall@example.com", "INC-1")
	if err == nil {
		t.Fatal("replayAppendLogDeadLetter() error = nil, want missing projector")
	}
	if store.claims != 0 || len(appendLog.appended) != 0 {
		t.Fatalf("claims/appended = %d/%d, want 0/0", store.claims, len(appendLog.appended))
	}
}

func TestReplayAppendLogDeadLetterRepublishesAppendRecords(t *testing.T) {
	store := &replayDeadLetterTestStore{record: replayTestDeadLetter("append")}
	appendLog := &replayRecordingAppendLog{}
	projector := &replayRecordingProjector{}

	if _, err := replayAppendLogDeadLetter(context.Background(), store, appendLog, projector, "apdl_1", "oncall@example.com", "INC-1"); err != nil {
		t.Fatalf("replayAppendLogDeadLetter() error = %v", err)
	}
	if len(appendLog.appended) != 1 || len(projector.projected) != 0 || store.completed != 1 {
		t.Fatalf("appended/projected/completed = %d/%d/%d, want 1/0/1", len(appendLog.appended), len(projector.projected), store.completed)
	}
}
