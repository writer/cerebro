package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/bootstrap"
	appconfig "github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func runAppendLog(args []string) error {
	if len(args) == 0 {
		return appendLogDeadLetterUsageError()
	}
	switch args[0] {
	case "dead-letters":
		return runAppendLogDeadLetters(args[1:])
	default:
		return appendLogDeadLetterUsageError()
	}
}

func runAppendLogDeadLetters(args []string) error {
	if len(args) == 0 {
		return appendLogDeadLetterUsageError()
	}
	cfg, err := appconfig.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	ctx, stop := sourceRuntimeCommandContext()
	defer stop()
	closeTelemetry, err := configureOpenTelemetry(ctx, cfg)
	if err != nil {
		return fmt.Errorf("configure telemetry: %w", err)
	}
	defer shutdownTelemetry(context.Background(), closeTelemetry, cfg.ShutdownTimeout)

	switch args[0] {
	case "list":
		return runAppendLogDeadLetterList(ctx, cfg, args[1:])
	case "replay":
		return runAppendLogDeadLetterReplay(ctx, cfg, args[1:])
	case "discard":
		return runAppendLogDeadLetterDiscard(ctx, cfg, args[1:])
	case "stats":
		return runAppendLogDeadLetterStats(ctx, cfg, args[1:])
	case "cleanup":
		return runAppendLogDeadLetterCleanup(ctx, cfg, args[1:])
	default:
		return appendLogDeadLetterUsageError()
	}
}

func appendLogDeadLetterUsageError() error {
	return usageError(fmt.Sprintf("usage: %s append-log dead-letters [list|replay|discard|stats|cleanup] ...", os.Args[0]))
}

func runAppendLogDeadLetterList(ctx context.Context, cfg appconfig.Config, args []string) error {
	filter, err := parseAppendLogDeadLetterListArgs(args)
	if err != nil {
		return err
	}
	store, closeDeps, err := openAppendLogDeadLetterStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		if err := closeDeps(); err != nil {
			log.Printf("close dependencies: %v", err)
		}
	}()
	records, err := store.ListAppendLogDeadLetters(ctx, filter)
	if err != nil {
		return err
	}
	return printJSON(appendLogDeadLetterListResponse(records))
}

func runAppendLogDeadLetterReplay(ctx context.Context, cfg appconfig.Config, args []string) error {
	id, actor, reason, err := parseAppendLogDeadLetterActionArgs("replay", args)
	if err != nil {
		return err
	}
	deps, closeDeps, err := bootstrap.OpenDependencies(ctx, cfg)
	if err != nil {
		return fmt.Errorf("open dependencies: %w", err)
	}
	defer func() {
		if err := closeDeps(); err != nil {
			log.Printf("close dependencies: %v", err)
		}
	}()
	store := appendLogDeadLetterStore(deps.StateStore)
	if store == nil {
		return errors.New("append log dead letter store is not configured")
	}
	if deps.AppendLog == nil {
		return errors.New("append log is not configured")
	}
	owner, token, err := newAppendLogDeadLetterReplayClaim()
	if err != nil {
		return err
	}
	record, err := store.ClaimAppendLogDeadLetterReplay(ctx, id, owner, token, 2*time.Minute)
	if err != nil {
		if errors.Is(err, ports.ErrAppendLogDeadLetterReplayClaimed) {
			return fmt.Errorf("append log dead letter %q replay is already claimed", id)
		}
		return err
	}
	if record.Event == nil {
		_ = store.ReleaseAppendLogDeadLetterReplay(ctx, id, token, "missing_event")
		return fmt.Errorf("append log dead letter %q has no replay event", id)
	}
	if err := appendWithDeadLetterReplayLease(ctx, deps.AppendLog, store, id, token, record.Event); err != nil {
		if releaseErr := store.ReleaseAppendLogDeadLetterReplay(ctx, id, token, "append_failed"); releaseErr != nil {
			return fmt.Errorf("replay append log dead letter %q: %w", id, errors.Join(err, fmt.Errorf("release claim: %w", releaseErr)))
		}
		return fmt.Errorf("replay append log dead letter %q: %w", id, err)
	}
	if err := store.CompleteAppendLogDeadLetterReplay(ctx, id, token, actor, reason); err != nil {
		if errors.Is(err, ports.ErrAppendLogDeadLetterAlreadyReplayed) {
			return printJSON(appendLogDeadLetterActionResponse(record, ports.AppendLogDeadLetterStatusReplayed))
		}
		return err
	}
	return printJSON(appendLogDeadLetterActionResponse(record, ports.AppendLogDeadLetterStatusReplayed))
}

func appendWithDeadLetterReplayLease(ctx context.Context, appendLog ports.AppendLog, store ports.AppendLogDeadLetterStore, id string, token string, event *cerebrov1.EventEnvelope) error {
	appendCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	renewed := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-appendCtx.Done():
				renewed <- nil
				return
			case <-ticker.C:
				if err := store.RenewAppendLogDeadLetterReplay(appendCtx, id, token, 2*time.Minute); err != nil {
					renewed <- err
					cancel()
					return
				}
			}
		}
	}()
	appendErr := appendLog.Append(appendCtx, event)
	cancel()
	renewErr := <-renewed
	if renewErr != nil {
		return fmt.Errorf("renew replay claim: %w", renewErr)
	}
	return appendErr
}

func newAppendLogDeadLetterReplayClaim() (string, string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", fmt.Errorf("generate append log dead letter replay claim: %w", err)
	}
	token := hex.EncodeToString(raw[:])
	return "cerebro-cli:" + token[:16], token, nil
}

func runAppendLogDeadLetterDiscard(ctx context.Context, cfg appconfig.Config, args []string) error {
	id, actor, reason, err := parseAppendLogDeadLetterDiscardArgs(args)
	if err != nil {
		return err
	}
	store, closeDeps, err := openAppendLogDeadLetterStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		if err := closeDeps(); err != nil {
			log.Printf("close dependencies: %v", err)
		}
	}()
	record, err := store.GetAppendLogDeadLetter(ctx, id)
	if err != nil {
		return err
	}
	if strings.TrimSpace(record.Status) != ports.AppendLogDeadLetterStatusPending {
		return fmt.Errorf("append log dead letter %q has status %q", id, record.Status)
	}
	if err := store.DiscardAppendLogDeadLetter(ctx, id, actor, reason); err != nil {
		return err
	}
	return printJSON(appendLogDeadLetterActionResponse(record, ports.AppendLogDeadLetterStatusDiscarded))
}

func runAppendLogDeadLetterStats(ctx context.Context, cfg appconfig.Config, args []string) error {
	if len(args) != 0 {
		return usageError(fmt.Sprintf("usage: %s append-log dead-letters stats", os.Args[0]))
	}
	store, closeDeps, err := openAppendLogDeadLetterStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		if err := closeDeps(); err != nil {
			log.Printf("close dependencies: %v", err)
		}
	}()
	backlog, err := store.GetAppendLogDeadLetterBacklog(ctx)
	if err != nil {
		return err
	}
	return printJSON(appendLogDeadLetterBacklogResponse(backlog))
}

func runAppendLogDeadLetterCleanup(ctx context.Context, cfg appconfig.Config, args []string) error {
	request, err := parseAppendLogDeadLetterCleanupArgs(args)
	if err != nil {
		return err
	}
	if request.TerminalBefore.IsZero() {
		request.TerminalBefore = time.Now().Add(-cfg.StateStore.DeadLetterTerminalRetention)
	}
	store, closeDeps, err := openAppendLogDeadLetterStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		if err := closeDeps(); err != nil {
			log.Printf("close dependencies: %v", err)
		}
	}()
	result, err := store.CleanupAppendLogDeadLetters(ctx, request)
	if err != nil {
		return err
	}
	return printJSON(appendLogDeadLetterCleanupResponse(result))
}

func openAppendLogDeadLetterStore(ctx context.Context, cfg appconfig.Config) (ports.AppendLogDeadLetterStore, func() error, error) {
	deps, closeDeps, err := bootstrap.OpenSourceRuntimeBootstrapDependencies(ctx, cfg)
	if err != nil {
		return nil, func() error { return nil }, fmt.Errorf("open state store: %w", err)
	}
	store := appendLogDeadLetterStore(deps.StateStore)
	if store == nil {
		_ = closeDeps()
		return nil, func() error { return nil }, errors.New("append log dead letter store is not configured")
	}
	return store, closeDeps, nil
}

func appendLogDeadLetterStore(store ports.StateStore) ports.AppendLogDeadLetterStore {
	deadLetters, ok := store.(ports.AppendLogDeadLetterStore)
	if !ok {
		return nil
	}
	return deadLetters
}

func parseAppendLogDeadLetterListArgs(args []string) (ports.AppendLogDeadLetterFilter, error) {
	filter := ports.AppendLogDeadLetterFilter{Status: ports.AppendLogDeadLetterStatusPending}
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return ports.AppendLogDeadLetterFilter{}, fmt.Errorf("invalid append log dead-letter list argument %q; want key=value", arg)
		}
		switch strings.TrimSpace(key) {
		case "status":
			filter.Status = strings.TrimSpace(value)
		case "subject":
			filter.Subject = strings.TrimSpace(value)
		case "runtime_id":
			filter.RuntimeID = strings.TrimSpace(value)
		case "source_id":
			filter.SourceID = strings.TrimSpace(value)
		case "limit":
			parsed, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return ports.AppendLogDeadLetterFilter{}, fmt.Errorf("parse limit: %w", err)
			}
			filter.Limit = uint32(parsed)
		default:
			return ports.AppendLogDeadLetterFilter{}, fmt.Errorf("unsupported append log dead-letter list argument %q", key)
		}
	}
	return filter, nil
}

func parseAppendLogDeadLetterDiscardArgs(args []string) (string, string, string, error) {
	return parseAppendLogDeadLetterActionArgs("discard", args)
}

func parseAppendLogDeadLetterActionArgs(command string, args []string) (string, string, string, error) {
	if len(args) < 2 || strings.TrimSpace(args[0]) == "" {
		return "", "", "", usageError(fmt.Sprintf("usage: %s append-log dead-letters %s <dead-letter-id> actor=<actor> reason=<reason>", os.Args[0], command))
	}
	id := strings.TrimSpace(args[0])
	actor := ""
	reason := ""
	for _, arg := range args[1:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return "", "", "", fmt.Errorf("invalid append log dead-letter %s argument %q; want key=value", command, arg)
		}
		switch strings.TrimSpace(key) {
		case "actor":
			actor = strings.TrimSpace(value)
		case "reason":
			reason = strings.TrimSpace(value)
		default:
			return "", "", "", fmt.Errorf("unsupported append log dead-letter %s argument %q", command, key)
		}
	}
	if actor == "" || reason == "" {
		return "", "", "", fmt.Errorf("%s actor and reason are required", command)
	}
	return id, actor, reason, nil
}

func parseAppendLogDeadLetterCleanupArgs(args []string) (ports.AppendLogDeadLetterCleanupRequest, error) {
	request := ports.AppendLogDeadLetterCleanupRequest{}
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return ports.AppendLogDeadLetterCleanupRequest{}, fmt.Errorf("invalid append log dead-letter cleanup argument %q; want key=value", arg)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "terminal_before":
			cutoff, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return ports.AppendLogDeadLetterCleanupRequest{}, fmt.Errorf("parse terminal_before as RFC3339: %w", err)
			}
			request.TerminalBefore = cutoff
		case "after_id":
			request.AfterID = value
		case "actor":
			request.Actor = value
		case "reason":
			request.Reason = value
		case "limit":
			parsed, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return ports.AppendLogDeadLetterCleanupRequest{}, fmt.Errorf("parse limit: %w", err)
			}
			request.Limit = uint32(parsed)
		default:
			return ports.AppendLogDeadLetterCleanupRequest{}, fmt.Errorf("unsupported append log dead-letter cleanup argument %q", key)
		}
	}
	if strings.TrimSpace(request.Actor) == "" || strings.TrimSpace(request.Reason) == "" {
		return ports.AppendLogDeadLetterCleanupRequest{}, usageError(fmt.Sprintf("usage: %s append-log dead-letters cleanup actor=<actor> reason=<reason> [terminal_before=<RFC3339>] [after_id=<dead-letter-id>] [limit=<count>]", os.Args[0]))
	}
	return request, nil
}

type appendLogDeadLetterSummary struct {
	ID                      string `json:"id"`
	Status                  string `json:"status"`
	Subject                 string `json:"subject"`
	Operation               string `json:"operation"`
	EventID                 string `json:"event_id"`
	EventKind               string `json:"event_kind"`
	TenantID                string `json:"tenant_id,omitempty"`
	SourceID                string `json:"source_id,omitempty"`
	RuntimeID               string `json:"runtime_id,omitempty"`
	JobID                   string `json:"job_id,omitempty"`
	ErrorCategory           string `json:"error_category,omitempty"`
	RetryCount              int    `json:"retry_count,omitempty"`
	MaxAttempts             int    `json:"max_attempts,omitempty"`
	PayloadHash             string `json:"payload_hash,omitempty"`
	PayloadBytes            int    `json:"payload_bytes,omitempty"`
	CreatedAt               string `json:"created_at,omitempty"`
	UpdatedAt               string `json:"updated_at,omitempty"`
	ReplayClaimed           bool   `json:"replay_claimed,omitempty"`
	ReplayOwner             string `json:"replay_owner,omitempty"`
	ReplayLeaseExpiresAt    string `json:"replay_lease_expires_at,omitempty"`
	ReplayAttemptCount      int    `json:"replay_attempt_count,omitempty"`
	LastReplayErrorCategory string `json:"last_replay_error_category,omitempty"`
}

type appendLogDeadLetterListOutput struct {
	Records []appendLogDeadLetterSummary `json:"records"`
	Count   int                          `json:"count"`
}

type appendLogDeadLetterActionOutput struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	EventID string `json:"event_id"`
	Subject string `json:"subject"`
}

type appendLogDeadLetterBacklogOutput struct {
	PendingRecords           int64  `json:"pending_records"`
	TerminalRecords          int64  `json:"terminal_records"`
	PendingPayloadBytes      int64  `json:"pending_payload_bytes"`
	OldestPendingAt          string `json:"oldest_pending_at,omitempty"`
	OldestPendingAgeSeconds  int64  `json:"oldest_pending_age_seconds,omitempty"`
	PendingRetentionSeconds  int64  `json:"pending_retention_seconds"`
	TerminalRetentionSeconds int64  `json:"terminal_retention_seconds"`
	WarningRecords           int64  `json:"warning_records"`
	HardRecords              int64  `json:"hard_records"`
	WarningBytes             int64  `json:"warning_bytes"`
	HardBytes                int64  `json:"hard_bytes"`
	PendingRetentionExceeded bool   `json:"pending_retention_exceeded"`
	WarningLimitReached      bool   `json:"warning_limit_reached"`
	HardLimitReached         bool   `json:"hard_limit_reached"`
}

type appendLogDeadLetterCleanupOutput struct {
	DeletedIDs   []string `json:"deleted_ids"`
	DeletedCount int      `json:"deleted_count"`
	NextAfterID  string   `json:"next_after_id,omitempty"`
	HasMore      bool     `json:"has_more"`
}

func appendLogDeadLetterListResponse(records []ports.AppendLogDeadLetter) appendLogDeadLetterListOutput {
	out := appendLogDeadLetterListOutput{Records: make([]appendLogDeadLetterSummary, 0, len(records)), Count: len(records)}
	for _, record := range records {
		out.Records = append(out.Records, appendLogDeadLetterSummaryFor(record))
	}
	return out
}

func appendLogDeadLetterSummaryFor(record ports.AppendLogDeadLetter) appendLogDeadLetterSummary {
	summary := appendLogDeadLetterSummary{
		ID:                      record.ID,
		Status:                  record.Status,
		Subject:                 record.Subject,
		Operation:               record.Operation,
		EventID:                 record.EventID,
		EventKind:               record.EventKind,
		TenantID:                record.TenantID,
		SourceID:                record.SourceID,
		RuntimeID:               record.RuntimeID,
		JobID:                   record.JobID,
		ErrorCategory:           record.ErrorCategory,
		RetryCount:              record.RetryCount,
		MaxAttempts:             record.MaxAttempts,
		PayloadHash:             record.PayloadHash,
		PayloadBytes:            record.PayloadBytes,
		ReplayClaimed:           strings.TrimSpace(record.Replay.Token) != "" && record.Replay.LeaseExpiresAt.After(time.Now()),
		ReplayOwner:             record.Replay.Owner,
		ReplayAttemptCount:      record.Replay.AttemptCount,
		LastReplayErrorCategory: record.Replay.LastErrorCategory,
	}
	if !record.CreatedAt.IsZero() {
		summary.CreatedAt = record.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	if !record.UpdatedAt.IsZero() {
		summary.UpdatedAt = record.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	if !record.Replay.LeaseExpiresAt.IsZero() {
		summary.ReplayLeaseExpiresAt = record.Replay.LeaseExpiresAt.UTC().Format(time.RFC3339)
	}
	return summary
}

func appendLogDeadLetterActionResponse(record ports.AppendLogDeadLetter, status string) appendLogDeadLetterActionOutput {
	return appendLogDeadLetterActionOutput{
		ID:      record.ID,
		Status:  status,
		EventID: record.EventID,
		Subject: record.Subject,
	}
}

func appendLogDeadLetterBacklogResponse(backlog ports.AppendLogDeadLetterBacklog) appendLogDeadLetterBacklogOutput {
	response := appendLogDeadLetterBacklogOutput{
		PendingRecords:           backlog.PendingRecords,
		TerminalRecords:          backlog.TerminalRecords,
		PendingPayloadBytes:      backlog.PendingPayloadBytes,
		PendingRetentionSeconds:  int64(backlog.PendingRetention.Seconds()),
		TerminalRetentionSeconds: int64(backlog.TerminalRetention.Seconds()),
		WarningRecords:           backlog.WarningRecords,
		HardRecords:              backlog.HardRecords,
		WarningBytes:             backlog.WarningBytes,
		HardBytes:                backlog.HardBytes,
		WarningLimitReached:      backlog.PendingRecords >= backlog.WarningRecords || backlog.PendingPayloadBytes >= backlog.WarningBytes,
		HardLimitReached:         backlog.PendingRecords >= backlog.HardRecords || backlog.PendingPayloadBytes >= backlog.HardBytes,
	}
	if !backlog.OldestPendingAt.IsZero() {
		response.OldestPendingAt = backlog.OldestPendingAt.UTC().Format(time.RFC3339)
		age := time.Since(backlog.OldestPendingAt)
		if age > 0 {
			response.OldestPendingAgeSeconds = int64(age.Seconds())
			response.PendingRetentionExceeded = backlog.PendingRetention > 0 && age >= backlog.PendingRetention
		}
	}
	return response
}

func appendLogDeadLetterCleanupResponse(result ports.AppendLogDeadLetterCleanupResult) appendLogDeadLetterCleanupOutput {
	return appendLogDeadLetterCleanupOutput{
		DeletedIDs:   result.DeletedIDs,
		DeletedCount: len(result.DeletedIDs),
		NextAfterID:  result.NextAfterID,
		HasMore:      result.HasMore,
	}
}
