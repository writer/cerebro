package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/bootstrap"
	appconfig "github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func runAppendLog(args []string) error {
	if len(args) == 0 {
		return usageError(fmt.Sprintf("usage: %s append-log dead-letters [list|replay|discard] ...", os.Args[0]))
	}
	switch args[0] {
	case "dead-letters":
		return runAppendLogDeadLetters(args[1:])
	default:
		return usageError(fmt.Sprintf("usage: %s append-log dead-letters [list|replay|discard] ...", os.Args[0]))
	}
}

func runAppendLogDeadLetters(args []string) error {
	if len(args) == 0 {
		return usageError(fmt.Sprintf("usage: %s append-log dead-letters [list|replay|discard] ...", os.Args[0]))
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
	default:
		return usageError(fmt.Sprintf("usage: %s append-log dead-letters [list|replay|discard] ...", os.Args[0]))
	}
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
	id, err := parseAppendLogDeadLetterIDArg("replay", args)
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
	record, err := store.GetAppendLogDeadLetter(ctx, id)
	if err != nil {
		return err
	}
	if strings.TrimSpace(record.Status) != ports.AppendLogDeadLetterStatusPending {
		return fmt.Errorf("append log dead letter %q has status %q", id, record.Status)
	}
	if record.Event == nil {
		return fmt.Errorf("append log dead letter %q has no replay event", id)
	}
	if err := deps.AppendLog.Append(ctx, record.Event); err != nil {
		return fmt.Errorf("replay append log dead letter %q: %w", id, err)
	}
	if err := store.MarkAppendLogDeadLetterReplayed(ctx, id); err != nil {
		if errors.Is(err, ports.ErrAppendLogDeadLetterAlreadyReplayed) {
			return printJSON(appendLogDeadLetterActionResponse(record, ports.AppendLogDeadLetterStatusReplayed))
		}
		return err
	}
	return printJSON(appendLogDeadLetterActionResponse(record, ports.AppendLogDeadLetterStatusReplayed))
}

func runAppendLogDeadLetterDiscard(ctx context.Context, cfg appconfig.Config, args []string) error {
	id, reason, err := parseAppendLogDeadLetterDiscardArgs(args)
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
	if err := store.DiscardAppendLogDeadLetter(ctx, id, reason); err != nil {
		return err
	}
	return printJSON(appendLogDeadLetterActionResponse(record, ports.AppendLogDeadLetterStatusDiscarded))
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

func parseAppendLogDeadLetterIDArg(command string, args []string) (string, error) {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		return "", usageError(fmt.Sprintf("usage: %s append-log dead-letters %s <dead-letter-id>", os.Args[0], command))
	}
	return strings.TrimSpace(args[0]), nil
}

func parseAppendLogDeadLetterDiscardArgs(args []string) (string, string, error) {
	if len(args) < 2 || strings.TrimSpace(args[0]) == "" {
		return "", "", usageError(fmt.Sprintf("usage: %s append-log dead-letters discard <dead-letter-id> reason=<reason>", os.Args[0]))
	}
	id := strings.TrimSpace(args[0])
	reason := ""
	for _, arg := range args[1:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return "", "", fmt.Errorf("invalid append log dead-letter discard argument %q; want key=value", arg)
		}
		if strings.TrimSpace(key) != "reason" {
			return "", "", fmt.Errorf("unsupported append log dead-letter discard argument %q", key)
		}
		reason = strings.TrimSpace(value)
	}
	if reason == "" {
		return "", "", errors.New("discard reason is required")
	}
	return id, reason, nil
}

type appendLogDeadLetterSummary struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	Subject       string `json:"subject"`
	Operation     string `json:"operation"`
	EventID       string `json:"event_id"`
	EventKind     string `json:"event_kind"`
	TenantID      string `json:"tenant_id,omitempty"`
	SourceID      string `json:"source_id,omitempty"`
	RuntimeID     string `json:"runtime_id,omitempty"`
	JobID         string `json:"job_id,omitempty"`
	ErrorCategory string `json:"error_category,omitempty"`
	RetryCount    int    `json:"retry_count,omitempty"`
	MaxAttempts   int    `json:"max_attempts,omitempty"`
	PayloadHash   string `json:"payload_hash,omitempty"`
	PayloadBytes  int    `json:"payload_bytes,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
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

func appendLogDeadLetterListResponse(records []ports.AppendLogDeadLetter) appendLogDeadLetterListOutput {
	out := appendLogDeadLetterListOutput{Records: make([]appendLogDeadLetterSummary, 0, len(records)), Count: len(records)}
	for _, record := range records {
		out.Records = append(out.Records, appendLogDeadLetterSummaryFor(record))
	}
	return out
}

func appendLogDeadLetterSummaryFor(record ports.AppendLogDeadLetter) appendLogDeadLetterSummary {
	summary := appendLogDeadLetterSummary{
		ID:            record.ID,
		Status:        record.Status,
		Subject:       record.Subject,
		Operation:     record.Operation,
		EventID:       record.EventID,
		EventKind:     record.EventKind,
		TenantID:      record.TenantID,
		SourceID:      record.SourceID,
		RuntimeID:     record.RuntimeID,
		JobID:         record.JobID,
		ErrorCategory: record.ErrorCategory,
		RetryCount:    record.RetryCount,
		MaxAttempts:   record.MaxAttempts,
		PayloadHash:   record.PayloadHash,
		PayloadBytes:  record.PayloadBytes,
	}
	if !record.CreatedAt.IsZero() {
		summary.CreatedAt = record.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	if !record.UpdatedAt.IsZero() {
		summary.UpdatedAt = record.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
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
