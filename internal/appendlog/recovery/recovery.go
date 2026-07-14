package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/telemetry"
)

// Wrap persists max-attempt-exhausted append failures to store before returning
// the original append error to the caller.
func Wrap(inner ports.AppendLog, store ports.AppendLogDeadLetterStore) ports.AppendLog {
	if inner == nil || store == nil {
		return inner
	}
	return &Log{inner: inner, store: store}
}

// Log records exhausted publish attempts while preserving the append-log
// interface used by runtime and workflow services.
type Log struct {
	inner ports.AppendLog
	store ports.AppendLogDeadLetterStore
}

func (l *Log) Ping(ctx context.Context) error {
	if l == nil || l.inner == nil {
		return errors.New("append log is not configured")
	}
	return l.inner.Ping(ctx)
}

func (l *Log) Append(ctx context.Context, event *cerebrov1.EventEnvelope) error {
	if l == nil || l.inner == nil {
		return errors.New("append log is not configured")
	}
	err := l.inner.Append(ctx, event)
	if err == nil {
		return nil
	}
	if recordErr := l.recordExhaustedPublish(ctx, event, err); recordErr != nil {
		return errors.Join(err, recordErr)
	}
	return err
}

func (l *Log) AppendBatch(ctx context.Context, events []*cerebrov1.EventEnvelope) error {
	for index, event := range events {
		if err := l.Append(ctx, event); err != nil {
			return fmt.Errorf("append batch event %d: %w", index, err)
		}
	}
	return nil
}

func (l *Log) Replay(ctx context.Context, request ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	replayer, ok := l.inner.(ports.EventReplayer)
	if !ok || replayer == nil {
		return nil, errors.New("append log replayer is not configured")
	}
	return replayer.Replay(ctx, request)
}

func (l *Log) ReplayPage(ctx context.Context, request ports.ReplayRequest) (ports.ReplayPage, error) {
	replayer, ok := l.inner.(ports.EventReplayPager)
	if !ok || replayer == nil {
		return ports.ReplayPage{}, errors.New("append log replay pager is not configured")
	}
	return replayer.ReplayPage(ctx, request)
}

func (l *Log) ScanRuntimeIndex(ctx context.Context, fromSeq uint64, batch uint32) (ports.RuntimeIndexScan, error) {
	source, ok := l.inner.(ports.RuntimeIndexSource)
	if !ok || source == nil {
		return ports.RuntimeIndexScan{}, errors.New("append log runtime index source is not configured")
	}
	return source.ScanRuntimeIndex(ctx, fromSeq, batch)
}

func (l *Log) recordExhaustedPublish(ctx context.Context, event *cerebrov1.EventEnvelope, err error) error {
	if l == nil || l.store == nil {
		return nil
	}
	var exhausted *ports.AppendLogPublishExhaustedError
	if !errors.As(err, &exhausted) || exhausted == nil {
		return nil
	}
	record, recordErr := deadLetterFromEvent(event, exhausted)
	if recordErr != nil {
		return fmt.Errorf("build append log dead letter: %w", recordErr)
	}
	if err := l.store.RecordAppendLogDeadLetter(ctx, record); err != nil {
		return fmt.Errorf("record append log dead letter %q: %w", record.ID, err)
	}
	telemetry.Event(ctx, "append_log.dead_letter.recorded", telemetry.Attrs(
		telemetry.Field{Key: "append_log.dead_letter.id", Value: record.ID},
		telemetry.Field{Key: "messaging.jetstream.subject", Value: record.Subject},
		telemetry.Field{Key: "event.kind", Value: record.EventKind},
		telemetry.Field{Key: "event.id_hash", Value: shortRecordHash(record.EventID)},
		telemetry.Field{Key: "runtime_id", Value: record.RuntimeID},
		telemetry.Field{Key: "source_id", Value: record.SourceID},
		telemetry.Field{Key: "tenant_id", Value: record.TenantID},
		telemetry.Field{Key: "job_id", Value: record.JobID},
		telemetry.Field{Key: "error_category", Value: record.ErrorCategory},
		telemetry.Field{Key: "retry_count", Value: record.RetryCount},
		telemetry.Field{Key: "max_attempts", Value: record.MaxAttempts},
	))
	telemetry.IncrementMain(ctx, "append_log.dead_letter.recorded.count", 1)
	return nil
}

func deadLetterFromEvent(event *cerebrov1.EventEnvelope, exhausted *ports.AppendLogPublishExhaustedError) (ports.AppendLogDeadLetter, error) {
	if event == nil {
		return ports.AppendLogDeadLetter{}, errors.New("event is required")
	}
	payload, hash, err := deterministicEventPayload(event)
	if err != nil {
		return ports.AppendLogDeadLetter{}, err
	}
	eventID := strings.TrimSpace(event.GetId())
	if eventID == "" {
		eventID = "sha256:" + hash
	}
	attrs := event.GetAttributes()
	record := ports.AppendLogDeadLetter{
		ID:            deadLetterID(strings.TrimSpace(exhausted.Subject), eventID, hash),
		Status:        ports.AppendLogDeadLetterStatusPending,
		Subject:       strings.TrimSpace(exhausted.Subject),
		Operation:     strings.TrimSpace(exhausted.Operation),
		EventID:       eventID,
		EventKind:     strings.TrimSpace(event.GetKind()),
		TenantID:      strings.TrimSpace(event.GetTenantId()),
		SourceID:      strings.TrimSpace(event.GetSourceId()),
		RuntimeID:     strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID]),
		JobID:         strings.TrimSpace(attrs[ports.EventAttributeJobID]),
		ErrorCategory: strings.TrimSpace(exhausted.ErrorCategory),
		ErrorMessage:  strings.TrimSpace(exhausted.Error()),
		RetryCount:    exhausted.RetryCount,
		MaxAttempts:   exhausted.MaxAttempts,
		PayloadHash:   hash,
		PayloadBytes:  len(payload),
		Event:         proto.Clone(event).(*cerebrov1.EventEnvelope),
	}
	if record.Operation == "" {
		record.Operation = "append"
	}
	if record.ErrorCategory == "" {
		record.ErrorCategory = "unknown"
	}
	return record, nil
}

func deterministicEventPayload(event *cerebrov1.EventEnvelope) ([]byte, string, error) {
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(event)
	if err != nil {
		return nil, "", fmt.Errorf("marshal append log event: %w", err)
	}
	sum := sha256.Sum256(payload)
	return payload, hex.EncodeToString(sum[:]), nil
}

func deadLetterID(subject string, eventID string, payloadHash string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strings.TrimSpace(subject),
		strings.TrimSpace(eventID),
		strings.TrimSpace(payloadHash),
	}, "\x00")))
	return "apdl_" + hex.EncodeToString(sum[:16])
}

func shortRecordHash(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:8])
}

var _ ports.AppendLog = (*Log)(nil)
var _ ports.AppendLogBatcher = (*Log)(nil)
var _ ports.EventReplayer = (*Log)(nil)
var _ ports.EventReplayPager = (*Log)(nil)
var _ ports.RuntimeIndexSource = (*Log)(nil)
