package events

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
)

type consumerProcessedEventDeduper struct {
	store      *executionstore.SQLiteStore
	namespace  string
	ttl        time.Duration
	maxRecords int
}

func newConsumerProcessedEventDeduper(path, stream, durable string, ttl time.Duration, maxRecords int) (*consumerProcessedEventDeduper, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("consumer dedupe state file is required")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("consumer dedupe ttl must be > 0")
	}
	if maxRecords <= 0 {
		return nil, fmt.Errorf("consumer dedupe max records must be > 0")
	}
	store, err := executionstore.NewSQLiteStore(path)
	if err != nil {
		return nil, err
	}
	return &consumerProcessedEventDeduper{
		store:      store,
		namespace:  fmt.Sprintf("%s:%s:%s", executionstore.NamespaceProcessedCloudEvent, strings.TrimSpace(stream), strings.TrimSpace(durable)),
		ttl:        ttl,
		maxRecords: maxRecords,
	}, nil
}

func (d *consumerProcessedEventDeduper) Close() error {
	if d == nil || d.store == nil {
		return nil
	}
	return d.store.Close()
}

func (d *consumerProcessedEventDeduper) Lookup(ctx context.Context, evt CloudEvent, payload []byte, now time.Time) (*executionstore.ProcessedEventRecord, bool, error) {
	if d == nil || d.store == nil {
		return nil, false, nil
	}
	key, ok := consumerProcessedEventKey(evt)
	if !ok {
		return nil, false, nil
	}
	record, err := d.store.LookupProcessedEvent(ctx, d.namespace, key, now)
	if err != nil || record == nil {
		return record, false, err
	}
	return record, record.PayloadHash != consumerProcessedEventPayloadHash(payload), nil
}

func (d *consumerProcessedEventDeduper) ObserveDuplicate(ctx context.Context, evt CloudEvent, now time.Time) error {
	if d == nil || d.store == nil {
		return nil
	}
	key, ok := consumerProcessedEventKey(evt)
	if !ok {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	return d.store.TouchProcessedEvent(ctx, d.namespace, key, now, d.ttl)
}

func (d *consumerProcessedEventDeduper) Remember(ctx context.Context, evt CloudEvent, payload []byte, processedAt time.Time) error {
	if d == nil || d.store == nil {
		return nil
	}
	key, ok := consumerProcessedEventKey(evt)
	if !ok {
		return nil
	}
	if processedAt.IsZero() {
		processedAt = time.Now().UTC()
	} else {
		processedAt = processedAt.UTC()
	}
	return d.store.RememberProcessedEvent(ctx, executionstore.ProcessedEventRecord{
		Namespace:   d.namespace,
		EventKey:    key,
		PayloadHash: consumerProcessedEventPayloadHash(payload),
		FirstSeenAt: processedAt,
		LastSeenAt:  processedAt,
		ProcessedAt: processedAt,
		ExpiresAt:   processedAt.Add(d.ttl),
	}, d.maxRecords)
}

func (d *consumerProcessedEventDeduper) Forget(ctx context.Context, evt CloudEvent) error {
	if d == nil || d.store == nil {
		return nil
	}
	key, ok := consumerProcessedEventKey(evt)
	if !ok {
		return nil
	}
	return d.store.DeleteProcessedEvent(ctx, d.namespace, key)
}

func consumerProcessedEventKey(evt CloudEvent) (string, bool) {
	eventID := strings.TrimSpace(evt.ID)
	if eventID == "" {
		return "", false
	}
	source := strings.TrimSpace(evt.Source)
	if source == "" {
		source = "unknown"
	}
	tenantID := strings.TrimSpace(evt.TenantID)
	if tenantID == "" {
		tenantID = "default"
	}
	keyPayload, err := json.Marshal([]string{tenantID, source, eventID})
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(keyPayload)
	return "sha256:" + hex.EncodeToString(sum[:]), true
}

func consumerProcessedEventPayloadHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
