package executionstore

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteStoreProcessedEventsRoundTripAndTouch(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Date(2026, 3, 12, 2, 0, 0, 0, time.UTC)
	err = store.RememberProcessedEvent(context.Background(), ProcessedEventRecord{
		Namespace:   NamespaceProcessedCloudEvent,
		EventKey:    "stream|durable|tenant|source|evt-1",
		PayloadHash: "hash-a",
		FirstSeenAt: now,
		LastSeenAt:  now,
		ProcessedAt: now,
		ExpiresAt:   now.Add(24 * time.Hour),
	}, 100)
	if err != nil {
		t.Fatalf("RememberProcessedEvent: %v", err)
	}

	record, err := store.LookupProcessedEvent(context.Background(), NamespaceProcessedCloudEvent, "stream|durable|tenant|source|evt-1", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("LookupProcessedEvent: %v", err)
	}
	if record == nil {
		t.Fatal("expected processed event record")
	}
	if record.PayloadHash != "hash-a" {
		t.Fatalf("expected payload hash hash-a, got %#v", record)
	}
	if record.DuplicateCount != 0 {
		t.Fatalf("expected read-only lookup to preserve duplicate count, got %#v", record)
	}

	if err := store.TouchProcessedEvent(context.Background(), NamespaceProcessedCloudEvent, "stream|durable|tenant|source|evt-1", now.Add(2*time.Hour), 24*time.Hour); err != nil {
		t.Fatalf("TouchProcessedEvent: %v", err)
	}

	touched, err := store.LookupProcessedEvent(context.Background(), NamespaceProcessedCloudEvent, "stream|durable|tenant|source|evt-1", now.Add(3*time.Hour))
	if err != nil {
		t.Fatalf("LookupProcessedEvent after touch: %v", err)
	}
	if touched == nil {
		t.Fatal("expected touched processed event record")
	}
	if touched.DuplicateCount != 1 {
		t.Fatalf("expected duplicate count increment to 1 after touch, got %#v", touched)
	}
}

func TestSQLiteStoreProcessedEventsTrimOldest(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	base := time.Date(2026, 3, 12, 2, 0, 0, 0, time.UTC)
	for i, key := range []string{"evt-1", "evt-2", "evt-3"} {
		ts := base.Add(time.Duration(i) * time.Minute)
		if err := store.RememberProcessedEvent(context.Background(), ProcessedEventRecord{
			Namespace:   NamespaceProcessedCloudEvent,
			EventKey:    key,
			PayloadHash: key,
			FirstSeenAt: ts,
			LastSeenAt:  ts,
			ProcessedAt: ts,
			ExpiresAt:   ts.Add(24 * time.Hour),
		}, 2); err != nil {
			t.Fatalf("RememberProcessedEvent %s: %v", key, err)
		}
	}

	first, err := store.LookupProcessedEvent(context.Background(), NamespaceProcessedCloudEvent, "evt-1", base.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("LookupProcessedEvent first: %v", err)
	}
	if first != nil {
		t.Fatalf("expected oldest processed event to be trimmed, got %#v", first)
	}
	last, err := store.LookupProcessedEvent(context.Background(), NamespaceProcessedCloudEvent, "evt-3", base.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("LookupProcessedEvent last: %v", err)
	}
	if last == nil {
		t.Fatal("expected newest processed event to remain after trim")
	}
}

func TestSQLiteStoreDeleteProcessedEvent(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Date(2026, 3, 12, 4, 0, 0, 0, time.UTC)
	if err := store.RememberProcessedEvent(context.Background(), ProcessedEventRecord{
		Namespace:   NamespaceProcessedCloudEvent,
		EventKey:    "evt-delete",
		PayloadHash: "hash-a",
		FirstSeenAt: now,
		LastSeenAt:  now,
		ProcessedAt: now,
		ExpiresAt:   now.Add(24 * time.Hour),
	}, 100); err != nil {
		t.Fatalf("RememberProcessedEvent: %v", err)
	}

	if err := store.DeleteProcessedEvent(context.Background(), NamespaceProcessedCloudEvent, "evt-delete"); err != nil {
		t.Fatalf("DeleteProcessedEvent: %v", err)
	}

	record, err := store.LookupProcessedEvent(context.Background(), NamespaceProcessedCloudEvent, "evt-delete", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("LookupProcessedEvent after delete: %v", err)
	}
	if record != nil {
		t.Fatalf("expected processed event to be deleted, got %#v", record)
	}
}

func TestSQLiteStoreClaimProcessedEventPreservesFirstSeenAtOnHashReplacement(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	firstSeen := time.Now().UTC().Add(-2 * time.Hour)
	if err := store.RememberProcessedEvent(context.Background(), ProcessedEventRecord{
		Namespace:   NamespaceProcessedCloudEvent,
		EventKey:    "evt-replace",
		Status:      ProcessedEventStatusProcessed,
		PayloadHash: "hash-a",
		FirstSeenAt: firstSeen,
		LastSeenAt:  firstSeen,
		ProcessedAt: firstSeen,
		ExpiresAt:   firstSeen.Add(24 * time.Hour),
	}, 100); err != nil {
		t.Fatalf("RememberProcessedEvent: %v", err)
	}

	claimed, existing, err := store.ClaimProcessedEvent(context.Background(), ProcessedEventRecord{
		Namespace:   NamespaceProcessedCloudEvent,
		EventKey:    "evt-replace",
		Status:      ProcessedEventStatusProcessing,
		PayloadHash: "hash-b",
		FirstSeenAt: firstSeen.Add(2 * time.Hour),
		LastSeenAt:  firstSeen.Add(2 * time.Hour),
		ProcessedAt: firstSeen.Add(2 * time.Hour),
		ExpiresAt:   time.Now().UTC().Add(2 * time.Hour),
	}, 100)
	if err != nil {
		t.Fatalf("ClaimProcessedEvent: %v", err)
	}
	if !claimed {
		t.Fatalf("claimed = %v, want true", claimed)
	}
	if existing != nil {
		t.Fatalf("existing = %#v, want nil on successful replacement", existing)
	}

	record, err := store.LookupProcessedEvent(context.Background(), NamespaceProcessedCloudEvent, "evt-replace", time.Now().UTC())
	if err != nil {
		t.Fatalf("LookupProcessedEvent: %v", err)
	}
	if record == nil {
		t.Fatal("expected processed event record")
	}
	if !record.FirstSeenAt.Equal(firstSeen) {
		t.Fatalf("first_seen_at = %s, want %s", record.FirstSeenAt, firstSeen)
	}
	if record.PayloadHash != "hash-b" {
		t.Fatalf("payload_hash = %q, want hash-b", record.PayloadHash)
	}
}

func TestSQLiteStoreClaimProcessedEventDoesNotReplaceActiveMismatchedClaim(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Now().UTC()
	claimed, existing, err := store.ClaimProcessedEvent(context.Background(), ProcessedEventRecord{
		Namespace:   NamespaceProcessedCloudEvent,
		EventKey:    "evt-processing",
		Status:      ProcessedEventStatusProcessing,
		PayloadHash: "hash-a",
		FirstSeenAt: now,
		LastSeenAt:  now,
		ProcessedAt: now,
		ExpiresAt:   now.Add(5 * time.Minute),
	}, 100)
	if err != nil {
		t.Fatalf("ClaimProcessedEvent first: %v", err)
	}
	if !claimed || existing != nil {
		t.Fatalf("first claim = (%v, %#v), want (true, nil)", claimed, existing)
	}

	claimed, existing, err = store.ClaimProcessedEvent(context.Background(), ProcessedEventRecord{
		Namespace:   NamespaceProcessedCloudEvent,
		EventKey:    "evt-processing",
		Status:      ProcessedEventStatusProcessing,
		PayloadHash: "hash-b",
		FirstSeenAt: now.Add(time.Minute),
		LastSeenAt:  now.Add(time.Minute),
		ProcessedAt: now.Add(time.Minute),
		ExpiresAt:   now.Add(6 * time.Minute),
	}, 100)
	if err != nil {
		t.Fatalf("ClaimProcessedEvent second: %v", err)
	}
	if claimed {
		t.Fatal("expected active mismatched claim to stay unclaimed")
	}
	if existing == nil {
		t.Fatal("expected existing active claim")
	}
	if existing.PayloadHash != "hash-a" {
		t.Fatalf("existing payload_hash = %q, want hash-a", existing.PayloadHash)
	}
	if existing.Status != ProcessedEventStatusProcessing {
		t.Fatalf("existing status = %q, want processing", existing.Status)
	}

	record, err := store.LookupProcessedEvent(context.Background(), NamespaceProcessedCloudEvent, "evt-processing", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("LookupProcessedEvent: %v", err)
	}
	if record == nil {
		t.Fatal("expected processed event record")
	}
	if record.PayloadHash != "hash-a" {
		t.Fatalf("payload_hash = %q, want hash-a", record.PayloadHash)
	}
}
