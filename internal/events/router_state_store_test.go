package events

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteAlertRouterStateStoreKeepsNewestRevision(t *testing.T) {
	store, err := NewSQLiteAlertRouterStateStore(filepath.Join(t.TempDir(), "router.db"))
	if err != nil {
		t.Fatalf("new state store: %v", err)
	}
	defer func() { _ = store.Close() }()

	newer := alertRouterStateSnapshot{
		Revision:      2,
		ThrottleUntil: map[string]time.Time{"route-a": time.Date(2026, 3, 8, 12, 5, 0, 0, time.UTC)},
	}
	older := alertRouterStateSnapshot{
		Revision:      1,
		ThrottleUntil: map[string]time.Time{"route-b": time.Date(2026, 3, 8, 12, 1, 0, 0, time.UTC)},
	}

	if err := store.Save(context.Background(), newer); err != nil {
		t.Fatalf("save newer snapshot: %v", err)
	}
	if err := store.Save(context.Background(), older); err != nil {
		t.Fatalf("save older snapshot: %v", err)
	}

	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("load state snapshot: %v", err)
	}
	if loaded.Revision != 2 {
		t.Fatalf("revision = %d, want 2", loaded.Revision)
	}
	if _, ok := loaded.ThrottleUntil["route-a"]; !ok {
		t.Fatalf("expected newer throttle entry to remain, got %#v", loaded.ThrottleUntil)
	}
	if _, ok := loaded.ThrottleUntil["route-b"]; ok {
		t.Fatalf("expected older snapshot not to overwrite newer state, got %#v", loaded.ThrottleUntil)
	}
}
