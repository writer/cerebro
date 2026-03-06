package findings

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/policy"
)

func TestIssueManager_Assign_NotFound(t *testing.T) {
	mgr := NewIssueManager(NewStore())
	if err := mgr.Assign("missing", "alice"); !errors.Is(err, ErrIssueNotFound) {
		t.Fatalf("expected ErrIssueNotFound, got %v", err)
	}
}

func TestIssueManager_FileStorePersistsUpdates(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "findings.json")
	store, err := NewFileStore(dbPath)
	if err != nil {
		t.Fatalf("create file store: %v", err)
	}

	store.Upsert(context.Background(), policy.Finding{ID: "f-1", PolicyID: "p-1", Severity: "high"})
	mgr := NewIssueManager(store)
	dueAt := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)

	if err := mgr.Assign("f-1", "alice"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if err := mgr.SetDueDate("f-1", dueAt); err != nil {
		t.Fatalf("set due date: %v", err)
	}
	if err := mgr.AddNote("f-1", "triaged"); err != nil {
		t.Fatalf("add note: %v", err)
	}
	if err := mgr.Sync(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	reloaded, err := NewFileStore(dbPath)
	if err != nil {
		t.Fatalf("re-open file store: %v", err)
	}
	defer reloaded.Close()

	f, ok := reloaded.Get("f-1")
	if !ok {
		t.Fatalf("expected finding to exist after reload")
	}
	if f.AssigneeName != "alice" {
		t.Fatalf("assignee = %q, want %q", f.AssigneeName, "alice")
	}
	if f.DueAt == nil || !f.DueAt.Equal(dueAt) {
		t.Fatalf("due_at = %v, want %v", f.DueAt, dueAt)
	}
	if !strings.Contains(f.Notes, "triaged") {
		t.Fatalf("note = %q, want to contain triaged", f.Notes)
	}
}

func TestIssueManager_SQLiteStorePersistsUpdates(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "findings.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("create sqlite store: %v", err)
	}

	store.Upsert(context.Background(), policy.Finding{
		ID:         "f-1",
		PolicyID:   "p-1",
		PolicyName: "Policy 1",
		Severity:   "critical",
	})

	mgr := NewIssueManager(store)
	if err := mgr.Assign("f-1", "bob"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if err := mgr.Resolve("f-1", "remediated"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := mgr.LinkTicket("f-1", "https://tickets.example.com/SEC-1", "SEC-1", "SEC-1"); err != nil {
		t.Fatalf("link ticket: %v", err)
	}

	f, ok := store.Get("f-1")
	if !ok {
		t.Fatalf("expected finding after update")
	}
	if f.AssigneeName != "bob" {
		t.Fatalf("assignee = %q, want %q", f.AssigneeName, "bob")
	}
	if f.Status != "RESOLVED" {
		t.Fatalf("status = %q, want RESOLVED", f.Status)
	}
	if f.ResolvedAt == nil {
		t.Fatal("expected resolved_at to be set")
	}
	if f.Resolution != "remediated" {
		t.Fatalf("resolution = %q, want %q", f.Resolution, "remediated")
	}
	if len(f.TicketURLs) != 1 || f.TicketURLs[0] != "https://tickets.example.com/SEC-1" {
		t.Fatalf("ticket urls = %#v", f.TicketURLs)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("close sqlite store: %v", err)
	}

	reloaded, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("re-open sqlite store: %v", err)
	}
	defer reloaded.Close()

	persisted, ok := reloaded.Get("f-1")
	if !ok {
		t.Fatalf("expected finding after sqlite reopen")
	}
	if persisted.AssigneeName != "bob" {
		t.Fatalf("persisted assignee = %q, want bob", persisted.AssigneeName)
	}
	if persisted.Status != "RESOLVED" {
		t.Fatalf("persisted status = %q, want RESOLVED", persisted.Status)
	}
	if persisted.ResolvedAt == nil {
		t.Fatal("expected persisted resolved_at")
	}
	if persisted.Resolution != "remediated" {
		t.Fatalf("persisted resolution = %q, want remediated", persisted.Resolution)
	}
}

func TestIssueManager_SnowflakeStoreMarksDirtyOnUpdate(t *testing.T) {
	store := NewSnowflakeStore(nil, "DB", "SCHEMA")
	store.Upsert(context.Background(), policy.Finding{ID: "f-1", PolicyID: "p-1", Severity: "high"})

	store.mu.Lock()
	store.dirty = make(map[string]bool)
	store.mu.Unlock()

	mgr := NewIssueManager(store)
	if err := mgr.Assign("f-1", "carol"); err != nil {
		t.Fatalf("assign: %v", err)
	}

	if got := store.DirtyCount(); got != 1 {
		t.Fatalf("dirty count = %d, want 1", got)
	}

	f, ok := store.Get("f-1")
	if !ok {
		t.Fatalf("expected finding in cache")
	}
	if f.AssigneeName != "carol" {
		t.Fatalf("assignee = %q, want carol", f.AssigneeName)
	}
}

func TestIssueManager_SnoozeEscalateAndAutoResolve(t *testing.T) {
	store := NewStore()
	store.Upsert(context.Background(), policy.Finding{
		ID:       "f-1",
		PolicyID: "p-1",
		Severity: "low",
	})

	mgr := NewIssueManager(store)
	if err := mgr.Snooze("f-1", 30*time.Minute); err != nil {
		t.Fatalf("snooze: %v", err)
	}
	if err := mgr.Escalate("f-1", "compound signals detected"); err != nil {
		t.Fatalf("escalate: %v", err)
	}
	if err := mgr.AutoResolve("f-1", "condition cleared"); err != nil {
		t.Fatalf("auto resolve: %v", err)
	}

	f, ok := store.Get("f-1")
	if !ok {
		t.Fatal("expected finding")
	}
	if f.Status != "RESOLVED" {
		t.Fatalf("status = %q, want RESOLVED", f.Status)
	}
	if f.Severity != "medium" {
		t.Fatalf("severity = %q, want medium", f.Severity)
	}
	if f.EscalationCount != 1 {
		t.Fatalf("escalation_count = %d, want 1", f.EscalationCount)
	}
	if f.ResolvedAt == nil {
		t.Fatal("expected resolved_at to be set")
	}
	if f.SnoozedUntil != nil {
		t.Fatalf("snoozed_until = %v, want nil after auto-resolve", f.SnoozedUntil)
	}
	if !strings.Contains(f.Notes, "Escalated: compound signals detected") {
		t.Fatalf("expected escalation note, got %q", f.Notes)
	}
}
