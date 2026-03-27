package agents

import (
	"context"
	"database/sql"
	"regexp"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

var sessionStoreDollarPlaceholderRe = regexp.MustCompile(`\$\d+`)

func sessionStoreSQLiteRewrite(query string) string {
	return sessionStoreDollarPlaceholderRe.ReplaceAllString(query, "?")
}

func newTestPostgresSessionStore(t *testing.T) *PostgresSessionStore {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	store := &PostgresSessionStore{
		db:         db,
		rewriteSQL: sessionStoreSQLiteRewrite,
	}
	if err := store.EnsureSchema(context.Background()); err != nil {
		_ = db.Close()
		t.Fatalf("EnsureSchema() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return store
}

func TestPostgresSessionStoreSaveAndGet(t *testing.T) {
	store := newTestPostgresSessionStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	session := &Session{
		ID:      "session-1",
		AgentID: "agent-1",
		UserID:  "user-1",
		Status:  "active",
		Messages: []Message{
			{Role: "user", Content: "investigate bucket"},
		},
		Context: SessionContext{
			FindingIDs: []string{"finding-1"},
			Metadata:   map[string]interface{}{"tenant": "tenant-a"},
		},
		CreatedAt: now,
		UpdatedAt: now.Add(time.Minute),
	}

	if err := store.Save(context.Background(), session); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	got, err := store.Get(context.Background(), session.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got == nil {
		t.Fatal("expected persisted session")
	}
	if got.UserID != session.UserID {
		t.Fatalf("UserID = %q, want %q", got.UserID, session.UserID)
	}
	if len(got.Messages) != 1 || got.Messages[0].Content != "investigate bucket" {
		t.Fatalf("unexpected messages: %#v", got.Messages)
	}
	if len(got.Context.FindingIDs) != 1 || got.Context.FindingIDs[0] != "finding-1" {
		t.Fatalf("unexpected context finding ids: %#v", got.Context.FindingIDs)
	}
}

func TestPostgresSessionStoreSaveUpdatesExistingRow(t *testing.T) {
	store := newTestPostgresSessionStore(t)
	session := &Session{
		ID:        "session-2",
		AgentID:   "agent-1",
		UserID:    "user-1",
		Status:    "active",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.Save(context.Background(), session); err != nil {
		t.Fatalf("initial Save() error = %v", err)
	}

	session.Status = "completed"
	session.Messages = []Message{{Role: "assistant", Content: "done"}}
	session.UpdatedAt = session.UpdatedAt.Add(2 * time.Minute)
	if err := store.Save(context.Background(), session); err != nil {
		t.Fatalf("update Save() error = %v", err)
	}

	got, err := store.Get(context.Background(), session.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Status != "completed" {
		t.Fatalf("Status = %q, want completed", got.Status)
	}
	if len(got.Messages) != 1 || got.Messages[0].Content != "done" {
		t.Fatalf("unexpected updated messages: %#v", got.Messages)
	}
}
