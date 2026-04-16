package agents

import (
	"context"
	"database/sql"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

var sessionStoreDollarPlaceholderRe = regexp.MustCompile(`\$\d+`)

func sessionStoreSQLiteRewrite(query string) string {
	return sessionStoreDollarPlaceholderRe.ReplaceAllString(query, "?")
}

func newConcurrentSessionStoreTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "sessions.sqlite")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(16)
	ctx := context.Background()
	conns := make([]*sql.Conn, 0, 16)
	for i := 0; i < 16; i++ {
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatalf("open sqlite connection: %v", err)
		}
		if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout = 10000"); err != nil {
			_ = conn.Close()
			t.Fatalf("set busy_timeout: %v", err)
		}
		if _, err := conn.ExecContext(ctx, "PRAGMA journal_mode = WAL"); err != nil {
			_ = conn.Close()
			t.Fatalf("set journal_mode: %v", err)
		}
		conns = append(conns, conn)
	}
	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			t.Fatalf("close sqlite connection: %v", err)
		}
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newTestPostgresSessionStoreWithDB(t *testing.T) (*PostgresSessionStore, *sql.DB) {
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
	return store, db
}

func newTestPostgresSessionStore(t *testing.T) *PostgresSessionStore {
	t.Helper()
	store, _ := newTestPostgresSessionStoreWithDB(t)
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
		return
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
	if got == nil {
		t.Fatal("expected persisted session")
		return
	}
	if got.Status != "completed" {
		t.Fatalf("Status = %q, want completed", got.Status)
	}
	if len(got.Messages) != 1 || got.Messages[0].Content != "done" {
		t.Fatalf("unexpected updated messages: %#v", got.Messages)
	}
}

func TestPostgresSessionStoreImportMissingDoesNotOverwriteExistingUpdates(t *testing.T) {
	store, db := newTestPostgresSessionStoreWithDB(t)
	session := &Session{
		ID:        "session-3",
		AgentID:   "agent-1",
		UserID:    "user-1",
		Status:    "active",
		Messages:  []Message{{Role: "user", Content: "investigate bucket"}},
		CreatedAt: time.Now().UTC().Add(-time.Hour).Truncate(time.Second),
		UpdatedAt: time.Now().UTC().Add(-30 * time.Minute).Truncate(time.Second),
	}

	if err := store.ImportMissing(context.Background(), []*Session{session}); err != nil {
		t.Fatalf("initial ImportMissing() error = %v", err)
	}

	updated := *session
	updated.Status = "completed"
	updated.Messages = []Message{{Role: "assistant", Content: "done"}}
	updated.UpdatedAt = session.UpdatedAt.Add(2 * time.Minute)
	if err := store.Save(context.Background(), &updated); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	reloaded := &PostgresSessionStore{
		db:         db,
		rewriteSQL: sessionStoreSQLiteRewrite,
	}
	if err := reloaded.ImportMissing(context.Background(), []*Session{session}); err != nil {
		t.Fatalf("repeat ImportMissing() error = %v", err)
	}

	got, err := reloaded.Get(context.Background(), session.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got == nil {
		t.Fatal("expected persisted session")
		return
	}
	if got.Status != "completed" {
		t.Fatalf("Status = %q, want completed after repeat import", got.Status)
	}
	if len(got.Messages) != 1 || got.Messages[0].Content != "done" {
		t.Fatalf("unexpected updated messages after repeat import: %#v", got.Messages)
	}
}

func TestPostgresSessionStoreConcurrentFirstUseEnsuresSchema(t *testing.T) {
	db := newConcurrentSessionStoreTestDB(t)
	store := &PostgresSessionStore{
		db:         db,
		rewriteSQL: sessionStoreSQLiteRewrite,
	}

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = store.Save(context.Background(), &Session{
				ID:        "session-concurrent-" + string(rune('a'+i)),
				AgentID:   "agent-1",
				UserID:    "user-1",
				Status:    "active",
				CreatedAt: time.Now().UTC(),
				UpdatedAt: time.Now().UTC(),
			})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: Save() error = %v", i, err)
		}
	}

	var count int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM `+postgresSessionTable).Scan(&count); err != nil {
		t.Fatalf("count query error = %v", err)
	}
	if count != n {
		t.Fatalf("count = %d, want %d", count, n)
	}
}
