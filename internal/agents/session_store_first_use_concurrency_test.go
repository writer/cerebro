package agents

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newConcurrentSessionSQLiteDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "sessions.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(8)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestTDDSessionStore_ConcurrentFirstGetOnFreshDB(t *testing.T) {
	store := NewPostgresSessionStore(newConcurrentSessionSQLiteDB(t))
	store.rewriteSQL = sessionStoreSQLiteRewrite

	const n = 20
	start := make(chan struct{})
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = store.Get(context.Background(), fmt.Sprintf("session-first-use-%d", i))
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: Get() error = %v", i, err)
		}
	}
}

func TestTDDSessionStore_SaveHonorsContextWhileWaitingForSchema(t *testing.T) {
	store := NewPostgresSessionStore(newConcurrentSessionSQLiteDB(t))
	store.rewriteSQL = sessionStoreSQLiteRewrite
	state := &schemaInitState{done: make(chan struct{})}
	store.schemaInit = state

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := store.Save(ctx, &Session{
		ID:      "session-1",
		AgentID: "agent",
		UserID:  "user",
		Status:  "active",
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
	if waited := time.Since(start); waited > 200*time.Millisecond {
		t.Fatalf("waited too long for context cancellation: %s", waited)
	}
	close(state.done)
}
