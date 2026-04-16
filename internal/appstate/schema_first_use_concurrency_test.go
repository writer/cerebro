package appstate

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

	"github.com/writer/cerebro/internal/snowflake"
)

func newConcurrentAppStateSQLiteDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "appstate.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(8)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestTDDAuditRepository_ConcurrentFirstListOnFreshDB(t *testing.T) {
	repo := NewAuditRepository(newConcurrentAppStateSQLiteDB(t))
	repo.rewriteSQL = appStateSQLiteRewrite

	const n = 20
	start := make(chan struct{})
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = repo.List(context.Background(), "", "", 10)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: List() error = %v", i, err)
		}
	}
}

func TestTDDRiskEngineStateRepository_ConcurrentFirstUseOnFreshDB(t *testing.T) {
	repo := NewRiskEngineStateRepository(newConcurrentAppStateSQLiteDB(t))
	repo.rewriteSQL = appStateSQLiteRewrite

	const n = 20
	start := make(chan struct{})
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = repo.LoadSnapshot(context.Background(), "security-graph")
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: LoadSnapshot() error = %v", i, err)
		}
	}
}

func TestTDDPolicyHistoryRepository_ConcurrentFirstListOnFreshDB(t *testing.T) {
	repo := NewPolicyHistoryRepository(newConcurrentAppStateSQLiteDB(t))
	repo.rewriteSQL = appStateSQLiteRewrite

	const n = 20
	start := make(chan struct{})
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = repo.List(context.Background(), fmt.Sprintf("policy-%d", i), 10)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: List() error = %v", i, err)
		}
	}
}

func TestTDDAuditRepository_LogHonorsContextWhileWaitingForSchema(t *testing.T) {
	repo := NewAuditRepository(newConcurrentAppStateSQLiteDB(t))
	repo.rewriteSQL = appStateSQLiteRewrite
	state := &schemaInitState{done: make(chan struct{})}
	repo.schemaInit = state

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := repo.Log(ctx, &snowflake.AuditEntry{
		Action:       "concurrent.action",
		ActorID:      "user",
		ResourceType: "race",
		ResourceID:   "r1",
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
	if waited := time.Since(start); waited > 200*time.Millisecond {
		t.Fatalf("waited too long for context cancellation: %s", waited)
	}
	close(state.done)
}

func TestTDDPolicyHistoryRepository_UpsertHonorsContextWhileWaitingForSchema(t *testing.T) {
	repo := NewPolicyHistoryRepository(newConcurrentAppStateSQLiteDB(t))
	repo.rewriteSQL = appStateSQLiteRewrite
	state := &schemaInitState{done: make(chan struct{})}
	repo.schemaInit = state

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := repo.Upsert(ctx, &snowflake.PolicyHistoryRecord{
		PolicyID:      "policy-1",
		Version:       1,
		Content:       []byte(`{"version":1}`),
		EffectiveFrom: time.Now().UTC(),
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
	if waited := time.Since(start); waited > 200*time.Millisecond {
		t.Fatalf("waited too long for context cancellation: %s", waited)
	}
	close(state.done)
}

func TestTDDRiskEngineStateRepository_SaveHonorsContextWhileWaitingForSchema(t *testing.T) {
	repo := NewRiskEngineStateRepository(newConcurrentAppStateSQLiteDB(t))
	repo.rewriteSQL = appStateSQLiteRewrite
	state := &schemaInitState{done: make(chan struct{})}
	repo.schemaInit = state

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := repo.SaveSnapshot(ctx, "security-graph", []byte(`{"score":42}`))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
	if waited := time.Since(start); waited > 200*time.Millisecond {
		t.Fatalf("waited too long for context cancellation: %s", waited)
	}
	close(state.done)
}
