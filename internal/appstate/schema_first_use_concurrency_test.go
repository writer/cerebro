package appstate

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	_ "modernc.org/sqlite"
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
