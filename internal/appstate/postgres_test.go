package appstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/writer/cerebro/internal/snowflake"
)

var appStateDollarPlaceholderRe = regexp.MustCompile(`\$\d+`)

func appStateSQLiteRewrite(query string) string {
	return appStateDollarPlaceholderRe.ReplaceAllString(query, "?")
}

func newConcurrentAppStateTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "appstate.sqlite")
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

func newTestAuditRepository(t *testing.T) *AuditRepository {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	repo := NewAuditRepository(db)
	repo.rewriteSQL = appStateSQLiteRewrite
	if err := repo.EnsureSchema(context.Background()); err != nil {
		_ = db.Close()
		t.Fatalf("EnsureSchema() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return repo
}

func TestAuditRepositoryLogAndList(t *testing.T) {
	repo := newTestAuditRepository(t)
	entry := &snowflake.AuditEntry{
		ID:           "audit-1",
		Timestamp:    time.Now().UTC().Truncate(time.Second),
		Action:       "policy.evaluate",
		ActorID:      "user-1",
		ActorType:    "user",
		ResourceType: "policy",
		ResourceID:   "policy-1",
		Details:      map[string]interface{}{"decision": "allow"},
		IPAddress:    "127.0.0.1",
		UserAgent:    "test",
	}
	if err := repo.Log(context.Background(), entry); err != nil {
		t.Fatalf("Log() error = %v", err)
	}

	entries, err := repo.List(context.Background(), "policy", "policy-1", 10)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if entries[0].Action != entry.Action {
		t.Fatalf("Action = %q, want %q", entries[0].Action, entry.Action)
	}
	if got := entries[0].Details["decision"]; got != "allow" {
		t.Fatalf("decision detail = %#v, want allow", got)
	}
}

func TestPolicyHistoryRepositoryUpsertAndList(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	repo := NewPolicyHistoryRepository(db)
	repo.rewriteSQL = appStateSQLiteRewrite
	if err := repo.EnsureSchema(context.Background()); err != nil {
		_ = db.Close()
		t.Fatalf("EnsureSchema() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	content, err := json.Marshal(map[string]any{"id": "policy-1"})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	record := &snowflake.PolicyHistoryRecord{
		PolicyID:      "policy-1",
		Version:       2,
		Content:       content,
		ChangeType:    "updated",
		EffectiveFrom: time.Now().UTC(),
	}
	if err := repo.Upsert(context.Background(), record); err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}

	records, err := repo.List(context.Background(), "policy-1", 10)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	if records[0].Version != 2 {
		t.Fatalf("Version = %d, want 2", records[0].Version)
	}
}

func TestRiskEngineStateRepositorySaveAndLoad(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	repo := NewRiskEngineStateRepository(db)
	repo.rewriteSQL = appStateSQLiteRewrite
	if err := repo.EnsureSchema(context.Background()); err != nil {
		_ = db.Close()
		t.Fatalf("EnsureSchema() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	payload := []byte(`{"score":42}`)
	if err := repo.SaveSnapshot(context.Background(), "security-graph", payload); err != nil {
		t.Fatalf("SaveSnapshot() error = %v", err)
	}
	got, err := repo.LoadSnapshot(context.Background(), "security-graph")
	if err != nil {
		t.Fatalf("LoadSnapshot() error = %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload = %s, want %s", got, payload)
	}
}

func TestAuditRepositoryConcurrentFirstUseEnsuresSchema(t *testing.T) {
	db := newConcurrentAppStateTestDB(t)
	repo := NewAuditRepository(db)
	repo.rewriteSQL = appStateSQLiteRewrite

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = repo.Log(context.Background(), &snowflake.AuditEntry{
				ID:           fmt.Sprintf("audit-%d", i),
				Action:       "policy.evaluate",
				ActorID:      "user",
				ResourceType: "policy",
				ResourceID:   "policy-1",
			})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: Log() error = %v", i, err)
		}
	}

	entries, err := repo.List(context.Background(), "policy", "policy-1", n+10)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(entries) != n {
		t.Fatalf("len(entries) = %d, want %d", len(entries), n)
	}
}

func TestPolicyHistoryRepositoryConcurrentFirstUseEnsuresSchema(t *testing.T) {
	db := newConcurrentAppStateTestDB(t)
	repo := NewPolicyHistoryRepository(db)
	repo.rewriteSQL = appStateSQLiteRewrite

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = repo.Upsert(context.Background(), &snowflake.PolicyHistoryRecord{
				PolicyID:      "policy-concurrent",
				Version:       i + 1,
				Content:       []byte(`{"version":1}`),
				EffectiveFrom: time.Now().UTC(),
			})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: Upsert() error = %v", i, err)
		}
	}

	records, err := repo.List(context.Background(), "policy-concurrent", n+10)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(records) != n {
		t.Fatalf("len(records) = %d, want %d", len(records), n)
	}
}

func TestRiskEngineStateRepositoryConcurrentFirstUseEnsuresSchema(t *testing.T) {
	db := newConcurrentAppStateTestDB(t)
	repo := NewRiskEngineStateRepository(db)
	repo.rewriteSQL = appStateSQLiteRewrite

	const graphID = "graph-concurrent"
	const n = 20
	var wg sync.WaitGroup
	saveErrs := make([]error, n)
	loadErrs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			saveErrs[i] = repo.SaveSnapshot(context.Background(), graphID, []byte(`{"i":1}`))
		}(i)
		go func(i int) {
			defer wg.Done()
			_, loadErrs[i] = repo.LoadSnapshot(context.Background(), graphID)
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if saveErrs[i] != nil {
			t.Fatalf("save goroutine %d: SaveSnapshot() error = %v", i, saveErrs[i])
		}
		if loadErrs[i] != nil {
			t.Fatalf("load goroutine %d: LoadSnapshot() error = %v", i, loadErrs[i])
		}
	}

	got, err := repo.LoadSnapshot(context.Background(), graphID)
	if err != nil {
		t.Fatalf("final LoadSnapshot() error = %v", err)
	}
	if len(got) == 0 {
		t.Fatal("expected snapshot payload after concurrent first use")
	}
}
