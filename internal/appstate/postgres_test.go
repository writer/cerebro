package appstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/writer/cerebro/internal/snowflake"
)

var appStateDollarPlaceholderRe = regexp.MustCompile(`\$\d+`)

func appStateSQLiteRewrite(query string) string {
	return appStateDollarPlaceholderRe.ReplaceAllString(query, "?")
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
