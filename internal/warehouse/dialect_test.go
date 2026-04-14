package warehouse

import (
	"strings"
	"testing"
)

func TestRewriteQueryForDialect_Postgres(t *testing.T) {
	query := `INSERT INTO demo (payload, created_at) VALUES (PARSE_JSON(?), CURRENT_TIMESTAMP())`
	got := RewriteQueryForDialect(query, DialectPostgres)

	if !strings.Contains(got, "CAST($1 AS JSONB)") {
		t.Fatalf("expected JSON cast rewrite, got %q", got)
	}
	if strings.Contains(got, "CURRENT_TIMESTAMP()") {
		t.Fatalf("expected CURRENT_TIMESTAMP() rewrite, got %q", got)
	}
}

func TestRewriteQueryForDialect_SQLite(t *testing.T) {
	query := `CREATE TABLE demo (payload VARIANT, created_at TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP())`
	got := RewriteQueryForDialect(query, DialectSQLite)

	if !strings.Contains(got, "payload JSON") {
		t.Fatalf("expected VARIANT rewrite, got %q", got)
	}
	if !strings.Contains(got, "created_at TEXT DEFAULT CURRENT_TIMESTAMP") {
		t.Fatalf("expected timestamp rewrite, got %q", got)
	}
}

func TestRewriteQueryForDialect_SQLiteInterval(t *testing.T) {
	query := `SELECT id FROM assets WHERE seen_at < NOW() - INTERVAL '7 days'`
	got := RewriteQueryForDialect(query, DialectSQLite)

	if !strings.Contains(got, "DATETIME(CURRENT_TIMESTAMP, '-7 days')") {
		t.Fatalf("expected sqlite interval rewrite, got %q", got)
	}
}
