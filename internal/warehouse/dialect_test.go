package warehouse

import (
	"errors"
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

func TestRewriteQueryForDialect_PostgresHandlesNestedParseJSON(t *testing.T) {
	query := `SELECT PARSE_JSON(PARSE_JSON(col)) FROM demo`
	got := RewriteQueryForDialect(query, DialectPostgres)
	want := `SELECT CAST(CAST(col AS JSONB) AS JSONB) FROM demo`

	if got != want {
		t.Fatalf("expected nested PARSE_JSON rewrite %q, got %q", want, got)
	}
}

func TestRewriteQueryForDialect_PostgresPreservesQuotedIdentifiers(t *testing.T) {
	query := `SELECT "VARIANT", "NUMBER" FROM demo`
	got := RewriteQueryForDialect(query, DialectPostgres)

	if got != query {
		t.Fatalf("expected quoted identifiers to remain unchanged, got %q", got)
	}
}

func TestRewriteQueryForDialect_PostgresContinuesDollarPlaceholderSequence(t *testing.T) {
	query := `SELECT * FROM demo WHERE tenant_id = $1 AND payload = ? AND severity = ?`
	got := RewriteQueryForDialect(query, DialectPostgres)
	want := `SELECT * FROM demo WHERE tenant_id = $1 AND payload = $2 AND severity = $3`

	if got != want {
		t.Fatalf("expected placeholder rewrite %q, got %q", want, got)
	}
}

func TestValidateQueryForDialect_RejectsUnsupportedSnowflakeConstructs(t *testing.T) {
	tests := []struct {
		name          string
		query         string
		wantConstruct string
	}{
		{
			name:          "qualify",
			query:         `SELECT * FROM demo QUALIFY ROW_NUMBER() OVER (PARTITION BY tenant_id ORDER BY created_at DESC) = 1`,
			wantConstruct: "QUALIFY",
		},
		{
			name:          "flatten",
			query:         `SELECT value FROM LATERAL FLATTEN(input => payload)`,
			wantConstruct: "FLATTEN",
		},
		{
			name:          "json operator",
			query:         `SELECT payload:key::STRING FROM demo`,
			wantConstruct: "Snowflake JSON : operator",
		},
		{
			name:          "create or replace table",
			query:         `CREATE OR REPLACE TABLE demo (id NUMBER)`,
			wantConstruct: "CREATE OR REPLACE TABLE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateQueryForDialect(tt.query, DialectPostgres)
			if !errors.Is(err, ErrUnsupportedSnowflakeDialectRewrite) {
				t.Fatalf("expected unsupported rewrite error, got %v", err)
			}
			if !strings.Contains(err.Error(), tt.wantConstruct) {
				t.Fatalf("expected error to mention %q, got %v", tt.wantConstruct, err)
			}
		})
	}
}

func TestValidateQueryForDialect_IgnoresQuotedUnsupportedConstructs(t *testing.T) {
	query := `SELECT 'QUALIFY payload:key::STRING' AS demo`
	if err := validateQueryForDialect(query, DialectPostgres); err != nil {
		t.Fatalf("expected quoted text to be ignored, got %v", err)
	}
}
