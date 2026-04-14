package warehouse

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestValidateReadOnlyQuery(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		wantErr error
	}{
		{name: "valid select", query: "SELECT * FROM users", wantErr: nil},
		{name: "valid with cte", query: "WITH recent AS (SELECT * FROM events) SELECT * FROM recent", wantErr: nil},
		{name: "valid trailing semicolon", query: "SELECT * FROM users;", wantErr: nil},
		{name: "empty query", query: "", wantErr: ErrEmptyQuery},
		{name: "non read only query", query: "UPDATE users SET admin=true", wantErr: ErrNonSelectQuery},
		{name: "inline comment rejected", query: "SELECT * FROM users -- test", wantErr: ErrSQLInjection},
		{name: "block comment rejected", query: "SELECT /* test */ * FROM users", wantErr: ErrSQLInjection},
		{name: "statement chaining rejected", query: "SELECT * FROM users; DROP TABLE users;", wantErr: ErrSQLInjection},
		{name: "forbidden keyword rejected", query: "WITH x AS (SELECT * FROM users) DELETE FROM users", wantErr: ErrSQLInjection},
		{name: "keyword in string literal allowed", query: "SELECT * FROM okta_system_logs WHERE event_type = 'policy.rule.delete'", wantErr: nil},
		{name: "keyword in quoted identifier allowed", query: "SELECT \"grant\" FROM permissions", wantErr: nil},
		{name: "keyword in escaped string literal allowed", query: "SELECT * FROM logs WHERE message = 'it''s safe to update'", wantErr: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateReadOnlyQuery(tt.query)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestBuildReadOnlyLimitedQuery(t *testing.T) {
	tests := []struct {
		name          string
		query         string
		limit         int
		wantErr       error
		wantLimit     int
		wantQueryPart string
	}{
		{
			name:          "builds bounded query",
			query:         "SELECT id FROM assets",
			limit:         25,
			wantLimit:     25,
			wantQueryPart: "FROM (SELECT id FROM assets) AS cerebro_readonly_query LIMIT 25",
		},
		{
			name:          "trims trailing semicolon",
			query:         "SELECT * FROM findings;",
			limit:         10,
			wantLimit:     10,
			wantQueryPart: "FROM (SELECT * FROM findings) AS cerebro_readonly_query LIMIT 10",
		},
		{
			name:          "normalizes now function",
			query:         "SELECT id FROM sentinelone_agents WHERE last_active_date < NOW() - INTERVAL '7 days'",
			limit:         50,
			wantLimit:     50,
			wantQueryPart: "CURRENT_TIMESTAMP() - INTERVAL '7 days'",
		},
		{
			name:          "applies default limit",
			query:         "SELECT * FROM findings",
			limit:         0,
			wantLimit:     DefaultReadOnlyQueryLimit,
			wantQueryPart: "LIMIT 100",
		},
		{
			name:          "clamps max limit",
			query:         "SELECT * FROM findings",
			limit:         99999,
			wantLimit:     MaxReadOnlyQueryLimit,
			wantQueryPart: "LIMIT 1000",
		},
		{
			name:          "preserves explicit top level limit within bound",
			query:         "SELECT * FROM findings LIMIT 10",
			limit:         100,
			wantLimit:     100,
			wantQueryPart: "SELECT * FROM findings LIMIT 10",
		},
		{
			name:    "rejects unsafe query",
			query:   "DROP TABLE findings",
			limit:   10,
			wantErr: ErrNonSelectQuery,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotQuery, gotLimit, err := BuildReadOnlyLimitedQuery(tt.query, tt.limit)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if gotLimit != tt.wantLimit {
				t.Fatalf("expected limit %d, got %d", tt.wantLimit, gotLimit)
			}
			if !strings.Contains(gotQuery, tt.wantQueryPart) {
				t.Fatalf("expected query %q to contain %q", gotQuery, tt.wantQueryPart)
			}
			if tt.name == "preserves explicit top level limit within bound" && strings.Contains(gotQuery, "cerebro_readonly_query") {
				t.Fatalf("expected explicit limit query to avoid extra wrapper, got %q", gotQuery)
			}
		})
	}
}

func TestNormalizeReadOnlyDialect(t *testing.T) {
	input := "SELECT NOW(), 'NOW() in string', \"NOW\", now ( ) FROM dual"
	normalized := normalizeReadOnlyDialect(input)

	if strings.Count(normalized, "CURRENT_TIMESTAMP()") != 2 {
		t.Fatalf("expected two NOW() replacements, got %q", normalized)
	}
	if !strings.Contains(normalized, "'NOW() in string'") {
		t.Fatalf("expected single-quoted literal to remain untouched, got %q", normalized)
	}
	if !strings.Contains(normalized, "\"NOW\"") {
		t.Fatalf("expected double-quoted identifier to remain untouched, got %q", normalized)
	}
}

func TestStripQuotedLiterals(t *testing.T) {
	query := "SELECT * FROM logs WHERE event_type = 'policy.rule.delete' AND \"grant\" = 'ok'"
	stripped := stripQuotedLiterals(query)

	if strings.Contains(strings.ToUpper(stripped), "DELETE") {
		t.Fatalf("expected DELETE in string literal to be stripped, got %q", stripped)
	}
	if strings.Contains(strings.ToUpper(stripped), "GRANT\"") {
		t.Fatalf("expected quoted identifier content to be stripped, got %q", stripped)
	}
}

func TestClampReadOnlyQueryTimeout(t *testing.T) {
	tests := []struct {
		name   string
		input  int
		expect time.Duration
	}{
		{name: "default when unset", input: 0, expect: DefaultReadOnlyQueryTimeout},
		{name: "uses provided timeout", input: 5, expect: 5 * time.Second},
		{name: "clamps max timeout", input: 999, expect: MaxReadOnlyQueryTimeout},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClampReadOnlyQueryTimeout(tt.input)
			if got != tt.expect {
				t.Fatalf("ClampReadOnlyQueryTimeout(%d) = %v, want %v", tt.input, got, tt.expect)
			}
		})
	}
}
