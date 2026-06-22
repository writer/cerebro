package postgres

import (
	"testing"
	"time"
)

func TestScanAskQuery(t *testing.T) {
	created := time.Date(2026, 6, 22, 8, 0, 0, 0, time.UTC)
	updated := time.Date(2026, 6, 22, 9, 0, 0, 0, time.UTC)
	scanner := &fakeScanner{values: []any{
		"ask-query-1", "local", "Stale admins", "Which admins are stale?",
		"urn:cerebro:local:identity:admin", "claude-sonnet-4-6", true,
		created, updated,
	}}
	query, err := scanAskQuery(scanner)
	if err != nil {
		t.Fatalf("scanAskQuery() error = %v", err)
	}
	if query.ID != "ask-query-1" || query.TenantID != "local" {
		t.Fatalf("unexpected identity fields: %+v", query)
	}
	if query.Name != "Stale admins" || query.Question != "Which admins are stale?" {
		t.Fatalf("unexpected content fields: %+v", query)
	}
	if query.ScopeURN != "urn:cerebro:local:identity:admin" || query.Model != "claude-sonnet-4-6" {
		t.Fatalf("unexpected scope/model: %+v", query)
	}
	if !query.Pinned {
		t.Fatal("query should be pinned")
	}
	if !query.CreatedAt.Equal(created) || !query.UpdatedAt.Equal(updated) {
		t.Fatalf("unexpected timestamps: created=%v updated=%v", query.CreatedAt, query.UpdatedAt)
	}
}

func TestAskQueryListLimit(t *testing.T) {
	cases := []struct {
		in   uint32
		want uint32
	}{
		{in: 0, want: 100},
		{in: 50, want: 50},
		{in: 1000, want: 500},
	}
	for _, tc := range cases {
		if got := askQueryListLimit(tc.in); got != tc.want {
			t.Fatalf("askQueryListLimit(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
