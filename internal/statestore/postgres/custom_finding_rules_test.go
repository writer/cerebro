package postgres

import (
	"database/sql"
	"testing"
	"time"
)

func TestScanCustomFindingRule(t *testing.T) {
	created := time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)
	updated := created.Add(time.Hour)
	rule, err := scanCustomFindingRule(&fakeScanner{values: []any{
		"writer",
		"custom-s3-public",
		"apiVersion: cerebro.writer.com/v1alpha1\n",
		"alice@example.com",
		"bob@example.com",
		sql.NullTime{Time: created, Valid: true},
		sql.NullTime{Time: updated, Valid: true},
	}})
	if err != nil {
		t.Fatalf("scanCustomFindingRule() error = %v", err)
	}
	if rule.TenantID != "writer" || rule.ID != "custom-s3-public" || rule.CreatedBy != "alice@example.com" || rule.UpdatedBy != "bob@example.com" {
		t.Fatalf("rule = %#v", rule)
	}
	if !rule.CreatedAt.Equal(created) || !rule.UpdatedAt.Equal(updated) {
		t.Fatalf("timestamps = %s %s", rule.CreatedAt, rule.UpdatedAt)
	}
}

func TestCustomFindingRuleStoreRequiresIdentifiers(t *testing.T) {
	store := &Store{}
	if _, err := store.ListCustomFindingRules(t.Context(), "writer"); err == nil {
		t.Fatal("ListCustomFindingRules() error = nil, want unconfigured store error")
	}
}
