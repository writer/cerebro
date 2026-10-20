package postgres

import (
	"database/sql"
	"testing"
	"time"
)

func TestScanAssetRiskModel(t *testing.T) {
	created := time.Date(2026, 6, 22, 8, 0, 0, 0, time.UTC)
	updated := time.Date(2026, 6, 22, 9, 0, 0, 0, time.UTC)
	payload := `{
		"tenant_id":"ignored",
		"asset_value":{"default":0.3,"kind_values":{"database":0.9}},
		"countermeasures":[{"key":"mfa","label":"MFA","attributes":["mfa_enabled"],"reduction":0.6}],
		"relations":{"can_admin":{"probability":0.9,"direction":"outgoing"}},
		"thresholds":{"critical":40,"high":20,"medium":8}
	}`
	model, err := scanAssetRiskModel(&fakeScanner{values: []any{
		"writer",
		payload,
		sql.NullTime{Time: created, Valid: true},
		sql.NullTime{Time: updated, Valid: true},
	}})
	if err != nil {
		t.Fatalf("scanAssetRiskModel() error = %v", err)
	}
	if model.TenantID != "writer" {
		t.Fatalf("TenantID = %q, want writer", model.TenantID)
	}
	if model.AssetValue.KindValues["database"] != 0.9 || model.Countermeasures[0].Key != "mfa" || model.Relations["can_admin"].Probability != 0.9 {
		t.Fatalf("decoded model = %#v", model)
	}
	if !model.CreatedAt.Equal(created) || !model.UpdatedAt.Equal(updated) {
		t.Fatalf("timestamps = %s/%s", model.CreatedAt, model.UpdatedAt)
	}
}

func TestScanAssetRiskModelRejectsInvalidJSON(t *testing.T) {
	if _, err := scanAssetRiskModel(&fakeScanner{values: []any{"writer", `{"relations":`, sql.NullTime{}, sql.NullTime{}}}); err == nil {
		t.Fatal("scanAssetRiskModel() error = nil, want decode error")
	}
}
