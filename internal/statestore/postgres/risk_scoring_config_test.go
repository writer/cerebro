package postgres

import (
	"database/sql"
	"testing"
	"time"
)

func TestScanRiskScoringConfig(t *testing.T) {
	created := time.Date(2026, 6, 22, 8, 0, 0, 0, time.UTC)
	updated := time.Date(2026, 6, 22, 9, 0, 0, 0, time.UTC)
	payload := `{
		"tenant_id":"ignored",
		"thresholds":{"critical":90,"high":75,"medium":45},
		"signals":{"epss_high":0.8,"epss_elevated":0.3,"cvss_critical":9.2,"cvss_high":7.2,"private_network_likelihood_cap":25},
		"relation_weights":{"default":2,"can_admin":12},
		"factor_weights":{"external_exposure":{"likelihood":20}}
	}`

	config, err := scanRiskScoringConfig(&fakeScanner{values: []any{
		"writer",
		payload,
		sql.NullTime{Time: created, Valid: true},
		sql.NullTime{Time: updated, Valid: true},
	}})
	if err != nil {
		t.Fatalf("scanRiskScoringConfig() error = %v", err)
	}
	if config.TenantID != "writer" {
		t.Fatalf("TenantID = %q, want writer", config.TenantID)
	}
	if config.Thresholds.Critical != 90 || config.RelationWeights["can_admin"] != 12 || config.FactorWeights["external_exposure"].Likelihood != 20 {
		t.Fatalf("decoded config = %#v", config)
	}
	if !config.CreatedAt.Equal(created) || !config.UpdatedAt.Equal(updated) {
		t.Fatalf("timestamps = %s/%s", config.CreatedAt, config.UpdatedAt)
	}
}

func TestScanRiskScoringConfigRejectsInvalidJSON(t *testing.T) {
	_, err := scanRiskScoringConfig(&fakeScanner{values: []any{
		"writer",
		`{"thresholds":`,
		sql.NullTime{},
		sql.NullTime{},
	}})
	if err == nil {
		t.Fatal("scanRiskScoringConfig() error = nil, want decode error")
	}
}
