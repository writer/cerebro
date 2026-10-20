package postgres

import (
	"database/sql"
	"reflect"
	"testing"
	"time"
)

func TestScanComplianceFrameworkSettings(t *testing.T) {
	updated := time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)
	settings, err := scanComplianceFrameworkSettings(&fakeScanner{values: []any{
		"writer",
		`["SOC 2","ISO 27001:2022"]`,
		sql.NullTime{Time: updated, Valid: true},
		sql.NullTime{Time: updated, Valid: true},
	}})
	if err != nil {
		t.Fatalf("scanComplianceFrameworkSettings() error = %v", err)
	}
	if settings.TenantID != "writer" || !reflect.DeepEqual(settings.EnabledFrameworks, []string{"SOC 2", "ISO 27001:2022"}) {
		t.Fatalf("settings = %#v", settings)
	}
	if !settings.UpdatedAt.Equal(updated) {
		t.Fatalf("UpdatedAt = %s, want %s", settings.UpdatedAt, updated)
	}
}

func TestScanComplianceFrameworkSettingsKeepsEmptySelection(t *testing.T) {
	settings, err := scanComplianceFrameworkSettings(&fakeScanner{values: []any{"writer", `null`, sql.NullTime{}, sql.NullTime{}}})
	if err != nil {
		t.Fatalf("scanComplianceFrameworkSettings() error = %v", err)
	}
	if settings.EnabledFrameworks == nil || len(settings.EnabledFrameworks) != 0 {
		t.Fatalf("EnabledFrameworks = %#v, want empty non-nil selection", settings.EnabledFrameworks)
	}
}

func TestScanComplianceFrameworkSettingsRejectsInvalidJSON(t *testing.T) {
	if _, err := scanComplianceFrameworkSettings(&fakeScanner{values: []any{"writer", `["SOC 2"`, sql.NullTime{}, sql.NullTime{}}}); err == nil {
		t.Fatal("scanComplianceFrameworkSettings() error = nil, want decode error")
	}
}
