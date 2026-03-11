package findings

import (
	"bytes"
	"encoding/csv"
	"testing"
)

func TestCSVExporter_SanitizesFormulaCells(t *testing.T) {
	exporter := NewCSVExporter()

	payload, err := exporter.Export([]*Finding{{
		Title:        "=SUM(1,1)",
		Severity:     "high",
		Status:       "OPEN",
		Description:  "-danger",
		ResourceType: "@resource",
		ResourceID:   "+id-1",
	}})
	if err != nil {
		t.Fatalf("export csv: %v", err)
	}

	rows, err := csv.NewReader(bytes.NewReader(payload)).ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}

	row := rows[1]
	if got := row[1]; got != "'=SUM(1,1)" {
		t.Fatalf("title cell = %q, want %q", got, "'=SUM(1,1)")
	}
	if got := row[4]; got != "'-danger" {
		t.Fatalf("description cell = %q, want %q", got, "'-danger")
	}
	if got := row[5]; got != "'@resource" {
		t.Fatalf("resource type cell = %q, want %q", got, "'@resource")
	}
	if got := row[6]; got != "'+id-1" {
		t.Fatalf("resource id cell = %q, want %q", got, "'+id-1")
	}
	if got := row[2]; got != "high" {
		t.Fatalf("severity cell = %q, want high", got)
	}
}
