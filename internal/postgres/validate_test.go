package postgres

import (
	"testing"
)

func TestValidateTableName(t *testing.T) {
	tests := []struct {
		name    string
		table   string
		wantErr bool
	}{
		{"valid simple", "findings", false},
		{"valid with underscore", "aws_s3_buckets", false},
		{"valid uppercase", "FINDINGS", false},
		{"empty", "", true},
		{"sql injection semicolon", "table;DROP", true},
		{"sql injection union", "table union select", true},
		{"sql injection comment", "table--comment", true},
		{"special chars", "table@name", true},
		{"starts with number", "1table", true},
		{"too long", string(make([]byte, 64)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTableName(tt.table)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTableName(%q) error = %v, wantErr %v", tt.table, err, tt.wantErr)
			}
		})
	}
}

func TestValidateTableNameStrict(t *testing.T) {
	tests := []struct {
		name    string
		table   string
		wantErr bool
	}{
		{"known prefix aws", "aws_s3_buckets", false},
		{"known prefix gcp", "gcp_compute_instances", false},
		{"known exact name", "endpoints", false},
		{"unknown prefix", "custom_table", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTableNameStrict(tt.table)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTableNameStrict(%q) error = %v, wantErr %v", tt.table, err, tt.wantErr)
			}
		})
	}
}

func TestSafeTableRef(t *testing.T) {
	tests := []struct {
		name    string
		schema  string
		table   string
		want    string
		wantErr bool
	}{
		{"valid", "public", "findings", "public.findings", false},
		{"uppercase normalized", "PUBLIC", "FINDINGS", "public.findings", false},
		{"empty schema", "", "findings", "", true},
		{"empty table", "public", "", "", true},
		{"injection in schema", "public;drop", "findings", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SafeTableRef(tt.schema, tt.table)
			if (err != nil) != tt.wantErr {
				t.Errorf("SafeTableRef(%q, %q) error = %v, wantErr %v", tt.schema, tt.table, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SafeTableRef(%q, %q) = %q, want %q", tt.schema, tt.table, got, tt.want)
			}
		})
	}
}

func TestSafeQualifiedTableRef(t *testing.T) {
	tests := []struct {
		name    string
		schema  string
		table   string
		want    string
		wantErr bool
	}{
		{"valid", "cerebro", "findings", "cerebro.findings", false},
		{"uppercase to lower", "CEREBRO", "FINDINGS", "cerebro.findings", false},
		{"empty schema", "", "findings", "", true},
		{"empty table", "cerebro", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SafeQualifiedTableRef(tt.schema, tt.table)
			if (err != nil) != tt.wantErr {
				t.Errorf("SafeQualifiedTableRef(%q, %q) error = %v, wantErr %v", tt.schema, tt.table, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SafeQualifiedTableRef(%q, %q) = %q, want %q", tt.schema, tt.table, got, tt.want)
			}
		})
	}
}

func TestQuoteIdentifier(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple", "findings", `"findings"`},
		{"with quotes", `my"table`, `"my""table"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := QuoteIdentifier(tt.input)
			if got != tt.want {
				t.Errorf("QuoteIdentifier(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
