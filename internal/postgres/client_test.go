package postgres

import (
	"database/sql"
	"testing"
)

func TestNewPostgresClient(t *testing.T) {
	// Test that NewPostgresClient initializes fields correctly.
	// Uses a nil *sql.DB since we're only testing struct setup.
	client := NewPostgresClient(nil, "raw", "cerebro")
	if client.Schema() != "raw" {
		t.Errorf("Schema() = %q, want %q", client.Schema(), "raw")
	}
	if client.AppSchema() != "cerebro" {
		t.Errorf("AppSchema() = %q, want %q", client.AppSchema(), "cerebro")
	}
	if client.Database() != "" {
		t.Errorf("Database() = %q, want empty string", client.Database())
	}
	if client.DB() != nil {
		t.Errorf("DB() should be nil when initialized with nil")
	}
}

func TestNewPostgresClientDefaultAppSchema(t *testing.T) {
	client := NewPostgresClient(nil, "raw", "")
	if client.AppSchema() != SchemaName {
		t.Errorf("AppSchema() = %q, want default %q", client.AppSchema(), SchemaName)
	}
}

func TestSelectClause(t *testing.T) {
	tests := []struct {
		name    string
		columns []string
		want    string
	}{
		{"nil columns", nil, "*"},
		{"empty columns", []string{}, "*"},
		{"single column", []string{"name"}, "name"},
		{"multiple columns", []string{"id", "name", "status"}, "id, name, status"},
		{"invalid column filtered", []string{"valid_col", "bad;col"}, "valid_col"},
		{"all invalid", []string{"bad;col", "also bad"}, "*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectClause(tt.columns)
			if got != tt.want {
				t.Errorf("selectClause(%v) = %q, want %q", tt.columns, got, tt.want)
			}
		})
	}
}

func TestCloseNilDB(t *testing.T) {
	client := NewPostgresClient(nil, "raw", "cerebro")
	if err := client.Close(); err != nil {
		t.Errorf("Close() on nil db should not error, got %v", err)
	}
}

func TestBuildCDCEventID(t *testing.T) {
	// Verify deterministic ID generation
	id1 := buildCDCEventID("table", "res1", "INSERT", "hash1", fixedTime())
	id2 := buildCDCEventID("table", "res1", "INSERT", "hash1", fixedTime())
	if id1 != id2 {
		t.Errorf("buildCDCEventID should be deterministic, got %q and %q", id1, id2)
	}

	// Different inputs should produce different IDs
	id3 := buildCDCEventID("table", "res2", "INSERT", "hash1", fixedTime())
	if id1 == id3 {
		t.Errorf("different inputs should produce different IDs")
	}
}

func TestNullableString(t *testing.T) {
	if nullableString(nil) != nil {
		t.Errorf("nullableString(nil) should return nil")
	}
	got := nullableString([]byte(`{"key":"val"}`))
	if got != `{"key":"val"}` {
		t.Errorf("nullableString(data) = %v, want JSON string", got)
	}
}

// Compile-time check that PostgresClient has the correct method signatures.
// This verifies it can serve as a warehouse implementation even though we
// can't do a full interface check until warehouse types are decoupled.
var _ interface {
	DB() *sql.DB
	Database() string
	Schema() string
	AppSchema() string
} = (*PostgresClient)(nil)
