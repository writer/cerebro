package postgres

import (
	"testing"

	"github.com/writer/cerebro/internal/config"
)

func TestOpenRejectsMissingDSN(t *testing.T) {
	if _, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres}); err == nil {
		t.Fatal("Open() error = nil, want non-nil")
	}
}

func TestCloseNilStore(t *testing.T) {
	var store *Store
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestSchemaStatementsChecksumChangesWithDDL(t *testing.T) {
	first := schemaStatementsChecksum([]string{"CREATE TABLE example (id text)"})
	second := schemaStatementsChecksum([]string{"CREATE TABLE example (id text, name text)"})
	if first == "" {
		t.Fatal("schemaStatementsChecksum() returned empty checksum")
	}
	if first == second {
		t.Fatal("schemaStatementsChecksum() did not change after DDL changed")
	}
	if got := schemaStatementsChecksum([]string{"  CREATE TABLE example (id text)  "}); got != first {
		t.Fatalf("schemaStatementsChecksum() = %q, want stable whitespace-normalized checksum %q", got, first)
	}
}
