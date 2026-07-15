package postgres

import (
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/config"
)

func TestPostgresAdvisoryLockKeyIsTextSafeAndBoundaryStable(t *testing.T) {
	t.Parallel()
	first := postgresAdvisoryLockKey("tenant-a", "event-a")
	if first == "" || strings.ContainsRune(first, '\x00') {
		t.Fatalf("postgresAdvisoryLockKey() = %q, want non-empty text without NUL bytes", first)
	}
	if got := postgresAdvisoryLockKey("tenant-a", "event-a"); got != first {
		t.Fatalf("postgresAdvisoryLockKey() = %q, want stable key %q", got, first)
	}
	if got := postgresAdvisoryLockKey("tenant", "-aevent-a"); got == first {
		t.Fatal("postgresAdvisoryLockKey() collapsed distinct part boundaries")
	}
}

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

func TestSchemaMigrationRecordUsesStableLabelVersion(t *testing.T) {
	version, first := schemaMigrationRecord("projection", []string{"CREATE TABLE example (id text)"})
	againVersion, second := schemaMigrationRecord("projection", []string{"CREATE TABLE example (id text, name text)"})
	if version != "ensure:projection" || againVersion != version {
		t.Fatalf("schemaMigrationRecord versions = %q, %q", version, againVersion)
	}
	if first == second {
		t.Fatal("schemaMigrationRecord checksum did not change after additive DDL changed")
	}
}
