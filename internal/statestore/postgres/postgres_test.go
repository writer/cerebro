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
