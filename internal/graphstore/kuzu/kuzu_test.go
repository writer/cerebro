//go:build cgo

package kuzu

import (
	"context"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/writer/cerebro/internal/config"
)

func TestOpenRejectsMissingPath(t *testing.T) {
	if _, err := Open(config.GraphStoreConfig{Driver: config.GraphStoreDriverKuzu}); err == nil {
		t.Fatal("Open() error = nil, want non-nil")
	}
}

func TestOpenAndPing(t *testing.T) {
	store, err := Open(config.GraphStoreConfig{
		Driver:   config.GraphStoreDriverKuzu,
		KuzuPath: filepath.Join(t.TempDir(), "graph"),
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Fatalf("Close() error = %v", closeErr)
		}
	}()
	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
}

func TestCloseNilStore(t *testing.T) {
	var store *Store
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestKuzuDSNEscapesFilesystemPath(t *testing.T) {
	absPath, err := filepath.Abs(filepath.Join(t.TempDir(), "graph?#%bad"))
	if err != nil {
		t.Fatalf("filepath.Abs() error = %v", err)
	}
	parsed, err := url.Parse(kuzuDSN(absPath))
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	if parsed.Path != filepath.ToSlash(absPath) {
		t.Fatalf("parsed.Path = %q, want %q", parsed.Path, filepath.ToSlash(absPath))
	}
	if parsed.RawQuery != "" {
		t.Fatalf("parsed.RawQuery = %q, want empty", parsed.RawQuery)
	}
	if parsed.Fragment != "" {
		t.Fatalf("parsed.Fragment = %q, want empty", parsed.Fragment)
	}
}
