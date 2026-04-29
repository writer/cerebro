//go:build cgo

package bootstrap

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/writer/cerebro/internal/config"
)

func TestOpenDependenciesConfiguresKuzu(t *testing.T) {
	deps, closeAll, err := OpenDependencies(context.Background(), config.Config{
		GraphStore: config.GraphStoreConfig{
			Driver:   config.GraphStoreDriverKuzu,
			KuzuPath: filepath.Join(t.TempDir(), "graph"),
		},
	})
	if err != nil {
		t.Fatalf("OpenDependencies() error = %v", err)
	}
	if deps.GraphStore == nil {
		t.Fatal("GraphStore = nil, want non-nil")
	}
	if err := closeAll(); err != nil {
		t.Fatalf("closeAll() error = %v", err)
	}
}
