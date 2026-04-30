//go:build !cgo

package bootstrap

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/config"
)

func TestOpenDependenciesRejectsKuzuWithoutCGO(t *testing.T) {
	_, _, err := OpenDependencies(context.Background(), config.Config{
		GraphStore: config.GraphStoreConfig{
			Driver:   config.GraphStoreDriverKuzu,
			KuzuPath: filepath.Join(t.TempDir(), "graph"),
		},
	})
	if err == nil || !strings.Contains(err.Error(), "requires CGO") {
		t.Fatalf("OpenDependencies() error = %v, want requires CGO", err)
	}
}
