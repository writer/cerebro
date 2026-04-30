//go:build !cgo

package kuzu

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/writer/cerebro/internal/config"
)

func TestOpenWithoutCGOReturnsClearError(t *testing.T) {
	_, err := Open(config.GraphStoreConfig{
		Driver:   config.GraphStoreDriverKuzu,
		KuzuPath: filepath.Join(t.TempDir(), "graph"),
	})
	if !errors.Is(err, errCGORequired) {
		t.Fatalf("Open() error = %v, want %v", err, errCGORequired)
	}
}
