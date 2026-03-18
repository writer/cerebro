package app

import (
	"path/filepath"
	"strings"

	"github.com/writer/cerebro/internal/executionstore"
)

func (a *App) initExecutionStore() {
	if a == nil || a.Config == nil {
		return
	}
	path := strings.TrimSpace(a.Config.ExecutionStoreFile)
	if path == "" {
		return
	}
	store, err := executionstore.NewSQLiteStore(path)
	if err != nil {
		if a.Logger != nil {
			a.Logger.Warn("failed to initialize shared execution store", "error", err, "path", path)
		}
		return
	}
	a.ExecutionStore = store
	if a.Logger != nil {
		a.Logger.Info("shared execution store initialized", "path", path)
	}
}

func (a *App) executionStoreForPath(path string) executionstore.Store {
	if a == nil || a.ExecutionStore == nil || a.Config == nil {
		return nil
	}
	if sameExecutionStorePath(a.Config.ExecutionStoreFile, path) {
		return a.ExecutionStore
	}
	return nil
}

func sameExecutionStorePath(left, right string) bool {
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)
	if left == "" || right == "" {
		return false
	}
	leftAbs, leftErr := filepath.Abs(filepath.Clean(left))
	rightAbs, rightErr := filepath.Abs(filepath.Clean(right))
	if leftErr == nil && rightErr == nil {
		return leftAbs == rightAbs
	}
	return filepath.Clean(left) == filepath.Clean(right)
}
