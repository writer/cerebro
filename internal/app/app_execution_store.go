package app

import (
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
