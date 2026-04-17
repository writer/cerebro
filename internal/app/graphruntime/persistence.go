package graphruntime

import (
	"strings"

	"github.com/writer/cerebro/internal/graph"
)

func (a *Runtime) InitGraphPersistenceStore() {
	if a == nil || a.config() == nil {
		return
	}
	path := strings.TrimSpace(a.config().GraphSnapshotPath)
	if path == "" {
		return
	}
	store, err := graph.NewGraphPersistenceStore(graph.GraphPersistenceOptions{
		LocalPath:    path,
		MaxSnapshots: a.config().GraphSnapshotMaxRetained,
	})
	if err != nil {
		if logger := a.logger(); logger != nil {
			logger.Warn("failed to initialize graph persistence store", "error", err, "path", path)
		}
		return
	}
	a.setGraphSnapshots(store)
	if logger := a.logger(); logger != nil {
		logger.Info("graph persistence store initialized", "path", path)
	}
}
