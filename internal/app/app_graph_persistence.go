package app

import (
	"strings"

	"github.com/writer/cerebro/internal/graph"
)

func (a *App) initGraphPersistenceStore() {
	if a == nil || a.Config == nil {
		return
	}
	path := strings.TrimSpace(a.Config.GraphSnapshotPath)
	if path == "" {
		return
	}
	store, err := graph.NewGraphPersistenceStore(graph.GraphPersistenceOptions{
		LocalPath:    path,
		MaxSnapshots: a.Config.GraphSnapshotMaxRetained,
		ReplicaURI:   a.Config.GraphSnapshotReplicaURI,
	})
	if err != nil {
		if a.Logger != nil {
			a.Logger.Warn("failed to initialize graph persistence store", "error", err, "path", path, "replica_uri", strings.TrimSpace(a.Config.GraphSnapshotReplicaURI))
		}
		return
	}
	a.GraphSnapshots = store
	if a.Logger != nil {
		a.Logger.Info("graph persistence store initialized", "path", path, "replica_uri", strings.TrimSpace(a.Config.GraphSnapshotReplicaURI))
	}
}
