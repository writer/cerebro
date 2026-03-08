package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

func (s *Server) graphDiff(w http.ResponseWriter, r *http.Request) {
	fromRaw := strings.TrimSpace(r.URL.Query().Get("from"))
	toRaw := strings.TrimSpace(r.URL.Query().Get("to"))
	if fromRaw == "" || toRaw == "" {
		s.error(w, http.StatusBadRequest, "both from and to query parameters are required (RFC3339)")
		return
	}

	from, err := time.Parse(time.RFC3339, fromRaw)
	if err != nil {
		s.error(w, http.StatusBadRequest, "invalid from timestamp, must be RFC3339")
		return
	}
	to, err := time.Parse(time.RFC3339, toRaw)
	if err != nil {
		s.error(w, http.StatusBadRequest, "invalid to timestamp, must be RFC3339")
		return
	}

	snapshotPath := strings.TrimSpace(os.Getenv("GRAPH_SNAPSHOT_PATH"))
	if snapshotPath == "" {
		snapshotPath = filepath.Join(".cerebro", "graph-snapshots")
	}

	store := graph.NewSnapshotStore(snapshotPath, 10)
	diff, err := store.DiffByTime(from, to)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "no snapshots") {
			status = http.StatusNotFound
		}
		s.error(w, status, err.Error())
		return
	}

	s.json(w, http.StatusOK, diff)
}
