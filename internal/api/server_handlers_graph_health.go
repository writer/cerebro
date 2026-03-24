package api

import (
	"net/http"
	"time"
)

func (s *Server) graphHealth(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.app == nil {
		writeJSONError(w, http.StatusServiceUnavailable, httpStatusToCode(http.StatusServiceUnavailable), "graph platform not initialized")
		return
	}
	s.json(w, http.StatusOK, s.app.GraphHealthSnapshot(time.Now().UTC()))
}
