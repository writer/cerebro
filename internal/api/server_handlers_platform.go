package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/writer/cerebro/internal/graph"
)

type platformGraphQueryRequest struct {
	Mode      string     `json:"mode,omitempty"`
	NodeID    string     `json:"node_id"`
	Direction string     `json:"direction,omitempty"`
	Limit     int        `json:"limit,omitempty"`
	TargetID  string     `json:"target_id,omitempty"`
	K         int        `json:"k,omitempty"`
	MaxDepth  int        `json:"max_depth,omitempty"`
	AsOf      *time.Time `json:"as_of,omitempty"`
	From      *time.Time `json:"from,omitempty"`
	To        *time.Time `json:"to,omitempty"`
}

func (s *Server) platformGraphQueries(w http.ResponseWriter, r *http.Request) {
	var req platformGraphQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.NodeID) == "" {
		s.error(w, http.StatusBadRequest, "node_id is required")
		return
	}
	values := url.Values{}
	values.Set("node_id", strings.TrimSpace(req.NodeID))
	if mode := strings.TrimSpace(req.Mode); mode != "" {
		values.Set("mode", mode)
	}
	if direction := strings.TrimSpace(req.Direction); direction != "" {
		values.Set("direction", direction)
	}
	if req.Limit > 0 {
		values.Set("limit", fmt.Sprintf("%d", req.Limit))
	}
	if targetID := strings.TrimSpace(req.TargetID); targetID != "" {
		values.Set("target_id", targetID)
	}
	if req.K > 0 {
		values.Set("k", fmt.Sprintf("%d", req.K))
	}
	if req.MaxDepth > 0 {
		values.Set("max_depth", fmt.Sprintf("%d", req.MaxDepth))
	}
	if req.AsOf != nil && !req.AsOf.IsZero() {
		values.Set("as_of", req.AsOf.UTC().Format(time.RFC3339))
	}
	if req.From != nil && !req.From.IsZero() {
		values.Set("from", req.From.UTC().Format(time.RFC3339))
	}
	if req.To != nil && !req.To.IsZero() {
		values.Set("to", req.To.UTC().Format(time.RFC3339))
	}
	platformGraphQueryFromValues(w, r, values, s.graphQuery)
}

func (s *Server) platformGraphQueriesGet(w http.ResponseWriter, r *http.Request) {
	s.graphQuery(w, r)
}

func (s *Server) platformGraphTemplates(w http.ResponseWriter, r *http.Request) {
	s.graphQueryTemplates(w, r)
}

func (s *Server) listPlatformGraphSnapshots(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusOK, s.platformGraphSnapshotCollection(r.Context()))
}

func (s *Server) getCurrentPlatformGraphSnapshot(w http.ResponseWriter, r *http.Request) {
	view, err := s.currentTenantSecurityGraphSnapshotView(r.Context())
	if err != nil {
		if errors.Is(err, graph.ErrStoreUnavailable) {
			s.errorFromErr(w, err)
			return
		}
		s.errorFromErr(w, err)
		return
	}
	current := graph.CurrentGraphSnapshotRecord(view)
	if current == nil {
		s.error(w, http.StatusNotFound, "graph snapshot not available")
		return
	}
	s.json(w, http.StatusOK, current)
}

func (s *Server) getPlatformGraphSnapshot(w http.ResponseWriter, r *http.Request) {
	snapshotID := strings.TrimSpace(chi.URLParam(r, "snapshot_id"))
	if snapshotID == "" {
		s.error(w, http.StatusBadRequest, "snapshot id required")
		return
	}
	snapshot, ok := s.platformGraphSnapshot(r.Context(), snapshotID)
	if !ok {
		s.error(w, http.StatusNotFound, "graph snapshot not found")
		return
	}
	s.json(w, http.StatusOK, snapshot)
}

func (s *Server) platformWriteClaim(w http.ResponseWriter, r *http.Request) {
	s.graphWriteClaim(w, r)
}

func (s *Server) platformWriteDecision(w http.ResponseWriter, r *http.Request) {
	s.graphWriteDecision(w, r)
}

func platformGraphQueryFromValues(w http.ResponseWriter, r *http.Request, values url.Values, next http.HandlerFunc) {
	reqCopy := r.Clone(r.Context())
	urlCopy := *r.URL
	urlCopy.RawQuery = values.Encode()
	reqCopy.URL = &urlCopy
	reqCopy.Method = http.MethodGet
	reqCopy.Body = http.NoBody
	next(w, reqCopy)
}

func (s *Server) platformGraphSnapshotCollection(ctx context.Context) graph.GraphSnapshotCollection {
	return graph.GraphSnapshotCollectionFromRecords(s.platformGraphSnapshotRecords(ctx), time.Now().UTC())
}

func (s *Server) platformGraphSnapshot(ctx context.Context, snapshotID string) (*graph.GraphSnapshotRecord, bool) {
	record, ok := s.platformGraphSnapshotRecords(ctx)[strings.TrimSpace(snapshotID)]
	if !ok || record == nil {
		return nil, false
	}
	snapshot := *record
	return &snapshot, true
}
