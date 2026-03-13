package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/evalops/cerebro/internal/graph"
	reports "github.com/evalops/cerebro/internal/graph/reports"
	"github.com/evalops/cerebro/internal/webhooks"
)

type platformGraphDiffRequest struct {
	FromSnapshotID    string `json:"from_snapshot_id"`
	ToSnapshotID      string `json:"to_snapshot_id"`
	ExecutionMode     string `json:"execution_mode,omitempty"`
	MaterializeResult *bool  `json:"materialize_result,omitempty"`
}

func (s *Server) createPlatformGraphDiff(w http.ResponseWriter, r *http.Request) {
	var req platformGraphDiffRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	switch strings.TrimSpace(req.ExecutionMode) {
	case "", "sync":
		diff, status, err := s.platformGraphSnapshotDiff(req.FromSnapshotID, req.ToSnapshotID)
		if err != nil {
			s.error(w, status, err.Error())
			return
		}
		if req.MaterializeResult != nil && *req.MaterializeResult {
			stored, err := s.materializePlatformGraphDiff(diff, "")
			if err != nil {
				s.error(w, http.StatusInternalServerError, err.Error())
				return
			}
			diff = stored
		}
		s.json(w, http.StatusOK, diff)
	case "async":
		requestedBy := strings.TrimSpace(GetUserID(r.Context()))
		job := s.newPlatformJob(r.Context(), "platform.graph_snapshot_diff", map[string]any{
			"from_snapshot_id": req.FromSnapshotID,
			"to_snapshot_id":   req.ToSnapshotID,
			"execution_mode":   "async",
		}, requestedBy)
		s.startPlatformJob(job.ID, func(_ context.Context) (any, error) {
			diff, status, err := s.platformGraphSnapshotDiff(req.FromSnapshotID, req.ToSnapshotID)
			if err != nil {
				return nil, reportExecutionError{StatusCode: status, Message: err.Error()}
			}
			stored, err := s.materializePlatformGraphDiff(diff, job.ID)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"diff_id":    stored.ID,
				"diff_url":   "/api/v1/platform/graph/diffs/" + stored.ID,
				"summary":    stored.Summary,
				"stored_at":  normalizeRFC3339(*stored.StoredAt),
				"job_id":     job.ID,
				"status_url": job.StatusURL,
			}, nil
		})
		s.json(w, http.StatusAccepted, job)
	default:
		s.error(w, http.StatusBadRequest, "execution_mode must be sync or async")
		return
	}
}

func (s *Server) getPlatformGraphDiffArtifact(w http.ResponseWriter, r *http.Request) {
	diffID := strings.TrimSpace(chi.URLParam(r, "diff_id"))
	if diffID == "" {
		s.error(w, http.StatusBadRequest, "diff id required")
		return
	}
	store := s.platformGraphDiffStore()
	if store == nil {
		s.error(w, http.StatusNotFound, "graph snapshot diff store not configured")
		return
	}
	record, err := store.Load(diffID)
	if err != nil {
		s.error(w, http.StatusNotFound, err.Error())
		return
	}
	s.json(w, http.StatusOK, record)
}

func (s *Server) getPlatformGraphDiffDetails(w http.ResponseWriter, r *http.Request) {
	diffID := strings.TrimSpace(chi.URLParam(r, "diff_id"))
	if diffID == "" {
		s.error(w, http.StatusBadRequest, "diff id required")
		return
	}
	record, _, status, err := s.platformGraphDiffForRead(diffID)
	if err != nil {
		s.error(w, status, err.Error())
		return
	}
	filter := parseGraphDiffFilterQuery(r)
	details, status, err := s.platformGraphDiffDetails(record, filter)
	if err != nil {
		s.error(w, status, err.Error())
		return
	}
	s.json(w, http.StatusOK, details)
}

func (s *Server) listPlatformGraphChangelog(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	since, until, err := parseGraphChangelogWindow(r, now)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	limit, err := parseOptionalIntQuery(r, "limit", 20, 1, 200)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	filter := parseGraphDiffFilterQuery(r)
	changelog := graph.GraphChangelog{
		GeneratedAt: now,
		Filter:      filter,
	}
	if !since.IsZero() {
		copy := since.UTC()
		changelog.Since = &copy
	}
	if !until.IsZero() {
		copy := until.UTC()
		changelog.Until = &copy
	}

	records := make([]graph.GraphSnapshotRecord, 0)
	for _, record := range s.platformGraphSnapshotRecordMap() {
		if record == nil || !record.Diffable {
			continue
		}
		records = append(records, *record)
	}
	sort.Slice(records, func(i, j int) bool {
		left := snapshotRecordSortTime(records[i])
		right := snapshotRecordSortTime(records[j])
		if !left.Equal(right) {
			return left.Before(right)
		}
		return records[i].ID < records[j].ID
	})

	entries := make([]graph.GraphChangelogEntry, 0, limit)
	for i := len(records) - 2; i >= 0; i-- {
		fromRecord := records[i]
		toRecord := records[i+1]
		changeTime := snapshotRecordSortTime(toRecord)
		if !since.IsZero() && changeTime.Before(since) {
			continue
		}
		if !until.IsZero() && changeTime.After(until) {
			continue
		}
		record, snapshots, _, err := s.platformGraphSnapshotDiffWithSnapshots(fromRecord.ID, toRecord.ID)
		if err != nil {
			continue
		}
		details := graph.BuildGraphSnapshotDiffDetails(record, snapshots[fromRecord.ID], snapshots[toRecord.ID], filter)
		if details == nil {
			continue
		}
		if details.Summary.NodesAdded == 0 &&
			details.Summary.NodesRemoved == 0 &&
			details.Summary.NodesModified == 0 &&
			details.Summary.EdgesAdded == 0 &&
			details.Summary.EdgesRemoved == 0 {
			continue
		}
		diffURL := "/api/v1/platform/graph/snapshots/" + fromRecord.ID + "/diffs/" + toRecord.ID
		if stored, err := s.loadPlatformGraphDiff(record.ID); err == nil && stored != nil {
			record = stored
			diffURL = "/api/v1/platform/graph/diffs/" + record.ID
		}
		entries = append(entries, graph.GraphChangelogEntry{
			DiffID:       record.ID,
			DiffURL:      diffURL,
			GeneratedAt:  record.GeneratedAt,
			StoredAt:     record.StoredAt,
			Materialized: record.Materialized,
			From:         record.From,
			To:           record.To,
			Summary:      details.Summary,
			Attribution:  details.Attribution,
		})
		if len(entries) == limit {
			break
		}
	}

	changelog.Entries = entries
	changelog.Count = len(entries)
	s.json(w, http.StatusOK, changelog)
}

func (s *Server) materializePlatformGraphDiff(record *graph.GraphSnapshotDiffRecord, jobID string) (*graph.GraphSnapshotDiffRecord, error) {
	store := s.platformGraphDiffStore()
	if store == nil {
		return nil, fmt.Errorf("graph snapshot diff store not configured")
	}
	if record == nil || strings.TrimSpace(record.ID) == "" {
		return nil, fmt.Errorf("graph snapshot diff record is required")
	}
	if existing, err := store.Load(strings.TrimSpace(record.ID)); err == nil && existing != nil {
		return existing, nil
	}
	cloned := *record
	cloned.JobID = strings.TrimSpace(jobID)
	stored, err := store.Save(&cloned)
	if err != nil {
		return nil, err
	}
	s.emitPlatformGraphChangelogComputed(context.Background(), stored)
	return stored, nil
}

func (s *Server) loadPlatformGraphDiff(diffID string) (*graph.GraphSnapshotDiffRecord, error) {
	store := s.platformGraphDiffStore()
	if store == nil {
		return nil, fmt.Errorf("graph snapshot diff store not configured")
	}
	return store.Load(diffID)
}

func (s *Server) platformGraphDiffForRead(diffID string) (*graph.GraphSnapshotDiffRecord, map[string]*graph.Snapshot, int, error) {
	diffID = strings.TrimSpace(diffID)
	if diffID == "" {
		return nil, nil, http.StatusBadRequest, fmt.Errorf("diff id required")
	}
	if stored, err := s.loadPlatformGraphDiff(diffID); err == nil && stored != nil {
		snapshots, status, err := s.platformGraphSnapshotsForRecord(stored)
		if err != nil {
			return nil, nil, status, err
		}
		return stored, snapshots, 0, nil
	}
	return s.platformGraphSnapshotDiffByID(diffID)
}

func (s *Server) platformGraphSnapshotsForRecord(record *graph.GraphSnapshotDiffRecord) (map[string]*graph.Snapshot, int, error) {
	if record == nil {
		return nil, http.StatusNotFound, fmt.Errorf("graph snapshot diff not found")
	}
	fromSnapshotID := strings.TrimSpace(record.From.ID)
	toSnapshotID := strings.TrimSpace(record.To.ID)
	if fromSnapshotID == "" || toSnapshotID == "" {
		return nil, http.StatusNotFound, fmt.Errorf("graph snapshot diff missing snapshot references")
	}
	store := s.platformGraphSnapshotStore()
	if store == nil {
		return nil, http.StatusNotFound, fmt.Errorf("graph snapshot store not configured")
	}
	snapshots, _, err := store.LoadSnapshotsByRecordIDs(fromSnapshotID, toSnapshotID)
	if err != nil {
		return nil, http.StatusNotFound, err
	}
	return snapshots, 0, nil
}

func (s *Server) platformGraphSnapshotDiffByID(diffID string) (*graph.GraphSnapshotDiffRecord, map[string]*graph.Snapshot, int, error) {
	diffID = strings.TrimSpace(diffID)
	if diffID == "" {
		return nil, nil, http.StatusBadRequest, fmt.Errorf("diff id required")
	}
	records := make([]graph.GraphSnapshotRecord, 0)
	for _, record := range s.platformGraphSnapshotRecordMap() {
		if record == nil || !record.Diffable {
			continue
		}
		records = append(records, *record)
	}
	sort.Slice(records, func(i, j int) bool {
		left := snapshotRecordSortTime(records[i])
		right := snapshotRecordSortTime(records[j])
		if !left.Equal(right) {
			return left.Before(right)
		}
		return records[i].ID < records[j].ID
	})
	for i := 0; i+1 < len(records); i++ {
		candidate := graph.BuildGraphSnapshotDiffRecord(records[i], records[i+1], &graph.GraphDiff{}, time.Time{})
		if candidate == nil || candidate.ID != diffID {
			continue
		}
		return s.platformGraphSnapshotDiffWithSnapshots(records[i].ID, records[i+1].ID)
	}
	return nil, nil, http.StatusNotFound, fmt.Errorf("graph snapshot diff not found: %s", diffID)
}

func (s *Server) platformGraphDiffStore() *graph.GraphSnapshotDiffStore {
	snapshotPath := strings.TrimSpace(os.Getenv("GRAPH_SNAPSHOT_PATH"))
	if snapshotPath == "" {
		snapshotPath = filepath.Join(".cerebro", "graph-snapshots")
	}
	return graph.NewGraphSnapshotDiffStore(filepath.Join(snapshotPath, "diffs"))
}

func (s *Server) platformGraphSnapshotRecordMap() map[string]*graph.GraphSnapshotRecord {
	records := s.platformGraphSnapshotRecords()
	if len(records) == 0 {
		return records
	}
	cloned := make(map[string]*graph.GraphSnapshotRecord, len(records))
	for id, record := range records {
		if record == nil {
			continue
		}
		copy := *record
		cloned[id] = &copy
	}
	return cloned
}

func (s *Server) getPlatformGraphSnapshotAncestry(w http.ResponseWriter, r *http.Request) {
	snapshotID := strings.TrimSpace(chi.URLParam(r, "snapshot_id"))
	if snapshotID == "" {
		s.error(w, http.StatusBadRequest, "snapshot id required")
		return
	}
	collection := s.platformGraphSnapshotCollection()
	ancestry, ok := graph.GraphSnapshotAncestryFromCollection(collection, snapshotID)
	if !ok {
		s.error(w, http.StatusNotFound, "graph snapshot not found")
		return
	}
	s.json(w, http.StatusOK, ancestry)
}

func (s *Server) getPlatformGraphSnapshotDiff(w http.ResponseWriter, r *http.Request) {
	fromSnapshotID := strings.TrimSpace(chi.URLParam(r, "snapshot_id"))
	toSnapshotID := strings.TrimSpace(chi.URLParam(r, "other_snapshot_id"))
	diff, status, err := s.platformGraphSnapshotDiff(fromSnapshotID, toSnapshotID)
	if err != nil {
		s.error(w, status, err.Error())
		return
	}
	s.json(w, http.StatusOK, diff)
}

func (s *Server) platformGraphSnapshotDiff(fromSnapshotID, toSnapshotID string) (*graph.GraphSnapshotDiffRecord, int, error) {
	record, _, status, err := s.platformGraphSnapshotDiffWithSnapshots(fromSnapshotID, toSnapshotID)
	return record, status, err
}

func (s *Server) platformGraphSnapshotDiffWithSnapshots(fromSnapshotID, toSnapshotID string) (*graph.GraphSnapshotDiffRecord, map[string]*graph.Snapshot, int, error) {
	fromSnapshotID = strings.TrimSpace(fromSnapshotID)
	toSnapshotID = strings.TrimSpace(toSnapshotID)
	if fromSnapshotID == "" || toSnapshotID == "" {
		return nil, nil, http.StatusBadRequest, fmt.Errorf("from_snapshot_id and to_snapshot_id are required")
	}
	records := s.platformGraphSnapshotRecordMap()
	fromRecord, ok := records[fromSnapshotID]
	if !ok {
		return nil, nil, http.StatusNotFound, fmt.Errorf("graph snapshot not found: %s", fromSnapshotID)
	}
	toRecord, ok := records[toSnapshotID]
	if !ok {
		return nil, nil, http.StatusNotFound, fmt.Errorf("graph snapshot not found: %s", toSnapshotID)
	}
	if !fromRecord.Diffable || !toRecord.Diffable {
		return nil, nil, http.StatusConflict, fmt.Errorf("graph snapshot diffs require materialized snapshots")
	}
	store := s.platformGraphSnapshotStore()
	if store == nil {
		return nil, nil, http.StatusNotFound, fmt.Errorf("graph snapshot store not configured")
	}
	snapshots, _, err := store.LoadSnapshotsByRecordIDs(fromSnapshotID, toSnapshotID)
	if err != nil {
		return nil, nil, http.StatusNotFound, err
	}
	diff := graph.DiffSnapshots(snapshots[fromSnapshotID], snapshots[toSnapshotID])
	record := graph.BuildGraphSnapshotDiffRecord(*fromRecord, *toRecord, diff, time.Now().UTC())
	if record == nil {
		return nil, nil, http.StatusInternalServerError, fmt.Errorf("failed to build graph snapshot diff")
	}
	return record, snapshots, 0, nil
}

func (s *Server) platformGraphSnapshotStore() *graph.SnapshotStore {
	snapshotPath := strings.TrimSpace(os.Getenv("GRAPH_SNAPSHOT_PATH"))
	if snapshotPath == "" {
		snapshotPath = filepath.Join(".cerebro", "graph-snapshots")
	}
	return graph.NewSnapshotStore(snapshotPath, 10)
}

func (s *Server) platformGraphSnapshotRecords() map[string]*graph.GraphSnapshotRecord {
	collection := reports.GraphSnapshotCollectionSnapshot(s.app.SecurityGraph, s.platformReportRunSnapshotMap(), time.Now().UTC())
	records := make(map[string]*graph.GraphSnapshotRecord, collection.Count)
	for i := range collection.Snapshots {
		record := collection.Snapshots[i]
		copy := record
		records[record.ID] = &copy
	}
	store := s.platformGraphSnapshotStore()
	if store == nil {
		return records
	}
	persisted, err := store.ListGraphSnapshotRecords()
	if err != nil {
		return records
	}
	for i := range persisted {
		record := persisted[i]
		existing, ok := records[record.ID]
		if !ok {
			copy := record
			records[record.ID] = &copy
			continue
		}
		mergePlatformGraphSnapshotRecord(existing, record)
	}
	return records
}

func (s *Server) platformReportRunSnapshotMap() map[string]*reports.ReportRun {
	if s.platformReportStore != nil {
		runs, err := s.platformReportStore.ListRuns("")
		if err == nil {
			records := make(map[string]*reports.ReportRun, len(runs))
			for _, run := range runs {
				if run == nil || strings.TrimSpace(run.ID) == "" {
					continue
				}
				records[run.ID] = reports.CloneReportRun(run)
			}
			s.platformReportRunMu.RLock()
			for id, run := range s.platformReportRuns {
				if run == nil {
					continue
				}
				records[id] = reports.CloneReportRun(run)
			}
			s.platformReportRunMu.RUnlock()
			return records
		}
	}
	s.platformReportRunMu.RLock()
	defer s.platformReportRunMu.RUnlock()
	return s.clonePlatformReportRunsLocked()
}

func mergePlatformGraphSnapshotRecord(dst *graph.GraphSnapshotRecord, src graph.GraphSnapshotRecord) {
	if dst == nil {
		return
	}
	if dst.BuiltAt == nil && src.BuiltAt != nil {
		copy := src.BuiltAt.UTC()
		dst.BuiltAt = &copy
	}
	if dst.CapturedAt == nil && src.CapturedAt != nil {
		copy := src.CapturedAt.UTC()
		dst.CapturedAt = &copy
	}
	if src.Current {
		dst.Current = true
	}
	if src.Materialized {
		dst.Materialized = true
	}
	if src.Diffable {
		dst.Diffable = true
	}
	if dst.ParentSnapshotID == "" {
		dst.ParentSnapshotID = strings.TrimSpace(src.ParentSnapshotID)
	}
	if dst.StorageClass == "" {
		dst.StorageClass = strings.TrimSpace(src.StorageClass)
	}
	if dst.RetentionClass == "" {
		dst.RetentionClass = strings.TrimSpace(src.RetentionClass)
	}
	if dst.IntegrityHash == "" {
		dst.IntegrityHash = strings.TrimSpace(src.IntegrityHash)
	}
	if dst.ExpiresAt == nil && src.ExpiresAt != nil {
		copy := src.ExpiresAt.UTC()
		dst.ExpiresAt = &copy
	}
	if dst.ByteSize == 0 {
		dst.ByteSize = src.ByteSize
	}
	if dst.NodeCount == 0 {
		dst.NodeCount = src.NodeCount
	}
	if dst.EdgeCount == 0 {
		dst.EdgeCount = src.EdgeCount
	}
	if dst.BuildDurationMS == 0 {
		dst.BuildDurationMS = src.BuildDurationMS
	}
	if dst.GraphSchemaVersion == 0 {
		dst.GraphSchemaVersion = src.GraphSchemaVersion
	}
	if dst.OntologyContractVersion == "" {
		dst.OntologyContractVersion = strings.TrimSpace(src.OntologyContractVersion)
	}
	if len(dst.Providers) == 0 {
		dst.Providers = append([]string(nil), src.Providers...)
	}
	if len(dst.Accounts) == 0 {
		dst.Accounts = append([]string(nil), src.Accounts...)
	}
}

func (s *Server) platformGraphDiffDetails(record *graph.GraphSnapshotDiffRecord, filter graph.GraphDiffFilter) (*graph.GraphSnapshotDiffDetails, int, error) {
	if record == nil {
		return nil, http.StatusNotFound, fmt.Errorf("graph snapshot diff not found")
	}
	store := s.platformGraphSnapshotStore()
	if store == nil {
		return nil, http.StatusNotFound, fmt.Errorf("graph snapshot store not configured")
	}
	snapshots, _, err := store.LoadSnapshotsByRecordIDs(record.From.ID, record.To.ID)
	if err != nil {
		return nil, http.StatusNotFound, err
	}
	details := graph.BuildGraphSnapshotDiffDetails(record, snapshots[record.From.ID], snapshots[record.To.ID], filter)
	if details == nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to build graph snapshot diff details")
	}
	return details, 0, nil
}

func parseGraphDiffFilterQuery(r *http.Request) graph.GraphDiffFilter {
	return graph.GraphDiffFilter{
		Kind:     graph.NodeKind(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("kind")))),
		Provider: strings.ToLower(strings.TrimSpace(r.URL.Query().Get("provider"))),
		Account:  strings.TrimSpace(r.URL.Query().Get("account")),
	}
}

func parseGraphChangelogWindow(r *http.Request, now time.Time) (time.Time, time.Time, error) {
	since, err := parseOptionalRFC3339Query(r, "since")
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	until, err := parseOptionalRFC3339Query(r, "until")
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("last")); raw != "" {
		window, err := parseFlexibleDuration(raw)
		if err != nil || window <= 0 {
			return time.Time{}, time.Time{}, errBadRequest("last must be a positive duration")
		}
		until = now.UTC()
		since = until.Add(-window)
	}
	if !since.IsZero() && !until.IsZero() && until.Before(since) {
		return time.Time{}, time.Time{}, errBadRequest("until must be greater than or equal to since")
	}
	return since, until, nil
}

func parseOptionalIntQuery(r *http.Request, key string, fallback, min, max int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, errBadRequest(key + " must be an integer")
	}
	if value < min || value > max {
		return 0, errBadRequest(fmt.Sprintf("%s must be between %d and %d", key, min, max))
	}
	return value, nil
}

func parseFlexibleDuration(raw string) (time.Duration, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return 0, fmt.Errorf("duration required")
	}
	if strings.HasSuffix(raw, "d") {
		days, err := strconv.ParseFloat(strings.TrimSuffix(raw, "d"), 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	return time.ParseDuration(raw)
}

func snapshotRecordSortTime(record graph.GraphSnapshotRecord) time.Time {
	switch {
	case record.BuiltAt != nil && !record.BuiltAt.IsZero():
		return record.BuiltAt.UTC()
	case record.CapturedAt != nil && !record.CapturedAt.IsZero():
		return record.CapturedAt.UTC()
	case record.LastObservedAt != nil && !record.LastObservedAt.IsZero():
		return record.LastObservedAt.UTC()
	case record.FirstObservedAt != nil && !record.FirstObservedAt.IsZero():
		return record.FirstObservedAt.UTC()
	default:
		return time.Time{}
	}
}

func (s *Server) emitPlatformGraphChangelogComputed(ctx context.Context, record *graph.GraphSnapshotDiffRecord) {
	if s == nil || s.app == nil || s.app.Webhooks == nil || record == nil {
		return
	}
	payload := map[string]any{
		"diff_id":        record.ID,
		"diff_url":       "/api/v1/platform/graph/diffs/" + record.ID,
		"generated_at":   record.GeneratedAt,
		"from_snapshot":  record.From.ID,
		"to_snapshot":    record.To.ID,
		"nodes_added":    record.Summary.NodesAdded,
		"nodes_removed":  record.Summary.NodesRemoved,
		"nodes_modified": record.Summary.NodesModified,
		"edges_added":    record.Summary.EdgesAdded,
		"edges_removed":  record.Summary.EdgesRemoved,
	}
	_ = s.app.Webhooks.EmitWithErrors(ctx, webhooks.EventPlatformGraphChangelogComputed, payload)
}
