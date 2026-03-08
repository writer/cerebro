package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/evalops/cerebro/internal/snowflake"
	nativesync "github.com/evalops/cerebro/internal/sync"
)

func (s *Server) backfillRelationshipIDs(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BatchSize int `json:"batch_size"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.BatchSize <= 0 {
		req.BatchSize = 200
	}

	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	extractor := nativesync.NewRelationshipExtractor(s.app.Snowflake, s.app.Logger)
	stats, err := extractor.BackfillNormalizedRelationshipIDs(r.Context(), req.BatchSize)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"scanned": stats.Scanned,
		"updated": stats.Updated,
		"deleted": stats.Deleted,
		"skipped": stats.Skipped,
	})
}

type azureSyncRequest struct {
	Subscription string   `json:"subscription"`
	Concurrency  int      `json:"concurrency"`
	Tables       []string `json:"tables"`
	Validate     bool     `json:"validate"`
}

var runAzureSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req azureSyncRequest) ([]nativesync.SyncResult, error) {
	opts := []nativesync.AzureEngineOption{}
	if req.Subscription != "" {
		opts = append(opts, nativesync.WithAzureSubscription(req.Subscription))
	}
	if req.Concurrency > 0 {
		opts = append(opts, nativesync.WithAzureConcurrency(req.Concurrency))
	}
	if len(req.Tables) > 0 {
		opts = append(opts, nativesync.WithAzureTableFilter(req.Tables))
	}

	syncer, err := nativesync.NewAzureSyncEngine(client, slog.Default(), opts...)
	if err != nil {
		return nil, fmt.Errorf("create azure sync engine: %w", err)
	}

	if req.Validate {
		results, err := syncer.ValidateTables(ctx)
		if err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		return results, nil
	}

	results, err := syncer.SyncAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("sync failed: %w", err)
	}
	return results, nil
}

func (s *Server) syncAzure(w http.ResponseWriter, r *http.Request) {
	var req azureSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	req.Subscription = strings.TrimSpace(req.Subscription)
	req.Tables = normalizeSyncTables(req.Tables)

	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	results, err := runAzureSyncWithOptions(r.Context(), s.app.Snowflake, req)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"provider": "azure",
		"validate": req.Validate,
		"results":  results,
	})
}

func normalizeSyncTables(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, table := range raw {
		name := strings.ToLower(strings.TrimSpace(table))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		normalized = append(normalized, name)
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}
