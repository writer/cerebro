package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/snowflake"
)

func (s *Server) syncStatus(w http.ResponseWriter, r *http.Request) {
	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	// Query _cq_sync_time from key tables to determine freshness
	tables := []string{
		"aws_s3_buckets",
		"aws_iam_users",
		"aws_ec2_instances",
		"gcp_storage_buckets",
		"gcp_compute_instances",
		"azure_storage_accounts",
		"k8s_core_pods",
	}

	sources := make(map[string]interface{})
	staleThreshold := 6 * time.Hour

	for _, table := range tables {
		// Validate table name (these are hardcoded above, but validate for safety)
		if err := snowflake.ValidateTableName(table); err != nil {
			continue
		}
		query := fmt.Sprintf("SELECT MAX(_cq_sync_time) as last_sync FROM %s", table)
		result, err := s.app.Snowflake.Query(r.Context(), query)
		if err != nil {
			continue // Table might not exist
		}

		if len(result.Rows) > 0 {
			lastSync := parseLastSyncRow(result.Rows[0])
			if !lastSync.IsZero() {
				status := "fresh"
				if time.Since(lastSync) > staleThreshold {
					status = "stale"
				}

				// Extract provider from table name
				provider := "unknown"
				if len(table) > 4 {
					switch {
					case table[:3] == "aws":
						provider = "aws"
					case table[:3] == "gcp":
						provider = "gcp"
					case table[:5] == "azure":
						provider = "azure"
					case table[:3] == "k8s":
						provider = "kubernetes"
					}
				}

				if existing, ok := sources[provider].(map[string]interface{}); ok {
					// Keep the most recent sync time
					if existingTime, ok := existing["last_sync"].(time.Time); ok {
						if lastSync.After(existingTime) {
							sources[provider] = map[string]interface{}{
								"last_sync": lastSync,
								"status":    status,
								"age":       time.Since(lastSync).String(),
							}
						}
					}
				} else {
					sources[provider] = map[string]interface{}{
						"last_sync": lastSync,
						"status":    status,
						"age":       time.Since(lastSync).String(),
					}
				}
			}
		}
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"sources":         sources,
		"stale_threshold": staleThreshold.String(),
		"checked_at":      time.Now().UTC(),
	})
}

func parseLastSyncRow(row map[string]interface{}) time.Time {
	value, ok := queryRowValue(row, "last_sync")
	if !ok {
		return time.Time{}
	}
	return parseLastSyncValue(value)
}

func parseLastSyncValue(value interface{}) time.Time {
	switch typed := value.(type) {
	case time.Time:
		return typed
	case *time.Time:
		if typed == nil {
			return time.Time{}
		}
		return *typed
	case string:
		if typed == "" {
			return time.Time{}
		}
		if parsed, err := time.Parse(time.RFC3339Nano, typed); err == nil {
			return parsed
		}
		if parsed, err := time.Parse(time.RFC3339, typed); err == nil {
			return parsed
		}
	}

	return time.Time{}
}

// Query endpoints

func (s *Server) listTables(w http.ResponseWriter, r *http.Request) {
	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	tables, err := s.app.Snowflake.ListTables(r.Context())
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"tables": tables, "count": len(tables)})
}

func (s *Server) executeQuery(w http.ResponseWriter, r *http.Request) {
	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	var req struct {
		Query          string `json:"query"`
		Limit          int    `json:"limit"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	boundedQuery, boundedLimit, err := snowflake.BuildReadOnlyLimitedQuery(req.Query, req.Limit)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	queryCtx, cancel := context.WithTimeout(r.Context(), snowflake.ClampReadOnlyQueryTimeout(req.TimeoutSeconds))
	defer cancel()

	result, err := s.app.Snowflake.Query(queryCtx, boundedQuery)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "query execution failed")
		return
	}

	if result != nil && result.Count > boundedLimit {
		result.Rows = result.Rows[:boundedLimit]
		result.Count = len(result.Rows)
	}

	s.json(w, http.StatusOK, result)
}

// Asset endpoints

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request) {
	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	table := chi.URLParam(r, "table")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 100
	}

	assets, err := s.app.Snowflake.GetAssets(r.Context(), table, snowflake.AssetFilter{
		Limit:   limit,
		Account: r.URL.Query().Get("account"),
		Region:  r.URL.Query().Get("region"),
	})
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"assets": assets, "count": len(assets)})
}

func (s *Server) getAsset(w http.ResponseWriter, r *http.Request) {
	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	table := chi.URLParam(r, "table")
	id := chi.URLParam(r, "id")

	asset, err := s.app.Snowflake.GetAssetByID(r.Context(), table, id)
	if err != nil {
		s.error(w, http.StatusNotFound, err.Error())
		return
	}
	s.json(w, http.StatusOK, asset)
}

// Policy endpoints

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	policies := s.app.Policy.ListPolicies()
	s.json(w, http.StatusOK, map[string]interface{}{"policies": policies, "count": len(policies)})
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	p, ok := s.app.Policy.GetPolicy(id)
	if !ok {
		s.error(w, http.StatusNotFound, "policy not found")
		return
	}
	s.json(w, http.StatusOK, p)
}

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) {
	var p policy.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}
	s.app.Policy.AddPolicy(&p)
	s.json(w, http.StatusCreated, p)
}

func (s *Server) evaluatePolicy(w http.ResponseWriter, r *http.Request) {
	var req policy.EvalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	resp, err := s.app.Policy.Evaluate(r.Context(), &req)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, resp)
}

// Finding endpoints

// Identity/Access Review endpoints
