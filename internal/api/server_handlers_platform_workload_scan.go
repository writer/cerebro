package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/workloadscan"
)

type platformWorkloadScanTargetCollection struct {
	GeneratedAt time.Time                     `json:"generated_at"`
	Count       int                           `json:"count"`
	Targets     []workloadscan.TargetPriority `json:"targets"`
}

func (s *Server) listPlatformWorkloadScanTargets(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.app == nil {
		s.error(w, http.StatusServiceUnavailable, "platform not initialized")
		return
	}
	g := s.app.CurrentSecurityGraph()
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "security graph not initialized")
		return
	}
	limit, err := parseOptionalIntQuery(r, "limit", 50, 1, 200)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	includeDeferred, _, err := parseOptionalBoolQuery(r, "include_deferred")
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	providers, err := parseWorkloadProviders(parseCSVQueryValues(r.URL.Query()["provider"]))
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	store, closeStore, err := s.platformWorkloadScanRunStore()
	if err != nil {
		s.error(w, http.StatusInternalServerError, "workload scan state unavailable")
		return
	}
	if closeStore != nil {
		defer closeStore()
	}
	targets, err := workloadscan.PrioritizeTargets(r.Context(), g, store, workloadscan.PrioritizationOptions{
		Providers:       providers,
		IncludeDeferred: includeDeferred,
		Limit:           limit,
		Now:             func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		s.error(w, http.StatusInternalServerError, "failed to prioritize workload scan targets")
		return
	}
	s.json(w, http.StatusOK, platformWorkloadScanTargetCollection{
		GeneratedAt: time.Now().UTC(),
		Count:       len(targets),
		Targets:     targets,
	})
}

func (s *Server) platformWorkloadScanRunStore() (workloadscan.RunStore, func(), error) {
	if s == nil || s.app == nil || s.app.Config == nil {
		return nil, nil, nil
	}
	path := strings.TrimSpace(s.app.Config.WorkloadScanStateFile)
	if path == "" {
		return nil, nil, nil
	}
	store, err := workloadscan.NewSQLiteRunStore(path)
	if err != nil {
		return nil, nil, err
	}
	return store, func() { _ = store.Close() }, nil
}

func parseWorkloadProviders(values []string) ([]workloadscan.ProviderKind, error) {
	if len(values) == 0 {
		return nil, nil
	}
	providers := make([]workloadscan.ProviderKind, 0, len(values))
	seen := make(map[workloadscan.ProviderKind]struct{}, len(values))
	for _, raw := range values {
		switch workloadscan.ProviderKind(strings.ToLower(strings.TrimSpace(raw))) {
		case workloadscan.ProviderAWS, workloadscan.ProviderGCP, workloadscan.ProviderAzure:
			provider := workloadscan.ProviderKind(strings.ToLower(strings.TrimSpace(raw)))
			if _, ok := seen[provider]; ok {
				continue
			}
			seen[provider] = struct{}{}
			providers = append(providers, provider)
		default:
			return nil, errBadRequest("provider must be one of aws, gcp, azure")
		}
	}
	return providers, nil
}
