package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/workloadscan"
)

type platformWorkloadScanTargetCollection struct {
	GeneratedAt time.Time                     `json:"generated_at"`
	Count       int                           `json:"count"`
	Targets     []workloadscan.TargetPriority `json:"targets"`
}

func (s *Server) listPlatformWorkloadScanTargets(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.platformWorkloadScan == nil {
		s.error(w, http.StatusServiceUnavailable, "platform not initialized")
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
	providers, err := parseWorkloadProviders(queryCSVValues(r, "provider"))
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	targets, err := s.platformWorkloadScan.PrioritizeTargets(r.Context(), workloadscan.PrioritizationOptions{
		Providers:       providers,
		IncludeDeferred: includeDeferred,
		Limit:           limit,
		Now:             currentUTC,
	})
	if err != nil {
		switch {
		case errors.Is(err, errPlatformWorkloadScanStateUnavailable):
			s.error(w, http.StatusInternalServerError, "workload scan state unavailable")
		case errors.Is(err, errPlatformWorkloadScanPrioritizeFailed):
			s.error(w, http.StatusInternalServerError, "failed to prioritize workload scan targets")
		case errors.Is(err, graph.ErrStoreUnavailable):
			s.errorFromErr(w, err)
		default:
			s.errorFromErr(w, err)
		}
		return
	}
	s.json(w, http.StatusOK, platformWorkloadScanTargetCollection{
		GeneratedAt: time.Now().UTC(),
		Count:       len(targets),
		Targets:     targets,
	})
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
