package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/writer/cerebro/internal/scanaudit"
)

type platformScanAuditCollection struct {
	GeneratedAt time.Time          `json:"generated_at"`
	Count       int                `json:"count"`
	Records     []scanaudit.Record `json:"records"`
}

type platformScanAuditUnifiedFindingCollection struct {
	GeneratedAt time.Time                  `json:"generated_at"`
	Count       int                        `json:"count"`
	Findings    []scanaudit.UnifiedFinding `json:"findings"`
}

func (s *Server) requireGlobalPlatformScanAuditAccess(w http.ResponseWriter, r *http.Request) bool {
	if !requestUsesTenantScope(r.Context()) {
		return true
	}
	s.error(w, http.StatusForbidden, "platform scan audit is not available in tenant scope")
	return false
}

func (s *Server) listPlatformScanAudit(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.platformScanAudit == nil {
		s.error(w, http.StatusInternalServerError, "platform scan audit store not configured")
		return
	}
	if !s.requireGlobalPlatformScanAuditAccess(w, r) {
		return
	}
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			s.error(w, http.StatusBadRequest, "limit must be between 1 and 200")
			return
		}
		limit = parsed
	}
	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			s.error(w, http.StatusBadRequest, "offset must be >= 0")
			return
		}
		offset = parsed
	}
	records, err := s.platformScanAudit.ListRecords(r.Context(), scanaudit.ListOptions{
		Namespaces:         queryCSVValues(r, "namespace"),
		Statuses:           queryCSVValues(r, "status"),
		ExcludeStatuses:    queryCSVValues(r, "exclude_status"),
		Limit:              limit,
		Offset:             offset,
		OrderBySubmittedAt: strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("order")), "submitted"),
	})
	if err != nil {
		switch {
		case errors.Is(err, errPlatformScanAuditStoreNotConfigured):
			s.error(w, http.StatusInternalServerError, "platform scan audit store not configured")
		case errors.Is(err, errPlatformScanAuditStoreUnavailable):
			s.error(w, http.StatusInternalServerError, "platform scan audit store unavailable")
		default:
			s.errorFromErr(w, err)
		}
		return
	}
	s.json(w, http.StatusOK, platformScanAuditCollection{
		GeneratedAt: time.Now().UTC(),
		Count:       len(records),
		Records:     records,
	})
}

func (s *Server) getPlatformScanAudit(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.platformScanAudit == nil {
		s.error(w, http.StatusInternalServerError, "platform scan audit store not configured")
		return
	}
	if !s.requireGlobalPlatformScanAuditAccess(w, r) {
		return
	}
	namespace := strings.TrimSpace(chi.URLParam(r, "namespace"))
	runID := strings.TrimSpace(chi.URLParam(r, "run_id"))
	if namespace == "" {
		s.error(w, http.StatusBadRequest, "namespace is required")
		return
	}
	if runID == "" {
		s.error(w, http.StatusBadRequest, "run id is required")
		return
	}
	record, ok, err := s.platformScanAudit.GetRecord(r.Context(), namespace, runID)
	if err != nil {
		switch {
		case errors.Is(err, errPlatformScanAuditStoreNotConfigured):
			s.error(w, http.StatusInternalServerError, "platform scan audit store not configured")
		case errors.Is(err, errPlatformScanAuditStoreUnavailable):
			s.error(w, http.StatusInternalServerError, "platform scan audit store unavailable")
		default:
			s.errorFromErr(w, err)
		}
		return
	}
	if !ok || record == nil {
		s.error(w, http.StatusNotFound, "scan audit record not found")
		return
	}
	s.json(w, http.StatusOK, record)
}

func (s *Server) listPlatformScanAuditFindings(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.platformScanAudit == nil {
		s.error(w, http.StatusInternalServerError, "platform scan audit store not configured")
		return
	}
	if !s.requireGlobalPlatformScanAuditAccess(w, r) {
		return
	}
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			s.error(w, http.StatusBadRequest, "limit must be between 1 and 200")
			return
		}
		limit = parsed
	}
	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			s.error(w, http.StatusBadRequest, "offset must be >= 0")
			return
		}
		offset = parsed
	}
	findings, err := s.platformScanAudit.ListUnifiedFindings(r.Context(), scanaudit.UnifiedFindingListOptions{
		Namespaces: queryCSVValues(r, "namespace"),
		Severities: queryCSVValues(r, "severity"),
		Kinds:      queryCSVValues(r, "kind"),
		Limit:      limit,
		Offset:     offset,
	})
	if err != nil {
		switch {
		case errors.Is(err, errPlatformScanAuditStoreNotConfigured):
			s.error(w, http.StatusInternalServerError, "platform scan audit store not configured")
		case errors.Is(err, errPlatformScanAuditStoreUnavailable):
			s.error(w, http.StatusInternalServerError, "platform scan audit store unavailable")
		default:
			s.errorFromErr(w, err)
		}
		return
	}
	s.json(w, http.StatusOK, platformScanAuditUnifiedFindingCollection{
		GeneratedAt: time.Now().UTC(),
		Count:       len(findings),
		Findings:    findings,
	})
}

func (s *Server) exportPlatformScanAudit(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.platformScanAudit == nil {
		s.error(w, http.StatusInternalServerError, "platform scan audit store not configured")
		return
	}
	if !s.requireGlobalPlatformScanAuditAccess(w, r) {
		return
	}
	namespace := strings.TrimSpace(chi.URLParam(r, "namespace"))
	runID := strings.TrimSpace(chi.URLParam(r, "run_id"))
	if namespace == "" {
		s.error(w, http.StatusBadRequest, "namespace is required")
		return
	}
	if runID == "" {
		s.error(w, http.StatusBadRequest, "run id is required")
		return
	}
	pkg, err := s.platformScanAudit.ExportRecord(r.Context(), namespace, runID)
	if err != nil {
		switch {
		case errors.Is(err, errPlatformScanAuditStoreNotConfigured):
			s.error(w, http.StatusInternalServerError, "platform scan audit store not configured")
		case errors.Is(err, errPlatformScanAuditStoreUnavailable):
			s.error(w, http.StatusInternalServerError, "platform scan audit store unavailable")
		default:
			s.errorFromErr(w, err)
		}
		return
	}
	zipBytes, err := scanaudit.RenderExportPackageZIP(*pkg)
	if err != nil {
		s.error(w, http.StatusInternalServerError, fmt.Sprintf("failed to render scan audit package: %v", err))
		return
	}
	filename := scanaudit.ExportPackageFilename(pkg.Record, time.Now().UTC())
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(zipBytes); err != nil { // #nosec G705 -- payload is server-generated ZIP bytes
		if s.app != nil && s.app.Logger != nil {
			s.app.Logger.Warn("failed to stream scan audit package", "namespace", namespace, "run_id", runID, "error", err)
		}
	}
}
