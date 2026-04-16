package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	reports "github.com/writer/cerebro/internal/graph/reports"
)

func (s *Server) listPlatformIntelligenceReports(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, reports.ReportCatalogSnapshot(time.Now().UTC()))
}

func (s *Server) getPlatformIntelligenceReport(w http.ResponseWriter, r *http.Request) {
	reportID := strings.TrimSpace(chi.URLParam(r, "id"))
	if reportID == "" {
		s.error(w, http.StatusBadRequest, "report id required")
		return
	}
	report, ok := reports.GetReportDefinition(reportID)
	if !ok {
		s.error(w, http.StatusNotFound, "report definition not found")
		return
	}
	s.json(w, http.StatusOK, report)
}

func (s *Server) listPlatformIntelligenceMeasures(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, reports.ReportMeasureCatalogSnapshot(time.Now().UTC()))
}

func (s *Server) listPlatformIntelligenceChecks(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, reports.ReportCheckCatalogSnapshot(time.Now().UTC()))
}

func (s *Server) listPlatformIntelligenceSectionEnvelopes(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, reports.ReportSectionEnvelopeCatalogSnapshot(time.Now().UTC()))
}

func (s *Server) getPlatformIntelligenceSectionEnvelope(w http.ResponseWriter, r *http.Request) {
	envelopeID := strings.TrimSpace(chi.URLParam(r, "envelope_id"))
	if envelopeID == "" {
		s.error(w, http.StatusBadRequest, "envelope id required")
		return
	}
	envelope, ok := reports.GetReportSectionEnvelopeDefinition(envelopeID)
	if !ok {
		s.error(w, http.StatusNotFound, "section envelope definition not found")
		return
	}
	s.json(w, http.StatusOK, envelope)
}

func (s *Server) listPlatformIntelligenceSectionFragments(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, reports.ReportSectionFragmentCatalogSnapshot(time.Now().UTC()))
}

func (s *Server) getPlatformIntelligenceSectionFragment(w http.ResponseWriter, r *http.Request) {
	fragmentID := strings.TrimSpace(chi.URLParam(r, "fragment_id"))
	if fragmentID == "" {
		s.error(w, http.StatusBadRequest, "fragment id required")
		return
	}
	fragment, ok := reports.GetReportSectionFragmentDefinition(fragmentID)
	if !ok {
		s.error(w, http.StatusNotFound, "section fragment definition not found")
		return
	}
	s.json(w, http.StatusOK, fragment)
}

func (s *Server) listPlatformIntelligenceBenchmarkPacks(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, reports.BenchmarkPackCatalogSnapshot(time.Now().UTC()))
}

func (s *Server) getPlatformIntelligenceBenchmarkPack(w http.ResponseWriter, r *http.Request) {
	packID := strings.TrimSpace(chi.URLParam(r, "pack_id"))
	if packID == "" {
		s.error(w, http.StatusBadRequest, "benchmark pack id required")
		return
	}
	pack, ok := reports.GetBenchmarkPack(packID)
	if !ok {
		s.error(w, http.StatusNotFound, "benchmark pack not found")
		return
	}
	s.json(w, http.StatusOK, pack)
}

func (s *Server) platformReportHandler(reportID string) (http.HandlerFunc, bool) {
	if handler, ok := s.platformReportHandlers[reportID]; ok {
		return handler, true
	}
	return nil, false
}

func reportParameterValuesToQuery(values []reports.ReportParameterValue) (url.Values, error) {
	query := url.Values{}
	for _, value := range values {
		encoded, err := value.QueryValue()
		if err != nil {
			return nil, err
		}
		query.Set(strings.TrimSpace(value.Name), encoded)
	}
	return query, nil
}

func decodePlatformAPIError(payload []byte) string {
	var apiErr APIError
	if err := json.Unmarshal(payload, &apiErr); err == nil {
		return strings.TrimSpace(apiErr.Error)
	}
	return ""
}
