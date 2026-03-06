package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/evalops/cerebro/internal/compliance"
	"github.com/evalops/cerebro/internal/findings"
	"github.com/evalops/cerebro/internal/metrics"
	"github.com/evalops/cerebro/internal/snowflake"
)

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	pagination := ParsePagination(r, 100, 1000)

	filter := findings.FindingFilter{
		Severity:   r.URL.Query().Get("severity"),
		Status:     r.URL.Query().Get("status"),
		PolicyID:   r.URL.Query().Get("policy_id"),
		SignalType: r.URL.Query().Get("signal_type"),
		Domain:     r.URL.Query().Get("domain"),
		Limit:      pagination.Limit,
		Offset:     pagination.Offset,
	}

	total := s.app.Findings.Count(filter)
	list := s.app.Findings.List(filter)
	paginationResp := BuildPaginationResponse(int64(total), pagination, len(list))

	s.json(w, http.StatusOK, map[string]interface{}{
		"findings":   list,
		"count":      len(list),
		"pagination": paginationResp,
	})
}

func (s *Server) findingsStats(w http.ResponseWriter, r *http.Request) {
	stats := s.app.Findings.Stats()
	s.json(w, http.StatusOK, stats)
}

func (s *Server) signalsDashboard(w http.ResponseWriter, r *http.Request) {
	stats := s.app.Findings.Stats()
	open := s.app.Findings.Count(findings.FindingFilter{Status: "OPEN"})
	snoozed := s.app.Findings.Count(findings.FindingFilter{Status: "SNOOZED"})
	recent := s.app.Findings.List(findings.FindingFilter{Limit: 25})

	s.json(w, http.StatusOK, map[string]interface{}{
		"summary": map[string]interface{}{
			"total_signals":   stats.Total,
			"open_signals":    open,
			"snoozed_signals": snoozed,
		},
		"stats":          stats,
		"recent_signals": recent,
		"count":          len(recent),
	})
}

func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	f, ok := s.app.Findings.Get(id)
	if !ok {
		s.error(w, http.StatusNotFound, "finding not found")
		return
	}
	s.json(w, http.StatusOK, f)
}

func (s *Server) scanFindings(w http.ResponseWriter, r *http.Request) {
	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	var req struct {
		Table string `json:"table"`
		Limit int    `json:"limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Limit == 0 {
		req.Limit = 100
	}

	assets, err := s.app.Snowflake.GetAssets(r.Context(), req.Table, snowflake.AssetFilter{Limit: req.Limit})
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	result := s.app.Scanner.ScanAssets(r.Context(), assets)

	// Persist findings
	for _, f := range result.Findings {
		s.app.Findings.Upsert(r.Context(), f)
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"scanned":    result.Scanned,
		"violations": result.Violations,
		"duration":   result.Duration.String(),
		"findings":   result.Findings,
	})
}

func (s *Server) resolveFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if s.app.Findings.Resolve(id) {
		s.json(w, http.StatusOK, map[string]string{"status": "resolved"})
	} else {
		s.error(w, http.StatusNotFound, "finding not found")
	}
}

func (s *Server) suppressFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if s.app.Findings.Suppress(id) {
		s.json(w, http.StatusOK, map[string]string{"status": "suppressed"})
	} else {
		s.error(w, http.StatusNotFound, "finding not found")
	}
}

func (s *Server) exportFindings(w http.ResponseWriter, r *http.Request) {
	filter := findings.FindingFilter{
		Severity:   r.URL.Query().Get("severity"),
		Status:     r.URL.Query().Get("status"),
		PolicyID:   r.URL.Query().Get("policy_id"),
		SignalType: r.URL.Query().Get("signal_type"),
		Domain:     r.URL.Query().Get("domain"),
	}
	list := s.app.Findings.List(filter)

	// Enrich findings with cloud URLs, tags, etc.
	for _, f := range list {
		findings.EnrichFinding(f)
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "csv"
	}

	var data []byte
	var err error
	var contentType string

	switch format {
	case "json":
		exporter := findings.NewJSONExporter(r.URL.Query().Get("pretty") == "true")
		data, err = exporter.Export(list)
		contentType = "application/json"
	case "csv":
		exporter := findings.NewCSVExporter()
		data, err = exporter.Export(list)
		contentType = "text/csv"
	default:
		s.error(w, http.StatusBadRequest, "invalid format, expected csv or json")
		return
	}

	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=findings.%s", format))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data) // #nosec G705 -- payload is generated server-side exporter output (CSV/JSON)
}

func (s *Server) assignFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Assignee string `json:"assignee"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	mgr := findings.NewIssueManager(s.app.Findings)
	if err := mgr.Assign(id, req.Assignee); err != nil {
		if errors.Is(err, findings.ErrIssueNotFound) {
			s.error(w, http.StatusNotFound, "finding not found")
		} else {
			s.error(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "assigned", "assignee": req.Assignee})
}

func (s *Server) setFindingDueDate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		DueAt time.Time `json:"due_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	mgr := findings.NewIssueManager(s.app.Findings)
	if err := mgr.SetDueDate(id, req.DueAt); err != nil {
		if errors.Is(err, findings.ErrIssueNotFound) {
			s.error(w, http.StatusNotFound, "finding not found")
		} else {
			s.error(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) addFindingNote(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	mgr := findings.NewIssueManager(s.app.Findings)
	if err := mgr.AddNote(id, req.Note); err != nil {
		if errors.Is(err, findings.ErrIssueNotFound) {
			s.error(w, http.StatusNotFound, "finding not found")
		} else {
			s.error(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "note added"})
}

func (s *Server) linkFindingTicket(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		URL        string `json:"url"`
		Name       string `json:"name"`
		ExternalID string `json:"external_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	mgr := findings.NewIssueManager(s.app.Findings)
	if err := mgr.LinkTicket(id, req.URL, req.Name, req.ExternalID); err != nil {
		if errors.Is(err, findings.ErrIssueNotFound) {
			s.error(w, http.StatusNotFound, "finding not found")
		} else {
			s.error(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "ticket linked"})
}

// Reporting endpoints

func (s *Server) executiveSummary(w http.ResponseWriter, r *http.Request) {
	reporter := findings.NewComplianceReporter(s.app.Findings, s.app.Policy)
	summary := reporter.GenerateExecutiveSummary()
	s.json(w, http.StatusOK, summary)
}

func (s *Server) riskSummary(w http.ResponseWriter, r *http.Request) {
	reporter := findings.NewComplianceReporter(s.app.Findings, s.app.Policy)
	risks := reporter.GenerateRiskSummary()
	s.json(w, http.StatusOK, map[string]interface{}{"risks": risks, "count": len(risks)})
}

func (s *Server) frameworkComplianceReport(w http.ResponseWriter, r *http.Request) {
	framework := chi.URLParam(r, "framework")
	reporter := findings.NewComplianceReporter(s.app.Findings, s.app.Policy)
	report := reporter.GenerateFrameworkReport(framework)
	s.json(w, http.StatusOK, report)
}

// Compliance endpoints

func (s *Server) listFrameworks(w http.ResponseWriter, r *http.Request) {
	frameworks := compliance.GetFrameworks()
	s.json(w, http.StatusOK, map[string]interface{}{"frameworks": frameworks, "count": len(frameworks)})
}

func (s *Server) getFramework(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	f := compliance.GetFramework(id)
	if f == nil {
		s.error(w, http.StatusNotFound, "framework not found")
		return
	}
	s.json(w, http.StatusOK, f)
}

func (s *Server) generateComplianceReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	framework := compliance.GetFramework(id)
	if framework == nil {
		s.error(w, http.StatusNotFound, "framework not found")
		return
	}

	// Generate report based on current findings
	openFindingsByPolicy := s.openFindingsByPolicy()

	report := compliance.ComplianceReport{
		FrameworkID:   framework.ID,
		FrameworkName: framework.Name,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Summary: compliance.ComplianceSummary{
			TotalControls: len(framework.Controls),
		},
		Controls: make([]compliance.ControlStatus, len(framework.Controls)),
	}

	// Build evidence map for failing controls
	type Evidence struct {
		Resource   string `json:"resource"`
		FindingID  string `json:"finding_id"`
		Severity   string `json:"severity"`
		DetectedAt string `json:"detected_at"`
	}
	controlEvidence := make(map[string][]Evidence)

	passing := 0
	totalFindings := 0
	for i, ctrl := range framework.Controls {
		// Count findings for this control and gather evidence
		failCount := 0
		var evidence []Evidence
		for _, policyID := range ctrl.PolicyIDs {
			if count, ok := openFindingsByPolicy[policyID]; ok {
				failCount += count
			}
			// Get sample findings for evidence (limit to 5 per policy)
			policyFindings := s.app.Findings.List(findings.FindingFilter{PolicyID: policyID, Status: "open"})
			for j, f := range policyFindings {
				if j >= 5 {
					break
				}
				resourceName := f.ResourceID
				if resourceName == "" {
					if arn, ok := f.Resource["arn"].(string); ok {
						resourceName = arn
					} else if name, ok := f.Resource["name"].(string); ok {
						resourceName = name
					}
				}
				evidence = append(evidence, Evidence{
					Resource:   resourceName,
					FindingID:  f.ID,
					Severity:   f.Severity,
					DetectedAt: f.FirstSeen.Format(time.RFC3339),
				})
			}
		}
		totalFindings += failCount

		status := "passing"
		if failCount > 0 {
			status = "failing"
			if len(evidence) > 10 {
				evidence = evidence[:10] // Limit evidence per control
			}
			controlEvidence[ctrl.ID] = evidence
		} else {
			passing++
		}

		report.Controls[i] = compliance.ControlStatus{
			ControlID: ctrl.ID,
			Status:    status,
			FailCount: failCount,
		}
	}

	report.Summary.PassingControls = passing
	report.Summary.FailingControls = len(framework.Controls) - passing
	if len(framework.Controls) > 0 {
		report.Summary.ComplianceScore = float64(passing) / float64(len(framework.Controls)) * 100
	}

	// Calculate weighted score based on control severity
	failingControlIDs := make(map[string]bool)
	for _, ctrl := range report.Controls {
		if ctrl.Status == "failing" {
			failingControlIDs[ctrl.ControlID] = true
		}
	}
	report.Summary.WeightedScore, _, _ = compliance.CalculateWeightedScore(framework.Controls, failingControlIDs)

	// Return enhanced response with evidence
	var dataWarning string
	response := map[string]interface{}{
		"report":         report,
		"total_findings": totalFindings,
		"evidence":       controlEvidence,
	}
	if dataWarning != "" {
		response["data_warning"] = dataWarning
	}

	s.json(w, http.StatusOK, response)
}

// Pre-audit health check - predicts audit outcome
func (s *Server) preAuditCheck(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	framework := compliance.GetFramework(id)
	if framework == nil {
		s.error(w, http.StatusNotFound, "framework not found")
		return
	}

	openFindingsByPolicy := s.openFindingsByPolicy()

	type ControlCheck struct {
		ControlID   string   `json:"control_id"`
		Title       string   `json:"title"`
		Status      string   `json:"status"` // passing, failing, at_risk
		Issues      []string `json:"issues,omitempty"`
		Findings    []string `json:"findings,omitempty"`
		Remediation string   `json:"remediation,omitempty"`
	}

	checks := make([]ControlCheck, 0, len(framework.Controls))
	passing, failing, atRisk := 0, 0, 0

	for _, ctrl := range framework.Controls {
		check := ControlCheck{
			ControlID: ctrl.ID,
			Title:     ctrl.Title,
			Status:    "passing",
		}

		for _, policyID := range ctrl.PolicyIDs {
			if count, ok := openFindingsByPolicy[policyID]; ok && count > 0 {
				check.Status = "failing"
				check.Issues = append(check.Issues, fmt.Sprintf("%d findings for policy %s", count, policyID))
				check.Findings = append(check.Findings, policyID)
			}
		}

		switch check.Status {
		case "passing":
			passing++
		case "failing":
			failing++
			check.Remediation = "Review and remediate findings before audit"
		case "at_risk":
			atRisk++
		}

		checks = append(checks, check)
	}

	// Determine estimated outcome
	outcome := "PASS"
	if failing > 0 {
		outcome = fmt.Sprintf("PASS WITH %d EXCEPTIONS", failing)
	}
	if len(framework.Controls) > 0 && float64(failing)/float64(len(framework.Controls)) > 0.2 {
		outcome = "AT RISK - RECOMMEND POSTPONING"
	}

	score := 0.0
	if len(framework.Controls) > 0 {
		score = float64(passing) / float64(len(framework.Controls)) * 100
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"framework_id":      framework.ID,
		"framework_name":    framework.Name,
		"generated_at":      time.Now().UTC().Format(time.RFC3339),
		"estimated_outcome": outcome,
		"summary": map[string]interface{}{
			"total_controls":   len(framework.Controls),
			"passing":          passing,
			"failing":          failing,
			"at_risk":          atRisk,
			"compliance_score": fmt.Sprintf("%.1f%%", score),
		},
		"controls":        checks,
		"recommendations": s.generateAuditRecommendations(failing, atRisk, len(framework.Controls)),
	})
}

func (s *Server) generateAuditRecommendations(failing, atRisk, total int) []string {
	var recs []string

	if failing > 0 {
		recs = append(recs, fmt.Sprintf("Remediate %d failing controls before audit", failing))
	}
	if atRisk > 0 {
		recs = append(recs, fmt.Sprintf("Review %d at-risk controls", atRisk))
	}
	if failing == 0 && atRisk == 0 {
		recs = append(recs, "All controls passing - ready for audit")
	}
	if total > 0 && float64(failing)/float64(total) > 0.1 {
		recs = append(recs, "Consider postponing audit until critical issues are resolved")
	}

	return recs
}

func (s *Server) openFindingsByPolicy() map[string]int {
	counts := make(map[string]int)
	for _, finding := range s.app.Findings.List(findings.FindingFilter{Status: "OPEN"}) {
		if finding.PolicyID == "" {
			continue
		}
		counts[finding.PolicyID]++
	}
	return counts
}

// Export audit package with evidence
func (s *Server) exportAuditPackage(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	framework := compliance.GetFramework(id)
	if framework == nil {
		metrics.RecordComplianceExport(false)
		s.error(w, http.StatusNotFound, "framework not found")
		return
	}

	generatedAt := time.Now().UTC()
	pkg := compliance.BuildAuditPackage(framework, s.openFindingsByPolicy(), generatedAt)

	zipBytes, err := compliance.RenderAuditPackageZIP(pkg)
	if err != nil {
		metrics.RecordComplianceExport(false)
		s.error(w, http.StatusInternalServerError, fmt.Sprintf("failed to render audit package: %v", err))
		return
	}

	filename := compliance.AuditPackageFilename(framework.ID, generatedAt)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(zipBytes); err != nil { // #nosec G705 -- payload is server-generated ZIP bytes
		metrics.RecordComplianceExport(false)
		s.app.Logger.Warn("failed to stream audit package", "error", err, "framework_id", framework.ID)
		return
	}
	metrics.RecordComplianceExport(true)
}
