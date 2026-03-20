package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/metrics"
)

var errScanFindingsMissingTables = errors.New("scan request missing tables")

type scanFindingsRequest struct {
	Table  string   `json:"table"`
	Tables []string `json:"tables"`
	Limit  int      `json:"limit"`
}

type scanFindingsTableResult struct {
	Table      string `json:"table"`
	Scanned    int64  `json:"scanned"`
	Violations int64  `json:"violations"`
	Duration   string `json:"duration"`
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	store := s.findingsCompliance.FindingsStore(r.Context())
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

	total := store.Count(filter)
	list := store.List(filter)
	paginationResp := BuildPaginationResponse(int64(total), pagination, len(list))

	s.json(w, http.StatusOK, map[string]interface{}{
		"findings":   list,
		"count":      len(list),
		"pagination": paginationResp,
	})
}

func (s *Server) findingsStats(w http.ResponseWriter, r *http.Request) {
	store := s.findingsCompliance.FindingsStore(r.Context())
	stats := store.Stats()
	s.json(w, http.StatusOK, stats)
}

func (s *Server) signalsDashboard(w http.ResponseWriter, r *http.Request) {
	store := s.findingsCompliance.FindingsStore(r.Context())
	stats := store.Stats()
	open := store.Count(findings.FindingFilter{Status: "OPEN"})
	snoozed := store.Count(findings.FindingFilter{Status: "SNOOZED"})
	recent := store.List(findings.FindingFilter{Limit: 25})

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
	store := s.findingsCompliance.FindingsStore(r.Context())
	id := chi.URLParam(r, "id")
	f, ok := store.Get(id)
	if !ok {
		s.error(w, http.StatusNotFound, "finding not found")
		return
	}
	s.json(w, http.StatusOK, f)
}

func (s *Server) deleteFinding(w http.ResponseWriter, r *http.Request) {
	store := s.findingsCompliance.FindingsStore(r.Context())
	id := chi.URLParam(r, "id")
	if strings.TrimSpace(id) == "" {
		s.error(w, http.StatusBadRequest, "finding id required")
		return
	}

	now := time.Now().UTC()
	err := store.Update(id, func(f *findings.Finding) error {
		f.Status = "DELETED"
		f.ResourceStatus = "Deleted"
		f.Resolution = "deleted via api"
		f.UpdatedAt = now
		f.StatusChangedAt = &now
		f.ResolvedAt = &now
		return nil
	})
	if errors.Is(err, findings.ErrIssueNotFound) {
		s.error(w, http.StatusNotFound, "finding not found")
		return
	}
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	s.json(w, http.StatusOK, map[string]string{
		"status": "deleted",
		"id":     id,
	})
}

func (s *Server) scanFindings(w http.ResponseWriter, r *http.Request) {
	req, tables, err := decodeScanFindingsRequest(r)
	if err != nil {
		if errors.Is(err, errScanFindingsMissingTables) {
			s.error(w, http.StatusBadRequest, "table or tables required")
			return
		}
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	result, err := s.findingsCompliance.ScanFindings(r.Context(), tables, req.Limit)
	if errors.Is(err, errFindingsComplianceScanUnavailable) {
		s.error(w, http.StatusServiceUnavailable, "findings scan not configured")
		return
	}
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"scanned":    result.Scanned,
		"violations": result.Violations,
		"duration":   result.Duration,
		"findings":   result.Findings,
		"tables":     result.Tables,
	})
}

func decodeScanFindingsRequest(r *http.Request) (scanFindingsRequest, []string, error) {
	var req scanFindingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return scanFindingsRequest{}, nil, err
	}

	if req.Limit <= 0 {
		req.Limit = 100
	}

	tables := normalizeScanRequestTables(req.Table, req.Tables)
	if len(tables) == 0 {
		return scanFindingsRequest{}, nil, errScanFindingsMissingTables
	}

	return req, tables, nil
}

func normalizeScanRequestTables(table string, tables []string) []string {
	rawTables := append([]string(nil), tables...)
	if strings.TrimSpace(table) != "" {
		rawTables = append(rawTables, table)
	}

	normalized := make([]string, 0, len(rawTables))
	seen := make(map[string]struct{}, len(rawTables))
	for _, tableName := range rawTables {
		candidate := strings.TrimSpace(strings.ToLower(tableName))
		if candidate == "" {
			continue
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		normalized = append(normalized, candidate)
	}

	return normalized
}

func (s *Server) resolveFinding(w http.ResponseWriter, r *http.Request) {
	store := s.findingsCompliance.FindingsStore(r.Context())
	id := chi.URLParam(r, "id")
	if store.Resolve(id) {
		s.json(w, http.StatusOK, map[string]string{"status": "resolved"})
	} else {
		s.error(w, http.StatusNotFound, "finding not found")
	}
}

func (s *Server) suppressFinding(w http.ResponseWriter, r *http.Request) {
	store := s.findingsCompliance.FindingsStore(r.Context())
	id := chi.URLParam(r, "id")
	if store.Suppress(id) {
		s.json(w, http.StatusOK, map[string]string{"status": "suppressed"})
	} else {
		s.error(w, http.StatusNotFound, "finding not found")
	}
}

func (s *Server) exportFindings(w http.ResponseWriter, r *http.Request) {
	store := s.findingsCompliance.FindingsStore(r.Context())
	filter := findings.FindingFilter{
		Severity:   r.URL.Query().Get("severity"),
		Status:     r.URL.Query().Get("status"),
		PolicyID:   r.URL.Query().Get("policy_id"),
		SignalType: r.URL.Query().Get("signal_type"),
		Domain:     r.URL.Query().Get("domain"),
	}
	list := store.List(filter)

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
		s.errorFromErr(w, err)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=findings.%s", format))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data) // #nosec G705 -- payload is generated server-side exporter output (CSV/JSON)
}

func (s *Server) assignFinding(w http.ResponseWriter, r *http.Request) {
	store := s.findingsCompliance.FindingsStore(r.Context())
	id := chi.URLParam(r, "id")
	var req struct {
		Assignee string `json:"assignee"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	mgr := findings.NewIssueManager(store)
	if err := mgr.Assign(id, req.Assignee); err != nil {
		if errors.Is(err, findings.ErrIssueNotFound) {
			s.error(w, http.StatusNotFound, "finding not found")
		} else {
			s.errorFromErr(w, err)
		}
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "assigned", "assignee": req.Assignee})
}

func (s *Server) setFindingDueDate(w http.ResponseWriter, r *http.Request) {
	store := s.findingsCompliance.FindingsStore(r.Context())
	id := chi.URLParam(r, "id")
	var req struct {
		DueAt time.Time `json:"due_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	mgr := findings.NewIssueManager(store)
	if err := mgr.SetDueDate(id, req.DueAt); err != nil {
		if errors.Is(err, findings.ErrIssueNotFound) {
			s.error(w, http.StatusNotFound, "finding not found")
		} else {
			s.errorFromErr(w, err)
		}
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) addFindingNote(w http.ResponseWriter, r *http.Request) {
	store := s.findingsCompliance.FindingsStore(r.Context())
	id := chi.URLParam(r, "id")
	var req struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	mgr := findings.NewIssueManager(store)
	if err := mgr.AddNote(id, req.Note); err != nil {
		if errors.Is(err, findings.ErrIssueNotFound) {
			s.error(w, http.StatusNotFound, "finding not found")
		} else {
			s.errorFromErr(w, err)
		}
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "note added"})
}

func (s *Server) linkFindingTicket(w http.ResponseWriter, r *http.Request) {
	store := s.findingsCompliance.FindingsStore(r.Context())
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

	mgr := findings.NewIssueManager(store)
	if err := mgr.LinkTicket(id, req.URL, req.Name, req.ExternalID); err != nil {
		if errors.Is(err, findings.ErrIssueNotFound) {
			s.error(w, http.StatusNotFound, "finding not found")
		} else {
			s.errorFromErr(w, err)
		}
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "ticket linked"})
}

// Reporting endpoints

func (s *Server) executiveSummary(w http.ResponseWriter, r *http.Request) {
	reporter := s.findingsCompliance.Reporter(r.Context())
	summary := reporter.GenerateExecutiveSummary()
	s.json(w, http.StatusOK, summary)
}

func (s *Server) riskSummary(w http.ResponseWriter, r *http.Request) {
	reporter := s.findingsCompliance.Reporter(r.Context())
	risks := reporter.GenerateRiskSummary()
	s.json(w, http.StatusOK, map[string]interface{}{"risks": risks, "count": len(risks)})
}

func (s *Server) frameworkComplianceReport(w http.ResponseWriter, r *http.Request) {
	framework := chi.URLParam(r, "framework")
	definition := compliance.GetFramework(framework)
	if definition == nil {
		reporter := s.findingsCompliance.Reporter(r.Context())
		report := reporter.GenerateFrameworkReport(framework)
		s.json(w, http.StatusOK, report)
		return
	}

	opts, err := parseComplianceEvaluationOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	report := s.findingsCompliance.EvaluateFramework(r.Context(), definition, opts)
	legacy := map[string]interface{}{
		"framework":             definition.Name,
		"total_controls":        report.Summary.TotalControls,
		"assessed_controls":     report.Summary.TotalControls - report.Summary.NotApplicableControls,
		"passing_controls":      report.Summary.PassingControls,
		"failing_controls":      report.Summary.FailingControls + report.Summary.PartialControls,
		"not_assessed_controls": report.Summary.NotApplicableControls,
		"coverage_percent":      report.Summary.ComplianceScore,
		"compliance_percent":    report.Summary.ComplianceScore,
		"control_status":        make(map[string]map[string]interface{}, len(report.Controls)),
		"findings_by_control":   make(map[string][]string, len(report.Controls)),
	}
	for _, ctrl := range report.Controls {
		status := "NOT_ASSESSED"
		switch ctrl.Status {
		case compliance.ControlStatePassing:
			status = "PASS"
		case compliance.ControlStateFailing, compliance.ControlStatePartial:
			status = "FAIL"
		}
		legacy["control_status"].(map[string]map[string]interface{})[ctrl.ControlID] = map[string]interface{}{
			"control_id":   ctrl.ControlID,
			"control_name": ctrl.Title,
			"status":       status,
			"findings":     ctrl.FailCount,
			"policy_ids":   ctrl.PolicyIDs,
		}
		findingsByControl := make([]string, 0)
		for _, item := range ctrl.Evidence {
			if item.PolicyID != "" && item.Status == compliance.ControlStateFailing {
				findingsByControl = append(findingsByControl, item.PolicyID)
			}
		}
		legacy["findings_by_control"].(map[string][]string)[ctrl.ControlID] = findingsByControl
	}
	s.json(w, http.StatusOK, legacy)
}

// Compliance endpoints

type complianceFrameworkStatusControl struct {
	ControlID        string                            `json:"control_id"`
	Title            string                            `json:"title,omitempty"`
	Description      string                            `json:"description,omitempty"`
	Severity         compliance.ControlSeverity        `json:"severity,omitempty"`
	Status           string                            `json:"status"`
	PassCount        int                               `json:"pass_count"`
	FailCount        int                               `json:"fail_count"`
	TotalAssets      int                               `json:"total_assets"`
	EvaluationSource string                            `json:"evaluation_source,omitempty"`
	LastEvaluated    string                            `json:"last_evaluated,omitempty"`
	PolicyIDs        []string                          `json:"policy_ids,omitempty"`
	GraphQueries     []compliance.GraphQueryDefinition `json:"graph_queries,omitempty"`
}

type complianceFrameworkStatusResponse struct {
	FrameworkID   string                             `json:"framework_id"`
	FrameworkName string                             `json:"framework_name"`
	Version       string                             `json:"version,omitempty"`
	GeneratedAt   string                             `json:"generated_at"`
	ValidAt       string                             `json:"valid_at,omitempty"`
	RecordedAt    string                             `json:"recorded_at,omitempty"`
	Summary       compliance.ComplianceSummary       `json:"summary"`
	Controls      []complianceFrameworkStatusControl `json:"controls"`
	TotalFindings int                                `json:"total_findings"`
}

type complianceControlDetailResponse struct {
	FrameworkID   string                   `json:"framework_id"`
	FrameworkName string                   `json:"framework_name"`
	Version       string                   `json:"version,omitempty"`
	GeneratedAt   string                   `json:"generated_at"`
	ValidAt       string                   `json:"valid_at,omitempty"`
	RecordedAt    string                   `json:"recorded_at,omitempty"`
	Control       compliance.Control       `json:"control"`
	Status        compliance.ControlStatus `json:"status"`
}

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

func (s *Server) getFrameworkStatus(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	framework := compliance.GetFramework(id)
	if framework == nil {
		s.error(w, http.StatusNotFound, "framework not found")
		return
	}

	opts, err := parseComplianceEvaluationOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	report := s.findingsCompliance.EvaluateFramework(r.Context(), framework, opts)

	s.json(w, http.StatusOK, complianceFrameworkStatusResponse{
		FrameworkID:   framework.ID,
		FrameworkName: framework.Name,
		Version:       framework.Version,
		GeneratedAt:   report.GeneratedAt,
		ValidAt:       formatOptionalTime(opts.ValidAt),
		RecordedAt:    formatOptionalTime(opts.RecordedAt),
		Summary:       report.Summary,
		Controls:      buildComplianceStatusControls(framework, report),
		TotalFindings: complianceReportFailCount(report),
	})
}

func (s *Server) getFrameworkControl(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	framework := compliance.GetFramework(id)
	if framework == nil {
		s.error(w, http.StatusNotFound, "framework not found")
		return
	}

	controlID := strings.TrimSpace(chi.URLParam(r, "control_id"))
	if controlID == "" {
		s.error(w, http.StatusBadRequest, "control id required")
		return
	}
	control, ok := compliance.GetControl(framework, controlID)
	if !ok {
		s.error(w, http.StatusNotFound, "control not found")
		return
	}

	opts, err := parseComplianceEvaluationOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	report := s.findingsCompliance.EvaluateFramework(r.Context(), framework, opts)
	status, ok := complianceStatusByID(report, controlID)
	if !ok {
		s.error(w, http.StatusNotFound, "control status not found")
		return
	}

	s.json(w, http.StatusOK, complianceControlDetailResponse{
		FrameworkID:   framework.ID,
		FrameworkName: framework.Name,
		Version:       framework.Version,
		GeneratedAt:   report.GeneratedAt,
		ValidAt:       formatOptionalTime(opts.ValidAt),
		RecordedAt:    formatOptionalTime(opts.RecordedAt),
		Control:       control,
		Status:        status,
	})
}

func (s *Server) generateComplianceReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	framework := compliance.GetFramework(id)
	if framework == nil {
		s.error(w, http.StatusNotFound, "framework not found")
		return
	}

	opts, err := parseComplianceEvaluationOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	report := compliance.RedactReportEvidence(s.findingsCompliance.EvaluateFramework(r.Context(), framework, opts))
	totalFindings := 0
	controlEvidence := make(map[string][]compliance.ControlEvidence)
	for _, ctrl := range report.Controls {
		totalFindings += ctrl.FailCount
		if len(ctrl.Evidence) > 0 {
			controlEvidence[ctrl.ControlID] = ctrl.Evidence
		}
	}
	response := map[string]interface{}{
		"report":         report,
		"total_findings": totalFindings,
		"evidence":       controlEvidence,
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

	type ControlCheck struct {
		ControlID   string   `json:"control_id"`
		Title       string   `json:"title"`
		Status      string   `json:"status"` // passing, failing, at_risk
		Issues      []string `json:"issues,omitempty"`
		Findings    []string `json:"findings,omitempty"`
		Remediation string   `json:"remediation,omitempty"`
	}

	checks := make([]ControlCheck, 0, len(framework.Controls))

	opts, err := parseComplianceEvaluationOptions(r)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	report := s.findingsCompliance.EvaluateFramework(r.Context(), framework, opts)
	for _, ctrl := range report.Controls {
		check := ControlCheck{
			ControlID: ctrl.ControlID,
			Title:     ctrl.Title,
			Status:    "passing",
		}
		switch ctrl.Status {
		case compliance.ControlStateFailing:
			check.Status = "failing"
		case compliance.ControlStatePartial, compliance.ControlStateUnknown:
			check.Status = "at_risk"
		case compliance.ControlStateNotApplicable:
			check.Status = "passing"
		}
		for _, item := range ctrl.Evidence {
			if item.Status == compliance.ControlStatePassing {
				continue
			}
			if item.Reason != "" {
				check.Issues = append(check.Issues, item.Reason)
			}
			if item.PolicyID != "" {
				check.Findings = append(check.Findings, item.PolicyID)
			}
		}

		switch ctrl.Status {
		case compliance.ControlStateFailing:
			check.Remediation = "Review and remediate findings before audit"
		case compliance.ControlStatePartial, compliance.ControlStateUnknown:
			check.Remediation = "Collect missing evidence or close ambiguous control gaps before audit"
		}

		checks = append(checks, check)
	}

	passing, failing, atRisk, notApplicable, assessedControls, score := preAuditMetrics(report)

	// Determine estimated outcome
	outcome := "PASS"
	if failing > 0 {
		outcome = fmt.Sprintf("PASS WITH %d EXCEPTIONS", failing)
	}
	if assessedControls > 0 && float64(failing)/float64(assessedControls) > 0.2 {
		outcome = "AT RISK - RECOMMEND POSTPONING"
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"framework_id":      framework.ID,
		"framework_name":    framework.Name,
		"generated_at":      report.GeneratedAt,
		"estimated_outcome": outcome,
		"summary": map[string]interface{}{
			"total_controls":   report.Summary.TotalControls,
			"passing":          passing,
			"failing":          failing,
			"at_risk":          atRisk,
			"not_applicable":   notApplicable,
			"compliance_score": fmt.Sprintf("%.1f%%", score),
		},
		"controls":        checks,
		"recommendations": s.generateAuditRecommendations(failing, atRisk, assessedControls),
	})
}

func preAuditMetrics(report compliance.ComplianceReport) (passing, failing, atRisk, notApplicable, assessedControls int, score float64) {
	passing = report.Summary.PassingControls
	failing = report.Summary.FailingControls
	atRisk = report.Summary.PartialControls
	notApplicable = report.Summary.NotApplicableControls
	assessedControls = report.Summary.TotalControls - notApplicable
	if assessedControls > 0 {
		score = float64(passing) / float64(assessedControls) * 100
	}
	return passing, failing, atRisk, notApplicable, assessedControls, score
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

func openFindingsByPolicy(store findings.FindingStore) map[string]int {
	counts := make(map[string]int)
	if store == nil {
		return counts
	}
	for _, finding := range store.List(findings.FindingFilter{Status: "OPEN"}) {
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

	opts, err := parseComplianceEvaluationOptions(r)
	if err != nil {
		metrics.RecordComplianceExport(false)
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	generatedAt := time.Now().UTC()
	report := s.findingsCompliance.EvaluateFramework(r.Context(), framework, opts)
	if report.GeneratedAt == "" {
		report.GeneratedAt = generatedAt.Format(time.RFC3339)
	}
	pkg := compliance.BuildAuditPackageFromReport(framework, compliance.RedactReportEvidence(report))

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
		s.findingsCompliance.Warn("failed to stream audit package", "error", err, "framework_id", framework.ID)
		return
	}
	metrics.RecordComplianceExport(true)
}

func parseComplianceEvaluationOptions(r *http.Request) (compliance.EvaluationOptions, error) {
	validAt, err := parseOptionalRFC3339Query(r, "valid_at")
	if err != nil {
		return compliance.EvaluationOptions{}, err
	}
	recordedAt, err := parseOptionalRFC3339Query(r, "recorded_at")
	if err != nil {
		return compliance.EvaluationOptions{}, err
	}
	return compliance.EvaluationOptions{
		ValidAt:    validAt,
		RecordedAt: recordedAt,
	}, nil
}

func buildComplianceStatusControls(framework *compliance.Framework, report compliance.ComplianceReport) []complianceFrameworkStatusControl {
	if framework == nil || len(report.Controls) == 0 {
		return nil
	}
	controls := make([]complianceFrameworkStatusControl, 0, len(report.Controls))
	for _, control := range framework.Controls {
		status, ok := complianceStatusByID(report, control.ID)
		if !ok {
			continue
		}
		controls = append(controls, complianceFrameworkStatusControl{
			ControlID:        status.ControlID,
			Title:            status.Title,
			Description:      status.Description,
			Severity:         status.Severity,
			Status:           status.Status,
			PassCount:        status.PassCount,
			FailCount:        status.FailCount,
			TotalAssets:      status.TotalAssets,
			EvaluationSource: status.EvaluationSource,
			LastEvaluated:    status.LastEvaluated,
			PolicyIDs:        append([]string(nil), status.PolicyIDs...),
			GraphQueries:     append([]compliance.GraphQueryDefinition(nil), control.GraphQueries...),
		})
	}
	return controls
}

func complianceStatusByID(report compliance.ComplianceReport, controlID string) (compliance.ControlStatus, bool) {
	for _, control := range report.Controls {
		if control.ControlID == controlID {
			return control, true
		}
	}
	return compliance.ControlStatus{}, false
}

func complianceReportFailCount(report compliance.ComplianceReport) int {
	total := 0
	for _, control := range report.Controls {
		total += control.FailCount
	}
	return total
}

func formatOptionalTime(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.UTC().Format(time.RFC3339)
}
