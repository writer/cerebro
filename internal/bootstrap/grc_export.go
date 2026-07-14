package bootstrap

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// grcExportLimit pulls the full available dataset for auditor exports rather
// than the smaller default page size used by the interactive list endpoints.
const grcExportLimit = grcMaxLimit

func (a *App) handleGRCFindingsExport(w http.ResponseWriter, r *http.Request) {
	page, err := a.grcFindingItemsFromRequest(r, grcExportLimit)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	rows := make([][]string, 0, len(page.Items))
	for _, item := range page.Items {
		rows = append(rows, grcFindingExportRow(item))
	}
	writeGRCCSV(w, grcExportFilename("findings"), grcFindingExportHeader(), rows)
}

func (a *App) handleGRCControlsExport(w http.ResponseWriter, r *http.Request) {
	controls, err := a.grcControlItemsFromRequest(r, grcExportLimit)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	rows := make([][]string, 0, len(controls))
	for _, control := range controls {
		rows = append(rows, grcControlExportRow(control))
	}
	writeGRCCSV(w, grcExportFilename("controls"), grcControlExportHeader(), rows)
}

func grcFindingExportHeader() []string {
	return []string{
		"id", "title", "severity", "status", "disposition",
		"risk_score", "likelihood_level", "impact_level",
		"owner", "assignee", "sla_status", "due_at",
		"tenant_id", "runtime_id", "source_id", "entity",
		"resource_urns", "rule_id", "policy_id", "policy_name", "controls",
		"evidence_count", "first_observed_at", "last_observed_at",
	}
}

func grcFindingExportRow(item grcFindingItem) []string {
	controls := make([]string, 0, len(item.Controls))
	for _, control := range item.Controls {
		controls = append(controls, strings.TrimSpace(control.FrameworkName+" "+control.ControlID))
	}
	return []string{
		item.ID, item.Title, item.Severity, item.Status, item.Disposition,
		strconv.Itoa(item.RiskScore), item.LikelihoodLevel, item.ImpactLevel,
		item.Owner, item.Assignee, item.SLAStatus, grcExportTime(item.DueAt),
		item.TenantID, item.RuntimeID, item.SourceID, item.Entity,
		strings.Join(item.ResourceURNs, "; "), item.RuleID, item.PolicyID, item.PolicyName, strings.Join(controls, "; "),
		strconv.Itoa(item.EvidenceCount), grcExportTime(item.FirstObservedAt), grcExportTime(item.LastObservedAt),
	}
}

func grcControlExportHeader() []string {
	return []string{
		"framework_name", "control_id", "status",
		"open_findings", "critical_findings", "high_findings", "evidence_items",
	}
}

func grcControlExportRow(item grcControlItem) []string {
	return []string{
		item.FrameworkName, item.ControlID, item.Status,
		strconv.Itoa(item.OpenFindings), strconv.Itoa(item.CriticalFindings),
		strconv.Itoa(item.HighFindings), strconv.Itoa(item.EvidenceItems),
	}
}

func grcExportTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func grcExportFilename(kind string) string {
	return fmt.Sprintf("cerebro-%s-%s.csv", kind, time.Now().UTC().Format("2006-01-02"))
}

func writeGRCCSV(w http.ResponseWriter, filename string, header []string, rows [][]string) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write(header); err != nil {
		http.Error(w, "failed to encode export", http.StatusInternalServerError)
		return
	}
	for _, row := range rows {
		sanitized := make([]string, len(row))
		for i, value := range row {
			sanitized[i] = grcCSVSanitizeCell(value)
		}
		if err := writer.Write(sanitized); err != nil {
			http.Error(w, "failed to encode export", http.StatusInternalServerError)
			return
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		http.Error(w, "failed to encode export", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buffer.Bytes())
}

func grcCSVSanitizeCell(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + value
	default:
		return value
	}
}
