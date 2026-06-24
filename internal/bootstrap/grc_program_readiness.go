package bootstrap

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/grccontrol"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecoverage"
)

const grcProgramWorkItemLimit = 12

type grcProgramReadinessResponse struct {
	Profile            grccontrol.Profile           `json:"profile"`
	Summary            grcProgramReadinessSummary   `json:"summary"`
	Frameworks         []grcProgramFramework        `json:"frameworks"`
	Controls           []grcProgramControl          `json:"controls"`
	WorkItems          []grcProgramWorkItem         `json:"work_items"`
	ProofBundle        grcProgramProofBundle        `json:"proof_bundle"`
	Connectors         []grcConnector               `json:"connectors"`
	SourceSummaries    []sourceRuntimeHealthSummary `json:"source_summaries,omitempty"`
	CoverageBlindSpots []sourcecoverage.Record      `json:"coverage_blind_spots,omitempty"`
	CoverageSummaries  []sourcecoverage.Summary     `json:"coverage_summaries,omitempty"`
	Metadata           grccontrol.ReportMetadata    `json:"metadata"`
	GeneratedAt        time.Time                    `json:"generated_at"`
}

type grcProgramReadinessSummary struct {
	Status                  string                              `json:"status"`
	Score                   int                                 `json:"score"`
	Controls                int                                 `json:"controls"`
	PassingControls         int                                 `json:"passing_controls"`
	FailingControls         int                                 `json:"failing_controls"`
	MissingEvidenceControls int                                 `json:"missing_evidence_controls"`
	StaleEvidenceControls   int                                 `json:"stale_evidence_controls"`
	ManualReviewControls    int                                 `json:"manual_review_controls"`
	EvidenceItems           int                                 `json:"evidence_items"`
	MissingEvidenceItems    int                                 `json:"missing_evidence_items"`
	StaleEvidenceItems      int                                 `json:"stale_evidence_items"`
	OpenFindings            int                                 `json:"open_findings"`
	CriticalFindings        int                                 `json:"critical_findings"`
	HighFindings            int                                 `json:"high_findings"`
	Connectors              int                                 `json:"connectors"`
	StaleConnectors         int                                 `json:"stale_connectors"`
	CoverageBlindSpots      int                                 `json:"coverage_blind_spots"`
	ReadinessBlockers       []grccontrol.ReportReadinessBlocker `json:"readiness_blockers,omitempty"`
}

type grcProgramFramework struct {
	FrameworkName           string `json:"framework_name"`
	FrameworkID             string `json:"framework_id,omitempty"`
	FrameworkVersion        string `json:"framework_version,omitempty"`
	FrameworkLifecycle      string `json:"framework_lifecycle,omitempty"`
	Status                  string `json:"status"`
	Score                   int    `json:"score"`
	Controls                int    `json:"controls"`
	PassingControls         int    `json:"passing_controls"`
	FailingControls         int    `json:"failing_controls"`
	MissingEvidenceControls int    `json:"missing_evidence_controls"`
	StaleEvidenceControls   int    `json:"stale_evidence_controls"`
	ManualReviewControls    int    `json:"manual_review_controls"`
	OpenFindings            int    `json:"open_findings"`
	EvidenceItems           int    `json:"evidence_items"`
}

type grcProgramControl struct {
	FrameworkName        string   `json:"framework_name"`
	FrameworkID          string   `json:"framework_id,omitempty"`
	FrameworkVersion     string   `json:"framework_version,omitempty"`
	FrameworkLifecycle   string   `json:"framework_lifecycle,omitempty"`
	ControlID            string   `json:"control_id"`
	Title                string   `json:"title,omitempty"`
	OwnerDomain          string   `json:"owner_domain,omitempty"`
	Status               string   `json:"status"`
	Score                int      `json:"score"`
	OpenFindings         int      `json:"open_findings"`
	CriticalFindings     int      `json:"critical_findings"`
	HighFindings         int      `json:"high_findings"`
	EvidenceItems        int      `json:"evidence_items"`
	MissingEvidence      int      `json:"missing_evidence_items,omitempty"`
	StaleEvidence        int      `json:"stale_evidence_items,omitempty"`
	EvidenceExpectations int      `json:"evidence_expectations,omitempty"`
	EvidenceQuality      string   `json:"evidence_quality,omitempty"`
	Action               string   `json:"action"`
	Href                 string   `json:"href,omitempty"`
	Reasons              []string `json:"reasons,omitempty"`
}

type grcProgramWorkItem struct {
	ID               string   `json:"id"`
	Kind             string   `json:"kind"`
	Title            string   `json:"title"`
	FrameworkName    string   `json:"framework_name,omitempty"`
	ControlID        string   `json:"control_id,omitempty"`
	Status           string   `json:"status"`
	Action           string   `json:"action"`
	OwnerDomain      string   `json:"owner_domain,omitempty"`
	OpenFindings     int      `json:"open_findings,omitempty"`
	CriticalFindings int      `json:"critical_findings,omitempty"`
	MissingEvidence  int      `json:"missing_evidence_items,omitempty"`
	StaleEvidence    int      `json:"stale_evidence_items,omitempty"`
	Href             string   `json:"href,omitempty"`
	Reasons          []string `json:"reasons,omitempty"`
}

type grcProgramProofBundle struct {
	ID                string                     `json:"id"`
	Title             string                     `json:"title"`
	Description       string                     `json:"description,omitempty"`
	Status            string                     `json:"status"`
	Score             int                        `json:"score"`
	ControlPacketPath string                     `json:"control_packet_path"`
	ExportPath        string                     `json:"export_path"`
	ReportsPath       string                     `json:"reports_path"`
	Readiness         grccontrol.ReportReadiness `json:"readiness"`
	GeneratedAt       time.Time                  `json:"generated_at"`
}

type grcProgramFrameworkAccumulator struct {
	grcProgramFramework
	scoreTotal int
}

func (a *App) handleGRCProgramReadiness(w http.ResponseWriter, r *http.Request) {
	result, err := a.buildGRCControlEvidencePacket(r)
	if err != nil {
		writeGRCControlPacketError(w, err)
		return
	}
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	runtimes, err := a.grcListRuntimes(r, scope)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	generatedAt := time.Now().UTC()
	sourceSummaries, err := a.grcSourceRuntimeHealthSummaries(r.Context(), runtimes, generatedAt)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	coverage := a.sourceCoverageRecords(runtimes, portsSourceRuntimeFilter(scope), generatedAt)
	connectors := grcConnectorItems(runtimes)
	coverageBlindSpots := sourcecoverage.BlindSpots(coverage)
	summary := grcBuildProgramReadinessSummary(result, connectors, len(coverageBlindSpots))
	controls := grcBuildProgramControls(result.Controls, result.Profile.ID, scope.TenantID)
	workItems := grcBuildProgramWorkItems(controls)

	writeJSON(w, http.StatusOK, grcProgramReadinessResponse{
		Profile:            result.Profile,
		Summary:            summary,
		Frameworks:         grcBuildProgramFrameworks(controls),
		Controls:           controls,
		WorkItems:          workItems,
		ProofBundle:        grcBuildProgramProofBundle(result, r.URL.Query(), generatedAt),
		Connectors:         connectors,
		SourceSummaries:    sourceSummaries,
		CoverageBlindSpots: coverageBlindSpots,
		CoverageSummaries:  sourcecoverage.Summaries(coverage),
		Metadata:           result.Metadata,
		GeneratedAt:        generatedAt,
	})
}

func grcBuildProgramReadinessSummary(result grccontrol.PacketResult, connectors []grcConnector, coverageBlindSpots int) grcProgramReadinessSummary {
	summary := grcProgramReadinessSummary{
		Status:             strings.TrimSpace(result.Metadata.Readiness.Status),
		Score:              result.Metadata.Readiness.Score,
		Controls:           len(result.Controls),
		EvidenceItems:      result.Metadata.Provenance.EvidenceCount,
		Connectors:         len(connectors),
		CoverageBlindSpots: coverageBlindSpots,
		ReadinessBlockers:  result.Metadata.Readiness.Blockers,
	}
	for _, connector := range connectors {
		if grcProgramConnectorNeedsAttention(connector) {
			summary.StaleConnectors++
		}
	}
	for _, control := range result.Controls {
		class := grcProgramControlClass(control)
		switch class {
		case "passing":
			summary.PassingControls++
		case "failing":
			summary.FailingControls++
		case "missing_evidence":
			summary.MissingEvidenceControls++
		case "stale_evidence":
			summary.StaleEvidenceControls++
		case "manual_review":
			summary.ManualReviewControls++
		}
		summary.OpenFindings += control.OpenFindings
		summary.CriticalFindings += control.CriticalFindings
		summary.HighFindings += control.HighFindings
		summary.MissingEvidenceItems += control.MissingEvidence
		summary.StaleEvidenceItems += control.StaleEvidence
	}
	if summary.Score == 0 && len(result.Controls) > 0 {
		total := 0
		for _, control := range result.Controls {
			total += grcProgramControlScore(control)
		}
		summary.Score = total / len(result.Controls)
	}
	if summary.Status == "" {
		summary.Status = grcProgramReadinessStatus(summary.Score, summary)
	}
	return summary
}

func grcBuildProgramControls(controls []grccontrol.ControlItem, profileID, tenantID string) []grcProgramControl {
	items := make([]grcProgramControl, 0, len(controls))
	for _, control := range controls {
		action := grcProgramControlAction(control)
		items = append(items, grcProgramControl{
			FrameworkName:        control.FrameworkName,
			FrameworkID:          control.FrameworkID,
			FrameworkVersion:     control.FrameworkVersion,
			FrameworkLifecycle:   control.FrameworkLifecycle,
			ControlID:            control.ControlID,
			Title:                control.Title,
			OwnerDomain:          control.OwnerDomain,
			Status:               control.Status,
			Score:                grcProgramControlScore(control),
			OpenFindings:         control.OpenFindings,
			CriticalFindings:     control.CriticalFindings,
			HighFindings:         control.HighFindings,
			EvidenceItems:        control.EvidenceItems,
			MissingEvidence:      control.MissingEvidence,
			StaleEvidence:        control.StaleEvidence,
			EvidenceExpectations: control.Expectations,
			EvidenceQuality:      control.EvidenceQuality,
			Action:               action,
			Href:                 grcProgramControlHref(profileID, tenantID, control.FrameworkName, control.ControlID),
			Reasons:              control.Reasons,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		left := grcProgramControlRank(items[i])
		right := grcProgramControlRank(items[j])
		for index := range left {
			if left[index] != right[index] {
				return left[index] < right[index]
			}
		}
		return items[i].FrameworkName+"\x00"+items[i].ControlID < items[j].FrameworkName+"\x00"+items[j].ControlID
	})
	return items
}

func grcBuildProgramFrameworks(controls []grcProgramControl) []grcProgramFramework {
	frameworks := map[string]*grcProgramFrameworkAccumulator{}
	for _, control := range controls {
		key := control.FrameworkName + "\x00" + control.FrameworkID + "\x00" + control.FrameworkVersion
		accumulator := frameworks[key]
		if accumulator == nil {
			accumulator = &grcProgramFrameworkAccumulator{grcProgramFramework: grcProgramFramework{
				FrameworkName:      control.FrameworkName,
				FrameworkID:        control.FrameworkID,
				FrameworkVersion:   control.FrameworkVersion,
				FrameworkLifecycle: control.FrameworkLifecycle,
			}}
			frameworks[key] = accumulator
		}
		accumulator.Controls++
		accumulator.scoreTotal += control.Score
		accumulator.OpenFindings += control.OpenFindings
		accumulator.EvidenceItems += control.EvidenceItems
		switch grcProgramControlClassFromStatus(control.Status, control.MissingEvidence, control.StaleEvidence) {
		case "passing":
			accumulator.PassingControls++
		case "failing":
			accumulator.FailingControls++
		case "missing_evidence":
			accumulator.MissingEvidenceControls++
		case "stale_evidence":
			accumulator.StaleEvidenceControls++
		case "manual_review":
			accumulator.ManualReviewControls++
		}
	}
	items := make([]grcProgramFramework, 0, len(frameworks))
	for _, accumulator := range frameworks {
		if accumulator.Controls > 0 {
			accumulator.Score = accumulator.scoreTotal / accumulator.Controls
		}
		accumulator.Status = grcProgramFrameworkStatus(accumulator.grcProgramFramework)
		items = append(items, accumulator.grcProgramFramework)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Score != items[j].Score {
			return items[i].Score < items[j].Score
		}
		return items[i].FrameworkName < items[j].FrameworkName
	})
	return items
}

func grcBuildProgramWorkItems(controls []grcProgramControl) []grcProgramWorkItem {
	items := make([]grcProgramWorkItem, 0, len(controls))
	for _, control := range controls {
		if control.Action == "Keep audit-ready" {
			continue
		}
		title := strings.TrimSpace(control.Title)
		if title == "" {
			title = strings.TrimSpace(control.FrameworkName + " " + control.ControlID)
		}
		items = append(items, grcProgramWorkItem{
			ID:               control.FrameworkName + ":" + control.ControlID,
			Kind:             "control",
			Title:            title,
			FrameworkName:    control.FrameworkName,
			ControlID:        control.ControlID,
			Status:           control.Status,
			Action:           control.Action,
			OwnerDomain:      control.OwnerDomain,
			OpenFindings:     control.OpenFindings,
			CriticalFindings: control.CriticalFindings,
			MissingEvidence:  control.MissingEvidence,
			StaleEvidence:    control.StaleEvidence,
			Href:             control.Href,
			Reasons:          control.Reasons,
		})
	}
	if len(items) > grcProgramWorkItemLimit {
		items = items[:grcProgramWorkItemLimit]
	}
	return items
}

func grcBuildProgramProofBundle(result grccontrol.PacketResult, query url.Values, generatedAt time.Time) grcProgramProofBundle {
	profileID := strings.TrimSpace(result.Profile.ID)
	if profileID == "" {
		profileID = grccontrol.DefaultEvidenceProfileID
	}
	reportQuery := url.Values{}
	for _, key := range []string{"tenant_id", "profile", "framework", "control"} {
		if value := strings.TrimSpace(query.Get(key)); value != "" {
			reportQuery.Set(key, value)
		}
	}
	if reportQuery.Get("profile") == "" {
		reportQuery.Set("profile", profileID)
	}
	return grcProgramProofBundle{
		ID:                "proofbundle:" + profileID,
		Title:             strings.TrimSpace(firstNonEmpty(result.Profile.Name, "Audit proof bundle")),
		Description:       "Control packet, readiness metadata, source scope, and export paths for auditor review.",
		Status:            result.Metadata.Readiness.Status,
		Score:             result.Metadata.Readiness.Score,
		ControlPacketPath: grcProgramAPIPath("/grc/control-packets", query),
		ExportPath:        grcProgramAPIPath("/grc/control-packets/export", query),
		ReportsPath:       grcProgramUIPath("/reports", reportQuery),
		Readiness:         result.Metadata.Readiness,
		GeneratedAt:       generatedAt,
	}
}

func grcProgramControlClass(control grccontrol.ControlItem) string {
	return grcProgramControlClassFromStatus(control.Status, control.MissingEvidence, control.StaleEvidence)
}

func grcProgramControlClassFromStatus(status string, missingEvidence, staleEvidence int) string {
	normalized := strings.ToLower(strings.TrimSpace(status))
	switch {
	case normalized == "failing":
		return "failing"
	case missingEvidence > 0 || normalized == "missing_evidence":
		return "missing_evidence"
	case staleEvidence > 0 || normalized == "stale_evidence":
		return "stale_evidence"
	case normalized == "manual_review" || normalized == "manual":
		return "manual_review"
	case normalized == "passing" || normalized == "satisfied" || normalized == "ready" || normalized == "ok":
		return "passing"
	default:
		return "manual_review"
	}
}

func grcProgramControlAction(control grccontrol.ControlItem) string {
	switch grcProgramControlClass(control) {
	case "failing":
		return "Remediate mapped findings"
	case "missing_evidence":
		return "Collect missing evidence"
	case "stale_evidence":
		return "Refresh stale evidence"
	case "manual_review":
		return "Complete manual assessment"
	default:
		return "Keep audit-ready"
	}
}

func grcProgramControlScore(control grccontrol.ControlItem) int {
	if control.EvidenceScore > 0 {
		return control.EvidenceScore
	}
	switch grcProgramControlClass(control) {
	case "passing":
		return 100
	case "stale_evidence":
		return 70
	case "manual_review":
		return 65
	case "missing_evidence":
		return 45
	case "failing":
		return 25
	default:
		return 50
	}
}

func grcProgramControlRank(control grcProgramControl) [5]int {
	statusWeight := map[string]int{
		"failing":          0,
		"missing_evidence": 1,
		"stale_evidence":   2,
		"manual_review":    3,
		"passing":          9,
	}
	class := grcProgramControlClassFromStatus(control.Status, control.MissingEvidence, control.StaleEvidence)
	return [5]int{
		statusWeight[class],
		-control.CriticalFindings,
		-control.OpenFindings,
		-control.MissingEvidence,
		control.Score,
	}
}

func grcProgramReadinessStatus(score int, summary grcProgramReadinessSummary) string {
	switch {
	case summary.FailingControls > 0 || summary.StaleConnectors > 0:
		return "blocked"
	case summary.MissingEvidenceControls > 0 || summary.ManualReviewControls > 0 || summary.CoverageBlindSpots > 0:
		return "needs_review"
	case score >= 90:
		return "ready"
	default:
		return "needs_review"
	}
}

func grcProgramFrameworkStatus(framework grcProgramFramework) string {
	switch {
	case framework.FailingControls > 0:
		return "blocked"
	case framework.MissingEvidenceControls > 0 || framework.StaleEvidenceControls > 0 || framework.ManualReviewControls > 0:
		return "needs_review"
	case framework.Score >= 90:
		return "ready"
	default:
		return "needs_review"
	}
}

func grcProgramConnectorNeedsAttention(connector grcConnector) bool {
	status := strings.ToLower(strings.TrimSpace(connector.Status))
	freshness := strings.ToLower(strings.TrimSpace(connector.Freshness))
	watermark := strings.ToLower(strings.TrimSpace(connector.WatermarkFreshness))
	return status == "stale" || status == "failed" || freshness == "stale" || watermark == "stale"
}

func grcProgramControlHref(profileID, tenantID, frameworkName, controlID string) string {
	values := url.Values{}
	if strings.TrimSpace(profileID) != "" {
		values.Set("profile", strings.TrimSpace(profileID))
	}
	if strings.TrimSpace(tenantID) != "" {
		values.Set("tenant_id", strings.TrimSpace(tenantID))
	}
	if strings.TrimSpace(frameworkName) != "" {
		values.Set("framework", strings.TrimSpace(frameworkName))
	}
	if strings.TrimSpace(controlID) != "" {
		values.Set("control", strings.TrimSpace(controlID))
	}
	return grcProgramUIPath("/controls", values)
}

func grcProgramAPIPath(path string, query url.Values) string {
	if encoded := query.Encode(); encoded != "" {
		return path + "?" + encoded
	}
	return path
}

func grcProgramUIPath(path string, query url.Values) string {
	if encoded := query.Encode(); encoded != "" {
		return path + "?" + encoded
	}
	return path
}

func portsSourceRuntimeFilter(scope grcScope) ports.SourceRuntimeFilter {
	return ports.SourceRuntimeFilter{
		RuntimeID:  scope.RuntimeID,
		RuntimeIDs: scope.RuntimeIDs,
		TenantID:   scope.TenantID,
		SourceID:   scope.SourceID,
		Limit:      scope.Limit,
	}
}
