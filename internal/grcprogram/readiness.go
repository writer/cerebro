package grcprogram

import (
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/grccontrol"
)

const workItemLimit = 12

type Readiness struct {
	Profile     grccontrol.Profile        `json:"profile"`
	Summary     Summary                   `json:"summary"`
	Frameworks  []Framework               `json:"frameworks"`
	Controls    []Control                 `json:"controls"`
	WorkItems   []WorkItem                `json:"work_items"`
	ProofBundle ProofBundle               `json:"proof_bundle"`
	Connectors  []Connector               `json:"connectors"`
	Metadata    grccontrol.ReportMetadata `json:"metadata"`
	GeneratedAt time.Time                 `json:"generated_at"`
}

type Summary struct {
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

type Framework struct {
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

type Control struct {
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

type WorkItem struct {
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

type ProofBundle struct {
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

type Connector struct {
	RuntimeID           string     `json:"runtime_id"`
	SourceID            string     `json:"source_id,omitempty"`
	TenantID            string     `json:"tenant_id,omitempty"`
	Status              string     `json:"status"`
	Freshness           string     `json:"freshness"`
	SyncLagSeconds      *int64     `json:"sync_lag_seconds,omitempty"`
	CheckpointWatermark *time.Time `json:"checkpoint_watermark,omitempty"`
	WatermarkLagSeconds *int64     `json:"watermark_lag_seconds,omitempty"`
	WatermarkFreshness  string     `json:"watermark_freshness,omitempty"`
	LastSyncedAt        *time.Time `json:"last_synced_at,omitempty"`
}

type BuildInput struct {
	Result             grccontrol.PacketResult
	Query              url.Values
	TenantID           string
	Connectors         []Connector
	CoverageBlindSpots int
	GeneratedAt        time.Time
}

type frameworkAccumulator struct {
	Framework
	scoreTotal int
}

func Build(input BuildInput) Readiness {
	generatedAt := input.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	controls := buildControls(input.Result.Controls, input.Result.Profile.ID, input.TenantID)
	summary := buildSummary(input.Result, input.Connectors, input.CoverageBlindSpots)
	return Readiness{
		Profile:     input.Result.Profile,
		Summary:     summary,
		Frameworks:  buildFrameworks(controls),
		Controls:    controls,
		WorkItems:   buildWorkItems(controls),
		ProofBundle: buildProofBundle(input.Result, summary, input.Query, generatedAt),
		Connectors:  input.Connectors,
		Metadata:    input.Result.Metadata,
		GeneratedAt: generatedAt,
	}
}

func buildSummary(result grccontrol.PacketResult, connectors []Connector, coverageBlindSpots int) Summary {
	summary := Summary{
		Status:             strings.TrimSpace(result.Metadata.Readiness.Status),
		Score:              result.Metadata.Readiness.Score,
		Controls:           len(result.Controls),
		EvidenceItems:      result.Metadata.Provenance.EvidenceCount,
		Connectors:         len(connectors),
		CoverageBlindSpots: coverageBlindSpots,
		ReadinessBlockers:  result.Metadata.Readiness.Blockers,
	}
	for _, connector := range connectors {
		if connectorNeedsAttention(connector) {
			summary.StaleConnectors++
		}
	}
	for _, control := range result.Controls {
		switch controlClass(control) {
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
			total += controlScore(control)
		}
		summary.Score = total / len(result.Controls)
	}
	if summary.Status == "" {
		summary.Status = readinessStatus(summary.Score, summary)
	}
	return summary
}

func buildControls(controls []grccontrol.ControlItem, profileID, tenantID string) []Control {
	items := make([]Control, 0, len(controls))
	for _, control := range controls {
		items = append(items, Control{
			FrameworkName:        control.FrameworkName,
			FrameworkID:          control.FrameworkID,
			FrameworkVersion:     control.FrameworkVersion,
			FrameworkLifecycle:   control.FrameworkLifecycle,
			ControlID:            control.ControlID,
			Title:                control.Title,
			OwnerDomain:          control.OwnerDomain,
			Status:               control.Status,
			Score:                controlScore(control),
			OpenFindings:         control.OpenFindings,
			CriticalFindings:     control.CriticalFindings,
			HighFindings:         control.HighFindings,
			EvidenceItems:        control.EvidenceItems,
			MissingEvidence:      control.MissingEvidence,
			StaleEvidence:        control.StaleEvidence,
			EvidenceExpectations: control.Expectations,
			EvidenceQuality:      control.EvidenceQuality,
			Action:               controlAction(control),
			Href:                 controlHref(profileID, tenantID, control.FrameworkName, control.ControlID),
			Reasons:              control.Reasons,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		left := controlRank(items[i])
		right := controlRank(items[j])
		for index := range left {
			if left[index] != right[index] {
				return left[index] < right[index]
			}
		}
		return items[i].FrameworkName+"\x00"+items[i].ControlID < items[j].FrameworkName+"\x00"+items[j].ControlID
	})
	return items
}

func buildFrameworks(controls []Control) []Framework {
	frameworks := map[string]*frameworkAccumulator{}
	for _, control := range controls {
		key := control.FrameworkName + "\x00" + control.FrameworkID + "\x00" + control.FrameworkVersion
		accumulator := frameworks[key]
		if accumulator == nil {
			accumulator = &frameworkAccumulator{Framework: Framework{
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
		switch controlClassFromStatus(control.Status, control.MissingEvidence, control.StaleEvidence) {
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
	items := make([]Framework, 0, len(frameworks))
	for _, accumulator := range frameworks {
		if accumulator.Controls > 0 {
			accumulator.Score = accumulator.scoreTotal / accumulator.Controls
		}
		accumulator.Status = frameworkStatus(accumulator.Framework)
		items = append(items, accumulator.Framework)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Score != items[j].Score {
			return items[i].Score < items[j].Score
		}
		return items[i].FrameworkName < items[j].FrameworkName
	})
	return items
}

func buildWorkItems(controls []Control) []WorkItem {
	items := make([]WorkItem, 0, len(controls))
	for _, control := range controls {
		if control.Action == "Keep audit-ready" {
			continue
		}
		title := strings.TrimSpace(control.Title)
		if title == "" {
			title = strings.TrimSpace(control.FrameworkName + " " + control.ControlID)
		}
		items = append(items, WorkItem{
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
	if len(items) > workItemLimit {
		items = items[:workItemLimit]
	}
	return items
}

func buildProofBundle(result grccontrol.PacketResult, summary Summary, query url.Values, generatedAt time.Time) ProofBundle {
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
	return ProofBundle{
		ID:                "proofbundle:" + profileID,
		Title:             strings.TrimSpace(firstNonEmpty(result.Profile.Name, "Audit proof bundle")),
		Description:       "Control packet, readiness metadata, source scope, and export paths for auditor review.",
		Status:            firstNonEmpty(result.Metadata.Readiness.Status, summary.Status),
		Score:             summary.Score,
		ControlPacketPath: pathWithQuery("/grc/control-packets", query),
		ExportPath:        pathWithQuery("/grc/control-packets/export", query),
		ReportsPath:       pathWithQuery("/reports", reportQuery),
		Readiness:         result.Metadata.Readiness,
		GeneratedAt:       generatedAt,
	}
}

func controlClass(control grccontrol.ControlItem) string {
	return controlClassFromStatus(control.Status, control.MissingEvidence, control.StaleEvidence)
}

func controlClassFromStatus(status string, missingEvidence, staleEvidence int) string {
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

func controlAction(control grccontrol.ControlItem) string {
	switch controlClass(control) {
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

func controlScore(control grccontrol.ControlItem) int {
	if control.EvidenceScore > 0 {
		return control.EvidenceScore
	}
	switch controlClass(control) {
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

func controlRank(control Control) [5]int {
	statusWeight := map[string]int{
		"failing":          0,
		"missing_evidence": 1,
		"stale_evidence":   2,
		"manual_review":    3,
		"passing":          9,
	}
	class := controlClassFromStatus(control.Status, control.MissingEvidence, control.StaleEvidence)
	return [5]int{
		statusWeight[class],
		-control.CriticalFindings,
		-control.OpenFindings,
		-control.MissingEvidence,
		control.Score,
	}
}

func readinessStatus(score int, summary Summary) string {
	switch {
	case summary.FailingControls > 0 || summary.StaleConnectors > 0:
		return "blocked"
	case summary.MissingEvidenceControls > 0 || summary.StaleEvidenceControls > 0 || summary.ManualReviewControls > 0 || summary.CoverageBlindSpots > 0:
		return "needs_review"
	case score >= 90:
		return "ready"
	default:
		return "needs_review"
	}
}

func frameworkStatus(framework Framework) string {
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

func connectorNeedsAttention(connector Connector) bool {
	status := strings.ToLower(strings.TrimSpace(connector.Status))
	freshness := strings.ToLower(strings.TrimSpace(connector.Freshness))
	watermark := strings.ToLower(strings.TrimSpace(connector.WatermarkFreshness))
	return status == "stale" || status == "failed" || freshness == "stale" || watermark == "stale"
}

func controlHref(profileID, tenantID, frameworkName, controlID string) string {
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
	return pathWithQuery("/grc/controls", values)
}

func pathWithQuery(path string, query url.Values) string {
	if encoded := query.Encode(); encoded != "" {
		return path + "?" + encoded
	}
	return path
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
