package grcfindings

import (
	"sort"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Summary struct {
	OpenFindings     int `json:"open_findings"`
	CriticalFindings int `json:"critical_findings"`
	HighFindings     int `json:"high_findings"`
	OverdueFindings  int `json:"overdue_findings"`
	Unassigned       int `json:"unassigned"`
	ControlsFailing  int `json:"controls_failing"`
	EvidenceItems    int `json:"evidence_items"`
	Connectors       int `json:"connectors"`
	StaleConnectors  int `json:"stale_connectors"`
}

type FindingItem struct {
	ID           string       `json:"id"`
	Title        string       `json:"title"`
	Severity     string       `json:"severity"`
	Status       string       `json:"status"`
	Summary      string       `json:"summary,omitempty"`
	TenantID     string       `json:"tenant_id,omitempty"`
	RuntimeID    string       `json:"runtime_id,omitempty"`
	SourceID     string       `json:"source_id,omitempty"`
	Entity       string       `json:"entity,omitempty"`
	ResourceURNs []string     `json:"resource_urns,omitempty"`
	RuleID       string       `json:"rule_id,omitempty"`
	PolicyID     string       `json:"policy_id,omitempty"`
	PolicyName   string       `json:"policy_name,omitempty"`
	Controls     []ControlRef `json:"controls,omitempty"`
	GRCFindingRisk
	GRCFindingWorkflowMetadata
	EvidenceCount   int        `json:"evidence_count"`
	Owner           string     `json:"owner"`
	SLAStatus       string     `json:"sla_status"`
	FirstObservedAt *time.Time `json:"first_observed_at,omitempty"`
	LastObservedAt  *time.Time `json:"last_observed_at,omitempty"`
}

type GRCFindingWorkflowMetadata struct {
	Disposition     string                     `json:"disposition,omitempty"`
	StatusReason    string                     `json:"status_reason,omitempty"`
	Assignee        string                     `json:"assignee,omitempty"`
	DueAt           *time.Time                 `json:"due_at,omitempty"`
	StatusUpdatedAt *time.Time                 `json:"status_updated_at,omitempty"`
	Notes           []ports.FindingNote        `json:"notes,omitempty"`
	Tickets         []ports.FindingTicket      `json:"tickets,omitempty"`
	ExternalRefs    []ports.FindingExternalRef `json:"external_refs,omitempty"`
}

type GRCFindingRisk struct {
	RiskScore       int      `json:"risk_score,omitempty"`
	LikelihoodScore int      `json:"likelihood_score,omitempty"`
	ImpactScore     int      `json:"impact_score,omitempty"`
	ConfidenceScore int      `json:"confidence_score,omitempty"`
	LikelihoodLevel string   `json:"likelihood_level,omitempty"`
	ImpactLevel     string   `json:"impact_level,omitempty"`
	RiskReasons     []string `json:"risk_reasons,omitempty"`
	RiskModel       string   `json:"risk_model_version,omitempty"`
}

type ControlRef struct {
	FrameworkName string `json:"framework_name"`
	ControlID     string `json:"control_id"`
}

type ControlItem struct {
	FrameworkName    string        `json:"framework_name"`
	ControlID        string        `json:"control_id"`
	Status           string        `json:"status"`
	OpenFindings     int           `json:"open_findings"`
	CriticalFindings int           `json:"critical_findings"`
	HighFindings     int           `json:"high_findings"`
	EvidenceItems    int           `json:"evidence_items"`
	Findings         []FindingItem `json:"findings,omitempty"`
}

type EvidenceItem struct {
	ID            string    `json:"id"`
	RuntimeID     string    `json:"runtime_id,omitempty"`
	RuleID        string    `json:"rule_id,omitempty"`
	FindingID     string    `json:"finding_id,omitempty"`
	FindingTitle  string    `json:"finding_title,omitempty"`
	RunID         string    `json:"run_id,omitempty"`
	ClaimIDs      []string  `json:"claim_ids,omitempty"`
	EventIDs      []string  `json:"event_ids,omitempty"`
	GraphRootURNs []string  `json:"graph_root_urns,omitempty"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
}

func FindingItems(findings []*ports.FindingRecord, sourceIDs map[string]string, evidenceCounts map[string]int) []FindingItem {
	items := make([]FindingItem, 0, len(findings))
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		items = append(items, FindingItem{
			ID:           finding.ID,
			Title:        fallbackString(finding.Title, finding.RuleID, finding.ID),
			Severity:     strings.ToUpper(strings.TrimSpace(finding.Severity)),
			Status:       NormalizedFindingStatus(finding.Status),
			Summary:      finding.Summary,
			TenantID:     finding.TenantID,
			RuntimeID:    finding.RuntimeID,
			SourceID:     sourceIDs[finding.RuntimeID],
			Entity:       PrimaryEntity(finding),
			ResourceURNs: append([]string(nil), finding.ResourceURNs...),
			RuleID:       finding.RuleID,
			PolicyID:     finding.PolicyID,
			PolicyName:   finding.PolicyName,
			Controls:     ControlRefs(finding.ControlRefs),
			GRCFindingRisk: GRCFindingRisk{
				RiskScore:       finding.RiskScore,
				LikelihoodScore: finding.LikelihoodScore,
				ImpactScore:     finding.ImpactScore,
				ConfidenceScore: finding.ConfidenceScore,
				LikelihoodLevel: finding.LikelihoodLevel,
				ImpactLevel:     finding.ImpactLevel,
				RiskReasons:     append([]string(nil), finding.RiskReasons...),
				RiskModel:       finding.RiskModelVersion,
			},
			GRCFindingWorkflowMetadata: GRCFindingWorkflowMetadata{
				StatusReason:    finding.StatusReason,
				Assignee:        finding.Assignee,
				DueAt:           timePtr(finding.DueAt),
				StatusUpdatedAt: timePtr(finding.StatusUpdatedAt),
				Notes:           append([]ports.FindingNote(nil), finding.Notes...),
				Tickets:         append([]ports.FindingTicket(nil), finding.Tickets...),
				ExternalRefs:    append([]ports.FindingExternalRef(nil), finding.ExternalRefs...),
			},
			EvidenceCount:   evidenceCounts[finding.ID],
			Owner:           fallbackString(finding.Assignee, "Unassigned"),
			SLAStatus:       SLAStatus(finding),
			FirstObservedAt: timePtr(finding.FirstObservedAt),
			LastObservedAt:  timePtr(finding.LastObservedAt),
		})
	}
	return items
}

func ControlRefs(refs []ports.FindingControlRef) []ControlRef {
	items := make([]ControlRef, 0, len(refs))
	for _, ref := range refs {
		framework := strings.TrimSpace(ref.FrameworkName)
		controlID := strings.TrimSpace(ref.ControlID)
		if framework == "" || controlID == "" {
			continue
		}
		items = append(items, ControlRef{FrameworkName: framework, ControlID: controlID})
	}
	return items
}

func EvidenceItems(evidence []*cerebrov1.FindingEvidence, findingTitles map[string]string) []EvidenceItem {
	items := make([]EvidenceItem, 0, len(evidence))
	for _, item := range evidence {
		if item == nil {
			continue
		}
		items = append(items, EvidenceItem{
			ID:            item.GetId(),
			RuntimeID:     item.GetRuntimeId(),
			RuleID:        item.GetRuleId(),
			FindingID:     item.GetFindingId(),
			FindingTitle:  findingTitles[item.GetFindingId()],
			RunID:         item.GetRunId(),
			ClaimIDs:      append([]string(nil), item.GetClaimIds()...),
			EventIDs:      append([]string(nil), item.GetEventIds()...),
			GraphRootURNs: append([]string(nil), item.GetGraphRootUrns()...),
			CreatedAt:     item.GetCreatedAt().AsTime(),
		})
	}
	return items
}

func ControlItems(findings []FindingItem, evidence []EvidenceItem) []ControlItem {
	controlMap := map[string]*ControlItem{}
	evidenceByFinding := map[string]int{}
	for _, item := range evidence {
		evidenceByFinding[item.FindingID]++
	}
	for _, finding := range findings {
		refs := finding.Controls
		if len(refs) == 0 {
			refs = []ControlRef{{FrameworkName: "Unmapped", ControlID: "Needs mapping"}}
		}
		for _, ref := range refs {
			key := ref.FrameworkName + "\x00" + ref.ControlID
			control := controlMap[key]
			if control == nil {
				control = &ControlItem{
					FrameworkName: ref.FrameworkName,
					ControlID:     ref.ControlID,
					Status:        "passing",
				}
				controlMap[key] = control
			}
			control.Findings = append(control.Findings, finding)
			if finding.Status == "OPEN" || strings.EqualFold(finding.Status, "open") {
				control.OpenFindings++
				control.Status = "failing"
				if finding.Severity == "CRITICAL" {
					control.CriticalFindings++
				}
				if finding.Severity == "HIGH" {
					control.HighFindings++
				}
			}
			if finding.EvidenceCount != 0 {
				control.EvidenceItems += finding.EvidenceCount
			} else {
				control.EvidenceItems += evidenceByFinding[finding.ID]
			}
		}
	}
	controls := make([]ControlItem, 0, len(controlMap))
	for _, control := range controlMap {
		controls = append(controls, *control)
	}
	sort.Slice(controls, func(i, j int) bool {
		left := controls[i]
		right := controls[j]
		if left.OpenFindings != right.OpenFindings {
			return left.OpenFindings > right.OpenFindings
		}
		return left.FrameworkName+left.ControlID < right.FrameworkName+right.ControlID
	})
	return controls
}

func BuildSummary(findings []FindingItem, controls []ControlItem, evidence []EvidenceItem, runtimes []*cerebrov1.SourceRuntime, findingSummary *ports.FindingSummary, evidenceCount *int) Summary {
	var summary Summary
	if evidenceCount != nil {
		summary.EvidenceItems = *evidenceCount
	} else {
		summary.EvidenceItems = len(evidence)
	}
	summary.Connectors = len(runtimes)
	if findingSummary != nil {
		summary.OpenFindings = findingSummary.OpenFindings
		summary.CriticalFindings = findingSummary.CriticalFindings
		summary.HighFindings = findingSummary.HighFindings
		summary.OverdueFindings = findingSummary.OverdueFindings
		summary.Unassigned = findingSummary.Unassigned
		summary.ControlsFailing = findingSummary.ControlsFailing
	} else {
		for _, finding := range findings {
			if finding.Status == "OPEN" {
				summary.OpenFindings++
				if finding.Severity == "CRITICAL" {
					summary.CriticalFindings++
				}
				if finding.Severity == "HIGH" {
					summary.HighFindings++
				}
				if finding.SLAStatus == "overdue" {
					summary.OverdueFindings++
				}
				if finding.Owner == "Unassigned" {
					summary.Unassigned++
				}
			}
		}
		for _, control := range controls {
			if control.Status == "failing" {
				summary.ControlsFailing++
			}
		}
	}
	for _, runtime := range runtimes {
		if ConnectorStatus(protoTimePtr(runtime.GetLastSyncedAt())) == "stale" {
			summary.StaleConnectors++
		}
	}
	return summary
}

func LimitFindings(items []FindingItem, limit int) []FindingItem {
	if len(items) > limit {
		return items[:limit]
	}
	return items
}

func LimitControls(items []ControlItem, limit int) []ControlItem {
	if len(items) > limit {
		return items[:limit]
	}
	return items
}

func LimitEvidence(items []EvidenceItem, limit int) []EvidenceItem {
	if len(items) > limit {
		return items[:limit]
	}
	return items
}

func PrimaryEntity(finding *ports.FindingRecord) string {
	if finding == nil {
		return ""
	}
	for _, urn := range finding.ResourceURNs {
		if strings.TrimSpace(urn) != "" {
			return strings.TrimSpace(urn)
		}
	}
	return fallbackString(finding.PolicyName, finding.PolicyID, finding.RuleID)
}

func NormalizedFindingStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "open", "finding_status_open":
		return "OPEN"
	case "resolved", "finding_status_resolved":
		return "RESOLVED"
	case "suppressed", "finding_status_suppressed":
		return "SUPPRESSED"
	default:
		return "UNKNOWN"
	}
}

func SLAStatus(finding *ports.FindingRecord) string {
	if finding == nil {
		return "unknown"
	}
	if NormalizedFindingStatus(finding.Status) != "OPEN" {
		return "closed"
	}
	if finding.DueAt.IsZero() {
		return "no_due_date"
	}
	if time.Now().UTC().After(finding.DueAt) {
		return "overdue"
	}
	if time.Until(finding.DueAt) <= 72*time.Hour {
		return "due_soon"
	}
	return "on_track"
}

func RecommendedAction(finding FindingItem) string {
	if finding.Owner == "Unassigned" {
		return "Assign an owner, confirm evidence, and set a remediation due date."
	}
	if finding.EvidenceCount == 0 {
		return "Request supporting evidence before audit review."
	}
	if len(finding.Controls) == 0 {
		return "Map this finding to the affected control objective."
	}
	return "Review evidence, confirm impact, and update remediation status."
}

func ConnectorStatus(lastSyncedAt *time.Time) string {
	if lastSyncedAt == nil {
		return "unknown"
	}
	if time.Since(*lastSyncedAt) > 24*time.Hour {
		return "stale"
	}
	return "healthy"
}

func ConnectorFreshness(lastSyncedAt *time.Time) string {
	if lastSyncedAt == nil {
		return "never_synced"
	}
	age := time.Since(*lastSyncedAt)
	switch {
	case age <= time.Hour:
		return "fresh"
	case age <= 24*time.Hour:
		return "recent"
	default:
		return "stale"
	}
}

func SeverityRank(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	case "INFO":
		return 4
	default:
		return 5
	}
}

func fallbackString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func timePtr(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	value = value.UTC()
	return &value
}

func protoTimePtr(value *timestamppb.Timestamp) *time.Time {
	if value == nil {
		return nil
	}
	timestamp := value.AsTime()
	if timestamp.IsZero() {
		return nil
	}
	timestamp = timestamp.UTC()
	return &timestamp
}
