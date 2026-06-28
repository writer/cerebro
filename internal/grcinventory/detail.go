package grcinventory

import (
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/grcfindings"
	"github.com/writer/cerebro/internal/ports"
)

type TimelineEvent struct {
	At          *time.Time `json:"at,omitempty"`
	Kind        string     `json:"kind"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	Status      string     `json:"status,omitempty"`
}

type Action struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Priority    string `json:"priority"`
	Href        string `json:"href,omitempty"`
}

type TestItem struct {
	Name         string     `json:"name"`
	Owner        string     `json:"owner"`
	Status       string     `json:"status"`
	DueAt        *time.Time `json:"due_at,omitempty"`
	ControlID    string     `json:"control_id,omitempty"`
	Framework    string     `json:"framework,omitempty"`
	FindingID    string     `json:"finding_id,omitempty"`
	FindingTitle string     `json:"finding_title,omitempty"`
}

type Vulnerability struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Status    string `json:"status"`
	SourceID  string `json:"source_id,omitempty"`
	FindingID string `json:"finding_id,omitempty"`
}

func Tests(findings []grcfindings.FindingItem, controls []grcfindings.ControlItem) []TestItem {
	tests := []TestItem{}
	seen := map[string]struct{}{}
	for _, finding := range findings {
		refs := finding.Controls
		if len(refs) == 0 {
			refs = []grcfindings.ControlRef{{FrameworkName: "Unmapped", ControlID: fallback(finding.PolicyName, finding.RuleID, finding.ID)}}
		}
		for _, ref := range refs {
			name := fallback(finding.PolicyName, finding.Title, ref.ControlID)
			key := name + "\x00" + ref.FrameworkName + "\x00" + ref.ControlID + "\x00" + finding.ID
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			tests = append(tests, TestItem{
				Name:         name,
				Owner:        finding.Owner,
				Status:       TestStatus(finding),
				DueAt:        finding.DueAt,
				ControlID:    ref.ControlID,
				Framework:    ref.FrameworkName,
				FindingID:    finding.ID,
				FindingTitle: finding.Title,
			})
		}
	}
	if len(tests) == 0 {
		for _, control := range controls {
			key := control.FrameworkName + "\x00" + control.ControlID
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			tests = append(tests, TestItem{
				Name:      control.ControlID,
				Owner:     "Unassigned",
				Status:    control.Status,
				ControlID: control.ControlID,
				Framework: control.FrameworkName,
			})
		}
	}
	sort.Slice(tests, func(i, j int) bool {
		if tests[i].Status != tests[j].Status {
			return tests[i].Status < tests[j].Status
		}
		return tests[i].Name < tests[j].Name
	})
	return tests
}

func TestStatus(finding grcfindings.FindingItem) string {
	if finding.Status == "OPEN" || strings.EqualFold(finding.Status, "open") {
		if finding.SLAStatus == "overdue" {
			return "overdue"
		}
		return "failing"
	}
	return "ok"
}

func Vulnerabilities(findings []grcfindings.FindingItem) []Vulnerability {
	vulnerabilities := []Vulnerability{}
	for _, finding := range findings {
		text := strings.ToLower(strings.Join([]string{finding.Title, finding.Summary, finding.RuleID, finding.PolicyID}, " "))
		if !strings.Contains(text, "vulnerab") && !strings.Contains(text, "cve-") && !strings.Contains(text, "package") {
			continue
		}
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:        fallback(finding.PolicyID, finding.RuleID, finding.ID),
			Title:     finding.Title,
			Severity:  finding.Severity,
			Status:    finding.Status,
			SourceID:  finding.SourceID,
			FindingID: finding.ID,
		})
	}
	return vulnerabilities
}

func ApplyFindingRisk(asset graphquery.InventoryAsset, findings []grcfindings.FindingItem, tests []TestItem, vulnerabilities []Vulnerability) graphquery.InventoryAsset {
	score := asset.RiskScore
	reasons := append([]string{}, asset.RiskReasons...)
	for _, finding := range findings {
		if int(finding.RiskScore) > score {
			score = int(finding.RiskScore)
		}
		if strings.EqualFold(finding.Status, "open") {
			reasons = append(reasons, "open finding")
		}
	}
	if FailingTests(tests) > 0 {
		score += 10
		reasons = append(reasons, "failing compliance tests")
	}
	if CriticalHighVulnerabilities(vulnerabilities) > 0 {
		score += 15
		reasons = append(reasons, "critical or high vulnerabilities")
	}
	if asset.ScopeState == ScopeStateOutScope {
		reasons = append(reasons, "out of GRC purview")
	}
	asset.RiskScore = ClampRisk(score)
	asset.RiskLevel = RiskLevel(asset.RiskScore)
	asset.RiskReasons = UniqueStrings(reasons)
	return asset
}

func Timeline(asset graphquery.InventoryAsset, findings []grcfindings.FindingItem, evidence []grcfindings.EvidenceItem, tests []TestItem, reports []*ports.GRCInventoryAssetReportRecord) []TimelineEvent {
	events := []TimelineEvent{}
	for _, key := range []string{"created_at", "first_seen_at"} {
		if at := ParseTime(asset.Attributes[key]); at != nil {
			events = append(events, TimelineEvent{At: at, Kind: "asset", Title: "Asset first observed", Status: "observed"})
			break
		}
	}
	for _, key := range []string{"updated_at", "last_seen_at", "last_synced_at"} {
		if at := ParseTime(asset.Attributes[key]); at != nil {
			events = append(events, TimelineEvent{At: at, Kind: "asset", Title: "Asset refreshed", Status: "observed"})
			break
		}
	}
	if asset.ScopeUpdatedAt != "" {
		events = append(events, TimelineEvent{At: ParseTime(asset.ScopeUpdatedAt), Kind: "scope", Title: "GRC purview updated", Description: asset.ScopeReason, Status: asset.ScopeState})
	}
	for _, report := range reports {
		if report == nil {
			continue
		}
		createdAt := report.CreatedAt.UTC()
		events = append(events, TimelineEvent{At: &createdAt, Kind: "asset_report", Title: "Asset reported for curation", Description: report.Reason, Status: report.TriageStatus})
		if report.TriagedAt != nil {
			events = append(events, TimelineEvent{At: report.TriagedAt, Kind: "asset_report", Title: "Asset report triaged", Description: report.TriageReason, Status: report.TriageStatus})
		}
	}
	for _, finding := range findings {
		events = append(events, TimelineEvent{At: finding.LastObservedAt, Kind: "finding", Title: finding.Title, Description: finding.ID, Status: finding.Status})
	}
	for _, item := range evidence {
		events = append(events, TimelineEvent{At: timePtr(item.CreatedAt), Kind: "evidence", Title: "Evidence attached", Description: item.ID, Status: "collected"})
	}
	for _, test := range tests {
		if test.DueAt != nil {
			events = append(events, TimelineEvent{At: test.DueAt, Kind: "test", Title: test.Name, Description: test.ControlID, Status: test.Status})
		}
	}
	sort.Slice(events, func(i, j int) bool {
		left, right := events[i].At, events[j].At
		if left == nil {
			return false
		}
		if right == nil {
			return true
		}
		return left.After(*right)
	})
	if len(events) > 25 {
		return events[:25]
	}
	return events
}

func Actions(asset graphquery.InventoryAsset, findings []grcfindings.FindingItem, controls []grcfindings.ControlItem, tests []TestItem, vulnerabilities []Vulnerability) []Action {
	ApplyReviewPosture(&asset)
	actions := []Action{}
	if asset.ScopeState == ScopeStateOutScope {
		actions = append(actions, Action{Title: "Confirm GRC purview", Description: "This asset is scoped out. Scope it back in if it should participate in controls, tests, and evidence review.", Priority: "high"})
	}
	if asset.Accountability != nil && asset.Accountability.State == AccountabilityRequired {
		actions = append(actions, Action{Title: "Assign accountable owner", Description: "Add ownership metadata for this GRC-relevant asset so evidence, findings, and remediation work have a responsible team.", Priority: "high"})
	}
	if CriticalHighVulnerabilities(vulnerabilities) > 0 {
		actions = append(actions, Action{Title: "Remediate critical or high vulnerabilities", Description: "Review linked findings and confirm active remediation plans for severe vulnerability exposure.", Priority: "high"})
	}
	if FailingTests(tests) > 0 {
		actions = append(actions, Action{Title: "Fix failing compliance tests", Description: "Prioritize failing or overdue tests mapped to this asset before audit evidence collection.", Priority: "medium"})
	}
	if len(controls) == 0 && len(findings) > 0 {
		actions = append(actions, Action{Title: "Map framework scope", Description: "Attach affected findings to framework controls to make audit impact explicit.", Priority: "medium"})
	}
	if len(actions) == 0 {
		actions = append(actions, Action{Title: "Keep monitoring", Description: "No immediate scope, accountability, vulnerability, or test gaps were detected for this asset.", Priority: "low"})
	}
	return actions
}

func FailingTests(tests []TestItem) int {
	count := 0
	for _, test := range tests {
		switch strings.ToLower(test.Status) {
		case "failing", "overdue", "open":
			count++
		}
	}
	return count
}

func CriticalHighVulnerabilities(items []Vulnerability) int {
	count := 0
	for _, item := range items {
		switch strings.ToUpper(item.Severity) {
		case "CRITICAL", "HIGH":
			count++
		}
	}
	return count
}

func ParseTime(value string) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, time.DateOnly} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			parsed = parsed.UTC()
			return &parsed
		}
	}
	return nil
}

func timePtr(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	value = value.UTC()
	return &value
}
