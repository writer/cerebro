package grcinventory

import (
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/ports"
)

const (
	ScopeStateInScope  = ports.GRCInventoryScopeStateIn
	ScopeStateOutScope = ports.GRCInventoryScopeStateOut

	ReviewBaseline      = "baseline"
	ReviewNeedsReview   = "needs_review"
	ReviewOutOfScope    = "out_of_scope"
	ReviewReportedIssue = "reported_issue"

	AccountabilityKnown    = "known"
	AccountabilityRequired = "required_missing"
	AccountabilityNone     = "not_required"
)

type Summary struct {
	TotalAssets         int `json:"total_assets"`
	InScopeAssets       int `json:"in_scope_assets"`
	OutOfScopeAssets    int `json:"out_of_scope_assets"`
	HighRiskAssets      int `json:"high_risk_assets"`
	UnassignedAssets    int `json:"unassigned_assets"`
	BaselineAssets      int `json:"baseline_assets"`
	NeedsReviewAssets   int `json:"needs_review_assets"`
	OwnerRequiredAssets int `json:"owner_required_assets"`
	AccountableAssets   int `json:"accountable_assets"`
	ReportedIssueAssets int `json:"reported_issue_assets"`
	OrgGroups           int `json:"org_groups"`
	PublicAssets        int `json:"public_assets"`
	ScopedCoveragePct   int `json:"scoped_coverage_pct"`
	AssignedCoveragePct int `json:"assigned_coverage_pct"`
}

func ApplyScope(asset *graphquery.InventoryAsset, record *ports.GRCInventoryScopeRecord) {
	if asset == nil {
		return
	}
	if strings.TrimSpace(asset.ScopeState) == "" {
		asset.ScopeState = ScopeStateInScope
	}
	if record == nil {
		return
	}
	asset.ScopeState = record.ScopeState
	asset.ScopeReason = record.Reason
	if !record.UpdatedAt.IsZero() {
		asset.ScopeUpdatedAt = record.UpdatedAt.UTC().Format(time.RFC3339)
	}
}

func ApplyAssetReportSummary(asset *graphquery.InventoryAsset, summary *ports.GRCInventoryAssetReportSummary) {
	if asset == nil || summary == nil {
		return
	}
	asset.AssetReportCount = summary.ReportCount
	asset.LatestAssetReportStatus = summary.TriageStatus
	asset.LatestAssetReportReason = summary.Reason
	if !summary.UpdatedAt.IsZero() {
		asset.LatestAssetReportUpdatedAt = summary.UpdatedAt.UTC().Format(time.RFC3339)
	}
}

func ApplyReviewPosture(asset *graphquery.InventoryAsset) {
	if asset == nil {
		return
	}
	if strings.TrimSpace(asset.ScopeState) == "" {
		asset.ScopeState = ScopeStateInScope
	}
	owner := AssetOwnerPrincipal(*asset)
	accountabilityReasons := accountabilityReasons(*asset)
	if asset.ScopeState == ScopeStateOutScope {
		reason := graphquery.InventoryReviewReason{Code: "scope_exclusion", Label: "Scoped out of GRC review"}
		asset.ReviewDisposition = &graphquery.InventoryReviewDisposition{
			State:   ReviewOutOfScope,
			Label:   "Scoped out",
			Detail:  fallback(asset.ScopeReason, "Excluded from controls, evidence collection, and review until scoped back in."),
			Reasons: []graphquery.InventoryReviewReason{reason},
		}
		asset.Accountability = &graphquery.InventoryAccountability{
			State:   AccountabilityNone,
			Label:   "Owner not required",
			Reasons: []graphquery.InventoryReviewReason{reason},
		}
		return
	}

	if owner != "" {
		asset.Accountability = &graphquery.InventoryAccountability{
			State:     AccountabilityKnown,
			Label:     "Owner known",
			Principal: owner,
		}
	} else if ownerRequired(*asset) {
		asset.Accountability = &graphquery.InventoryAccountability{
			State:   AccountabilityRequired,
			Label:   "Owner required",
			Reasons: accountabilityReasons,
		}
	} else {
		asset.Accountability = &graphquery.InventoryAccountability{
			State:   AccountabilityNone,
			Label:   "Owner not required",
			Reasons: []graphquery.InventoryReviewReason{{Code: "baseline_no_action", Label: "No active GRC action"}},
		}
	}

	if hasActiveReport(*asset) {
		asset.ReviewDisposition = &graphquery.InventoryReviewDisposition{
			State:   ReviewReportedIssue,
			Label:   "Reported issue",
			Detail:  fallback(asset.LatestAssetReportReason, "A reviewer reported this asset for triage."),
			Reasons: []graphquery.InventoryReviewReason{{Code: "reported_issue", Label: "Reviewer report"}},
		}
		return
	}
	if asset.Accountability != nil && asset.Accountability.State == AccountabilityRequired {
		asset.ReviewDisposition = &graphquery.InventoryReviewDisposition{
			State:   ReviewNeedsReview,
			Label:   "Needs review",
			Detail:  "GRC-relevant evidence indicates this asset needs an accountable owner.",
			Reasons: accountabilityReasons,
		}
		return
	}
	asset.ReviewDisposition = &graphquery.InventoryReviewDisposition{
		State:   ReviewBaseline,
		Label:   "Baseline",
		Detail:  "No immediate GRC action required.",
		Reasons: []graphquery.InventoryReviewReason{{Code: "baseline_no_action", Label: "No active GRC action"}},
	}
}

func FilterByScope(assets []graphquery.InventoryAsset, state string) []graphquery.InventoryAsset {
	state = strings.TrimSpace(state)
	if state == "" || state == "all" {
		return assets
	}
	filtered := make([]graphquery.InventoryAsset, 0, len(assets))
	for _, asset := range assets {
		assetState := strings.TrimSpace(asset.ScopeState)
		if assetState == "" {
			assetState = ScopeStateInScope
		}
		if assetState == state {
			filtered = append(filtered, asset)
		}
	}
	return filtered
}

func FilterByReviewDisposition(assets []graphquery.InventoryAsset, state string) []graphquery.InventoryAsset {
	state = strings.TrimSpace(state)
	if state == "" || state == "all" {
		return assets
	}
	filtered := make([]graphquery.InventoryAsset, 0, len(assets))
	for _, asset := range assets {
		ApplyReviewPosture(&asset)
		if asset.ReviewDisposition != nil && asset.ReviewDisposition.State == state {
			filtered = append(filtered, asset)
		}
	}
	return filtered
}

func FilterByAccountability(assets []graphquery.InventoryAsset, state string) []graphquery.InventoryAsset {
	state = strings.TrimSpace(state)
	if state == "" || state == "all" {
		return assets
	}
	filtered := make([]graphquery.InventoryAsset, 0, len(assets))
	for _, asset := range assets {
		ApplyReviewPosture(&asset)
		if asset.Accountability != nil && asset.Accountability.State == state {
			filtered = append(filtered, asset)
		}
	}
	return filtered
}

func Summarize(assets []graphquery.InventoryAsset) Summary {
	summary := Summary{TotalAssets: len(assets)}
	orgs := map[string]struct{}{}
	for _, asset := range assets {
		ApplyReviewPosture(&asset)
		state := strings.TrimSpace(asset.ScopeState)
		if state == ScopeStateInScope {
			summary.InScopeAssets++
		}
		if state == ScopeStateOutScope {
			summary.OutOfScopeAssets++
		}
		if asset.RiskScore >= 70 {
			summary.HighRiskAssets++
		}
		if AssetOwner(asset) == "Unassigned" {
			summary.UnassignedAssets++
		}
		if asset.ReviewDisposition != nil {
			switch asset.ReviewDisposition.State {
			case ReviewBaseline:
				summary.BaselineAssets++
			case ReviewNeedsReview:
				summary.NeedsReviewAssets++
			case ReviewReportedIssue:
				summary.ReportedIssueAssets++
			}
		}
		if asset.Accountability != nil {
			switch asset.Accountability.State {
			case AccountabilityKnown:
				summary.AccountableAssets++
			case AccountabilityRequired:
				summary.OwnerRequiredAssets++
			}
		}
		if AssetPublic(asset) {
			summary.PublicAssets++
		}
		if org := AssetOrg(asset); org != "" {
			orgs[org] = struct{}{}
		}
	}
	summary.OrgGroups = len(orgs)
	if summary.TotalAssets > 0 {
		summary.ScopedCoveragePct = int(float64(summary.InScopeAssets) / float64(summary.TotalAssets) * 100)
		summary.AssignedCoveragePct = int(float64(summary.TotalAssets-summary.UnassignedAssets) / float64(summary.TotalAssets) * 100)
	}
	return summary
}

func ClampRisk(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func RiskLevel(score int) string {
	switch {
	case score >= 85:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 40:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "unknown"
	}
}

func UniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func AssetOwner(asset graphquery.InventoryAsset) string {
	return fallback(AssetOwnerPrincipal(asset), "Unassigned")
}

func AssetOwnerPrincipal(asset graphquery.InventoryAsset) string {
	return fallback(asset.Attributes["owner"], asset.Attributes["owner_email"], asset.Attributes["assignee"], asset.Attributes["account_manager_email"], asset.Attributes["owner_login"])
}

func AssetOrg(asset graphquery.InventoryAsset) string {
	return fallback(asset.Attributes["org"], asset.Attributes["owner_login"], asset.Attributes["account_id"], asset.Attributes["project_id"], asset.SourceID)
}

func AssetPublic(asset graphquery.InventoryAsset) bool {
	return attributeTruthy(asset, "public", "publicly_accessible", "internet_exposed", "external")
}

func hasActiveReport(asset graphquery.InventoryAsset) bool {
	if asset.AssetReportCount <= 0 {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(asset.LatestAssetReportStatus)) {
	case ports.GRCInventoryAssetReportStatusRejected, ports.GRCInventoryAssetReportStatusResolved:
		return false
	default:
		return true
	}
}

func ownerRequired(asset graphquery.InventoryAsset) bool {
	if asset.ScopeState == ScopeStateOutScope || AssetOwnerPrincipal(asset) != "" {
		return false
	}
	if attributeTruthy(asset, "owner_required", "requires_owner", "accountability_required") {
		return true
	}
	return asset.RiskScore >= 70 || AssetPublic(asset)
}

func accountabilityReasons(asset graphquery.InventoryAsset) []graphquery.InventoryReviewReason {
	reasons := []graphquery.InventoryReviewReason{}
	if asset.RiskScore >= 70 {
		reasons = append(reasons, graphquery.InventoryReviewReason{Code: "high_risk", Label: "High risk"})
	}
	if AssetPublic(asset) {
		reasons = append(reasons, graphquery.InventoryReviewReason{Code: "public_exposure", Label: "Public exposure"})
	}
	if attributeTruthy(asset, "owner_required", "requires_owner", "accountability_required") {
		reasons = append(reasons, graphquery.InventoryReviewReason{Code: "accountability_required", Label: "Accountability required"})
	}
	if len(reasons) == 0 {
		reasons = append(reasons, graphquery.InventoryReviewReason{Code: "accountability_missing", Label: "Owner missing where required"})
	}
	return reasons
}

func attributeTruthy(asset graphquery.InventoryAsset, keys ...string) bool {
	for _, key := range keys {
		switch strings.ToLower(strings.TrimSpace(asset.Attributes[key])) {
		case "1", "t", "true", "yes", "y":
			return true
		}
	}
	return false
}

func fallback(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
