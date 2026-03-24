package graph

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultVendorRiskReportLimit          = 50
	defaultVendorRiskMonitoringWindowDays = 30
)

// VendorRiskReportOptions controls graph-backed vendor inventory reporting.
type VendorRiskReportOptions struct {
	MinRiskScore         int
	RiskLevels           []RiskLevel
	VerificationStatuses []string
	Categories           []string
	PermissionLevels     []string
	Limit                int
	IncludeAlerts        bool
	MonitoringWindow     time.Duration
}

// VendorRiskReport captures the current vendor inventory, derived risk posture,
// and any recent score/access changes observable in graph history.
type VendorRiskReport struct {
	GeneratedAt time.Time               `json:"generated_at"`
	Filters     VendorRiskReportFilters `json:"filters"`
	Summary     VendorRiskSummary       `json:"summary"`
	Count       int                     `json:"count"`
	TotalCount  int                     `json:"total_count"`
	Vendors     []VendorRiskRecord      `json:"vendors"`
	Alerts      []VendorRiskAlert       `json:"alerts,omitempty"`
}

// VendorRiskReportFilters echoes the effective report filter set.
type VendorRiskReportFilters struct {
	MinRiskScore         int      `json:"min_risk_score"`
	RiskLevels           []string `json:"risk_levels,omitempty"`
	VerificationStatuses []string `json:"verification_statuses,omitempty"`
	Categories           []string `json:"categories,omitempty"`
	PermissionLevels     []string `json:"permission_levels,omitempty"`
	Limit                int      `json:"limit"`
	IncludeAlerts        bool     `json:"include_alerts"`
	MonitoringWindowDays int      `json:"monitoring_window_days"`
}

// VendorRiskSummary provides roll-up counts over the full discovered inventory.
type VendorRiskSummary struct {
	VendorCount               int            `json:"vendor_count"`
	ReturnedCount             int            `json:"returned_count"`
	RiskCounts                map[string]int `json:"risk_counts,omitempty"`
	VerificationCounts        map[string]int `json:"verification_counts,omitempty"`
	CategoryCounts            map[string]int `json:"category_counts,omitempty"`
	PermissionCounts          map[string]int `json:"permission_counts,omitempty"`
	AverageRiskScore          float64        `json:"average_risk_score"`
	MaxRiskScore              int            `json:"max_risk_score"`
	TotalAccessibleResources  int            `json:"total_accessible_resources"`
	TotalSensitiveResources   int            `json:"total_sensitive_resources"`
	TotalDependentPrincipals  int            `json:"total_dependent_principals"`
	TotalDependentUsers       int            `json:"total_dependent_users"`
	TotalDependentGroups      int            `json:"total_dependent_groups"`
	TotalDependentSvcAccounts int            `json:"total_dependent_service_accounts"`
	AlertCount                int            `json:"alert_count"`
}

// VendorRiskRecord describes one auto-discovered third-party integration.
type VendorRiskRecord struct {
	VendorID                       string             `json:"vendor_id"`
	Name                           string             `json:"name"`
	RiskLevel                      RiskLevel          `json:"risk_level"`
	RiskScore                      int                `json:"risk_score"`
	VendorCategory                 string             `json:"vendor_category,omitempty"`
	VerificationStatus             string             `json:"verification_status,omitempty"`
	PermissionLevel                string             `json:"permission_level,omitempty"`
	SourceProviders                []string           `json:"source_providers,omitempty"`
	IntegrationTypes               []string           `json:"integration_types,omitempty"`
	OwnerOrganizationIDs           []string           `json:"owner_organization_ids,omitempty"`
	AccessibleResourceKinds        []string           `json:"accessible_resource_kinds,omitempty"`
	VerifiedPublisherIDs           []string           `json:"verified_publisher_ids,omitempty"`
	VerifiedPublisherNames         []string           `json:"verified_publisher_names,omitempty"`
	Aliases                        []string           `json:"aliases,omitempty"`
	ManagedNodeCount               int                `json:"managed_node_count"`
	ManagedApplicationCount        int                `json:"managed_application_count"`
	ManagedServiceAccountCount     int                `json:"managed_service_account_count"`
	AccessibleResourceCount        int                `json:"accessible_resource_count"`
	SensitiveResourceCount         int                `json:"sensitive_resource_count"`
	ReadAccessCount                int                `json:"read_access_count"`
	WriteAccessCount               int                `json:"write_access_count"`
	AdminAccessCount               int                `json:"admin_access_count"`
	DependentPrincipalCount        int                `json:"dependent_principal_count"`
	DependentUserCount             int                `json:"dependent_user_count"`
	DependentGroupCount            int                `json:"dependent_group_count"`
	DependentServiceAccountCount   int                `json:"dependent_service_account_count"`
	DelegatedGrantCount            int                `json:"delegated_grant_count"`
	DelegatedAdminConsentCount     int                `json:"delegated_admin_consent_count"`
	DelegatedPrincipalConsentCount int                `json:"delegated_principal_consent_count"`
	DelegatedScopeCount            int                `json:"delegated_scope_count"`
	ActiveGrantCount               int                `json:"active_grant_count"`
	AdminGrantCount                int                `json:"admin_grant_count"`
	PrincipalGrantCount            int                `json:"principal_grant_count"`
	RecentOAuthActivityCount       int                `json:"recent_oauth_activity_count"`
	RecentOAuthAuthorizeCount      int                `json:"recent_oauth_authorize_event_count"`
	RecentOAuthRevokeCount         int                `json:"recent_oauth_revoke_event_count"`
	AnonymousApplicationCount      int                `json:"anonymous_application_count"`
	NativeApplicationCount         int                `json:"native_application_count"`
	VerifiedPublisherCount         int                `json:"verified_publisher_count"`
	UnverifiedIntegrationCount     int                `json:"unverified_integration_count"`
	AppRoleAssignmentRequiredCount int                `json:"app_role_assignment_required_count"`
	AppRoleAssignmentOptionalCount int                `json:"app_role_assignment_optional_count"`
	LastGrantUpdatedAt             *time.Time         `json:"last_grant_updated_at,omitempty"`
	LastOAuthActivityAt            *time.Time         `json:"last_oauth_activity_at,omitempty"`
	RiskDrivers                    []VendorRiskDriver `json:"risk_drivers,omitempty"`
}

// VendorRiskDriver summarizes one current risk signal contributing to the score.
type VendorRiskDriver struct {
	Type     string   `json:"type"`
	Severity Severity `json:"severity"`
	Summary  string   `json:"summary"`
	Value    int      `json:"value"`
}

// VendorRiskAlert surfaces one recent risk/access change for continuous monitoring.
type VendorRiskAlert struct {
	VendorID      string    `json:"vendor_id"`
	VendorName    string    `json:"vendor_name"`
	Type          string    `json:"type"`
	Severity      Severity  `json:"severity"`
	Summary       string    `json:"summary"`
	CurrentValue  float64   `json:"current_value,omitempty"`
	PreviousValue float64   `json:"previous_value,omitempty"`
	Delta         float64   `json:"delta,omitempty"`
	ObservedAt    time.Time `json:"observed_at"`
}

// BuildVendorRiskReport materializes a vendor inventory and derived risk
// assessment from the current graph state.
func BuildVendorRiskReport(g *Graph, opts VendorRiskReportOptions) VendorRiskReport {
	opts = normalizeVendorRiskReportOptions(opts)
	report := VendorRiskReport{
		GeneratedAt: time.Now().UTC(),
		Filters: VendorRiskReportFilters{
			MinRiskScore:         opts.MinRiskScore,
			RiskLevels:           riskLevelsToStrings(opts.RiskLevels),
			VerificationStatuses: append([]string(nil), opts.VerificationStatuses...),
			Categories:           append([]string(nil), opts.Categories...),
			PermissionLevels:     append([]string(nil), opts.PermissionLevels...),
			Limit:                opts.Limit,
			IncludeAlerts:        opts.IncludeAlerts,
			MonitoringWindowDays: int(opts.MonitoringWindow.Hours() / 24),
		},
		Summary: VendorRiskSummary{
			RiskCounts:         make(map[string]int),
			VerificationCounts: make(map[string]int),
			CategoryCounts:     make(map[string]int),
			PermissionCounts:   make(map[string]int),
		},
	}
	if g == nil {
		return report
	}

	allRecords := make([]VendorRiskRecord, 0)
	allAlerts := make([]VendorRiskAlert, 0)
	for _, node := range g.GetNodesByKind(NodeKindVendor) {
		if node == nil {
			continue
		}
		record := vendorRiskRecordFromNode(node)
		allRecords = append(allRecords, record)

		report.Summary.VendorCount++
		report.Summary.RiskCounts[string(record.RiskLevel)]++
		if record.VerificationStatus != "" {
			report.Summary.VerificationCounts[record.VerificationStatus]++
		}
		if record.VendorCategory != "" {
			report.Summary.CategoryCounts[record.VendorCategory]++
		}
		if record.PermissionLevel != "" {
			report.Summary.PermissionCounts[record.PermissionLevel]++
		}
		report.Summary.TotalAccessibleResources += record.AccessibleResourceCount
		report.Summary.TotalSensitiveResources += record.SensitiveResourceCount
		report.Summary.TotalDependentPrincipals += record.DependentPrincipalCount
		report.Summary.TotalDependentUsers += record.DependentUserCount
		report.Summary.TotalDependentGroups += record.DependentGroupCount
		report.Summary.TotalDependentSvcAccounts += record.DependentServiceAccountCount
		report.Summary.AverageRiskScore += float64(record.RiskScore)
		if record.RiskScore > report.Summary.MaxRiskScore {
			report.Summary.MaxRiskScore = record.RiskScore
		}

		if opts.IncludeAlerts {
			allAlerts = append(allAlerts, vendorRiskAlertsForNode(g, node, record, opts.MonitoringWindow)...)
		}
	}
	if report.Summary.VendorCount > 0 {
		report.Summary.AverageRiskScore = math.Round((report.Summary.AverageRiskScore/float64(report.Summary.VendorCount))*100) / 100
	}

	sortVendorRiskRecords(allRecords)
	sortVendorRiskAlerts(allAlerts)

	filtered := make([]VendorRiskRecord, 0, len(allRecords))
	for _, record := range allRecords {
		if !vendorRiskRecordMatches(record, opts) {
			continue
		}
		filtered = append(filtered, record)
	}
	report.TotalCount = len(filtered)
	if opts.Limit > 0 && len(filtered) > opts.Limit {
		filtered = filtered[:opts.Limit]
	}
	report.Count = len(filtered)
	report.Vendors = filtered
	report.Summary.ReturnedCount = report.Count

	if opts.IncludeAlerts {
		returnedSet := make(map[string]struct{}, len(filtered))
		for _, record := range filtered {
			returnedSet[record.VendorID] = struct{}{}
		}
		filteredAlerts := make([]VendorRiskAlert, 0, len(allAlerts))
		for _, alert := range allAlerts {
			if _, ok := returnedSet[alert.VendorID]; ok {
				filteredAlerts = append(filteredAlerts, alert)
			}
		}
		report.Alerts = filteredAlerts
		report.Summary.AlertCount = len(filteredAlerts)
	}
	return report
}

func normalizeVendorRiskReportOptions(opts VendorRiskReportOptions) VendorRiskReportOptions {
	if opts.MinRiskScore < 0 {
		opts.MinRiskScore = 0
	}
	if opts.MinRiskScore > 100 {
		opts.MinRiskScore = 100
	}
	if opts.Limit <= 0 {
		opts.Limit = defaultVendorRiskReportLimit
	}
	opts.RiskLevels = normalizeRiskLevels(opts.RiskLevels)
	opts.VerificationStatuses = normalizeVendorFilterStrings(opts.VerificationStatuses)
	opts.Categories = normalizeVendorFilterStrings(opts.Categories)
	opts.PermissionLevels = normalizeVendorFilterStrings(opts.PermissionLevels)
	if !opts.IncludeAlerts {
		opts.MonitoringWindow = 0
	} else if opts.MonitoringWindow <= 0 {
		opts.MonitoringWindow = defaultVendorRiskMonitoringWindowDays * 24 * time.Hour
	}
	return opts
}

func normalizeRiskLevels(values []RiskLevel) []RiskLevel {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[RiskLevel]struct{}, len(values))
	normalized := make([]RiskLevel, 0, len(values))
	for _, value := range values {
		level := RiskLevel(strings.ToLower(strings.TrimSpace(string(value))))
		switch level {
		case RiskCritical, RiskHigh, RiskMedium, RiskLow, RiskNone:
		default:
			continue
		}
		if _, ok := seen[level]; ok {
			continue
		}
		seen[level] = struct{}{}
		normalized = append(normalized, level)
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i] < normalized[j] })
	return normalized
}

func riskLevelsToStrings(values []RiskLevel) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

func normalizeVendorFilterStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}

func vendorRiskRecordFromNode(node *Node) VendorRiskRecord {
	record := VendorRiskRecord{
		VendorID:                       node.ID,
		Name:                           strings.TrimSpace(node.Name),
		RiskLevel:                      node.Risk,
		RiskScore:                      vendorPropertyInt(node, "vendor_risk_score"),
		VendorCategory:                 vendorPropertyString(node, "vendor_category"),
		VerificationStatus:             vendorPropertyString(node, "verification_status"),
		PermissionLevel:                vendorPropertyString(node, "permission_level"),
		SourceProviders:                vendorPropertyStrings(node, "source_providers"),
		IntegrationTypes:               vendorPropertyStrings(node, "integration_types"),
		OwnerOrganizationIDs:           vendorPropertyStrings(node, "owner_organization_ids"),
		AccessibleResourceKinds:        vendorPropertyStrings(node, "accessible_resource_kinds"),
		VerifiedPublisherIDs:           vendorPropertyStrings(node, "verified_publisher_ids"),
		VerifiedPublisherNames:         vendorPropertyStrings(node, "verified_publisher_names"),
		Aliases:                        vendorPropertyStrings(node, "aliases"),
		ManagedNodeCount:               vendorPropertyInt(node, "managed_node_count"),
		ManagedApplicationCount:        vendorPropertyInt(node, "managed_application_count"),
		ManagedServiceAccountCount:     vendorPropertyInt(node, "managed_service_account_count"),
		AccessibleResourceCount:        vendorPropertyInt(node, "accessible_resource_count"),
		SensitiveResourceCount:         vendorPropertyInt(node, "sensitive_resource_count"),
		ReadAccessCount:                vendorPropertyInt(node, "read_access_count"),
		WriteAccessCount:               vendorPropertyInt(node, "write_access_count"),
		AdminAccessCount:               vendorPropertyInt(node, "admin_access_count"),
		DependentPrincipalCount:        vendorPropertyInt(node, "dependent_principal_count"),
		DependentUserCount:             vendorPropertyInt(node, "dependent_user_count"),
		DependentGroupCount:            vendorPropertyInt(node, "dependent_group_count"),
		DependentServiceAccountCount:   vendorPropertyInt(node, "dependent_service_account_count"),
		DelegatedGrantCount:            vendorPropertyInt(node, "delegated_grant_count"),
		DelegatedAdminConsentCount:     vendorPropertyInt(node, "delegated_admin_consent_count"),
		DelegatedPrincipalConsentCount: vendorPropertyInt(node, "delegated_principal_consent_count"),
		DelegatedScopeCount:            vendorPropertyInt(node, "delegated_scope_count"),
		ActiveGrantCount:               vendorPropertyInt(node, "active_grant_count"),
		AdminGrantCount:                vendorPropertyInt(node, "admin_grant_count"),
		PrincipalGrantCount:            vendorPropertyInt(node, "principal_grant_count"),
		RecentOAuthActivityCount:       vendorPropertyInt(node, "recent_oauth_activity_count"),
		RecentOAuthAuthorizeCount:      vendorPropertyInt(node, "recent_oauth_authorize_event_count"),
		RecentOAuthRevokeCount:         vendorPropertyInt(node, "recent_oauth_revoke_event_count"),
		AnonymousApplicationCount:      vendorPropertyInt(node, "anonymous_application_count"),
		NativeApplicationCount:         vendorPropertyInt(node, "native_application_count"),
		VerifiedPublisherCount:         vendorPropertyInt(node, "verified_publisher_count"),
		UnverifiedIntegrationCount:     vendorPropertyInt(node, "unverified_integration_count"),
		AppRoleAssignmentRequiredCount: vendorPropertyInt(node, "app_role_assignment_required_count"),
		AppRoleAssignmentOptionalCount: vendorPropertyInt(node, "app_role_assignment_optional_count"),
		LastGrantUpdatedAt:             vendorPropertyTime(node, "last_grant_updated_at"),
		LastOAuthActivityAt:            vendorPropertyTime(node, "last_oauth_activity_at"),
	}
	record.RiskDrivers = vendorRiskDrivers(record)
	if record.RiskLevel == "" {
		record.RiskLevel = vendorRiskLevelFromScore(record.RiskScore)
	}
	return record
}

func sortVendorRiskRecords(records []VendorRiskRecord) {
	sort.Slice(records, func(i, j int) bool {
		left := records[i]
		right := records[j]
		switch {
		case left.RiskScore != right.RiskScore:
			return left.RiskScore > right.RiskScore
		case left.SensitiveResourceCount != right.SensitiveResourceCount:
			return left.SensitiveResourceCount > right.SensitiveResourceCount
		case left.AdminAccessCount != right.AdminAccessCount:
			return left.AdminAccessCount > right.AdminAccessCount
		default:
			return left.Name < right.Name
		}
	})
}

func sortVendorRiskAlerts(alerts []VendorRiskAlert) {
	sort.Slice(alerts, func(i, j int) bool {
		left := alerts[i]
		right := alerts[j]
		if !left.ObservedAt.Equal(right.ObservedAt) {
			return left.ObservedAt.After(right.ObservedAt)
		}
		if left.Severity != right.Severity {
			return vendorAlertSeverityRank(left.Severity) > vendorAlertSeverityRank(right.Severity)
		}
		if left.Delta != right.Delta {
			return left.Delta > right.Delta
		}
		return left.VendorID < right.VendorID
	})
}

func vendorRiskRecordMatches(record VendorRiskRecord, opts VendorRiskReportOptions) bool {
	if record.RiskScore < opts.MinRiskScore {
		return false
	}
	if len(opts.RiskLevels) > 0 {
		match := false
		for _, level := range opts.RiskLevels {
			if record.RiskLevel == level {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	if len(opts.VerificationStatuses) > 0 && !containsVendorFilterValue(opts.VerificationStatuses, record.VerificationStatus) {
		return false
	}
	if len(opts.Categories) > 0 && !containsVendorFilterValue(opts.Categories, record.VendorCategory) {
		return false
	}
	if len(opts.PermissionLevels) > 0 && !containsVendorFilterValue(opts.PermissionLevels, record.PermissionLevel) {
		return false
	}
	return true
}

func containsVendorFilterValue(values []string, current string) bool {
	current = strings.ToLower(strings.TrimSpace(current))
	for _, value := range values {
		if current == strings.ToLower(strings.TrimSpace(value)) {
			return true
		}
	}
	return false
}

func vendorRiskDrivers(record VendorRiskRecord) []VendorRiskDriver {
	drivers := make([]VendorRiskDriver, 0, 6)
	if record.AdminAccessCount > 0 {
		drivers = append(drivers, VendorRiskDriver{Type: "admin_access", Severity: SeverityHigh, Summary: "Vendor has admin-level access to managed resources.", Value: record.AdminAccessCount})
	}
	if record.SensitiveResourceCount > 0 {
		severity := SeverityMedium
		if record.SensitiveResourceCount > 1 {
			severity = SeverityHigh
		}
		drivers = append(drivers, VendorRiskDriver{Type: "sensitive_data_access", Severity: severity, Summary: "Vendor can reach sensitive resources in the graph.", Value: record.SensitiveResourceCount})
	}
	if record.DelegatedAdminConsentCount > 0 {
		drivers = append(drivers, VendorRiskDriver{Type: "delegated_admin_consent", Severity: SeverityHigh, Summary: "Vendor holds delegated admin consent grants.", Value: record.DelegatedAdminConsentCount})
	}
	if record.UnverifiedIntegrationCount > 0 {
		drivers = append(drivers, VendorRiskDriver{Type: "unverified_integration", Severity: SeverityMedium, Summary: "Vendor inventory includes unverified integrations.", Value: record.UnverifiedIntegrationCount})
	}
	if record.DependentPrincipalCount > 0 {
		drivers = append(drivers, VendorRiskDriver{Type: "dependency_breadth", Severity: SeverityLow, Summary: "Internal principals depend on this vendor integration.", Value: record.DependentPrincipalCount})
	}
	if record.AnonymousApplicationCount > 0 {
		drivers = append(drivers, VendorRiskDriver{Type: "anonymous_application", Severity: SeverityMedium, Summary: "Vendor inventory includes anonymous/public client applications.", Value: record.AnonymousApplicationCount})
	}
	sort.Slice(drivers, func(i, j int) bool {
		if drivers[i].Severity != drivers[j].Severity {
			return vendorAlertSeverityRank(drivers[i].Severity) > vendorAlertSeverityRank(drivers[j].Severity)
		}
		if drivers[i].Value != drivers[j].Value {
			return drivers[i].Value > drivers[j].Value
		}
		return drivers[i].Type < drivers[j].Type
	})
	return drivers
}

func vendorRiskAlertsForNode(g *Graph, node *Node, record VendorRiskRecord, window time.Duration) []VendorRiskAlert {
	if g == nil || node == nil || window <= 0 {
		return nil
	}
	alerts := make([]VendorRiskAlert, 0, 5)
	if alert, ok := vendorChangeAlert(g, node, record, "vendor_risk_score", float64(record.RiskScore), "risk_score_increase", "Vendor risk score increased over the monitoring window.", vendorRiskScoreAlertSeverity(record.RiskScore), window); ok {
		alerts = append(alerts, alert)
	}
	if alert, ok := vendorChangeAlert(g, node, record, "admin_access_count", float64(record.AdminAccessCount), "admin_access_expansion", "Vendor gained additional admin-level reach.", SeverityHigh, window); ok {
		alerts = append(alerts, alert)
	}
	if alert, ok := vendorChangeAlert(g, node, record, "sensitive_resource_count", float64(record.SensitiveResourceCount), "sensitive_resource_expansion", "Vendor gained access to additional sensitive resources.", SeverityHigh, window); ok {
		alerts = append(alerts, alert)
	}
	if alert, ok := vendorChangeAlert(g, node, record, "delegated_admin_consent_count", float64(record.DelegatedAdminConsentCount), "delegated_admin_consent_growth", "Vendor gained additional delegated admin consent grants.", SeverityHigh, window); ok {
		alerts = append(alerts, alert)
	}
	if alert, ok := vendorChangeAlert(g, node, record, "unverified_integration_count", float64(record.UnverifiedIntegrationCount), "unverified_integration_growth", "Vendor accumulated more unverified integrations.", SeverityMedium, window); ok {
		alerts = append(alerts, alert)
	}
	if record.UnverifiedIntegrationCount > 0 {
		now := time.Now().UTC()
		alerts = append(alerts, VendorRiskAlert{
			VendorID:      record.VendorID,
			VendorName:    record.Name,
			Type:          "unverified_integration_present",
			Severity:      SeverityMedium,
			Summary:       "Vendor currently has one or more unverified integrations.",
			CurrentValue:  float64(record.UnverifiedIntegrationCount),
			PreviousValue: 0,
			Delta:         float64(record.UnverifiedIntegrationCount),
			ObservedAt:    vendorAlertObservedAt(record.LastGrantUpdatedAt, record.LastOAuthActivityAt, &now),
		})
	}
	sortVendorRiskAlerts(alerts)
	return alerts
}

func vendorChangeAlert(g *Graph, node *Node, record VendorRiskRecord, property string, current float64, alertType, summary string, severity Severity, window time.Duration) (VendorRiskAlert, bool) {
	previous, observedAt, ok := vendorPreviousNumericProperty(g, node.ID, property, current, window)
	if !ok || current <= previous {
		return VendorRiskAlert{}, false
	}
	return VendorRiskAlert{
		VendorID:      record.VendorID,
		VendorName:    record.Name,
		Type:          alertType,
		Severity:      severity,
		Summary:       summary,
		CurrentValue:  current,
		PreviousValue: previous,
		Delta:         current - previous,
		ObservedAt:    observedAt,
	}, true
}

func vendorPreviousNumericProperty(g *Graph, nodeID, property string, current float64, window time.Duration) (float64, time.Time, bool) {
	history := g.GetNodePropertyHistory(nodeID, property, window)
	if len(history) == 0 {
		return 0, time.Time{}, false
	}
	approxCurrent := false
	for i := len(history) - 1; i >= 0; i-- {
		value, ok := vendorAnyFloat(history[i].Value)
		if !ok {
			continue
		}
		if !approxCurrent && floatsEqual(value, current) {
			approxCurrent = true
			continue
		}
		return value, history[i].Timestamp.UTC(), true
	}
	if len(history) == 1 {
		value, ok := vendorAnyFloat(history[0].Value)
		if ok && !floatsEqual(value, current) {
			return value, history[0].Timestamp.UTC(), true
		}
	}
	return 0, time.Time{}, false
}

func vendorRiskScoreAlertSeverity(score int) Severity {
	switch {
	case score >= 70:
		return SeverityHigh
	case score >= 40:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

func vendorAlertObservedAt(times ...*time.Time) time.Time {
	best := time.Time{}
	for _, value := range times {
		if value == nil || value.IsZero() {
			continue
		}
		if best.IsZero() || value.After(best) {
			best = value.UTC()
		}
	}
	if best.IsZero() {
		best = time.Now().UTC()
	}
	return best
}

func vendorRiskLevelFromScore(score int) RiskLevel {
	switch {
	case score >= 70:
		return RiskHigh
	case score >= 40:
		return RiskMedium
	case score > 0:
		return RiskLow
	default:
		return RiskNone
	}
}

func vendorAlertSeverityRank(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

func vendorPropertyString(node *Node, key string) string {
	if node == nil {
		return ""
	}
	value, ok := node.PropertyValue(key)
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func vendorPropertyStrings(node *Node, key string) []string {
	if node == nil {
		return nil
	}
	value, ok := node.PropertyValue(key)
	if !ok || value == nil {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			text := strings.TrimSpace(fmt.Sprint(item))
			if text != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		text := strings.TrimSpace(fmt.Sprint(value))
		if text == "" {
			return nil
		}
		return []string{text}
	}
}

func vendorPropertyInt(node *Node, key string) int {
	if node == nil {
		return 0
	}
	value, ok := node.PropertyValue(key)
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case int:
		return typed
	case int8:
		return int(typed)
	case int16:
		return int(typed)
	case int32:
		return int(typed)
	case int64:
		return clampInt64ToInt(typed)
	case uint:
		return clampUint64ToInt(uint64(typed))
	case uint8:
		return int(typed)
	case uint16:
		return int(typed)
	case uint32:
		return clampUint64ToInt(uint64(typed))
	case uint64:
		return clampUint64ToInt(typed)
	case float32:
		return int(typed)
	case float64:
		return int(typed)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err == nil {
			return parsed
		}
	}
	return 0
}

func clampInt64ToInt(value int64) int {
	const maxInt = int(^uint(0) >> 1)
	const minInt = -maxInt - 1
	if value > int64(maxInt) {
		return maxInt
	}
	if value < int64(minInt) {
		return minInt
	}
	return int(value)
}

func clampUint64ToInt(value uint64) int {
	const maxInt = int(^uint(0) >> 1)
	if value > uint64(maxInt) {
		return maxInt
	}
	return int(value)
}

func vendorPropertyTime(node *Node, key string) *time.Time {
	if node == nil {
		return nil
	}
	value, ok := node.PropertyValue(key)
	if !ok || value == nil {
		return nil
	}
	switch typed := value.(type) {
	case time.Time:
		copy := typed.UTC()
		return &copy
	case *time.Time:
		if typed == nil || typed.IsZero() {
			return nil
		}
		copy := typed.UTC()
		return &copy
	case string:
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(typed))
		if err != nil {
			return nil
		}
		copy := parsed.UTC()
		return &copy
	default:
		return nil
	}
}

func vendorAnyFloat(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int8:
		return float64(typed), true
	case int16:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case uint:
		return float64(typed), true
	case uint8:
		return float64(typed), true
	case uint16:
		return float64(typed), true
	case uint32:
		return float64(typed), true
	case uint64:
		return float64(typed), true
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		if err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func floatsEqual(left, right float64) bool {
	return math.Abs(left-right) < 0.0001
}
