package identity

import (
	"context"
	"sort"
	"time"
)

// AccessReport summarizes identity and access posture
type AccessReport struct {
	GeneratedAt      time.Time                `json:"generated_at"`
	Period           ReportPeriod             `json:"period"`
	Summary          ReportSummary            `json:"summary"`
	ByProvider       map[string]ProviderStats `json:"by_provider"`
	StaleAccess      StaleAccessSummary       `json:"stale_access"`
	PrivilegedUsers  []PrivilegedUserSummary  `json:"privileged_users"`
	RiskDistribution map[string]int           `json:"risk_distribution"`
	Recommendations  []string                 `json:"recommendations"`
}

type ReportPeriod struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type ReportSummary struct {
	TotalUsers           int `json:"total_users"`
	TotalServiceAccounts int `json:"total_service_accounts"`
	TotalRoles           int `json:"total_roles"`
	TotalGroups          int `json:"total_groups"`
	StaleUsersCount      int `json:"stale_users_count"`
	OrphanedCount        int `json:"orphaned_count"`
	ExcessivePrivCount   int `json:"excessive_priv_count"`
	RiskScore            int `json:"risk_score"` // 0-100
}

type ProviderStats struct {
	Provider        string `json:"provider"`
	Users           int    `json:"users"`
	ServiceAccounts int    `json:"service_accounts"`
	Roles           int    `json:"roles"`
	StaleUsers      int    `json:"stale_users"`
	UnusedKeys      int    `json:"unused_keys"`
}

type StaleAccessSummary struct {
	InactiveUsers     int `json:"inactive_users"`
	UnusedAccessKeys  int `json:"unused_access_keys"`
	OrphanedAccounts  int `json:"orphaned_accounts"`
	StaleServiceAccts int `json:"stale_service_accounts"`
	TotalFindings     int `json:"total_findings"`
}

type PrivilegedUserSummary struct {
	Principal    Principal  `json:"principal"`
	Provider     string     `json:"provider"`
	Roles        []string   `json:"roles"`
	LastActivity *time.Time `json:"last_activity,omitempty"`
	RiskScore    int        `json:"risk_score"`
}

// ReportGenerator creates access reports
type ReportGenerator struct {
	detector *StaleAccessDetector
}

func NewReportGenerator() *ReportGenerator {
	return &ReportGenerator{
		detector: NewStaleAccessDetector(DefaultThresholds()),
	}
}

// GenerateReport creates a comprehensive access report
func (g *ReportGenerator) GenerateReport(ctx context.Context, data IdentityData) (*AccessReport, error) {
	report := &AccessReport{
		GeneratedAt: time.Now().UTC(),
		Period: ReportPeriod{
			Start: time.Now().AddDate(0, 0, -90),
			End:   time.Now(),
		},
		ByProvider:       make(map[string]ProviderStats),
		RiskDistribution: make(map[string]int),
	}

	// Calculate summary stats
	report.Summary.TotalUsers = len(data.Users)
	report.Summary.TotalServiceAccounts = len(data.ServiceAccounts)
	report.Summary.TotalRoles = len(data.Roles)
	report.Summary.TotalGroups = len(data.Groups)

	// Detect stale access
	staleUsers := g.detector.DetectStaleUsers(ctx, data.Users)
	unusedKeys := g.detector.DetectUnusedAccessKeys(ctx, data.Credentials)
	orphaned := g.detector.DetectOrphanedAccounts(ctx, data.Users, data.HRData)
	staleSAs := g.detector.DetectStaleServiceAccounts(ctx, data.ServiceAccounts)
	excessivePriv := g.detector.DetectExcessivePrivileges(ctx, data.RoleBindings)

	report.StaleAccess = StaleAccessSummary{
		InactiveUsers:     len(staleUsers),
		UnusedAccessKeys:  len(unusedKeys),
		OrphanedAccounts:  len(orphaned),
		StaleServiceAccts: len(staleSAs),
		TotalFindings:     len(staleUsers) + len(unusedKeys) + len(orphaned) + len(staleSAs),
	}

	report.Summary.StaleUsersCount = len(staleUsers)
	report.Summary.OrphanedCount = len(orphaned)
	report.Summary.ExcessivePrivCount = len(excessivePriv)

	// Risk distribution
	allFindings := append(staleUsers, unusedKeys...)
	allFindings = append(allFindings, orphaned...)
	allFindings = append(allFindings, staleSAs...)
	allFindings = append(allFindings, excessivePriv...)

	for _, f := range allFindings {
		report.RiskDistribution[f.Severity]++
	}

	// Calculate risk score
	report.Summary.RiskScore = g.calculateRiskScore(report)

	// Provider breakdown
	for _, user := range data.Users {
		provider := extractString(user, "provider", "_cq_source_name")
		if provider == "" {
			provider = "unknown"
		}
		stats := report.ByProvider[provider]
		stats.Provider = provider
		stats.Users++
		report.ByProvider[provider] = stats
	}

	for _, sa := range data.ServiceAccounts {
		provider := extractString(sa, "provider", "_cq_source_name")
		if provider == "" {
			provider = "unknown"
		}
		stats := report.ByProvider[provider]
		stats.ServiceAccounts++
		report.ByProvider[provider] = stats
	}

	// Count stale by provider
	for _, f := range staleUsers {
		if stats, ok := report.ByProvider[f.Provider]; ok {
			stats.StaleUsers++
			report.ByProvider[f.Provider] = stats
		}
	}

	for _, f := range unusedKeys {
		if stats, ok := report.ByProvider[f.Provider]; ok {
			stats.UnusedKeys++
			report.ByProvider[f.Provider] = stats
		}
	}

	// Identify privileged users
	report.PrivilegedUsers = g.identifyPrivilegedUsers(data)

	// Generate recommendations
	report.Recommendations = g.generateRecommendations(report)

	return report, nil
}

func (g *ReportGenerator) calculateRiskScore(report *AccessReport) int {
	score := 0

	// Base score from findings
	score += report.RiskDistribution["critical"] * 20
	score += report.RiskDistribution["high"] * 10
	score += report.RiskDistribution["medium"] * 5
	score += report.RiskDistribution["low"] * 2

	// Adjust for scale
	if report.Summary.TotalUsers > 0 {
		staleRatio := float64(report.Summary.StaleUsersCount) / float64(report.Summary.TotalUsers)
		if staleRatio > 0.2 {
			score += 20
		} else if staleRatio > 0.1 {
			score += 10
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func (g *ReportGenerator) identifyPrivilegedUsers(data IdentityData) []PrivilegedUserSummary {
	privileged := make([]PrivilegedUserSummary, 0, len(data.Users)/10)

	for _, user := range data.Users {
		if !isPrivileged(user) {
			continue
		}

		summary := PrivilegedUserSummary{
			Principal:    extractPrincipal(user),
			Provider:     extractString(user, "provider", "_cq_source_name"),
			LastActivity: extractTime(user, "password_last_used", "last_login"),
			RiskScore:    0,
		}

		// Extract roles
		if roles, ok := user["attached_policies"].([]interface{}); ok {
			for _, r := range roles {
				if rs, ok := r.(string); ok {
					summary.Roles = append(summary.Roles, rs)
				}
			}
		}

		// Calculate individual risk score
		if summary.LastActivity != nil {
			daysSince := int(time.Since(*summary.LastActivity).Hours() / 24)
			if daysSince > 90 {
				summary.RiskScore = 80
			} else if daysSince > 30 {
				summary.RiskScore = 50
			} else {
				summary.RiskScore = 20
			}
		} else {
			summary.RiskScore = 60 // Unknown last activity is risky
		}

		privileged = append(privileged, summary)
	}

	// Sort by risk score descending
	sort.Slice(privileged, func(i, j int) bool {
		return privileged[i].RiskScore > privileged[j].RiskScore
	})

	// Return top 20
	if len(privileged) > 20 {
		privileged = privileged[:20]
	}

	return privileged
}

func (g *ReportGenerator) generateRecommendations(report *AccessReport) []string {
	var recs []string

	if report.StaleAccess.InactiveUsers > 10 {
		recs = append(recs, "Review and disable "+itoa(report.StaleAccess.InactiveUsers)+" inactive user accounts")
	}

	if report.StaleAccess.UnusedAccessKeys > 5 {
		recs = append(recs, "Rotate or delete "+itoa(report.StaleAccess.UnusedAccessKeys)+" unused access keys")
	}

	if report.StaleAccess.OrphanedAccounts > 0 {
		recs = append(recs, "Investigate "+itoa(report.StaleAccess.OrphanedAccounts)+" potentially orphaned accounts")
	}

	if report.Summary.ExcessivePrivCount > 0 {
		recs = append(recs, "Review "+itoa(report.Summary.ExcessivePrivCount)+" accounts with excessive privileges")
	}

	if report.Summary.RiskScore > 70 {
		recs = append(recs, "High identity risk score - prioritize access review campaign")
	}

	if len(report.PrivilegedUsers) > 0 {
		inactive := 0
		for _, p := range report.PrivilegedUsers {
			if p.RiskScore > 50 {
				inactive++
			}
		}
		if inactive > 0 {
			recs = append(recs, itoa(inactive)+" privileged users have not been active recently - verify access is still required")
		}
	}

	if len(recs) == 0 {
		recs = append(recs, "Identity posture is healthy - continue monitoring")
	}

	return recs
}

// IdentityData holds all identity information for analysis
type IdentityData struct {
	Users           []map[string]interface{}
	ServiceAccounts []map[string]interface{}
	Roles           []map[string]interface{}
	Groups          []map[string]interface{}
	Credentials     []map[string]interface{}
	RoleBindings    []map[string]interface{}
	HRData          []map[string]interface{} // For orphan detection
}
