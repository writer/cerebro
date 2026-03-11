package identity

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/policy"
)

// StaleAccessDetector identifies unused or orphaned access
type StaleAccessDetector struct {
	thresholds StaleThresholds
}

// StaleThresholds configures detection parameters
type StaleThresholds struct {
	InactiveDays      int // Days since last login to consider stale
	UnusedKeyDays     int // Days since access key last used
	OrphanedCheckDays int // Days to check for orphaned accounts
	PrivilegedDays    int // Stricter threshold for privileged accounts
}

// DefaultThresholds returns sensible defaults
func DefaultThresholds() StaleThresholds {
	return StaleThresholds{
		InactiveDays:      90,
		UnusedKeyDays:     90,
		OrphanedCheckDays: 30,
		PrivilegedDays:    30,
	}
}

func NewStaleAccessDetector(thresholds StaleThresholds) *StaleAccessDetector {
	return &StaleAccessDetector{thresholds: thresholds}
}

// StaleAccessFinding represents a detected stale access issue
type StaleAccessFinding struct {
	ID           string                 `json:"id"`
	Type         StaleAccessType        `json:"type"`
	Severity     string                 `json:"severity"`
	Principal    Principal              `json:"principal"`
	Provider     string                 `json:"provider"`
	Account      string                 `json:"account"`
	LastActivity *time.Time             `json:"last_activity,omitempty"`
	DaysSince    int                    `json:"days_since"`
	Details      string                 `json:"details"`
	Remediation  string                 `json:"remediation"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

type StaleAccessType string

const (
	StaleAccessInactiveUser        StaleAccessType = "inactive_user"
	StaleAccessUnusedAccessKey     StaleAccessType = "unused_access_key"
	StaleAccessOrphanedAccount     StaleAccessType = "orphaned_account"
	StaleAccessStaleServiceAccount StaleAccessType = "stale_service_account"
	StaleAccessUnusedRole          StaleAccessType = "unused_role"
	StaleAccessExcessivePrivilege  StaleAccessType = "excessive_privilege"
)

// ToPolicyFinding converts identity stale-access findings into the platform's
// canonical policy finding format for persistence and downstream remediation.
func (f StaleAccessFinding) ToPolicyFinding() policy.Finding {
	policyID, policyName := staleAccessPolicyMetadata(f.Type)
	severity := strings.ToLower(strings.TrimSpace(f.Severity))
	if severity == "" {
		severity = "medium"
	}

	resource := map[string]interface{}{
		"stale_access_type": string(f.Type),
		"principal_id":      f.Principal.ID,
		"principal_name":    f.Principal.Name,
		"principal_email":   f.Principal.Email,
		"principal_type":    f.Principal.Type,
		"provider":          f.Provider,
		"account":           f.Account,
		"days_since":        f.DaysSince,
	}
	if f.LastActivity != nil {
		resource["last_activity"] = f.LastActivity.UTC().Format(time.RFC3339)
	}
	for key, value := range f.Metadata {
		resource[key] = value
	}

	resourceID := strings.TrimSpace(f.Principal.ID)
	if resourceID == "" {
		resourceID = strings.TrimSpace(f.ID)
	}
	resourceName := strings.TrimSpace(f.Principal.Name)
	if resourceName == "" {
		resourceName = strings.TrimSpace(f.Principal.Email)
	}

	riskCategories := []string{"identity", "stale_access"}
	switch f.Type {
	case StaleAccessExcessivePrivilege:
		riskCategories = append(riskCategories, "over_privileged")
	case StaleAccessUnusedAccessKey:
		riskCategories = append(riskCategories, "credential_hygiene")
	case StaleAccessOrphanedAccount:
		riskCategories = append(riskCategories, "orphaned_identity")
	case StaleAccessStaleServiceAccount:
		riskCategories = append(riskCategories, "service_account_hygiene")
	default:
		riskCategories = append(riskCategories, "inactive_identity")
	}

	return policy.Finding{
		ID:             "identity-" + f.ID,
		PolicyID:       policyID,
		PolicyName:     policyName,
		Title:          policyName,
		Severity:       severity,
		Description:    f.Details,
		Remediation:    f.Remediation,
		Resource:       resource,
		ResourceType:   "identity/" + f.Principal.Type,
		ResourceID:     resourceID,
		ResourceName:   resourceName,
		RiskCategories: riskCategories,
	}
}

func staleAccessPolicyMetadata(findingType StaleAccessType) (string, string) {
	switch findingType {
	case StaleAccessInactiveUser:
		return "identity-stale-inactive-user", "Inactive Identity Account"
	case StaleAccessUnusedAccessKey:
		return "identity-unused-access-key", "Unused Access Key"
	case StaleAccessOrphanedAccount:
		return "identity-orphaned-account", "Orphaned Identity Account"
	case StaleAccessStaleServiceAccount:
		return "identity-stale-service-account", "Stale Service Account"
	case StaleAccessUnusedRole:
		return "identity-unused-role", "Unused Identity Role"
	case StaleAccessExcessivePrivilege:
		return "identity-excessive-privilege", "Excessive Privilege Assignment"
	default:
		return "identity-stale-access", "Identity Stale Access"
	}
}

// DetectStaleUsers finds users with no recent login activity
func (d *StaleAccessDetector) DetectStaleUsers(ctx context.Context, users []map[string]interface{}) []StaleAccessFinding {
	var findings []StaleAccessFinding
	now := time.Now()

	for _, user := range users {
		lastLogin := extractTime(user, "password_last_used", "last_login", "lastSignInDateTime")
		if lastLogin == nil {
			continue
		}

		daysSince := int(now.Sub(*lastLogin).Hours() / 24)
		threshold := d.thresholds.InactiveDays

		// Stricter threshold for admins
		if isPrivileged(user) {
			threshold = d.thresholds.PrivilegedDays
		}

		if daysSince > threshold {
			findings = append(findings, StaleAccessFinding{
				ID:           generateID("stale-user", user),
				Type:         StaleAccessInactiveUser,
				Severity:     severityForDays(daysSince, threshold),
				Principal:    extractPrincipal(user),
				Provider:     extractString(user, "provider", "_cq_source_name"),
				Account:      extractString(user, "account_id", "subscription_id", "project_id"),
				LastActivity: lastLogin,
				DaysSince:    daysSince,
				Details:      "User has not logged in for over " + itoa(daysSince) + " days",
				Remediation:  "Review if user still requires access. Disable or delete if no longer needed.",
			})
		}
	}

	return findings
}

// DetectUnusedAccessKeys finds access keys with no recent usage
func (d *StaleAccessDetector) DetectUnusedAccessKeys(ctx context.Context, credentials []map[string]interface{}) []StaleAccessFinding {
	var findings []StaleAccessFinding
	now := time.Now()

	for _, cred := range credentials {
		// Check access key 1
		if extractBool(cred, "access_key_1_active") {
			lastUsed := extractTime(cred, "access_key_1_last_used_date")
			if lastUsed != nil {
				daysSince := int(now.Sub(*lastUsed).Hours() / 24)
				if daysSince > d.thresholds.UnusedKeyDays {
					findings = append(findings, StaleAccessFinding{
						ID:           generateID("unused-key-1", cred),
						Type:         StaleAccessUnusedAccessKey,
						Severity:     "medium",
						Principal:    extractPrincipal(cred),
						Provider:     "aws",
						Account:      extractString(cred, "account_id"),
						LastActivity: lastUsed,
						DaysSince:    daysSince,
						Details:      "Access key 1 not used for " + itoa(daysSince) + " days",
						Remediation:  "Rotate or delete the unused access key.",
						Metadata:     map[string]interface{}{"key_number": 1},
					})
				}
			}
		}

		// Check access key 2
		if extractBool(cred, "access_key_2_active") {
			lastUsed := extractTime(cred, "access_key_2_last_used_date")
			if lastUsed != nil {
				daysSince := int(now.Sub(*lastUsed).Hours() / 24)
				if daysSince > d.thresholds.UnusedKeyDays {
					findings = append(findings, StaleAccessFinding{
						ID:           generateID("unused-key-2", cred),
						Type:         StaleAccessUnusedAccessKey,
						Severity:     "medium",
						Principal:    extractPrincipal(cred),
						Provider:     "aws",
						Account:      extractString(cred, "account_id"),
						LastActivity: lastUsed,
						DaysSince:    daysSince,
						Details:      "Access key 2 not used for " + itoa(daysSince) + " days",
						Remediation:  "Rotate or delete the unused access key.",
						Metadata:     map[string]interface{}{"key_number": 2},
					})
				}
			}
		}
	}

	return findings
}

// DetectOrphanedAccounts finds accounts that may belong to departed users
func (d *StaleAccessDetector) DetectOrphanedAccounts(ctx context.Context, users []map[string]interface{}, hrData []map[string]interface{}) []StaleAccessFinding {
	var findings []StaleAccessFinding

	// Build set of active employees from HR data
	activeEmployees := make(map[string]bool)
	for _, emp := range hrData {
		if email := extractString(emp, "email", "work_email"); email != "" {
			activeEmployees[email] = true
		}
	}

	// Find cloud users not in HR system
	for _, user := range users {
		email := extractString(user, "email", "user_principal_name", "mail")
		if email == "" {
			continue
		}

		// Skip service accounts
		if isServiceAccount(user) {
			continue
		}

		if !activeEmployees[email] {
			findings = append(findings, StaleAccessFinding{
				ID:          generateID("orphaned", user),
				Type:        StaleAccessOrphanedAccount,
				Severity:    "high",
				Principal:   extractPrincipal(user),
				Provider:    extractString(user, "provider", "_cq_source_name"),
				Account:     extractString(user, "account_id", "subscription_id", "project_id"),
				Details:     "User account may be orphaned - not found in HR system",
				Remediation: "Verify user employment status and disable if departed.",
			})
		}
	}

	return findings
}

// DetectStaleServiceAccounts finds service accounts with no recent activity
func (d *StaleAccessDetector) DetectStaleServiceAccounts(ctx context.Context, serviceAccounts []map[string]interface{}) []StaleAccessFinding {
	var findings []StaleAccessFinding
	now := time.Now()

	for _, sa := range serviceAccounts {
		lastAuth := extractTime(sa, "last_authenticated_time", "last_used")
		if lastAuth == nil {
			// If never used, check creation date
			created := extractTime(sa, "create_time", "created_at")
			if created != nil {
				daysSince := int(now.Sub(*created).Hours() / 24)
				if daysSince > d.thresholds.UnusedKeyDays {
					findings = append(findings, StaleAccessFinding{
						ID:          generateID("stale-sa", sa),
						Type:        StaleAccessStaleServiceAccount,
						Severity:    "medium",
						Principal:   extractPrincipal(sa),
						Provider:    extractString(sa, "provider", "_cq_source_name"),
						Account:     extractString(sa, "project_id", "account_id"),
						DaysSince:   daysSince,
						Details:     "Service account created " + itoa(daysSince) + " days ago but never used",
						Remediation: "Review if service account is still needed. Delete if unused.",
					})
				}
			}
			continue
		}

		daysSince := int(now.Sub(*lastAuth).Hours() / 24)
		if daysSince > d.thresholds.UnusedKeyDays {
			findings = append(findings, StaleAccessFinding{
				ID:           generateID("stale-sa", sa),
				Type:         StaleAccessStaleServiceAccount,
				Severity:     "medium",
				Principal:    extractPrincipal(sa),
				Provider:     extractString(sa, "provider", "_cq_source_name"),
				Account:      extractString(sa, "project_id", "account_id"),
				LastActivity: lastAuth,
				DaysSince:    daysSince,
				Details:      "Service account not used for " + itoa(daysSince) + " days",
				Remediation:  "Review if service account is still needed. Delete or disable if unused.",
			})
		}
	}

	return findings
}

// DetectExcessivePrivileges finds users/SAs with admin access who don't need it
func (d *StaleAccessDetector) DetectExcessivePrivileges(ctx context.Context, bindings []map[string]interface{}) []StaleAccessFinding {
	var findings []StaleAccessFinding

	adminRoles := map[string]bool{
		"roles/owner":  true,
		"roles/editor": true,
		"arn:aws:iam::aws:policy/AdministratorAccess": true,
		"Owner":       true,
		"Contributor": true,
	}

	for _, binding := range bindings {
		role := extractString(binding, "role", "role_name", "role_definition_name")
		if !adminRoles[role] {
			continue
		}

		// Check if this is a service account with broad admin
		principal := extractPrincipal(binding)
		if principal.Type == "service_account" {
			findings = append(findings, StaleAccessFinding{
				ID:          generateID("excessive-priv", binding),
				Type:        StaleAccessExcessivePrivilege,
				Severity:    "high",
				Principal:   principal,
				Provider:    extractString(binding, "provider", "_cq_source_name"),
				Account:     extractString(binding, "project_id", "account_id"),
				Details:     "Service account has admin-level role: " + role,
				Remediation: "Replace broad admin role with specific, least-privilege roles.",
				Metadata:    map[string]interface{}{"role": role},
			})
		}
	}

	return findings
}

// Helper functions

func extractTime(m map[string]interface{}, keys ...string) *time.Time {
	for _, key := range keys {
		if val, ok := m[key]; ok {
			switch v := val.(type) {
			case time.Time:
				return &v
			case *time.Time:
				return v
			case string:
				if t, err := time.Parse(time.RFC3339, v); err == nil {
					return &t
				}
			}
		}
	}
	return nil
}

func extractString(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if val, ok := m[key].(string); ok && val != "" {
			return val
		}
	}
	return ""
}

func extractBool(m map[string]interface{}, keys ...string) bool {
	for _, key := range keys {
		if val, ok := m[key]; ok {
			switch typed := val.(type) {
			case bool:
				return typed
			case string:
				return typed == "true" || typed == "TRUE"
			}
		}
	}
	return false
}

func extractPrincipal(m map[string]interface{}) Principal {
	p := Principal{
		ID:    extractString(m, "arn", "id", "unique_id", "object_id"),
		Name:  extractString(m, "user_name", "name", "display_name", "email"),
		Email: extractString(m, "email", "user_principal_name", "mail"),
		Type:  "user",
	}

	// Detect service accounts
	if isServiceAccount(m) {
		p.Type = "service_account"
	}

	return p
}

func isServiceAccount(m map[string]interface{}) bool {
	// AWS
	if path, ok := m["path"].(string); ok && path == "/" {
		if name := extractString(m, "user_name"); name != "" {
			// Service accounts often have specific naming patterns
			return false // AWS doesn't have distinct SA concept like GCP
		}
	}

	// GCP
	if email := extractString(m, "email"); email != "" {
		if len(email) > 30 && contains(email, ".iam.gserviceaccount.com") {
			return true
		}
	}

	// Azure
	if spType := extractString(m, "service_principal_type"); spType == "Application" {
		return true
	}

	return false
}

func isPrivileged(m map[string]interface{}) bool {
	// Check for admin policies
	if policies, ok := m["attached_policies"].([]interface{}); ok {
		for _, p := range policies {
			if ps, ok := p.(string); ok {
				if contains(ps, "Admin") || contains(ps, "FullAccess") {
					return true
				}
			}
		}
	}

	// Check for admin groups
	if groups, ok := m["groups"].([]interface{}); ok {
		for _, g := range groups {
			if gs, ok := g.(string); ok {
				if contains(gs, "admin") || contains(gs, "Admin") {
					return true
				}
			}
		}
	}

	return false
}

func severityForDays(actual, threshold int) string {
	ratio := float64(actual) / float64(threshold)
	if ratio > 3 {
		return "high"
	}
	if ratio > 2 {
		return "medium"
	}
	return "low"
}

func generateID(prefix string, m map[string]interface{}) string {
	id := extractString(m, "arn", "id", "unique_id", "object_id", "_cq_id")
	if id == "" {
		id = extractString(m, "user_name", "name", "email")
	}
	return prefix + "-" + id
}

func itoa(i int) string {
	return strconv.Itoa(i)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
