// Package applicationworkspace owns application-workspace selector validation
// and tenant-qualified grant evaluation.
package applicationworkspace

import (
	"errors"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/writer/cerebro/internal/config"
)

const (
	Header             = "X-Cerebro-Workspace"
	maxSelectorIDBytes = 256
)

var ErrInvalidSelector = errors.New("invalid application workspace selector")

// Select reconciles the header and query selectors and validates the result.
func Select(headerValue, queryValue string) (string, error) {
	headerValue = strings.TrimSpace(headerValue)
	queryValue = strings.TrimSpace(queryValue)
	if headerValue != "" && queryValue != "" && headerValue != queryValue {
		return "", ErrInvalidSelector
	}
	workspaceID := queryValue
	if workspaceID == "" {
		workspaceID = headerValue
	}
	if workspaceID != "" && !ValidID(workspaceID) {
		return "", ErrInvalidSelector
	}
	return workspaceID, nil
}

// ValidID reports whether value is a single bounded opaque workspace ID.
func ValidID(value string) bool {
	if value == "" || len(value) > maxSelectorIDBytes || !utf8.ValidString(value) || value == "*" || strings.Contains(value, ",") {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

// Allowed preserves tenant-wide legacy access when no grants are configured.
func Allowed(grants []config.ApplicationWorkspaceGrant, tenantID, workspaceID string) bool {
	if workspaceID == "" || len(grants) == 0 {
		return true
	}
	for _, grant := range grants {
		if strings.TrimSpace(grant.TenantID) != tenantID {
			continue
		}
		for _, grantedID := range grant.ApplicationWorkspaceIDs {
			if grantedID == workspaceID {
				return true
			}
		}
	}
	return false
}

// NormalizeGrants validates, deduplicates, and sorts tenant-qualified grants.
func NormalizeGrants(grants []config.ApplicationWorkspaceGrant) ([]config.ApplicationWorkspaceGrant, bool) {
	if len(grants) == 0 {
		return nil, true
	}
	byTenant := make(map[string]map[string]struct{}, len(grants))
	for _, grant := range grants {
		tenantID := strings.TrimSpace(grant.TenantID)
		if tenantID == "" || len(grant.ApplicationWorkspaceIDs) == 0 {
			return nil, false
		}
		workspaceIDs := byTenant[tenantID]
		if workspaceIDs == nil {
			workspaceIDs = make(map[string]struct{}, len(grant.ApplicationWorkspaceIDs))
			byTenant[tenantID] = workspaceIDs
		}
		for _, candidate := range grant.ApplicationWorkspaceIDs {
			workspaceID := strings.TrimSpace(candidate)
			if !ValidID(workspaceID) {
				return nil, false
			}
			workspaceIDs[workspaceID] = struct{}{}
		}
	}
	tenantIDs := make([]string, 0, len(byTenant))
	for tenantID := range byTenant {
		tenantIDs = append(tenantIDs, tenantID)
	}
	sort.Strings(tenantIDs)
	normalized := make([]config.ApplicationWorkspaceGrant, 0, len(tenantIDs))
	for _, tenantID := range tenantIDs {
		workspaceIDs := make([]string, 0, len(byTenant[tenantID]))
		for workspaceID := range byTenant[tenantID] {
			workspaceIDs = append(workspaceIDs, workspaceID)
		}
		sort.Strings(workspaceIDs)
		normalized = append(normalized, config.ApplicationWorkspaceGrant{
			TenantID:                tenantID,
			ApplicationWorkspaceIDs: workspaceIDs,
		})
	}
	return normalized, true
}

// GrantTenantsAllowed verifies every grant is within the principal tenant set.
func GrantTenantsAllowed(tenantID string, allowedTenants []string, grants []config.ApplicationWorkspaceGrant) bool {
	allowed := make(map[string]struct{}, len(allowedTenants))
	for _, candidate := range allowedTenants {
		allowed[strings.TrimSpace(candidate)] = struct{}{}
	}
	for _, grant := range grants {
		if tenantID != "" && grant.TenantID == tenantID {
			continue
		}
		if _, ok := allowed[grant.TenantID]; ok {
			continue
		}
		return false
	}
	return true
}

// CloneGrants returns a deep copy suitable for an authenticated principal.
func CloneGrants(grants []config.ApplicationWorkspaceGrant) []config.ApplicationWorkspaceGrant {
	cloned := make([]config.ApplicationWorkspaceGrant, 0, len(grants))
	for _, grant := range grants {
		cloned = append(cloned, config.ApplicationWorkspaceGrant{
			TenantID:                grant.TenantID,
			ApplicationWorkspaceIDs: append([]string(nil), grant.ApplicationWorkspaceIDs...),
		})
	}
	return cloned
}
