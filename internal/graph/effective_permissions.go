package graph

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"
)

// EffectivePermissions represents the actual permissions an identity has
type EffectivePermissions struct {
	PrincipalID      string                     `json:"principal_id"`
	PrincipalName    string                     `json:"principal_name"`
	Resources        map[string]*ResourceAccess `json:"resources"`
	Summary          *PermissionSummary         `json:"summary"`
	RiskAssessment   *PermissionRiskAssessment  `json:"risk_assessment"`
	InheritanceChain []*PermissionSource        `json:"inheritance_chain"`
}

// ResourceAccess describes what actions are allowed on a resource
type ResourceAccess struct {
	ResourceID   string     `json:"resource_id"`
	ResourceName string     `json:"resource_name"`
	ResourceType NodeKind   `json:"resource_type"`
	Actions      []string   `json:"actions"`
	Effect       EdgeEffect `json:"effect"`  // allow or deny
	Sources      []string   `json:"sources"` // which policies grant this
	Path         []string   `json:"path"`    // how access is achieved
	IsDirect     bool       `json:"is_direct"`
	IsInherited  bool       `json:"is_inherited"`
	Conditions   []string   `json:"conditions,omitempty"`
}

// PermissionSummary provides high-level stats
type PermissionSummary struct {
	TotalResources     int            `json:"total_resources"`
	TotalActions       int            `json:"total_actions"`
	AdminAccess        int            `json:"admin_access"`
	WriteAccess        int            `json:"write_access"`
	ReadAccess         int            `json:"read_access"`
	DeleteAccess       int            `json:"delete_access"`
	CrossAccountAccess int            `json:"cross_account_access"`
	WildcardActions    int            `json:"wildcard_actions"`
	ResourcesByType    map[string]int `json:"resources_by_type"`
}

// PermissionRiskAssessment evaluates the risk of the permissions
type PermissionRiskAssessment struct {
	OverallRisk       RiskLevel            `json:"overall_risk"`
	RiskScore         float64              `json:"risk_score"` // 0-100
	Findings          []*PermissionFinding `json:"findings"`
	OverprivilegedBy  float64              `json:"overprivileged_by"` // percentage above baseline
	UnusedPermissions int                  `json:"unused_permissions,omitempty"`
}

// PermissionFinding is a specific risk finding about permissions
type PermissionFinding struct {
	Type           string   `json:"type"`
	Severity       Severity `json:"severity"`
	Description    string   `json:"description"`
	Resource       string   `json:"resource,omitempty"`
	Action         string   `json:"action,omitempty"`
	Recommendation string   `json:"recommendation"`
}

// PermissionSource tracks where a permission comes from
type PermissionSource struct {
	Type       string `json:"type"` // direct, group, role, resource_policy, scp
	SourceID   string `json:"source_id"`
	SourceName string `json:"source_name"`
	Effect     string `json:"effect"`
}

// EffectivePermissionsCalculator computes real permissions
type EffectivePermissionsCalculator struct {
	graph        *Graph
	cache        sync.Map // principalID -> *cachedPermissions
	cacheVersion uint64
	mu           sync.RWMutex
}

type cachedPermissions struct {
	permissions *EffectivePermissions
	version     uint64
}

// NewEffectivePermissionsCalculator creates a new calculator
func NewEffectivePermissionsCalculator(g *Graph) *EffectivePermissionsCalculator {
	return &EffectivePermissionsCalculator{graph: g, cacheVersion: 1}
}

// InvalidateCache invalidates all cached permissions (call when graph changes)
func (c *EffectivePermissionsCalculator) InvalidateCache() {
	c.mu.Lock()
	c.cacheVersion++
	c.mu.Unlock()
}

// InvalidatePrincipal invalidates cache for a specific principal
func (c *EffectivePermissionsCalculator) InvalidatePrincipal(principalID string) {
	c.cache.Delete(principalID)
}

// Calculate computes effective permissions for a principal
func (c *EffectivePermissionsCalculator) Calculate(principalID string) *EffectivePermissions {
	// Check cache with version validation
	c.mu.RLock()
	currentVersion := c.cacheVersion
	c.mu.RUnlock()

	if cached, ok := c.cache.Load(principalID); ok {
		if cp, ok := cached.(*cachedPermissions); ok && cp.version == currentVersion {
			return cp.permissions
		}
	}

	principal, ok := c.graph.GetNode(principalID)
	if !ok {
		return nil
	}

	ep := &EffectivePermissions{
		PrincipalID:   principalID,
		PrincipalName: principal.Name,
		Resources:     make(map[string]*ResourceAccess),
	}

	// Collect permissions from all sources
	c.collectDirectPermissions(ep, principalID)
	c.collectGroupPermissions(ep, principalID)
	c.collectRolePermissions(ep, principalID)
	c.applyDenyRules(ep, principalID)

	// Generate summary
	ep.Summary = c.generateSummary(ep)

	// Assess risk
	ep.RiskAssessment = c.assessRisk(ep)

	// Cache result with version
	c.cache.Store(principalID, &cachedPermissions{
		permissions: ep,
		version:     currentVersion,
	})

	return ep
}

func (c *EffectivePermissionsCalculator) collectDirectPermissions(ep *EffectivePermissions, principalID string) {
	for _, edge := range c.graph.GetOutEdges(principalID) {
		if edge.IsDeny() {
			continue
		}

		targetNode, ok := c.graph.GetNode(edge.Target)
		if !ok || !targetNode.IsResource() {
			continue
		}

		actions := permissionActionsForEdge(edge)
		conditions := permissionConditionsForEdge(edge)
		source := permissionSourceForEdge(edge, principalID, ep.PrincipalName, "direct", "allow")

		if existing, ok := ep.Resources[edge.Target]; ok {
			existing.Actions = mergeActions(existing.Actions, actions)
			existing.Sources = mergeActions(existing.Sources, []string{source.SourceID})
			existing.Conditions = mergeActions(existing.Conditions, conditions)
			existing.IsDirect = true
		} else {
			ep.Resources[edge.Target] = &ResourceAccess{
				ResourceID:   edge.Target,
				ResourceName: targetNode.Name,
				ResourceType: targetNode.Kind,
				Actions:      actions,
				Effect:       EdgeEffectAllow,
				Sources:      []string{source.SourceID},
				Path:         []string{principalID, edge.Target},
				IsDirect:     true,
				Conditions:   conditions,
			}
		}

		ep.InheritanceChain = append(ep.InheritanceChain, source)
	}
}

func (c *EffectivePermissionsCalculator) collectGroupPermissions(ep *EffectivePermissions, principalID string) {
	// Find groups this principal is a member of
	for _, edge := range c.graph.GetOutEdges(principalID) {
		if edge.Kind != EdgeKindMemberOf {
			continue
		}

		groupNode, ok := c.graph.GetNode(edge.Target)
		if !ok || groupNode.Kind != NodeKindGroup {
			continue
		}

		// Get group's permissions
		for _, groupEdge := range c.graph.GetOutEdges(edge.Target) {
			if groupEdge.IsDeny() {
				continue
			}

			targetNode, ok := c.graph.GetNode(groupEdge.Target)
			if !ok || !targetNode.IsResource() {
				continue
			}

			actions := permissionActionsForEdge(groupEdge)
			conditions := permissionConditionsForEdge(groupEdge)

			// Merge with existing or create new
			if existing, ok := ep.Resources[groupEdge.Target]; ok {
				existing.Actions = mergeActions(existing.Actions, actions)
				existing.Sources = append(existing.Sources, groupNode.ID)
				existing.Conditions = mergeActions(existing.Conditions, conditions)
			} else {
				ep.Resources[groupEdge.Target] = &ResourceAccess{
					ResourceID:   groupEdge.Target,
					ResourceName: targetNode.Name,
					ResourceType: targetNode.Kind,
					Actions:      actions,
					Effect:       EdgeEffectAllow,
					Sources:      []string{groupNode.ID},
					Path:         []string{principalID, groupNode.ID, groupEdge.Target},
					IsInherited:  true,
					Conditions:   conditions,
				}
			}

			ep.InheritanceChain = append(ep.InheritanceChain, &PermissionSource{
				Type:       "group",
				SourceID:   groupNode.ID,
				SourceName: groupNode.Name,
				Effect:     "allow",
			})
		}
	}
}

func (c *EffectivePermissionsCalculator) collectRolePermissions(ep *EffectivePermissions, principalID string) {
	// Find roles this principal can assume
	visited := make(map[string]bool)
	c.collectRolePermissionsRecursive(ep, principalID, principalID, visited, []string{principalID})
}

func (c *EffectivePermissionsCalculator) collectRolePermissionsRecursive(
	ep *EffectivePermissions,
	_ string, // principalID - kept for potential future use
	currentID string,
	visited map[string]bool,
	path []string,
) {
	if visited[currentID] {
		return
	}
	visited[currentID] = true

	for _, edge := range c.graph.GetOutEdges(currentID) {
		if edge.Kind != EdgeKindCanAssume {
			continue
		}

		roleNode, ok := c.graph.GetNode(edge.Target)
		if !ok || roleNode.Kind != NodeKindRole {
			continue
		}

		newPath := append([]string{}, path...)
		newPath = append(newPath, roleNode.ID)

		// Get role's permissions
		for _, roleEdge := range c.graph.GetOutEdges(roleNode.ID) {
			if roleEdge.IsDeny() {
				continue
			}

			if roleEdge.Kind == EdgeKindCanAssume {
				// Role can assume another role - recurse
				c.collectRolePermissionsRecursive(ep, "", roleNode.ID, visited, newPath)
				continue
			}

			targetNode, ok := c.graph.GetNode(roleEdge.Target)
			if !ok || !targetNode.IsResource() {
				continue
			}

			actions := permissionActionsForEdge(roleEdge)
			conditions := permissionConditionsForEdge(roleEdge)
			resourcePath := append([]string{}, newPath...)
			resourcePath = append(resourcePath, roleEdge.Target)

			if existing, ok := ep.Resources[roleEdge.Target]; ok {
				existing.Actions = mergeActions(existing.Actions, actions)
				existing.Sources = append(existing.Sources, roleNode.ID)
				existing.Conditions = mergeActions(existing.Conditions, conditions)
			} else {
				ep.Resources[roleEdge.Target] = &ResourceAccess{
					ResourceID:   roleEdge.Target,
					ResourceName: targetNode.Name,
					ResourceType: targetNode.Kind,
					Actions:      actions,
					Effect:       EdgeEffectAllow,
					Sources:      []string{roleNode.ID},
					Path:         resourcePath,
					IsInherited:  true,
					Conditions:   conditions,
				}
			}

			ep.InheritanceChain = append(ep.InheritanceChain, &PermissionSource{
				Type:       "role",
				SourceID:   roleNode.ID,
				SourceName: roleNode.Name,
				Effect:     "allow",
			})
		}
	}
}

func (c *EffectivePermissionsCalculator) applyDenyRules(ep *EffectivePermissions, principalID string) {
	// Collect all deny edges from various sources
	// Priority order: SCPs > Resource Policies > Identity Policies
	denies := make(map[string][]string) // resourceID -> denied actions

	// 1. Direct denies from principal
	for _, edge := range c.graph.GetOutEdges(principalID) {
		if !edge.IsDeny() {
			continue
		}
		targetNode, ok := c.graph.GetNode(edge.Target)
		if !ok || !targetNode.IsResource() {
			continue
		}
		actions := permissionActionsForEdge(edge)
		denies[edge.Target] = append(denies[edge.Target], actions...)

		ep.InheritanceChain = append(ep.InheritanceChain, permissionSourceForEdge(edge, principalID, ep.PrincipalName, "direct_deny", "deny"))
	}

	// 2. Group denies - check all groups the principal is a member of
	for _, edge := range c.graph.GetOutEdges(principalID) {
		if edge.Kind != EdgeKindMemberOf {
			continue
		}

		groupNode, ok := c.graph.GetNode(edge.Target)
		if !ok || groupNode.Kind != NodeKindGroup {
			continue
		}

		for _, groupEdge := range c.graph.GetOutEdges(edge.Target) {
			if !groupEdge.IsDeny() {
				continue
			}

			targetNode, ok := c.graph.GetNode(groupEdge.Target)
			if !ok || !targetNode.IsResource() {
				continue
			}

			actions := permissionActionsForEdge(groupEdge)
			denies[groupEdge.Target] = append(denies[groupEdge.Target], actions...)

			ep.InheritanceChain = append(ep.InheritanceChain, &PermissionSource{
				Type:       "group_deny",
				SourceID:   groupNode.ID,
				SourceName: groupNode.Name,
				Effect:     "deny",
			})
		}
	}

	// 3. Role denies - check all roles the principal can assume
	visited := make(map[string]bool)
	c.collectRoleDenies(ep, principalID, denies, visited)

	// 4. Service Control Policies (SCPs) - apply organization-level restrictions
	// SCPs are stored as special nodes with EdgeKindSCP edges
	c.applyServiceControlPolicies(ep, principalID, denies)

	// 5. Permission Boundaries - AWS specific, limits max permissions
	c.applyPermissionBoundaries(ep, principalID, denies)

	// Apply all collected denies
	for resourceID, deniedActions := range denies {
		if access, ok := ep.Resources[resourceID]; ok {
			access.Actions = removeActions(access.Actions, deniedActions)
			if len(access.Actions) == 0 {
				delete(ep.Resources, resourceID)
			}
		}
	}
}

// collectRoleDenies recursively collects deny rules from assumable roles
func (c *EffectivePermissionsCalculator) collectRoleDenies(
	ep *EffectivePermissions,
	currentID string,
	denies map[string][]string,
	visited map[string]bool,
) {
	if visited[currentID] {
		return
	}
	visited[currentID] = true

	for _, edge := range c.graph.GetOutEdges(currentID) {
		if edge.Kind != EdgeKindCanAssume {
			continue
		}

		roleNode, ok := c.graph.GetNode(edge.Target)
		if !ok || roleNode.Kind != NodeKindRole {
			continue
		}

		// Check role's deny edges
		for _, roleEdge := range c.graph.GetOutEdges(roleNode.ID) {
			if !roleEdge.IsDeny() {
				if roleEdge.Kind == EdgeKindCanAssume {
					// Role can assume another role - recurse
					c.collectRoleDenies(ep, roleNode.ID, denies, visited)
				}
				continue
			}

			targetNode, ok := c.graph.GetNode(roleEdge.Target)
			if !ok || !targetNode.IsResource() {
				continue
			}

			actions := permissionActionsForEdge(roleEdge)
			denies[roleEdge.Target] = append(denies[roleEdge.Target], actions...)

			ep.InheritanceChain = append(ep.InheritanceChain, &PermissionSource{
				Type:       "role_deny",
				SourceID:   roleNode.ID,
				SourceName: roleNode.Name,
				Effect:     "deny",
			})
		}
	}
}

// applyServiceControlPolicies applies organization-level SCPs
func (c *EffectivePermissionsCalculator) applyServiceControlPolicies(
	ep *EffectivePermissions,
	principalID string,
	denies map[string][]string,
) {
	principal, ok := c.graph.GetNode(principalID)
	if !ok {
		return
	}

	// SCPs are attached to accounts/OUs and inherited down
	// Look for SCP nodes that apply to this principal's account
	accountID := principal.Account

	// Find all SCP nodes
	for _, node := range c.graph.GetNodesByKind(NodeKindSCP) {
		// Check if this SCP applies to the principal's account
		applies := false
		if targetsRaw, exists := node.Properties["target_accounts"]; exists {
			switch targets := targetsRaw.(type) {
			case []string:
				for _, target := range targets {
					if target == accountID || target == "*" {
						applies = true
						break
					}
				}
			case []any:
				for _, targetRaw := range targets {
					if target, ok := targetRaw.(string); ok {
						if target == accountID || target == "*" {
							applies = true
							break
						}
					}
				}
			}
		}
		if !applies {
			continue
		}

		// Get denied actions from SCP
		for _, edge := range c.graph.GetOutEdges(node.ID) {
			if !edge.IsDeny() {
				continue
			}

			// SCPs can deny access to services/actions globally
			// Apply to all matching resources
			actions := edgeKindToActions(edge.Kind)
			if edge.Target == "*" {
				// Deny applies to all resources
				for resourceID := range ep.Resources {
					denies[resourceID] = append(denies[resourceID], actions...)
				}
			} else {
				denies[edge.Target] = append(denies[edge.Target], actions...)
			}

			ep.InheritanceChain = append(ep.InheritanceChain, &PermissionSource{
				Type:       "scp",
				SourceID:   node.ID,
				SourceName: node.Name,
				Effect:     "deny",
			})
		}

		// SCPs can also work as allow-lists (implicit deny everything not allowed)
		if allowList, ok := node.Properties["allow_list"].(bool); ok && allowList {
			allowedActions := make(map[string]map[string]bool)

			for _, edge := range c.graph.GetOutEdges(node.ID) {
				if edge.IsDeny() {
					continue
				}
				actions := edgeKindToActions(edge.Kind)
				if allowedActions[edge.Target] == nil {
					allowedActions[edge.Target] = make(map[string]bool)
				}
				for _, a := range actions {
					allowedActions[edge.Target][a] = true
				}
			}

			// Everything not explicitly allowed is denied
			for resourceID, access := range ep.Resources {
				allowed := allowedActions[resourceID]
				if allowed == nil {
					allowed = allowedActions["*"]
				}
				if allowed == nil {
					// Nothing allowed - deny all
					denies[resourceID] = append(denies[resourceID], access.Actions...)
				} else {
					// Only keep allowed actions
					for _, action := range access.Actions {
						if !allowed[action] && !allowed["*"] {
							denies[resourceID] = append(denies[resourceID], action)
						}
					}
				}
			}
		}
	}
}

// applyPermissionBoundaries applies AWS permission boundaries
func (c *EffectivePermissionsCalculator) applyPermissionBoundaries(
	ep *EffectivePermissions,
	principalID string,
	denies map[string][]string,
) {
	principal, ok := c.graph.GetNode(principalID)
	if !ok {
		return
	}

	// Check if principal has a permission boundary attached
	boundaryID, ok := principal.Properties["permission_boundary"].(string)
	if !ok || boundaryID == "" {
		return
	}

	boundary, ok := c.graph.GetNode(boundaryID)
	if !ok {
		return
	}

	// Permission boundary works as an allow-list
	// Only actions allowed by the boundary are effective
	allowedActions := make(map[string]map[string]bool)

	for _, edge := range c.graph.GetOutEdges(boundaryID) {
		if edge.IsDeny() {
			continue
		}
		actions := edgeKindToActions(edge.Kind)
		if allowedActions[edge.Target] == nil {
			allowedActions[edge.Target] = make(map[string]bool)
		}
		for _, a := range actions {
			allowedActions[edge.Target][a] = true
		}
	}

	// If boundary exists, everything not in the boundary is implicitly denied
	for resourceID, access := range ep.Resources {
		allowed := allowedActions[resourceID]
		if allowed == nil {
			allowed = allowedActions["*"]
		}
		if allowed == nil {
			// Nothing in boundary for this resource - deny all
			denies[resourceID] = append(denies[resourceID], access.Actions...)
		} else {
			// Only keep actions that are both granted AND in the boundary
			for _, action := range access.Actions {
				if !allowed[action] && !allowed["*"] {
					denies[resourceID] = append(denies[resourceID], action)
				}
			}
		}
	}

	ep.InheritanceChain = append(ep.InheritanceChain, &PermissionSource{
		Type:       "permission_boundary",
		SourceID:   boundaryID,
		SourceName: boundary.Name,
		Effect:     "limit",
	})
}

func (c *EffectivePermissionsCalculator) generateSummary(ep *EffectivePermissions) *PermissionSummary {
	summary := &PermissionSummary{
		TotalResources:  len(ep.Resources),
		ResourcesByType: make(map[string]int),
	}

	actionSet := make(map[string]bool)
	principal, _ := c.graph.GetNode(ep.PrincipalID)
	principalAccount := ""
	if principal != nil {
		principalAccount = principal.Account
	}

	for _, access := range ep.Resources {
		summary.ResourcesByType[string(access.ResourceType)]++

		for _, action := range access.Actions {
			actionSet[action] = true

			if strings.Contains(action, "*") {
				summary.WildcardActions++
			}

			// Categorize action
			actionLower := strings.ToLower(action)
			if strings.Contains(actionLower, "admin") || strings.Contains(actionLower, "fullcontrol") || action == "*" {
				summary.AdminAccess++
			} else if strings.Contains(actionLower, "write") || strings.Contains(actionLower, "put") || strings.Contains(actionLower, "create") {
				summary.WriteAccess++
			} else if strings.Contains(actionLower, "delete") || strings.Contains(actionLower, "remove") {
				summary.DeleteAccess++
			} else {
				summary.ReadAccess++
			}
		}

		// Check cross-account
		resourceNode, ok := c.graph.GetNode(access.ResourceID)
		if ok && resourceNode.Account != "" && resourceNode.Account != principalAccount {
			summary.CrossAccountAccess++
		}
	}

	summary.TotalActions = len(actionSet)
	return summary
}

func (c *EffectivePermissionsCalculator) assessRisk(ep *EffectivePermissions) *PermissionRiskAssessment {
	assessment := &PermissionRiskAssessment{
		OverallRisk: RiskLow,
		Findings:    make([]*PermissionFinding, 0),
	}

	score := 0.0

	// Check for wildcard permissions
	if ep.Summary.WildcardActions > 0 {
		score += float64(ep.Summary.WildcardActions) * 15
		assessment.Findings = append(assessment.Findings, &PermissionFinding{
			Type:           "wildcard_permissions",
			Severity:       SeverityHigh,
			Description:    "Has wildcard (*) permissions",
			Recommendation: "Replace wildcard with specific actions",
		})
	}

	// Check for admin access to sensitive resources
	if ep.Summary.AdminAccess > 5 {
		score += float64(ep.Summary.AdminAccess) * 10
		assessment.Findings = append(assessment.Findings, &PermissionFinding{
			Type:           "excessive_admin",
			Severity:       SeverityHigh,
			Description:    "Has admin access to many resources",
			Recommendation: "Apply least privilege principle",
		})
	}

	// Check for cross-account access
	if ep.Summary.CrossAccountAccess > 0 {
		score += float64(ep.Summary.CrossAccountAccess) * 8
		assessment.Findings = append(assessment.Findings, &PermissionFinding{
			Type:           "cross_account",
			Severity:       SeverityMedium,
			Description:    "Has cross-account access",
			Recommendation: "Review cross-account trust relationships",
		})
	}

	// Check for delete permissions on critical resources
	for _, access := range ep.Resources {
		resourceNode, ok := c.graph.GetNode(access.ResourceID)
		if !ok {
			continue
		}

		for _, action := range access.Actions {
			if strings.Contains(strings.ToLower(action), "delete") {
				if resourceNode.Risk == RiskCritical || resourceNode.Risk == RiskHigh {
					score += 20
					assessment.Findings = append(assessment.Findings, &PermissionFinding{
						Type:           "delete_critical",
						Severity:       SeverityCritical,
						Description:    "Can delete critical resource",
						Resource:       access.ResourceID,
						Action:         action,
						Recommendation: "Remove delete permission or add approval workflow",
					})
				}
			}
		}
	}

	// Check for secrets access
	for _, access := range ep.Resources {
		if access.ResourceType == NodeKindSecret {
			score += 15
			assessment.Findings = append(assessment.Findings, &PermissionFinding{
				Type:           "secrets_access",
				Severity:       SeverityMedium,
				Description:    "Has access to secrets",
				Resource:       access.ResourceID,
				Recommendation: "Ensure secrets access is necessary and audited",
			})
		}
	}

	// Calculate overprivileged percentage (compared to peer average)
	// This would ideally use peer group analysis
	if ep.Summary.TotalActions > 50 {
		assessment.OverprivilegedBy = float64(ep.Summary.TotalActions-50) / 50.0 * 100
		if assessment.OverprivilegedBy > 50 {
			assessment.Findings = append(assessment.Findings, &PermissionFinding{
				Type:           "overprivileged",
				Severity:       SeverityMedium,
				Description:    "Significantly more permissions than typical",
				Recommendation: "Review and reduce permissions",
			})
		}
	}

	// Normalize score
	if score > 100 {
		score = 100
	}
	assessment.RiskScore = score

	// Determine overall risk level
	if score >= 70 {
		assessment.OverallRisk = RiskCritical
	} else if score >= 50 {
		assessment.OverallRisk = RiskHigh
	} else if score >= 25 {
		assessment.OverallRisk = RiskMedium
	} else {
		assessment.OverallRisk = RiskLow
	}

	return assessment
}

// ClearCache clears the permissions cache
func (c *EffectivePermissionsCalculator) ClearCache() {
	c.cache.Range(func(key, value any) bool {
		c.cache.Delete(key)
		return true
	})
}

// ComparePermissions shows the difference between two principals' permissions
func (c *EffectivePermissionsCalculator) ComparePermissions(principalA, principalB string) *PermissionComparison {
	epA := c.Calculate(principalA)
	epB := c.Calculate(principalB)

	if epA == nil || epB == nil {
		return nil
	}

	comparison := &PermissionComparison{
		PrincipalA: principalA,
		PrincipalB: principalB,
		OnlyA:      make(map[string]*ResourceAccess),
		OnlyB:      make(map[string]*ResourceAccess),
		Common:     make(map[string]*ResourceAccessDiff),
	}

	// Find resources only in A
	for resourceID, accessA := range epA.Resources {
		if accessB, ok := epB.Resources[resourceID]; ok {
			// In both - compare actions
			comparison.Common[resourceID] = &ResourceAccessDiff{
				ResourceID: resourceID,
				ActionsA:   accessA.Actions,
				ActionsB:   accessB.Actions,
				OnlyInA:    subtractActions(accessA.Actions, accessB.Actions),
				OnlyInB:    subtractActions(accessB.Actions, accessA.Actions),
			}
		} else {
			comparison.OnlyA[resourceID] = accessA
		}
	}

	// Find resources only in B
	for resourceID, accessB := range epB.Resources {
		if _, ok := epA.Resources[resourceID]; !ok {
			comparison.OnlyB[resourceID] = accessB
		}
	}

	comparison.OnlyACount = len(comparison.OnlyA)
	comparison.OnlyBCount = len(comparison.OnlyB)
	comparison.CommonCount = len(comparison.Common)

	return comparison
}

// PermissionComparison shows differences between two principals
type PermissionComparison struct {
	PrincipalA  string                         `json:"principal_a"`
	PrincipalB  string                         `json:"principal_b"`
	OnlyA       map[string]*ResourceAccess     `json:"only_a"`
	OnlyB       map[string]*ResourceAccess     `json:"only_b"`
	Common      map[string]*ResourceAccessDiff `json:"common"`
	OnlyACount  int                            `json:"only_a_count"`
	OnlyBCount  int                            `json:"only_b_count"`
	CommonCount int                            `json:"common_count"`
}

// ResourceAccessDiff shows action differences on a common resource
type ResourceAccessDiff struct {
	ResourceID string   `json:"resource_id"`
	ActionsA   []string `json:"actions_a"`
	ActionsB   []string `json:"actions_b"`
	OnlyInA    []string `json:"only_in_a"`
	OnlyInB    []string `json:"only_in_b"`
}

// Helper functions

func edgeKindToActions(kind EdgeKind) []string {
	switch kind {
	case EdgeKindCanRead:
		return []string{"read", "get", "list", "describe"}
	case EdgeKindCanWrite:
		return []string{"write", "put", "create", "update"}
	case EdgeKindCanDelete:
		return []string{"delete", "remove"}
	case EdgeKindCanAdmin:
		return []string{"*"}
	default:
		return []string{string(kind)}
	}
}

func permissionActionsForEdge(edge *Edge) []string {
	if edge != nil {
		if actions := stringSliceFromValue(edge.Properties["actions"]); len(actions) > 0 {
			return actions
		}
	}
	return edgeKindToActions(edge.Kind)
}

func permissionConditionsForEdge(edge *Edge) []string {
	if edge == nil || edge.Properties == nil {
		return nil
	}
	raw, ok := edge.Properties["conditions"]
	if !ok || raw == nil {
		return nil
	}
	payload, err := json.Marshal(raw)
	if err != nil {
		value := strings.TrimSpace(toString(raw))
		if value == "" {
			return nil
		}
		return []string{value}
	}
	return []string{string(payload)}
}

func permissionSourceForEdge(edge *Edge, fallbackID, fallbackName, fallbackType, effect string) *PermissionSource {
	sourceID := fallbackID
	sourceName := fallbackName
	sourceType := fallbackType
	if edge != nil && edge.Properties != nil {
		if via := strings.TrimSpace(toString(edge.Properties["via"])); via != "" {
			sourceID = via
			sourceName = via
		}
		if strings.EqualFold(strings.TrimSpace(toString(edge.Properties["mechanism"])), "resource_policy") {
			sourceType = "resource_policy"
		}
	}
	return &PermissionSource{
		Type:       sourceType,
		SourceID:   sourceID,
		SourceName: sourceName,
		Effect:     effect,
	}
}

func mergeActions(a, b []string) []string {
	actionSet := make(map[string]bool)
	for _, action := range a {
		actionSet[action] = true
	}
	for _, action := range b {
		actionSet[action] = true
	}

	result := make([]string, 0, len(actionSet))
	for action := range actionSet {
		result = append(result, action)
	}
	sort.Strings(result)
	return result
}

func removeActions(actions, toRemove []string) []string {
	removeSet := make(map[string]bool)
	for _, a := range toRemove {
		removeSet[a] = true
	}

	var result []string
	for _, a := range actions {
		if !removeSet[a] {
			result = append(result, a)
		}
	}
	return result
}

func subtractActions(a, b []string) []string {
	bSet := make(map[string]bool)
	for _, action := range b {
		bSet[action] = true
	}

	var result []string
	for _, action := range a {
		if !bSet[action] {
			result = append(result, action)
		}
	}
	return result
}

// GenerateLeastPrivilegePolicy generates a minimal policy for the actual usage
func (c *EffectivePermissionsCalculator) GenerateLeastPrivilegePolicy(
	principalID string,
	usedActions map[string][]string, // resourceID -> actions actually used
) *LeastPrivilegePolicy {
	ep := c.Calculate(principalID)
	if ep == nil {
		return nil
	}

	policy := &LeastPrivilegePolicy{
		PrincipalID:        principalID,
		RecommendedActions: make(map[string][]string),
		RemovedActions:     make(map[string][]string),
	}

	for resourceID, access := range ep.Resources {
		used := usedActions[resourceID]
		if len(used) == 0 {
			// No usage - recommend removing all access
			policy.RemovedActions[resourceID] = access.Actions
			policy.TotalRemoved += len(access.Actions)
			continue
		}

		// Keep only used actions
		policy.RecommendedActions[resourceID] = used
		removed := subtractActions(access.Actions, used)
		if len(removed) > 0 {
			policy.RemovedActions[resourceID] = removed
			policy.TotalRemoved += len(removed)
		}
	}

	policy.TotalKept = 0
	for _, actions := range policy.RecommendedActions {
		policy.TotalKept += len(actions)
	}

	if ep.Summary.TotalActions > 0 {
		policy.ReductionPercent = float64(policy.TotalRemoved) / float64(ep.Summary.TotalActions) * 100
	}

	return policy
}

// LeastPrivilegePolicy is a recommended minimal policy
type LeastPrivilegePolicy struct {
	PrincipalID        string              `json:"principal_id"`
	RecommendedActions map[string][]string `json:"recommended_actions"`
	RemovedActions     map[string][]string `json:"removed_actions"`
	TotalKept          int                 `json:"total_kept"`
	TotalRemoved       int                 `json:"total_removed"`
	ReductionPercent   float64             `json:"reduction_percent"`
}
