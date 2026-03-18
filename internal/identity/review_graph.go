package identity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/google/uuid"
)

type toxicReviewContext struct {
	IDs         []string
	Names       []string
	AttackPaths int
}

type resolvedGraphContextKey struct{}

// WithResolvedGraph reuses a caller-resolved graph so downstream access-review
// generation does not repeat store snapshot work during the same request.
func WithResolvedGraph(ctx context.Context, g *graph.Graph) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if g == nil {
		return ctx
	}
	return context.WithValue(ctx, resolvedGraphContextKey{}, g)
}

func resolvedGraphFromContext(ctx context.Context) *graph.Graph {
	if ctx == nil {
		return nil
	}
	g, _ := ctx.Value(resolvedGraphContextKey{}).(*graph.Graph)
	return g
}

func (s *Service) generateReviewItems(ctx context.Context, review *AccessReview) ([]ReviewItem, error) {
	if s == nil {
		return review.Items, nil
	}
	g := resolvedGraphFromContext(ctx)
	if g == nil && s.graphResolver != nil {
		g = s.graphResolver(ctx)
	}
	if g == nil {
		return review.Items, nil
	}

	graphReview := graph.CreateAccessReview(g, review.Name, toGraphReviewScope(review.Scope), review.CreatedBy)
	calc := graph.NewEffectivePermissionsCalculator(g)
	toxicIndex := buildToxicReviewIndex(graph.NewToxicCombinationEngine().Analyze(g))

	items := make([]ReviewItem, 0, len(graphReview.Items))
	for _, graphItem := range graphReview.Items {
		item, ok := s.mapGraphReviewItem(g, review, graphItem, calc, toxicIndex)
		if !ok {
			continue
		}
		items = append(items, item)
	}
	return dedupeReviewItems(items), nil
}

func toGraphReviewScope(scope ReviewScope) graph.ReviewScope {
	mode := scope.effectiveMode()
	graphScope := graph.ReviewScope{
		AccountIDs: append([]string(nil), scope.Accounts...),
		Principals: append([]string(nil), scope.Users...),
		Resources:  append([]string(nil), scope.Resources...),
		RiskLevels: append([]string(nil), scope.RiskLevels...),
	}
	switch mode {
	case ReviewScopeModeAccount:
		graphScope.Type = graph.ScopeTypeAccount
	case ReviewScopeModePrincipal:
		graphScope.Type = graph.ScopeTypePrincipal
	case ReviewScopeModeResource:
		graphScope.Type = graph.ScopeTypeResource
	case ReviewScopeModeHighRisk:
		graphScope.Type = graph.ScopeTypeHighRisk
	case ReviewScopeModeCrossAccount:
		graphScope.Type = graph.ScopeTypeCrossAccount
	case ReviewScopeModePrivilegeCreep:
		graphScope.Type = graph.ScopeTypePrivilegeCreep
	default:
		graphScope.Type = graph.ScopeTypeAll
	}
	return graphScope
}

func (s *Service) mapGraphReviewItem(g *graph.Graph, review *AccessReview, graphItem *graph.AccessReviewItem, calc *graph.EffectivePermissionsCalculator, toxicIndex map[string]toxicReviewContext) (ReviewItem, bool) {
	principalNode, ok := g.GetNode(graphItem.PrincipalID)
	if !ok || principalNode == nil {
		return ReviewItem{}, false
	}
	resourceNode, ok := g.GetNode(graphItem.ResourceID)
	if !ok || resourceNode == nil {
		return ReviewItem{}, false
	}

	principal := principalFromGraphNode(principalNode)
	principal.LastLogin = extractLastActivityFromNode(principalNode)
	lastActivity := principal.LastLogin

	var resourceAccess *graph.ResourceAccess
	if calc != nil {
		if perms := calc.Calculate(graphItem.PrincipalID); perms != nil {
			resourceAccess = perms.Resources[graphItem.ResourceID]
		}
	}

	grants := buildAccessGrants(principalNode, resourceNode, resourceAccess, graphItem.AccessType, review.CreatedAt)
	reviewerCandidates := reviewerCandidatesForResource(review, g, resourceNode)
	toxic := mergeToxicContexts(toxicIndex[principalNode.ID], toxicIndex[resourceNode.ID])
	path := uniqueStrings(append(append([]string(nil), graphItem.Path...), accessPath(resourceAccess)...))
	flags := uniqueStrings(append(append([]string(nil), graphItem.Flags...), deriveReviewFlags(principalNode, resourceNode, lastActivity, toxic)...))

	item := ReviewItem{
		ID:                 uuid.New().String(),
		ReviewID:           review.ID,
		Type:               principal.Type,
		Principal:          principal,
		Access:             grants,
		ReviewerCandidates: reviewerCandidates,
		LastActivity:       lastActivity,
		Path:               path,
		Flags:              flags,
		Metadata: map[string]any{
			"resource_id":             resourceNode.ID,
			"resource_name":           resourceNode.Name,
			"resource_kind":           string(resourceNode.Kind),
			"resource_provider":       resourceNode.Provider,
			"resource_account":        resourceNode.Account,
			"resource_risk":           string(resourceNode.Risk),
			"resource_owners":         reviewerCandidates,
			"toxic_combination_ids":   toxic.IDs,
			"toxic_combination_names": toxic.Names,
			"attack_path_count":       toxic.AttackPaths,
		},
	}

	if !matchesScopeFilters(review.Scope, item, resourceNode, resourceAccess) {
		return ReviewItem{}, false
	}

	item.RiskScore, item.RiskFactors = s.calculateGraphRisk(&item, resourceNode, toxic)
	item.Recommendation = buildRecommendation(item, resourceNode, toxic)
	return item, true
}

func matchesScopeFilters(scope ReviewScope, item ReviewItem, resourceNode *graph.Node, resourceAccess *graph.ResourceAccess) bool {
	if len(scope.Providers) > 0 && !matchesAny(scope.Providers, item.Principal.Provider, resourceNode.Provider) {
		return false
	}
	if len(scope.Accounts) > 0 && !matchesAny(scope.Accounts, item.Principal.Account, resourceNode.Account) {
		return false
	}
	if len(scope.Users) > 0 && !matchesAny(scope.Users, item.Principal.ID, item.Principal.Email, item.Principal.Name) {
		return false
	}
	if len(scope.Resources) > 0 && !matchesAny(scope.Resources, resourceNode.ID, resourceNode.Name) {
		return false
	}
	if len(scope.Applications) > 0 && !matchesAny(scope.Applications, resourceNode.ID, resourceNode.Name) {
		return false
	}
	if len(scope.Roles) > 0 {
		values := make([]string, 0, len(item.Access)+len(item.Path))
		for _, grant := range item.Access {
			values = append(values, grant.Role, grant.GrantedBy)
		}
		values = append(values, item.Path...)
		if resourceAccess != nil {
			values = append(values, resourceAccess.Sources...)
		}
		if !matchesAny(scope.Roles, values...) {
			return false
		}
	}
	if len(scope.RiskLevels) > 0 && !matchesAny(scope.RiskLevels, string(resourceNode.Risk)) {
		return false
	}
	return true
}

func buildAccessGrants(principalNode, resourceNode *graph.Node, resourceAccess *graph.ResourceAccess, accessType graph.EdgeKind, fallbackTime time.Time) []AccessGrant {
	grantedAt := fallbackTime.UTC()
	if principalNode != nil && !principalNode.CreatedAt.IsZero() {
		grantedAt = principalNode.CreatedAt.UTC()
	}
	if resourceAccess == nil || len(resourceAccess.Actions) == 0 {
		return []AccessGrant{{
			ID:           uuid.New().String(),
			Resource:     resourceNode.ID,
			ResourceType: string(resourceNode.Kind),
			Permission:   permissionForEdgeKind(accessType),
			GrantedAt:    grantedAt,
			GrantedBy:    strings.TrimSpace(principalNode.ID),
		}}
	}
	grants := make([]AccessGrant, 0, len(resourceAccess.Actions))
	role := firstRoleSource(resourceAccess.Sources)
	for _, action := range resourceAccess.Actions {
		grants = append(grants, AccessGrant{
			ID:           uuid.New().String(),
			Resource:     resourceNode.ID,
			ResourceType: string(resourceNode.Kind),
			Permission:   action,
			Role:         role,
			GrantedAt:    grantedAt,
			GrantedBy:    strings.Join(resourceAccess.Sources, ","),
		})
	}
	return grants
}

func accessPath(access *graph.ResourceAccess) []string {
	if access == nil {
		return nil
	}
	return append([]string(nil), access.Path...)
}

func firstRoleSource(sources []string) string {
	for _, source := range sources {
		normalized := strings.ToLower(strings.TrimSpace(source))
		if strings.Contains(normalized, "role") || strings.Contains(normalized, "group") {
			return source
		}
	}
	if len(sources) == 0 {
		return ""
	}
	return sources[0]
}

func reviewerCandidatesForResource(review *AccessReview, g *graph.Graph, resource *graph.Node) []string {
	candidates := append([]string(nil), review.Reviewers...)
	if g != nil && resource != nil {
		for _, edge := range g.GetInEdges(resource.ID) {
			if edge.Kind != graph.EdgeKindOwns && edge.Kind != graph.EdgeKindManagedBy && edge.Kind != graph.EdgeKindAssignedTo {
				continue
			}
			node, ok := g.GetNode(edge.Source)
			if !ok || node == nil || !node.IsIdentity() && node.Kind != graph.NodeKindPerson {
				continue
			}
			candidates = append(candidates, node.ID)
		}
	}
	return uniqueStrings(candidates)
}

func deriveReviewFlags(principalNode, resourceNode *graph.Node, lastActivity *time.Time, toxic toxicReviewContext) []string {
	flags := make([]string, 0, 4)
	if principalNode != nil && resourceNode != nil && principalNode.Account != "" && resourceNode.Account != "" && principalNode.Account != resourceNode.Account {
		flags = append(flags, "cross_account")
	}
	if lastActivity != nil && time.Since(*lastActivity) > 90*24*time.Hour {
		flags = append(flags, "stale_access")
	}
	if len(toxic.IDs) > 0 {
		flags = append(flags, "toxic_combination")
	}
	if resourceNode != nil && (resourceNode.Risk == graph.RiskHigh || resourceNode.Risk == graph.RiskCritical) {
		flags = append(flags, "sensitive_resource")
	}
	return flags
}

func (s *Service) calculateGraphRisk(item *ReviewItem, resourceNode *graph.Node, toxic toxicReviewContext) (int, []string) {
	score, factors := s.riskCalculator.Calculate(item)
	if resourceNode != nil {
		switch resourceNode.Risk {
		case graph.RiskCritical:
			score += 25
			factors = append(factors, "Critical resource")
		case graph.RiskHigh:
			score += 15
			factors = append(factors, "High-risk resource")
		case graph.RiskMedium:
			score += 5
		}
	}
	if len(toxic.IDs) > 0 {
		score += 20
		factors = append(factors, fmt.Sprintf("Participates in %d toxic combination(s)", len(toxic.IDs)))
	}
	if len(item.Path) > 2 {
		score += 10
		factors = append(factors, "Inherited or multi-hop access path")
	}
	if item.LastActivity == nil {
		score += 10
		factors = append(factors, "No last-activity evidence")
	}
	if score > 100 {
		score = 100
	}
	return score, uniqueStrings(factors)
}

func buildRecommendation(item ReviewItem, resourceNode *graph.Node, toxic toxicReviewContext) *ReviewRecommendation {
	if len(toxic.IDs) > 0 || item.RiskScore >= 85 {
		return &ReviewRecommendation{Action: DecisionEscalate, Reason: "Access participates in a high-risk graph pattern and needs owner review", Confidence: "high"}
	}
	if item.LastActivity != nil && time.Since(*item.LastActivity) > 90*24*time.Hour {
		return &ReviewRecommendation{Action: DecisionRevoke, Reason: "Access appears unused for more than 90 days", Confidence: "high"}
	}
	if resourceNode != nil && resourceNode.Risk == graph.RiskCritical && item.RiskScore >= 60 {
		return &ReviewRecommendation{Action: DecisionModify, Reason: "Critical-resource access should be reduced to least privilege", Confidence: "medium"}
	}
	if item.LastActivity != nil && time.Since(*item.LastActivity) <= 30*24*time.Hour && item.RiskScore < 40 {
		return &ReviewRecommendation{Action: DecisionApprove, Reason: "Access is recently used and low risk", Confidence: "high"}
	}
	return &ReviewRecommendation{Action: DecisionDefer, Reason: "Insufficient certainty for automatic approval or revocation", Confidence: "medium"}
}

func buildToxicReviewIndex(combos []*graph.ToxicCombination) map[string]toxicReviewContext {
	index := make(map[string]toxicReviewContext)
	for _, combo := range combos {
		if combo == nil {
			continue
		}
		seen := map[string]struct{}{}
		for _, id := range combo.AffectedAssets {
			seen[id] = struct{}{}
		}
		for _, factor := range combo.Factors {
			seen[factor.NodeID] = struct{}{}
		}
		if combo.AttackPath != nil {
			if combo.AttackPath.EntryPoint != nil {
				seen[combo.AttackPath.EntryPoint.ID] = struct{}{}
			}
			if combo.AttackPath.Target != nil {
				seen[combo.AttackPath.Target.ID] = struct{}{}
			}
			for _, step := range combo.AttackPath.Steps {
				seen[step.FromNode] = struct{}{}
				seen[step.ToNode] = struct{}{}
			}
		}
		for id := range seen {
			ctx := index[id]
			ctx.IDs = append(ctx.IDs, combo.ID)
			ctx.Names = append(ctx.Names, combo.Name)
			if combo.AttackPath != nil {
				ctx.AttackPaths++
			}
			ctx.IDs = uniqueStrings(ctx.IDs)
			ctx.Names = uniqueStrings(ctx.Names)
			index[id] = ctx
		}
	}
	return index
}

func mergeToxicContexts(values ...toxicReviewContext) toxicReviewContext {
	merged := toxicReviewContext{}
	for _, value := range values {
		merged.IDs = append(merged.IDs, value.IDs...)
		merged.Names = append(merged.Names, value.Names...)
		merged.AttackPaths += value.AttackPaths
	}
	merged.IDs = uniqueStrings(merged.IDs)
	merged.Names = uniqueStrings(merged.Names)
	return merged
}

func dedupeReviewItems(items []ReviewItem) []ReviewItem {
	seen := make(map[string]struct{}, len(items))
	result := make([]ReviewItem, 0, len(items))
	for _, item := range items {
		key := item.Principal.ID + "->" + resourceIDForItem(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, item)
	}
	return result
}

func resourceIDForItem(item ReviewItem) string {
	if len(item.Access) > 0 {
		return item.Access[0].Resource
	}
	if value, ok := item.Metadata["resource_id"].(string); ok {
		return value
	}
	return ""
}

func principalFromGraphNode(node *graph.Node) Principal {
	principal := Principal{
		ID:        node.ID,
		Type:      string(node.Kind),
		Name:      node.Name,
		Provider:  node.Provider,
		Account:   node.Account,
		CreatedAt: node.CreatedAt,
	}
	if email := extractString(graphNodeProperties(node), "email", "user_principal_name", "mail"); email != "" {
		principal.Email = email
	} else if strings.Contains(node.Name, "@") {
		principal.Email = node.Name
	}
	switch node.Kind {
	case graph.NodeKindServiceAccount:
		principal.Type = "service_account"
	case graph.NodeKindGroup:
		principal.Type = "group"
	case graph.NodeKindRole:
		principal.Type = "role"
	default:
		principal.Type = "user"
	}
	return principal
}

func extractLastActivityFromNode(node *graph.Node) *time.Time {
	if node == nil {
		return nil
	}
	props := graphNodeProperties(node)
	if last := extractTime(props,
		"last_used", "lastUsedAt", "password_last_used", "last_login", "lastSignInDateTime",
		"last_authenticated_time", "access_key_1_last_used_date", "access_key_2_last_used_date",
	); last != nil {
		return last
	}
	if !node.UpdatedAt.IsZero() {
		last := node.UpdatedAt.UTC()
		return &last
	}
	return nil
}

func graphNodeProperties(node *graph.Node) map[string]interface{} {
	props := make(map[string]interface{}, len(node.Properties)+8)
	for key, value := range node.Properties {
		props[key] = value
	}
	props["id"] = node.ID
	props["name"] = node.Name
	props["provider"] = node.Provider
	props["account_id"] = node.Account
	props["email"] = extractString(props, "email", "user_principal_name", "mail")
	return props
}

func permissionForEdgeKind(kind graph.EdgeKind) string {
	switch kind {
	case graph.EdgeKindCanAdmin:
		return "admin"
	case graph.EdgeKindCanWrite:
		return "write"
	case graph.EdgeKindCanRead:
		return "read"
	case graph.EdgeKindCanDelete:
		return "delete"
	case graph.EdgeKindCanAssume:
		return "assume"
	default:
		return strings.TrimSpace(string(kind))
	}
}

func matchesAny(expected []string, values ...string) bool {
	normalizedExpected := make(map[string]struct{}, len(expected))
	for _, value := range expected {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			normalizedExpected[value] = struct{}{}
		}
	}
	for _, value := range values {
		candidate := strings.ToLower(strings.TrimSpace(value))
		if candidate == "" {
			continue
		}
		if _, ok := normalizedExpected[candidate]; ok {
			return true
		}
	}
	return false
}
