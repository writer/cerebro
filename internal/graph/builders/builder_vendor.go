package builders

import (
	"encoding/json"
	"sort"
	"strings"
	"unicode"
)

const vendorProjectionSourceSystem = "graph_builder_vendor_projection"

var vendorLegalSuffixTokens = map[string]struct{}{
	"ag":           {},
	"bv":           {},
	"co":           {},
	"company":      {},
	"corp":         {},
	"corporation":  {},
	"gmbh":         {},
	"inc":          {},
	"incorporated": {},
	"limited":      {},
	"llc":          {},
	"ltd":          {},
	"plc":          {},
	"pty":          {},
	"sarl":         {},
	"sas":          {},
	"spa":          {},
	"srl":          {},
}

var vendorCorporateSuffixPhrases = [][]string{
	{"video", "communications"},
	{"communications"},
	{"technology"},
	{"technologies"},
	{"software"},
	{"systems"},
}

type vendorIdentity struct {
	rawName             string
	aliasKey            string
	ownerOrgID          string
	verifiedPublisherID string
	integrationType     string
}

type vendorProjection struct {
	id                   string
	name                 string
	aliasKey             string
	rawNames             map[string]struct{}
	aliasKeys            map[string]struct{}
	ownerOrganizationIDs map[string]struct{}
	verifiedPublisherIDs map[string]struct{}
	sourceProviders      map[string]struct{}
	integrationTypes     map[string]struct{}
	managedNodeIDs       map[string]struct{}
}

func (b *Builder) buildVendorNodes() {
	if b == nil || b.graph == nil {
		return
	}

	candidates := b.graph.GetAllNodes()
	for _, node := range candidates {
		if node == nil || node.Kind != NodeKindVendor {
			continue
		}
		if !strings.EqualFold(propertyString(node.Properties, "source_system"), vendorProjectionSourceSystem) {
			continue
		}
		b.graph.RemoveNode(node.ID)
	}

	var projections []*vendorProjection
	for _, node := range candidates {
		if node == nil || node.Kind == NodeKindVendor {
			continue
		}
		identity, ok := vendorIdentityForNode(node)
		if !ok {
			continue
		}
		projection := matchVendorProjection(projections, identity)
		if projection == nil {
			projection = &vendorProjection{
				rawNames:             make(map[string]struct{}),
				aliasKeys:            make(map[string]struct{}),
				ownerOrganizationIDs: make(map[string]struct{}),
				verifiedPublisherIDs: make(map[string]struct{}),
				sourceProviders:      make(map[string]struct{}),
				integrationTypes:     make(map[string]struct{}),
				managedNodeIDs:       make(map[string]struct{}),
			}
			projections = append(projections, projection)
		}
		projection.absorb(identity, node)
	}

	for _, projection := range projections {
		projection.finalize()
		if projection.id == "" || strings.TrimSpace(projection.name) == "" {
			continue
		}
		vendor := b.ensureVendorNode(projection)
		if vendor == nil {
			continue
		}
		for managedNodeID := range projection.managedNodeIDs {
			b.addEdgeIfMissing(&Edge{
				Source: managedNodeID,
				Target: vendor.ID,
				Kind:   EdgeKindManagedBy,
				Effect: EdgeEffectAllow,
				Properties: map[string]any{
					"relationship":    "vendor",
					"source_system":   vendorProjectionSourceSystem,
					"cross_system":    true,
					"vendor_node_id":  vendor.ID,
					"vendor_name":     vendor.Name,
					"managed_node_id": managedNodeID,
				},
			})
		}
		b.refreshVendorSignals(vendor, projection)
	}
}

func (p *vendorProjection) absorb(identity vendorIdentity, node *Node) {
	if p == nil || node == nil {
		return
	}
	if rawName := strings.TrimSpace(identity.rawName); rawName != "" {
		p.rawNames[rawName] = struct{}{}
	}
	if aliasKey := strings.TrimSpace(identity.aliasKey); aliasKey != "" {
		p.aliasKeys[aliasKey] = struct{}{}
	}
	if ownerOrgID := strings.TrimSpace(identity.ownerOrgID); ownerOrgID != "" {
		p.ownerOrganizationIDs[ownerOrgID] = struct{}{}
	}
	if verifiedPublisherID := strings.TrimSpace(identity.verifiedPublisherID); verifiedPublisherID != "" {
		p.verifiedPublisherIDs[verifiedPublisherID] = struct{}{}
	}
	if provider := strings.TrimSpace(node.Provider); provider != "" {
		p.sourceProviders[provider] = struct{}{}
	}
	if identity.integrationType != "" {
		p.integrationTypes[identity.integrationType] = struct{}{}
	}
	p.managedNodeIDs[node.ID] = struct{}{}
}

func (p *vendorProjection) finalize() {
	if p == nil {
		return
	}
	p.aliasKey = chooseCanonicalVendorAliasKey(p.aliasKeys)
	if p.aliasKey == "" {
		p.aliasKey = chooseCanonicalVendorAliasKey(vendorAliasSetFromRawNames(p.rawNames))
	}
	p.name = chooseCanonicalVendorDisplayName(p.rawNames, p.aliasKey)
	if strings.TrimSpace(p.name) == "" {
		p.name = p.aliasKey
	}
	p.id = vendorNodeID(p.name)
}

func matchVendorProjection(projections []*vendorProjection, identity vendorIdentity) *vendorProjection {
	for _, projection := range projections {
		if projection == nil {
			continue
		}
		if identity.ownerOrgID != "" {
			if _, ok := projection.ownerOrganizationIDs[identity.ownerOrgID]; ok {
				return projection
			}
		}
		if identity.verifiedPublisherID != "" {
			if _, ok := projection.verifiedPublisherIDs[identity.verifiedPublisherID]; ok {
				return projection
			}
		}
	}
	for _, projection := range projections {
		if projection == nil {
			continue
		}
		if identity.aliasKey == "" {
			continue
		}
		for aliasKey := range projection.aliasKeys {
			if vendorAliasKeysMatch(aliasKey, identity.aliasKey) {
				return projection
			}
		}
	}
	return nil
}

func vendorAliasKeysMatch(left, right string) bool {
	return strings.EqualFold(strings.TrimSpace(left), strings.TrimSpace(right))
}

func vendorAliasSetFromRawNames(rawNames map[string]struct{}) map[string]struct{} {
	aliases := make(map[string]struct{}, len(rawNames))
	for rawName := range rawNames {
		if aliasKey := vendorAliasKey(rawName); aliasKey != "" {
			aliases[aliasKey] = struct{}{}
		}
	}
	return aliases
}

func chooseCanonicalVendorAliasKey(aliasKeys map[string]struct{}) string {
	best := ""
	bestTokens := 0
	for aliasKey := range aliasKeys {
		aliasKey = strings.TrimSpace(aliasKey)
		if aliasKey == "" {
			continue
		}
		tokenCount := len(strings.Fields(aliasKey))
		if best == "" || tokenCount < bestTokens || (tokenCount == bestTokens && len(aliasKey) < len(best)) || (tokenCount == bestTokens && len(aliasKey) == len(best) && aliasKey < best) {
			best = aliasKey
			bestTokens = tokenCount
		}
	}
	return best
}

func chooseCanonicalVendorDisplayName(rawNames map[string]struct{}, canonicalAliasKey string) string {
	best := ""
	for rawName := range rawNames {
		rawName = strings.TrimSpace(rawName)
		if rawName == "" {
			continue
		}
		if canonicalAliasKey != "" && vendorAliasKey(rawName) != canonicalAliasKey {
			continue
		}
		if best == "" || len(rawName) < len(best) || (len(rawName) == len(best) && rawName < best) {
			best = rawName
		}
	}
	if best != "" {
		return best
	}
	for rawName := range rawNames {
		rawName = strings.TrimSpace(rawName)
		if rawName == "" {
			continue
		}
		if best == "" || len(rawName) < len(best) || (len(rawName) == len(best) && rawName < best) {
			best = rawName
		}
	}
	return best
}

func vendorAliasKey(value string) string {
	tokens := vendorNameTokens(value)
	tokens = trimVendorAliasSuffixTokens(tokens)
	if len(tokens) == 0 {
		return ""
	}
	return strings.Join(tokens, " ")
}

func trimVendorAliasSuffixTokens(tokens []string) []string {
	tokens = trimVendorLegalSuffixTokens(tokens)
	for {
		trimmed := trimVendorCorporateSuffixPhrase(tokens)
		if len(trimmed) == len(tokens) {
			return tokens
		}
		tokens = trimVendorLegalSuffixTokens(trimmed)
	}
}

func trimVendorLegalSuffixTokens(tokens []string) []string {
	for len(tokens) > 0 {
		if _, ok := vendorLegalSuffixTokens[tokens[len(tokens)-1]]; !ok {
			break
		}
		tokens = tokens[:len(tokens)-1]
	}
	return tokens
}

func trimVendorCorporateSuffixPhrase(tokens []string) []string {
	for _, phrase := range vendorCorporateSuffixPhrases {
		if len(tokens) <= len(phrase) {
			continue
		}
		offset := len(tokens) - len(phrase)
		match := true
		for i := range phrase {
			if tokens[offset+i] != phrase[i] {
				match = false
				break
			}
		}
		if match {
			return tokens[:offset]
		}
	}
	return tokens
}

func vendorNameTokens(value string) []string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return nil
	}
	var tokens []string
	var current strings.Builder
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			current.WriteRune(r)
			continue
		}
		if current.Len() == 0 {
			continue
		}
		tokens = append(tokens, current.String())
		current.Reset()
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

func vendorDisplayAliases(rawNames map[string]struct{}, canonicalName string) []string {
	aliases := make([]string, 0, len(rawNames))
	for rawName := range rawNames {
		rawName = strings.TrimSpace(rawName)
		if rawName == "" || rawName == canonicalName {
			continue
		}
		aliases = append(aliases, rawName)
	}
	sort.Strings(aliases)
	return aliases
}

func vendorCategory(integrationTypes map[string]struct{}) string {
	if len(integrationTypes) == 0 {
		return ""
	}
	return "saas_integration"
}

func vendorPermissionLevel(readCount, writeCount, adminCount int) string {
	switch {
	case adminCount > 0:
		return "admin"
	case writeCount > 0:
		return "write"
	case readCount > 0:
		return "read"
	default:
		return "none"
	}
}

func vendorTargetIsSensitive(node *Node) bool {
	if node == nil {
		return false
	}
	switch strings.ToLower(propertyString(node.Properties, "data_classification")) {
	case "confidential", "restricted", "sensitive":
		return true
	}
	for _, key := range []string{"contains_pii", "contains_phi", "contains_pci", "contains_secrets"} {
		if value, ok := node.Properties[key].(bool); ok && value {
			return true
		}
	}
	return node.Kind == NodeKindSecret
}

func boolPropertyValue(properties map[string]any, key string) (bool, bool) {
	if properties == nil {
		return false, false
	}
	value, ok := properties[key]
	if !ok {
		return false, false
	}
	typed, ok := value.(bool)
	if !ok {
		return false, false
	}
	return typed, true
}

func targetKindsForEdges(g *Graph, edges []*Edge) map[string]struct{} {
	kinds := make(map[string]struct{})
	for _, edge := range edges {
		if edge == nil {
			continue
		}
		target, ok := g.GetNode(edge.Target)
		if !ok || target == nil || strings.TrimSpace(string(target.Kind)) == "" {
			continue
		}
		kinds[string(target.Kind)] = struct{}{}
	}
	return kinds
}

func sensitiveTargetsForEdges(g *Graph, edges []*Edge) map[string]struct{} {
	targets := make(map[string]struct{})
	for _, edge := range edges {
		if edge == nil {
			continue
		}
		target, ok := g.GetNode(edge.Target)
		if !ok || target == nil || !vendorTargetIsSensitive(target) {
			continue
		}
		targets[edge.Target] = struct{}{}
	}
	return targets
}

func permissionEdges(edges []*Edge) []*Edge {
	filtered := make([]*Edge, 0, len(edges))
	for _, edge := range edges {
		if edge == nil {
			continue
		}
		switch edge.Kind {
		case EdgeKindCanRead, EdgeKindCanWrite, EdgeKindCanAdmin, EdgeKindCanDelete:
			filtered = append(filtered, edge)
		}
	}
	return filtered
}

func relationshipProperties(edge *Edge) map[string]any {
	if edge == nil || edge.Properties == nil {
		return nil
	}
	raw, ok := edge.Properties["properties"]
	if !ok || raw == nil {
		return nil
	}
	switch typed := raw.(type) {
	case map[string]any:
		return typed
	case string:
		var decoded map[string]any
		if err := json.Unmarshal([]byte(typed), &decoded); err == nil {
			return decoded
		}
	case []byte:
		var decoded map[string]any
		if err := json.Unmarshal(typed, &decoded); err == nil {
			return decoded
		}
	}
	return nil
}

func relationshipPropertyString(edge *Edge, key string) string {
	return strings.TrimSpace(queryRowString(relationshipProperties(edge), key))
}

func delegatedGrantKey(edge *Edge) string {
	if edge == nil {
		return ""
	}
	if grantID := relationshipPropertyString(edge, "grant_id"); grantID != "" {
		return grantID
	}
	grantType := strings.ToLower(relationshipPropertyString(edge, "grant_type"))
	if !strings.HasPrefix(grantType, "delegated_permission") {
		return ""
	}
	return strings.Join([]string{
		edge.Source,
		edge.Target,
		grantType,
		strings.ToLower(relationshipPropertyString(edge, "consent_type")),
		relationshipPropertyString(edge, "scope"),
	}, "|")
}

func appendDelegatedScopes(edge *Edge, scopes map[string]struct{}) {
	if edge == nil || scopes == nil {
		return
	}
	for _, scope := range strings.Fields(relationshipPropertyString(edge, "scope")) {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		scopes[scope] = struct{}{}
	}
}

func edgesByPermission(edges []*Edge) (map[string]struct{}, map[string]struct{}, map[string]struct{}, map[string]struct{}) {
	accessibleTargets := make(map[string]struct{})
	readableTargets := make(map[string]struct{})
	writableTargets := make(map[string]struct{})
	adminTargets := make(map[string]struct{})

	for _, edge := range edges {
		if edge == nil {
			continue
		}
		switch edge.Kind {
		case EdgeKindCanRead:
			accessibleTargets[edge.Target] = struct{}{}
			readableTargets[edge.Target] = struct{}{}
		case EdgeKindCanWrite:
			accessibleTargets[edge.Target] = struct{}{}
			writableTargets[edge.Target] = struct{}{}
		case EdgeKindCanAdmin, EdgeKindCanDelete:
			accessibleTargets[edge.Target] = struct{}{}
			adminTargets[edge.Target] = struct{}{}
		}
	}
	return accessibleTargets, readableTargets, writableTargets, adminTargets
}

func (b *Builder) ensureVendorNode(projection *vendorProjection) *Node {
	if projection == nil {
		return nil
	}
	if existing, ok := b.graph.GetNode(projection.id); ok && existing != nil {
		if existing.Properties == nil {
			existing.Properties = make(map[string]any)
		}
		existing.Kind = NodeKindVendor
		existing.Name = projection.name
		existing.Properties["source_system"] = vendorProjectionSourceSystem
		return existing
	}

	vendor := &Node{
		ID:   projection.id,
		Kind: NodeKindVendor,
		Name: projection.name,
		Properties: map[string]any{
			"canonical_name": projection.name,
			"source_system":  vendorProjectionSourceSystem,
		},
	}
	b.graph.AddNode(vendor)
	resolved, _ := b.graph.GetNode(projection.id)
	if resolved == nil {
		return nil
	}
	return resolved
}

func (b *Builder) refreshVendorSignals(vendor *Node, projection *vendorProjection) {
	if vendor == nil || projection == nil {
		return
	}
	if vendor.Properties == nil {
		vendor.Properties = make(map[string]any)
	}

	var managedApplicationCount int
	var managedServiceAccountCount int
	var anonymousApplicationCount int
	var nativeApplicationCount int
	var appRoleAssignmentRequiredCount int
	var appRoleAssignmentOptionalCount int
	var verifiedIntegrationCount int
	var unverifiedIntegrationCount int
	accessibleTargets := make(map[string]struct{})
	readableTargets := make(map[string]struct{})
	writableTargets := make(map[string]struct{})
	adminTargets := make(map[string]struct{})
	accessibleResourceKinds := make(map[string]struct{})
	sensitiveTargets := make(map[string]struct{})
	dependentPrincipals := make(map[string]struct{})
	dependentUsers := make(map[string]struct{})
	dependentGroups := make(map[string]struct{})
	dependentServiceAccounts := make(map[string]struct{})
	delegatedGrantIDs := make(map[string]struct{})
	delegatedAdminConsentGrantIDs := make(map[string]struct{})
	delegatedPrincipalConsentGrantIDs := make(map[string]struct{})
	delegatedScopes := make(map[string]struct{})
	verifiedPublisherIDs := make(map[string]struct{})
	verifiedPublisherNames := make(map[string]struct{})

	for managedNodeID := range projection.managedNodeIDs {
		node, ok := b.graph.GetNode(managedNodeID)
		if !ok || node == nil {
			continue
		}
		switch node.Kind {
		case NodeKindApplication:
			managedApplicationCount++
			if anonymous, ok := boolPropertyValue(node.Properties, "anonymous"); ok && anonymous {
				anonymousApplicationCount++
			}
			if nativeApp, ok := boolPropertyValue(node.Properties, "native_app"); ok && nativeApp {
				nativeApplicationCount++
			}
		case NodeKindServiceAccount:
			managedServiceAccountCount++
		}
		if node.Kind == NodeKindServiceAccount {
			if required, ok := boolPropertyValue(node.Properties, "app_role_assignment_required"); ok {
				if required {
					appRoleAssignmentRequiredCount++
				} else {
					appRoleAssignmentOptionalCount++
				}
			}
			if verifiedPublisherID := strings.TrimSpace(propertyString(node.Properties, "verified_publisher_id")); verifiedPublisherID != "" {
				verifiedIntegrationCount++
				verifiedPublisherIDs[verifiedPublisherID] = struct{}{}
				if verifiedPublisherName := strings.TrimSpace(propertyString(node.Properties, "verified_publisher_display_name")); verifiedPublisherName != "" {
					verifiedPublisherNames[verifiedPublisherName] = struct{}{}
				}
			} else if strings.TrimSpace(propertyString(node.Properties, "publisher_name")) != "" {
				unverifiedIntegrationCount++
			}
		}
		outEdges := permissionEdges(b.graph.GetOutEdges(managedNodeID))
		nodeAccessibleTargets, nodeReadableTargets, nodeWritableTargets, nodeAdminTargets := edgesByPermission(outEdges)
		for target := range nodeAccessibleTargets {
			accessibleTargets[target] = struct{}{}
		}
		for target := range nodeReadableTargets {
			readableTargets[target] = struct{}{}
		}
		for target := range nodeWritableTargets {
			writableTargets[target] = struct{}{}
		}
		for target := range nodeAdminTargets {
			adminTargets[target] = struct{}{}
		}
		for kind := range targetKindsForEdges(b.graph, outEdges) {
			accessibleResourceKinds[kind] = struct{}{}
		}
		for target := range sensitiveTargetsForEdges(b.graph, outEdges) {
			sensitiveTargets[target] = struct{}{}
		}
		for _, edge := range outEdges {
			grantType := strings.ToLower(relationshipPropertyString(edge, "grant_type"))
			if grantType != "delegated_permission" {
				continue
			}
			if grantKey := delegatedGrantKey(edge); grantKey != "" {
				delegatedGrantIDs[grantKey] = struct{}{}
				if strings.EqualFold(relationshipPropertyString(edge, "consent_type"), "AllPrincipals") {
					delegatedAdminConsentGrantIDs[grantKey] = struct{}{}
				}
			}
			appendDelegatedScopes(edge, delegatedScopes)
		}
		for _, edge := range permissionEdges(b.graph.GetInEdges(managedNodeID)) {
			if !strings.EqualFold(relationshipPropertyString(edge, "grant_type"), "delegated_permission_consent") {
				continue
			}
			if grantKey := delegatedGrantKey(edge); grantKey != "" {
				delegatedGrantIDs[grantKey] = struct{}{}
				delegatedPrincipalConsentGrantIDs[grantKey] = struct{}{}
			}
			appendDelegatedScopes(edge, delegatedScopes)
		}
		collectVendorDependentPrincipals(b.graph, managedNodeID, dependentPrincipals, dependentUsers, dependentGroups, dependentServiceAccounts)
	}

	riskScore := vendorRiskScore(
		len(readableTargets),
		len(writableTargets),
		len(adminTargets),
		len(accessibleTargets),
		len(sensitiveTargets),
		len(dependentPrincipals),
		len(dependentGroups),
		appRoleAssignmentOptionalCount,
		len(delegatedAdminConsentGrantIDs),
		len(delegatedScopes),
		anonymousApplicationCount,
		nativeApplicationCount,
	)

	vendor.Properties["canonical_name"] = vendor.Name
	vendor.Properties["source_system"] = vendorProjectionSourceSystem
	vendor.Properties["aliases"] = vendorDisplayAliases(projection.rawNames, vendor.Name)
	vendor.Properties["owner_organization_ids"] = sortedVendorKeys(projection.ownerOrganizationIDs)
	vendor.Properties["source_providers"] = sortedVendorKeys(projection.sourceProviders)
	vendor.Properties["integration_types"] = sortedVendorKeys(projection.integrationTypes)
	vendor.Properties["vendor_category"] = vendorCategory(projection.integrationTypes)
	vendor.Properties["managed_node_count"] = len(projection.managedNodeIDs)
	vendor.Properties["managed_application_count"] = managedApplicationCount
	vendor.Properties["managed_service_account_count"] = managedServiceAccountCount
	vendor.Properties["anonymous_application_count"] = anonymousApplicationCount
	vendor.Properties["native_application_count"] = nativeApplicationCount
	vendor.Properties["verified_publisher_count"] = verifiedIntegrationCount
	vendor.Properties["verified_publisher_ids"] = sortedVendorKeys(verifiedPublisherIDs)
	vendor.Properties["verified_publisher_names"] = sortedVendorKeys(verifiedPublisherNames)
	vendor.Properties["unverified_integration_count"] = unverifiedIntegrationCount
	vendor.Properties["verification_status"] = vendorVerificationStatus(verifiedIntegrationCount, unverifiedIntegrationCount)
	vendor.Properties["app_role_assignment_required_count"] = appRoleAssignmentRequiredCount
	vendor.Properties["app_role_assignment_optional_count"] = appRoleAssignmentOptionalCount
	vendor.Properties["accessible_resource_count"] = len(accessibleTargets)
	vendor.Properties["accessible_resource_kinds"] = sortedVendorKeys(accessibleResourceKinds)
	vendor.Properties["sensitive_resource_count"] = len(sensitiveTargets)
	vendor.Properties["delegated_grant_count"] = len(delegatedGrantIDs)
	vendor.Properties["delegated_admin_consent_count"] = len(delegatedAdminConsentGrantIDs)
	vendor.Properties["delegated_principal_consent_count"] = len(delegatedPrincipalConsentGrantIDs)
	vendor.Properties["delegated_scope_count"] = len(delegatedScopes)
	vendor.Properties["delegated_scopes"] = sortedVendorKeys(delegatedScopes)
	vendor.Properties["read_access_count"] = len(readableTargets)
	vendor.Properties["write_access_count"] = len(writableTargets)
	vendor.Properties["admin_access_count"] = len(adminTargets)
	vendor.Properties["dependent_principal_count"] = len(dependentPrincipals)
	vendor.Properties["dependent_user_count"] = len(dependentUsers)
	vendor.Properties["dependent_group_count"] = len(dependentGroups)
	vendor.Properties["dependent_service_account_count"] = len(dependentServiceAccounts)
	vendor.Properties["vendor_risk_score"] = riskScore
	vendor.Properties["permission_level"] = vendorPermissionLevel(len(readableTargets), len(writableTargets), len(adminTargets))
	vendor.Risk = vendorRiskLevelFromScore(riskScore)
}

func vendorIdentityForNode(node *Node) (vendorIdentity, bool) {
	if node == nil {
		return vendorIdentity{}, false
	}

	switch {
	case node.Provider == "okta" && node.Kind == NodeKindApplication:
		rawName := strings.TrimSpace(node.Name)
		aliasKey := vendorAliasKey(rawName)
		if rawName == "" || aliasKey == "" {
			return vendorIdentity{}, false
		}
		return vendorIdentity{
			rawName:         rawName,
			aliasKey:        aliasKey,
			integrationType: "okta_application",
		}, true
	case node.Provider == "azure" && node.Kind == NodeKindServiceAccount:
		if !strings.EqualFold(propertyString(node.Properties, "azure_resource_type"), "service_principal") {
			return vendorIdentity{}, false
		}
		principalType := strings.ToLower(strings.TrimSpace(firstNonEmpty(
			propertyString(node.Properties, "identity_type"),
			propertyString(node.Properties, "type"),
		)))
		if strings.Contains(principalType, "managed") {
			return vendorIdentity{}, false
		}
		rawName := strings.TrimSpace(firstNonEmpty(
			propertyString(node.Properties, "verified_publisher_display_name"),
			propertyString(node.Properties, "publisher_name"),
		))
		aliasKey := vendorAliasKey(rawName)
		if rawName == "" || aliasKey == "" {
			return vendorIdentity{}, false
		}
		return vendorIdentity{
			rawName:             rawName,
			aliasKey:            aliasKey,
			ownerOrgID:          strings.TrimSpace(propertyString(node.Properties, "app_owner_organization_id")),
			verifiedPublisherID: strings.TrimSpace(propertyString(node.Properties, "verified_publisher_id")),
			integrationType:     "entra_service_principal",
		}, true
	case node.Provider == "google_workspace" && node.Kind == NodeKindApplication:
		rawName := strings.TrimSpace(firstNonEmpty(
			propertyString(node.Properties, "display_text"),
			node.Name,
		))
		aliasKey := vendorAliasKey(rawName)
		if rawName == "" || aliasKey == "" {
			return vendorIdentity{}, false
		}
		return vendorIdentity{
			rawName:         rawName,
			aliasKey:        aliasKey,
			integrationType: "google_workspace_application",
		}, true
	default:
		return vendorIdentity{}, false
	}
}

func vendorNodeID(name string) string {
	normalized := normalizeOrgKey(name)
	if normalized == "" {
		return ""
	}
	return "vendor:" + normalized
}

func collectVendorDependentPrincipals(g *Graph, managedNodeID string, all, users, groups, serviceAccounts map[string]struct{}) {
	if g == nil || managedNodeID == "" {
		return
	}
	seenGroups := make(map[string]struct{})
	for _, edge := range permissionEdges(g.GetInEdges(managedNodeID)) {
		if edge == nil {
			continue
		}
		source, ok := g.GetNode(edge.Source)
		if !ok || source == nil {
			continue
		}
		switch source.Kind {
		case NodeKindUser:
			all[source.ID] = struct{}{}
			users[source.ID] = struct{}{}
		case NodeKindServiceAccount:
			all[source.ID] = struct{}{}
			serviceAccounts[source.ID] = struct{}{}
		case NodeKindGroup:
			collectVendorGroupDependents(g, source.ID, seenGroups, all, users, groups, serviceAccounts)
		}
	}
}

func collectVendorGroupDependents(g *Graph, groupID string, seenGroups, all, users, groups, serviceAccounts map[string]struct{}) {
	if g == nil || groupID == "" {
		return
	}
	queue := []string{groupID}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if _, ok := seenGroups[current]; ok {
			continue
		}
		seenGroups[current] = struct{}{}
		all[current] = struct{}{}
		groups[current] = struct{}{}
		for _, edge := range g.GetInEdges(current) {
			if edge == nil || edge.Kind != EdgeKindMemberOf {
				continue
			}
			source, ok := g.GetNode(edge.Source)
			if !ok || source == nil {
				continue
			}
			switch source.Kind {
			case NodeKindUser:
				all[source.ID] = struct{}{}
				users[source.ID] = struct{}{}
			case NodeKindServiceAccount:
				all[source.ID] = struct{}{}
				serviceAccounts[source.ID] = struct{}{}
			case NodeKindGroup:
				queue = append(queue, source.ID)
			}
		}
	}
}

func vendorRiskScore(readCount, writeCount, adminCount, accessibleResourceCount, sensitiveResourceCount, dependentPrincipalCount, dependentGroupCount, optionalAssignmentCount, delegatedAdminConsentCount, delegatedScopeCount, anonymousApplicationCount, nativeApplicationCount int) int {
	score := 0
	switch {
	case adminCount > 0:
		score += 70
	case writeCount > 0:
		score += 45
	case readCount > 0:
		score += 20
	}
	score += minInt(10, accessibleResourceCount*3)
	score += minInt(15, sensitiveResourceCount*10)
	score += minInt(15, dependentPrincipalCount*2)
	score += minInt(10, dependentGroupCount*5)
	score += minInt(10, optionalAssignmentCount*5)
	score += minInt(15, delegatedAdminConsentCount*15)
	score += minInt(10, delegatedScopeCount*2)
	score += minInt(10, anonymousApplicationCount*8)
	score += minInt(5, nativeApplicationCount*2)
	if score > 100 {
		return 100
	}
	return score
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

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func vendorVerificationStatus(verifiedIntegrationCount, unverifiedIntegrationCount int) string {
	switch {
	case verifiedIntegrationCount > 0 && unverifiedIntegrationCount == 0:
		return "verified"
	case verifiedIntegrationCount > 0 && unverifiedIntegrationCount > 0:
		return "mixed"
	case unverifiedIntegrationCount > 0:
		return "unverified"
	default:
		return "unknown"
	}
}

func propertyString(properties map[string]any, key string) string {
	if properties == nil {
		return ""
	}
	return strings.TrimSpace(queryRowString(properties, key))
}

func sortedVendorKeys(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		if strings.TrimSpace(key) == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
