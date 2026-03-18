package builders

import (
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
	rawName         string
	aliasKey        string
	ownerOrgID      string
	integrationType string
}

type vendorProjection struct {
	id                   string
	name                 string
	aliasKey             string
	rawNames             map[string]struct{}
	aliasKeys            map[string]struct{}
	ownerOrganizationIDs map[string]struct{}
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
	var appRoleAssignmentRequiredCount int
	var appRoleAssignmentOptionalCount int
	accessibleTargets := make(map[string]struct{})
	readableTargets := make(map[string]struct{})
	writableTargets := make(map[string]struct{})
	adminTargets := make(map[string]struct{})
	accessibleResourceKinds := make(map[string]struct{})
	sensitiveTargets := make(map[string]struct{})

	for managedNodeID := range projection.managedNodeIDs {
		node, ok := b.graph.GetNode(managedNodeID)
		if !ok || node == nil {
			continue
		}
		switch node.Kind {
		case NodeKindApplication:
			managedApplicationCount++
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
	}

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
	vendor.Properties["app_role_assignment_required_count"] = appRoleAssignmentRequiredCount
	vendor.Properties["app_role_assignment_optional_count"] = appRoleAssignmentOptionalCount
	vendor.Properties["accessible_resource_count"] = len(accessibleTargets)
	vendor.Properties["accessible_resource_kinds"] = sortedVendorKeys(accessibleResourceKinds)
	vendor.Properties["sensitive_resource_count"] = len(sensitiveTargets)
	vendor.Properties["read_access_count"] = len(readableTargets)
	vendor.Properties["write_access_count"] = len(writableTargets)
	vendor.Properties["admin_access_count"] = len(adminTargets)
	vendor.Properties["permission_level"] = vendorPermissionLevel(len(readableTargets), len(writableTargets), len(adminTargets))
	vendor.Risk = vendorRiskLevel(len(readableTargets), len(writableTargets), len(adminTargets))
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
		rawName := strings.TrimSpace(propertyString(node.Properties, "publisher_name"))
		aliasKey := vendorAliasKey(rawName)
		if rawName == "" || aliasKey == "" {
			return vendorIdentity{}, false
		}
		return vendorIdentity{
			rawName:         rawName,
			aliasKey:        aliasKey,
			ownerOrgID:      strings.TrimSpace(propertyString(node.Properties, "app_owner_organization_id")),
			integrationType: "entra_service_principal",
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

func vendorRiskLevel(readCount, writeCount, adminCount int) RiskLevel {
	switch {
	case adminCount > 0:
		return RiskHigh
	case writeCount > 0:
		return RiskMedium
	case readCount > 0:
		return RiskLow
	default:
		return RiskNone
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
