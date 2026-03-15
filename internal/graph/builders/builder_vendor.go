package builders

import (
	"sort"
	"strings"
)

const vendorProjectionSourceSystem = "graph_builder_vendor_projection"

type vendorProjection struct {
	id               string
	name             string
	sourceProviders  map[string]struct{}
	integrationTypes map[string]struct{}
	managedNodeIDs   map[string]struct{}
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

	projections := make(map[string]*vendorProjection)
	for _, node := range candidates {
		if node == nil || node.Kind == NodeKindVendor {
			continue
		}
		name, integrationType, ok := vendorIdentityForNode(node)
		if !ok {
			continue
		}
		vendorID := vendorNodeID(name)
		if vendorID == "" {
			continue
		}

		projection, exists := projections[vendorID]
		if !exists {
			projection = &vendorProjection{
				id:               vendorID,
				name:             strings.TrimSpace(name),
				sourceProviders:  make(map[string]struct{}),
				integrationTypes: make(map[string]struct{}),
				managedNodeIDs:   make(map[string]struct{}),
			}
			projections[vendorID] = projection
		}
		if projection.name == "" {
			projection.name = strings.TrimSpace(name)
		}
		if provider := strings.TrimSpace(node.Provider); provider != "" {
			projection.sourceProviders[provider] = struct{}{}
		}
		if integrationType != "" {
			projection.integrationTypes[integrationType] = struct{}{}
		}
		projection.managedNodeIDs[node.ID] = struct{}{}
	}

	for _, projection := range projections {
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

func (b *Builder) ensureVendorNode(projection *vendorProjection) *Node {
	if projection == nil {
		return nil
	}
	if existing, ok := b.graph.GetNode(projection.id); ok && existing != nil {
		if existing.Properties == nil {
			existing.Properties = make(map[string]any)
		}
		existing.Kind = NodeKindVendor
		if strings.TrimSpace(existing.Name) == "" {
			existing.Name = projection.name
		}
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
	readableTargets := make(map[string]struct{})
	writableTargets := make(map[string]struct{})
	adminTargets := make(map[string]struct{})
	accessibleTargets := make(map[string]struct{})

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
		for _, edge := range b.graph.GetOutEdges(managedNodeID) {
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
	}

	vendor.Properties["canonical_name"] = vendor.Name
	vendor.Properties["source_system"] = vendorProjectionSourceSystem
	vendor.Properties["source_providers"] = sortedVendorKeys(projection.sourceProviders)
	vendor.Properties["integration_types"] = sortedVendorKeys(projection.integrationTypes)
	vendor.Properties["managed_node_count"] = len(projection.managedNodeIDs)
	vendor.Properties["managed_application_count"] = managedApplicationCount
	vendor.Properties["managed_service_account_count"] = managedServiceAccountCount
	vendor.Properties["accessible_resource_count"] = len(accessibleTargets)
	vendor.Properties["read_access_count"] = len(readableTargets)
	vendor.Properties["write_access_count"] = len(writableTargets)
	vendor.Properties["admin_access_count"] = len(adminTargets)
	vendor.Risk = vendorRiskLevel(len(readableTargets), len(writableTargets), len(adminTargets))
}

func vendorIdentityForNode(node *Node) (string, string, bool) {
	if node == nil {
		return "", "", false
	}

	switch {
	case node.Provider == "okta" && node.Kind == NodeKindApplication:
		name := strings.TrimSpace(node.Name)
		if name == "" {
			return "", "", false
		}
		return name, "okta_application", true
	case node.Provider == "azure" && node.Kind == NodeKindServiceAccount:
		if !strings.EqualFold(propertyString(node.Properties, "azure_resource_type"), "service_principal") {
			return "", "", false
		}
		principalType := strings.ToLower(strings.TrimSpace(firstNonEmpty(
			propertyString(node.Properties, "identity_type"),
			propertyString(node.Properties, "type"),
		)))
		if strings.Contains(principalType, "managed") {
			return "", "", false
		}
		name := strings.TrimSpace(propertyString(node.Properties, "publisher_name"))
		if name == "" {
			return "", "", false
		}
		return name, "entra_service_principal", true
	default:
		return "", "", false
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
