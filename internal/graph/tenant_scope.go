package graph

import (
	"sort"
	"strings"
)

const tenantPropertyKey = "tenant_id"

func normalizeNodeTenantID(node *Node) {
	if node == nil {
		return
	}
	tenantID := strings.TrimSpace(node.TenantID)
	if tenantID == "" && node.Properties != nil {
		tenantID = strings.TrimSpace(readString(node.Properties, tenantPropertyKey))
	}
	node.TenantID = tenantID
	if tenantID == "" {
		return
	}
	if node.Properties == nil {
		node.Properties = make(map[string]any, 1)
	}
	node.Properties[tenantPropertyKey] = tenantID
}

func nodeTenantID(node *Node) string {
	if node == nil {
		return ""
	}
	if tenantID := strings.TrimSpace(node.TenantID); tenantID != "" {
		return tenantID
	}
	if node.Properties == nil {
		return ""
	}
	return strings.TrimSpace(readString(node.Properties, tenantPropertyKey))
}

// NodeVisibleToTenant returns true when a node is visible to a tenant-scoped query.
// Empty tenant scope keeps the full graph visible. Untagged nodes are treated as shared.
func NodeVisibleToTenant(node *Node, tenantID string) bool {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return true
	}
	nodeTenant := nodeTenantID(node)
	return nodeTenant == "" || nodeTenant == tenantID
}

// HasScopedNodesForTenant returns true when the graph contains at least one node
// explicitly scoped to the requested tenant.
func (g *Graph) HasScopedNodesForTenant(tenantID string) bool {
	tenantID = strings.TrimSpace(tenantID)
	if g == nil {
		return false
	}
	if tenantID == "" {
		return false
	}
	for _, node := range g.GetAllNodes() {
		if nodeTenantID(node) == tenantID {
			return true
		}
	}
	return false
}

// SubgraphForTenantWithScopedNodes returns one graph view scoped to nodes
// visible to the tenant together with whether the source graph contained any
// nodes explicitly scoped to that tenant.
//
// Empty tenant scope returns the original graph and reports no tenant-scoped
// nodes to avoid unnecessary cloning.
func (g *Graph) SubgraphForTenantWithScopedNodes(tenantID string) (*Graph, bool) {
	tenantID = strings.TrimSpace(tenantID)
	if g == nil {
		return nil, false
	}
	if tenantID == "" {
		return g, false
	}

	out := New()
	out.SetSchemaValidationMode(g.SchemaValidationMode())
	hasScopedNodes := false
	for _, node := range g.GetAllNodes() {
		nodeTenant := nodeTenantID(node)
		if nodeTenant == tenantID {
			hasScopedNodes = true
		}
		if nodeTenant != "" && nodeTenant != tenantID {
			continue
		}
		out.AddNode(cloneNode(node))
	}
	for _, node := range out.GetAllNodes() {
		for _, edge := range g.GetOutEdges(node.ID) {
			if edge == nil {
				continue
			}
			if _, ok := out.GetNode(edge.Source); !ok {
				continue
			}
			if _, ok := out.GetNode(edge.Target); !ok {
				continue
			}
			out.AddEdge(cloneEdge(edge))
		}
	}

	meta := g.Metadata()
	meta.NodeCount = out.NodeCount()
	meta.EdgeCount = out.EdgeCount()
	meta.Accounts = uniqueNonEmptyNodeStrings(out.GetAllNodes(), func(node *Node) string { return node.Account })
	meta.Providers = uniqueNonEmptyNodeStrings(out.GetAllNodes(), func(node *Node) string { return node.Provider })
	out.SetMetadata(meta)
	out.BuildIndex()
	return out, hasScopedNodes
}

// SubgraphForTenant returns one graph view scoped to nodes visible to the
// tenant. Empty tenant scope returns the original graph to avoid unnecessary
// cloning.
func (g *Graph) SubgraphForTenant(tenantID string) *Graph {
	out, _ := g.SubgraphForTenantWithScopedNodes(tenantID)
	return out
}

func uniqueNonEmptyNodeStrings(nodes []*Node, value func(*Node) string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if node == nil {
			continue
		}
		candidate := strings.TrimSpace(value(node))
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	sort.Strings(out)
	return out
}
