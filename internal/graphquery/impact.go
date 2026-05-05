package graphquery

import (
	"context"
	"fmt"
	"sort"
	"strings"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/writer/cerebro/internal/ports"
)

const (
	ImpactKindAsset         = "asset"
	ImpactKindPackage       = "package"
	ImpactKindVulnerability = "vulnerability"

	defaultImpactDepth = 4
	defaultImpactLimit = 100
	maxImpactDepth     = 6
	maxImpactLimit     = 250
)

type ImpactRequest struct {
	Kind       string
	TenantID   string
	Identifier string
	RootURN    string
	Depth      uint32
	Limit      uint32
}

type ImpactResult struct {
	Kind            string                        `json:"kind"`
	Query           string                        `json:"query"`
	RootURN         string                        `json:"root_urn"`
	Root            *ports.NeighborhoodNode       `json:"root,omitempty"`
	Assets          []*ports.NeighborhoodNode     `json:"assets"`
	Packages        []*ports.NeighborhoodNode     `json:"packages"`
	Vulnerabilities []*ports.NeighborhoodNode     `json:"vulnerabilities"`
	Evidence        []*ports.NeighborhoodNode     `json:"evidence"`
	Relations       []*ports.NeighborhoodRelation `json:"relations"`
}

func (s *Service) GetImpact(ctx context.Context, request ImpactRequest) (*ImpactResult, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	rootURN, err := impactRootURN(request)
	if err != nil {
		return nil, err
	}
	if err := validateCerebroURN(rootURN); err != nil {
		return nil, err
	}
	depth := normalizeImpactDepth(request.Depth)
	limit := normalizeImpactLimit(request.Limit)
	nodes, relations, err := s.collectImpactGraph(ctx, rootURN, depth, limit)
	if err != nil {
		return nil, err
	}
	result := &ImpactResult{
		Kind:      normalizeImpactKind(request.Kind),
		Query:     strings.TrimSpace(request.Identifier),
		RootURN:   rootURN,
		Root:      nodes[rootURN],
		Relations: sortedImpactRelations(relations),
	}
	for _, node := range sortedImpactNodes(nodes) {
		switch {
		case classifyImpactNode(node) == ImpactKindPackage:
			result.Packages = append(result.Packages, node)
		case classifyImpactNode(node) == ImpactKindVulnerability:
			result.Vulnerabilities = append(result.Vulnerabilities, node)
		case classifyImpactNode(node) == "evidence":
			result.Evidence = append(result.Evidence, node)
		default:
			result.Assets = append(result.Assets, node)
		}
	}
	return result, nil
}

func (s *Service) collectImpactGraph(ctx context.Context, rootURN string, depth int, limit int) (map[string]*ports.NeighborhoodNode, map[string]*ports.NeighborhoodRelation, error) {
	nodes := map[string]*ports.NeighborhoodNode{}
	relations := map[string]*ports.NeighborhoodRelation{}
	visited := map[string]bool{}
	frontier := []string{rootURN}
	for hop := 0; hop <= depth && len(frontier) > 0 && len(nodes) < limit; hop++ {
		next := []string{}
		for _, urn := range frontier {
			if visited[urn] || len(nodes) >= limit {
				continue
			}
			visited[urn] = true
			neighborhood, err := s.store.GetEntityNeighborhood(ctx, urn, limit)
			if err != nil {
				return nil, nil, err
			}
			if neighborhood == nil {
				continue
			}
			addImpactNode(nodes, neighborhood.Root, limit)
			for _, neighbor := range neighborhood.Neighbors {
				if addImpactNode(nodes, neighbor, limit) && !visited[neighbor.URN] {
					next = append(next, neighbor.URN)
				}
			}
			for _, relation := range neighborhood.Relations {
				if relation == nil {
					continue
				}
				key := relation.FromURN + "|" + relation.Relation + "|" + relation.ToURN
				relations[key] = relation
			}
		}
		frontier = next
	}
	return nodes, relations, nil
}

func impactRootURN(request ImpactRequest) (string, error) {
	if rootURN := strings.TrimSpace(request.RootURN); rootURN != "" {
		return rootURN, nil
	}
	identifier := strings.TrimSpace(request.Identifier)
	if strings.HasPrefix(identifier, "urn:cerebro:") {
		return identifier, nil
	}
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return "", fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	switch normalizeImpactKind(request.Kind) {
	case ImpactKindVulnerability:
		if identifier == "" {
			return "", fmt.Errorf("%w: vulnerability identifier is required", ErrInvalidRequest)
		}
		return projectionURN(tenantID, "vulnerability", strings.ToLower(identifier)), nil
	case ImpactKindPackage:
		if identifier == "" {
			return "", fmt.Errorf("%w: package identifier is required", ErrInvalidRequest)
		}
		return projectionURN(tenantID, "package", "canonical", canonicalPackageImpactIdentity(identifier)), nil
	case ImpactKindAsset:
		return "", fmt.Errorf("%w: asset impact requires a root urn", ErrInvalidRequest)
	default:
		return "", fmt.Errorf("%w: unsupported impact kind %q", ErrInvalidRequest, request.Kind)
	}
}

func normalizeImpactKind(kind string) string {
	switch strings.TrimSpace(strings.ToLower(kind)) {
	case "cve", "vuln", "vulnerability":
		return ImpactKindVulnerability
	case "pkg", "package":
		return ImpactKindPackage
	case "asset", "root":
		return ImpactKindAsset
	default:
		return strings.TrimSpace(strings.ToLower(kind))
	}
}

func normalizeImpactDepth(depth uint32) int {
	switch {
	case depth == 0:
		return defaultImpactDepth
	case depth > maxImpactDepth:
		return maxImpactDepth
	default:
		return int(depth)
	}
}

func normalizeImpactLimit(limit uint32) int {
	switch {
	case limit == 0:
		return defaultImpactLimit
	case limit > maxImpactLimit:
		return maxImpactLimit
	default:
		return int(limit)
	}
}

func addImpactNode(nodes map[string]*ports.NeighborhoodNode, node *ports.NeighborhoodNode, limit int) bool {
	if node == nil || strings.TrimSpace(node.URN) == "" {
		return false
	}
	if _, ok := nodes[node.URN]; ok {
		return false
	}
	if len(nodes) >= limit {
		return false
	}
	nodes[node.URN] = node
	return true
}

func classifyImpactNode(node *ports.NeighborhoodNode) string {
	if node == nil {
		return ""
	}
	entityType := strings.ToLower(strings.TrimSpace(node.EntityType))
	switch {
	case entityType == "package":
		return ImpactKindPackage
	case entityType == "vulnerability" || strings.Contains(entityType, "advisory"):
		return ImpactKindVulnerability
	case strings.Contains(entityType, "alert") || strings.Contains(entityType, "evidence") || strings.Contains(entityType, "finding"):
		return "evidence"
	default:
		return ImpactKindAsset
	}
}

func sortedImpactNodes(nodes map[string]*ports.NeighborhoodNode) []*ports.NeighborhoodNode {
	result := make([]*ports.NeighborhoodNode, 0, len(nodes))
	for _, node := range nodes {
		result = append(result, node)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].URN < result[j].URN })
	return result
}

func sortedImpactRelations(relations map[string]*ports.NeighborhoodRelation) []*ports.NeighborhoodRelation {
	result := make([]*ports.NeighborhoodRelation, 0, len(relations))
	for _, relation := range relations {
		result = append(result, relation)
	}
	sort.Slice(result, func(i, j int) bool {
		left := result[i].FromURN + "|" + result[i].Relation + "|" + result[i].ToURN
		right := result[j].FromURN + "|" + result[j].Relation + "|" + result[j].ToURN
		return left < right
	})
	return result
}

func canonicalPackageImpactIdentity(value string) string {
	normalized := strings.TrimSpace(value)
	if purl, err := packageurl.FromString(normalized); err == nil {
		purl.Version = ""
		purl.Qualifiers = nil
		purl.Subpath = ""
		return strings.TrimSpace(purl.ToString())
	}
	if index := strings.IndexAny(normalized, "?#"); index >= 0 {
		normalized = normalized[:index]
	}
	lastSlash := strings.LastIndex(normalized, "/")
	if versionIndex := strings.LastIndex(normalized, "@"); versionIndex > lastSlash {
		normalized = normalized[:versionIndex]
	}
	return strings.TrimSpace(normalized)
}

func projectionURN(tenantID string, kind string, parts ...string) string {
	tenant := strings.TrimSpace(tenantID)
	entityKind := strings.TrimSpace(kind)
	if tenant == "" || entityKind == "" {
		return ""
	}
	values := make([]string, 0, len(parts)+4)
	values = append(values, "urn", "cerebro", tenant, entityKind)
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value != "" {
			values = append(values, value)
		}
	}
	return strings.Join(values, ":")
}
