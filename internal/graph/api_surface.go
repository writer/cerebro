package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const defaultAPISurfaceMaxDepth = 4

type APISurfaceReportOptions struct {
	IncludeInternal bool `json:"include_internal"`
	MaxDepth        int  `json:"max_depth"`
	Limit           int  `json:"limit"`
}

type APISurfaceReport struct {
	GeneratedAt time.Time            `json:"generated_at"`
	Summary     APISurfaceSummary    `json:"summary"`
	Count       int                  `json:"count"`
	Endpoints   []APISurfaceEndpoint `json:"endpoints"`
	Findings    []APISurfaceFinding  `json:"findings,omitempty"`
}

type APISurfaceSummary struct {
	EndpointCount         int      `json:"endpoint_count"`
	PublicEndpointCount   int      `json:"public_endpoint_count"`
	InternalEndpointCount int      `json:"internal_endpoint_count"`
	NoAuthFindingCount    int      `json:"no_auth_finding_count"`
	CORSFindingCount      int      `json:"cors_finding_count"`
	Providers             []string `json:"providers,omitempty"`
}

type APISurfaceEndpoint struct {
	ID                 string              `json:"id"`
	URL                string              `json:"url"`
	Method             string              `json:"method,omitempty"`
	Host               string              `json:"host,omitempty"`
	Path               string              `json:"path,omitempty"`
	Provider           string              `json:"provider,omitempty"`
	Account            string              `json:"account,omitempty"`
	Region             string              `json:"region,omitempty"`
	Public             bool                `json:"public"`
	AuthType           string              `json:"auth_type,omitempty"`
	APIKeyRequired     bool                `json:"api_key_required,omitempty"`
	CORSPermissive     bool                `json:"cors_permissive,omitempty"`
	ExposureSource     string              `json:"exposure_source,omitempty"`
	ProviderService    string              `json:"provider_service,omitempty"`
	ServedBy           []APISurfaceNodeRef `json:"served_by,omitempty"`
	BackendTargets     []APISurfaceNodeRef `json:"backend_targets,omitempty"`
	ReachableResources []APISurfaceNodeRef `json:"reachable_resources,omitempty"`
}

type APISurfaceNodeRef struct {
	ID   string    `json:"id"`
	Kind NodeKind  `json:"kind"`
	Name string    `json:"name,omitempty"`
	Risk RiskLevel `json:"risk,omitempty"`
}

type APISurfaceFinding struct {
	ID         string `json:"id"`
	EndpointID string `json:"endpoint_id"`
	Category   string `json:"category"`
	Severity   string `json:"severity"`
	Title      string `json:"title"`
	Message    string `json:"message"`
}

func AnalyzeAPISurface(g *Graph, opts APISurfaceReportOptions) APISurfaceReport {
	report := APISurfaceReport{
		GeneratedAt: time.Now().UTC(),
		Endpoints:   make([]APISurfaceEndpoint, 0),
		Findings:    make([]APISurfaceFinding, 0),
	}
	if g == nil {
		return report
	}

	maxDepth := opts.MaxDepth
	if maxDepth <= 0 {
		maxDepth = defaultAPISurfaceMaxDepth
	}

	providers := make(map[string]struct{})
	for _, node := range g.GetNodesByKind(NodeKindAPIEndpoint) {
		if node == nil {
			continue
		}
		endpoint := apiSurfaceEndpointForNode(g, node, maxDepth)
		if !opts.IncludeInternal && !endpoint.Public {
			continue
		}
		report.Endpoints = append(report.Endpoints, endpoint)
		if endpoint.Provider != "" {
			providers[endpoint.Provider] = struct{}{}
		}
		if endpoint.Public {
			report.Summary.PublicEndpointCount++
		} else {
			report.Summary.InternalEndpointCount++
		}
		report.Findings = append(report.Findings, findingsForAPISurfaceEndpoint(endpoint)...)
	}

	sort.Slice(report.Endpoints, func(i, j int) bool {
		if report.Endpoints[i].Public != report.Endpoints[j].Public {
			return report.Endpoints[i].Public
		}
		if report.Endpoints[i].URL != report.Endpoints[j].URL {
			return report.Endpoints[i].URL < report.Endpoints[j].URL
		}
		return report.Endpoints[i].Method < report.Endpoints[j].Method
	})

	if opts.Limit > 0 && len(report.Endpoints) > opts.Limit {
		report.Endpoints = report.Endpoints[:opts.Limit]
	}

	sort.Slice(report.Findings, func(i, j int) bool {
		if report.Findings[i].Severity != report.Findings[j].Severity {
			return severityRank(report.Findings[i].Severity) > severityRank(report.Findings[j].Severity)
		}
		return report.Findings[i].ID < report.Findings[j].ID
	})

	report.Summary.EndpointCount = len(report.Endpoints)
	report.Summary.Providers = sortedProviderKeys(providers)
	for _, finding := range report.Findings {
		switch finding.Category {
		case "missing_auth":
			report.Summary.NoAuthFindingCount++
		case "permissive_cors":
			report.Summary.CORSFindingCount++
		}
	}
	report.Count = len(report.Endpoints)
	return report
}

func apiSurfaceEndpointForNode(g *Graph, node *Node, maxDepth int) APISurfaceEndpoint {
	endpoint := APISurfaceEndpoint{
		ID:              node.ID,
		URL:             nodePropertyString(node, "url"),
		Method:          strings.ToUpper(nodePropertyString(node, "method")),
		Host:            nodePropertyString(node, "host"),
		Path:            nodePropertyString(node, "path"),
		Provider:        node.Provider,
		Account:         node.Account,
		Region:          node.Region,
		Public:          nodePropertyBool(node, "public") || nodeHasInternetExposure(g, node.ID),
		AuthType:        normalizeEndpointAuthType(nodePropertyString(node, "auth_type")),
		APIKeyRequired:  nodePropertyBool(node, "api_key_required"),
		CORSPermissive:  nodePropertyBool(node, "cors_permissive"),
		ExposureSource:  nodePropertyString(node, "exposure_source"),
		ProviderService: nodePropertyString(node, "provider_service"),
		ServedBy:        uniqueAPIRefsFromNodes(g, incomingEdgeSources(g, node.ID, EdgeKindServes)),
		BackendTargets:  apiEndpointBackends(g, node),
	}
	endpoint.ReachableResources = reachableAPIResources(g, node.ID, maxDepth)
	return endpoint
}

func findingsForAPISurfaceEndpoint(endpoint APISurfaceEndpoint) []APISurfaceFinding {
	if !endpoint.Public {
		return nil
	}
	var findings []APISurfaceFinding
	if endpoint.AuthType == "none" && !endpoint.APIKeyRequired {
		findings = append(findings, APISurfaceFinding{
			ID:         "finding:graph-api:no-auth:" + endpoint.ID,
			EndpointID: endpoint.ID,
			Category:   "missing_auth",
			Severity:   "high",
			Title:      "Public API endpoint without authentication",
			Message:    fmt.Sprintf("Public API endpoint %s does not advertise provider-managed authentication.", endpoint.URL),
		})
	}
	if endpoint.CORSPermissive {
		findings = append(findings, APISurfaceFinding{
			ID:         "finding:graph-api:permissive-cors:" + endpoint.ID,
			EndpointID: endpoint.ID,
			Category:   "permissive_cors",
			Severity:   "medium",
			Title:      "Public API endpoint allows permissive CORS",
			Message:    fmt.Sprintf("Public API endpoint %s allows wildcard cross-origin requests.", endpoint.URL),
		})
	}
	return findings
}

func apiEndpointBackends(g *Graph, node *Node) []APISurfaceNodeRef {
	targets := make(map[string]APISurfaceNodeRef)
	for _, edge := range g.GetOutEdges(node.ID) {
		if edge == nil || edge.IsDeny() {
			continue
		}
		if edge.Kind != EdgeKindTargets && edge.Kind != EdgeKindCalls && edge.Kind != EdgeKindConnectsTo {
			continue
		}
		if target, ok := g.GetNode(edge.Target); ok && target != nil {
			targets[target.ID] = apiSurfaceRef(target)
		}
	}
	if backendTargets, ok := node.PropertyValue("backend_targets"); ok {
		for _, backendID := range stringSlice(backendTargets) {
			if backendID == "" {
				continue
			}
			if target, ok := g.GetNode(backendID); ok && target != nil {
				targets[target.ID] = apiSurfaceRef(target)
				continue
			}
			targets[backendID] = APISurfaceNodeRef{ID: backendID}
		}
	}
	out := make([]APISurfaceNodeRef, 0, len(targets))
	for _, ref := range targets {
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func reachableAPIResources(g *Graph, startID string, maxDepth int) []APISurfaceNodeRef {
	if g == nil || strings.TrimSpace(startID) == "" || maxDepth <= 0 {
		return nil
	}
	type frontierItem struct {
		id    string
		depth int
	}
	queue := []frontierItem{{id: startID, depth: 0}}
	visited := map[string]struct{}{startID: {}}
	results := make(map[string]APISurfaceNodeRef)
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.depth >= maxDepth {
			continue
		}
		for _, edge := range g.GetOutEdges(current.id) {
			if edge == nil || edge.IsDeny() {
				continue
			}
			if edge.Target == "" || edge.Target == string(NodeKindInternet) || edge.Target == "internet" {
				continue
			}
			if _, seen := visited[edge.Target]; seen {
				continue
			}
			visited[edge.Target] = struct{}{}
			target, ok := g.GetNode(edge.Target)
			if !ok || target == nil {
				continue
			}
			if target.Kind != NodeKindAPIEndpoint {
				results[target.ID] = apiSurfaceRef(target)
			}
			queue = append(queue, frontierItem{id: target.ID, depth: current.depth + 1})
		}
	}
	out := make([]APISurfaceNodeRef, 0, len(results))
	for _, ref := range results {
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func incomingEdgeSources(g *Graph, targetID string, kind EdgeKind) []string {
	if g == nil || targetID == "" {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, edge := range g.GetInEdges(targetID) {
		if edge == nil || edge.Kind != kind || edge.Source == "" {
			continue
		}
		if _, ok := seen[edge.Source]; ok {
			continue
		}
		seen[edge.Source] = struct{}{}
		out = append(out, edge.Source)
	}
	sort.Strings(out)
	return out
}

func uniqueAPIRefsFromNodes(g *Graph, ids []string) []APISurfaceNodeRef {
	if g == nil || len(ids) == 0 {
		return nil
	}
	out := make([]APISurfaceNodeRef, 0, len(ids))
	for _, id := range ids {
		node, ok := g.GetNode(id)
		if !ok || node == nil {
			continue
		}
		out = append(out, apiSurfaceRef(node))
	}
	return out
}

func apiSurfaceRef(node *Node) APISurfaceNodeRef {
	if node == nil {
		return APISurfaceNodeRef{}
	}
	return APISurfaceNodeRef{
		ID:   node.ID,
		Kind: node.Kind,
		Name: firstNonEmpty(strings.TrimSpace(node.Name), node.ID),
		Risk: node.Risk,
	}
}

func nodeHasInternetExposure(g *Graph, nodeID string) bool {
	if g == nil || nodeID == "" {
		return false
	}
	for _, edge := range g.GetInEdges(nodeID) {
		if edge != nil && edge.Kind == EdgeKindExposedTo && edge.Source == "internet" {
			return true
		}
	}
	return false
}

func nodePropertyString(node *Node, key string) string {
	if node == nil {
		return ""
	}
	value, ok := node.PropertyValue(key)
	if !ok {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", value))
}

func nodePropertyBool(node *Node, key string) bool {
	if node == nil {
		return false
	}
	value, ok := node.PropertyValue(key)
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true", "1", "yes":
			return true
		}
	}
	return false
}

func stringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			text := strings.TrimSpace(fmt.Sprintf("%v", item))
			if text != "" {
				out = append(out, text)
			}
		}
		return out
	case string:
		if trimmed := strings.TrimSpace(typed); trimmed != "" {
			return []string{trimmed}
		}
	}
	return nil
}

func sortedProviderKeys(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func normalizeEndpointAuthType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "unknown":
		return ""
	case "none":
		return "none"
	case "aws_iam", "iam":
		return "iam"
	case "custom", "lambda", "lambda_authorizer":
		return "custom"
	case "cognito", "cognito_user_pools":
		return "cognito"
	case "jwt":
		return "jwt"
	case "oidc":
		return "oidc"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}
