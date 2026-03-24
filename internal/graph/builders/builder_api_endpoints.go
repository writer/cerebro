package builders

import (
	"context"
	"net/url"
	"strings"
)

const (
	apiEndpointProjectionSourcePrefix = "projection:"
	apiEndpointProjectionSourceSystem = apiEndpointProjectionSourcePrefix + "uri_property"
)

func (b *Builder) buildAPIEndpointNodes(ctx context.Context) {
	if b == nil || b.graph == nil {
		return
	}

	b.clearProjectedAPIEndpointNodes()
	b.projectResourceURIAPIEndpoints()
	b.projectAWSAPIEndpoints(ctx)
}

func (b *Builder) projectResourceURIAPIEndpoints() {
	for _, node := range b.graph.GetAllNodes() {
		endpoint, ok := apiEndpointProjectionForNode(node)
		if !ok {
			continue
		}
		b.addAPIEndpointProjection(endpoint, []string{node.ID})
	}
}

func (b *Builder) addAPIEndpointProjection(endpoint apiEndpointProjection, servedBy []string) {
	if b == nil || b.graph == nil || endpoint.ID == "" {
		return
	}

	properties := map[string]any{
		"url":              endpoint.URL,
		"scheme":           endpoint.Scheme,
		"host":             endpoint.Host,
		"path":             endpoint.Path,
		"public":           endpoint.Public,
		"exposure_source":  endpoint.ExposureSource,
		"provider_service": endpoint.ProviderService,
	}
	if endpoint.Method != "" {
		properties["method"] = endpoint.Method
	}
	if endpoint.AuthType != "" {
		properties["auth_type"] = endpoint.AuthType
	}
	if endpoint.APIKeyRequired {
		properties["api_key_required"] = true
	}
	if endpoint.CORSPermissive {
		properties["cors_permissive"] = true
	}
	if len(endpoint.BackendTargets) > 0 {
		properties["backend_targets"] = append([]string(nil), endpoint.BackendTargets...)
	}

	if existing, ok := b.graph.GetNode(endpoint.ID); ok && existing != nil {
		for key, value := range properties {
			existing.Properties[key] = value
		}
		if existing.Name == "" {
			existing.Name = endpoint.displayName()
		}
		existing.Risk = endpointRisk(endpoint.Public)
	} else {
		b.graph.AddNode(&Node{
			ID:         endpoint.ID,
			Kind:       NodeKindAPIEndpoint,
			Name:       endpoint.displayName(),
			Provider:   endpoint.Provider,
			Account:    endpoint.Account,
			Region:     endpoint.Region,
			Risk:       endpointRisk(endpoint.Public),
			Properties: properties,
		})
	}

	for _, sourceID := range servedBy {
		sourceID = strings.TrimSpace(sourceID)
		if sourceID == "" {
			continue
		}
		b.addEdgeIfMissing(&Edge{
			ID:     sourceID + "->" + endpoint.ID + ":serves",
			Source: sourceID,
			Target: endpoint.ID,
			Kind:   EdgeKindServes,
			Effect: EdgeEffectAllow,
		})
		b.addEdgeIfMissing(&Edge{
			ID:     endpoint.ID + "->" + sourceID + ":targets",
			Source: endpoint.ID,
			Target: sourceID,
			Kind:   EdgeKindTargets,
			Effect: EdgeEffectAllow,
		})
	}

	for _, targetID := range endpoint.BackendTargets {
		targetID = strings.TrimSpace(targetID)
		if targetID == "" {
			continue
		}
		if _, ok := b.graph.GetNode(targetID); !ok {
			continue
		}
		b.addEdgeIfMissing(&Edge{
			ID:     endpoint.ID + "->" + targetID + ":targets",
			Source: endpoint.ID,
			Target: targetID,
			Kind:   EdgeKindTargets,
			Effect: EdgeEffectAllow,
		})
	}
}

func (b *Builder) clearProjectedAPIEndpointNodes() {
	for _, node := range b.graph.GetAllNodes() {
		if node == nil || node.Kind != NodeKindAPIEndpoint {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(propertyString(node.Properties, "exposure_source")), apiEndpointProjectionSourcePrefix) {
			continue
		}
		b.graph.RemoveNode(node.ID)
	}
}

type apiEndpointProjection struct {
	ID              string
	URL             string
	Scheme          string
	Host            string
	Path            string
	Method          string
	Public          bool
	AuthType        string
	APIKeyRequired  bool
	CORSPermissive  bool
	ExposureSource  string
	ProviderService string
	Provider        string
	Account         string
	Region          string
	BackendTargets  []string
}

func (p apiEndpointProjection) displayName() string {
	if p.Method == "" {
		return p.URL
	}
	return p.Method + " " + p.URL
}

func apiEndpointProjectionForNode(node *Node) (apiEndpointProjection, bool) {
	if node == nil || !node.IsResource() {
		return apiEndpointProjection{}, false
	}

	rawURL := strings.TrimSpace(toString(node.Properties["uri"]))
	if rawURL == "" {
		return apiEndpointProjection{}, false
	}

	normalizedURL, scheme, host, path, ok := normalizeAPIEndpointURL(rawURL)
	if !ok {
		return apiEndpointProjection{}, false
	}

	return apiEndpointProjection{
		ID:              apiEndpointNodeID(normalizedURL),
		URL:             normalizedURL,
		Scheme:          scheme,
		Host:            host,
		Path:            path,
		Public:          isNodePublic(node),
		AuthType:        normalizeEndpointAuthType(propertyString(node.Properties, "auth_type")),
		ExposureSource:  apiEndpointProjectionSourceSystem,
		ProviderService: "uri_projection",
		Provider:        node.Provider,
		Account:         node.Account,
		Region:          node.Region,
	}, true
}

func normalizeAPIEndpointURL(rawURL string) (normalized string, scheme string, host string, path string, ok bool) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed == nil {
		return "", "", "", "", false
	}
	if parsed.Host == "" || parsed.Scheme == "" {
		return "", "", "", "", false
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return "", "", "", "", false
	}

	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.RawQuery = ""
	parsed.Fragment = ""
	if parsed.Path == "/" {
		parsed.Path = ""
	} else {
		parsed.Path = strings.TrimRight(parsed.Path, "/")
	}
	parsed.RawPath = ""

	normalized = parsed.String()
	return normalized, parsed.Scheme, parsed.Host, parsed.Path, normalized != ""
}

func apiEndpointNodeID(endpointURL string) string {
	return "api_endpoint:" + endpointURL
}

func apiEndpointMethodNodeID(method, endpointURL string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return apiEndpointNodeID(endpointURL)
	}
	return "api_endpoint:" + method + ":" + endpointURL
}

func endpointRisk(public bool) RiskLevel {
	if public {
		return RiskMedium
	}
	return RiskNone
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
