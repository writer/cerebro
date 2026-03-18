package builders

import (
	"net/url"
	"strings"
)

const apiEndpointProjectionSourceSystem = "uri_property"

func (b *Builder) buildAPIEndpointNodes() {
	if b == nil || b.graph == nil {
		return
	}

	b.clearProjectedAPIEndpointNodes()

	for _, node := range b.graph.GetAllNodes() {
		endpoint, ok := apiEndpointProjectionForNode(node)
		if !ok {
			continue
		}

		if _, exists := b.graph.GetNode(endpoint.ID); !exists {
			b.graph.AddNode(&Node{
				ID:       endpoint.ID,
				Kind:     NodeKindAPIEndpoint,
				Name:     endpoint.URL,
				Provider: node.Provider,
				Account:  node.Account,
				Region:   node.Region,
				Risk:     endpointRisk(endpoint.Public),
				Properties: map[string]any{
					"url":             endpoint.URL,
					"scheme":          endpoint.Scheme,
					"host":            endpoint.Host,
					"path":            endpoint.Path,
					"public":          endpoint.Public,
					"exposure_source": endpoint.ExposureSource,
				},
			})
		}

		b.addEdgeIfMissing(&Edge{
			ID:     node.ID + "->" + endpoint.ID + ":serves",
			Source: node.ID,
			Target: endpoint.ID,
			Kind:   EdgeKindServes,
			Effect: EdgeEffectAllow,
		})
	}
}

func (b *Builder) clearProjectedAPIEndpointNodes() {
	for _, node := range b.graph.GetAllNodes() {
		if node == nil || node.Kind != NodeKindAPIEndpoint {
			continue
		}
		if !strings.EqualFold(propertyString(node.Properties, "exposure_source"), apiEndpointProjectionSourceSystem) {
			continue
		}
		b.graph.RemoveNode(node.ID)
	}
}

type apiEndpointProjection struct {
	ID             string
	URL            string
	Scheme         string
	Host           string
	Path           string
	Public         bool
	ExposureSource string
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
		ID:             apiEndpointNodeID(normalizedURL),
		URL:            normalizedURL,
		Scheme:         scheme,
		Host:           host,
		Path:           path,
		Public:         isNodePublic(node),
		ExposureSource: apiEndpointProjectionSourceSystem,
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

func endpointRisk(public bool) RiskLevel {
	if public {
		return RiskMedium
	}
	return RiskNone
}
