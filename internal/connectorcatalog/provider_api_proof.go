package connectorcatalog

import (
	"net/url"
	"regexp"
	"strings"
)

const providerAPIProofThreshold = 100

var templateValuePattern = regexp.MustCompile(`(\$\{[^}]+\}|<[^>]+>|\{[^}]+\})`)
var runtimeURLLocatorPattern = regexp.MustCompile(`^\$\{(?:config|connection|credential)\.[A-Za-z0-9_]*(?:url|base_url|api_base_url)\}(?:/[^\\\s]*)?$`)

type providerAPIProof struct {
	Score    int
	Level    string
	Gaps     []string
	HasProof bool
}

func providerAPIProofScore(api runtimeProviderAPIFields, missingFamilies []string) providerAPIProof {
	score := 0
	var gaps []string
	if hasProviderAPIContract(api) {
		score += 20
	} else {
		gaps = append(gaps, "provider_api:contract")
	}

	if validProviderAPIBasis(api.Basis) {
		score += 10
	} else {
		gaps = append(gaps, "provider_api:basis")
	}
	if strings.TrimSpace(api.VerifiedAt) != "" {
		score += 5
	} else {
		gaps = append(gaps, "provider_api:verified_at")
	}

	if providerAPILocatorOK(api) {
		score += 10
	} else {
		gaps = append(gaps, "provider_api:locator")
	}

	badReferences := providerAPIReferenceGaps(api.References)
	if len(badReferences) == 0 && len(normalizedList(api.References)) > 0 {
		score += 15
	} else {
		gaps = append(gaps, badReferences...)
		if len(normalizedList(api.References)) == 0 {
			gaps = append(gaps, "provider_api:reference")
		}
	}

	if providerAPIMachineSpecOK(api) {
		score += 15
	} else {
		gaps = append(gaps, "provider_api:machine_readable_spec")
	}

	if providerAPIAuthMechanicsOK(api) {
		score += 10
	} else {
		gaps = append(gaps, "provider_api:auth_mechanics")
	}

	if len(missingFamilies) == 0 && len(providerAPIFamilies(api)) > 0 {
		score += 15
	} else {
		gaps = append(gaps, "provider_api:family_mapping")
		for _, family := range missingFamilies {
			if family = strings.TrimSpace(family); family != "" {
				gaps = append(gaps, "provider_api:family:"+family)
			}
		}
	}

	gaps = normalizedOrderedList(gaps)
	level := "needs_proof"
	if score >= providerAPIProofThreshold {
		level = "verified"
	}
	return providerAPIProof{Score: score, Level: level, Gaps: gaps, HasProof: score >= providerAPIProofThreshold}
}

func validProviderAPIBasis(value string) bool {
	switch strings.TrimSpace(value) {
	case "detected", "declared", "discovered":
		return true
	default:
		return false
	}
}

func providerAPILocatorOK(api runtimeProviderAPIFields) bool {
	locator := firstProviderAPIValue(api.BaseURL, api.Endpoint)
	if strings.TrimSpace(locator) == "" {
		return false
	}
	return providerAPIURLLooksGrounded(locator)
}

func providerAPIReferenceGaps(references []string) []string {
	var gaps []string
	for _, reference := range normalizedList(references) {
		if !providerAPIURLLooksGrounded(reference) {
			gaps = append(gaps, "provider_api:reference_url")
			continue
		}
		if providerAPIURLIsOAuthEndpoint(reference) {
			gaps = append(gaps, "provider_api:reference_oauth_endpoint")
		}
	}
	return normalizedOrderedList(gaps)
}

func providerAPIMachineSpecOK(api runtimeProviderAPIFields) bool {
	if providerAPISpecPointerOK(api.SpecURL, api.SpecKind, api.Transport) {
		return true
	}
	for _, reference := range normalizedList(api.References) {
		if providerAPISpecPointerOK(reference, "", api.Transport) {
			return true
		}
	}
	if strings.TrimSpace(api.Transport) == "graphql" {
		return providerAPIURLLooksGrounded(api.Endpoint) && strings.Contains(strings.ToLower(api.Endpoint), "graphql")
	}
	return false
}

func providerAPISpecPointerOK(specURL string, specKind string, transport string) bool {
	specURL = strings.TrimSpace(specURL)
	specKind = strings.TrimSpace(specKind)
	if strings.TrimSpace(transport) == "graphql" && specURL == "introspection" {
		return true
	}
	if specURL == "" || providerAPIURLIsOAuthEndpoint(specURL) || !providerAPIURLLooksGrounded(specURL) {
		return false
	}
	lowerURL := strings.ToLower(specURL)
	lowerKind := strings.ToLower(specKind)
	if strings.Contains(lowerURL, "postman") {
		return strings.Contains(lowerKind, "postman")
	}
	if strings.Contains(lowerURL, "asyncapi") {
		return false
	}
	if lowerKind == "google_discovery" {
		return strings.Contains(lowerURL, "googleapis.com/$discovery/rest") ||
			strings.Contains(lowerURL, "googleapis.com/discovery/v1/apis/")
	}
	if lowerKind == "openapi_embedded_html" {
		return providerAPIURLLooksGrounded(specURL)
	}
	if providerAPIMarkdownReferenceOK(lowerURL, lowerKind) {
		return true
	}
	hasMachineURL := strings.Contains(lowerURL, "openapi") ||
		strings.Contains(lowerURL, "swagger") ||
		strings.HasSuffix(providerAPIURLPath(lowerURL), ".json") ||
		strings.HasSuffix(providerAPIURLPath(lowerURL), ".yaml") ||
		strings.HasSuffix(providerAPIURLPath(lowerURL), ".yml") ||
		strings.HasSuffix(providerAPIURLPath(lowerURL), ".graphql")
	if hasMachineURL {
		return true
	}
	return strings.Contains(lowerKind, "graphql") && strings.Contains(lowerURL, "graphql")
}

func providerAPIMarkdownReferenceOK(lowerURL string, lowerKind string) bool {
	switch lowerKind {
	case "api_reference_markdown", "markdown_reference", "provider_reference_markdown":
	default:
		return false
	}
	path := providerAPIURLPath(lowerURL)
	if !strings.HasSuffix(path, ".md") {
		return false
	}
	return strings.Contains(lowerURL, "/docs/") ||
		strings.Contains(lowerURL, "/developer") ||
		strings.Contains(lowerURL, "/reference")
}

func providerAPIAuthMechanicsOK(api runtimeProviderAPIFields) bool {
	mechanics := strings.TrimSpace(api.AuthMechanics)
	if mechanics == "" || mechanics == "unknown" {
		return false
	}
	if strings.HasPrefix(strings.TrimSpace(api.Auth), "oauth_") && len(normalizedList(api.ScopeEvidence)) == 0 && len(normalizedList(api.AuthEvidence)) == 0 {
		return false
	}
	return true
}

func providerAPIURLLooksGrounded(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "//") {
		return false
	}
	if runtimeURLLocatorPattern.MatchString(strings.ToLower(raw)) {
		return true
	}
	parsed, ok := parseProviderAPIURL(raw)
	if !ok {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return false
	}
	if host == "localhost" || strings.HasPrefix(host, "127.") || strings.HasPrefix(host, "0.") {
		return false
	}
	if strings.Contains(host, "example.") || strings.HasSuffix(host, ".example") || strings.HasSuffix(host, ".test") || strings.HasSuffix(host, ".invalid") {
		return false
	}
	return true
}

func providerAPIURLIsOAuthEndpoint(raw string) bool {
	parsed, ok := parseProviderAPIURL(raw)
	if !ok {
		return false
	}
	segments := providerAPIPathSegments(parsed.EscapedPath())
	for i, segment := range segments {
		switch segment {
		case "oauth", "oauth2":
			return true
		case "authorize", "token":
			if len(segments) == 1 || providerAPIOAuthContext(previousProviderAPIPathSegment(segments, i)) {
				return true
			}
		}
	}
	return false
}

func providerAPIPathSegments(path string) []string {
	parts := strings.Split(strings.Trim(strings.ToLower(path), "/"), "/")
	segments := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			segments = append(segments, part)
		}
	}
	return segments
}

func previousProviderAPIPathSegment(segments []string, index int) string {
	if index <= 0 || index > len(segments)-1 {
		return ""
	}
	return segments[index-1]
}

func providerAPIOAuthContext(segment string) bool {
	switch segment {
	case "auth", "connect", "oauth", "oauth2", "oidc":
		return true
	default:
		return false
	}
}

func providerAPIURLPath(raw string) string {
	parsed, ok := parseProviderAPIURL(raw)
	if !ok {
		return strings.ToLower(strings.TrimSpace(raw))
	}
	return strings.ToLower(parsed.EscapedPath())
}

func parseProviderAPIURL(raw string) (*url.URL, bool) {
	templated := templateValuePattern.ReplaceAllString(strings.TrimSpace(raw), "tenant")
	parsed, err := url.Parse(templated)
	if err != nil || parsed == nil {
		return nil, false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, false
	}
	return parsed, parsed.Hostname() != ""
}

func firstProviderAPIValue(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
