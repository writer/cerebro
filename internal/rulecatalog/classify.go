package rulecatalog

import (
	"sort"
	"strings"
)

// Domain groups rules by the kind of system they protect.
const (
	DomainPaaS        = "paas"
	DomainSaaS        = "saas"
	DomainIdentity    = "identity"
	DomainCorrelation = "correlation"
)

// Posture names the security posture discipline a rule belongs to.
const (
	PostureCSPM        = "cspm"
	PostureSSPM        = "sspm"
	PostureISPM        = "ispm"
	PostureCorrelation = "correlation"
)

// Evaluation describes how a rule's matcher runs.
const (
	EvaluationCEL         = "cel"
	EvaluationSQL         = "sql"
	EvaluationGraph       = "graph"
	EvaluationEvent       = "event"
	EvaluationCorrelation = "correlation"
)

// Detection describes how a rule produces alerts: posture checks probe
// collected resource state, event rules react to the stream, and correlation
// rules join several signals or graph paths.
const (
	DetectionPosture     = "posture"
	DetectionEvent       = "event"
	DetectionCorrelation = "correlation"
)

const providerMultiCloud = "multi-cloud"

var cloudProviders = map[string]struct{}{
	"aws": {}, "azure": {}, "gcp": {}, "kubernetes": {}, "oci": {}, "cloudflare": {}, "terraform": {},
}

var identityProviders = map[string]struct{}{
	"okta": {}, "entra": {}, "auth0": {}, "duo": {}, "jumpcloud": {}, "onelogin": {}, "pingidentity": {},
	"sailpoint": {}, "saviynt": {}, "cyberark": {}, "forgerock": {},
}

var saasProviders = map[string]struct{}{
	"github": {}, "gitlab": {}, "m365": {}, "google": {}, "salesforce": {}, "slack": {}, "stripe": {},
	"zendesk": {}, "hubspot": {}, "atlassian": {}, "gong": {}, "servicenow": {}, "workday": {}, "zoom": {},
	"ramp": {}, "vanta": {}, "panther": {}, "splunk": {}, "jamf": {}, "kandji": {}, "kolide": {},
	"intune": {}, "sentinelone": {}, "pagerduty": {}, "backstage": {}, "openai": {}, "anthropic": {},
	"tailscale": {}, "oracle": {}, "hris": {},
}

var providerAliases = map[string]string{
	"k8s":       "kubernetes",
	"gke":       "gcp",
	"eks":       "aws",
	"aks":       "azure",
	"microsoft": "m365",
	"office365": "m365",
}

// paasCategories are policy domains whose generic resource types describe
// cloud infrastructure rather than a SaaS application.
var paasCategories = map[string]struct{}{
	"aws": {}, "azure": {}, "gcp": {}, "kubernetes": {}, "container": {}, "database": {}, "network": {},
	"backup": {}, "certificate": {}, "dspm": {}, "runtime": {}, "cloud_security": {}, "cross-provider": {},
	"api": {}, "ai": {}, "secrets": {}, "telemetry": {}, "vulnerability": {}, "cicd": {}, "cerebro": {},
}

var identityCategories = map[string]struct{}{"identity": {}, "okta": {}}

// Classification is the domain, posture, and provider assigned to one rule.
type Classification struct {
	Domain   string `json:"domain"`
	Posture  string `json:"posture"`
	Provider string `json:"provider"`
}

func postureForDomain(domain string) string {
	switch domain {
	case DomainPaaS:
		return PostureCSPM
	case DomainIdentity:
		return PostureISPM
	case DomainCorrelation:
		return PostureCorrelation
	default:
		return PostureSSPM
	}
}

func newClassification(domain string, provider string) Classification {
	return Classification{Domain: domain, Posture: postureForDomain(domain), Provider: provider}
}

// ClassifyPolicy assigns a classification from a declarative rule's category,
// resource type, tags, and graph source kinds.
func ClassifyPolicy(category string, resourceType string, tags []string, graphSourceKinds []string) Classification {
	category = strings.ToLower(strings.TrimSpace(category))
	if len(graphSourceKinds) != 0 {
		providers := providersFromSourceKinds(graphSourceKinds)
		if len(providers) > 1 {
			return newClassification(DomainCorrelation, strings.Join(providers, "+"))
		}
		if len(providers) == 1 {
			return classifyProvider(providers[0], category)
		}
	}
	provider := knownProvider(resourceProviderToken(resourceType))
	if provider == "" {
		provider = providerFromTags(tags)
	}
	if provider == "" {
		provider = knownProvider(category)
	}
	if _, ok := identityCategories[category]; ok {
		if provider == "" {
			provider = "identity"
		}
		return newClassification(DomainIdentity, provider)
	}
	if provider != "" {
		return classifyProvider(provider, category)
	}
	if _, ok := paasCategories[category]; ok {
		return newClassification(DomainPaaS, providerMultiCloud)
	}
	if category == "" {
		category = "custom"
	}
	return newClassification(DomainSaaS, category)
}

// correlateUnanchoredGraph moves graph-query rules that resolved to no known
// provider out of the SaaS fallback: a provider-less graph query spans whatever
// the graph holds, which is correlation rather than one SaaS application.
func correlateUnanchoredGraph(classification Classification) Classification {
	if classification.Domain == DomainSaaS && knownProvider(classification.Provider) == "" {
		return newClassification(DomainCorrelation, "cerebro")
	}
	return classification
}

// ClassifyDetection assigns a classification to a compiled Go detection.
func ClassifyDetection(sourceID string, packID string, evaluationMode string, tags []string) Classification {
	source := strings.ToLower(strings.TrimSpace(sourceID))
	pack := strings.ToLower(strings.TrimSpace(packID))
	switch {
	case source == "cloud" || pack == "cloud":
		if provider := cloudProviderFromTags(tags); provider != "" {
			return newClassification(DomainPaaS, provider)
		}
		return newClassification(DomainPaaS, providerMultiCloud)
	case pack == "grc" || source == "graph" || pack == "data" || isCerebroInternalSource(source):
		return newClassification(DomainCorrelation, "cerebro")
	case pack == "identity" && source == "identity":
		return newClassification(DomainCorrelation, "identity")
	case pack == "identity":
		if provider := knownProvider(source); provider != "" {
			return newClassification(DomainIdentity, provider)
		}
		return newClassification(DomainIdentity, source)
	case source == "trivy" || source == "vulnview" || source == "runtime":
		return newClassification(DomainPaaS, source)
	}
	if provider := knownProvider(source); provider != "" {
		return classifyProvider(provider, "")
	}
	if strings.EqualFold(evaluationMode, "graph") {
		return newClassification(DomainCorrelation, firstNonEmpty(source, "cerebro"))
	}
	return newClassification(DomainSaaS, firstNonEmpty(source, pack, "cerebro"))
}

// cerebroInternalSources emit signals derived from Cerebro's own analysis
// pipelines rather than from one external system.
var cerebroInternalSources = map[string]struct{}{
	"archetype": {}, "aurelius": {}, "cerebro": {}, "cosmo": {}, "evidence_cas": {}, "panopticon": {},
	"sdk": {}, "security_reviewer": {}, "security_tooling_map": {}, "trusted_endpoint": {},
}

func isCerebroInternalSource(source string) bool {
	_, ok := cerebroInternalSources[source]
	return ok
}

func classifyProvider(provider string, category string) Classification {
	if _, ok := identityCategories[category]; ok {
		return newClassification(DomainIdentity, provider)
	}
	if _, ok := identityProviders[provider]; ok {
		return newClassification(DomainIdentity, provider)
	}
	if _, ok := cloudProviders[provider]; ok {
		return newClassification(DomainPaaS, provider)
	}
	return newClassification(DomainSaaS, provider)
}

func resourceProviderToken(resourceType string) string {
	value := strings.ToLower(strings.TrimSpace(resourceType))
	if value == "" {
		return ""
	}
	if idx := strings.Index(value, "|"); idx >= 0 {
		value = value[:idx]
	}
	for _, separator := range []string{"::", ".", "_"} {
		if idx := strings.Index(value, separator); idx > 0 {
			return value[:idx]
		}
	}
	return value
}

func knownProvider(token string) string {
	token = strings.ToLower(strings.TrimSpace(token))
	if alias, ok := providerAliases[token]; ok {
		token = alias
	}
	if _, ok := cloudProviders[token]; ok {
		return token
	}
	if _, ok := identityProviders[token]; ok {
		return token
	}
	if _, ok := saasProviders[token]; ok {
		return token
	}
	return ""
}

func providerFromTags(tags []string) string {
	if provider := cloudProviderFromTags(tags); provider != "" {
		return provider
	}
	for _, tag := range tags {
		if provider := knownProvider(tag); provider != "" {
			return provider
		}
	}
	return ""
}

func cloudProviderFromTags(tags []string) string {
	for _, tag := range tags {
		provider := knownProvider(tag)
		if _, ok := cloudProviders[provider]; ok {
			return provider
		}
	}
	return ""
}

func providersFromSourceKinds(kinds []string) []string {
	seen := map[string]struct{}{}
	for _, kind := range kinds {
		token := resourceProviderToken(kind)
		provider := knownProvider(token)
		if provider == "" {
			provider = token
		}
		if provider != "" {
			seen[provider] = struct{}{}
		}
	}
	providers := make([]string, 0, len(seen))
	for provider := range seen {
		providers = append(providers, provider)
	}
	sort.Strings(providers)
	return providers
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
