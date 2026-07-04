// Command connectorapidisco builds a compact provider API discovery worklist
// from the connector catalog review artifact.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/connectorcatalog"
)

func main() {
	var reviewPath string
	var apisGuruPath string
	var outPath string
	flag.StringVar(&reviewPath, "review-json", "tmp/connector-catalog-review.json", "connector catalog review JSON path")
	flag.StringVar(&apisGuruPath, "apisguru-list", "tmp/apisguru-list.json", "optional cached APIs.guru list.json path")
	flag.StringVar(&outPath, "out", "tmp/connector-api-discovery.json", "provider API discovery worklist JSON path")
	flag.Parse()

	report, err := readReview(reviewPath)
	if err != nil {
		fail(err)
	}
	registry, err := readAPIsGuru(apisGuruPath)
	if err != nil && !os.IsNotExist(err) {
		fail(err)
	}
	worklist := buildWorklist(report.APIDiscoveryQueue, registry)
	if err := writeJSON(outPath, worklist); err != nil {
		fail(err)
	}
	fmt.Printf("connector-api-discovery: candidates=%d apisguru_matches=%d out=%s\n", worklist.Summary.Candidates, worklist.Summary.APIsGuruMatches, outPath)
}

type Worklist struct {
	Summary WorklistSummary `json:"summary"`
	Items   []WorklistItem  `json:"items"`
}

type WorklistSummary struct {
	Candidates      int            `json:"candidates"`
	APIsGuruMatches int            `json:"apis_guru_matches"`
	ByPriorityTier  map[string]int `json:"by_priority_tier,omitempty"`
}

type WorklistItem struct {
	SourceID           string               `json:"source_id"`
	DisplayName        string               `json:"display_name,omitempty"`
	CatalogPath        string               `json:"catalog_path,omitempty"`
	PackagePath        string               `json:"package_path,omitempty"`
	Priority           int                  `json:"priority"`
	PriorityTier       string               `json:"priority_tier"`
	PriorityReasons    []string             `json:"priority_reasons,omitempty"`
	MissingFamilies    []string             `json:"missing_families,omitempty"`
	ExistingReferences []string             `json:"existing_references,omitempty"`
	APIsGuru           []APIsGuruSuggestion `json:"apis_guru,omitempty"`
	SearchQueries      []string             `json:"search_queries,omitempty"`
	NextAction         string               `json:"next_action"`
}

type APIsGuruSuggestion struct {
	Key        string   `json:"key"`
	Title      string   `json:"title,omitempty"`
	SpecURL    string   `json:"spec_url,omitempty"`
	YamlURL    string   `json:"yaml_url,omitempty"`
	OriginURLs []string `json:"origin_urls,omitempty"`
	Confidence string   `json:"confidence"`
}

type apisGuruRegistry map[string]struct {
	Preferred string `json:"preferred"`
	Versions  map[string]struct {
		Info struct {
			Title         string `json:"title"`
			XProviderName string `json:"x-providerName"`
			XOrigin       []struct {
				URL string `json:"url"`
			} `json:"x-origin"`
		} `json:"info"`
		SwaggerURL     string `json:"swaggerUrl"`
		SwaggerYamlURL string `json:"swaggerYamlUrl"`
	} `json:"versions"`
}

func readReview(path string) (connectorcatalog.ReviewReport, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- operator-provided artifact path for a build-time tool.
	if err != nil {
		return connectorcatalog.ReviewReport{}, fmt.Errorf("read review JSON: %w", err)
	}
	var report connectorcatalog.ReviewReport
	if err := json.Unmarshal(payload, &report); err != nil {
		return connectorcatalog.ReviewReport{}, fmt.Errorf("parse review JSON: %w", err)
	}
	return report, nil
}

func readAPIsGuru(path string) (apisGuruRegistry, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- optional local cache for a build-time tool.
	if err != nil {
		return nil, err
	}
	var registry apisGuruRegistry
	if err := json.Unmarshal(payload, &registry); err != nil {
		return nil, fmt.Errorf("parse APIs.guru list: %w", err)
	}
	return registry, nil
}

func buildWorklist(candidates []connectorcatalog.APIDiscoveryCandidate, registry apisGuruRegistry) Worklist {
	worklist := Worklist{
		Summary: WorklistSummary{ByPriorityTier: map[string]int{}},
		Items:   make([]WorklistItem, 0, len(candidates)),
	}
	for _, candidate := range candidates {
		suggestions := apisGuruSuggestions(registry, candidate)
		if len(suggestions) > 0 {
			worklist.Summary.APIsGuruMatches++
		}
		priority := priorityFor(candidate, suggestions)
		worklist.Items = append(worklist.Items, WorklistItem{
			SourceID:           candidate.SourceID,
			DisplayName:        candidate.DisplayName,
			CatalogPath:        candidate.Path,
			PackagePath:        candidate.PackagePath,
			Priority:           priority.Score,
			PriorityTier:       priority.Tier,
			PriorityReasons:    priority.Reasons,
			MissingFamilies:    append([]string(nil), candidate.MissingFamilies...),
			ExistingReferences: append([]string(nil), candidate.ExistingReferences...),
			APIsGuru:           suggestions,
			SearchQueries:      discoveryQueries(candidate),
			NextAction:         candidate.NextAction,
		})
		worklist.Summary.ByPriorityTier[priority.Tier]++
	}
	sort.SliceStable(worklist.Items, func(i int, j int) bool {
		if worklist.Items[i].Priority != worklist.Items[j].Priority {
			return worklist.Items[i].Priority > worklist.Items[j].Priority
		}
		if len(worklist.Items[i].APIsGuru) != len(worklist.Items[j].APIsGuru) {
			return len(worklist.Items[i].APIsGuru) > len(worklist.Items[j].APIsGuru)
		}
		if len(worklist.Items[i].MissingFamilies) != len(worklist.Items[j].MissingFamilies) {
			return len(worklist.Items[i].MissingFamilies) > len(worklist.Items[j].MissingFamilies)
		}
		return worklist.Items[i].SourceID < worklist.Items[j].SourceID
	})
	worklist.Summary.Candidates = len(worklist.Items)
	if len(worklist.Summary.ByPriorityTier) == 0 {
		worklist.Summary.ByPriorityTier = nil
	}
	return worklist
}

type priority struct {
	Score   int
	Tier    string
	Reasons []string
}

func priorityFor(candidate connectorcatalog.APIDiscoveryCandidate, suggestions []APIsGuruSuggestion) priority {
	score := 0
	reasons := map[string]struct{}{}
	add := func(points int, reason string) {
		score += points
		if reason != "" {
			reasons[reason] = struct{}{}
		}
	}
	if len(suggestions) > 0 {
		add(35, "machine_readable_spec_match")
	}
	switch catalogCategory(candidate.Path) {
	case "identity-access-secrets":
		add(35, "identity_access_source")
	case "security-posture-vulnerability":
		add(32, "security_posture_source")
	case "cloud-infrastructure-devops":
		add(28, "cloud_infrastructure_source")
	case "observability-soar-threat-intel":
		add(24, "incident_and_alert_source")
	case "ai-governance":
		add(20, "ai_governance_source")
	case "collaboration-productivity":
		add(16, "collaboration_source")
	case "business-data-grc":
		add(12, "business_grc_source")
	}
	missingFamilies := normalizedOrderedList(candidate.MissingFamilies)
	if len(missingFamilies) >= 4 {
		add(min(len(missingFamilies)*2, 12), "multi_family_runtime")
	}
	familyReasons := map[string]int{}
	for _, family := range missingFamilies {
		points, reason := familyPriority(family)
		if reason == "" {
			continue
		}
		if points > familyReasons[reason] {
			familyReasons[reason] = points
		}
	}
	for reason, points := range familyReasons {
		add(points, reason)
	}
	auth := strings.TrimSpace(candidate.Auth)
	switch {
	case strings.HasPrefix(auth, "oauth_"):
		add(8, "oauth_scope_docs_needed")
	case auth == "aws_sigv4" || auth == "signature" || auth == "jwt" || auth == "two_step" || strings.HasPrefix(auth, "duo_hmac"):
		add(10, "nontrivial_auth_docs_needed")
	case auth != "":
		add(4, "auth_model_known")
	}
	if strings.TrimSpace(candidate.BaseURL) != "" {
		add(5, "base_url_hint")
	}
	if len(candidate.ExistingReferences) > 0 {
		add(8, "existing_reference_hint")
	}
	out := priority{
		Score:   score,
		Tier:    priorityTier(score),
		Reasons: sortedReasonKeys(reasons),
	}
	return out
}

func catalogCategory(path string) string {
	parts := strings.Split(filepathSlash(path), "/")
	for i, part := range parts {
		if part == "catalog" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func filepathSlash(path string) string {
	return strings.ReplaceAll(path, "\\", "/")
}

func familyPriority(family string) (int, string) {
	family = normalizedFamily(family)
	switch {
	case family == "users" || family == "user" || strings.Contains(family, "identity"):
		return 12, "identity_family"
	case family == "groups" || family == "group" || strings.Contains(family, "membership"):
		return 10, "access_relationship_family"
	case strings.Contains(family, "role") || strings.Contains(family, "permission") || strings.Contains(family, "entitlement"):
		return 12, "privilege_family"
	case strings.Contains(family, "audit") || strings.Contains(family, "log"):
		return 12, "audit_trail_family"
	case strings.Contains(family, "finding") || strings.Contains(family, "vulnerab") || strings.Contains(family, "threat") || strings.Contains(family, "incident") || strings.Contains(family, "alert"):
		return 12, "risk_signal_family"
	case strings.Contains(family, "secret") || strings.Contains(family, "token") || strings.Contains(family, "key") || strings.Contains(family, "credential") || strings.Contains(family, "service_account"):
		return 12, "secret_or_service_account_family"
	case strings.Contains(family, "asset") || strings.Contains(family, "device") || strings.Contains(family, "application") || strings.Contains(family, "repository") || strings.Contains(family, "project") || strings.Contains(family, "workspace"):
		return 8, "asset_inventory_family"
	case strings.Contains(family, "policy") || strings.Contains(family, "control") || strings.Contains(family, "configuration") || strings.Contains(family, "setting"):
		return 8, "control_configuration_family"
	default:
		return 0, ""
	}
}

func normalizedFamily(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizedOrderedList(values []string) []string {
	seen := map[string]struct{}{}
	ordered := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		ordered = append(ordered, value)
	}
	return ordered
}

func priorityTier(score int) string {
	switch {
	case score >= 70:
		return "urgent"
	case score >= 50:
		return "high"
	case score >= 25:
		return "standard"
	default:
		return "backlog"
	}
}

func sortedReasonKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func discoveryQueries(candidate connectorcatalog.APIDiscoveryCandidate) []string {
	values := append([]string(nil), candidate.SearchQueries...)
	display := strings.TrimSpace(candidate.DisplayName)
	if display == "" {
		display = strings.TrimSpace(candidate.SourceID)
	}
	if display != "" {
		values = append(values,
			"web search: "+display+" developer API reference",
			"web search: "+display+" OpenAPI spec",
		)
	}
	if auth := strings.TrimSpace(candidate.Auth); strings.HasPrefix(auth, "oauth_") && display != "" {
		values = append(values, "web search: "+display+" OAuth scopes API")
	}
	if host := hostFromURL(candidate.BaseURL); host != "" {
		values = append(values,
			"web search: "+host+" openapi",
			"web search: "+host+" swagger",
		)
	}
	return normalizedOrderedList(values)
}

func hostFromURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "{") || strings.Contains(raw, "}") {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	return parsed.Hostname()
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func apisGuruSuggestions(registry apisGuruRegistry, candidate connectorcatalog.APIDiscoveryCandidate) []APIsGuruSuggestion {
	if len(registry) == 0 {
		return nil
	}
	sourceID := normalizedToken(candidate.SourceID)
	display := normalizedToken(candidate.DisplayName)
	suggestions := []APIsGuruSuggestion{}
	for key, api := range registry {
		version := api.Versions[api.Preferred]
		keyRoot := normalizedToken(apiKeyRoot(key))
		title := normalizedToken(version.Info.Title)
		provider := normalizedToken(version.Info.XProviderName)
		confidence := ""
		switch {
		case sourceID != "" && (sourceID == keyRoot || sourceID == provider):
			confidence = "source_id"
		case display != "" && (display == title || display == keyRoot || display == provider):
			confidence = "display_name"
		default:
			continue
		}
		suggestions = append(suggestions, APIsGuruSuggestion{
			Key:        key,
			Title:      strings.TrimSpace(version.Info.Title),
			SpecURL:    strings.TrimSpace(version.SwaggerURL),
			YamlURL:    strings.TrimSpace(version.SwaggerYamlURL),
			OriginURLs: originURLs(version.Info.XOrigin),
			Confidence: confidence,
		})
	}
	sort.SliceStable(suggestions, func(i int, j int) bool {
		if suggestions[i].Confidence != suggestions[j].Confidence {
			return suggestions[i].Confidence > suggestions[j].Confidence
		}
		return suggestions[i].Key < suggestions[j].Key
	})
	if len(suggestions) > 5 {
		return suggestions[:5]
	}
	return suggestions
}

func originURLs(values []struct {
	URL string `json:"url"`
}) []string {
	out := []string{}
	for _, value := range values {
		if strings.TrimSpace(value.URL) != "" {
			out = append(out, strings.TrimSpace(value.URL))
		}
	}
	sort.Strings(out)
	return out
}

func apiKeyRoot(key string) string {
	key = strings.TrimSpace(key)
	if before, _, ok := strings.Cut(key, ":"); ok {
		key = before
	}
	if before, _, ok := strings.Cut(key, "."); ok {
		key = before
	}
	return key
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

func normalizedToken(value string) string {
	return nonAlnum.ReplaceAllString(strings.ToLower(strings.TrimSpace(value)), "")
}

func writeJSON(path string, value any) error {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal worklist: %w", err)
	}
	payload = append(payload, '\n')
	if err := os.MkdirAll(dirFor(path), 0o750); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func dirFor(path string) string {
	if idx := strings.LastIndexAny(path, `/\`); idx >= 0 {
		return path[:idx]
	}
	return "."
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "connector-api-discovery:", err)
	os.Exit(1)
}
