// Command connectorapidisco builds a compact provider API discovery worklist
// from the connector catalog review artifact.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
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
	Candidates      int `json:"candidates"`
	APIsGuruMatches int `json:"apis_guru_matches"`
}

type WorklistItem struct {
	SourceID           string               `json:"source_id"`
	DisplayName        string               `json:"display_name,omitempty"`
	PackagePath        string               `json:"package_path,omitempty"`
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
	worklist := Worklist{Items: make([]WorklistItem, 0, len(candidates))}
	for _, candidate := range candidates {
		suggestions := apisGuruSuggestions(registry, candidate)
		if len(suggestions) > 0 {
			worklist.Summary.APIsGuruMatches++
		}
		worklist.Items = append(worklist.Items, WorklistItem{
			SourceID:           candidate.SourceID,
			DisplayName:        candidate.DisplayName,
			PackagePath:        candidate.PackagePath,
			MissingFamilies:    append([]string(nil), candidate.MissingFamilies...),
			ExistingReferences: append([]string(nil), candidate.ExistingReferences...),
			APIsGuru:           suggestions,
			SearchQueries:      append([]string(nil), candidate.SearchQueries...),
			NextAction:         candidate.NextAction,
		})
	}
	sort.SliceStable(worklist.Items, func(i int, j int) bool {
		if len(worklist.Items[i].APIsGuru) != len(worklist.Items[j].APIsGuru) {
			return len(worklist.Items[i].APIsGuru) > len(worklist.Items[j].APIsGuru)
		}
		return worklist.Items[i].SourceID < worklist.Items[j].SourceID
	})
	worklist.Summary.Candidates = len(worklist.Items)
	return worklist
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
