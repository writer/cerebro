// Command connectorimport industrializes connector-definition authoring.
//
// It reads a manifest of providers, resolves each provider's OpenAPI document
// (local file, URL, or APIs.guru registry key), runs the generic engine and
// classifier, writes catalog-ready definitions to a staging directory, and
// emits a measured funnel report (yield + blocking reasons). With
// -append-catalog it appends the supported entries into the built-in catalog so
// they go live with no per-connector Go code.
//
// Examples:
//
//	go run ./tools/connectorimport -manifest tools/connectorimport/targets.yaml
//	go run ./tools/connectorimport -manifest tools/connectorimport/targets.yaml \
//	  -append-catalog internal/connectorcatalog/catalog
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/writer/cerebro/internal/connectorimport"
	"gopkg.in/yaml.v3"
)

const (
	apisGuruListURL  = "https://api.apis.guru/v2/list.json"
	maxSpecBytes     = 32 << 20
	defaultOutputDir = "tmp/connector-candidates"
)

type manifest struct {
	Targets []manifestTarget `yaml:"targets"`
}

type manifestTarget struct {
	SourceID    string   `yaml:"source_id"`
	DisplayName string   `yaml:"display_name"`
	Description string   `yaml:"description"`
	Domain      string   `yaml:"domain"`
	Categories  []string `yaml:"categories"`
	BaseURL     string   `yaml:"base_url"`
	AuthModel   string   `yaml:"auth_model"`
	MaxFamilies int      `yaml:"max_families"`
	AllFamilies bool     `yaml:"all_families"`

	APIsGuru string `yaml:"apis_guru"`
	SpecURL  string `yaml:"spec_url"`
	SpecFile string `yaml:"spec_file"`
}

func (t manifestTarget) target() connectorimport.Target {
	return connectorimport.Target{
		SourceID:    t.SourceID,
		DisplayName: t.DisplayName,
		Description: t.Description,
		Domain:      t.Domain,
		Categories:  t.Categories,
		BaseURL:     t.BaseURL,
		AuthModel:   t.AuthModel,
		MaxFamilies: t.MaxFamilies,
		AllFamilies: t.AllFamilies,
	}
}

func main() {
	var manifestPath, outDir, reportOut, appendCatalog, apisGuruList string
	var limit, timeoutSeconds int
	flag.StringVar(&manifestPath, "manifest", "", "provider manifest YAML path (required)")
	flag.StringVar(&outDir, "out", defaultOutputDir, "staging output directory for candidate catalog files and report")
	flag.StringVar(&reportOut, "report-out", "", "funnel report JSON path; defaults to <out>/report.json")
	flag.StringVar(&appendCatalog, "append-catalog", "", "when set, append supported entries into <dir>/<domain>.yaml")
	flag.StringVar(&apisGuruList, "apisguru-list", "", "path to a cached APIs.guru list.json; fetched over network when empty")
	flag.IntVar(&limit, "limit", 0, "process at most N manifest targets (0 = all)")
	flag.IntVar(&timeoutSeconds, "timeout", 30, "per-request HTTP timeout in seconds")
	flag.Parse()

	if strings.TrimSpace(manifestPath) == "" {
		fail(fmt.Errorf("-manifest is required"))
	}
	man, err := readManifest(manifestPath)
	if err != nil {
		fail(err)
	}
	targets := man.Targets
	if limit > 0 && limit < len(targets) {
		targets = targets[:limit]
	}

	client := &http.Client{Timeout: time.Duration(timeoutSeconds) * time.Second}
	registry, err := loadAPIsGuru(client, apisGuruList)
	if err != nil {
		fail(err)
	}

	outcomes := make([]connectorimport.Outcome, 0, len(targets))
	for _, entry := range targets {
		outcomes = append(outcomes, runTarget(client, registry, entry))
	}

	if err := os.MkdirAll(outDir, 0o750); err != nil {
		fail(err)
	}
	if err := writeStagingCatalogs(outDir, outcomes); err != nil {
		fail(err)
	}
	summary := connectorimport.Summarize(outcomes)
	if strings.TrimSpace(reportOut) == "" {
		reportOut = filepath.Join(outDir, "report.json")
	}
	if err := writeReport(reportOut, summary, outcomes); err != nil {
		fail(err)
	}
	if strings.TrimSpace(appendCatalog) != "" {
		appended, err := appendToCatalog(appendCatalog, outcomes)
		if err != nil {
			fail(err)
		}
		fmt.Printf("appended %d supported entries into %s\n", appended, appendCatalog)
	}
	printSummary(summary, outcomes)
}

func runTarget(client *http.Client, registry apisGuruRegistry, entry manifestTarget) connectorimport.Outcome {
	doc, err := resolveSpec(client, registry, entry)
	if err != nil {
		return connectorimport.Outcome{
			SourceID: entry.SourceID,
			Domain:   entry.Domain,
			Verdict:  connectorimport.VerdictGenerationError,
			Error:    err.Error(),
		}
	}
	return connectorimport.GenerateTarget(doc, entry.target())
}

func resolveSpec(client *http.Client, registry apisGuruRegistry, entry manifestTarget) (*openapi3.T, error) {
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = false
	switch {
	case strings.TrimSpace(entry.SpecFile) != "":
		payload, err := os.ReadFile(entry.SpecFile) //nolint:gosec // operator-provided spec path for a build-time tool.
		if err != nil {
			return nil, fmt.Errorf("read spec file: %w", err)
		}
		return parseSpec(loader, payload)
	case strings.TrimSpace(entry.SpecURL) != "":
		return loadSpecFromURL(client, loader, entry.SpecURL)
	case strings.TrimSpace(entry.APIsGuru) != "":
		specURL, err := registry.specURL(entry.APIsGuru)
		if err != nil {
			return nil, err
		}
		return loadSpecFromURL(client, loader, specURL)
	default:
		return nil, fmt.Errorf("target %q has no spec_file, spec_url, or apis_guru source", entry.SourceID)
	}
}

func loadSpecFromURL(client *http.Client, loader *openapi3.Loader, specURL string) (*openapi3.T, error) {
	payload, err := fetch(client, specURL)
	if err != nil {
		return nil, err
	}
	return parseSpec(loader, payload)
}

// parseSpec loads an OpenAPI 3 document, transparently converting Swagger 2.0
// specs (a large share of the APIs.guru corpus) to OpenAPI 3 first. This
// recovers the dominant "spec_parse" intake failure.
func parseSpec(loader *openapi3.Loader, payload []byte) (*openapi3.T, error) {
	if isSwaggerV2(payload) {
		return convertSwaggerV2(loader, payload)
	}
	doc, err := loader.LoadFromData(payload)
	if err != nil {
		return nil, fmt.Errorf("parse spec: %w", err)
	}
	return doc, nil
}

func isSwaggerV2(payload []byte) bool {
	var probe struct {
		Swagger string `yaml:"swagger" json:"swagger"`
	}
	if err := yaml.Unmarshal(payload, &probe); err != nil {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(probe.Swagger), "2")
}

func convertSwaggerV2(loader *openapi3.Loader, payload []byte) (*openapi3.T, error) {
	jsonBytes, err := yamlToJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("normalize swagger 2.0 spec: %w", err)
	}
	var doc2 openapi2.T
	if err := json.Unmarshal(jsonBytes, &doc2); err != nil {
		return nil, fmt.Errorf("parse swagger 2.0 spec: %w", err)
	}
	doc3, err := openapi2conv.ToV3(&doc2)
	if err != nil {
		return nil, fmt.Errorf("convert swagger 2.0 to openapi 3: %w", err)
	}
	_ = loader.ResolveRefsIn(doc3, nil)
	return doc3, nil
}

// yamlToJSON converts a YAML (or already-JSON) payload to JSON so it can be
// unmarshaled into kin-openapi's JSON-tagged openapi2 types.
func yamlToJSON(payload []byte) ([]byte, error) {
	var generic any
	if err := yaml.Unmarshal(payload, &generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}

func fetch(client *http.Client, rawURL string) ([]byte, error) {
	if !strings.HasPrefix(rawURL, "https://") {
		return nil, fmt.Errorf("refusing non-https spec url %q", rawURL)
	}
	response, err := client.Get(rawURL) //nolint:noctx // build-time codegen tool; per-request timeout set on client.
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", rawURL, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", rawURL, response.StatusCode)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxSpecBytes))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", rawURL, err)
	}
	return payload, nil
}

type apisGuruRegistry map[string]struct {
	Preferred string `json:"preferred"`
	Versions  map[string]struct {
		SwaggerURL     string `json:"swaggerUrl"`
		SwaggerYamlURL string `json:"swaggerYamlUrl"`
	} `json:"versions"`
}

func (r apisGuruRegistry) specURL(key string) (string, error) {
	api, ok := r[key]
	if !ok {
		return "", fmt.Errorf("apis_guru key %q not found in registry", key)
	}
	version, ok := api.Versions[api.Preferred]
	if !ok {
		for _, candidate := range api.Versions {
			version = candidate
			break
		}
	}
	if url := strings.TrimSpace(version.SwaggerYamlURL); url != "" {
		return url, nil
	}
	if url := strings.TrimSpace(version.SwaggerURL); url != "" {
		return url, nil
	}
	return "", fmt.Errorf("apis_guru key %q has no resolvable spec url", key)
}

func loadAPIsGuru(client *http.Client, cachePath string) (apisGuruRegistry, error) {
	var payload []byte
	var err error
	if strings.TrimSpace(cachePath) != "" {
		payload, err = os.ReadFile(cachePath) //nolint:gosec // operator-provided cache path for a build-time tool.
		if err != nil {
			return nil, fmt.Errorf("read apisguru cache: %w", err)
		}
	} else {
		payload, err = fetch(client, apisGuruListURL)
		if err != nil {
			// A missing registry is only fatal when a target needs it; defer.
			return apisGuruRegistry{}, nil
		}
	}
	registry := apisGuruRegistry{}
	if err := json.Unmarshal(payload, &registry); err != nil {
		return nil, fmt.Errorf("parse apisguru list: %w", err)
	}
	return registry, nil
}

func writeStagingCatalogs(outDir string, outcomes []connectorimport.Outcome) error {
	byDomain := map[string][]connectorimport.Outcome{}
	for _, outcome := range outcomes {
		if !outcome.CatalogReady() {
			continue
		}
		domain := strings.TrimSpace(outcome.Domain)
		if domain == "" {
			domain = "uncategorized"
		}
		byDomain[domain] = append(byDomain[domain], outcome)
	}
	for domain, entries := range byDomain {
		header := fmt.Sprintf("Candidate connector definitions for %s.\nGenerated by tools/connectorimport; review before promotion.", domain)
		body, err := connectorimport.RenderCatalogEntries(header, entries)
		if err != nil {
			return err
		}
		path := filepath.Join(outDir, domain+".yaml")
		if err := os.WriteFile(path, body, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return nil
}

func appendToCatalog(catalogDir string, outcomes []connectorimport.Outcome) (int, error) {
	blocks, err := connectorimport.RenderCatalogEntryBlocks(outcomes)
	if err != nil {
		return 0, err
	}
	byDomain := map[string][]connectorimport.Outcome{}
	for _, outcome := range outcomes {
		if outcome.CatalogReady() {
			byDomain[strings.TrimSpace(outcome.Domain)] = append(byDomain[strings.TrimSpace(outcome.Domain)], outcome)
		}
	}
	appended := 0
	for domain, entries := range byDomain {
		path := filepath.Join(catalogDir, domain+".yaml")
		existing, err := os.ReadFile(path) //nolint:gosec // operator-provided catalog dir for a build-time tool.
		if err != nil {
			return appended, fmt.Errorf("read catalog file %s (is -append-catalog domain valid?): %w", path, err)
		}
		present := existingSourceIDs(string(existing))
		var additions strings.Builder
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].SourceID < entries[j].SourceID })
		for _, outcome := range entries {
			if _, ok := present[outcome.SourceID]; ok {
				continue
			}
			additions.WriteString(strings.TrimRight(blocks[outcome.SourceID], "\n"))
			additions.WriteString("\n")
			appended++
		}
		if additions.Len() == 0 {
			continue
		}
		merged := strings.TrimRight(string(existing), "\n") + "\n" + additions.String()
		if err := os.WriteFile(path, []byte(merged), 0o600); err != nil {
			return appended, fmt.Errorf("write catalog file %s: %w", path, err)
		}
	}
	return appended, nil
}

func existingSourceIDs(body string) map[string]struct{} {
	ids := map[string]struct{}{}
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "source_id:") {
			ids[strings.TrimSpace(strings.TrimPrefix(trimmed, "source_id:"))] = struct{}{}
		}
	}
	return ids
}

func writeReport(path string, summary connectorimport.Summary, outcomes []connectorimport.Outcome) error {
	report := struct {
		Summary  connectorimport.Summary   `json:"summary"`
		Outcomes []connectorimport.Outcome `json:"outcomes"`
	}{Summary: summary, Outcomes: outcomes}
	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(payload, '\n'), 0o600); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return os.WriteFile(strings.TrimSuffix(path, filepath.Ext(path))+".md", []byte(renderReportMarkdown(summary, outcomes)), 0o600)
}

func renderReportMarkdown(summary connectorimport.Summary, outcomes []connectorimport.Outcome) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Connector import funnel\n\n")
	fmt.Fprintf(&b, "- Targets: %d\n", summary.Targets)
	fmt.Fprintf(&b, "- Supported (catalog-ready, zero-code live): %d\n", summary.Supported)
	fmt.Fprintf(&b, "- Extension required: %d\n", summary.ExtensionNeeded)
	fmt.Fprintf(&b, "- Bespoke required: %d\n", summary.BespokeNeeded)
	fmt.Fprintf(&b, "- Runtime unsupported (classifier-ok, runtime-blocked): %d\n", summary.RuntimeUnsupported)
	fmt.Fprintf(&b, "- Proof-gate failed (runtime-ok, catalog-gate-blocked): %d\n", summary.ProofGateFailed)
	fmt.Fprintf(&b, "- Generation errors: %d\n", summary.GenerationError)
	fmt.Fprintf(&b, "- Yield: %.1f%%\n\n", summary.YieldPercent)
	if len(summary.BlockingReasons) > 0 {
		fmt.Fprintf(&b, "## Top blocking reasons (grammar/intake roadmap)\n\n")
		for _, kv := range sortedCounts(summary.BlockingReasons) {
			fmt.Fprintf(&b, "- `%s`: %d\n", kv.key, kv.count)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "## Per-target outcomes\n\n")
	fmt.Fprintf(&b, "| source_id | domain | verdict | families | note |\n")
	fmt.Fprintf(&b, "| --- | --- | --- | --- | --- |\n")
	for _, outcome := range outcomes {
		note := outcome.Error
		if note == "" && len(outcome.MissingFeatures) > 0 {
			note = strings.Join(outcome.MissingFeatures, ", ")
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %s |\n", outcome.SourceID, outcome.Domain, outcome.Verdict, outcome.FamilyCount, truncate(note, 80))
	}
	return b.String()
}

func printSummary(summary connectorimport.Summary, outcomes []connectorimport.Outcome) {
	fmt.Printf("connector-import: targets=%d supported=%d extension=%d bespoke=%d runtime_unsupported=%d proof_gate=%d error=%d yield=%.1f%%\n",
		summary.Targets, summary.Supported, summary.ExtensionNeeded, summary.BespokeNeeded, summary.RuntimeUnsupported, summary.ProofGateFailed, summary.GenerationError, summary.YieldPercent)
	for _, kv := range sortedCounts(summary.BlockingReasons) {
		fmt.Printf("  blocked-by %s: %d\n", kv.key, kv.count)
	}
}

type countEntry struct {
	key   string
	count int
}

func sortedCounts(counts map[string]int) []countEntry {
	entries := make([]countEntry, 0, len(counts))
	for key, count := range counts {
		entries = append(entries, countEntry{key: key, count: count})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return entries[i].key < entries[j].key
	})
	return entries
}

func truncate(value string, max int) string {
	value = strings.ReplaceAll(value, "\n", " ")
	if len(value) <= max {
		return value
	}
	return value[:max-1] + "…"
}

func readManifest(path string) (manifest, error) {
	payload, err := os.ReadFile(path) //nolint:gosec // operator-provided manifest path for a build-time tool.
	if err != nil {
		return manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	var man manifest
	if err := yaml.Unmarshal(payload, &man); err != nil {
		return manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	if len(man.Targets) == 0 {
		return manifest{}, fmt.Errorf("manifest %s has no targets", path)
	}
	return man, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "connectorimport:", err)
	os.Exit(1)
}
