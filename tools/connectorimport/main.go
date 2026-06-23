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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/connectorimport"
)

const (
	apisGuruListURL  = "https://api.apis.guru/v2/list.json"
	maxSpecBytes     = 32 << 20
	defaultOutputDir = "tmp/connector-candidates"
)

func main() {
	var manifestPath, outDir, reportOut, appendCatalog, defsOut, apisGuruList string
	var limit, timeoutSeconds int
	flag.StringVar(&manifestPath, "manifest", "", "provider manifest YAML path (required)")
	flag.StringVar(&outDir, "out", defaultOutputDir, "staging output directory for candidate catalog files and report")
	flag.StringVar(&reportOut, "report-out", "", "funnel report JSON path; defaults to <out>/report.json")
	flag.StringVar(&appendCatalog, "append-catalog", "", "when set, append supported entries into <dir>/<domain>.yaml")
	flag.StringVar(&defsOut, "defs-out", "", "when set, write each supported entry's connector definition as <dir>/<source_id>.json for direct Source CDK promotion")
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

	f := newFetcher(time.Duration(timeoutSeconds) * time.Second)
	registry, err := loadAPIsGuru(f, apisGuruList)
	if err != nil {
		fail(err)
	}

	outcomes := make([]connectorimport.Outcome, 0, len(targets))
	for _, entry := range targets {
		outcomes = append(outcomes, runTarget(f, registry, entry))
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
	if strings.TrimSpace(defsOut) != "" {
		written, err := writeDefinitionJSON(defsOut, outcomes)
		if err != nil {
			fail(err)
		}
		fmt.Printf("wrote %d connector definitions into %s\n", written, defsOut)
	}
	printSummary(summary, outcomes)
}

func runTarget(f *fetcher, registry apisGuruRegistry, entry manifestTarget) connectorimport.Outcome {
	doc, err := resolveSpec(f, registry, entry)
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

func fail(err error) {
	fmt.Fprintln(os.Stderr, "connectorimport:", err)
	os.Exit(1)
}
