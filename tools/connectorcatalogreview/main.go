package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/writer/cerebro/internal/connectorcatalog"
)

func main() {
	root := flag.String("root", ".", "repository root")
	markdownOut := flag.String("markdown-out", "", "write a Markdown review report to this path")
	jsonOut := flag.String("json-out", "", "write a JSON review report to this path")
	maxItems := flag.Int("max-items", 40, "maximum rows/questions rendered in Markdown sections")
	includeRuntimeDepth := flag.Bool("runtime-depth", true, "scan source packages and projector tests for runtime-depth evidence")
	requireRuntimeDepth := flag.Bool("runtime-depth-required", false, "fail when runtime-depth evidence cannot be scanned")
	flag.Parse()

	catalogRoot := filepath.Join(*root, "internal", "connectorcatalog", "catalog")
	analysis, err := connectorcatalog.AnalyzeDir(catalogRoot, connectorcatalog.Options{DryRunSourcegen: true})
	if err != nil {
		fmt.Fprintf(os.Stderr, "connector-catalog-review: %v\n", err)
		os.Exit(1)
	}
	reportResult, err := buildReviewReport(analysis, *root, *includeRuntimeDepth, *requireRuntimeDepth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connector-catalog-review: %v\n", err)
		os.Exit(1)
	}
	if reportResult.RuntimeDepthWarning != nil {
		fmt.Fprintf(os.Stderr, "connector-catalog-review: runtime depth unavailable; using catalog-only report: %v\n", reportResult.RuntimeDepthWarning)
	}
	report := reportResult.Report
	if *jsonOut != "" {
		if err := writeJSON(*jsonOut, report); err != nil {
			fmt.Fprintf(os.Stderr, "connector-catalog-review: %v\n", err)
			os.Exit(1)
		}
	}
	markdown := connectorcatalog.RenderReviewMarkdown(report, *maxItems)
	if *markdownOut != "" {
		if err := writeFile(*markdownOut, []byte(markdown)); err != nil {
			fmt.Fprintf(os.Stderr, "connector-catalog-review: %v\n", err)
			os.Exit(1)
		}
	}
	referenceRuntimeSources := 0
	if report.Summary.RuntimeDepth != nil {
		referenceRuntimeSources = report.Summary.RuntimeDepth.ReferenceRuntimeSources
	}
	fmt.Printf("connector-catalog-review: sources=%d projected_families=%d reference_runtime_sources=%d cleanup_findings=%d questions=%d\n",
		report.Summary.Total,
		report.Summary.ProjectedFamilies,
		referenceRuntimeSources,
		report.Summary.CleanupFindings,
		report.Summary.Questions,
	)
	if *markdownOut == "" && *jsonOut == "" {
		fmt.Print(markdown)
	}
}

type reviewReportResult struct {
	Report              connectorcatalog.ReviewReport
	RuntimeDepthWarning error
}

func buildReviewReport(analysis connectorcatalog.Analysis, root string, includeRuntimeDepth bool, requireRuntimeDepth bool) (reviewReportResult, error) {
	if !includeRuntimeDepth {
		return reviewReportResult{Report: connectorcatalog.ReviewAnalysis(analysis)}, nil
	}
	runtimeInventory, err := connectorcatalog.DiscoverRuntimeDepth(root)
	if err != nil {
		report := connectorcatalog.ReviewAnalysis(analysis)
		if requireRuntimeDepth {
			return reviewReportResult{}, fmt.Errorf("discover runtime depth: %w", err)
		}
		return reviewReportResult{Report: report, RuntimeDepthWarning: err}, nil
	}
	return reviewReportResult{Report: connectorcatalog.ReviewAnalysisWithRuntimeDepth(analysis, runtimeInventory)}, nil
}

func writeJSON(path string, report connectorcatalog.ReviewReport) error {
	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report JSON: %w", err)
	}
	payload = append(payload, '\n')
	return writeFile(path, payload)
}

func writeFile(path string, payload []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("set %s permissions: %w", path, err)
	}
	return nil
}
