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
	flag.Parse()

	catalogRoot := filepath.Join(*root, "internal", "connectorcatalog", "catalog")
	analysis, err := connectorcatalog.AnalyzeDir(catalogRoot, connectorcatalog.Options{DryRunSourcegen: true})
	if err != nil {
		fmt.Fprintf(os.Stderr, "connector-catalog-review: %v\n", err)
		os.Exit(1)
	}
	report := connectorcatalog.ReviewAnalysis(analysis)
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
	fmt.Printf("connector-catalog-review: sources=%d projected_families=%d cleanup_findings=%d questions=%d\n",
		report.Summary.Total,
		report.Summary.ProjectedFamilies,
		report.Summary.CleanupFindings,
		report.Summary.Questions,
	)
	if *markdownOut == "" && *jsonOut == "" {
		fmt.Print(markdown)
	}
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
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
