package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	findinganalysis "github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/sourceregistry"
)

const defaultOutputPath = "internal/findings/public_detection_catalog.json"

func main() {
	root := flag.String("root", ".", "repository root")
	output := flag.String("output", defaultOutputPath, "catalog output path relative to root")
	write := flag.Bool("write", false, "write the generated catalog")
	check := flag.Bool("check", false, "check that the generated catalog is fresh")
	flag.Parse()

	if !*write && !*check {
		fmt.Fprintln(os.Stderr, "detectioncatalog: one of --write or --check is required")
		os.Exit(2)
	}
	content, err := generateCatalog()
	if err != nil {
		fmt.Fprintf(os.Stderr, "detectioncatalog: %v\n", err)
		os.Exit(1)
	}
	path := filepath.Join(filepath.Clean(*root), filepath.FromSlash(*output))
	if *write {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "detectioncatalog: create output directory: %v\n", err)
			os.Exit(1)
		}
		if err := rejectSymlink(path); err != nil {
			fmt.Fprintf(os.Stderr, "detectioncatalog: write %s: %v\n", *output, err)
			os.Exit(1)
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "detectioncatalog: write %s: %v\n", *output, err)
			os.Exit(1)
		}
	}
	if *check {
		if err := rejectSymlink(path); err != nil {
			fmt.Fprintf(os.Stderr, "detectioncatalog: read %s: %v\n", *output, err)
			os.Exit(1)
		}
		existing, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "detectioncatalog: read %s: %v\n", *output, err)
			os.Exit(1)
		}
		if !bytes.Equal(bytes.TrimSpace(existing), bytes.TrimSpace(content)) {
			fmt.Fprintf(os.Stderr, "detectioncatalog: %s is stale; run `make detection-catalog-generate`\n", *output)
			os.Exit(1)
		}
	}
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlinked catalog files are not allowed")
	}
	return nil
}

func generateCatalog() ([]byte, error) {
	catalog := findinganalysis.BuiltinPublicDetectionCatalog()
	registry, err := sourceregistry.Builtin()
	if err != nil {
		return nil, fmt.Errorf("load source registry: %w", err)
	}
	catalog = findinganalysis.EnrichPublicDetectionCatalogWithSourceCoverage(catalog, registry.CoverageContracts())
	if errs := findinganalysis.ValidateRuleMetadataCompleteness(findinganalysis.BuiltinRuleMetadata()); len(errs) != 0 {
		return nil, errs[0]
	}
	content, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal public detection catalog: %w", err)
	}
	content = append(content, '\n')
	return content, nil
}
