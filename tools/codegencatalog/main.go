package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/writer/cerebro/internal/codegencatalog"
)

func main() {
	var catalogPath string
	var markdownPath string
	var jsonPath string
	var write bool
	var check bool
	flag.StringVar(&catalogPath, "catalog", "devex/codegen_catalog.json", "codegen registry path")
	flag.StringVar(&markdownPath, "markdown-out", "docs/engineering/devex-codegen.md", "generated Markdown path")
	flag.StringVar(&jsonPath, "json-out", "docs/engineering/devex-codegen-catalog.json", "generated JSON path")
	flag.BoolVar(&write, "write", false, "write generated artifacts")
	flag.BoolVar(&check, "check", false, "check generated artifacts")
	flag.Parse()
	if write == check {
		fail("exactly one of -write or -check is required")
	}
	catalog, err := codegencatalog.Load(catalogPath)
	if err != nil {
		fail(err.Error())
	}
	canonicalJSON, err := catalog.CanonicalJSON()
	if err != nil {
		fail(err.Error())
	}
	outputs := map[string][]byte{
		markdownPath: catalog.Markdown(),
		jsonPath:     canonicalJSON,
	}
	for path, expected := range outputs {
		if write {
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				fail(err.Error())
			}
			if err := os.WriteFile(path, expected, 0o600); err != nil {
				fail(err.Error())
			}
			continue
		}
		actual, err := os.ReadFile(path) // #nosec G304 -- repository path from operator flags.
		if err != nil {
			fail(fmt.Sprintf("read %s: %v", path, err))
		}
		if !bytes.Equal(actual, expected) {
			fail(fmt.Sprintf("%s is stale; run make codegen-catalog-generate", path))
		}
	}
	fmt.Fprintf(os.Stderr, "codegencatalog: %d families are valid and current\n", len(catalog.Families))
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, "codegencatalog:", message)
	os.Exit(1)
}
