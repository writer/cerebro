// Command rustcarve distills bounded Go behavior and parity evidence into a
// closed migration IR. It never transpiles arbitrary Go syntax.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	var requestPath string
	var outputDir string
	var root string
	var check bool
	flag.StringVar(&requestPath, "request", "", "closed rustcarve request JSON")
	flag.StringVar(&outputDir, "out", "", "generated artifact directory")
	flag.StringVar(&root, "root", ".", "repository root")
	flag.BoolVar(&check, "check", false, "verify generated artifacts are current")
	flag.Parse()
	if requestPath == "" || outputDir == "" {
		fail(fmt.Errorf("-request and -out are required"))
	}
	request, err := loadCarveRequest(requestPath)
	if err != nil {
		var inputErr typedInputError
		if errors.As(err, &inputErr) {
			report := unsupportedReport{SchemaVersion: unsupportedReportV1, ReasonCodes: []reasonCode{inputErr.Reason}, Details: []string{inputErr.Error()}}
			payload, marshalErr := marshalJSON(report)
			if marshalErr != nil {
				fail(marshalErr)
			}
			if writeErr := applyArtifacts(outputDir, map[string][]byte{"unsupported.json": payload}, check); writeErr != nil {
				fail(writeErr)
			}
			fmt.Fprintf(os.Stderr, "rustcarve: unsupported: %s\n", inputErr.Reason)
			os.Exit(2)
		}
		fail(err)
	}
	result, err := distill(root, request)
	if err != nil {
		fail(err)
	}
	if result.Unsupported != nil {
		payload, marshalErr := marshalJSON(result.Unsupported)
		if marshalErr != nil {
			fail(marshalErr)
		}
		if err := applyArtifacts(outputDir, map[string][]byte{"unsupported.json": payload}, check); err != nil {
			fail(err)
		}
		fmt.Fprintf(os.Stderr, "rustcarve: unsupported: %s\n", joinReasons(result.Unsupported.ReasonCodes))
		os.Exit(2)
	}
	if err := applyArtifacts(outputDir, result.Artifacts, check); err != nil {
		fail(err)
	}
}

func applyArtifacts(outputDir string, artifacts map[string][]byte, check bool) error {
	for _, relative := range sortedArtifactPaths(artifacts) {
		target := filepath.Join(outputDir, relative)
		if check {
			existing, err := os.ReadFile(target) // #nosec G304 -- explicit generated output path.
			if err != nil {
				return fmt.Errorf("read generated %s: %w", relative, err)
			}
			if err := checkGenerated(existing, artifacts[relative]); err != nil {
				return fmt.Errorf("%s: %w", relative, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
		if err := os.WriteFile(target, artifacts[relative], 0o600); err != nil {
			return fmt.Errorf("write %s: %w", relative, err)
		}
	}
	return nil
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "rustcarve: %v\n", err)
	os.Exit(1)
}
