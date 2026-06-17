package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/writer/cerebro/internal/compliance"
	findinganalysis "github.com/writer/cerebro/internal/findings"
	"gopkg.in/yaml.v3"
)

type pathList []string

func main() {
	root := flag.String("root", ".", "repository root")
	profiles := flag.String("profiles", compliance.DefaultControlProfilesPath, "control profile YAML path relative to root")
	output := flag.String("output", compliance.DefaultControlCoverageIndexPath, "generated control coverage index YAML path relative to root")
	write := flag.Bool("write", false, "write the generated control coverage index")
	check := flag.Bool("check", false, "check that the generated control coverage index is fresh")
	var catalogs pathList
	flag.Var(&catalogs, "catalog", "control catalog YAML path relative to root; may be repeated")
	flag.Parse()

	if len(catalogs) == 0 {
		catalogs = append(catalogs, compliance.DefaultControlCatalogPath)
	}
	if !*write && !*check {
		fmt.Fprintln(os.Stderr, "controlindex: one of --write or --check is required")
		os.Exit(2)
	}

	content, err := generateCoverageIndex(filepath.Clean(*root), catalogs, *profiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "controlindex: %v\n", err)
		os.Exit(1)
	}
	path := filepath.Join(filepath.Clean(*root), filepath.FromSlash(*output))
	if *write {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "controlindex: create output directory: %v\n", err)
			os.Exit(1)
		}
		if err := rejectSymlink(path); err != nil {
			fmt.Fprintf(os.Stderr, "controlindex: write %s: %v\n", *output, err)
			os.Exit(1)
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "controlindex: write %s: %v\n", *output, err)
			os.Exit(1)
		}
	}
	if *check {
		if err := rejectSymlink(path); err != nil {
			fmt.Fprintf(os.Stderr, "controlindex: read %s: %v\n", *output, err)
			os.Exit(1)
		}
		existing, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "controlindex: read %s: %v\n", *output, err)
			os.Exit(1)
		}
		if !bytes.Equal(bytes.TrimSpace(existing), bytes.TrimSpace(content)) {
			fmt.Fprintf(os.Stderr, "controlindex: %s is stale; run `make control-index-generate`\n", *output)
			os.Exit(1)
		}
	}
}

func (p *pathList) String() string {
	return strings.Join(*p, ",")
}

func (p *pathList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("catalog path is required")
	}
	*p = append(*p, value)
	return nil
}

func generateCoverageIndex(root string, catalogPaths []string, profilePath string) ([]byte, error) {
	catalog, err := loadControlCatalog(root, catalogPaths)
	if err != nil {
		return nil, err
	}
	profiles, err := loadControlProfiles(root, profilePath)
	if err != nil {
		return nil, err
	}
	index, issues := compliance.BuildControlCoverageIndex(catalog, profiles, builtinRuleControlMappings())
	if len(issues) != 0 {
		return nil, validationIssuesError(profilePath, issues)
	}
	content, err := yaml.Marshal(index)
	if err != nil {
		return nil, fmt.Errorf("encode coverage index: %w", err)
	}
	return content, nil
}

func loadControlCatalog(root string, paths []string) (*compliance.CatalogIndex, error) {
	catalogPaths := make([]string, 0, len(paths))
	for _, path := range paths {
		catalogPaths = append(catalogPaths, filepath.Join(root, filepath.FromSlash(strings.TrimSpace(path))))
	}
	catalog, err := compliance.LoadControlCatalogFiles(catalogPaths...)
	if err != nil {
		return nil, err
	}
	index, issues := compliance.BuildCatalogIndex(catalog)
	if len(issues) != 0 {
		return nil, validationIssuesError(strings.Join(paths, ","), issues)
	}
	return index, nil
}

func loadControlProfiles(root string, path string) (compliance.ControlProfileSet, error) {
	return compliance.LoadControlProfileSetFile(filepath.Join(root, filepath.FromSlash(path)))
}

func builtinRuleControlMappings() []compliance.RuleControlMapping {
	mappings := []compliance.RuleControlMapping{}
	for _, metadata := range findinganalysis.BuiltinRuleMetadata() {
		ruleID := strings.TrimSpace(metadata.ID)
		if ruleID == "" {
			continue
		}
		refs := make([]compliance.ControlRef, 0, len(metadata.ControlRefs))
		for _, ref := range metadata.ControlRefs {
			refs = append(refs, compliance.ControlRef{
				FrameworkName: ref.FrameworkName,
				ControlID:     ref.ControlID,
			})
		}
		mappings = append(mappings, compliance.RuleControlMapping{
			RuleID:      ruleID,
			ControlRefs: refs,
		})
	}
	return mappings
}

func validationIssuesError(path string, issues []compliance.ValidationIssue) error {
	lines := make([]string, 0, len(issues))
	for _, issue := range issues {
		if strings.TrimSpace(issue.Path) == "" {
			lines = append(lines, strings.TrimSpace(path)+": "+issue.Message)
			continue
		}
		lines = append(lines, strings.TrimSpace(path)+": "+issue.Path+": "+issue.Message)
	}
	return errors.New(strings.Join(lines, "\n"))
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
		return fmt.Errorf("symlinked generated files are not allowed")
	}
	return nil
}
