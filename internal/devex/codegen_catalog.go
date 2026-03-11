package devex

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

const DefaultCodegenCatalogPath = "devex/codegen_catalog.json"

type CodegenCatalog struct {
	APIVersion string          `json:"api_version"`
	Kind       string          `json:"kind"`
	Families   []CodegenFamily `json:"families"`
}

type CodegenFamily struct {
	ID           string        `json:"id"`
	Title        string        `json:"title"`
	Summary      string        `json:"summary"`
	ChangeReason string        `json:"change_reason"`
	Triggers     []string      `json:"triggers"`
	Generator    *CodegenStep  `json:"generator,omitempty"`
	Checks       []CodegenStep `json:"checks,omitempty"`
	Outputs      []string      `json:"outputs,omitempty"`
	CIJobs       []string      `json:"ci_jobs,omitempty"`
}

type CodegenStep struct {
	Key                      string            `json:"key,omitempty"`
	Summary                  string            `json:"summary"`
	MakeTarget               string            `json:"make_target,omitempty"`
	Command                  []string          `json:"command"`
	Env                      map[string]string `json:"env,omitempty"`
	IncludeInPRGeneratedStep bool              `json:"include_in_pr_generated_step,omitempty"`
}

func LoadCodegenCatalog(path string) (CodegenCatalog, error) {
	payload, err := readRepoFile(path)
	if err != nil {
		return CodegenCatalog{}, err
	}
	var catalog CodegenCatalog
	if err := json.Unmarshal(payload, &catalog); err != nil {
		return CodegenCatalog{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if err := ValidateCodegenCatalog(catalog); err != nil {
		return CodegenCatalog{}, err
	}
	return catalog, nil
}

func LoadBuiltInCodegenCatalog() (CodegenCatalog, error) {
	return LoadCodegenCatalog(builtInCodegenCatalogPath())
}

func ValidateCodegenCatalog(catalog CodegenCatalog) error {
	var problems []string
	if strings.TrimSpace(catalog.APIVersion) == "" {
		problems = append(problems, "catalog api_version is required")
	}
	if strings.TrimSpace(catalog.Kind) == "" {
		problems = append(problems, "catalog kind is required")
	}
	if len(catalog.Families) == 0 {
		problems = append(problems, "catalog families must not be empty")
	}

	familyIDs := map[string]struct{}{}
	checkKeys := map[string]string{}
	for _, family := range catalog.Families {
		prefix := fmt.Sprintf("family %q", family.ID)
		if strings.TrimSpace(family.ID) == "" {
			problems = append(problems, "family id is required")
			continue
		}
		if _, exists := familyIDs[family.ID]; exists {
			problems = append(problems, fmt.Sprintf("duplicate family id %q", family.ID))
		}
		familyIDs[family.ID] = struct{}{}
		if strings.TrimSpace(family.Title) == "" {
			problems = append(problems, prefix+": title is required")
		}
		if strings.TrimSpace(family.Summary) == "" {
			problems = append(problems, prefix+": summary is required")
		}
		if strings.TrimSpace(family.ChangeReason) == "" {
			problems = append(problems, prefix+": change_reason is required")
		}
		if len(family.Triggers) == 0 {
			problems = append(problems, prefix+": triggers must not be empty")
		}
		for _, trigger := range family.Triggers {
			if strings.TrimSpace(trigger) == "" {
				problems = append(problems, prefix+": triggers must not contain empty values")
			}
		}
		if family.Generator != nil {
			problems = append(problems, validateStep(*family.Generator, prefix+": generator")...)
		}
		if len(family.Checks) == 0 {
			problems = append(problems, prefix+": checks must not be empty")
		}
		for _, check := range family.Checks {
			problems = append(problems, validateStep(check, prefix+": check")...)
			if strings.TrimSpace(check.Key) == "" {
				problems = append(problems, prefix+": check key is required")
				continue
			}
			if owner, exists := checkKeys[check.Key]; exists {
				problems = append(problems, fmt.Sprintf("duplicate check key %q in %s and %s", check.Key, owner, family.ID))
			}
			checkKeys[check.Key] = family.ID
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func ValidateCodegenCatalogReferences(catalog CodegenCatalog, makefilePath, workflowPath string) error {
	makefileContent, err := readRepoFile(makefilePath)
	if err != nil {
		return fmt.Errorf("read %s: %w", makefilePath, err)
	}
	workflowContent, err := readRepoFile(workflowPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", workflowPath, err)
	}
	makeTargets := parseMakeTargets(string(makefileContent))
	workflowJobs := parseWorkflowJobs(string(workflowContent))

	var problems []string
	for _, family := range catalog.Families {
		if family.Generator != nil && strings.TrimSpace(family.Generator.MakeTarget) != "" {
			if _, ok := makeTargets[family.Generator.MakeTarget]; !ok {
				problems = append(problems, fmt.Sprintf("family %q references missing make target %q", family.ID, family.Generator.MakeTarget))
			}
		}
		for _, check := range family.Checks {
			if strings.TrimSpace(check.MakeTarget) != "" {
				if _, ok := makeTargets[check.MakeTarget]; !ok {
					problems = append(problems, fmt.Sprintf("family %q check %q references missing make target %q", family.ID, check.Key, check.MakeTarget))
				}
			}
		}
		for _, job := range family.CIJobs {
			if _, ok := workflowJobs[job]; !ok {
				problems = append(problems, fmt.Sprintf("family %q references missing CI job %q", family.ID, job))
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func validateStep(step CodegenStep, prefix string) []string {
	var problems []string
	if strings.TrimSpace(step.Summary) == "" {
		problems = append(problems, prefix+": summary is required")
	}
	if step.IncludeInPRGeneratedStep && strings.TrimSpace(step.MakeTarget) == "" {
		problems = append(problems, prefix+": include_in_pr_generated_step requires make_target")
	}
	if len(step.Command) == 0 {
		problems = append(problems, prefix+": command must not be empty")
	}
	for _, part := range step.Command {
		if strings.TrimSpace(part) == "" {
			problems = append(problems, prefix+": command must not contain empty values")
			break
		}
	}
	return problems
}

func parseMakeTargets(content string) map[string]struct{} {
	targets := map[string]struct{}{}
	re := regexp.MustCompile(`(?m)^([A-Za-z0-9][A-Za-z0-9._-]*):`)
	for _, match := range re.FindAllStringSubmatch(content, -1) {
		targets[match[1]] = struct{}{}
	}
	return targets
}

func parseWorkflowJobs(content string) map[string]struct{} {
	jobs := map[string]struct{}{}
	re := regexp.MustCompile(`(?m)^  ([A-Za-z0-9][A-Za-z0-9._-]*):\s*$`)
	for _, match := range re.FindAllStringSubmatch(content, -1) {
		jobs[match[1]] = struct{}{}
	}
	return jobs
}

func builtInCodegenCatalogPath() string {
	return filepath.Join(repositoryRootPath(), DefaultCodegenCatalogPath)
}

func repositoryRootPath() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Join(filepath.Dir(filename), "..", "..")
}

func readRepoFile(path string) ([]byte, error) {
	rootPath := repositoryRootPath()
	relativePath, err := repositoryRelativePath(rootPath, path)
	if err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	file, err := root.Open(relativePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	return io.ReadAll(file)
}

func repositoryRelativePath(rootPath, candidate string) (string, error) {
	absolute := candidate
	if !filepath.IsAbs(absolute) {
		absolute = filepath.Join(rootPath, absolute)
	}
	absolute, err := filepath.Abs(absolute)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	rootPath, err = filepath.Abs(rootPath)
	if err != nil {
		return "", err
	}
	rootPath = filepath.Clean(rootPath)

	relative, err := filepath.Rel(rootPath, absolute)
	if err != nil {
		return "", err
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes repository root %q", absolute, rootPath)
	}
	return relative, nil
}
