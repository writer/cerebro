package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

const (
	defaultCatalogPath    = "internal/graphactions/action_catalog.yaml"
	defaultOutputPath     = "internal/graphactions/registry_gen.go"
	maxGeneratedFileBytes = 4 << 20
)

var goIdentifierRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type actionCatalog struct {
	Version string               `yaml:"version"`
	Actions []actionCatalogEntry `yaml:"actions"`
}

type actionCatalogEntry struct {
	ID                  string `yaml:"id"`
	ConstName           string `yaml:"const_name"`
	Provider            string `yaml:"provider"`
	ProviderConst       string `yaml:"provider_const"`
	ProviderAction      string `yaml:"provider_action"`
	ProviderActionConst string `yaml:"provider_action_const"`
	TargetKind          string `yaml:"target_kind"`
	TargetKindConst     string `yaml:"target_kind_const"`
	TargetResolver      string `yaml:"target_resolver"`
	EligibilityChecker  string `yaml:"eligibility_checker"`
	Effect              string `yaml:"effect"`
	Destructive         bool   `yaml:"destructive"`
	ReversibleBy        string `yaml:"reversible_by"`
}

func main() {
	root := flag.String("root", ".", "repository root")
	catalog := flag.String("catalog", defaultCatalogPath, "graph action catalog path relative to root")
	output := flag.String("output", defaultOutputPath, "generated Go output path relative to root")
	write := flag.Bool("write", false, "write the generated graph action registry")
	check := flag.Bool("check", false, "check that the generated graph action registry is fresh")
	flag.Parse()

	if !*write && !*check {
		fmt.Fprintln(os.Stderr, "graphactiongen: one of --write or --check is required")
		os.Exit(2)
	}
	content, err := generate(filepath.Clean(*root), filepath.FromSlash(*catalog))
	if err != nil {
		fmt.Fprintf(os.Stderr, "graphactiongen: %v\n", err)
		os.Exit(1)
	}
	path := filepath.Join(filepath.Clean(*root), filepath.FromSlash(*output))
	if *write {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "graphactiongen: create output directory: %v\n", err)
			os.Exit(1)
		}
		if err := writeGeneratedFile(path, content); err != nil {
			fmt.Fprintf(os.Stderr, "graphactiongen: write %s: %v\n", *output, err)
			os.Exit(1)
		}
	}
	if *check {
		existing, err := readGeneratedFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "graphactiongen: read %s: %v\n", *output, err)
			os.Exit(1)
		}
		if !bytes.Equal(bytes.TrimSpace(existing), bytes.TrimSpace(content)) {
			fmt.Fprintf(os.Stderr, "graphactiongen: %s is stale; run `make graph-action-generate`\n", *output)
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
		return fmt.Errorf("symlinked generated graph action files are not allowed")
	}
	return nil
}

func writeGeneratedFile(path string, content []byte) error {
	if err := rejectSymlink(path); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tempPath)
		}
	}()
	if _, err := temp.Write(content); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Chmod(0o644); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	removeTemp = false
	return nil
}

func readGeneratedFile(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("symlinked generated graph action files are not allowed")
		}
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxGeneratedFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxGeneratedFileBytes {
		return nil, fmt.Errorf("generated graph action file exceeds %d bytes", maxGeneratedFileBytes)
	}
	return content, nil
}

func readBoundedFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxGeneratedFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxGeneratedFileBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxGeneratedFileBytes)
	}
	return content, nil
}

func generate(root string, catalogPath string) ([]byte, error) {
	path := filepath.Join(root, catalogPath)
	content, err := readBoundedFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalog %s: %w", catalogPath, err)
	}
	var catalog actionCatalog
	if err := yaml.Unmarshal(content, &catalog); err != nil {
		return nil, fmt.Errorf("decode catalog %s: %w", catalogPath, err)
	}
	if err := validateCatalog(catalog); err != nil {
		return nil, err
	}
	return renderCatalog(catalog)
}

func validateCatalog(catalog actionCatalog) error {
	if strings.TrimSpace(catalog.Version) != "graph-actions.cerebro/v1alpha1" {
		return fmt.Errorf("unsupported catalog version %q", catalog.Version)
	}
	if len(catalog.Actions) == 0 {
		return fmt.Errorf("catalog has no actions")
	}
	ids := map[string]struct{}{}
	constNames := map[string]struct{}{}
	providerConstValues := map[string]string{}
	providerActionConstValues := map[string]string{}
	targetKindConstValues := map[string]string{}
	for i, action := range catalog.Actions {
		if err := validateAction(i, action); err != nil {
			return err
		}
		if _, exists := ids[action.ID]; exists {
			return fmt.Errorf("duplicate action id %q", action.ID)
		}
		ids[action.ID] = struct{}{}
		if _, exists := constNames[action.ConstName]; exists {
			return fmt.Errorf("duplicate action const_name %q", action.ConstName)
		}
		constNames[action.ConstName] = struct{}{}
		if prior, exists := providerConstValues[action.ProviderConst]; exists && prior != action.Provider {
			return fmt.Errorf("action %q: provider_const %q maps to both %q and %q", action.ID, action.ProviderConst, prior, action.Provider)
		}
		providerConstValues[action.ProviderConst] = action.Provider
		if prior, exists := providerActionConstValues[action.ProviderActionConst]; exists && prior != action.ProviderAction {
			return fmt.Errorf("action %q: provider_action_const %q maps to both %q and %q", action.ID, action.ProviderActionConst, prior, action.ProviderAction)
		}
		providerActionConstValues[action.ProviderActionConst] = action.ProviderAction
		if prior, exists := targetKindConstValues[action.TargetKindConst]; exists && prior != action.TargetKind {
			return fmt.Errorf("action %q: target_kind_const %q maps to both %q and %q", action.ID, action.TargetKindConst, prior, action.TargetKind)
		}
		targetKindConstValues[action.TargetKindConst] = action.TargetKind
	}
	for _, action := range catalog.Actions {
		if action.ReversibleBy != "" {
			if _, exists := ids[action.ReversibleBy]; !exists {
				return fmt.Errorf("action %q reversible_by references unknown action %q", action.ID, action.ReversibleBy)
			}
		}
	}
	return nil
}

func validateAction(index int, action actionCatalogEntry) error {
	requiredStrings := map[string]string{
		"id":                    action.ID,
		"const_name":            action.ConstName,
		"provider":              action.Provider,
		"provider_const":        action.ProviderConst,
		"provider_action":       action.ProviderAction,
		"provider_action_const": action.ProviderActionConst,
		"target_kind":           action.TargetKind,
		"target_kind_const":     action.TargetKindConst,
		"target_resolver":       action.TargetResolver,
		"eligibility_checker":   action.EligibilityChecker,
		"effect":                action.Effect,
	}
	for field, value := range requiredStrings {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("actions[%d].%s is required", index, field)
		}
	}
	for field, value := range map[string]string{
		"const_name":            action.ConstName,
		"provider_const":        action.ProviderConst,
		"provider_action_const": action.ProviderActionConst,
		"target_kind_const":     action.TargetKindConst,
		"target_resolver":       action.TargetResolver,
		"eligibility_checker":   action.EligibilityChecker,
	} {
		if !goIdentifierRE.MatchString(value) {
			return fmt.Errorf("actions[%d].%s = %q is not a Go identifier", index, field, value)
		}
	}
	return nil
}

func renderCatalog(catalog actionCatalog) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("// Code generated by go run ./tools/graphactiongen --write; DO NOT EDIT.\n")
	buf.WriteString("\npackage graphactions\n\n")
	writeStringConstants(&buf, "Action IDs", actionConstants(catalog.Actions))
	writeStringConstants(&buf, "Target kinds", targetKindConstants(catalog.Actions))
	writeStringSlice(&buf, "generatedActionIDs", actionConstants(catalog.Actions))
	writeStringSlice(&buf, "generatedProviderIDs", providerConstants(catalog.Actions))
	writeStringSlice(&buf, "generatedTargetKinds", targetKindConstants(catalog.Actions))
	buf.WriteString("func DefaultRegistry() Registry {\n")
	buf.WriteString("\tactions := make(map[string]ActionSpec, len(generatedActionSpecs))\n")
	buf.WriteString("\tfor _, spec := range generatedActionSpecs {\n")
	buf.WriteString("\t\tactions[spec.ID] = spec\n")
	buf.WriteString("\t}\n")
	buf.WriteString("\treturn Registry{actions: actions}\n")
	buf.WriteString("}\n\n")
	buf.WriteString("func KnownActionSpecs() []ActionSpec {\n")
	buf.WriteString("\tout := make([]ActionSpec, len(generatedActionSpecs))\n")
	buf.WriteString("\tcopy(out, generatedActionSpecs)\n")
	buf.WriteString("\treturn out\n")
	buf.WriteString("}\n\n")
	buf.WriteString("func KnownActionMetadata() []ActionMetadata {\n")
	buf.WriteString("\tout := make([]ActionMetadata, 0, len(generatedActionSpecs))\n")
	buf.WriteString("\tfor _, spec := range generatedActionSpecs {\n")
	buf.WriteString("\t\tout = append(out, spec.Metadata())\n")
	buf.WriteString("\t}\n")
	buf.WriteString("\treturn out\n")
	buf.WriteString("}\n\n")
	buf.WriteString("func KnownActionIDs() []string {\n")
	buf.WriteString("\tout := make([]string, len(generatedActionIDs))\n")
	buf.WriteString("\tcopy(out, generatedActionIDs)\n")
	buf.WriteString("\treturn out\n")
	buf.WriteString("}\n\n")
	buf.WriteString("func KnownProviderIDs() []string {\n")
	buf.WriteString("\tout := make([]string, len(generatedProviderIDs))\n")
	buf.WriteString("\tcopy(out, generatedProviderIDs)\n")
	buf.WriteString("\treturn out\n")
	buf.WriteString("}\n\n")
	buf.WriteString("func KnownTargetKinds() []string {\n")
	buf.WriteString("\tout := make([]string, len(generatedTargetKinds))\n")
	buf.WriteString("\tcopy(out, generatedTargetKinds)\n")
	buf.WriteString("\treturn out\n")
	buf.WriteString("}\n\n")
	buf.WriteString("var generatedActionSpecs = []ActionSpec{\n")
	for _, action := range catalog.Actions {
		buf.WriteString("\t{\n")
		fmt.Fprintf(&buf, "\t\tID: %s,\n", action.ConstName)
		fmt.Fprintf(&buf, "\t\tProvider: %s,\n", action.ProviderConst)
		fmt.Fprintf(&buf, "\t\tProviderAction: %s,\n", action.ProviderActionConst)
		fmt.Fprintf(&buf, "\t\tTargetKind: %s,\n", action.TargetKindConst)
		fmt.Fprintf(&buf, "\t\tEffect: %q,\n", action.Effect)
		fmt.Fprintf(&buf, "\t\tDestructive: %t,\n", action.Destructive)
		fmt.Fprintf(&buf, "\t\tReversibleBy: %q,\n", action.ReversibleBy)
		fmt.Fprintf(&buf, "\t\tResolveTarget: %s,\n", action.TargetResolver)
		fmt.Fprintf(&buf, "\t\tCheckEligibility: %s,\n", action.EligibilityChecker)
		buf.WriteString("\t},\n")
	}
	buf.WriteString("}\n")
	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("format generated Go: %w\n%s", err, buf.String())
	}
	return formatted, nil
}

type stringConstant struct {
	Name  string
	Value string
}

func actionConstants(actions []actionCatalogEntry) []stringConstant {
	out := make([]stringConstant, 0, len(actions))
	for _, action := range actions {
		out = append(out, stringConstant{Name: action.ConstName, Value: action.ID})
	}
	return out
}

func providerConstants(actions []actionCatalogEntry) []stringConstant {
	seen := map[string]string{}
	for _, action := range actions {
		seen[action.ProviderConst] = action.Provider
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]stringConstant, 0, len(names))
	for _, name := range names {
		out = append(out, stringConstant{Name: name, Value: seen[name]})
	}
	return out
}

func targetKindConstants(actions []actionCatalogEntry) []stringConstant {
	seen := map[string]string{}
	for _, action := range actions {
		seen[action.TargetKindConst] = action.TargetKind
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]stringConstant, 0, len(names))
	for _, name := range names {
		out = append(out, stringConstant{Name: name, Value: seen[name]})
	}
	return out
}

func writeStringConstants(buf *bytes.Buffer, title string, constants []stringConstant) {
	if len(constants) == 0 {
		return
	}
	fmt.Fprintf(buf, "// %s.\n", title)
	buf.WriteString("const (\n")
	for _, constant := range constants {
		fmt.Fprintf(buf, "\t%s = %q\n", constant.Name, constant.Value)
	}
	buf.WriteString(")\n\n")
}

func writeStringSlice(buf *bytes.Buffer, name string, constants []stringConstant) {
	if len(constants) == 0 {
		return
	}
	fmt.Fprintf(buf, "var %s = []string{\n", name)
	for _, constant := range constants {
		fmt.Fprintf(buf, "\t%s,\n", constant.Name)
	}
	buf.WriteString("}\n\n")
}
