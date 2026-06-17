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
type profileList []string

const controlExtensionScaffoldVersion = "2026-06-17"

func main() {
	root := flag.String("root", ".", "repository root")
	profiles := flag.String("profiles", compliance.DefaultControlProfilesPath, "control profile YAML path relative to root")
	output := flag.String("output", compliance.DefaultControlCoverageIndexPath, "generated control coverage index YAML path relative to root")
	initExtension := flag.String("init-extension", "", "write a starter control extension pack to this directory relative to root")
	extensionID := flag.String("extension-id", "", "control extension id for --init-extension")
	extensionName := flag.String("extension-name", "", "control extension name for --init-extension")
	frameworkID := flag.String("framework-id", "", "custom framework id for --init-extension")
	frameworkName := flag.String("framework-name", "", "custom framework name for --init-extension")
	profileID := flag.String("profile-id", "", "starter control profile id for --init-extension")
	profileName := flag.String("profile-name", "", "starter control profile name for --init-extension")
	write := flag.Bool("write", false, "write the generated control coverage index")
	check := flag.Bool("check", false, "check that the generated control coverage index is fresh")
	var catalogs pathList
	var extensions pathList
	var selectedProfiles profileList
	flag.Var(&catalogs, "catalog", "control catalog YAML path relative to root; may be repeated")
	flag.Var(&extensions, "extension", "control extension manifest path relative to root; may be repeated")
	flag.Var(&selectedProfiles, "profile", "control profile id to include in the generated index; may be repeated")
	flag.Parse()

	if strings.TrimSpace(*initExtension) != "" {
		options := newControlExtensionScaffoldOptions(*initExtension, *extensionID, *extensionName, *frameworkID, *frameworkName, *profileID, *profileName)
		if err := validateControlExtensionScaffoldFlags(*write, *check, []string(selectedProfiles), options); err != nil {
			fmt.Fprintf(os.Stderr, "controlindex: %v\n", err)
			os.Exit(2)
		}
		if err := writeControlExtensionScaffold(filepath.Clean(*root), options); err != nil {
			fmt.Fprintf(os.Stderr, "controlindex: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if len(catalogs) == 0 {
		catalogs = append(catalogs, compliance.DefaultControlCatalogPath)
	}
	if err := validateControlIndexFlags(*write, *check, *output, []string(selectedProfiles)); err != nil {
		fmt.Fprintf(os.Stderr, "controlindex: %v\n", err)
		os.Exit(2)
	}

	content, err := generateCoverageIndex(filepath.Clean(*root), catalogs, *profiles, extensions, []string(selectedProfiles))
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

func (p *profileList) String() string {
	return strings.Join(*p, ",")
}

func (p *profileList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("profile id is required")
	}
	*p = append(*p, value)
	return nil
}

func validateControlIndexFlags(write bool, check bool, output string, selectedProfileIDs []string) error {
	if !write && !check {
		return fmt.Errorf("one of --write or --check is required")
	}
	if len(selectedProfileIDs) != 0 && isDefaultCoverageOutput(output) {
		return fmt.Errorf("--profile requires --output because %s stores the complete profile index", compliance.DefaultControlCoverageIndexPath)
	}
	return nil
}

func isDefaultCoverageOutput(path string) bool {
	return filepath.ToSlash(filepath.Clean(strings.TrimSpace(path))) == filepath.ToSlash(filepath.Clean(compliance.DefaultControlCoverageIndexPath))
}

type controlExtensionScaffoldOptions struct {
	Dir           string
	Version       string
	ExtensionID   string
	ExtensionName string
	FrameworkID   string
	FrameworkName string
	ProfileID     string
	ProfileName   string
}

func newControlExtensionScaffoldOptions(dir, extensionID, extensionName, frameworkID, frameworkName, profileID, profileName string) controlExtensionScaffoldOptions {
	dir = strings.TrimSpace(dir)
	baseID := scaffoldSlugValue(firstNonEmpty(extensionID, filepath.Base(filepath.Clean(filepath.FromSlash(dir)))))
	if baseID == "" {
		baseID = "custom-controls"
	}
	frameworkBaseID := strings.TrimSuffix(baseID, "-controls")
	if frameworkBaseID == "" {
		frameworkBaseID = baseID
	}
	options := controlExtensionScaffoldOptions{
		Dir:           dir,
		Version:       controlExtensionScaffoldVersion,
		ExtensionID:   baseID,
		ExtensionName: scaffoldTitle(baseID),
		FrameworkID:   frameworkBaseID,
		FrameworkName: scaffoldTitle(frameworkBaseID) + " Framework",
		ProfileID:     frameworkBaseID + "-audit",
		ProfileName:   scaffoldTitle(frameworkBaseID) + " Audit",
	}
	if value := scaffoldSlugValue(extensionID); value != "" {
		options.ExtensionID = value
	}
	if value := strings.TrimSpace(extensionName); value != "" {
		options.ExtensionName = value
	}
	if value := scaffoldSlugValue(frameworkID); value != "" {
		options.FrameworkID = value
	}
	if value := strings.TrimSpace(frameworkName); value != "" {
		options.FrameworkName = value
	}
	if value := scaffoldSlugValue(profileID); value != "" {
		options.ProfileID = value
	}
	if value := strings.TrimSpace(profileName); value != "" {
		options.ProfileName = value
	}
	return options
}

func validateControlExtensionScaffoldFlags(write bool, check bool, selectedProfileIDs []string, options controlExtensionScaffoldOptions) error {
	if write || check {
		return fmt.Errorf("--init-extension cannot be combined with --write or --check")
	}
	if len(selectedProfileIDs) != 0 {
		return fmt.Errorf("--init-extension cannot be combined with --profile")
	}
	if strings.TrimSpace(options.Dir) == "" {
		return fmt.Errorf("--init-extension directory is required")
	}
	for label, value := range map[string]string{
		"extension id":   options.ExtensionID,
		"extension name": options.ExtensionName,
		"framework id":   options.FrameworkID,
		"framework name": options.FrameworkName,
		"profile id":     options.ProfileID,
		"profile name":   options.ProfileName,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", label)
		}
	}
	return nil
}

func writeControlExtensionScaffold(root string, options controlExtensionScaffoldOptions) error {
	dir := resolveRootPath(root, options.Dir)
	if err := rejectSymlink(dir); err != nil {
		return fmt.Errorf("create extension directory: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create extension directory: %w", err)
	}
	files := map[string]any{
		"extension.yaml": controlExtensionScaffoldPack(options),
		"controls.yaml":  controlExtensionScaffoldCatalog(options),
		"profiles.yaml":  controlExtensionScaffoldProfiles(options),
	}
	names := []string{"extension.yaml", "controls.yaml", "profiles.yaml"}
	for _, name := range names {
		if err := rejectExistingScaffoldFile(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	for _, name := range names {
		if err := writeScaffoldYAMLFile(filepath.Join(dir, name), files[name]); err != nil {
			return err
		}
	}
	return nil
}

func controlExtensionScaffoldPack(options controlExtensionScaffoldOptions) compliance.ControlExtensionPack {
	return compliance.ControlExtensionPack{
		Version:     strings.TrimSpace(options.Version),
		ID:          strings.TrimSpace(options.ExtensionID),
		Name:        strings.TrimSpace(options.ExtensionName),
		Description: "Custom control framework and reusable audit selections.",
		Catalogs:    []string{"controls.yaml"},
		Profiles:    []string{"profiles.yaml"},
	}
}

func controlExtensionScaffoldCatalog(options controlExtensionScaffoldOptions) compliance.ControlCatalog {
	automatable := true
	manualEvidenceAllowed := true
	required := true
	return compliance.ControlCatalog{
		Version: strings.TrimSpace(options.Version),
		Frameworks: []compliance.Framework{{
			ID:          strings.TrimSpace(options.FrameworkID),
			Name:        strings.TrimSpace(options.FrameworkName),
			Version:     "2026",
			Description: "Custom auditor-facing controls for this compliance scope.",
			Tags:        []string{"custom_framework"},
			Families: []compliance.Family{{
				ID:          "IAM",
				Name:        "Identity and Access Management",
				Description: "Access controls that protect production systems and privileged actions.",
				Tags:        []string{"identity", "access"},
				Controls: []compliance.Control{{
					ID:                     "IAM-1",
					Title:                  "Privileged access requires MFA",
					Objective:              "Privileged users authenticate with phishing-resistant MFA before production access is granted.",
					Intent:                 "Reduce account takeover risk for administrative and production access paths.",
					Applicability:          []string{"production", "privileged_access"},
					AssessmentMethods:      []string{"examine", "test"},
					ImplementationGuidance: []string{"Require privileged identities to enroll MFA before production access is granted."},
					AuditProcedure:         []string{"Compare privileged account inventory with current MFA enrollment evidence."},
					FailureModes:           []string{"Privileged user has active production access without enrolled MFA."},
					RemediationGuidance:    []string{"Remove privileged access until MFA enrollment is complete."},
					ExceptionGuidance:      "Time-bound exceptions require compensating monitoring and approval.",
					EvidenceExpectations: []compliance.EvidenceExpectation{{
						ID:                "privileged-mfa-state",
						Title:             "Privileged MFA enrollment",
						Type:              "identity_configuration",
						Description:       "Current MFA posture for privileged users.",
						Required:          &required,
						AssessmentMethods: []string{"examine", "test"},
						FreshnessSLA:      "30d",
						AcceptedFrom:      []string{"identity_provider", "source_snapshot"},
					}},
					FreshnessSLA:          "30d",
					OwnerDomain:           "identity",
					Automatable:           &automatable,
					ManualEvidenceAllowed: &manualEvidenceAllowed,
					Tags:                  []string{"mfa", "privileged_access"},
					MapsTo: []compliance.ControlRef{{
						FrameworkName: "SOC 2",
						ControlID:     "CC6.1",
					}},
				}},
			}},
		}},
	}
}

func controlExtensionScaffoldProfiles(options controlExtensionScaffoldOptions) compliance.ControlProfileSet {
	return compliance.ControlProfileSet{
		Version: strings.TrimSpace(options.Version),
		Profiles: []compliance.ControlSelection{{
			ID:          strings.TrimSpace(options.ProfileID),
			Name:        strings.TrimSpace(options.ProfileName),
			Description: "Starter audit profile for the custom framework.",
			Frameworks: []compliance.FrameworkSelection{{
				ID:       strings.TrimSpace(options.FrameworkID),
				Controls: []string{"IAM-1"},
			}},
			IncludeApplicability: []string{"production"},
			IncludeAssessments:   []string{"examine", "test"},
		}},
	}
}

func writeScaffoldYAMLFile(path string, value any) error {
	if err := rejectSymlink(path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	content, err := yaml.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("write %s: file already exists", path)
		}
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer file.Close()
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func rejectExistingScaffoldFile(path string) error {
	if err := rejectSymlink(path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	_, err := os.Lstat(path)
	if err == nil {
		return fmt.Errorf("write %s: file already exists", path)
	}
	if os.IsNotExist(err) {
		return nil
	}
	return fmt.Errorf("write %s: %w", path, err)
}

func scaffoldSlugValue(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	lastHyphen := false
	for _, char := range value {
		isAlphaNumeric := (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9')
		if isAlphaNumeric {
			builder.WriteRune(char)
			lastHyphen = false
			continue
		}
		if builder.Len() == 0 || lastHyphen {
			continue
		}
		builder.WriteByte('-')
		lastHyphen = true
	}
	return strings.Trim(builder.String(), "-")
}

func scaffoldTitle(id string) string {
	parts := strings.Split(scaffoldSlugValue(id), "-")
	words := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		words = append(words, strings.ToUpper(part[:1])+part[1:])
	}
	if len(words) == 0 {
		return "Custom Controls"
	}
	return strings.Join(words, " ")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func generateCoverageIndex(root string, catalogPaths []string, profilePath string, extensionPaths []string, selectedProfileIDs []string) ([]byte, error) {
	absoluteRoot, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return nil, fmt.Errorf("resolve root: %w", err)
	}
	root = absoluteRoot
	extensionCatalogs, extensionProfiles, err := loadControlExtensions(root, extensionPaths)
	if err != nil {
		return nil, err
	}
	catalogPaths = append(catalogPaths, extensionCatalogs...)
	catalog, err := loadControlCatalog(root, catalogPaths)
	if err != nil {
		return nil, err
	}
	profiles, err := loadControlProfiles(root, profilePath)
	if err != nil {
		return nil, err
	}
	if len(extensionProfiles) != 0 {
		profileSets := []compliance.ControlProfileSet{profiles}
		for _, path := range extensionProfiles {
			extensionProfile, err := loadControlProfiles(root, path)
			if err != nil {
				return nil, err
			}
			profileSets = append(profileSets, extensionProfile)
		}
		profiles = compliance.MergeControlProfileSets(profileSets...)
	}
	selectedProfileSet, selectedProfiles, err := selectControlProfiles(profiles, selectedProfileIDs)
	if err != nil {
		return nil, err
	}
	profiles = selectedProfileSet
	index, issues := compliance.BuildControlCoverageIndex(catalog, profiles, builtinRuleControlMappings())
	if len(issues) != 0 {
		return nil, validationIssuesError(profilePath, issues)
	}
	if len(selectedProfiles) != 0 {
		index = filterCoverageIndexProfiles(index, selectedProfiles)
	}
	content, err := yaml.Marshal(index)
	if err != nil {
		return nil, fmt.Errorf("encode coverage index: %w", err)
	}
	return content, nil
}

func selectControlProfiles(set compliance.ControlProfileSet, profileIDs []string) (compliance.ControlProfileSet, map[string]struct{}, error) {
	selected := map[string]struct{}{}
	needed := map[string]struct{}{}
	if len(profileIDs) == 0 {
		return set, selected, nil
	}
	profilesByID := map[string]compliance.ControlSelection{}
	for _, profile := range set.Profiles {
		id := strings.TrimSpace(profile.ID)
		if id == "" {
			continue
		}
		if _, ok := profilesByID[id]; ok {
			continue
		}
		profilesByID[id] = profile
	}
	var collect func(id string)
	collect = func(id string) {
		if _, ok := needed[id]; ok {
			return
		}
		profile, ok := profilesByID[id]
		if !ok {
			return
		}
		needed[id] = struct{}{}
		for _, includeID := range profile.IncludeProfiles {
			collect(strings.TrimSpace(includeID))
		}
	}
	for _, profileID := range profileIDs {
		profileID = strings.TrimSpace(profileID)
		if profileID == "" {
			return compliance.ControlProfileSet{}, nil, fmt.Errorf("profile id is required")
		}
		if _, ok := profilesByID[profileID]; !ok {
			return compliance.ControlProfileSet{}, nil, fmt.Errorf("profile %q is not declared", profileID)
		}
		selected[profileID] = struct{}{}
		collect(profileID)
	}
	filtered := compliance.ControlProfileSet{Version: strings.TrimSpace(set.Version)}
	for _, profile := range set.Profiles {
		id := strings.TrimSpace(profile.ID)
		if _, ok := needed[id]; ok {
			filtered.Profiles = append(filtered.Profiles, profile)
		}
	}
	return filtered, selected, nil
}

func filterCoverageIndexProfiles(index compliance.ControlCoverageIndex, selected map[string]struct{}) compliance.ControlCoverageIndex {
	filtered := compliance.ControlCoverageIndex{Version: index.Version}
	for _, profile := range index.Profiles {
		if _, ok := selected[strings.TrimSpace(profile.ID)]; ok {
			filtered.Profiles = append(filtered.Profiles, profile)
		}
	}
	return filtered
}

func loadControlCatalog(root string, paths []string) (*compliance.CatalogIndex, error) {
	catalogPaths := make([]string, 0, len(paths))
	for _, path := range paths {
		catalogPaths = append(catalogPaths, resolveRootPath(root, strings.TrimSpace(path)))
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
	return compliance.LoadControlProfileSetFile(resolveRootPath(root, path))
}

func loadControlExtensions(root string, paths []string) ([]string, []string, error) {
	catalogPaths := []string{}
	profilePaths := []string{}
	for _, path := range paths {
		manifestPath := resolveRootPath(root, path)
		pack, err := compliance.LoadControlExtensionPackFile(manifestPath)
		if err != nil {
			return nil, nil, fmt.Errorf("load extension %s: %w", path, err)
		}
		if issues := compliance.ValidateControlExtensionPack(pack); len(issues) != 0 {
			return nil, nil, validationIssuesError(path, issues)
		}
		manifestDir := filepath.Dir(manifestPath)
		for _, catalog := range pack.Catalogs {
			catalogPaths = append(catalogPaths, resolveExtensionPath(manifestDir, catalog))
		}
		for _, profiles := range pack.Profiles {
			profilePaths = append(profilePaths, resolveExtensionPath(manifestDir, profiles))
		}
	}
	return catalogPaths, profilePaths, nil
}

func resolveRootPath(root string, path string) string {
	path = strings.TrimSpace(path)
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(root, filepath.FromSlash(path))
}

func resolveExtensionPath(manifestDir string, path string) string {
	path = strings.TrimSpace(path)
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(manifestDir, filepath.FromSlash(path))
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
