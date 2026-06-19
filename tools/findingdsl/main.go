package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/findingdsl"
)

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		if err := runCommand(os.Args[1], os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "findingdsl: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := runLegacy(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "findingdsl: %v\n", err)
		os.Exit(1)
	}
}

func runCommand(command string, args []string) error {
	switch command {
	case "check":
		return runCheck(args)
	case "migrate", "migrate-policies":
		return runMigrate(args)
	case "new":
		return runNew(args)
	case "fmt":
		return runFmt(args)
	case "schema":
		return runSchema(args)
	case "test":
		return runTest(args)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func runLegacy(args []string) error {
	flags := flag.NewFlagSet("findingdsl", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	check := flags.Bool("check", false, "validate checked-in finding DSL files")
	migratePolicies := flags.Bool("migrate-policies", false, "convert legacy policy JSON files into PolicyFindingRule DSL YAML")
	write := flags.Bool("write", false, "write migration output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*check && !*migratePolicies {
		return errors.New("one of --check or --migrate-policies is required")
	}
	if *migratePolicies {
		if err := migratePolicyFiles(filepath.Clean(*root), *write); err != nil {
			return err
		}
	}
	if *check {
		if err := checkPolicyRules(filepath.Clean(*root)); err != nil {
			return err
		}
	}
	return nil
}

func runCheck(args []string) error {
	flags := flag.NewFlagSet("findingdsl check", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(args); err != nil {
		return err
	}
	return checkPolicyRules(filepath.Clean(*root))
}

func runMigrate(args []string) error {
	flags := flag.NewFlagSet("findingdsl migrate", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	write := flags.Bool("write", false, "write migration output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	return migratePolicyFiles(filepath.Clean(*root), *write)
}

func runNew(args []string) error {
	flags := flag.NewFlagSet("findingdsl new", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	id := flags.String("id", "", "policy id")
	domain := flags.String("domain", "", "policy domain under policies/")
	name := flags.String("name", "", "policy name")
	description := flags.String("description", "", "policy description")
	severity := flags.String("severity", "medium", "policy severity")
	effect := flags.String("effect", "", "policy effect for condition-backed policies")
	resource := flags.String("resource", "", "policy resource selector")
	resourceType := flags.String("resource-type", "", "human-readable resource type")
	remediation := flags.String("remediation", "", "remediation summary")
	query := flags.String("query", "", "query-backed policy expression")
	graphQuery := flags.String("graph-query", "", "read-only Cypher query for a graph-backed policy")
	graphRowLimit := flags.Int("graph-row-limit", 0, "graph query row limit")
	output := flags.String("out", "", "output path; defaults to policies/<domain>/<id>.yaml")
	write := flags.Bool("write", false, "write the policy file instead of printing YAML")
	var conditions stringList
	var references stringList
	var tags stringList
	var risks stringList
	var frameworks stringList
	var steps stringList
	var graphParams stringList
	var graphRequiredColumns stringList
	flags.Var(&conditions, "condition", "condition-backed policy expression; repeatable")
	flags.Var(&references, "reference", "metadata reference URL or document path; repeatable")
	flags.Var(&tags, "tag", "metadata tag; repeatable")
	flags.Var(&risks, "risk-category", "risk category; repeatable")
	flags.Var(&frameworks, "framework", "framework mapping as name:control[,control]; repeatable")
	flags.Var(&steps, "remediation-step", "remediation step; repeatable")
	flags.Var(&graphParams, "graph-param", "graph Cypher parameter as key=value; repeatable")
	flags.Var(&graphRequiredColumns, "graph-required-column", "required graph query return alias; repeatable")
	if err := flags.Parse(args); err != nil {
		return err
	}
	parsedFrameworks, err := parseFrameworks(frameworks)
	if err != nil {
		return err
	}
	parsedGraphParams, err := parseGraphParams(graphParams)
	if err != nil {
		return err
	}
	rule := findingdsl.NewPolicyRule(findingdsl.NewPolicyRuleInput{
		ID:           *id,
		Domain:       *domain,
		Name:         *name,
		Description:  *description,
		References:   references,
		Severity:     *severity,
		Effect:       *effect,
		Resource:     *resource,
		ResourceType: *resourceType,
		Conditions:   conditions,
		Query:        *query,
		Graph: findingdsl.PolicyRuleGraphFinding{
			Query:           *graphQuery,
			RowLimit:        *graphRowLimit,
			Params:          parsedGraphParams,
			RequiredColumns: graphRequiredColumns,
		},
		Tags:            tags,
		RiskCategories:  risks,
		Frameworks:      parsedFrameworks,
		Remediation:     *remediation,
		RemediationStep: steps,
	})
	if issues := findingdsl.ValidatePolicyRule(rule); len(issues) != 0 {
		printIssues(issues)
		return fmt.Errorf("new policy is invalid with %d issue(s)", len(issues))
	}
	content, err := findingdsl.FormatPolicyRuleYAML(rule)
	if err != nil {
		return err
	}
	if !*write {
		_, err := os.Stdout.Write(content)
		return err
	}
	targetRel := strings.TrimSpace(*output)
	if targetRel == "" {
		if strings.TrimSpace(*domain) == "" {
			return errors.New("--domain is required when --out is omitted")
		}
		targetRel = findingdsl.PolicyRuleRelPath(*domain, rule.Metadata.ID)
	}
	if err := writeRepoFile(filepath.Clean(*root), targetRel, content, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "findingdsl: wrote %s\n", filepath.ToSlash(targetRel))
	return nil
}

func runFmt(args []string) error {
	flags := flag.NewFlagSet("findingdsl fmt", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	write := flags.Bool("write", false, "rewrite policy files in place")
	check := flags.Bool("check", false, "fail if any policy file is not formatted")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cleanRoot := filepath.Clean(*root)
	paths := flags.Args()
	if len(paths) == 0 {
		discovered, err := allPolicyRulePaths(cleanRoot)
		if err != nil {
			return err
		}
		paths = discovered
	}
	changed := 0
	for _, path := range paths {
		rel, err := policyRel(cleanRoot, resolvePath(cleanRoot, path))
		if err != nil {
			return err
		}
		rule, issues, err := findingdsl.LoadPolicyRuleFile(cleanRoot, filepath.Join(cleanRoot, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		if len(issues) != 0 {
			printIssues(issues)
			return fmt.Errorf("%s is invalid", rel)
		}
		formatted, err := findingdsl.FormatPolicyRuleYAML(rule)
		if err != nil {
			return err
		}
		current, err := readRepoFile(cleanRoot, rel)
		if err != nil {
			return err
		}
		if bytes.Equal(current, formatted) {
			continue
		}
		changed++
		if *write {
			if err := writeRepoFile(cleanRoot, rel, formatted, 0o600); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "formatted %s\n", rel)
			continue
		}
		fmt.Fprintf(os.Stdout, "%s needs formatting\n", rel)
	}
	if changed != 0 && (*check || !*write) {
		return fmt.Errorf("%d policy file(s) need formatting", changed)
	}
	return nil
}

func runSchema(args []string) error {
	flags := flag.NewFlagSet("findingdsl schema", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	output := flags.String("out", findingdsl.PolicyRuleSchemaRelPath, "schema output path")
	write := flags.Bool("write", false, "write schema output")
	check := flags.Bool("check", false, "fail if schema output is stale")
	if err := flags.Parse(args); err != nil {
		return err
	}
	schema, err := findingdsl.PolicyRuleJSONSchema()
	if err != nil {
		return err
	}
	schema = append(schema, '\n')
	if !*write && !*check {
		_, err := os.Stdout.Write(schema)
		return err
	}
	cleanRoot := filepath.Clean(*root)
	if *write {
		return writeRepoFile(cleanRoot, *output, schema, 0o600)
	}
	current, err := readRepoFile(cleanRoot, *output)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, schema) {
		return fmt.Errorf("%s is stale; run go run ./tools/findingdsl schema --write", filepath.ToSlash(*output))
	}
	return nil
}

func runTest(args []string) error {
	flags := flag.NewFlagSet("findingdsl test", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cleanRoot := filepath.Clean(*root)
	paths := flags.Args()
	if len(paths) == 0 {
		discovered, err := findingdsl.DiscoverPolicyTestSuites(cleanRoot)
		if err != nil {
			return err
		}
		paths = discovered
	}
	if len(paths) == 0 {
		fmt.Fprintln(os.Stdout, "findingdsl: no policy test suites found")
		return nil
	}
	var issues []findingdsl.Issue
	for _, path := range paths {
		rel, err := policyRel(cleanRoot, resolvePath(cleanRoot, path))
		if err != nil {
			return err
		}
		issues = append(issues, findingdsl.RunPolicyRuleTestSuite(cleanRoot, filepath.Join(cleanRoot, filepath.FromSlash(rel)))...)
	}
	if len(issues) != 0 {
		printIssues(issues)
		return fmt.Errorf("policy DSL tests failed with %d issue(s)", len(issues))
	}
	fmt.Fprintf(os.Stdout, "findingdsl: %d policy test suite(s) passed\n", len(paths))
	return nil
}

func checkPolicyRules(root string) error {
	rules, issues, err := findingdsl.LoadPolicyRules(root)
	if err != nil {
		return err
	}
	printIssues(issues)
	if len(issues) != 0 {
		return fmt.Errorf("policy DSL validation failed with %d issue(s)", len(issues))
	}
	if len(rules) == 0 {
		return errors.New("no PolicyFindingRule DSL files found under policies/")
	}
	return nil
}

func migratePolicyFiles(root string, write bool) error {
	cleanRoot := filepath.Clean(root)
	repoRoot, err := os.OpenRoot(cleanRoot)
	if err != nil {
		return fmt.Errorf("open repository root: %w", err)
	}
	defer repoRoot.Close()
	policiesRoot := filepath.Join(cleanRoot, "policies")
	converted := 0
	err = filepath.WalkDir(policiesRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		rel, err := policyRel(cleanRoot, path)
		if err != nil {
			return err
		}
		if rel == findingdsl.ControlMappingRelPath {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: symlinked policy files are not allowed", rel)
		}
		content, err := repoRoot.ReadFile(rel)
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		legacy, err := findingdsl.DecodeLegacyPolicy(content)
		if err != nil {
			return fmt.Errorf("decode %s: %w", rel, err)
		}
		rule := findingdsl.FromLegacyPolicy(strings.TrimSuffix(rel, ".json")+".yaml", legacy)
		if issues := findingdsl.ValidatePolicyRule(rule); len(issues) != 0 {
			messages := make([]string, 0, len(issues))
			for _, issue := range issues {
				messages = append(messages, issue.Message)
			}
			return fmt.Errorf("validate migrated %s: %s", rel, strings.Join(messages, "; "))
		}
		yamlContent, err := findingdsl.MarshalPolicyRuleYAML(rule)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", rel, err)
		}
		targetRel := strings.TrimSuffix(rel, ".json") + ".yaml"
		if !write {
			fmt.Fprintf(os.Stdout, "would convert %s -> %s\n", rel, targetRel)
			converted++
			return nil
		}
		if err := ensureMigrationTargetAvailable(repoRoot, targetRel); err != nil {
			return fmt.Errorf("write %s: %w", targetRel, err)
		}
		if err := repoRoot.WriteFile(targetRel, yamlContent, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", targetRel, err)
		}
		if err := repoRoot.Remove(rel); err != nil {
			return fmt.Errorf("remove %s: %w", rel, err)
		}
		converted++
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("policies directory not found")
		}
		return err
	}
	if converted == 0 {
		fmt.Fprintln(os.Stdout, "findingdsl: no legacy policy JSON files to migrate")
		return nil
	}
	if write {
		fmt.Fprintf(os.Stdout, "findingdsl: converted %d legacy policy file(s)\n", converted)
	} else {
		fmt.Fprintf(os.Stdout, "findingdsl: %d legacy policy file(s) would be converted; rerun with --write\n", converted)
	}
	return nil
}

func ensureMigrationTargetAvailable(root *os.Root, rel string) error {
	info, err := root.Lstat(rel)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("symlinked generated files are not allowed")
	}
	return errors.New("destination already exists")
}

func allPolicyRulePaths(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(filepath.Join(root, "policies"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(path)
		if entry.Type()&os.ModeSymlink != 0 || findingdsl.ControlMappingRelPath == rel || strings.Contains(rel, ".test.") {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		policyPath, err := policyRel(root, path)
		if err != nil {
			return err
		}
		paths = append(paths, policyPath)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return paths, nil
}

func parseFrameworks(values []string) ([]findingdsl.PolicyFramework, error) {
	frameworks := make([]findingdsl.PolicyFramework, 0, len(values))
	for _, value := range values {
		framework, err := findingdsl.ParseFrameworkSpec(value)
		if err != nil {
			return nil, err
		}
		frameworks = append(frameworks, framework)
	}
	return frameworks, nil
}

func parseGraphParams(values []string) (map[string]any, error) {
	if len(values) == 0 {
		return nil, nil
	}
	params := map[string]any{}
	for _, value := range values {
		key, rawValue, ok := strings.Cut(value, "=")
		key = strings.TrimSpace(key)
		rawValue = strings.TrimSpace(rawValue)
		if !ok || key == "" {
			return nil, fmt.Errorf("graph-param %q must use key=value format", value)
		}
		params[key] = parseGraphParamValue(rawValue)
	}
	return params, nil
}

func parseGraphParamValue(value string) any {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true":
		return true
	case "false":
		return false
	case "null":
		return nil
	}
	if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
		return parsed
	}
	if parsed, err := strconv.ParseFloat(value, 64); err == nil {
		return parsed
	}
	return value
}

func printIssues(issues []findingdsl.Issue) {
	for _, issue := range issues {
		fmt.Fprintf(os.Stderr, "%s: %s\n", issue.Path, issue.Message)
	}
}

func readRepoFile(root string, rel string) ([]byte, error) {
	cleanRel, err := safeRepoRel(rel)
	if err != nil {
		return nil, err
	}
	content, err := fs.ReadFile(os.DirFS(root), cleanRel)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", cleanRel, err)
	}
	return content, nil
}

func writeRepoFile(root string, rel string, content []byte, perm fs.FileMode) error {
	cleanRel, err := safeRepoRel(rel)
	if err != nil {
		return err
	}
	repoRoot, err := os.OpenRoot(root)
	if err != nil {
		return fmt.Errorf("open repository root: %w", err)
	}
	defer repoRoot.Close()
	dir := filepath.ToSlash(filepath.Dir(cleanRel))
	if dir != "." {
		if err := repoRoot.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	if err := rejectSymlink(repoRoot, cleanRel); err != nil {
		return fmt.Errorf("write %s: %w", cleanRel, err)
	}
	if err := repoRoot.WriteFile(cleanRel, content, perm); err != nil {
		return fmt.Errorf("write %s: %w", cleanRel, err)
	}
	return nil
}

func rejectSymlink(root *os.Root, rel string) error {
	info, err := root.Lstat(rel)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("symlinked generated files are not allowed")
	}
	return nil
}

func resolvePath(root string, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, filepath.FromSlash(path))
}

func policyRel(root string, path string) (string, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", fmt.Errorf("resolve policy path: %w", err)
	}
	rel = filepath.ToSlash(rel)
	if strings.HasPrefix(rel, "../") || rel == ".." || filepath.IsAbs(rel) {
		return "", fmt.Errorf("policy path %q escapes repository root", path)
	}
	if !strings.HasPrefix(rel, "policies/") {
		return "", fmt.Errorf("policy path %q is outside policies/", rel)
	}
	return rel, nil
}

func safeRepoRel(rel string) (string, error) {
	cleanRel := filepath.ToSlash(filepath.Clean(filepath.FromSlash(rel)))
	if strings.HasPrefix(cleanRel, "../") || cleanRel == ".." || filepath.IsAbs(cleanRel) {
		return "", fmt.Errorf("path %q escapes repository root", rel)
	}
	return cleanRel, nil
}
