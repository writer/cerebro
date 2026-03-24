package app

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPreCommitHookRunsFastLintOnStagedGoFiles(t *testing.T) {
	root := repoRoot(t)
	hookPath := filepath.Join(root, ".githooks", "pre-commit")
	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read pre-commit hook: %v", err)
	}
	text := string(content)

	if !strings.Contains(text, "./scripts/pre_commit_checks.sh") {
		t.Fatalf("expected pre-commit hook to delegate to scripts/pre_commit_checks.sh")
	}
}

func TestPreCommitChecksScriptRunsFormattingVetAndIdentifierSafetyChecks(t *testing.T) {
	root := repoRoot(t)
	scriptPath := filepath.Join(root, "scripts", "pre_commit_checks.sh")
	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read pre_commit_checks.sh: %v", err)
	}
	text := string(content)

	if !strings.Contains(text, "git diff --cached --name-only --diff-filter=ACM -- '*.go'") {
		t.Fatalf("expected pre-commit checks script to inspect staged Go files")
	}
	if !strings.Contains(text, "STAGED_PATHS=()") {
		t.Fatalf("expected pre-commit checks script to collect all staged paths")
	}
	if strings.Contains(text, "mapfile") {
		t.Fatalf("expected pre-commit hook to avoid bash 4-only mapfile")
	}
	if !strings.Contains(text, "build constraints exclude all Go files") {
		t.Fatalf("expected pre-commit hook to skip build-ignored generator directories")
	}
	if !strings.Contains(text, "gofmt -w") {
		t.Fatalf("expected pre-commit checks script to run gofmt")
	}
	if !strings.Contains(text, "go vet") {
		t.Fatalf("expected pre-commit checks script to run go vet")
	}
	if !strings.Contains(text, `go test "${FILTERED_PACKAGE_DIRS[@]}"`) {
		t.Fatalf("expected pre-commit checks script to run go test on staged package directories")
	}
	if !strings.Contains(text, "golangci-lint run --fast-only") {
		t.Fatalf("expected pre-commit checks script to run golangci-lint --fast-only")
	}
	if !strings.Contains(text, "go run ./scripts/check_graph_id_safety/main.go") {
		t.Fatalf("expected pre-commit checks script to run graph ID safety checks")
	}
	for _, command := range []string{
		"go run ./scripts/check_api_contract_compat/main.go",
		"go run ./scripts/check_cloudevents_contract_compat/main.go",
		"go run ./scripts/check_report_contract_compat/main.go",
		"go run ./scripts/check_entity_facet_compat/main.go",
		"go run ./scripts/check_agent_sdk_contract_compat/main.go",
		"go test ./internal/graphingest -run 'TestMapperContractFixtures|TestMapperSourceDomainCoverageGuardrails' -count=1",
	} {
		if !strings.Contains(text, command) {
			t.Fatalf("expected pre-commit checks script to run %s", command)
		}
	}
	for _, fragment := range []string{
		"internal/graph/schema/",
		"internal/graph/store_spanner",
		"go test ./internal/graph -run TestSpannerWorldModelSchemaStatements -count=1",
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("expected pre-commit checks script to include %s", fragment)
		}
	}
}

func TestPreCommitConfigUsesSharedChecksScript(t *testing.T) {
	root := repoRoot(t)
	configPath := filepath.Join(root, ".pre-commit-config.yaml")
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read .pre-commit-config.yaml: %v", err)
	}
	text := string(content)

	if !strings.Contains(text, "scripts/pre_commit_checks.sh") {
		t.Fatalf("expected .pre-commit-config.yaml to reference scripts/pre_commit_checks.sh")
	}
	if !strings.Contains(text, "pass_filenames: false") {
		t.Fatalf("expected .pre-commit-config.yaml to disable filename passing for the shared script")
	}
}

func TestMakefileDefinesPreCommitTarget(t *testing.T) {
	root := repoRoot(t)
	makefilePath := filepath.Join(root, "Makefile")
	content, err := os.ReadFile(makefilePath)
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	text := string(content)

	if !strings.Contains(text, ".PHONY:") || !strings.Contains(text, " pre-commit") {
		t.Fatalf("expected Makefile .PHONY declaration to include pre-commit")
	}
	if !strings.Contains(text, "\npre-commit:\n\t./scripts/pre_commit_checks.sh") {
		t.Fatalf("expected Makefile to define a pre-commit target that runs scripts/pre_commit_checks.sh")
	}
	if !strings.Contains(text, " verify") {
		t.Fatalf("expected Makefile .PHONY declaration to include verify")
	}
	for _, fragment := range []string{
		"\nverify:\n\tgo test -race ./...",
		"\t$(MAKE) lint",
		"\t$(MAKE) api-contract-compat",
		"\t$(MAKE) cloudevents-contract-compat",
		"\t$(MAKE) report-contract-compat",
		"\t$(MAKE) entity-facet-contract-compat",
		"\t$(MAKE) agent-sdk-contract-compat",
		"\t$(MAKE) graph-ontology-guardrails",
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("expected Makefile verify target to include %q", fragment)
		}
	}
}

func TestPrePushHookRunsChangedDevexPreflight(t *testing.T) {
	root := repoRoot(t)
	hookPath := filepath.Join(root, ".githooks", "pre-push")
	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read pre-push hook: %v", err)
	}
	text := string(content)

	if !strings.Contains(text, "python3 ./scripts/devex.py run --mode changed") {
		t.Fatalf("expected pre-push hook to run changed-file DevEx preflight")
	}
	if !strings.Contains(text, "CEREBRO_SKIP_PRE_PUSH") {
		t.Fatalf("expected pre-push hook to allow explicit skip")
	}
	if !strings.Contains(text, "git symbolic-ref --quiet --short \"refs/remotes/${remote_name}/HEAD\"") {
		t.Fatalf("expected pre-push hook to resolve the push remote's default branch")
	}
	if !strings.Contains(text, "git merge-base HEAD \"$candidate\"") {
		t.Fatalf("expected pre-push hook to skip unrelated remote base refs")
	}
	if !strings.Contains(text, "CEREBRO_DEVEX_BASE_REF") {
		t.Fatalf("expected pre-push hook to support an override base ref")
	}
}

func TestHooksTargetInstallsTrackedHooksAndFallbackShims(t *testing.T) {
	root := repoRoot(t)

	makefilePath := filepath.Join(root, "Makefile")
	makefileContent, err := os.ReadFile(makefilePath)
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	makefileText := string(makefileContent)
	if !strings.Contains(makefileText, "./scripts/install_hooks.sh") {
		t.Fatalf("expected Makefile hooks target to invoke scripts/install_hooks.sh")
	}

	scriptPath := filepath.Join(root, "scripts", "install_hooks.sh")
	scriptContent, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read install_hooks.sh: %v", err)
	}
	scriptText := string(scriptContent)

	checks := []string{
		"git rev-parse --git-common-dir",
		"for hook in pre-commit pre-push; do",
		"cat >\"$git_common_dir/hooks/$hook\" <<EOF",
		"hook_path=\"\\${repo_root}/.githooks/$hook\"",
		"exec \"\\$hook_path\" \"\\$@\"",
		"git config core.hooksPath .githooks",
	}
	for _, needle := range checks {
		if !strings.Contains(scriptText, needle) {
			t.Fatalf("expected install_hooks.sh to contain %q", needle)
		}
	}
}

func TestAgentSDKPackagesCheckUsesPortableTOMLValidator(t *testing.T) {
	root := repoRoot(t)

	makefilePath := filepath.Join(root, "Makefile")
	makefileContent, err := os.ReadFile(makefilePath)
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	makefileText := string(makefileContent)
	if !strings.Contains(makefileText, "python3 ./scripts/validate_toml.py sdk/python/pyproject.toml") {
		t.Fatalf("expected agent-sdk-packages-check to use scripts/validate_toml.py")
	}

	scriptPath := filepath.Join(root, "scripts", "validate_toml.py")
	scriptContent, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read validate_toml.py: %v", err)
	}
	scriptText := string(scriptContent)

	checks := []string{
		"import tomli as tomllib",
		"skipping TOML parse",
		"parser.load(handle)",
	}
	for _, needle := range checks {
		if !strings.Contains(scriptText, needle) {
			t.Fatalf("expected validate_toml.py to contain %q", needle)
		}
	}
}

func TestGolangCILintConfigEnablesTestLinting(t *testing.T) {
	root := repoRoot(t)
	configPath := filepath.Join(root, ".golangci.yml")
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read golangci config: %v", err)
	}
	text := string(content)

	if !strings.Contains(text, "tests: true") {
		t.Fatalf("expected golangci config to lint tests")
	}
	if !strings.Contains(text, "path: _test\\.go") {
		t.Fatalf("expected golangci config to define test-file exclusion rules")
	}
	if !strings.Contains(text, "- noctx") {
		t.Fatalf("expected golangci config to exclude noctx on test files")
	}
}

func TestGoVersionScriptMatchesGoMod(t *testing.T) {
	root := repoRoot(t)
	expected := expectedGoVersionFromGoMod(t, root)

	scriptPath := filepath.Join(root, "scripts", "go_version.sh")
	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read go_version.sh: %v", err)
	}
	text := string(content)

	if !strings.Contains(text, "toolchain go") {
		t.Fatalf("expected go_version.sh to parse toolchain directive")
	}
	if !strings.Contains(text, "version=\"$(awk '/^go [0-9]/{print $2; exit}'") {
		t.Fatalf("expected go_version.sh to fall back to go directive")
	}
	if !strings.Contains(text, "printf '%s\\n' \"${version}\"") {
		t.Fatalf("expected go_version.sh to print parsed version")
	}
	if expected == "" {
		t.Fatalf("expected non-empty go.mod version")
	}
}

func TestDockerfileUsesGoVersionBuildArg(t *testing.T) {
	root := repoRoot(t)
	dockerfilePath := filepath.Join(root, "Dockerfile")
	content, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	text := string(content)

	if !strings.Contains(text, "ARG GO_VERSION") {
		t.Fatalf("expected Dockerfile to declare GO_VERSION build arg")
	}
	if !strings.Contains(text, "golang:${GO_VERSION}-alpine") {
		t.Fatalf("expected Dockerfile builder image to use GO_VERSION build arg")
	}
}

func TestWorkflowsUseGoVersionFileFromGoMod(t *testing.T) {
	root := repoRoot(t)
	workflowFiles := []string{
		".github/workflows/ci.yml",
		".github/workflows/release.yml",
		".github/workflows/security-source-scan.yml",
	}

	for _, rel := range workflowFiles {
		abs := filepath.Join(root, rel)
		content, err := os.ReadFile(abs)
		if err != nil {
			t.Fatalf("read workflow %s: %v", rel, err)
		}
		text := string(content)

		if !strings.Contains(text, "go-version-file: go.mod") {
			t.Fatalf("expected workflow %s to use go-version-file: go.mod", rel)
		}
		if strings.Contains(text, "go-version: '1.26.1'") {
			t.Fatalf("expected workflow %s to avoid hardcoded Go version", rel)
		}
	}
}

func TestWorkflowsAvoidNode20OnlyBuilderAction(t *testing.T) {
	root := repoRoot(t)
	workflowFiles := []string{
		".github/workflows/ci.yml",
		".github/workflows/release.yml",
	}

	for _, rel := range workflowFiles {
		abs := filepath.Join(root, rel)
		content, err := os.ReadFile(abs)
		if err != nil {
			t.Fatalf("read workflow %s: %v", rel, err)
		}
		text := string(content)

		if strings.Contains(text, "useblacksmith/setup-docker-builder") {
			t.Fatalf("expected workflow %s to avoid Node20-only useblacksmith/setup-docker-builder", rel)
		}
		if !strings.Contains(text, "docker/setup-buildx-action@") {
			t.Fatalf("expected workflow %s to use docker/setup-buildx-action", rel)
		}
	}
}

func TestDockerBuildCommandsPassGoVersionBuildArg(t *testing.T) {
	root := repoRoot(t)

	makefilePath := filepath.Join(root, "Makefile")
	makefileContent, err := os.ReadFile(makefilePath)
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	makefileText := string(makefileContent)
	if !strings.Contains(makefileText, "GO_VERSION ?= $(shell ./scripts/go_version.sh)") {
		t.Fatalf("expected Makefile to derive GO_VERSION from scripts/go_version.sh")
	}
	if !strings.Contains(makefileText, "docker build --build-arg GO_VERSION=$(GO_VERSION) -t cerebro:latest .") {
		t.Fatalf("expected Makefile docker-build target to pass GO_VERSION build arg")
	}
	if !strings.Contains(makefileText, "docker build --build-arg GO_VERSION=$(GO_VERSION) -f Dockerfile -t $(SECURITY_SCAN_IMAGE) .") {
		t.Fatalf("expected Makefile security scan image build to pass GO_VERSION build arg")
	}
	for _, target := range []string{"gosec:", "govulncheck:", "graph-ontology-guardrails:", "devex-codegen:", "devex-codegen-check:", "devex-changed:", "devex-pr:"} {
		if !strings.Contains(makefileText, "\n"+target) {
			t.Fatalf("expected Makefile to define %s", strings.TrimSuffix(target, ":"))
		}
	}
	if !strings.Contains(makefileText, "python3 ./scripts/devex.py run --mode changed") {
		t.Fatalf("expected Makefile devex-changed target to invoke scripts/devex.py")
	}
	if !strings.Contains(makefileText, "python3 ./scripts/devex.py run --mode pr") {
		t.Fatalf("expected Makefile devex-pr target to invoke scripts/devex.py")
	}
	if !strings.Contains(makefileText, "go run ./scripts/generate_devex_codegen_docs/main.go") {
		t.Fatalf("expected Makefile devex-codegen target to invoke scripts/generate_devex_codegen_docs/main.go")
	}
	if !strings.Contains(makefileText, "CEREBRO_CLI_MODE=direct ./bin/cerebro policy validate") {
		t.Fatalf("expected Makefile policy-validate target to force direct CLI mode")
	}
	if !strings.Contains(makefileText, "CEREBRO_CLI_MODE=direct ./bin/cerebro policy list") {
		t.Fatalf("expected Makefile policy-list target to force direct CLI mode")
	}

	ciPath := filepath.Join(root, ".github", "workflows", "ci.yml")
	ciContent, err := os.ReadFile(ciPath)
	if err != nil {
		t.Fatalf("read ci workflow: %v", err)
	}
	ciText := string(ciContent)
	if !strings.Contains(ciText, "GO_VERSION=\"$(./scripts/go_version.sh)\"") {
		t.Fatalf("expected CI workflow to derive GO_VERSION from go.mod via script")
	}
	if !strings.Contains(ciText, "docker build --build-arg GO_VERSION=\"${GO_VERSION}\" -f Dockerfile -t cerebro:ci .") {
		t.Fatalf("expected CI workflow Docker build to pass GO_VERSION build arg")
	}
}

func TestGoGenerateDirectivesForGeneratedArtifacts(t *testing.T) {
	root := repoRoot(t)

	appPath := filepath.Join(root, "internal", "app", "app.go")
	appContent, err := os.ReadFile(appPath)
	if err != nil {
		t.Fatalf("read app.go: %v", err)
	}
	appText := string(appContent)
	if !strings.Contains(appText, "//go:generate sh -c \"cd ../.. && go run ./scripts/generate_config_docs/main.go\"") {
		t.Fatalf("expected app.go to include go:generate directive for config docs")
	}

	routesPath := filepath.Join(root, "internal", "api", "server_routes.go")
	routesContent, err := os.ReadFile(routesPath)
	if err != nil {
		t.Fatalf("read server_routes.go: %v", err)
	}
	routesText := string(routesContent)
	if !strings.Contains(routesText, "//go:generate sh -c \"cd ../.. && go run ./scripts/openapi_route_parity.go --write\"") {
		t.Fatalf("expected server_routes.go to include go:generate directive for OpenAPI sync")
	}

	devGuidePath := filepath.Join(root, "docs", "DEVELOPMENT.md")
	devGuideContent, err := os.ReadFile(devGuidePath)
	if err != nil {
		t.Fatalf("read DEVELOPMENT.md: %v", err)
	}
	devGuideText := string(devGuideContent)
	if !strings.Contains(devGuideText, "go generate ./internal/app ./internal/api") {
		t.Fatalf("expected DEVELOPMENT.md to document go generate workflow")
	}
}

func TestDevelopmentGuideDocumentsDevexPreflight(t *testing.T) {
	root := repoRoot(t)
	devGuidePath := filepath.Join(root, "docs", "DEVELOPMENT.md")
	content, err := os.ReadFile(devGuidePath)
	if err != nil {
		t.Fatalf("read DEVELOPMENT.md: %v", err)
	}
	text := string(content)

	for _, needle := range []string{"make devex-changed", "make devex-pr", "make devex-codegen-check", "devex/codegen_catalog.json", "python3 scripts/devex.py plan --mode changed"} {
		if !strings.Contains(text, needle) {
			t.Fatalf("expected DEVELOPMENT.md to document %s", needle)
		}
	}
}

func TestDevexScriptPlansRelevantChecks(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("python3", "./scripts/devex.py", "plan", "--mode", "changed", "--json", "--files", "api/openapi.yaml", "internal/graph/entity_facets.go", "devex/codegen_catalog.json", ".githooks/pre-push")
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("run scripts/devex.py: %v", err)
	}

	var plan struct {
		Steps []struct {
			Key string `json:"key"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(output, &plan); err != nil {
		t.Fatalf("decode devex plan: %v", err)
	}
	keys := make(map[string]struct{}, len(plan.Steps))
	for _, step := range plan.Steps {
		keys[step.Key] = struct{}{}
	}
	for _, expected := range []string{"changed-go-tests", "changed-go-lint", "openapi-check", "entity-facet-docs-check", "entity-facet-contract-compat", "devex-codegen-check", "devex-static-tests"} {
		if _, ok := keys[expected]; !ok {
			t.Fatalf("expected devex plan to include %q, got %#v", expected, keys)
		}
	}
}

func TestDevexScriptChangedModeIncludesWorkspaceDiffSources(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "scripts", "devex.py")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read scripts/devex.py: %v", err)
	}
	text := string(content)

	for _, needle := range []string{
		"merge-base\", \"HEAD\", base_ref",
		"run_git([\"diff\", \"--name-only\", \"--diff-filter=ACMRTUXB\", f\"{merge_base}...HEAD\"])",
		"run_git([\"diff\", \"--name-only\", \"--diff-filter=ACMRTUXB\"])",
		"run_git([\"diff\", \"--cached\", \"--name-only\", \"--diff-filter=ACMRTUXB\"])",
		"run_git([\"ls-files\", \"--others\", \"--exclude-standard\"])",
		"DevexScriptChangedModeIncludesWorkspaceDiffSources",
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("expected scripts/devex.py to include %s", needle)
		}
	}
}

func TestDevexScriptPrefersGoPathToolingForGoChecks(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "scripts", "devex.py")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read scripts/devex.py: %v", err)
	}
	text := string(content)

	goPathIdx := strings.Index(text, "candidate = Path(")
	whichIdx := strings.Index(text, "resolved = shutil.which(executable)")
	if goPathIdx == -1 || whichIdx == -1 {
		t.Fatalf("expected scripts/devex.py to resolve both GOPATH and PATH tooling")
	}
	if goPathIdx > whichIdx {
		t.Fatalf("expected scripts/devex.py to prefer GOPATH tooling before PATH resolution")
	}
	if !strings.Contains(text, "if executable in {\"golangci-lint\", \"gosec\", \"govulncheck\", \"goimports\"}") {
		t.Fatalf("expected scripts/devex.py to special-case Go developer tools")
	}
}

func TestDevexScriptSkipsBuildIgnoredGeneratorDirs(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("python3", "./scripts/devex.py", "plan", "--mode", "changed", "--json", "--files", "scripts/generate_config_docs/main.go")
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("run scripts/devex.py: %v", err)
	}

	var plan struct {
		Steps []struct {
			Key     string   `json:"key"`
			Command []string `json:"command"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(output, &plan); err != nil {
		t.Fatalf("decode devex plan: %v", err)
	}

	for _, step := range plan.Steps {
		for _, arg := range step.Command {
			if arg == "./scripts/generate_config_docs" {
				t.Fatalf("expected build-ignored generator package to be excluded from changed-go steps, got %#v", plan.Steps)
			}
		}
	}
}

func TestConfigDocsGeneratorIgnoresMethodLoadConfig(t *testing.T) {
	root := repoRoot(t)
	scriptPath := filepath.Join(root, "scripts", "generate_config_docs", "main.go")
	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read generate_config_docs script: %v", err)
	}
	text := string(content)

	if !strings.Contains(text, "if fn.Recv != nil") {
		t.Fatalf("expected config docs generator to ignore method declarations when matching LoadConfig")
	}
}

func TestDependabotConfigCoversCoreEcosystems(t *testing.T) {
	root := repoRoot(t)

	configPath := filepath.Join(root, ".github", "dependabot.yml")
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read dependabot config: %v", err)
	}
	text := string(content)

	for _, ecosystem := range []string{"gomod", "docker", "github-actions"} {
		if !strings.Contains(text, `package-ecosystem: "`+ecosystem+`"`) {
			t.Fatalf("expected dependabot config to include %s updates", ecosystem)
		}
	}
	for _, group := range []string{"go-minor-and-patch", "docker-base-images", "github-actions"} {
		if !strings.Contains(text, group+":") {
			t.Fatalf("expected dependabot config to include %s group", group)
		}
	}
}

func TestNoLogPrintCallsInAppCode(t *testing.T) {
	root := repoRoot(t)
	roots := []string{
		filepath.Join(root, "cmd"),
		filepath.Join(root, "internal"),
	}
	printCalls := map[string]struct{}{
		"Print":   {},
		"Printf":  {},
		"Println": {},
	}

	fset := token.NewFileSet()
	violations := make([]string, 0)
	for _, scanRoot := range roots {
		err := filepath.WalkDir(scanRoot, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			if filepath.Ext(path) != ".go" {
				return nil
			}

			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}

			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel == nil {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "log" {
					return true
				}
				if _, ok := printCalls[sel.Sel.Name]; !ok {
					return true
				}

				relPath, relErr := filepath.Rel(root, path)
				if relErr != nil {
					relPath = path
				}
				pos := fset.Position(call.Pos())
				violations = append(violations, fmt.Sprintf("%s:%d uses log.%s", relPath, pos.Line, sel.Sel.Name))
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("scan %s: %v", scanRoot, err)
		}
	}

	if len(violations) > 0 {
		t.Fatalf("found disallowed log.Print* calls:\n%s", strings.Join(violations, "\n"))
	}
}

func TestCICoverageThresholdsIncludeSyncProvidersAndJobs(t *testing.T) {
	root := repoRoot(t)
	ciPath := filepath.Join(root, ".github", "workflows", "ci.yml")
	content, err := os.ReadFile(ciPath)
	if err != nil {
		t.Fatalf("read ci workflow: %v", err)
	}
	text := string(content)

	required := []string{
		"\"github.com/writer/cerebro/internal/sync\":",
		"\"github.com/writer/cerebro/internal/providers\":",
		"\"github.com/writer/cerebro/internal/jobs\":",
	}
	for _, needle := range required {
		if !strings.Contains(text, needle) {
			t.Fatalf("expected CI coverage thresholds to include %s", needle)
		}
	}
}

func TestSharedTestutilHelpersAreDefinedAndAdopted(t *testing.T) {
	root := repoRoot(t)

	helperPath := filepath.Join(root, "internal", "testutil", "testutil.go")
	helperContent, err := os.ReadFile(helperPath)
	if err != nil {
		t.Fatalf("read testutil helper file: %v", err)
	}
	helperText := string(helperContent)
	for _, fn := range []string{"func Logger()", "func Context(t *testing.T)"} {
		if !strings.Contains(helperText, fn) {
			t.Fatalf("expected internal/testutil/testutil.go to define %s", fn)
		}
	}

	adoptionFiles := []string{
		filepath.Join(root, "internal", "remediation", "engine_test.go"),
		filepath.Join(root, "internal", "scheduler", "scheduler_test.go"),
	}
	for _, file := range adoptionFiles {
		content, readErr := os.ReadFile(file)
		if readErr != nil {
			t.Fatalf("read adoption file %s: %v", file, readErr)
		}
		if !strings.Contains(string(content), "testutil.Logger()") {
			t.Fatalf("expected %s to use testutil.Logger()", file)
		}
	}
}

func expectedGoVersionFromGoMod(t *testing.T, root string) string {
	t.Helper()

	goModPath := filepath.Join(root, "go.mod")
	content, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}

	fallback := ""
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "toolchain go") {
			return strings.TrimPrefix(line, "toolchain go")
		}
		if strings.HasPrefix(line, "go ") {
			fallback = strings.TrimSpace(strings.TrimPrefix(line, "go "))
		}
	}
	if fallback == "" {
		t.Fatal("go.mod missing both toolchain and go directives")
	}
	return fallback
}

func repoRoot(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}
