package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/tools/droidreview/bodyread"
)

const opusBugReviewModel = "claude-opus-4-8"

type preflightResult struct {
	ChangedFiles   []string          `json:"changed_files"`
	RunDroidReview bool              `json:"run_droid_review"`
	ReviewModel    string            `json:"review_model"`
	ReviewReason   string            `json:"review_reason"`
	Findings       []checkFinding    `json:"findings"`
	Checks         []string          `json:"checks"`
	ProbePlan      []reviewProbePass `json:"probe_plan"`
}

type checkFinding struct {
	Rule    string `json:"rule"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Message string `json:"message"`
}

type reviewProbePass struct {
	Name     string   `json:"name"`
	Why      string   `json:"why"`
	Commands []string `json:"commands"`
}

func main() {
	var base string
	var head string
	var repo string
	var jsonOut string
	flag.StringVar(&base, "base", "origin/main", "base git revision for changed-file preflight")
	flag.StringVar(&head, "head", "HEAD", "head git revision for changed-file preflight")
	flag.StringVar(&repo, "repo", ".", "repository root")
	flag.StringVar(&jsonOut, "json-out", "", "optional path for structured Droid preflight JSON")
	flag.Parse()

	started := time.Now()
	result, err := run(base, head, repo)
	if jsonOut != "" {
		if writeErr := writeJSONFile(jsonOut, result); writeErr != nil && err == nil {
			err = writeErr
		}
	}
	writeGitHubMetadata(result, time.Since(started), err)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func writeJSONFile(path string, result preflightResult) error {
	payload, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal preflight json: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil && filepath.Dir(path) != "." {
		return fmt.Errorf("create preflight json dir: %w", err)
	}
	if err := os.WriteFile(path, append(payload, '\n'), 0o600); err != nil {
		return fmt.Errorf("write preflight json: %w", err)
	}
	return nil
}

func run(base, head, repo string) (preflightResult, error) {
	files, err := changedFiles(base, head, repo)
	if err != nil {
		return preflightResult{RunDroidReview: true, ReviewModel: opusBugReviewModel}, err
	}
	result := classifyReview(files)
	result.Checks = []string{
		"bounded-body-read",
		"source-http-safety",
		"cypher-safety",
		"ask-post-processing-boundary",
		"candidate-lifecycle-atomicity",
	}
	result.ProbePlan = reviewProbePlan(files)
	for _, file := range files {
		if !strings.HasSuffix(file, ".go") || strings.HasSuffix(file, "_test.go") {
			continue
		}
		switch {
		case strings.HasPrefix(file, "vendor/"),
			strings.HasPrefix(file, "gen/"),
			strings.HasPrefix(file, "sdk/"),
			strings.Contains(file, "/testdata/"):
			continue
		}
		path := filepath.Join(repo, filepath.FromSlash(file))
		body, err := os.ReadFile(path)
		if err != nil {
			return result, fmt.Errorf("read %s: %w", file, err)
		}
		fileFindings, err := bodyread.FindUnboundedReadAll(file, body)
		if err != nil {
			return result, fmt.Errorf("scan %s: %w", file, err)
		}
		for _, finding := range fileFindings {
			result.Findings = append(result.Findings, checkFinding{
				Rule:    "bounded-body-read",
				File:    finding.File,
				Line:    finding.Line,
				Message: "io.ReadAll must read from io.LimitReader or be replaced with streaming code",
			})
		}
		result.Findings = append(result.Findings, sourceHTTPFindings(file, body)...)
		result.Findings = append(result.Findings, cypherFindings(file, body)...)
		result.Findings = append(result.Findings, askPostProcessingFindings(file, body)...)
		result.Findings = append(result.Findings, candidateLifecycleFindings(file, body)...)
	}
	if len(result.Findings) > 0 {
		var message strings.Builder
		message.WriteString("Droid review preflight found invariant violations:\n")
		for _, finding := range result.Findings {
			fmt.Fprintf(&message, "- [%s] %s:%d %s\n", finding.Rule, finding.File, finding.Line, finding.Message)
		}
		return result, fmt.Errorf("%s", strings.TrimRight(message.String(), "\n"))
	}
	fmt.Printf("Droid review preflight passed for %d changed files. run_droid_review=%t review_model=%s reason=%q\n", len(files), result.RunDroidReview, result.ReviewModel, result.ReviewReason)
	return result, nil
}

func reviewProbePlan(files []string) []reviewProbePass {
	passes := []reviewProbePass{{
		Name:     "changed-invariants",
		Why:      "Map changed paths to repository invariants before reviewing diffs.",
		Commands: []string{"make droid-review-preflight"},
	}}
	if anyFile(files, func(file string) bool {
		return strings.HasPrefix(file, "internal/graphagent/") || strings.HasPrefix(file, "internal/graphquery/")
	}) {
		passes = append(passes, reviewProbePass{
			Name:     "ask-trajectory",
			Why:      "Ask changes must preserve tenant-scoped read-only Cypher, deterministic routes, recovery events, and citation validation.",
			Commands: []string{"go test ./internal/graphagent -run 'TestAskTrajectory|TestService|TestConvertDraftToQuery'"},
		})
	}
	if anyFile(files, func(file string) bool {
		return strings.HasPrefix(file, ".github/workflows/") || strings.HasPrefix(file, "scripts/") || strings.HasPrefix(file, "sources/")
	}) {
		passes = append(passes, reviewProbePass{
			Name:     "security-context",
			Why:      "Workflow, script, and connector changes need scanner context plus manual exploitability validation.",
			Commands: []string{"make droid-review-sast"},
		})
	}
	if anyFile(files, func(file string) bool { return strings.HasSuffix(file, ".go") }) {
		passes = append(passes, reviewProbePass{
			Name:     "focused-go-tests",
			Why:      "Run the narrow Go packages touched by the diff before relying on the full verify gate.",
			Commands: []string{"go test ./tools/droidreview/..."},
		})
	}
	return passes
}

func anyFile(files []string, pred func(string) bool) bool {
	for _, file := range files {
		if pred(file) {
			return true
		}
	}
	return false
}

func changedFiles(base, head, repo string) ([]string, error) {
	files := map[string]struct{}{}
	for _, args := range [][]string{
		{"diff", "--name-only", "--diff-filter=ACMR", base + "..." + head},
		{"diff", "--name-only", "--diff-filter=ACMR"},
		{"diff", "--cached", "--name-only", "--diff-filter=ACMR"},
		{"ls-files", "--others", "--exclude-standard"},
	} {
		output, err := gitOutput(repo, args...)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				files[filepath.ToSlash(line)] = struct{}{}
			}
		}
	}
	ordered := make([]string, 0, len(files))
	for file := range files {
		ordered = append(ordered, file)
	}
	sort.Strings(ordered)
	return ordered, nil
}

func gitOutput(repo string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w\n%s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func classifyReview(files []string) preflightResult {
	result := preflightResult{
		ChangedFiles:   files,
		RunDroidReview: false,
		ReviewModel:    opusBugReviewModel,
		ReviewReason:   "docs/templates only; fast preflight and CI are sufficient",
	}
	for _, file := range files {
		if requiresBugReview(file) {
			result.RunDroidReview = true
			result.ReviewReason = "code, workflow, API, source, or security-sensitive paths changed"
			break
		}
	}
	return result
}

func requiresBugReview(file string) bool {
	switch {
	case strings.HasSuffix(file, ".go"),
		file == "go.mod",
		file == "go.sum",
		file == "Makefile",
		strings.HasPrefix(file, ".github/workflows/"),
		strings.HasPrefix(file, "api/"),
		strings.HasPrefix(file, "cmd/"),
		strings.HasPrefix(file, "gen/"),
		strings.HasPrefix(file, "internal/"),
		strings.HasPrefix(file, "scripts/"),
		strings.HasPrefix(file, "sources/"),
		strings.HasPrefix(file, "tools/"):
		return true
	default:
		return false
	}
}

func sourceHTTPFindings(file string, body []byte) []checkFinding {
	if !strings.HasPrefix(file, "sources/") {
		return nil
	}
	markers := []string{
		"http.DefaultClient",
		"&http.Client{",
		"io.ReadAll(resp.Body)",
		"io.ReadAll(response.Body)",
		"func readLimitedBody(",
		"type safeRoundTripper",
	}
	var findings []checkFinding
	for _, marker := range markers {
		if index := bytes.Index(body, []byte(marker)); index >= 0 {
			findings = append(findings, checkFinding{
				Rule:    "source-http-safety",
				File:    file,
				Line:    lineForIndex(body, index),
				Message: fmt.Sprintf("%s must stay centralized in internal/sourcehttp", marker),
			})
		}
	}
	return findings
}

func cypherFindings(file string, body []byte) []checkFinding {
	if !strings.HasPrefix(file, "internal/graphagent/") && !strings.HasPrefix(file, "internal/graphquery/") {
		return nil
	}
	if strings.HasSuffix(file, "_test.go") {
		return nil
	}
	var findings []checkFinding
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, body, 0)
	if err != nil {
		return findings
	}
	ast.Inspect(parsed, func(node ast.Node) bool {
		lit, ok := node.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		marker := suspiciousCypherToken(value)
		if marker != "" {
			findings = append(findings, checkFinding{
				Rule:    "cypher-safety",
				File:    file,
				Line:    fset.Position(lit.Pos()).Line,
				Message: fmt.Sprintf("Cypher templates must stay read-only and validator-covered; suspicious token %q found", marker),
			})
		}
		return true
	})
	return findings
}

func suspiciousCypherToken(value string) string {
	if isCypherSafetyGuidance(value) {
		return ""
	}
	upper := strings.ToUpper(value)
	cypherSignals := []string{"MATCH ", " RETURN ", "\nRETURN ", "WHERE ", "OPTIONAL MATCH", "UNWIND ", " LIMIT "}
	hasCypherSignal := false
	for _, signal := range cypherSignals {
		if strings.Contains(upper, signal) {
			hasCypherSignal = true
			break
		}
	}
	if !hasCypherSignal {
		return ""
	}
	for _, marker := range []string{"CREATE ", "MERGE ", "DELETE ", "DETACH DELETE", " SET ", "REMOVE ", "LOAD CSV", "CALL DBMS", "CALL APOC"} {
		if strings.Contains(upper, marker) {
			return strings.TrimSpace(marker)
		}
	}
	return ""
}

func isCypherSafetyGuidance(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(lower, "rules:") &&
		strings.Contains(lower, "generate read-only cypher") &&
		strings.Contains(lower, "do not use")
}

func askPostProcessingFindings(file string, body []byte) []checkFinding {
	if file != "internal/graphagent/ask.go" && file != "internal/graphagent/query_plan.go" {
		return nil
	}
	if !bytes.Contains(body, []byte("postProcessAskRows")) {
		return nil
	}
	if bytes.Contains(body, []byte("conversion.Deterministic")) || bytes.Contains(body, []byte(".Deterministic")) {
		return nil
	}
	return []checkFinding{{
		Rule:    "ask-post-processing-boundary",
		File:    file,
		Line:    lineForIndex(body, bytes.Index(body, []byte("postProcessAskRows"))),
		Message: "Ask post-processing must remain gated to deterministic templates, not LLM fallback rows",
	}}
}

func candidateLifecycleFindings(file string, body []byte) []checkFinding {
	if !strings.HasPrefix(file, "internal/findings/") && !strings.HasPrefix(file, "internal/statestore/") {
		return nil
	}
	if !bytes.Contains(body, []byte("FindingCandidate")) {
		return nil
	}
	hasRead := bytes.Contains(body, []byte("GetFindingCandidate")) || bytes.Contains(body, []byte("ListFindingCandidates"))
	hasWrite := bytes.Contains(body, []byte("UpdateFindingCandidate")) || bytes.Contains(body, []byte("RejectFindingCandidate"))
	hasAtomicHint := bytes.Contains(bytes.ToLower(body), []byte("compare-and-swap")) || bytes.Contains(bytes.ToLower(body), []byte("transaction"))
	if !hasRead || !hasWrite || hasAtomicHint {
		return nil
	}
	return []checkFinding{{
		Rule:    "candidate-lifecycle-atomicity",
		File:    file,
		Line:    lineForIndex(body, bytes.Index(body, []byte("FindingCandidate"))),
		Message: "candidate lifecycle code that reads and writes candidate state must use store-owned CAS or a transaction",
	}}
}

func lineForIndex(body []byte, index int) int {
	if index < 0 {
		return 1
	}
	return bytes.Count(body[:index], []byte("\n")) + 1
}

func writeGitHubMetadata(result preflightResult, duration time.Duration, runErr error) {
	if path := os.Getenv("GITHUB_OUTPUT"); path != "" {
		_ = appendFile(path, []byte(fmt.Sprintf("run_droid_review=%t\nreview_model=%s\nreview_reason=%s\n", result.RunDroidReview, result.ReviewModel, sanitizeOutput(result.ReviewReason))))
	}
	if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
		var summary strings.Builder
		summary.WriteString("\n### Droid Review Decision\n\n")
		fmt.Fprintf(&summary, "- Changed files: %d\n", len(result.ChangedFiles))
		fmt.Fprintf(&summary, "- Run Droid model review: `%t`\n", result.RunDroidReview)
		fmt.Fprintf(&summary, "- Review model: `%s`\n", result.ReviewModel)
		fmt.Fprintf(&summary, "- Reason: %s\n", result.ReviewReason)
		fmt.Fprintf(&summary, "- Preflight duration: %.1fs\n", duration.Seconds())
		if runErr != nil {
			fmt.Fprintf(&summary, "- Result: failed with %d finding(s)\n", len(result.Findings))
		} else {
			summary.WriteString("- Result: passed\n")
		}
		if len(result.Checks) > 0 {
			summary.WriteString("\nChecks:\n")
			for _, check := range result.Checks {
				fmt.Fprintf(&summary, "- `%s`\n", check)
			}
		}
		if len(result.ProbePlan) > 0 {
			summary.WriteString("\nProbe plan:\n")
			for _, pass := range result.ProbePlan {
				fmt.Fprintf(&summary, "- `%s`: %s Commands: `%s`\n", pass.Name, pass.Why, strings.Join(pass.Commands, "`, `"))
			}
		}
		if len(result.Findings) > 0 {
			summary.WriteString("\nFindings:\n")
			for _, finding := range result.Findings {
				fmt.Fprintf(&summary, "- `%s` %s:%d %s\n", finding.Rule, finding.File, finding.Line, finding.Message)
			}
		}
		_ = appendFile(path, []byte(summary.String()))
	}
}

func appendFile(path string, body []byte) (err error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	_, err = file.Write(body)
	return err
}

func sanitizeOutput(value string) string {
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	return value
}
