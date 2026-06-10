package archtests

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLeakPatternsCoverOSSBoundaryCategories(t *testing.T) {
	patterns := loadLeakPatterns(t)
	cases := []string{
		"neo4j=abc123ef" + ".databases.neo4j.io",
		"okta=00u1" + "abcDEF234ghiJ5d7",
		"token=ghp_" + "abcdefghijklmnopqrstuvwxyz",
		"access_" + `token="abcdefghijklmnopqrstuvwxyz"`,
	}
	for _, candidate := range cases {
		if !matchesAnyLeakPattern(t, patterns, candidate) {
			t.Fatalf("expected leak patterns to match %q", candidate)
		}
	}
}

func TestLeakPatternsAllowSyntheticExamples(t *testing.T) {
	patterns := loadLeakPatterns(t)
	cases := []string{
		"tenant_urn=urn:cerebro:example:runtime:demo",
		"tenant_urn=urn:cerebro:acme:runtime:demo",
		"owner=alice@example.com",
		"api=https://app.example.com/login",
		"repo=ExampleInternal/cerebro",
		"stack=dev",
	}
	for _, candidate := range cases {
		if matchesAnyLeakPattern(t, patterns, candidate) {
			t.Fatalf("expected leak patterns not to match synthetic example %q", candidate)
		}
	}
}

func TestLeakCheckExcludesRootCertificateFiles(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "leak_check.sh"))
	if err != nil {
		t.Fatalf("read leak_check.sh: %v", err)
	}
	script := string(data)
	for _, want := range []string{
		"':(exclude)*.pem'",
		"':(exclude)**/*.pem'",
		"':(exclude)*.crt'",
		"':(exclude)**/*.crt'",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("leak_check.sh missing git pathspec %s", want)
		}
	}
}

func TestLeakCheckRejectsConcretePRMetadata(t *testing.T) {
	cases := []string{
		"Overlay test: alert `123` linked to `internet.ip:198.51.100.24` and `aws.ec2.instance:i-0123456789abcdef0`.",
		"Validation linked case `456` to `urn:cerebro:example:kubernetes_workload:cluster:namespace:Deployment/service`.",
		"Runtime validation touched cloud account 123456789012.",
	}
	for _, body := range cases {
		if output, err := runLeakCheckPRBody(t, "feat(source): enrich graph context", body); err == nil {
			t.Fatalf("expected PR metadata leak check to reject %q\n%s", body, output)
		}
	}
}

func TestLeakCheckAllowsHighLevelPRMetadata(t *testing.T) {
	body := strings.Join([]string{
		"Adds projection enrichment for extracted infrastructure and identity context.",
		"Test Plan:",
		"- go test ./internal/sourceprojection -run 'TestProjectPanopticon' -count=1 -v",
		"- make lint",
		"- go test ./...",
		"Live-shaped samples were reconstructed locally without publishing tenant or resource identifiers.",
	}, "\n")
	if output, err := runLeakCheckPRBody(t, "feat(source): enrich graph context", body); err != nil {
		t.Fatalf("expected high-level PR metadata to pass leak check: %v\n%s", err, output)
	}
}

func loadLeakPatterns(t *testing.T) []string {
	t.Helper()
	path := filepath.Join(repoRoot(t), "scripts", "leak_patterns.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read leak patterns: %v", err)
	}
	var patterns []string
	for _, line := range strings.Split(string(data), "\n") {
		value := strings.TrimSpace(line)
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		patterns = append(patterns, value)
	}
	if len(patterns) == 0 {
		t.Fatal("no leak patterns loaded")
	}
	return patterns
}

func runLeakCheckPRBody(t *testing.T, title string, body string) (string, error) {
	t.Helper()
	cmd := exec.Command("./scripts/leak_check.sh", "pr-body", title, body)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "CEREBRO_LEAK_USER_PATTERNS="+filepath.Join(t.TempDir(), "missing-patterns.txt"))
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func matchesAnyLeakPattern(t *testing.T, patterns []string, candidate string) bool {
	t.Helper()
	for _, pattern := range patterns {
		matched, errOutput, err := grepExtendedRegexpMatches(pattern, candidate)
		if err != nil {
			t.Fatalf("grep -E failed for leak pattern %q: %v\n%s", pattern, err, errOutput)
		}
		if matched {
			return true
		}
	}
	return false
}

func grepExtendedRegexpMatches(pattern, candidate string) (bool, string, error) {
	cmd := exec.Command("grep", "-E", "-q", "--", pattern)
	cmd.Stdin = strings.NewReader(candidate + "\n")
	output, err := cmd.CombinedOutput()
	if err == nil {
		return true, string(output), nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		return false, string(output), nil
	}
	return false, string(output), err
}
