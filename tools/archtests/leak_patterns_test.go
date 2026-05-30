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
