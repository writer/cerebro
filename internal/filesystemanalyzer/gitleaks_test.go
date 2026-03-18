package filesystemanalyzer

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseGitleaksOutput(t *testing.T) {
	raw := []byte(`[
		{
			"RuleID": "AWS Access Key",
			"Description": "AWS key",
			"StartLine": 7,
			"Match": "AKIA1234567890ABCDEF",
			"Secret": "AKIA1234567890ABCDEF",
			"File": "./workspace/.env",
			"Fingerprint": "aws:fingerprint"
		},
		{
			"RuleID": "Generic API Key",
			"Description": "Generic secret",
			"StartLine": 3,
			"Match": "super-secret-value",
			"Secret": "super-secret-value",
			"File": "workspace/app.conf",
			"Fingerprint": "generic:fingerprint"
		},
		{
			"RuleID": "npm-access-token",
			"Description": "npm token",
			"StartLine": 5,
			"Match": "npm_1234567890abcdefghijklmnopqrstuvwxyz",
			"Secret": "npm_1234567890abcdefghijklmnopqrstuvwxyz",
			"File": "workspace/.npmrc",
			"Fingerprint": "npm:fingerprint"
		}
	]`)

	findings, err := parseGitleaksOutput(raw)
	if err != nil {
		t.Fatalf("parseGitleaksOutput: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected three findings, got %#v", findings)
	}
	if findings[0].Type != "aws_access_key" || findings[0].Severity != "critical" {
		t.Fatalf("expected aws finding normalization, got %#v", findings[0])
	}
	if findings[0].Path != "workspace/.env" || findings[0].Line != 7 {
		t.Fatalf("expected normalized path and line, got %#v", findings[0])
	}
	if len(findings[0].References) != 1 || findings[0].References[0].Provider != "aws" {
		t.Fatalf("expected aws reference extraction, got %#v", findings[0])
	}
	if strings.Contains(findings[0].Match, "AKIA1234567890ABCDEF") {
		t.Fatalf("expected gitleaks finding to be fingerprinted, got %#v", findings[0])
	}
	if findings[1].Type != "generic_api_key" || findings[1].Severity != "medium" {
		t.Fatalf("expected generic finding normalization, got %#v", findings[1])
	}
	if findings[2].Type != "npm_token" || findings[2].Severity != "high" {
		t.Fatalf("expected npm finding normalization, got %#v", findings[2])
	}
}

func TestGitleaksScannerScanFilesystem(t *testing.T) {
	script := "#!/bin/sh\n" +
		"found_report_path=0\n" +
		"while [ \"$#\" -gt 0 ]; do\n" +
		"  if [ \"$1\" = \"--report-path\" ] && [ \"$2\" = \"-\" ]; then\n" +
		"    found_report_path=1\n" +
		"    break\n" +
		"  fi\n" +
		"  shift\n" +
		"done\n" +
		"if [ \"$found_report_path\" -ne 1 ]; then\n" +
		"  echo missing --report-path - >&2\n" +
		"  exit 2\n" +
		"fi\n" +
		"printf '%s' '[{\"RuleID\":\"GitHub\",\"Description\":\"GitHub token\",\"StartLine\":1,\"Match\":\"ghp_1234567890abcdefghijklmn\",\"Secret\":\"ghp_1234567890abcdefghijklmn\",\"File\":\"workspace/.env\"}]'\n"
	path := writeSecretScannerExecutable(t, script)

	result, err := NewGitleaksScanner(path).ScanFilesystem(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("ScanFilesystem: %v", err)
	}
	if result.Engine != "gitleaks" || len(result.Findings) != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.Findings[0].Type != "github_token" {
		t.Fatalf("expected github token mapping, got %#v", result.Findings[0])
	}
}

func TestGitleaksScannerScanFilesystemError(t *testing.T) {
	script := "#!/bin/sh\necho boom >&2\nexit 2\n"
	path := writeSecretScannerExecutable(t, script)

	_, err := NewGitleaksScanner(path).ScanFilesystem(context.Background(), t.TempDir())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected stderr in error, got %v", err)
	}
}

func TestParseGitleaksReportRejectsOversizedOutput(t *testing.T) {
	raw := []byte(`[{"RuleID":"GitHub","Description":"GitHub token","StartLine":1,"Match":"ghp_1234567890abcdefghijklmn","Secret":"ghp_1234567890abcdefghijklmn","File":"workspace/.env"}]`)

	_, err := parseGitleaksReport(bytes.NewReader(raw), 32, defaultGitleaksMaxFindings)
	if err == nil {
		t.Fatal("expected size limit error")
	}
	if !strings.Contains(err.Error(), "max size") {
		t.Fatalf("expected max size error, got %v", err)
	}
}

func TestParseGitleaksReportRejectsTooManyFindings(t *testing.T) {
	raw := []byte(`[
		{"RuleID":"GitHub","Description":"GitHub token","StartLine":1,"Match":"ghp_1234567890abcdefghijklmn","Secret":"ghp_1234567890abcdefghijklmn","File":"workspace/.env"},
		{"RuleID":"GitHub","Description":"GitHub token","StartLine":2,"Match":"ghp_abcdefghijklmnopqrstuvwxyz","Secret":"ghp_abcdefghijklmnopqrstuvwxyz","File":"workspace/.env"}
	]`)

	_, err := parseGitleaksReport(bytes.NewReader(raw), int64(len(raw))+1, 1)
	if err == nil {
		t.Fatal("expected max findings error")
	}
	if !strings.Contains(err.Error(), "max findings") {
		t.Fatalf("expected max findings error, got %v", err)
	}
}

func TestNormalizeGitleaksRuleIDCanonicalizesNPMTokens(t *testing.T) {
	if got := normalizeGitleaksRuleID("npm-access-token"); got != "npm_token" {
		t.Fatalf("expected npm token canonicalization, got %q", got)
	}
}

func writeSecretScannerExecutable(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gitleaks")
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return path
}
