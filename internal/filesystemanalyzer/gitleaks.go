package filesystemanalyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultGitleaksMaxReportBytes = 8 << 20
	defaultGitleaksMaxFindings    = 5000
)

// GitleaksScanner wraps `gitleaks dir` for filesystem-root secret scanning.
type GitleaksScanner struct {
	binaryPath     string
	maxReportBytes int64
	maxFindings    int
}

type GitleaksGitScanner struct {
	binaryPath     string
	maxReportBytes int64
	maxFindings    int
}

func NewGitleaksScanner(binaryPath string) *GitleaksScanner {
	if strings.TrimSpace(binaryPath) == "" {
		binaryPath = "gitleaks"
	}
	return &GitleaksScanner{
		binaryPath:     binaryPath,
		maxReportBytes: defaultGitleaksMaxReportBytes,
		maxFindings:    defaultGitleaksMaxFindings,
	}
}

func NewGitleaksGitScanner(binaryPath string) *GitleaksGitScanner {
	if strings.TrimSpace(binaryPath) == "" {
		binaryPath = "gitleaks"
	}
	return &GitleaksGitScanner{
		binaryPath:     binaryPath,
		maxReportBytes: defaultGitleaksMaxReportBytes,
		maxFindings:    defaultGitleaksMaxFindings,
	}
}

func (s *GitleaksScanner) ScanFilesystem(ctx context.Context, rootfsPath string) (*SecretScanResult, error) {
	if strings.TrimSpace(s.binaryPath) == "" {
		return nil, fmt.Errorf("gitleaks binary path is required")
	}
	rootfsPath = strings.TrimSpace(rootfsPath)
	if rootfsPath == "" {
		return nil, fmt.Errorf("filesystem path is required")
	}
	if strings.ContainsAny(rootfsPath, "\r\n") {
		return nil, fmt.Errorf("filesystem path must not contain newlines")
	}
	absPath, err := filepath.Abs(rootfsPath)
	if err != nil {
		return nil, fmt.Errorf("resolve filesystem path %s: %w", rootfsPath, err)
	}

	cmd := exec.CommandContext(
		ctx,
		s.binaryPath,
		"dir",
		"--no-banner",
		"--log-level", "error",
		"--exit-code", "0",
		"--report-format", "json",
		"--report-path", "-",
		absPath,
	) // #nosec G204 -- fixed binary/arguments, no shell interpolation
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("gitleaks dir scan stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("gitleaks dir scan failed to start: %w", err)
	}
	findings, err := parseGitleaksReport(stdout, s.maxReportBytes, s.maxFindings)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if stderrText := strings.TrimSpace(stderr.String()); stderrText != "" {
			return nil, fmt.Errorf("%w: %s", err, stderrText)
		}
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		stderrText := strings.TrimSpace(stderr.String())
		if stderrText != "" {
			return nil, fmt.Errorf("gitleaks dir scan failed: %s", stderrText)
		}
		return nil, fmt.Errorf("gitleaks dir scan failed: %w", err)
	}
	return &SecretScanResult{
		Engine:   "gitleaks",
		Findings: findings,
	}, nil
}

func (s *GitleaksGitScanner) ScanGitHistory(ctx context.Context, repoPath string) (*GitHistoryScanResult, error) {
	if strings.TrimSpace(s.binaryPath) == "" {
		return nil, fmt.Errorf("gitleaks binary path is required")
	}
	repoPath = strings.TrimSpace(repoPath)
	if repoPath == "" {
		return nil, fmt.Errorf("repository path is required")
	}
	if strings.ContainsAny(repoPath, "\r\n") {
		return nil, fmt.Errorf("repository path must not contain newlines")
	}
	absPath, err := filepath.Abs(repoPath)
	if err != nil {
		return nil, fmt.Errorf("resolve repository path %s: %w", repoPath, err)
	}

	cmd := exec.CommandContext(
		ctx,
		s.binaryPath,
		"git",
		"--no-banner",
		"--log-level", "error",
		"--exit-code", "0",
		"--report-format", "json",
		"--report-path", "-",
		absPath,
	) // #nosec G204 -- fixed binary/arguments, no shell interpolation
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("gitleaks git scan stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("gitleaks git scan failed to start: %w", err)
	}
	result, err := parseGitleaksGitReport(stdout, s.maxReportBytes, s.maxFindings)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if stderrText := strings.TrimSpace(stderr.String()); stderrText != "" {
			return nil, fmt.Errorf("%w: %s", err, stderrText)
		}
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		stderrText := strings.TrimSpace(stderr.String())
		if stderrText != "" {
			return nil, fmt.Errorf("gitleaks git scan failed: %s", stderrText)
		}
		return nil, fmt.Errorf("gitleaks git scan failed: %w", err)
	}
	return result, nil
}

type gitleaksFinding struct {
	RuleID      string
	Description string
	StartLine   int
	Match       string
	Secret      string
	File        string
	Fingerprint string
	Commit      string
	Author      string
	Email       string
	Date        string
	Verified    bool
}

func parseGitleaksOutput(data []byte) ([]SecretFinding, error) {
	return parseGitleaksReport(bytes.NewReader(data), int64(len(data))+1, defaultGitleaksMaxFindings)
}

func parseGitleaksGitOutput(data []byte) (*GitHistoryScanResult, error) {
	return parseGitleaksGitReport(bytes.NewReader(data), int64(len(data))+1, defaultGitleaksMaxFindings)
}

func parseGitleaksReport(r io.Reader, maxReportBytes int64, maxFindings int) ([]SecretFinding, error) {
	if maxReportBytes <= 0 {
		return nil, fmt.Errorf("gitleaks max report bytes must be positive")
	}
	if maxFindings <= 0 {
		return nil, fmt.Errorf("gitleaks max findings must be positive")
	}
	limited := &io.LimitedReader{R: r, N: maxReportBytes + 1}
	decoder := json.NewDecoder(limited)

	token, err := decoder.Token()
	if err != nil {
		if err == io.EOF {
			return nil, nil
		}
		if limited.N <= 0 {
			return nil, fmt.Errorf("gitleaks report exceeded max size of %d bytes", maxReportBytes)
		}
		return nil, fmt.Errorf("parse gitleaks report: %w", err)
	}
	if token == nil {
		if limited.N <= 0 {
			return nil, fmt.Errorf("gitleaks report exceeded max size of %d bytes", maxReportBytes)
		}
		return nil, nil
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '[' {
		return nil, fmt.Errorf("parse gitleaks report: expected JSON array")
	}

	findings := make([]SecretFinding, 0)
	for decoder.More() {
		if len(findings) >= maxFindings {
			return nil, fmt.Errorf("gitleaks report exceeded max findings of %d", maxFindings)
		}
		var raw gitleaksFinding
		if err := decoder.Decode(&raw); err != nil {
			if limited.N <= 0 {
				return nil, fmt.Errorf("gitleaks report exceeded max size of %d bytes", maxReportBytes)
			}
			return nil, fmt.Errorf("parse gitleaks report: %w", err)
		}
		findings = append(findings, normalizeSecretFinding(convertGitleaksFinding(raw)))
	}
	if _, err := decoder.Token(); err != nil {
		if limited.N <= 0 {
			return nil, fmt.Errorf("gitleaks report exceeded max size of %d bytes", maxReportBytes)
		}
		return nil, fmt.Errorf("parse gitleaks report: %w", err)
	}
	if limited.N <= 0 {
		return nil, fmt.Errorf("gitleaks report exceeded max size of %d bytes", maxReportBytes)
	}
	return findings, nil
}

func parseGitleaksGitReport(r io.Reader, maxReportBytes int64, maxFindings int) (*GitHistoryScanResult, error) {
	rawFindings, err := parseRawGitleaksReport(r, maxReportBytes, maxFindings)
	if err != nil {
		return nil, err
	}
	result := &GitHistoryScanResult{
		Engine:   "gitleaks",
		Findings: make([]GitHistoryFinding, 0, len(rawFindings)),
	}
	for _, raw := range rawFindings {
		result.Findings = append(result.Findings, convertGitleaksGitFinding(raw))
	}
	return result, nil
}

func parseRawGitleaksReport(r io.Reader, maxReportBytes int64, maxFindings int) ([]gitleaksFinding, error) {
	if maxReportBytes <= 0 {
		return nil, fmt.Errorf("gitleaks max report bytes must be positive")
	}
	if maxFindings <= 0 {
		return nil, fmt.Errorf("gitleaks max findings must be positive")
	}
	limited := &io.LimitedReader{R: r, N: maxReportBytes + 1}
	decoder := json.NewDecoder(limited)

	token, err := decoder.Token()
	if err != nil {
		if err == io.EOF {
			return nil, nil
		}
		if limited.N <= 0 {
			return nil, fmt.Errorf("gitleaks report exceeded max size of %d bytes", maxReportBytes)
		}
		return nil, fmt.Errorf("parse gitleaks report: %w", err)
	}
	if token == nil {
		if limited.N <= 0 {
			return nil, fmt.Errorf("gitleaks report exceeded max size of %d bytes", maxReportBytes)
		}
		return nil, nil
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '[' {
		return nil, fmt.Errorf("parse gitleaks report: expected JSON array")
	}

	findings := make([]gitleaksFinding, 0)
	for decoder.More() {
		if len(findings) >= maxFindings {
			return nil, fmt.Errorf("gitleaks report exceeded max findings of %d", maxFindings)
		}
		var raw gitleaksFinding
		if err := decoder.Decode(&raw); err != nil {
			if limited.N <= 0 {
				return nil, fmt.Errorf("gitleaks report exceeded max size of %d bytes", maxReportBytes)
			}
			return nil, fmt.Errorf("parse gitleaks report: %w", err)
		}
		findings = append(findings, raw)
	}
	if _, err := decoder.Token(); err != nil {
		if limited.N <= 0 {
			return nil, fmt.Errorf("gitleaks report exceeded max size of %d bytes", maxReportBytes)
		}
		return nil, fmt.Errorf("parse gitleaks report: %w", err)
	}
	if limited.N <= 0 {
		return nil, fmt.Errorf("gitleaks report exceeded max size of %d bytes", maxReportBytes)
	}
	return findings, nil
}

func convertGitleaksFinding(f gitleaksFinding) SecretFinding {
	ruleType := normalizeGitleaksRuleID(f.RuleID)
	lineNo := f.StartLine
	if lineNo <= 0 {
		lineNo = 1
	}
	filePath := strings.TrimPrefix(strings.TrimSpace(f.File), "./")
	matchSource := firstNonEmpty(strings.TrimSpace(f.Secret), strings.TrimSpace(f.Match), strings.TrimSpace(f.Fingerprint), strings.TrimSpace(f.RuleID))
	description := strings.TrimSpace(f.Description)
	if description == "" {
		description = fmt.Sprintf("Potential secret detected by Gitleaks rule %s.", firstNonEmpty(strings.TrimSpace(f.RuleID), "unknown"))
	}
	converted := SecretFinding{
		Type:        ruleType,
		Severity:    gitleaksSeverity(ruleType),
		Path:        filePath,
		Line:        lineNo,
		Match:       fingerprintSecretMatch(matchSource),
		Description: description,
	}
	if ref, ok := secretReferenceFromExternalMatch(ruleType, firstNonEmpty(f.Secret, f.Match)); ok {
		converted.References = append(converted.References, ref)
	}
	return converted
}

func convertGitleaksGitFinding(f gitleaksFinding) GitHistoryFinding {
	base := normalizeSecretFinding(convertGitleaksFinding(f))
	converted := GitHistoryFinding{
		ID:          base.ID,
		Type:        base.Type,
		Severity:    base.Severity,
		Path:        base.Path,
		Line:        base.Line,
		Match:       base.Match,
		Description: base.Description,
		References:  append([]SecretReference(nil), base.References...),
		CommitSHA:   strings.TrimSpace(f.Commit),
		AuthorName:  strings.TrimSpace(f.Author),
		AuthorEmail: strings.TrimSpace(f.Email),
		Verified:    f.Verified,
		VerificationStatus: func() string {
			if f.Verified {
				return "verified_active"
			}
			return "unverified"
		}(),
	}
	if committedAt, ok := parseGitleaksTimestamp(f.Date); ok {
		converted.CommittedAt = &committedAt
	}
	return converted
}

func parseGitleaksTimestamp(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func normalizeGitleaksRuleID(ruleID string) string {
	candidate := sanitizeSecretType(ruleID)
	switch {
	case candidate == "aws":
		return "aws_access_key"
	case strings.Contains(candidate, "aws") && strings.Contains(candidate, "access"):
		return "aws_access_key"
	case strings.Contains(candidate, "github"):
		return "github_token"
	case strings.Contains(candidate, "gitlab"):
		return "gitlab_token"
	case strings.Contains(candidate, "npm"):
		return "npm_token"
	case strings.Contains(candidate, "slack"):
		return "slack_token"
	case strings.Contains(candidate, "stripe"):
		return "stripe_api_key"
	case strings.Contains(candidate, "twilio"):
		return "twilio_api_key"
	case strings.Contains(candidate, "sendgrid"):
		return "sendgrid_api_key"
	case strings.Contains(candidate, "mailgun"):
		return "mailgun_api_key"
	case strings.Contains(candidate, "jwt"):
		return "jwt_token"
	case strings.Contains(candidate, "docker"):
		return "docker_registry_credentials"
	case strings.Contains(candidate, "private_key"), strings.Contains(candidate, "private") && strings.Contains(candidate, "key"):
		return "private_key"
	case strings.Contains(candidate, "database"), strings.Contains(candidate, "connection"), strings.Contains(candidate, "jdbc"), strings.Contains(candidate, "mongodb"), strings.Contains(candidate, "postgres"), strings.Contains(candidate, "mysql"), strings.Contains(candidate, "redis"):
		return "database_connection_string"
	case candidate != "":
		return candidate
	default:
		return "external_secret"
	}
}

func gitleaksSeverity(secretType string) string {
	switch secretType {
	case "aws_access_key", "database_connection_string", "private_key", "gcp_service_account_key":
		return "critical"
	case "external_secret", "generic_api_key", "generic_credential", "high_entropy_string":
		return "medium"
	default:
		return "high"
	}
}

func secretReferenceFromExternalMatch(secretType, match string) (SecretReference, bool) {
	match = strings.TrimSpace(match)
	switch secretType {
	case "aws_access_key":
		if key := awsAccessKeyPattern.FindString(match); key != "" {
			return SecretReference{Kind: "cloud_identity", Provider: "aws", Identifier: strings.TrimSpace(key)}, true
		}
	case "database_connection_string":
		if ref, ok := parseDatabaseConnectionReference(match); ok {
			return ref, true
		}
	}
	return SecretReference{}, false
}
