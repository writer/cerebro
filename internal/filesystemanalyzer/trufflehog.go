package filesystemanalyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type TruffleHogGitScanner struct {
	binaryPath     string
	maxReportBytes int64
	maxFindings    int
}

type CompositeGitHistoryScanner struct {
	scanners []GitHistoryScanner
}

func NewTruffleHogGitScanner(binaryPath string) *TruffleHogGitScanner {
	if strings.TrimSpace(binaryPath) == "" {
		binaryPath = "trufflehog"
	}
	return &TruffleHogGitScanner{
		binaryPath:     binaryPath,
		maxReportBytes: defaultGitleaksMaxReportBytes,
		maxFindings:    defaultGitleaksMaxFindings,
	}
}

func NewCompositeGitHistoryScanner(scanners ...GitHistoryScanner) *CompositeGitHistoryScanner {
	filtered := make([]GitHistoryScanner, 0, len(scanners))
	for _, scanner := range scanners {
		if scanner != nil {
			filtered = append(filtered, scanner)
		}
	}
	return &CompositeGitHistoryScanner{scanners: filtered}
}

func (s *TruffleHogGitScanner) ScanGitHistory(ctx context.Context, repoPath string) (*GitHistoryScanResult, error) {
	if strings.TrimSpace(s.binaryPath) == "" {
		return nil, fmt.Errorf("trufflehog binary path is required")
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
	repoURL := (&url.URL{Scheme: "file", Path: absPath}).String()

	cmd := exec.CommandContext(
		ctx,
		s.binaryPath,
		"git",
		repoURL,
		"--json",
		"--results=verified,unknown",
	) // #nosec G204 -- fixed binary/arguments, no shell interpolation
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("trufflehog git scan stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("trufflehog git scan failed to start: %w", err)
	}
	result, err := parseTruffleHogGitReport(stdout, s.maxReportBytes, s.maxFindings)
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
			return nil, fmt.Errorf("trufflehog git scan failed: %s", stderrText)
		}
		return nil, fmt.Errorf("trufflehog git scan failed: %w", err)
	}
	return result, nil
}

func (s *CompositeGitHistoryScanner) ScanGitHistory(ctx context.Context, repoPath string) (*GitHistoryScanResult, error) {
	result := &GitHistoryScanResult{}
	if len(s.scanners) == 0 {
		return result, nil
	}

	engines := make([]string, 0, len(s.scanners))
	merged := make([]GitHistoryFinding, 0)
	indexByKey := make(map[string]int)
	for _, scanner := range s.scanners {
		scanResult, err := scanner.ScanGitHistory(ctx, repoPath)
		if err != nil {
			return nil, err
		}
		if scanResult == nil {
			continue
		}
		if engine := strings.TrimSpace(scanResult.Engine); engine != "" {
			engines = append(engines, engine)
		}
		for _, finding := range scanResult.Findings {
			key := gitHistoryFindingMergeKey(finding)
			if idx, ok := indexByKey[key]; ok {
				merged[idx] = mergeGitHistoryFinding(merged[idx], finding)
				continue
			}
			indexByKey[key] = len(merged)
			merged = append(merged, finding)
		}
	}

	result.Engine = strings.Join(uniqueStringsInOrder(engines), "+")
	result.Findings = merged
	return result, nil
}

type truffleHogGitRecord struct {
	DetectorName   string `json:"DetectorName"`
	Verified       bool   `json:"Verified"`
	Raw            string `json:"Raw"`
	Redacted       string `json:"Redacted"`
	SourceMetadata struct {
		Data struct {
			Git struct {
				Commit     string `json:"commit"`
				File       string `json:"file"`
				Email      string `json:"email"`
				Repository string `json:"repository"`
				Timestamp  string `json:"timestamp"`
				Line       int    `json:"line"`
			} `json:"Git"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

func parseTruffleHogGitOutput(data []byte) (*GitHistoryScanResult, error) {
	return parseTruffleHogGitReport(bytes.NewReader(data), int64(len(data))+1, defaultGitleaksMaxFindings)
}

func parseTruffleHogGitReport(r io.Reader, maxReportBytes int64, maxFindings int) (*GitHistoryScanResult, error) {
	if maxReportBytes <= 0 {
		return nil, fmt.Errorf("trufflehog max report bytes must be positive")
	}
	if maxFindings <= 0 {
		return nil, fmt.Errorf("trufflehog max findings must be positive")
	}

	limited := &io.LimitedReader{R: r, N: maxReportBytes + 1}
	decoder := json.NewDecoder(limited)
	result := &GitHistoryScanResult{
		Engine:   "trufflehog",
		Findings: make([]GitHistoryFinding, 0),
	}
	for {
		var raw truffleHogGitRecord
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			if limited.N <= 0 {
				return nil, fmt.Errorf("trufflehog report exceeded max size of %d bytes", maxReportBytes)
			}
			return nil, fmt.Errorf("parse trufflehog report: %w", err)
		}
		if len(result.Findings) >= maxFindings {
			return nil, fmt.Errorf("trufflehog report exceeded max findings of %d", maxFindings)
		}
		result.Findings = append(result.Findings, convertTruffleHogGitFinding(raw))
	}
	if limited.N <= 0 {
		return nil, fmt.Errorf("trufflehog report exceeded max size of %d bytes", maxReportBytes)
	}
	return result, nil
}

func convertTruffleHogGitFinding(f truffleHogGitRecord) GitHistoryFinding {
	git := f.SourceMetadata.Data.Git
	secretType := normalizeGitleaksRuleID(f.DetectorName)
	lineNo := git.Line
	if lineNo <= 0 {
		lineNo = 1
	}
	description := fmt.Sprintf("Potential secret detected by TruffleHog detector %s.", firstNonEmpty(strings.TrimSpace(f.DetectorName), "unknown"))
	if f.Verified {
		description = fmt.Sprintf("Verified active secret detected by TruffleHog detector %s.", firstNonEmpty(strings.TrimSpace(f.DetectorName), "unknown"))
	}

	authorName, authorEmail := parseTruffleHogAuthor(git.Email)
	verificationStatus := "rotated"
	if f.Verified {
		verificationStatus = "verified_active"
	}
	converted := GitHistoryFinding{
		ID:                 secretFindingKey(normalizeSecretFinding(SecretFinding{Type: secretType, Path: strings.TrimPrefix(strings.TrimSpace(git.File), "./"), Line: lineNo, Match: fingerprintSecretMatch(firstNonEmpty(strings.TrimSpace(f.Redacted), strings.TrimSpace(f.Raw), strings.TrimSpace(f.DetectorName)))})),
		Type:               secretType,
		Severity:           gitleaksSeverity(secretType),
		Path:               strings.TrimPrefix(strings.TrimSpace(git.File), "./"),
		Line:               lineNo,
		Match:              fingerprintSecretMatch(firstNonEmpty(strings.TrimSpace(f.Redacted), strings.TrimSpace(f.Raw), strings.TrimSpace(f.DetectorName))),
		Description:        description,
		CommitSHA:          strings.TrimSpace(git.Commit),
		AuthorName:         authorName,
		AuthorEmail:        authorEmail,
		Verified:           f.Verified,
		VerificationStatus: verificationStatus,
	}
	if committedAt, ok := parseTruffleHogTimestamp(git.Timestamp); ok {
		converted.CommittedAt = &committedAt
	}
	if ref, ok := secretReferenceFromExternalMatch(secretType, firstNonEmpty(strings.TrimSpace(f.Raw), strings.TrimSpace(f.Redacted))); ok {
		converted.References = append(converted.References, ref)
	}
	return converted
}

func parseTruffleHogAuthor(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if start := strings.Index(raw, "<"); start >= 0 && strings.HasSuffix(raw, ">") {
		name := strings.TrimSpace(raw[:start])
		email := strings.TrimSpace(strings.TrimSuffix(raw[start+1:], ">"))
		if name == "" {
			name = email
		}
		return name, email
	}
	return raw, raw
}

func parseTruffleHogTimestamp(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{
		"2006-01-02 15:04:05 -0700 MST",
		time.RFC3339,
	} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func gitHistoryFindingMergeKey(finding GitHistoryFinding) string {
	return strings.Join([]string{
		strings.TrimSpace(finding.CommitSHA),
		strings.TrimSpace(finding.Path),
		fmt.Sprintf("%d", finding.Line),
		strings.TrimSpace(finding.Type),
		strings.TrimSpace(finding.Match),
	}, "|")
}

func mergeGitHistoryFinding(current, incoming GitHistoryFinding) GitHistoryFinding {
	merged := current
	if gitHistoryVerificationRank(incoming.VerificationStatus) > gitHistoryVerificationRank(merged.VerificationStatus) {
		merged.Verified = incoming.Verified
		merged.VerificationStatus = incoming.VerificationStatus
	}
	if gitHistorySeverityRank(incoming.Severity) > gitHistorySeverityRank(merged.Severity) {
		merged.Severity = incoming.Severity
	}
	if strings.TrimSpace(merged.AuthorEmail) == "" && strings.TrimSpace(incoming.AuthorEmail) != "" {
		merged.AuthorEmail = incoming.AuthorEmail
	}
	if strings.TrimSpace(merged.AuthorName) == "" || merged.AuthorName == merged.AuthorEmail {
		if strings.TrimSpace(incoming.AuthorName) != "" {
			merged.AuthorName = incoming.AuthorName
		}
	} else if strings.TrimSpace(incoming.AuthorName) != "" && len(strings.TrimSpace(incoming.AuthorName)) > len(strings.TrimSpace(merged.AuthorName)) {
		merged.AuthorName = incoming.AuthorName
	}
	if merged.CommittedAt == nil && incoming.CommittedAt != nil {
		ts := incoming.CommittedAt.UTC()
		merged.CommittedAt = &ts
	}
	if strings.TrimSpace(merged.Description) == "" && strings.TrimSpace(incoming.Description) != "" {
		merged.Description = incoming.Description
	}
	if len(merged.References) == 0 && len(incoming.References) > 0 {
		merged.References = append([]SecretReference(nil), incoming.References...)
	}
	return merged
}

func gitHistoryVerificationRank(status string) int {
	switch strings.TrimSpace(status) {
	case "verified_active":
		return 3
	case "rotated":
		return 2
	case "unverified":
		return 1
	default:
		return 0
	}
}

func gitHistorySeverityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func uniqueStringsInOrder(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
