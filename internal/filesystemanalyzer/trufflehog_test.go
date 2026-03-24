package filesystemanalyzer

import (
	"context"
	"testing"
)

type stubGitHistoryScanner struct {
	result *GitHistoryScanResult
	err    error
}

func (s stubGitHistoryScanner) ScanGitHistory(context.Context, string) (*GitHistoryScanResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}

func TestParseTruffleHogGitOutputIncludesVerificationStatusAndAuthor(t *testing.T) {
	raw := []byte(`{"SourceMetadata":{"Data":{"Git":{"commit":"fbc14303ffbf8fb1c2c1914e8dda7d0121633aca","file":"keys","email":"Alice Example <alice@example.com>","repository":"https://github.com/acme/platform","timestamp":"2026-03-16 10:17:40 -0700 PDT","line":4}}},"DetectorName":"AWS","Verified":true,"Raw":"AKIAYVP4CIPPERUVIFXG","Redacted":"AKIAYVP4CIPPERUVIFXG"}
{"SourceMetadata":{"Data":{"Git":{"commit":"beadedbeadedbeadedbeadedbeadedbeadedbe","file":"config/.env","email":"bob@example.com","repository":"https://github.com/acme/platform","timestamp":"2025-12-01 08:15:00 +0000 UTC","line":9}}},"DetectorName":"GitHub","Verified":false,"Raw":"ghp_1234567890abcdefghijklmn","Redacted":"ghp_1234567890abcdefghijklmn"}
`)

	result, err := parseTruffleHogGitOutput(raw)
	if err != nil {
		t.Fatalf("parseTruffleHogGitOutput: %v", err)
	}
	if result == nil || result.Engine != "trufflehog" {
		t.Fatalf("expected trufflehog engine, got %#v", result)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected two findings, got %#v", result)
	}

	verified := result.Findings[0]
	if verified.Type != "aws_access_key" {
		t.Fatalf("expected aws_access_key type, got %#v", verified)
	}
	if verified.CommitSHA != "fbc14303ffbf8fb1c2c1914e8dda7d0121633aca" {
		t.Fatalf("expected commit metadata, got %#v", verified)
	}
	if verified.AuthorName != "Alice Example" || verified.AuthorEmail != "alice@example.com" {
		t.Fatalf("expected author metadata, got %#v", verified)
	}
	if verified.VerificationStatus != "verified_active" || !verified.Verified {
		t.Fatalf("expected verified_active status, got %#v", verified)
	}
	if verified.CommittedAt == nil {
		t.Fatalf("expected committed_at timestamp, got %#v", verified)
	}

	rotated := result.Findings[1]
	if rotated.Type != "github_token" {
		t.Fatalf("expected github_token type, got %#v", rotated)
	}
	if rotated.VerificationStatus != "rotated" {
		t.Fatalf("expected rotated verification status, got %#v", rotated)
	}
	if rotated.AuthorName != "bob@example.com" || rotated.AuthorEmail != "bob@example.com" {
		t.Fatalf("expected email fallback author parsing, got %#v", rotated)
	}
}

func TestCompositeGitHistoryScannerMergesDuplicateFindingsAcrossEngines(t *testing.T) {
	composite := NewCompositeGitHistoryScanner(
		stubGitHistoryScanner{result: &GitHistoryScanResult{
			Engine: "gitleaks",
			Findings: []GitHistoryFinding{{
				ID:                 "gitleaks-1",
				Type:               "aws_access_key",
				Severity:           "high",
				Path:               "keys.env",
				Line:               4,
				Match:              "sha256:deadbeef",
				CommitSHA:          "abc123",
				AuthorName:         "Alice",
				AuthorEmail:        "alice@example.com",
				VerificationStatus: "unverified",
			}},
		}},
		stubGitHistoryScanner{result: &GitHistoryScanResult{
			Engine: "trufflehog",
			Findings: []GitHistoryFinding{
				{
					ID:                 "trufflehog-1",
					Type:               "aws_access_key",
					Severity:           "critical",
					Path:               "keys.env",
					Line:               4,
					Match:              "sha256:deadbeef",
					CommitSHA:          "abc123",
					AuthorName:         "Alice Example",
					AuthorEmail:        "alice@example.com",
					Verified:           true,
					VerificationStatus: "verified_active",
				},
				{
					ID:                 "trufflehog-2",
					Type:               "github_token",
					Severity:           "high",
					Path:               "config/.env",
					Line:               9,
					Match:              "sha256:cafebabe",
					CommitSHA:          "def456",
					AuthorEmail:        "bob@example.com",
					VerificationStatus: "rotated",
				},
			},
		}},
	)

	result, err := composite.ScanGitHistory(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("ScanGitHistory: %v", err)
	}
	if result == nil || result.Engine != "gitleaks+trufflehog" {
		t.Fatalf("expected merged engine label, got %#v", result)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected duplicate findings to merge, got %#v", result.Findings)
	}

	merged := result.Findings[0]
	if merged.Type != "aws_access_key" {
		t.Fatalf("expected merged aws finding first, got %#v", merged)
	}
	if !merged.Verified || merged.VerificationStatus != "verified_active" {
		t.Fatalf("expected verified_active finding to win merge, got %#v", merged)
	}
	if merged.AuthorName != "Alice Example" {
		t.Fatalf("expected richer author metadata to be retained, got %#v", merged)
	}

	rotated := result.Findings[1]
	if rotated.VerificationStatus != "rotated" {
		t.Fatalf("expected rotated finding to be retained, got %#v", rotated)
	}
}
