package filesystemanalyzer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/scanner"
)

type stubFilesystemScanner struct {
	result *scanner.ContainerScanResult
	err    error
}

func (s stubFilesystemScanner) ScanFilesystem(context.Context, string) (*scanner.ContainerScanResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}

func TestAnalyzerCatalogsPackagesSecretsAndConfigs(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "etc", "os-release"), "ID=ubuntu\nNAME=Ubuntu\nPRETTY_NAME=Ubuntu 20.04 LTS\nVERSION_ID=20.04\n")
	mustWriteFile(t, filepath.Join(root, "var", "lib", "dpkg", "status"), "Package: openssl\nVersion: 3.0.2-0ubuntu1\n\nPackage: curl\nVersion: 7.81.0-1ubuntu1\n")
	mustWriteFile(t, filepath.Join(root, "workspace", "go.sum"), "github.com/google/uuid v1.6.0\ngolang.org/x/text v0.14.0/go.mod\n")
	mustWriteFile(t, filepath.Join(root, "srv", "app", "node_modules", "lodash", "package.json"), `{"name":"lodash","version":"4.17.20"}`)
	mustWriteFile(t, filepath.Join(root, "home", "user", ".env"), "DATABASE_PASSWORD=super-secret-password\n")
	mustWriteFile(t, filepath.Join(root, "etc", "ssh", "sshd_config"), "PermitRootLogin yes\nPasswordAuthentication yes\n")
	mustWriteFile(t, filepath.Join(root, "etc", "sudoers"), "user ALL=(ALL) NOPASSWD:ALL\n")
	suidPath := filepath.Join(root, "usr", "local", "bin", "helper")
	mustWriteFile(t, suidPath, "#!/bin/sh\necho helper\n")
	if err := os.Chmod(suidPath, 0o4755); err != nil {
		t.Fatalf("Chmod suid: %v", err)
	}

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if report.OS.ID != "ubuntu" || !report.OS.EOL {
		t.Fatalf("unexpected OS info: %#v", report.OS)
	}
	if report.Summary.PackageCount < 4 {
		t.Fatalf("expected package inventory, got %#v", report.Packages)
	}
	if report.Summary.SecretCount == 0 {
		t.Fatalf("expected secret findings, got %#v", report.Secrets)
	}
	if report.Summary.MisconfigurationCount < 3 {
		t.Fatalf("expected config findings, got %#v", report.Misconfigurations)
	}
	if report.SBOM.Format != "cyclonedx-json" || len(report.SBOM.Components) < 4 {
		t.Fatalf("unexpected sbom: %#v", report.SBOM)
	}
}

func TestAnalyzerIncludesVulnerabilityScannerResults(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "etc", "os-release"), "ID=alpine\nNAME=Alpine\nVERSION_ID=3.18\n")

	report, err := New(Options{VulnerabilityScanner: stubFilesystemScanner{result: &scanner.ContainerScanResult{
		OS:           "Alpine Linux",
		Architecture: "amd64",
		Vulnerabilities: []scanner.ImageVulnerability{{
			CVE:      "CVE-2026-0001",
			Severity: "high",
			Package:  "busybox",
		}},
		Findings: []scanner.ContainerFinding{{
			ID:       "vuln:CVE-2026-0001",
			Type:     "vulnerability",
			Severity: "high",
			Title:    "busybox vulnerability",
		}},
	}}}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if report.OS.Name != "Alpine Linux" || report.OS.Architecture != "amd64" {
		t.Fatalf("expected scanner OS hints to flow through, got %#v", report.OS)
	}
	if len(report.Vulnerabilities) != 1 || len(report.Findings) == 0 {
		t.Fatalf("expected vulnerability scanner results, got %#v %#v", report.Vulnerabilities, report.Findings)
	}
}

func TestDedupeVulnerabilitiesUsesIDWhenCVEIsMissing(t *testing.T) {
	vulns := dedupeVulnerabilities([]scanner.ImageVulnerability{
		{
			ID:               "GHSA-2026-0001",
			Package:          "busybox",
			InstalledVersion: "1.36.1-r0",
		},
		{
			ID:               "GHSA-2026-0002",
			Package:          "busybox",
			InstalledVersion: "1.36.1-r0",
		},
		{
			ID:               "GHSA-2026-0001",
			Package:          "busybox",
			InstalledVersion: "1.36.1-r0",
		},
	})
	if len(vulns) != 2 {
		t.Fatalf("expected distinct missing-CVE vulnerabilities to survive dedupe, got %#v", vulns)
	}
}

func TestAnalyzerRecordsUnreadableFileErrors(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "etc", "os-release"), "ID=ubuntu\nNAME=Ubuntu\nVERSION_ID=22.04\n")
	statusPath := filepath.Join(root, "var", "lib", "dpkg", "status")
	mustWriteFile(t, statusPath, "Package: openssl\nVersion: 3.0.2-0ubuntu1\n")
	if err := os.Chmod(statusPath, 0); err != nil {
		t.Fatalf("Chmod(%s): %v", statusPath, err)
	}
	defer func() {
		_ = os.Chmod(statusPath, 0o644)
	}()

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	rawErrors, ok := report.Metadata["errors"]
	if !ok {
		t.Fatalf("expected metadata errors, got %#v", report.Metadata)
	}
	errors, ok := rawErrors.([]string)
	if !ok {
		t.Fatalf("expected []string metadata errors, got %T", rawErrors)
	}
	found := false
	for _, entry := range errors {
		if strings.Contains(entry, "var/lib/dpkg/status") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected unreadable file error for dpkg status, got %#v", errors)
	}
}

func TestAnalyzerRedactsPersistedSecretMatches(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "home", "user", ".env"), strings.Join([]string{
		"AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
		"GITHUB_TOKEN=ghp_1234567890abcdefghijklmn",
		"PASSWORD=super-secret-password",
	}, "\n"))

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(report.Secrets) < 3 {
		t.Fatalf("expected secret findings, got %#v", report.Secrets)
	}
	for _, finding := range report.Secrets {
		if strings.Contains(finding.Match, "AKIA1234567890ABCDEF") ||
			strings.Contains(finding.Match, "ghp_1234567890abcdefghijklmn") ||
			strings.Contains(finding.Match, "super-secret-password") {
			t.Fatalf("expected redacted persisted match, got %#v", finding)
		}
		if finding.Type != "private_key" && finding.Match != "<redacted>" && !strings.HasPrefix(finding.Match, "sha256:") {
			t.Fatalf("expected fingerprinted match, got %#v", finding)
		}
	}
}

func TestAnalyzerExtractsResolvableSecretReferences(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "home", "user", ".env"), strings.Join([]string{
		"AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
		"DATABASE_URL=postgresql://app:secret@prod-db.internal:5432/appdb?sslmode=require",
		"MONGO_URL=mongodb+srv://app:secret@atlas-cluster.mongodb.net/appdb?retryWrites=true&w=majority",
	}, "\n"))
	mustWriteFile(t, filepath.Join(root, "var", "secrets", "gcp-key.json"), `{
		"type": "service_account",
		"private_key_id": "key-123",
		"client_email": "runtime-sa@proj-1.iam.gserviceaccount.com",
		"token_uri": "https://oauth2.googleapis.com/token"
	}`)

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	byType := make(map[string]SecretFinding, len(report.Secrets))
	var dbFindings []SecretFinding
	for _, finding := range report.Secrets {
		byType[finding.Type] = finding
		if finding.Type == "database_connection_string" {
			dbFindings = append(dbFindings, finding)
		}
	}

	awsFinding, ok := byType["aws_access_key"]
	if !ok || len(awsFinding.References) != 1 {
		t.Fatalf("expected aws_access_key reference, got %#v", awsFinding)
	}
	if got := awsFinding.References[0].Identifier; got != "AKIA1234567890ABCDEF" {
		t.Fatalf("expected aws access key identifier, got %q", got)
	}

	if len(dbFindings) != 2 {
		t.Fatalf("expected two database connection findings, got %#v", dbFindings)
	}
	foundPostgres := false
	foundMongo := false
	for _, finding := range dbFindings {
		for _, ref := range finding.References {
			if ref.Attributes["scheme"] == "postgresql" && ref.Host == "prod-db.internal" && ref.Database == "appdb" {
				foundPostgres = true
			}
			if ref.Attributes["scheme"] == "mongodb+srv" && ref.Host == "atlas-cluster.mongodb.net" && ref.Database == "appdb" {
				foundMongo = true
			}
		}
	}
	if !foundPostgres {
		t.Fatalf("expected postgresql reference, got %#v", dbFindings)
	}
	if !foundMongo {
		t.Fatalf("expected mongodb+srv reference, got %#v", dbFindings)
	}

	gcpFinding, ok := byType["gcp_service_account_key"]
	if !ok || len(gcpFinding.References) != 1 {
		t.Fatalf("expected gcp service account key reference, got %#v", gcpFinding)
	}
	if got := gcpFinding.References[0].Identifier; got != "runtime-sa@proj-1.iam.gserviceaccount.com" {
		t.Fatalf("expected gcp client_email reference, got %q", got)
	}
	if got := gcpFinding.References[0].Attributes["private_key_id"]; got != "key-123" {
		t.Fatalf("expected private_key_id key-123, got %q", got)
	}
}

func TestShouldSecretScanUsesConfiguredMaxBytes(t *testing.T) {
	size := defaultMaxSecretBytes + 1
	if shouldSecretScan("workspace/.env", 0, size, defaultMaxSecretBytes) {
		t.Fatalf("expected file larger than default cap to be skipped")
	}
	if !shouldSecretScan("workspace/.env", 0, size, defaultMaxSecretBytes+1024) {
		t.Fatalf("expected configured secret byte cap to allow scan")
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}
