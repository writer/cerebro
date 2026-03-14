package filesystemanalyzer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evalops/cerebro/internal/scanner"
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

type stubSecretScanner struct {
	result *SecretScanResult
	err    error
}

func (s stubSecretScanner) ScanFilesystem(context.Context, string) (*SecretScanResult, error) {
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

func TestAnalyzerDetectsExpandedSecretPatternsAndDockerRegistryCredentials(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "workspace", ".env"), strings.Join([]string{
		"GITLAB_TOKEN=glpat-1234567890abcdefghijklmn",
		"NPM_TOKEN=npm_1234567890abcdefghijklmnopqrstuvwxyz",
		"STRIPE_KEY=sk_live_1234567890abcdefghijklmnop",
		"TWILIO_KEY=SK0123456789abcdef0123456789abcdef",
		"SENDGRID_KEY=SG.ABCDEFGHIJKLMNOP.QRSTUVWXYZabcdefghi",
		"MAILGUN_KEY=key-0123456789abcdef0123456789abcdef",
		"JWT_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWV9.c2lnbmF0dXJlLXNlY3JldC12YWx1ZQ",
	}, "\n"))
	mustWriteFile(t, filepath.Join(root, "root", ".docker", "config.json"), `{
		"auths": {
			"https://123456789012.dkr.ecr.us-east-1.amazonaws.com": {
				"auth": "ZWNydXNlcjpTdXBlclNlY3JldFBhc3M="
			}
		}
	}`)

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	byType := make(map[string]SecretFinding, len(report.Secrets))
	for _, finding := range report.Secrets {
		byType[finding.Type] = finding
	}
	for _, kind := range []string{
		"gitlab_token",
		"npm_token",
		"stripe_api_key",
		"twilio_api_key",
		"sendgrid_api_key",
		"mailgun_api_key",
		"jwt_token",
		"docker_registry_credentials",
	} {
		if _, ok := byType[kind]; !ok {
			t.Fatalf("expected secret finding %q, got %#v", kind, report.Secrets)
		}
	}

	dockerFinding := byType["docker_registry_credentials"]
	if len(dockerFinding.References) != 1 {
		t.Fatalf("expected docker registry reference, got %#v", dockerFinding)
	}
	ref := dockerFinding.References[0]
	if ref.Provider != "aws" || ref.Host != "123456789012.dkr.ecr.us-east-1.amazonaws.com" {
		t.Fatalf("expected ECR reference metadata, got %#v", ref)
	}
	if ref.Attributes["username"] != "ecruser" {
		t.Fatalf("expected docker username extraction, got %#v", ref.Attributes)
	}
	if strings.Contains(dockerFinding.Match, "SuperSecretPass") {
		t.Fatalf("expected docker credential to be redacted, got %#v", dockerFinding)
	}
}

func TestAnalyzerMergesExternalSecretScannerResultsWithoutDuplicates(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "workspace", ".env"), "GITHUB_TOKEN=ghp_1234567890abcdefghijklmn\n")

	report, err := New(Options{
		SecretScanner: stubSecretScanner{result: &SecretScanResult{
			Engine: "stub",
			Findings: []SecretFinding{{
				Type:     "github_token",
				Severity: "high",
				Path:     "workspace/.env",
				Line:     1,
				Match:    fingerprintSecretMatch("ghp_1234567890abcdefghijklmn"),
			}},
		}},
	}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if report.Metadata["secret_scan_engine"] != "stub" {
		t.Fatalf("expected secret scan engine metadata, got %#v", report.Metadata)
	}
	count := 0
	for _, finding := range report.Secrets {
		if finding.Type == "github_token" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected deduped github token finding, got %#v", report.Secrets)
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

func TestAnalyzerDetectsIaCArtifactsAndMisconfigurations(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "infra", "main.tf"), strings.Join([]string{
		`resource "aws_security_group" "public" {`,
		`  ingress {`,
		`    cidr_blocks = ["0.0.0.0/0"]`,
		`  }`,
		`}`,
		`resource "aws_s3_bucket" "logs" {`,
		`  bucket = "prod-logs"`,
		`}`,
	}, "\n"))
	mustWriteFile(t, filepath.Join(root, "infra", "terraform.tfstate"), `{"version":4,"terraform_version":"1.8.0","resources":[{"type":"aws_s3_bucket","name":"logs"}]}`)
	mustWriteFile(t, filepath.Join(root, "deploy", "service.yaml"), "apiVersion: v1\nkind: Service\nmetadata:\n  name: api\n")
	mustWriteFile(t, filepath.Join(root, "app", ".env"), "DATABASE_PASSWORD=super-secret-password\n")

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if report.Summary.IaCArtifactCount != 4 {
		t.Fatalf("expected four IaC/config artifacts, got %#v", report.IaCArtifacts)
	}

	artifactTypes := make(map[string]IaCArtifact, len(report.IaCArtifacts))
	for _, artifact := range report.IaCArtifacts {
		artifactTypes[artifact.Type] = artifact
	}
	for _, kind := range []string{"terraform", "terraform_state", "kubernetes_manifest", "environment_file"} {
		if _, ok := artifactTypes[kind]; !ok {
			t.Fatalf("expected artifact %q, got %#v", kind, report.IaCArtifacts)
		}
	}

	findingTypes := make(map[string]ConfigFinding, len(report.Misconfigurations))
	for _, finding := range report.Misconfigurations {
		findingTypes[finding.Type] = finding
	}
	if finding, ok := findingTypes["terraform_state"]; !ok {
		t.Fatalf("expected terraform_state finding, got %#v", report.Misconfigurations)
	} else if finding.ArtifactType != "terraform_state" || finding.ResourceType != "terraform_state" {
		t.Fatalf("expected terraform_state metadata, got %#v", finding)
	}
	if _, ok := findingTypes["iac_public_exposure"]; !ok {
		t.Fatalf("expected public exposure finding, got %#v", report.Misconfigurations)
	}
	if finding, ok := findingTypes["iac_missing_bucket_encryption"]; !ok {
		t.Fatalf("expected missing bucket encryption finding, got %#v", report.Misconfigurations)
	} else if finding.ResourceType != "bucket" {
		t.Fatalf("expected bucket resource type, got %#v", finding)
	}

	foundMisconfigFinding := false
	for _, finding := range report.Findings {
		if finding.Type == "misconfiguration" && strings.Contains(strings.ToLower(finding.Title), "terraform state") {
			foundMisconfigFinding = true
			break
		}
	}
	if !foundMisconfigFinding {
		t.Fatalf("expected terraform state finding in container findings, got %#v", report.Findings)
	}
}

func TestAnalyzerDoesNotFlagBucketEncryptionForHelmValuesReference(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "charts", "api", "values.yaml"), strings.Join([]string{
		"# terraform module provisions aws_s3_bucket elsewhere",
		"bucketName: app-logs",
	}, "\n"))

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	foundHelmValues := false
	for _, artifact := range report.IaCArtifacts {
		if artifact.Type == "helm_values" {
			foundHelmValues = true
			break
		}
	}
	if !foundHelmValues {
		t.Fatalf("expected helm_values artifact, got %#v", report.IaCArtifacts)
	}

	for _, finding := range report.Misconfigurations {
		if finding.Type == "iac_missing_bucket_encryption" {
			t.Fatalf("expected no bucket encryption finding for Helm values reference, got %#v", report.Misconfigurations)
		}
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
