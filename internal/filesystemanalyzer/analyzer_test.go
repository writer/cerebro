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

type stubMalwareScanner struct {
	result *scanner.MalwareScanResult
	err    error
}

func (s stubMalwareScanner) ScanData(context.Context, []byte, string) (*scanner.MalwareScanResult, error) {
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

func TestAnalyzerRecordsMalwareScannerErrors(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "bin", "payload.sh"), "#!/bin/sh\necho payload\n")

	clamav := filepath.Join(root, "clamscan")
	mustWriteFile(t, clamav, "#!/bin/sh\necho 'database missing' >&2\nexit 2\n")
	if err := os.Chmod(clamav, 0o755); err != nil {
		t.Fatalf("Chmod(%s): %v", clamav, err)
	}

	malwareScanner := scanner.NewMalwareScanner()
	malwareScanner.RegisterEngine(scanner.NewClamAVBinaryEngine(clamav))

	report, err := New(Options{MalwareScanner: malwareScanner}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	rawErrors, ok := report.Metadata["errors"]
	if !ok {
		t.Fatalf("expected malware scan metadata errors, got %#v", report.Metadata)
	}
	errors, ok := rawErrors.([]string)
	if !ok {
		t.Fatalf("expected []string metadata errors, got %T", rawErrors)
	}
	if len(errors) == 0 || !strings.Contains(strings.Join(errors, "\n"), "clamav binary scan failed: database missing") {
		t.Fatalf("expected malware scan error to surface, got %#v", errors)
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
	stripeKey := "sk_" + "live_" + strings.Repeat("1234abcd", 3)
	twilioKey := "SK" + strings.Repeat("01234567", 4)
	mustWriteFile(t, filepath.Join(root, "workspace", ".env"), strings.Join([]string{
		"GITLAB_TOKEN=glpat-1234567890abcdefghijklmn",
		"NPM_TOKEN=npm_1234567890abcdefghijklmnopqrstuvwxyz",
		"STRIPE_KEY=" + stripeKey,
		"TWILIO_KEY=" + twilioKey,
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

func TestAnalyzerDetectsExpandedCloudSecretFamiliesAndSkipsPlaceholders(t *testing.T) {
	root := t.TempDir()
	stripeKey := "sk_" + "live_" + strings.Repeat("1234abcd", 3)
	twilioKey := "SK" + strings.Repeat("01234567", 4)
	mustWriteFile(t, filepath.Join(root, "app", ".env"), strings.Join([]string{
		"STRIPE_SECRET_KEY=" + stripeKey,
		"SENDGRID_API_KEY=SG.abcdefghijklmnop.ABCDEFGHIJKLMNOP",
		"GCP_API_KEY=AIza12345678901234567890123456789012345",
		"GOOGLE_OAUTH_CLIENT_SECRET=GOCSPX-1234567890abcdefghijklmnop",
		"TWILIO_API_KEY=" + twilioKey,
		"AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=opsstore;AccountKey=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=;EndpointSuffix=core.windows.net",
		"JWT_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InN2Yy1hY2NvdW50IiwiZXhwIjoyMDAwMDAwMDAwfQ.c2lnbmF0dXJl",
		"API_KEY=${SECRET_VALUE}",
		"DATABASE_URL=postgresql://localhost:5432/appdb",
	}, "\n"))

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	types := make(map[string]SecretFinding, len(report.Secrets))
	for _, finding := range report.Secrets {
		types[finding.Type] = finding
	}

	for _, expected := range []string{
		"stripe_api_key",
		"sendgrid_api_key",
		"gcp_api_key",
		"google_oauth_client_secret",
		"twilio_api_key",
		"azure_storage_connection_string",
		"jwt_token",
	} {
		if _, ok := types[expected]; !ok {
			t.Fatalf("expected secret type %q, got %#v", expected, report.Secrets)
		}
	}

	if _, ok := types["database_connection_string"]; ok {
		t.Fatalf("expected credential-less database URL to be ignored, got %#v", report.Secrets)
	}
	if _, ok := types["inline_secret"]; ok {
		t.Fatalf("expected placeholder inline secret assignment to be ignored, got %#v", report.Secrets)
	}

	azureFinding := types["azure_storage_connection_string"]
	if len(azureFinding.References) != 1 {
		t.Fatalf("expected azure connection string reference, got %#v", azureFinding)
	}
	if azureFinding.References[0].Provider != "azure" || azureFinding.References[0].Identifier != "opsstore" {
		t.Fatalf("expected azure storage account reference, got %#v", azureFinding.References[0])
	}
}

func TestAnalyzerDoesNotMatchUppercaseTwilioLikeKeys(t *testing.T) {
	root := t.TempDir()
	twilioLikeValue := "SK" + strings.Repeat("ABCD", 8)
	mustWriteFile(t, filepath.Join(root, "app", ".env"), "TWILIO_API_KEY="+twilioLikeValue+"\n")

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	for _, finding := range report.Secrets {
		if finding.Type == "twilio_api_key" {
			t.Fatalf("expected uppercase Twilio-like value to be ignored, got %#v", finding)
		}
	}
}

func TestAnalyzerDetectsDatabaseURLWithCustomSecretQueryKey(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "app", ".env"), "DATABASE_URL=postgresql://db.internal:5432/appdb?client.secret=topsecret\n")

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	for _, finding := range report.Secrets {
		if finding.Type != "database_connection_string" {
			continue
		}
		if len(finding.References) != 1 {
			t.Fatalf("expected database reference, got %#v", finding)
		}
		if finding.References[0].Host != "db.internal" || finding.References[0].Database != "appdb" {
			t.Fatalf("expected parsed database reference, got %#v", finding.References[0])
		}
		return
	}
	t.Fatalf("expected database connection finding, got %#v", report.Secrets)
}

func TestAnalyzerDetectsJDBCSQLServerReferenceWhenLaterSecretFieldEmpty(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "app", ".env"), "DATABASE_URL=jdbc:sqlserver://db.internal:1433;databaseName=appdb;password=s3cr3t;token=\n")

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	for _, finding := range report.Secrets {
		if finding.Type != "database_connection_string" {
			continue
		}
		if len(finding.References) != 1 {
			t.Fatalf("expected sqlserver reference, got %#v", finding)
		}
		ref := finding.References[0]
		if ref.Host != "db.internal" || ref.Database != "appdb" || ref.Attributes["scheme"] != "sqlserver" {
			t.Fatalf("expected sqlserver reference metadata, got %#v", ref)
		}
		return
	}
	t.Fatalf("expected sqlserver database connection finding, got %#v", report.Secrets)
}
func TestInlineSecretValueHandlesQuotedValuesWithSemicolons(t *testing.T) {
	value, key := inlineSecretValue(`PASSWORD='secret;value';`)
	if key != "PASSWORD" {
		t.Fatalf("expected PASSWORD key, got %q", key)
	}
	if value != "secret;value" {
		t.Fatalf("expected semicolon-delimited secret value to remain intact, got %q", value)
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

func TestAnalyzerIncludesMalwareScannerResults(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "bin", "payload.sh"), "#!/bin/sh\necho infected\n")

	report, err := New(Options{
		MalwareScanner: stubMalwareScanner{result: &scanner.MalwareScanResult{
			Hash:        "sha256:feedface",
			Status:      scanner.ScanStatusMalicious,
			Malicious:   true,
			MalwareType: "signature_match",
			MalwareName: "Eicar-Test-Signature",
			Engine:      "clamav_binary",
			Confidence:  90,
		}},
	}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if report.Summary.MalwareCount != 1 {
		t.Fatalf("expected one malware finding, got %#v", report.Malware)
	}
	if len(report.Malware) != 1 {
		t.Fatalf("expected malware finding in report, got %#v", report.Malware)
	}
	malware := report.Malware[0]
	if malware.Path != "bin/payload.sh" || malware.Engine != "clamav_binary" {
		t.Fatalf("unexpected malware finding: %#v", malware)
	}
	found := false
	for _, finding := range report.Findings {
		if finding.Type == "malware" && strings.Contains(finding.Description, "Eicar-Test-Signature") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected malware container finding, got %#v", report.Findings)
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

func TestShouldMalwareScanUsesConfiguredMaxBytes(t *testing.T) {
	size := defaultMaxMalwareBytes + 1
	if shouldMalwareScan("workspace/payload.sh", 0o755, size, defaultMaxMalwareBytes) {
		t.Fatalf("expected file larger than default cap to be skipped")
	}
	if !shouldMalwareScan("workspace/payload.sh", 0o755, size, defaultMaxMalwareBytes+1024) {
		t.Fatalf("expected configured malware byte cap to allow scan")
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
