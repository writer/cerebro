package sync

import (
	"testing"
	"time"

	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"strings"

	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"github.com/evalops/cerebro/internal/snowflake"
	"github.com/evalops/cerebro/internal/warehouse"
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestClassifyCloudKeySignals(t *testing.T) {
	secret := &grafeaspb.SecretOccurrence{
		Kind: grafeaspb.SecretKind_SECRET_KIND_GCP_SERVICE_ACCOUNT_KEY,
		Statuses: []*grafeaspb.SecretStatus{
			{
				Status:     grafeaspb.SecretStatus_VALID,
				Message:    "Valid key grants admin access in other project",
				UpdateTime: timestamppb.Now(),
			},
		},
	}

	isCloudKey, highPrivilege, crossAccount := classifyCloudKeySignals(secret)
	if !isCloudKey {
		t.Fatal("expected cloud key to be detected")
	}
	if !highPrivilege {
		t.Fatal("expected high privilege signal")
	}
	if !crossAccount {
		t.Fatal("expected cross-account signal")
	}
}

func TestClassifyCloudKeySignalsNonCloudKey(t *testing.T) {
	secret := &grafeaspb.SecretOccurrence{
		Kind: grafeaspb.SecretKind_SECRET_KIND_OPENAI_API_KEY,
		Statuses: []*grafeaspb.SecretStatus{
			{Status: grafeaspb.SecretStatus_VALID},
		},
	}

	isCloudKey, highPrivilege, crossAccount := classifyCloudKeySignals(secret)
	if isCloudKey || highPrivilege || crossAccount {
		t.Fatalf("expected non-cloud key to return false signals, got cloud=%v high=%v cross=%v", isCloudKey, highPrivilege, crossAccount)
	}
}

func TestNormalizeArtifactImageURI(t *testing.T) {
	raw := "https://us-docker.pkg.dev/writer-sa-dev/app/repo@sha256:abc123/"
	got := normalizeArtifactImageURI(raw)
	want := "us-docker.pkg.dev/writer-sa-dev/app/repo@sha256:abc123"
	if got != want {
		t.Fatalf("normalizeArtifactImageURI() = %q, want %q", got, want)
	}
}

func TestSerializeSecretStatuses(t *testing.T) {
	statuses := serializeSecretStatuses([]*grafeaspb.SecretStatus{
		{
			Status:     grafeaspb.SecretStatus_VALID,
			Message:    "valid",
			UpdateTime: timestamppb.Now(),
		},
	})

	if len(statuses) != 1 {
		t.Fatalf("expected 1 status row, got %d", len(statuses))
	}
	if statuses[0]["status"] != "VALID" {
		t.Fatalf("expected status VALID, got %v", statuses[0]["status"])
	}
	if statuses[0]["message"] != "valid" {
		t.Fatalf("expected message to be serialized, got %v", statuses[0]["message"])
	}
}

func TestClassifyImageScanStatus(t *testing.T) {
	if scanned, status := classifyImageScanStatus(grafeaspb.DiscoveryOccurrence_ANALYSIS_STATUS_UNSPECIFIED); scanned || status != "UNSCANNED" {
		t.Fatalf("expected unspecified status to be unscanned, got scanned=%v status=%q", scanned, status)
	}

	scanned, status := classifyImageScanStatus(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS)
	if !scanned {
		t.Fatalf("expected FINISHED_SUCCESS to be scanned")
	}
	if status == "UNSCANNED" {
		t.Fatalf("expected concrete scan status for finished success")
	}
}

func TestShouldReplaceScanSignal(t *testing.T) {
	now := time.Now()
	existing := artifactImageScanSignal{Scanned: false, ScanStatus: "UNSCANNED", UpdatedAt: now}
	candidate := artifactImageScanSignal{Scanned: true, ScanStatus: "FINISHED_SUCCESS", UpdatedAt: now.Add(-time.Minute)}
	if !shouldReplaceScanSignal(existing, candidate) {
		t.Fatalf("expected scanned candidate to replace unscanned existing signal")
	}

	existing = artifactImageScanSignal{Scanned: true, ScanStatus: "FINISHED_SUCCESS", UpdatedAt: now}
	candidate = artifactImageScanSignal{Scanned: false, ScanStatus: "SCANNING", UpdatedAt: now.Add(-time.Minute)}
	if shouldReplaceScanSignal(existing, candidate) {
		t.Fatalf("did not expect older unscanned candidate to replace scanned existing signal")
	}
}

func TestDetectContainerRegistryType(t *testing.T) {
	if got := detectContainerRegistryType("us.gcr.io/writer/app/image@sha256:abc"); got != "gcr" {
		t.Fatalf("expected gcr, got %q", got)
	}
	if got := detectContainerRegistryType("us-docker.pkg.dev/writer/app/image@sha256:abc"); got != "artifact_registry" {
		t.Fatalf("expected artifact_registry, got %q", got)
	}
	if got := detectContainerRegistryType("docker.io/library/nginx:latest"); got != "unknown" {
		t.Fatalf("expected unknown, got %q", got)
	}
}

func TestIsOpenSSLCVE(t *testing.T) {
	if !isOpenSSLCVE("CVE-2022-3602") {
		t.Fatal("expected CVE-2022-3602 to be classified as OpenSSL CVE")
	}
	if !isOpenSSLCVE("cve-2022-3786") {
		t.Fatal("expected CVE-2022-3786 to be classified as OpenSSL CVE")
	}
	if isOpenSSLCVE("CVE-2023-1234") {
		t.Fatal("did not expect unrelated CVE to be classified as OpenSSL CVE")
	}
}

func TestAppendUniqueString(t *testing.T) {
	values := []string{"A", "B"}
	values = appendUniqueString(values, "B")
	values = appendUniqueString(values, "C")

	if len(values) != 3 {
		t.Fatalf("expected 3 unique values, got %d", len(values))
	}
	if values[2] != "C" {
		t.Fatalf("expected appended unique value C, got %q", values[2])
	}
}

func TestUpsertVulnerabilitiesAggregatesInsertErrors(t *testing.T) {
	store := &warehouse.MemoryWarehouse{
		QueryFunc: func(_ context.Context, query string, _ ...any) (*snowflake.QueryResult, error) {
			if !strings.Contains(query, "CREATE TABLE IF NOT EXISTS GCP_CONTAINER_VULNERABILITIES") {
				t.Fatalf("unexpected query %q", query)
			}
			return &snowflake.QueryResult{}, nil
		},
		ExecFunc: func(_ context.Context, query string, args ...any) (sql.Result, error) {
			if strings.Contains(query, "INSERT INTO GCP_CONTAINER_VULNERABILITIES") {
				return warehouseResult(0), errors.New("insert failed")
			}
			return warehouseResult(0), nil
		},
	}
	syncer := NewGCPSecuritySync(store, slog.New(slog.NewTextHandler(io.Discard, nil)), "project-a", "")

	err := syncer.upsertVulnerabilities(context.Background(), []map[string]interface{}{
		{
			"_cq_id":        "occ-1",
			"project_id":    "project-a",
			"name":          "occ-1",
			"resource_uri":  "gcr.io/project/image@sha256:abc",
			"severity":      "HIGH",
			"cve_id":        "CVE-2024-1234",
			"fix_available": true,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "insert vulnerabilities") {
		t.Fatalf("expected aggregated insert error, got %v", err)
	}
}

func TestUpsertDockerImagesAddsCompatibilityColumns(t *testing.T) {
	store := &warehouse.MemoryWarehouse{
		QueryFunc: func(_ context.Context, query string, _ ...any) (*snowflake.QueryResult, error) {
			if !strings.Contains(query, "CREATE TABLE IF NOT EXISTS GCP_ARTIFACT_REGISTRY_IMAGES") {
				t.Fatalf("unexpected query %q", query)
			}
			return &snowflake.QueryResult{}, nil
		},
	}
	syncer := NewGCPSecuritySync(store, slog.New(slog.NewTextHandler(io.Discard, nil)), "project-a", "")

	err := syncer.upsertDockerImages(context.Background(), []map[string]interface{}{
		{
			"_cq_id":                        "image-1",
			"project_id":                    "project-a",
			"name":                          "image-1",
			"uri":                           "us-docker.pkg.dev/project-a/repo/image@sha256:abc",
			"registry_type":                 "artifact_registry",
			"scanned":                       true,
			"scan_status":                   "FINISHED_SUCCESS",
			"vulnerabilities":               "[\"CVE-2022-3602\"]",
			"has_vulnerabilities":           true,
			"has_openssl_vulnerability":     true,
			"secrets":                       "[]",
			"has_cloud_keys":                false,
			"has_high_privilege_cloud_keys": false,
			"has_cross_account_cloud_keys":  false,
		},
	})
	if err != nil {
		t.Fatalf("upsertDockerImages returned error: %v", err)
	}

	alterCount := 0
	insertCount := 0
	for _, call := range store.Execs {
		if strings.HasPrefix(call.Statement, "ALTER TABLE GCP_ARTIFACT_REGISTRY_IMAGES ADD COLUMN IF NOT EXISTS") {
			alterCount++
		}
		if strings.Contains(call.Statement, "INSERT INTO GCP_ARTIFACT_REGISTRY_IMAGES") {
			insertCount++
		}
	}
	if alterCount != 10 {
		t.Fatalf("expected 10 compatibility alter statements, got %d", alterCount)
	}
	if insertCount != 1 {
		t.Fatalf("expected 1 image insert, got %d", insertCount)
	}
}

func TestUpsertSCCFindingsPersistsFindings(t *testing.T) {
	store := &warehouse.MemoryWarehouse{
		QueryFunc: func(_ context.Context, query string, _ ...any) (*snowflake.QueryResult, error) {
			if !strings.Contains(query, "CREATE TABLE IF NOT EXISTS GCP_SCC_FINDINGS") {
				t.Fatalf("unexpected query %q", query)
			}
			return &snowflake.QueryResult{}, nil
		},
	}
	syncer := NewGCPSecuritySync(store, slog.New(slog.NewTextHandler(io.Discard, nil)), "project-a", "123456")

	err := syncer.upsertSCCFindings(context.Background(), []map[string]interface{}{
		{
			"_cq_id":        "finding-1",
			"project_id":    "project-a",
			"name":          "finding-1",
			"parent":        "organizations/123456/sources/1",
			"resource_name": "//cloudresourcemanager.googleapis.com/projects/project-a",
			"severity":      "HIGH",
		},
	})
	if err != nil {
		t.Fatalf("upsertSCCFindings returned error: %v", err)
	}

	var sawDelete, sawInsert bool
	for _, call := range store.Execs {
		if strings.Contains(call.Statement, "DELETE FROM GCP_SCC_FINDINGS WHERE PROJECT_ID = ?") {
			sawDelete = true
		}
		if strings.Contains(call.Statement, "INSERT INTO GCP_SCC_FINDINGS") {
			sawInsert = true
		}
	}
	if !sawDelete || !sawInsert {
		t.Fatalf("expected delete and insert for SCC findings, execs=%#v", store.Execs)
	}
}

func TestSecurityFormattingHelpers(t *testing.T) {
	if got := extractCVEFromNote("projects/goog-vulnz/notes/CVE-2024-1234"); got != "CVE-2024-1234" {
		t.Fatalf("unexpected cve id %q", got)
	}
	if got := formatPackageIssues([]*grafeaspb.VulnerabilityOccurrence_PackageIssue{{
		AffectedPackage: "openssl",
		AffectedVersion: &grafeaspb.Version{FullName: "1.1.1"},
		FixedVersion:    &grafeaspb.Version{FullName: "1.1.1w"},
	}}); !strings.Contains(got, "openssl@1.1.1 (fix: 1.1.1w)") {
		t.Fatalf("unexpected package issue summary %q", got)
	}
	if got := formatIndicator(&securitycenterpb.Indicator{IpAddresses: []string{"1.2.3.4"}, Domains: []string{"example.com"}}); got != "ip:1.2.3.4,domain:example.com" {
		t.Fatalf("unexpected indicator format %q", got)
	}
	if got := formatVulnerability(&securitycenterpb.Vulnerability{
		Cve: &securitycenterpb.Cve{
			Id:     "CVE-2024-1234",
			Cvssv3: &securitycenterpb.Cvssv3{BaseScore: 9.8},
		},
	}); !strings.Contains(got, "CVE-2024-1234") {
		t.Fatalf("unexpected vulnerability format %q", got)
	}
	if got := toStr(42); got != "42" {
		t.Fatalf("unexpected toStr output %q", got)
	}
}
