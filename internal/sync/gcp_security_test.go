package sync

import (
	"testing"
	"time"

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
