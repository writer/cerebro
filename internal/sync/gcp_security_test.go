package sync

import (
	"testing"

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
