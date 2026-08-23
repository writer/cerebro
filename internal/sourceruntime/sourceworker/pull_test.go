package sourceworker

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestPullSeparatesTerminalCheckpointFromSameRunContinuation(t *testing.T) {
	terminal := tailscaleOutput("", "user-1", 1_725_000_000_000)
	pull, err := PullFromExecutionOutput(terminal, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	if pull.NextCursor != nil {
		t.Fatalf("terminal NextCursor = %#v, want nil", pull.NextCursor)
	}
	providerCursor, watermark, err := ProviderResume(
		&cerebrov1.SourceCursor{Opaque: pull.Checkpoint.GetCursorOpaque()}, "tailscale", "user",
	)
	if err != nil {
		t.Fatal(err)
	}
	if providerCursor != "user-1" || watermark != 1_725_000_000_000 {
		t.Fatalf("restart = (%q, %d), want terminal cursor and watermark", providerCursor, watermark)
	}

	nonterminal := tailscaleOutput("page-2", "page-2", 1_725_000_001_000)
	pull, err = PullFromExecutionOutput(nonterminal, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	if pull.NextCursor.GetOpaque() != "page-2" {
		t.Fatalf("nonterminal NextCursor = %q, want page-2", pull.NextCursor.GetOpaque())
	}
	providerCursor, _, err = ProviderResume(
		&cerebrov1.SourceCursor{Opaque: pull.Checkpoint.GetCursorOpaque()}, "tailscale", "user",
	)
	if err != nil || providerCursor != "page-2" {
		t.Fatalf("nonterminal checkpoint = %q, %v", providerCursor, err)
	}
}

func TestProviderResumeFailsClosedForMalformedAndCrossFamilyCheckpoints(t *testing.T) {
	for name, cursor := range map[string]string{
		"malformed":    `{"version":1`,
		"cross family": `{"version":1,"source":"tailscale","family":"device","mode":"rust_provider_checkpoint","resumable_checkpoint":true,"token":"device-1"}`,
		"cross source": `{"version":1,"source":"other","family":"user","mode":"rust_provider_checkpoint","resumable_checkpoint":true,"token":"user-1"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := ProviderResume(&cerebrov1.SourceCursor{Opaque: cursor}, "tailscale", "user")
			if !errors.Is(err, ErrWorkerContract) {
				t.Fatalf("ProviderResume() error = %v, want ErrWorkerContract", err)
			}
		})
	}
}

func TestPublicExecutionConfigNeverCarriesCredentialMaterial(t *testing.T) {
	public := PublicExecutionConfig(map[string]string{
		"family": "user", "tailnet": "example.com", "base_url": "https://api.tailscale.com/api/v2",
		"token": "secret-token", "graph_token": "secret-graph-token", "tenant_id": "tenant-1",
	})
	if len(public) != 3 || public["token"] != "" || public["graph_token"] != "" || public["tenant_id"] != "" {
		t.Fatalf("public config leaked private fields: %#v", public)
	}
}

func tailscaleOutput(nextCursor, checkpointCursor string, watermark int64) *ExecutionOutput {
	plan := &cerebrov1.SourceExecutionPlanV1{SourceId: "tailscale", FamilyId: "user", EventKind: "tailscale.user", SchemaRef: "tailscale/user/v1"}
	record := &cerebrov1.SourceWorkerRecordV1{
		ProviderId: "user-1", EventId: "tailscale-tenant-1-user-user-1", OccurredAtUnixMillis: watermark,
		Attributes:  map[string]string{"tenant_id": "tenant-1", "family": "user", "resource_urn": "urn:cerebro:tenant-1:tailscale_user:user-1"},
		PayloadJson: []byte(`{"id":"user-1"}`),
	}
	return &ExecutionOutput{
		Plan: plan, Result: &cerebrov1.SourceWorkerDecodeResultV1{NextCursor: nextCursor, ResultDigestSha256: "digest"},
		Program: &PageProgram{TransitionDigest: "transition", AdmittedRecords: []*cerebrov1.SourceWorkerRecordV1{record}, CheckpointCursor: checkpointCursor, CheckpointWatermarkUnixMillis: watermark},
	}
}
