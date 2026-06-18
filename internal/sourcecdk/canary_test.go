package sourcecdk

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
)

func TestFingerprintCheckpointRoundTrip(t *testing.T) {
	watermark := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	checkpoint := FingerprintCheckpoint(" github ", " repository ", watermark, map[string]string{
		" " + CanaryKindKey + " ": " newest_updated_resource ",
		CanaryHashKey:             " abc123 ",
		"empty":                   " ",
	})
	if checkpoint == nil {
		t.Fatal("FingerprintCheckpoint() = nil, want checkpoint")
	}
	if got := checkpoint.GetWatermark().AsTime(); !got.Equal(watermark) {
		t.Fatalf("checkpoint watermark = %s, want %s", got, watermark)
	}
	metadata := CheckpointFingerprint(checkpoint, "github", "repository")
	if metadata[CanaryKindKey] != "newest_updated_resource" || metadata[CanaryHashKey] != "abc123" {
		t.Fatalf("CheckpointFingerprint() = %#v, want normalized canary metadata", metadata)
	}
	if _, ok := metadata["empty"]; ok {
		t.Fatalf("CheckpointFingerprint() kept empty metadata: %#v", metadata)
	}
}

func TestCheckpointFingerprintRejectsMalformedOrMismatchedMetadata(t *testing.T) {
	if got := CheckpointFingerprint(&cerebrov1.SourceCheckpoint{CursorOpaque: "native-token"}, "github", "repository"); got != nil {
		t.Fatalf("CheckpointFingerprint(native) = %#v, want nil", got)
	}
	checkpoint := FingerprintCheckpoint("github", "repository", time.Now().UTC(), map[string]string{CanaryHashKey: "abc"})
	if got := CheckpointFingerprint(checkpoint, "github", "audit"); got != nil {
		t.Fatalf("CheckpointFingerprint(wrong family) = %#v, want nil", got)
	}
}

func TestMergeFingerprintCheckpointPreservesIncrementalBoundaries(t *testing.T) {
	watermark := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	checkpoint := IncrementalWatermarkCheckpoint("github", "repository", []*primitives.Event{
		{Id: "repo-boundary", OccurredAt: timestamppb.New(watermark)},
	}, IncrementalWatermarkState{})

	merged := MergeFingerprintCheckpoint(checkpoint, "github", "repository", map[string]string{
		CanaryHashKey:       "abc",
		CanaryConfidenceKey: CanaryConfidenceHeuristic,
	})
	envelope, ok := DecodeCursorEnvelope(merged.GetCursorOpaque())
	if !ok {
		t.Fatal("merged checkpoint cursor is not an envelope")
	}
	if envelope.Mode != incrementalWatermarkMode {
		t.Fatalf("merged mode = %q, want incremental watermark mode", envelope.Mode)
	}
	if got := envelope.BoundaryIDs; len(got) != 1 || got[0] != "repo-boundary" {
		t.Fatalf("boundary IDs = %#v, want existing repo boundary", got)
	}
	if envelope.Extra[CanaryHashKey] != "abc" {
		t.Fatalf("merged extra = %#v, want canary hash", envelope.Extra)
	}
}

func TestSkippedAndReconciledFingerprintCheckpointHistory(t *testing.T) {
	reconciledAt := time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC)
	firstSkip := reconciledAt.Add(time.Hour)
	secondSkip := firstSkip.Add(time.Hour)
	checkpoint := ReconciledFingerprintCheckpoint(nil, "github", "repository", reconciledAt, map[string]string{
		CanaryHashKey:      "abc",
		ManifestVersionKey: "v1",
	}, reconciledAt)
	checkpoint = SkippedFingerprintCheckpoint(checkpoint, "github", "repository", map[string]string{CanaryHashKey: "abc"}, firstSkip)
	checkpoint = SkippedFingerprintCheckpoint(checkpoint, "github", "repository", map[string]string{CanaryHashKey: "abc"}, secondSkip)

	metadata := CheckpointFingerprint(checkpoint, "github", "repository")
	if metadata[CanarySkipCountKey] != "2" {
		t.Fatalf("skip count = %q, want 2", metadata[CanarySkipCountKey])
	}
	if metadata[CanaryFirstSkippedKey] != firstSkip.Format(time.RFC3339Nano) {
		t.Fatalf("first skipped = %q, want first skip timestamp", metadata[CanaryFirstSkippedKey])
	}

	checkpoint = ReconciledFingerprintCheckpoint(checkpoint, "github", "repository", reconciledAt, map[string]string{CanaryHashKey: "abc"}, secondSkip)
	metadata = CheckpointFingerprint(checkpoint, "github", "repository")
	if metadata[CanarySkipCountKey] != "0" {
		t.Fatalf("reconciled skip count = %q, want 0", metadata[CanarySkipCountKey])
	}
	if metadata[CanaryFirstSkippedKey] != "" || metadata[CanaryLastSkippedKey] != "" {
		t.Fatalf("reconciled skip metadata = %#v, want cleared skip timestamps", metadata)
	}
}

func TestFreshnessProbeReconciliationReason(t *testing.T) {
	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	base := map[string]string{
		CanaryHashKey:         "abc",
		CanaryConfidenceKey:   CanaryConfidenceHeuristic,
		CanaryConfigHashKey:   "cfg-a",
		CanaryReconciledAtKey: now.Add(-time.Hour).Format(time.RFC3339Nano),
		CanaryFirstSkippedKey: now.Add(-30 * time.Minute).Format(time.RFC3339Nano),
		CanarySkipCountKey:    "1",
		ManifestVersionKey:    "v1",
	}
	policy := CanaryReconciliationPolicy{
		Confidence:             CanaryConfidenceHeuristic,
		MaxSkipDuration:        time.Hour,
		MaxConsecutiveSkips:    3,
		ReconciliationInterval: 24 * time.Hour,
		ManifestVersion:        "v1",
		ConfigHash:             "cfg-a",
		Now:                    now,
	}
	if got := FreshnessProbeReconciliationReason(base, policy); got != "" {
		t.Fatalf("normal guardrail reason = %q, want empty", got)
	}

	withSkipCount := cloneMetadata(base)
	withSkipCount[CanarySkipCountKey] = "3"
	if got := FreshnessProbeReconciliationReason(withSkipCount, policy); got != PullReconciliationReasonMaxConsecutiveSkips {
		t.Fatalf("skip count guardrail = %q, want max_consecutive_skips", got)
	}

	withSkipDuration := cloneMetadata(base)
	withSkipDuration[CanaryFirstSkippedKey] = now.Add(-time.Hour).Format(time.RFC3339Nano)
	if got := FreshnessProbeReconciliationReason(withSkipDuration, policy); got != PullReconciliationReasonMaxSkipDuration {
		t.Fatalf("skip duration guardrail = %q, want max_skip_duration", got)
	}

	withConfigChange := cloneMetadata(base)
	withConfigChange[CanaryConfigHashKey] = "cfg-b"
	if got := FreshnessProbeReconciliationReason(withConfigChange, policy); got != PullReconciliationReasonSourceConfigChanged {
		t.Fatalf("config guardrail = %q, want source_config_changed", got)
	}

	withManifestChange := cloneMetadata(base)
	withManifestChange[ManifestVersionKey] = "v0"
	if got := FreshnessProbeReconciliationReason(withManifestChange, policy); got != PullReconciliationReasonCanaryManifestChanged {
		t.Fatalf("manifest guardrail = %q, want canary_manifest_version_changed", got)
	}

	withReconciliationInterval := cloneMetadata(base)
	withReconciliationInterval[CanaryReconciledAtKey] = now.Add(-24 * time.Hour).Format(time.RFC3339Nano)
	if got := FreshnessProbeReconciliationReason(withReconciliationInterval, policy); got != PullReconciliationReasonReconciliationInterval {
		t.Fatalf("interval guardrail = %q, want reconciliation_interval", got)
	}
}

func cloneMetadata(metadata map[string]string) map[string]string {
	clone := make(map[string]string, len(metadata))
	for key, value := range metadata {
		clone[key] = value
	}
	return clone
}
