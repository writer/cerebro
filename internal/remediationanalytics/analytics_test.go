package remediationanalytics

import (
	"errors"
	"testing"
	"time"
)

func TestPredictionReceiptIsDeterministicAndVersionBound(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	input := PredictionInput{TenantID: "tenant-a", ReportRunID: "report-a", CandidateID: "candidate-a", PlanModelVersion: "model-v2", ActionType: "revoke_access", TargetType: "identity", FindingRevisions: []FindingRevision{{FindingID: "finding-b", Fingerprint: "fp-b", RuleID: "rule-b", Revision: 2}, {FindingID: "finding-a", Fingerprint: "fp-a", RuleID: "rule-a", Revision: 1}}, PredictedRiskDelta: 12.5, PredictedAttackPathDelta: 2, CreatedAt: now}
	first, err := NewPredictionReceipt(input)
	if err != nil {
		t.Fatal(err)
	}
	input.FindingRevisions[0], input.FindingRevisions[1] = input.FindingRevisions[1], input.FindingRevisions[0]
	second, err := NewPredictionReceipt(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest {
		t.Fatalf("digest changed with input order: %s != %s", first.Digest, second.Digest)
	}
	input.PlanModelVersion = "model-v3"
	third, err := NewPredictionReceipt(input)
	if err != nil {
		t.Fatal(err)
	}
	if third.Digest == first.Digest {
		t.Fatal("model version did not change prediction digest")
	}
}

func TestRealizedResultCensorsUnhealthyVerification(t *testing.T) {
	prediction := testPrediction(t)
	value := 4.0
	_, err := NewRealizedResult(RealizedInput{Prediction: prediction, SourceHealth: SourceUnhealthy, CensoredReason: "source_collection_failed", RealizedRiskDelta: &value, ObservedAt: prediction.CreatedAt.Add(time.Hour)})
	if !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("error = %v, want ErrInvalidRecord", err)
	}
	result, err := NewRealizedResult(RealizedInput{Prediction: prediction, SourceHealth: SourceUnhealthy, CensoredReason: "source_collection_failed", ObservedAt: prediction.CreatedAt.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if result.CensoredReason == "" || result.RealizedRiskDelta != nil || result.RiskPredictionError != nil {
		t.Fatalf("unexpected censored result: %+v", result)
	}
}

func TestRealizedResultRejectsUnboundFinding(t *testing.T) {
	prediction := testPrediction(t)
	value := 10.0
	_, err := NewRealizedResult(RealizedInput{Prediction: prediction, VerificationID: "verify-a", VerifiedClosedFindingIDs: []string{"foreign-finding"}, SourceHealth: SourceHealthy, RealizedRiskDelta: &value, ObservedAt: prediction.CreatedAt.Add(time.Hour)})
	if !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("error = %v, want ErrInvalidRecord", err)
	}
}

func TestDeriveResolutionEpisodesTracksDurabilityAndRecurrence(t *testing.T) {
	opened := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	closed := opened.Add(24 * time.Hour)
	recurred := closed.Add(35 * 24 * time.Hour)
	observations := []LifecycleObservation{{TenantID: "tenant-a", FindingID: "finding-a", Fingerprint: "fp-a", RuleID: "rule-a", Kind: ObservationRecurred, ObservedAt: recurred}, {TenantID: "tenant-a", FindingID: "finding-a", Fingerprint: "fp-a", RuleID: "rule-a", Kind: ObservationOpened, ObservedAt: opened}, {TenantID: "tenant-a", FindingID: "finding-a", Fingerprint: "fp-a", RuleID: "rule-a", Kind: ObservationVerifiedClosed, VerificationID: "verify-a", ObservedAt: closed}}
	episodes, err := DeriveResolutionEpisodes(observations, recurred.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(episodes) != 2 {
		t.Fatalf("episodes = %d, want 2", len(episodes))
	}
	if episodes[0].Durability != DurabilityRecurred || episodes[0].TimeToRecurrence != 35*24*time.Hour {
		t.Fatalf("first episode = %+v", episodes[0])
	}
	if episodes[1].Durability != DurabilityOpen || !episodes[1].OpenedAt.Equal(recurred) {
		t.Fatalf("second episode = %+v", episodes[1])
	}
}

func TestDeriveResolutionEpisodesDoesNotCreditUnhealthySource(t *testing.T) {
	opened := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	closed := opened.Add(time.Hour)
	unhealthy := closed.Add(24 * time.Hour)
	episodes, err := DeriveResolutionEpisodes([]LifecycleObservation{{TenantID: "tenant-a", FindingID: "finding-a", Fingerprint: "fp-a", RuleID: "rule-a", Kind: ObservationOpened, ObservedAt: opened}, {TenantID: "tenant-a", FindingID: "finding-a", Fingerprint: "fp-a", RuleID: "rule-a", Kind: ObservationVerifiedClosed, VerificationID: "verify-a", ObservedAt: closed}, {TenantID: "tenant-a", FindingID: "finding-a", Fingerprint: "fp-a", RuleID: "rule-a", Kind: ObservationSourceUnhealthy, ObservedAt: unhealthy}}, closed.Add(100*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if episodes[0].Durability != DurabilityIndeterminateSourceUnhealthy {
		t.Fatalf("durability = %s", episodes[0].Durability)
	}
}

func TestBuildBenchmarksSeparatesTenantAndVersionAndDisclosesSample(t *testing.T) {
	prediction := testPrediction(t)
	risk := 10.0
	result, err := NewRealizedResult(RealizedInput{Prediction: prediction, VerificationID: "verify-a", VerifiedClosedFindingIDs: []string{"finding-a"}, SourceHealth: SourceHealthy, RealizedRiskDelta: &risk, ObservedAt: prediction.CreatedAt.Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	otherPrediction := prediction
	otherPrediction.TenantID = "tenant-b"
	otherPrediction.Digest = "sha256:other"
	other, err := NewRealizedResult(RealizedInput{Prediction: otherPrediction, VerificationID: "verify-b", StillMatchingFindingIDs: []string{"finding-a"}, SourceHealth: SourceHealthy, RealizedRiskDelta: &risk, ObservedAt: otherPrediction.CreatedAt.Add(4 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	benchmarks := BuildBenchmarks([]RealizedResult{other, result}, 2)
	if len(benchmarks) != 2 {
		t.Fatalf("benchmarks = %d, want 2", len(benchmarks))
	}
	for _, benchmark := range benchmarks {
		if benchmark.SampleSize != 1 || benchmark.MinimumSampleMet {
			t.Fatalf("benchmark = %+v", benchmark)
		}
	}
}

func testPrediction(t *testing.T) PredictionReceipt {
	t.Helper()
	receipt, err := NewPredictionReceipt(PredictionInput{TenantID: "tenant-a", ReportRunID: "report-a", CandidateID: "candidate-a", PlanModelVersion: "model-v2", ActionType: "revoke_access", TargetType: "identity", FindingRevisions: []FindingRevision{{FindingID: "finding-a", Fingerprint: "fp-a", RuleID: "rule-a", Revision: 1}}, PredictedRiskDelta: 12, PredictedAttackPathDelta: 1, CreatedAt: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}
