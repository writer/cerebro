package complianceassessment

import "testing"

func TestVerifyResultChunkPageChecksPayloadAndContinuation(t *testing.T) {
	firstResult := validObjectiveResult()
	secondResult := validObjectiveResult()
	secondResult.ID = "assessment-result-00000000000000000000000000000002"
	secondResult.ObjectiveID = "objective-2"
	first := verificationTestChunk(t, "run-1", 1, "", []ObjectiveResult{firstResult})
	second := verificationTestChunk(t, "run-1", 2, first.Digest, []ObjectiveResult{secondResult})

	verification, err := VerifyResultChunkPage("run-1", 0, "", ResultChunkPage{
		Chunks: []ResultChunk{first, second},
	})
	if err != nil {
		t.Fatalf("VerifyResultChunkPage() error = %v", err)
	}
	if !verification.Verified || verification.ChunkCount != 2 || verification.ResultCount != 2 || verification.NextPreviousDigest != second.Digest {
		t.Fatalf("VerifyResultChunkPage() = %#v", verification)
	}

	second.Results[0].ID = "tampered"
	if _, err := VerifyResultChunkPage("run-1", 1, first.Digest, ResultChunkPage{Chunks: []ResultChunk{second}}); err == nil {
		t.Fatal("VerifyResultChunkPage() accepted a tampered result payload")
	}
}

func TestVerifyResultChunkPageRejectsBrokenSequenceAndPredecessor(t *testing.T) {
	chunk := verificationTestChunk(t, "run-1", 2, "sha256:previous", []ObjectiveResult{validObjectiveResult()})
	if _, err := VerifyResultChunkPage("run-1", 0, "", ResultChunkPage{Chunks: []ResultChunk{chunk}}); err == nil {
		t.Fatal("VerifyResultChunkPage() accepted a missing first chunk")
	}
	if _, err := VerifyResultChunkPage("run-1", 1, "sha256:other", ResultChunkPage{Chunks: []ResultChunk{chunk}}); err == nil {
		t.Fatal("VerifyResultChunkPage() accepted a broken predecessor")
	}
}

func TestVerifyResultChunkPageRejectsEmptyContinuation(t *testing.T) {
	if _, err := VerifyResultChunkPage("run-1", 0, "", ResultChunkPage{HasMore: true, NextSequence: 1}); err == nil {
		t.Fatal("VerifyResultChunkPage() accepted an empty page with a continuation")
	}
}

func verificationTestChunk(t *testing.T, runID string, sequence uint32, previous string, results []ObjectiveResult) ResultChunk {
	t.Helper()
	digest, err := CanonicalResultChunkDigest(previous, results)
	if err != nil {
		t.Fatal(err)
	}
	return ResultChunk{
		RunID: runID, Sequence: sequence,
		FirstResultID: results[0].ID, LastResultID: results[len(results)-1].ID,
		// #nosec G115 -- every test fixture in this helper contains one or two results.
		Count: uint32(len(results)), PreviousDigest: previous,
		Digest: digest, Results: results,
	}
}
