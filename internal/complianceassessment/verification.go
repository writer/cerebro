package complianceassessment

import (
	"fmt"
	"strings"
)

// CanonicalResultChunkDigest returns the digest used by persisted result
// chunks. It is exported so transports and SDK conformance tests can verify
// the exact canonical bytes without reimplementing the encoding contract.
func CanonicalResultChunkDigest(previousDigest string, results []ObjectiveResult) (string, error) {
	payload, err := canonicalBytes(results)
	if err != nil {
		return "", err
	}
	return digestResultChunkPayload(strings.TrimSpace(previousDigest), payload), nil
}

// ResultPageVerification records the independently checked boundaries of one
// paged result response. Callers pass NextPreviousDigest into the next page to
// verify the chain across transport boundaries.
type ResultPageVerification struct {
	Verified               bool   `json:"verified"`
	ChunkCount             uint32 `json:"chunk_count"`
	ResultCount            uint64 `json:"result_count"`
	FirstSequence          uint32 `json:"first_sequence,omitempty"`
	LastSequence           uint32 `json:"last_sequence,omitempty"`
	ExpectedPreviousDigest string `json:"expected_previous_digest,omitempty"`
	NextPreviousDigest     string `json:"next_previous_digest,omitempty"`
}

// VerifyResultChunkPage recomputes each chunk digest, validates result
// boundaries, and verifies the predecessor chain for a page returned after the
// supplied sequence.
func VerifyResultChunkPage(runID string, afterSequence uint32, expectedPreviousDigest string, page ResultChunkPage) (ResultPageVerification, error) {
	verification := ResultPageVerification{
		ExpectedPreviousDigest: strings.TrimSpace(expectedPreviousDigest),
	}
	if afterSequence == 0 && verification.ExpectedPreviousDigest != "" {
		return verification, fmt.Errorf("%w: the first result page cannot have a predecessor digest", ErrInvalidResult)
	}
	if len(page.Chunks) == 0 {
		if page.HasMore || page.NextSequence != 0 {
			return verification, fmt.Errorf("%w: an empty result page cannot advertise a continuation", ErrInvalidResult)
		}
		verification.Verified = true
		verification.NextPreviousDigest = verification.ExpectedPreviousDigest
		return verification, nil
	}

	expectedSequence := afterSequence + 1
	previousDigest := verification.ExpectedPreviousDigest
	for index, chunk := range page.Chunks {
		if strings.TrimSpace(chunk.RunID) != strings.TrimSpace(runID) {
			return verification, fmt.Errorf("%w: result chunk run does not match the requested run", ErrInvalidResult)
		}
		if chunk.Sequence != expectedSequence {
			return verification, fmt.Errorf("%w: result chunk sequence %d does not follow %d", ErrInvalidResult, chunk.Sequence, expectedSequence-1)
		}
		if strings.TrimSpace(chunk.PreviousDigest) != previousDigest {
			return verification, fmt.Errorf("%w: result chunk %d predecessor digest does not match", ErrInvalidResult, chunk.Sequence)
		}
		if err := validateRecoveredResultChunk(chunk); err != nil {
			return verification, fmt.Errorf("%w: verify result chunk %d: %v", ErrInvalidResult, chunk.Sequence, err)
		}
		if index == 0 {
			verification.FirstSequence = chunk.Sequence
		}
		verification.LastSequence = chunk.Sequence
		verification.ChunkCount++
		verification.ResultCount += uint64(chunk.Count)
		previousDigest = strings.TrimSpace(chunk.Digest)
		expectedSequence++
	}
	if page.HasMore && page.NextSequence != verification.LastSequence {
		return verification, fmt.Errorf("%w: next sequence does not match the verified page boundary", ErrInvalidResult)
	}

	verification.Verified = true
	verification.NextPreviousDigest = previousDigest
	return verification, nil
}
