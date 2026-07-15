package complianceassessment

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/observability"
)

const ReplayVerificationVersion = "assessment-replay-verification/v1"

type HistoricalGapKind string

const (
	HistoricalGapManifest HistoricalGapKind = "manifest"
	HistoricalGapRevision HistoricalGapKind = "revision"
	HistoricalGapResult   HistoricalGapKind = "result"
)

type HistoricalGap struct {
	Kind       HistoricalGapKind `json:"kind"`
	ID         string            `json:"id"`
	Digest     string            `json:"digest"`
	RevisionID string            `json:"revision_id,omitempty"`
}

type ReplayMismatchKind string

const (
	ReplayMismatchManifest       ReplayMismatchKind = "manifest_hash"
	ReplayMismatchRevision       ReplayMismatchKind = "revision_hash"
	ReplayMismatchStoredResult   ReplayMismatchKind = "stored_result_hash"
	ReplayMismatchReplayedResult ReplayMismatchKind = "replayed_result_hash"
)

type ReplayMismatch struct {
	Kind     ReplayMismatchKind `json:"kind"`
	ID       string             `json:"id,omitempty"`
	Expected string             `json:"expected"`
	Observed string             `json:"observed"`
}

type ReplayVerificationStatus string

const (
	ReplayVerified   ReplayVerificationStatus = "verified"
	ReplayGap        ReplayVerificationStatus = "historical_gap"
	ReplayMismatched ReplayVerificationStatus = "mismatch"
)

type ReplayVerificationReceipt struct {
	Version              string                   `json:"version"`
	Status               ReplayVerificationStatus `json:"status"`
	ExpectedManifestHash string                   `json:"expected_manifest_hash"`
	ExpectedResultHash   string                   `json:"expected_result_hash"`
	ReplayedResultHash   string                   `json:"replayed_result_hash,omitempty"`
	HistoricalGaps       []HistoricalGap          `json:"historical_gaps,omitempty"`
	Mismatches           []ReplayMismatch         `json:"mismatches,omitempty"`
	ReceiptDigest        string                   `json:"receipt_digest"`
}

// PinnedHistory exposes only exact historical lookups. Replay verification has
// no current-state lookup and therefore cannot silently replace missing history
// with a newer scope, revision, evidence object, or result.
type PinnedHistory interface {
	LoadManifest(context.Context, string) (InputManifest, bool, error)
	LoadRevision(context.Context, ManifestRevision) ([]byte, bool, error)
	LoadResultSet(context.Context, string) ([]ObjectiveResult, bool, error)
}

type PinnedReplayInput struct {
	Manifest InputManifest `json:"manifest"`
	// Revisions is keyed by RevisionArtifactKey so revision IDs reused across
	// artifact kinds or identities cannot overwrite one another.
	Revisions map[string][]byte `json:"revisions"`
}

type PinnedReplayer interface {
	Replay(context.Context, PinnedReplayInput) ([]ObjectiveResult, error)
}

type ReplayVerificationInput struct {
	ExpectedManifestHash string
	ExpectedResultHash   string
	History              PinnedHistory
	Replayer             PinnedReplayer
}

func VerifyDeterministicReplay(ctx context.Context, input ReplayVerificationInput) (ReplayVerificationReceipt, error) {
	receipt := ReplayVerificationReceipt{
		Version:              ReplayVerificationVersion,
		ExpectedManifestHash: strings.TrimSpace(input.ExpectedManifestHash),
		ExpectedResultHash:   strings.TrimSpace(input.ExpectedResultHash),
	}
	if input.History == nil || input.Replayer == nil || receipt.ExpectedManifestHash == "" || receipt.ExpectedResultHash == "" {
		recordReplayMetric("failed")
		return ReplayVerificationReceipt{}, errors.New("pinned history, replayer, and expected hashes are required")
	}

	manifest, found, err := input.History.LoadManifest(ctx, receipt.ExpectedManifestHash)
	if err != nil {
		recordReplayMetric("failed")
		return ReplayVerificationReceipt{}, fmt.Errorf("load historical manifest: %w", err)
	}
	if !found {
		receipt.HistoricalGaps = append(receipt.HistoricalGaps, HistoricalGap{Kind: HistoricalGapManifest, ID: "input_manifest", Digest: receipt.ExpectedManifestHash})
	}

	var revisions map[string][]byte
	if found {
		manifest = NormalizeManifest(manifest)
		observedManifestHash, digestErr := CanonicalManifestDigest(manifest)
		if digestErr != nil {
			receipt.Mismatches = append(receipt.Mismatches, ReplayMismatch{Kind: ReplayMismatchManifest, ID: "input_manifest", Expected: receipt.ExpectedManifestHash, Observed: "invalid"})
		} else if observedManifestHash != receipt.ExpectedManifestHash {
			receipt.Mismatches = append(receipt.Mismatches, ReplayMismatch{Kind: ReplayMismatchManifest, ID: "input_manifest", Expected: receipt.ExpectedManifestHash, Observed: observedManifestHash})
		} else {
			revisions = make(map[string][]byte, len(manifest.Revisions))
			for _, revision := range manifest.Revisions {
				artifact, revisionFound, loadErr := input.History.LoadRevision(ctx, revision)
				if loadErr != nil {
					recordReplayMetric("failed")
					return ReplayVerificationReceipt{}, fmt.Errorf("load historical revision %q: %w", revision.RevisionID, loadErr)
				}
				if !revisionFound {
					receipt.HistoricalGaps = append(receipt.HistoricalGaps, HistoricalGap{Kind: HistoricalGapRevision, ID: revision.ID, Digest: revision.Digest, RevisionID: revision.RevisionID})
					continue
				}
				observed := digestBytes(artifact)
				if observed != revision.Digest {
					receipt.Mismatches = append(receipt.Mismatches, ReplayMismatch{Kind: ReplayMismatchRevision, ID: revision.RevisionID, Expected: revision.Digest, Observed: observed})
					continue
				}
				revisions[RevisionArtifactKey(revision)] = append([]byte(nil), artifact...)
			}
		}
	}

	storedResults, resultsFound, err := input.History.LoadResultSet(ctx, receipt.ExpectedResultHash)
	if err != nil {
		recordReplayMetric("failed")
		return ReplayVerificationReceipt{}, fmt.Errorf("load historical result: %w", err)
	}
	if !resultsFound {
		receipt.HistoricalGaps = append(receipt.HistoricalGaps, HistoricalGap{Kind: HistoricalGapResult, ID: "objective_results", Digest: receipt.ExpectedResultHash})
	} else if observed, digestErr := CanonicalResultSetDigest(storedResults); digestErr != nil {
		receipt.Mismatches = append(receipt.Mismatches, ReplayMismatch{Kind: ReplayMismatchStoredResult, ID: "objective_results", Expected: receipt.ExpectedResultHash, Observed: "invalid"})
	} else if observed != receipt.ExpectedResultHash {
		receipt.Mismatches = append(receipt.Mismatches, ReplayMismatch{Kind: ReplayMismatchStoredResult, ID: "objective_results", Expected: receipt.ExpectedResultHash, Observed: observed})
	}

	if len(receipt.HistoricalGaps) == 0 && len(receipt.Mismatches) == 0 {
		replayed, replayErr := input.Replayer.Replay(ctx, PinnedReplayInput{Manifest: manifest, Revisions: revisions})
		if replayErr != nil {
			recordReplayMetric("failed")
			return ReplayVerificationReceipt{}, fmt.Errorf("replay pinned assessment: %w", replayErr)
		}
		receipt.ReplayedResultHash, err = CanonicalResultSetDigest(replayed)
		if err != nil {
			receipt.Mismatches = append(receipt.Mismatches, ReplayMismatch{Kind: ReplayMismatchReplayedResult, ID: "objective_results", Expected: receipt.ExpectedResultHash, Observed: "invalid"})
		} else if receipt.ReplayedResultHash != receipt.ExpectedResultHash {
			receipt.Mismatches = append(receipt.Mismatches, ReplayMismatch{Kind: ReplayMismatchReplayedResult, ID: "objective_results", Expected: receipt.ExpectedResultHash, Observed: receipt.ReplayedResultHash})
		}
	}

	normalizeReplayReceipt(&receipt)
	switch {
	case len(receipt.HistoricalGaps) != 0:
		receipt.Status = ReplayGap
	case len(receipt.Mismatches) != 0:
		receipt.Status = ReplayMismatched
	default:
		receipt.Status = ReplayVerified
	}
	digestInput := receipt
	digestInput.ReceiptDigest = ""
	data, err := canonicalBytes(digestInput)
	if err != nil {
		recordReplayMetric("failed")
		return ReplayVerificationReceipt{}, err
	}
	receipt.ReceiptDigest = digestBytes(data)
	recordReplayMetric(string(receipt.Status))
	return receipt, nil
}

func RevisionArtifactKey(revision ManifestRevision) string {
	return strings.TrimSpace(revision.Kind) + "\x00" + strings.TrimSpace(revision.ID) + "\x00" + strings.TrimSpace(revision.RevisionID)
}

func normalizeReplayReceipt(receipt *ReplayVerificationReceipt) {
	sort.Slice(receipt.HistoricalGaps, func(i, j int) bool {
		left := string(receipt.HistoricalGaps[i].Kind) + "\x00" + receipt.HistoricalGaps[i].ID + "\x00" + receipt.HistoricalGaps[i].RevisionID
		right := string(receipt.HistoricalGaps[j].Kind) + "\x00" + receipt.HistoricalGaps[j].ID + "\x00" + receipt.HistoricalGaps[j].RevisionID
		return left < right
	})
	sort.Slice(receipt.Mismatches, func(i, j int) bool {
		return string(receipt.Mismatches[i].Kind)+"\x00"+receipt.Mismatches[i].ID < string(receipt.Mismatches[j].Kind)+"\x00"+receipt.Mismatches[j].ID
	})
}

func recordReplayMetric(status string) {
	observability.Default.Inc("cerebro_assurance_replay_total", map[string]string{"status": status})
}
