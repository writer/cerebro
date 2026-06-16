package sourcecdk

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

const (
	// FamilyFreshnessProbeMode marks checkpoints that only carry a family-level
	// freshness canary and should not be treated as provider pagination cursors.
	FamilyFreshnessProbeMode = "family_freshness_probe"

	FamilyFreshnessExtraKind       = "canary_kind"
	FamilyFreshnessExtraResourceID = "canary_resource_id"
	FamilyFreshnessExtraObservedAt = "canary_observed_at"
	FamilyFreshnessExtraUpdatedAt  = "canary_updated_at"
	FamilyFreshnessExtraHash       = "canary_hash"
	FamilyFreshnessExtraConfidence = "canary_confidence"
)

// FamilyFreshnessConfidence describes whether an unchanged freshness canary is
// provider-authoritative or only a high-correlation dirty signal.
type FamilyFreshnessConfidence string

const (
	FamilyFreshnessConfidenceAuthoritative FamilyFreshnessConfidence = "authoritative"
	FamilyFreshnessConfidenceHeuristic     FamilyFreshnessConfidence = "heuristic"
)

// FamilyFreshnessProbe is the normalized provider canary stored in
// CursorEnvelope.Extra so connectors can skip expensive reads when a cheap,
// family-level metadata resource has not changed.
type FamilyFreshnessProbe struct {
	Kind       string
	ResourceID string
	ObservedAt time.Time
	UpdatedAt  time.Time
	Hash       string
	Confidence FamilyFreshnessConfidence
}

// FamilyFreshnessHash returns a stable digest for the provider fields that
// define whether a canary changed. Do not include ObservedAt in these parts.
func FamilyFreshnessHash(parts ...string) string {
	hash := sha256.New()
	wrote := false
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		wrote = true
		_, _ = hash.Write([]byte(part))
		_, _ = hash.Write([]byte{0})
	}
	if !wrote {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// FamilyFreshnessProbeFromCheckpoint restores a family freshness canary from a
// checkpoint cursor envelope.
func FamilyFreshnessProbeFromCheckpoint(source string, family string, checkpoint *cerebrov1.SourceCheckpoint) (FamilyFreshnessProbe, bool) {
	if checkpoint == nil {
		return FamilyFreshnessProbe{}, false
	}
	envelope, ok := DecodeCursorEnvelope(checkpoint.GetCursorOpaque())
	if !ok || !familyFreshnessEnvelopeMatches(envelope, source, family) {
		return FamilyFreshnessProbe{}, false
	}
	extra := envelope.Extra
	probe := FamilyFreshnessProbe{
		Kind:       strings.TrimSpace(extra[FamilyFreshnessExtraKind]),
		ResourceID: strings.TrimSpace(extra[FamilyFreshnessExtraResourceID]),
		Hash:       strings.TrimSpace(extra[FamilyFreshnessExtraHash]),
		Confidence: normalizeFamilyFreshnessConfidence(extra[FamilyFreshnessExtraConfidence]),
	}
	probe.ObservedAt = parseFamilyFreshnessTime(extra[FamilyFreshnessExtraObservedAt])
	probe.UpdatedAt = parseFamilyFreshnessTime(extra[FamilyFreshnessExtraUpdatedAt])
	probe, valid := normalizeFamilyFreshnessProbe(probe)
	if !valid || probe.Hash == "" {
		return FamilyFreshnessProbe{}, false
	}
	return probe, true
}

// FamilyFreshnessChangeProbe compares a newly observed family freshness canary
// with the durable checkpoint and returns the ChangeProbe expected by Family.
func FamilyFreshnessChangeProbe(source string, family string, checkpoint *cerebrov1.SourceCheckpoint, probe FamilyFreshnessProbe) ChangeProbe {
	next := FamilyFreshnessCheckpoint(source, family, checkpoint, probe)
	normalized, valid := normalizeFamilyFreshnessProbe(probe)
	if !valid {
		return ChangeProbe{Checkpoint: next}
	}
	previous, ok := FamilyFreshnessProbeFromCheckpoint(source, family, checkpoint)
	unchanged := ok &&
		previous.Kind == normalized.Kind &&
		previous.ResourceID == normalized.ResourceID &&
		previous.Hash == normalized.Hash
	return ChangeProbe{
		Unchanged:          unchanged,
		Checkpoint:         next,
		ShortCircuitReason: PullShortCircuitReasonNotModified,
	}
}

// BeginFamilyFreshnessRead restores probe metadata from continuation cursors
// and runs a start-of-family freshness probe when no provider cursor is active.
func BeginFamilyFreshnessRead(source string, family string, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint, probe func(*cerebrov1.SourceCheckpoint) (ChangeProbe, error)) (*cerebrov1.SourceCheckpoint, *Pull, error) {
	readCheckpoint := FamilyFreshnessCheckpointFromCursor(source, family, cursor, checkpoint)
	if strings.TrimSpace(CursorToken(cursor)) != "" || probe == nil {
		return readCheckpoint, nil, nil
	}
	change, err := probe(checkpoint)
	if err != nil {
		return nil, nil, err
	}
	if change.Unchanged {
		reason := change.ShortCircuitReason
		if reason == "" {
			reason = PullShortCircuitReasonNotModified
		}
		return change.Checkpoint, &Pull{Checkpoint: change.Checkpoint, ShortCircuitReason: reason}, nil
	}
	if change.Checkpoint != nil {
		readCheckpoint = change.Checkpoint
	}
	return readCheckpoint, nil, nil
}

// FamilyFreshnessCheckpoint stores a family freshness canary in a checkpoint
// cursor envelope while preserving existing cursor, watermark, boundary, and
// extra metadata where possible.
func FamilyFreshnessCheckpoint(source string, family string, checkpoint *cerebrov1.SourceCheckpoint, probe FamilyFreshnessProbe) *cerebrov1.SourceCheckpoint {
	next := cloneCheckpointForFreshness(checkpoint)
	normalized, valid := normalizeFamilyFreshnessProbe(probe)
	if !valid {
		return next
	}
	if next == nil {
		next = &cerebrov1.SourceCheckpoint{}
	}
	opaque := strings.TrimSpace(next.GetCursorOpaque())
	envelope, ok := DecodeCursorEnvelope(opaque)
	if !ok || !familyFreshnessEnvelopeMatches(envelope, source, family) {
		envelope = CursorEnvelope{Token: opaque}
	}
	envelope.Source = strings.TrimSpace(source)
	envelope.Family = strings.TrimSpace(family)
	if strings.TrimSpace(envelope.Mode) == "" {
		envelope.Mode = FamilyFreshnessProbeMode
	}
	if envelope.Extra == nil {
		envelope.Extra = map[string]string{}
	}
	envelope.Extra[FamilyFreshnessExtraKind] = normalized.Kind
	envelope.Extra[FamilyFreshnessExtraResourceID] = normalized.ResourceID
	if !normalized.ObservedAt.IsZero() {
		envelope.Extra[FamilyFreshnessExtraObservedAt] = normalized.ObservedAt.UTC().Format(time.RFC3339Nano)
	}
	if !normalized.UpdatedAt.IsZero() {
		envelope.Extra[FamilyFreshnessExtraUpdatedAt] = normalized.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	envelope.Extra[FamilyFreshnessExtraHash] = normalized.Hash
	if normalized.Confidence != "" {
		envelope.Extra[FamilyFreshnessExtraConfidence] = string(normalized.Confidence)
	}
	encoded, err := EncodeCursorEnvelope(envelope)
	if err != nil {
		return next
	}
	next.CursorOpaque = encoded
	return next
}

// FamilyFreshnessCheckpointFromCursor copies probe metadata from a cursor
// envelope into a checkpoint. This is useful when continuation cursors must
// carry a run-start canary across pages.
func FamilyFreshnessCheckpointFromCursor(source string, family string, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) *cerebrov1.SourceCheckpoint {
	if cursor == nil {
		return checkpoint
	}
	return FamilyFreshnessCheckpointFromCheckpoint(source, family, &cerebrov1.SourceCheckpoint{CursorOpaque: cursor.GetOpaque()}, checkpoint)
}

// FamilyFreshnessCheckpointFromCheckpoint copies probe metadata from one
// checkpoint envelope into another checkpoint.
func FamilyFreshnessCheckpointFromCheckpoint(source string, family string, from *cerebrov1.SourceCheckpoint, checkpoint *cerebrov1.SourceCheckpoint) *cerebrov1.SourceCheckpoint {
	probe, ok := FamilyFreshnessProbeFromCheckpoint(source, family, from)
	if !ok {
		return checkpoint
	}
	return FamilyFreshnessCheckpoint(source, family, checkpoint, probe)
}

// FamilyFreshnessCursor returns a provider cursor wrapped with freshness probe
// metadata when from carries one. CursorToken unwraps the provider token.
func FamilyFreshnessCursor(source string, family string, from *cerebrov1.SourceCheckpoint, cursor string) string {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return ""
	}
	checkpoint := FamilyFreshnessCheckpointFromCheckpoint(source, family, from, &cerebrov1.SourceCheckpoint{CursorOpaque: cursor})
	if checkpoint == nil {
		return cursor
	}
	return checkpoint.GetCursorOpaque()
}

func normalizeFamilyFreshnessProbe(probe FamilyFreshnessProbe) (FamilyFreshnessProbe, bool) {
	probe.Kind = strings.TrimSpace(probe.Kind)
	probe.ResourceID = strings.TrimSpace(probe.ResourceID)
	probe.Hash = strings.TrimSpace(probe.Hash)
	probe.ObservedAt = probe.ObservedAt.UTC()
	probe.UpdatedAt = probe.UpdatedAt.UTC()
	probe.Confidence = normalizeFamilyFreshnessConfidence(string(probe.Confidence))
	if probe.Hash == "" {
		probe.Hash = FamilyFreshnessHash(
			probe.Kind,
			probe.ResourceID,
			probe.UpdatedAt.Format(time.RFC3339Nano),
			string(probe.Confidence),
		)
	}
	return probe, probe.Kind != "" && probe.Hash != ""
}

func normalizeFamilyFreshnessConfidence(confidence string) FamilyFreshnessConfidence {
	switch FamilyFreshnessConfidence(strings.ToLower(strings.TrimSpace(confidence))) {
	case FamilyFreshnessConfidenceAuthoritative:
		return FamilyFreshnessConfidenceAuthoritative
	case FamilyFreshnessConfidenceHeuristic:
		return FamilyFreshnessConfidenceHeuristic
	default:
		return ""
	}
}

func parseFamilyFreshnessTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

func familyFreshnessEnvelopeMatches(envelope CursorEnvelope, source string, family string) bool {
	if strings.TrimSpace(envelope.Source) != "" && strings.TrimSpace(envelope.Source) != strings.TrimSpace(source) {
		return false
	}
	return strings.TrimSpace(envelope.Family) == "" || strings.TrimSpace(envelope.Family) == strings.TrimSpace(family)
}

func cloneCheckpointForFreshness(checkpoint *cerebrov1.SourceCheckpoint) *cerebrov1.SourceCheckpoint {
	if checkpoint == nil {
		return nil
	}
	return proto.Clone(checkpoint).(*cerebrov1.SourceCheckpoint)
}
