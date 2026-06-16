package sourcecdk

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
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
	FamilyFreshnessExtraSkipCount  = "canary_skip_count"
	FamilyFreshnessExtraFullReadAt = "canary_full_read_at"
	FamilyFreshnessExtraReason     = "canary_reconcile_reason"
)

// FamilyFreshnessConfidence describes whether an unchanged freshness canary is
// provider-authoritative or only a high-correlation dirty signal.
type FamilyFreshnessConfidence string

const (
	FamilyFreshnessConfidenceAuthoritative FamilyFreshnessConfidence = "authoritative"
	FamilyFreshnessConfidenceHeuristic     FamilyFreshnessConfidence = "heuristic"
)

// FamilyFreshnessProbeErrorMode controls what BeginFamilyFreshnessReadWithOptions
// does when the cheap metadata probe fails.
type FamilyFreshnessProbeErrorMode string

const (
	FamilyFreshnessProbeErrorFailClosed FamilyFreshnessProbeErrorMode = "fail_closed"
	FamilyFreshnessProbeErrorFailOpen   FamilyFreshnessProbeErrorMode = "fail_open"
)

const (
	FamilyFreshnessReasonInitial      = "initial"
	FamilyFreshnessReasonChanged      = "changed"
	FamilyFreshnessReasonShortCircuit = "short_circuit"
	FamilyFreshnessReasonMaxSkipCount = "max_skip_count"
	FamilyFreshnessReasonMaxSkipAge   = "max_skip_age"
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
	SkipCount  int
	FullReadAt time.Time
	Reason     string
}

// FamilyFreshnessReadOptions makes probe policy explicit for connectors that
// use freshness metadata before a normal family read.
type FamilyFreshnessReadOptions struct {
	Confidence     FamilyFreshnessConfidence
	MaxSkipCount   int
	MaxSkipAge     time.Duration
	ProbeErrorMode FamilyFreshnessProbeErrorMode
	Now            func() time.Time
}

// FamilyFreshnessCheckpointInfo describes freshness metadata restored from a
// checkpoint without exposing provider-specific hash or resource fields.
type FamilyFreshnessCheckpointInfo struct {
	Source     string
	Family     string
	Confidence FamilyFreshnessConfidence
	SkipCount  int
	Reason     string
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
	return familyFreshnessProbeFromEnvelope(envelope)
}

// FamilyFreshnessInfoFromCheckpoint restores bounded freshness metadata for
// runtime health and telemetry without exposing provider canary identities.
func FamilyFreshnessInfoFromCheckpoint(checkpoint *cerebrov1.SourceCheckpoint) (FamilyFreshnessCheckpointInfo, bool) {
	if checkpoint == nil {
		return FamilyFreshnessCheckpointInfo{}, false
	}
	envelope, ok := DecodeCursorEnvelope(checkpoint.GetCursorOpaque())
	if !ok {
		return FamilyFreshnessCheckpointInfo{}, false
	}
	probe, ok := familyFreshnessProbeFromEnvelope(envelope)
	if !ok {
		return FamilyFreshnessCheckpointInfo{}, false
	}
	return FamilyFreshnessCheckpointInfo{
		Source:     strings.TrimSpace(envelope.Source),
		Family:     strings.TrimSpace(envelope.Family),
		Confidence: probe.Confidence,
		SkipCount:  probe.SkipCount,
		Reason:     probe.Reason,
	}, true
}

func familyFreshnessProbeFromEnvelope(envelope CursorEnvelope) (FamilyFreshnessProbe, bool) {
	extra := envelope.Extra
	probe := FamilyFreshnessProbe{
		Kind:       strings.TrimSpace(extra[FamilyFreshnessExtraKind]),
		ResourceID: strings.TrimSpace(extra[FamilyFreshnessExtraResourceID]),
		Hash:       strings.TrimSpace(extra[FamilyFreshnessExtraHash]),
		Confidence: normalizeFamilyFreshnessConfidence(extra[FamilyFreshnessExtraConfidence]),
		SkipCount:  parseFamilyFreshnessInt(extra[FamilyFreshnessExtraSkipCount]),
		Reason:     normalizeFamilyFreshnessReason(extra[FamilyFreshnessExtraReason]),
	}
	probe.ObservedAt = parseFamilyFreshnessTime(extra[FamilyFreshnessExtraObservedAt])
	probe.UpdatedAt = parseFamilyFreshnessTime(extra[FamilyFreshnessExtraUpdatedAt])
	probe.FullReadAt = parseFamilyFreshnessTime(extra[FamilyFreshnessExtraFullReadAt])
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
	return BeginFamilyFreshnessReadWithOptions(source, family, cursor, checkpoint, probe, FamilyFreshnessReadOptions{})
}

// BeginFamilyFreshnessReadWithOptions restores probe metadata from continuation
// cursors, applies explicit stale-heuristic policy, and runs a start-of-family
// freshness probe when no provider cursor is active.
func BeginFamilyFreshnessReadWithOptions(source string, family string, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint, probe func(*cerebrov1.SourceCheckpoint) (ChangeProbe, error), options FamilyFreshnessReadOptions) (*cerebrov1.SourceCheckpoint, *Pull, error) {
	readCheckpoint := FamilyFreshnessCheckpointFromCursor(source, family, cursor, checkpoint)
	if strings.TrimSpace(CursorToken(cursor)) != "" || probe == nil {
		return readCheckpoint, nil, nil
	}
	change, err := probe(checkpoint)
	if err != nil {
		if normalizeFamilyFreshnessProbeErrorMode(options.ProbeErrorMode) == FamilyFreshnessProbeErrorFailOpen {
			return readCheckpoint, nil, nil
		}
		return nil, nil, err
	}
	change = applyFamilyFreshnessReadOptions(source, family, checkpoint, change, options)
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
	} else {
		delete(envelope.Extra, FamilyFreshnessExtraObservedAt)
	}
	if !normalized.UpdatedAt.IsZero() {
		envelope.Extra[FamilyFreshnessExtraUpdatedAt] = normalized.UpdatedAt.UTC().Format(time.RFC3339Nano)
	} else {
		delete(envelope.Extra, FamilyFreshnessExtraUpdatedAt)
	}
	envelope.Extra[FamilyFreshnessExtraHash] = normalized.Hash
	if normalized.Confidence != "" {
		envelope.Extra[FamilyFreshnessExtraConfidence] = string(normalized.Confidence)
	} else {
		delete(envelope.Extra, FamilyFreshnessExtraConfidence)
	}
	if normalized.SkipCount > 0 {
		envelope.Extra[FamilyFreshnessExtraSkipCount] = strconv.Itoa(normalized.SkipCount)
	} else {
		delete(envelope.Extra, FamilyFreshnessExtraSkipCount)
	}
	if !normalized.FullReadAt.IsZero() {
		envelope.Extra[FamilyFreshnessExtraFullReadAt] = normalized.FullReadAt.UTC().Format(time.RFC3339Nano)
	} else {
		delete(envelope.Extra, FamilyFreshnessExtraFullReadAt)
	}
	if normalized.Reason != "" {
		envelope.Extra[FamilyFreshnessExtraReason] = normalized.Reason
	} else {
		delete(envelope.Extra, FamilyFreshnessExtraReason)
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
	probe.FullReadAt = probe.FullReadAt.UTC()
	probe.Confidence = normalizeFamilyFreshnessConfidence(string(probe.Confidence))
	if probe.SkipCount < 0 {
		probe.SkipCount = 0
	}
	probe.Reason = normalizeFamilyFreshnessReason(probe.Reason)
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

func applyFamilyFreshnessReadOptions(source string, family string, checkpoint *cerebrov1.SourceCheckpoint, change ChangeProbe, options FamilyFreshnessReadOptions) ChangeProbe {
	nextProbe, hasNext := FamilyFreshnessProbeFromCheckpoint(source, family, change.Checkpoint)
	if !hasNext {
		return change
	}
	previousProbe, hasPrevious := FamilyFreshnessProbeFromCheckpoint(source, family, checkpoint)
	now := familyFreshnessNow(options)
	if nextProbe.ObservedAt.IsZero() {
		nextProbe.ObservedAt = now
	}
	if options.Confidence != "" {
		nextProbe.Confidence = options.Confidence
	}
	if !change.Unchanged {
		nextProbe.SkipCount = 0
		nextProbe.FullReadAt = nextProbe.ObservedAt
		if hasPrevious {
			nextProbe.Reason = FamilyFreshnessReasonChanged
		} else {
			nextProbe.Reason = FamilyFreshnessReasonInitial
		}
		change.Checkpoint = FamilyFreshnessCheckpoint(source, family, change.Checkpoint, nextProbe)
		return change
	}
	nextProbe.FullReadAt = previousProbe.FullReadAt
	forceReason := familyFreshnessForceReason(previousProbe, hasPrevious, options, now)
	if forceReason != "" {
		nextProbe.SkipCount = 0
		nextProbe.FullReadAt = nextProbe.ObservedAt
		nextProbe.Reason = forceReason
		change.Unchanged = false
		change.ShortCircuitReason = ""
		change.Checkpoint = FamilyFreshnessCheckpoint(source, family, change.Checkpoint, nextProbe)
		return change
	}
	if hasPrevious {
		nextProbe.SkipCount = previousProbe.SkipCount + 1
	}
	nextProbe.Reason = FamilyFreshnessReasonShortCircuit
	change.Checkpoint = FamilyFreshnessCheckpoint(source, family, change.Checkpoint, nextProbe)
	return change
}

func familyFreshnessForceReason(previous FamilyFreshnessProbe, hasPrevious bool, options FamilyFreshnessReadOptions, now time.Time) string {
	if !hasPrevious {
		return ""
	}
	if options.MaxSkipCount > 0 && previous.SkipCount >= options.MaxSkipCount {
		return FamilyFreshnessReasonMaxSkipCount
	}
	if options.MaxSkipAge > 0 {
		if previous.FullReadAt.IsZero() {
			return FamilyFreshnessReasonMaxSkipAge
		}
		if !now.IsZero() && !previous.FullReadAt.After(now) && now.Sub(previous.FullReadAt) >= options.MaxSkipAge {
			return FamilyFreshnessReasonMaxSkipAge
		}
	}
	return ""
}

func familyFreshnessNow(options FamilyFreshnessReadOptions) time.Time {
	if options.Now != nil {
		if now := options.Now().UTC(); !now.IsZero() {
			return now
		}
	}
	return time.Now().UTC()
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

func normalizeFamilyFreshnessProbeErrorMode(mode FamilyFreshnessProbeErrorMode) FamilyFreshnessProbeErrorMode {
	switch FamilyFreshnessProbeErrorMode(strings.ToLower(strings.TrimSpace(string(mode)))) {
	case FamilyFreshnessProbeErrorFailOpen:
		return FamilyFreshnessProbeErrorFailOpen
	default:
		return FamilyFreshnessProbeErrorFailClosed
	}
}

func normalizeFamilyFreshnessReason(reason string) string {
	switch strings.ToLower(strings.TrimSpace(reason)) {
	case FamilyFreshnessReasonInitial:
		return FamilyFreshnessReasonInitial
	case FamilyFreshnessReasonChanged:
		return FamilyFreshnessReasonChanged
	case FamilyFreshnessReasonShortCircuit:
		return FamilyFreshnessReasonShortCircuit
	case FamilyFreshnessReasonMaxSkipCount:
		return FamilyFreshnessReasonMaxSkipCount
	case FamilyFreshnessReasonMaxSkipAge:
		return FamilyFreshnessReasonMaxSkipAge
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

func parseFamilyFreshnessInt(value string) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed < 0 {
		return 0
	}
	return parsed
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
