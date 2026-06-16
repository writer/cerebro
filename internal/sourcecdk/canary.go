package sourcecdk

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

const canaryCheckpointMode = "metadata_canary"

const (
	CanaryKindKey       = "canary_kind"
	CanaryResourceIDKey = "canary_resource_id"
	CanaryObservedAtKey = "canary_observed_at"
	CanaryUpdatedAtKey  = "canary_updated_at"
	CanaryHashKey       = "canary_hash"
	CanaryConfidenceKey = "canary_confidence"
	ManifestVersionKey  = "manifest_version"

	CanaryConfigHashKey           = "canary_config_hash"
	CanaryFirstSkippedKey         = "canary_first_skipped_at"
	CanaryLastSkippedKey          = "canary_last_skipped_at"
	CanarySkipCountKey            = "canary_skip_count"
	CanaryReconciledAtKey         = "canary_reconciled_at"
	CanaryConfidenceHeuristic     = "heuristic"
	CanaryConfidenceAuthoritative = "authoritative"
)

// CanaryReconciliationPolicy controls when a matching metadata canary may
// short-circuit and when it must force a normal reconciliation.
type CanaryReconciliationPolicy struct {
	Confidence             string
	MaxSkipDuration        time.Duration
	MaxConsecutiveSkips    int
	ReconciliationInterval time.Duration
	ManifestVersion        string
	ConfigHash             string
	Now                    time.Time
}

// FingerprintCheckpoint creates a checkpoint that stores metadata canary state
// in CursorEnvelope.Extra without requiring a SourceCheckpoint proto change.
func FingerprintCheckpoint(source, family string, watermark time.Time, metadata map[string]string) *cerebrov1.SourceCheckpoint {
	source = strings.TrimSpace(source)
	family = strings.TrimSpace(family)
	if source == "" || family == "" {
		return nil
	}
	metadata = normalizedCursorMap(metadata)
	if watermark.IsZero() && len(metadata) == 0 {
		return nil
	}
	envelope := CursorEnvelope{
		Source:              source,
		Family:              family,
		Mode:                canaryCheckpointMode,
		ResumableCheckpoint: true,
		Extra:               metadata,
	}
	if !watermark.IsZero() {
		SetCursorWatermark(&envelope, watermark)
	}
	opaque, err := EncodeCursorEnvelope(envelope)
	if err != nil {
		return nil
	}
	checkpoint := &cerebrov1.SourceCheckpoint{CursorOpaque: opaque}
	if !watermark.IsZero() {
		checkpoint.Watermark = timestamppb.New(watermark.UTC())
	}
	return checkpoint
}

// CheckpointFingerprint returns a cloned metadata canary map from checkpoint
// when its cursor envelope belongs to source/family.
func CheckpointFingerprint(checkpoint *cerebrov1.SourceCheckpoint, source, family string) map[string]string {
	if checkpoint == nil {
		return nil
	}
	envelope, ok := DecodeCursorEnvelope(checkpoint.GetCursorOpaque())
	if !ok || !incrementalCursorMatches(envelope, source, family) || len(envelope.Extra) == 0 {
		return nil
	}
	return normalizedCursorMap(envelope.Extra)
}

// MergeFingerprintCheckpoint writes canary metadata into checkpoint while
// preserving any existing watermark, continuation token, and boundary IDs.
func MergeFingerprintCheckpoint(checkpoint *cerebrov1.SourceCheckpoint, source, family string, metadata map[string]string) *cerebrov1.SourceCheckpoint {
	return fingerprintCheckpointWithMetadata(checkpoint, source, family, metadata, nil)
}

// ReconciledFingerprintCheckpoint marks metadata as reconciled by a normal
// family read and resets consecutive skip history.
func ReconciledFingerprintCheckpoint(checkpoint *cerebrov1.SourceCheckpoint, source, family string, watermark time.Time, metadata map[string]string, now time.Time) *cerebrov1.SourceCheckpoint {
	if checkpoint == nil {
		checkpoint = FingerprintCheckpoint(source, family, watermark, metadata)
	}
	now = normalizeCanaryTime(now)
	metadata = normalizedCursorMap(metadata)
	if metadata == nil {
		metadata = map[string]string{}
	}
	metadata[CanaryReconciledAtKey] = now.Format(time.RFC3339Nano)
	metadata[CanarySkipCountKey] = "0"
	return fingerprintCheckpointWithMetadata(checkpoint, source, family, metadata, []string{
		CanaryFirstSkippedKey,
		CanaryLastSkippedKey,
	})
}

// SkippedFingerprintCheckpoint marks metadata as short-circuited and advances
// the skip history kept in CursorEnvelope.Extra.
func SkippedFingerprintCheckpoint(checkpoint *cerebrov1.SourceCheckpoint, source, family string, metadata map[string]string, now time.Time) *cerebrov1.SourceCheckpoint {
	stored := CheckpointFingerprint(checkpoint, source, family)
	now = normalizeCanaryTime(now)
	metadata = normalizedCursorMap(metadata)
	if metadata == nil {
		metadata = map[string]string{}
	}
	if stored != nil {
		if first := strings.TrimSpace(stored[CanaryFirstSkippedKey]); first != "" {
			metadata[CanaryFirstSkippedKey] = first
		}
		metadata[CanarySkipCountKey] = strconv.Itoa(canarySkipCount(stored) + 1)
	}
	if strings.TrimSpace(metadata[CanaryFirstSkippedKey]) == "" {
		metadata[CanaryFirstSkippedKey] = now.Format(time.RFC3339Nano)
	}
	metadata[CanaryLastSkippedKey] = now.Format(time.RFC3339Nano)
	if strings.TrimSpace(metadata[CanarySkipCountKey]) == "" {
		metadata[CanarySkipCountKey] = "1"
	}
	return fingerprintCheckpointWithMetadata(checkpoint, source, family, metadata, nil)
}

// FreshnessProbeReconciliationReason returns the first guardrail reason that
// requires a normal sync for a matching freshness probe. Empty means the probe
// may short-circuit.
func FreshnessProbeReconciliationReason(metadata map[string]string, policy CanaryReconciliationPolicy) PullReconciliationReason {
	metadata = normalizedCursorMap(metadata)
	if len(metadata) == 0 {
		return PullReconciliationReasonCanaryStateMissing
	}
	if strings.TrimSpace(policy.ManifestVersion) != "" && strings.TrimSpace(metadata[ManifestVersionKey]) != strings.TrimSpace(policy.ManifestVersion) {
		return PullReconciliationReasonCanaryManifestChanged
	}
	if strings.TrimSpace(policy.ConfigHash) != "" && strings.TrimSpace(metadata[CanaryConfigHashKey]) != strings.TrimSpace(policy.ConfigHash) {
		return PullReconciliationReasonSourceConfigChanged
	}
	confidence := strings.ToLower(strings.TrimSpace(policy.Confidence))
	if confidence == "" {
		confidence = strings.ToLower(strings.TrimSpace(metadata[CanaryConfidenceKey]))
	}
	if confidence == "" {
		confidence = CanaryConfidenceHeuristic
	}
	if confidence != CanaryConfidenceHeuristic {
		return ""
	}
	now := normalizeCanaryTime(policy.Now)
	if policy.MaxConsecutiveSkips > 0 && canarySkipCount(metadata) >= policy.MaxConsecutiveSkips {
		return PullReconciliationReasonMaxConsecutiveSkips
	}
	if policy.MaxSkipDuration > 0 {
		firstSkipped := parseCanaryTime(metadata[CanaryFirstSkippedKey])
		if firstSkipped.IsZero() && canarySkipCount(metadata) > 0 {
			return PullReconciliationReasonCanaryStateMissing
		}
		if !firstSkipped.IsZero() && !now.Before(firstSkipped.Add(policy.MaxSkipDuration)) {
			return PullReconciliationReasonMaxSkipDuration
		}
	}
	if policy.ReconciliationInterval > 0 {
		reconciledAt := parseCanaryTime(metadata[CanaryReconciledAtKey])
		if reconciledAt.IsZero() {
			return PullReconciliationReasonCanaryStateMissing
		}
		if !now.Before(reconciledAt.Add(policy.ReconciliationInterval)) {
			return PullReconciliationReasonReconciliationInterval
		}
	}
	return ""
}

// FingerprintHash returns a stable SHA-256 hash for shallow provider metadata.
func FingerprintHash(values map[string]string) string {
	values = normalizedCursorMap(values)
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	hash := sha256.New()
	for _, key := range keys {
		hash.Write([]byte(key))
		hash.Write([]byte{0})
		hash.Write([]byte(values[key]))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// ConfigHash returns a stable SHA-256 hash for source runtime config values.
func ConfigHash(values map[string]string) string {
	return FingerprintHash(values)
}

func fingerprintCheckpointWithMetadata(checkpoint *cerebrov1.SourceCheckpoint, source, family string, metadata map[string]string, deleteKeys []string) *cerebrov1.SourceCheckpoint {
	source = strings.TrimSpace(source)
	family = strings.TrimSpace(family)
	if source == "" || family == "" {
		return checkpoint
	}
	next := cloneCanaryCheckpoint(checkpoint)
	if next == nil {
		return FingerprintCheckpoint(source, family, time.Time{}, metadata)
	}
	envelope, ok := DecodeCursorEnvelope(next.GetCursorOpaque())
	if !ok || !incrementalCursorMatches(envelope, source, family) {
		envelope = CursorEnvelope{
			Source:              source,
			Family:              family,
			Mode:                canaryCheckpointMode,
			ResumableCheckpoint: true,
		}
		if watermark := timestampCanaryTime(next.GetWatermark()); !watermark.IsZero() {
			SetCursorWatermark(&envelope, watermark)
		}
	}
	if strings.TrimSpace(envelope.Source) == "" {
		envelope.Source = source
	}
	if strings.TrimSpace(envelope.Family) == "" {
		envelope.Family = family
	}
	if strings.TrimSpace(envelope.Mode) == "" {
		envelope.Mode = canaryCheckpointMode
	}
	envelope.ResumableCheckpoint = true
	if envelope.Extra == nil {
		envelope.Extra = map[string]string{}
	}
	for _, key := range deleteKeys {
		delete(envelope.Extra, strings.TrimSpace(key))
	}
	for key, value := range normalizedCursorMap(metadata) {
		envelope.Extra[key] = value
	}
	envelope.Extra = normalizedCursorMap(envelope.Extra)
	opaque, err := EncodeCursorEnvelope(envelope)
	if err != nil {
		return checkpoint
	}
	next.CursorOpaque = opaque
	if next.Watermark == nil {
		if watermark := CursorWatermark(envelope); !watermark.IsZero() {
			next.Watermark = timestamppb.New(watermark.UTC())
		}
	}
	return next
}

func canarySkipCount(metadata map[string]string) int {
	count, err := strconv.Atoi(strings.TrimSpace(metadata[CanarySkipCountKey]))
	if err != nil || count < 0 {
		return 0
	}
	return count
}

func parseCanaryTime(value string) time.Time {
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

func normalizeCanaryTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().UTC()
	}
	return value.UTC()
}

func timestampCanaryTime(value *timestamppb.Timestamp) time.Time {
	if value == nil || !value.IsValid() {
		return time.Time{}
	}
	return value.AsTime().UTC()
}

func cloneCanaryCheckpoint(checkpoint *cerebrov1.SourceCheckpoint) *cerebrov1.SourceCheckpoint {
	if checkpoint == nil {
		return nil
	}
	next := &cerebrov1.SourceCheckpoint{CursorOpaque: checkpoint.GetCursorOpaque()}
	if watermark := timestampCanaryTime(checkpoint.GetWatermark()); !watermark.IsZero() {
		next.Watermark = timestamppb.New(watermark)
	}
	return next
}
