// Package vulnpipelinetest provides an in-memory VulnerabilityPipelineStore
// for tests of the pipeline and its transports.
package vulnpipelinetest

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// Retention limits mirror the Postgres store.
const (
	batchRetention      = 500
	quarantineRetention = 2000
	heldBatchLimit      = 50
	heldBatchBytes      = 128 << 20
	heldBatchAge        = 14 * 24 * time.Hour
	heldExpiredMessage  = "held delivery expired before a mapping was activated; resend it after activation"
	resolvedRetention   = 365 * 24 * time.Hour
	observationMaxLimit = 500
)

// MemoryStore is an in-memory VulnerabilityPipelineStore with the same
// semantics the Postgres store implements.
type MemoryStore struct {
	mu           sync.Mutex
	profiles     map[string]*ports.VulnerabilityProfile
	observations map[string]*ports.VulnerabilityObservation
	batches      map[string]*ports.VulnerabilityIngestBatch
	quarantine   []*ports.VulnerabilityQuarantineRecord
	snapshots    *snapshotLocks
}

// snapshotLocks hands out one mutex per profile, like the Postgres advisory
// lock behind LockVulnerabilityProfileSnapshot.
type snapshotLocks struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func (l *snapshotLocks) lock(name string) func() {
	l.mu.Lock()
	lock, ok := l.locks[name]
	if !ok {
		lock = &sync.Mutex{}
		l.locks[name] = lock
	}
	l.mu.Unlock()
	lock.Lock()
	var once sync.Once
	return func() { once.Do(lock.Unlock) }
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		profiles:     map[string]*ports.VulnerabilityProfile{},
		observations: map[string]*ports.VulnerabilityObservation{},
		batches:      map[string]*ports.VulnerabilityIngestBatch{},
		snapshots:    &snapshotLocks{locks: map[string]*sync.Mutex{}},
	}
}

func key(parts ...string) string { return strings.Join(parts, "\x00") }

func copyProfile(profile *ports.VulnerabilityProfile) *ports.VulnerabilityProfile {
	clone := *profile
	return &clone
}

// copyBatch omits the raw payload, as the Postgres listing queries do.
func copyBatch(batch *ports.VulnerabilityIngestBatch) *ports.VulnerabilityIngestBatch {
	clone := *batch
	clone.RawPayload = nil
	return &clone
}

func (m *MemoryStore) PutVulnerabilityProfile(_ context.Context, profile *ports.VulnerabilityProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, ok := m.profiles[key(profile.TenantID, profile.ID)]
	if !ok {
		m.profiles[key(profile.TenantID, profile.ID)] = copyProfile(profile)
		return nil
	}
	if !stored.CreatedAt.Equal(profile.CreatedAt) {
		return fmt.Errorf("%w: vulnerability profile %q already exists or was replaced concurrently", ports.ErrVulnerabilityPipelineConflict, profile.ID)
	}
	next := copyProfile(profile)
	next.MappingVersion = stored.MappingVersion
	if next.MappingJSON != stored.MappingJSON || !sameTime(next.MappingActivatedAt, stored.MappingActivatedAt) {
		next.MappingVersion = stored.MappingVersion + 1
	}
	kindChanged := next.PullKind != stored.PullKind
	if !kindChanged {
		next.PullCursor = stored.PullCursor
	}
	switch {
	case next.PullKind == "":
		next.NextPullAt = nil
	case kindChanged:
	case next.NextPullAt == nil || (stored.NextPullAt != nil && stored.NextPullAt.Before(*next.NextPullAt)):
		next.NextPullAt = stored.NextPullAt
	}
	next.ClaimOwner, next.ClaimExpiresAt = stored.ClaimOwner, stored.ClaimExpiresAt
	next.LastIngestAt, next.LastStatus, next.LastError = stored.LastIngestAt, stored.LastStatus, stored.LastError
	m.profiles[key(profile.TenantID, profile.ID)] = next
	profile.MappingVersion, profile.PullCursor, profile.NextPullAt = next.MappingVersion, next.PullCursor, next.NextPullAt
	return nil
}

func sameTime(a *time.Time, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func (m *MemoryStore) GetVulnerabilityProfile(_ context.Context, tenantID string, profileID string) (*ports.VulnerabilityProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	profile, ok := m.profiles[key(tenantID, profileID)]
	if !ok {
		return nil, ports.ErrVulnerabilityProfileNotFound
	}
	return copyProfile(profile), nil
}

func (m *MemoryStore) ListVulnerabilityProfiles(_ context.Context, tenantID string) ([]*ports.VulnerabilityProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []*ports.VulnerabilityProfile{}
	for _, profile := range m.profiles {
		if profile.TenantID == tenantID {
			out = append(out, copyProfile(profile))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *MemoryStore) DeleteVulnerabilityProfile(_ context.Context, tenantID string, profileID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.profiles[key(tenantID, profileID)]; !ok {
		return ports.ErrVulnerabilityProfileNotFound
	}
	delete(m.profiles, key(tenantID, profileID))
	for id, batch := range m.batches {
		if batch.TenantID == tenantID && batch.ProfileID == profileID {
			delete(m.batches, id)
		}
	}
	kept := m.quarantine[:0]
	for _, record := range m.quarantine {
		if record.TenantID != tenantID || record.ProfileID != profileID {
			kept = append(kept, record)
		}
	}
	m.quarantine = kept
	now := time.Now().UTC()
	for _, observation := range m.observations {
		if observation.TenantID != tenantID || observation.ProfileID != profileID || observation.ResolvedAt != nil {
			continue
		}
		if openStatus(observation.Status) {
			observation.Status = "fixed"
		}
		at := now
		observation.ResolvedAt, observation.Resolution = &at, ports.VulnerabilityResolutionProfileDeleted
	}
	return nil
}

func (m *MemoryStore) SaveVulnerabilityProfileDraft(_ context.Context, tenantID string, profileID string, draft string, report string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	profile, ok := m.profiles[key(tenantID, profileID)]
	if !ok {
		return ports.ErrVulnerabilityProfileNotFound
	}
	profile.DraftMappingJSON, profile.DraftReportJSON, profile.DraftCreatedAt, profile.UpdatedAt = draft, report, &at, at
	return nil
}

func (m *MemoryStore) RecordVulnerabilityProfileIngest(_ context.Context, tenantID string, profileID string, update ports.VulnerabilityProfileIngestUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	profile, ok := m.profiles[key(tenantID, profileID)]
	if !ok {
		return ports.ErrVulnerabilityProfileNotFound
	}
	at := update.At
	profile.LastIngestAt, profile.LastStatus, profile.LastError = &at, update.Status, update.Error
	if update.PullCursor != nil {
		profile.PullCursor = *update.PullCursor
	}
	return nil
}

func (m *MemoryStore) ClaimDueVulnerabilityProfiles(_ context.Context, now time.Time, owner string, ttl time.Duration, limit int) ([]*ports.VulnerabilityProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	limit = min(max(limit, 1), 100)
	due := []*ports.VulnerabilityProfile{}
	for _, profile := range m.profiles {
		if !profile.Enabled || profile.PullKind == "" || profile.NextPullAt == nil || profile.NextPullAt.After(now) {
			continue
		}
		if profile.ClaimExpiresAt != nil && profile.ClaimExpiresAt.After(now) {
			continue
		}
		due = append(due, profile)
	}
	sort.Slice(due, func(i, j int) bool { return due[i].NextPullAt.Before(*due[j].NextPullAt) })
	out := []*ports.VulnerabilityProfile{}
	for _, profile := range due[:min(limit, len(due))] {
		expires := now.Add(ttl)
		profile.ClaimOwner, profile.ClaimExpiresAt = owner, &expires
		out = append(out, copyProfile(profile))
	}
	return out, nil
}

func (m *MemoryStore) CompleteVulnerabilityProfileClaim(_ context.Context, tenantID string, profileID string, owner string, next time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	profile, ok := m.profiles[key(tenantID, profileID)]
	if !ok || profile.ClaimOwner != owner {
		return nil
	}
	profile.ClaimOwner, profile.ClaimExpiresAt, profile.NextPullAt = "", nil, &next
	return nil
}

func (m *MemoryStore) LockVulnerabilityProfileSnapshot(_ context.Context, tenantID string, profileID string) (func(), error) {
	return m.snapshots.lock(key(tenantID, profileID)), nil
}

func (m *MemoryStore) UpsertVulnerabilityObservations(_ context.Context, observations []*ports.VulnerabilityObservation) (ports.VulnerabilityUpsertResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := ports.VulnerabilityUpsertResult{}
	for _, observation := range observations {
		if observation == nil {
			continue
		}
		clone := *observation
		if existing, ok := m.observations[key(clone.TenantID, clone.ID)]; ok {
			if existing.IngestedAt.After(clone.IngestedAt) {
				result.SkippedStale++
				continue
			}
			first := existing.FirstSeenAt
			if clone.FirstSeenAt != nil && (first == nil || clone.FirstSeenAt.Before(*first)) {
				first = clone.FirstSeenAt
			}
			clone.FirstSeenAt = first
		}
		if clone.FirstSeenAt == nil {
			at := clone.IngestedAt
			clone.FirstSeenAt = &at
		}
		m.observations[key(clone.TenantID, clone.ID)] = &clone
		result.Written++
	}
	return result, nil
}

func (m *MemoryStore) CountVulnerabilityResolutionCandidates(_ context.Context, tenantID string, profileID string, before time.Time) (ports.VulnerabilityResolutionCandidates, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	candidates := ports.VulnerabilityResolutionCandidates{}
	for _, observation := range m.observations {
		if observation.TenantID != tenantID || observation.ProfileID != profileID || observation.ResolvedAt != nil {
			continue
		}
		candidates.Unresolved++
		if observation.IngestedAt.Before(before) {
			candidates.Absent++
		}
	}
	return candidates, nil
}

func (m *MemoryStore) ResolveAbsentVulnerabilityObservations(_ context.Context, tenantID string, profileID string, before time.Time, resolvedAt time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, observation := range m.observations {
		if observation.TenantID != tenantID || observation.ProfileID != profileID || observation.ResolvedAt != nil || !observation.IngestedAt.Before(before) {
			continue
		}
		at := resolvedAt
		observation.ResolvedAt, observation.Resolution, observation.Status = &at, "absent_from_snapshot", "fixed"
		count++
	}
	return count, nil
}

type observationCursor struct {
	rank       int
	observedAt time.Time
	id         string
}

func encodeCursor(observation *ports.VulnerabilityObservation) string {
	raw := strconv.Itoa(severityRank(observation.Severity)) + "|" + strconv.FormatInt(observation.ObservedAt.UTC().UnixMicro(), 10) + "|" + observation.ID
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeCursor(raw string) (*observationCursor, error) {
	invalid := fmt.Errorf("%w: invalid vulnerability observation cursor", ports.ErrVulnerabilityPipelineInvalidRequest)
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, invalid
	}
	parts := strings.SplitN(string(decoded), "|", 3)
	if len(parts) != 3 || parts[2] == "" || len(parts[2]) > 512 {
		return nil, invalid
	}
	rank, rankErr := strconv.Atoi(parts[0])
	micros, timeErr := strconv.ParseInt(parts[1], 10, 64)
	minMicros := time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC).UnixMicro()
	maxMicros := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC).UnixMicro()
	if rankErr != nil || timeErr != nil || rank < 0 || rank > 5 || micros < minMicros || micros > maxMicros {
		return nil, invalid
	}
	return &observationCursor{rank: rank, observedAt: time.UnixMicro(micros).UTC(), id: parts[2]}, nil
}

// after reports whether observation sorts after the cursor in worst-first
// order, matching the Postgres keyset predicate.
func (c *observationCursor) after(observation *ports.VulnerabilityObservation) bool {
	rank := severityRank(observation.Severity)
	if rank != c.rank {
		return rank < c.rank
	}
	observed := observation.ObservedAt.UTC().Truncate(time.Microsecond)
	if !observed.Equal(c.observedAt) {
		return observed.Before(c.observedAt)
	}
	return observation.ID < c.id
}

func matchesFilter(observation *ports.VulnerabilityObservation, filter ports.VulnerabilityObservationFilter) bool {
	switch {
	case observation.TenantID != filter.TenantID,
		len(filter.SourceIDs) > 0 && !contains(filter.SourceIDs, observation.SourceID),
		filter.ProfileID != "" && observation.ProfileID != filter.ProfileID,
		len(filter.Severities) > 0 && !contains(filter.Severities, observation.Severity),
		len(filter.Statuses) > 0 && !contains(filter.Statuses, observation.Status),
		len(filter.Classes) > 0 && !contains(filter.Classes, observation.Class),
		filter.VulnerabilityID != "" && observation.PrimaryVulnerabilityID != filter.VulnerabilityID && !contains(observation.VulnerabilityIDs, filter.VulnerabilityID),
		filter.AssetIdentifier != "" && observation.AssetIdentifier != filter.AssetIdentifier,
		filter.CorrelationKey != "" && observation.CorrelationKey != filter.CorrelationKey:
		return false
	}
	search := strings.ToLower(strings.TrimSpace(filter.Search))
	if search == "" {
		return true
	}
	for _, field := range []string{observation.Title, observation.AssetIdentifier, observation.PackageName, observation.PrimaryVulnerabilityID} {
		if strings.Contains(strings.ToLower(field), search) {
			return true
		}
	}
	return false
}

func (m *MemoryStore) ListVulnerabilityObservations(_ context.Context, filter ports.VulnerabilityObservationFilter) (*ports.VulnerabilityObservationPage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var cursor *observationCursor
	if filter.Cursor != "" {
		decoded, err := decodeCursor(filter.Cursor)
		if err != nil {
			return nil, err
		}
		cursor = decoded
	}
	limit := filter.Limit
	if limit <= 0 || limit > observationMaxLimit {
		limit = 50
	}
	out := []*ports.VulnerabilityObservation{}
	for _, observation := range m.observations {
		if !matchesFilter(observation, filter) || (cursor != nil && !cursor.after(observation)) {
			continue
		}
		clone := *observation
		out = append(out, &clone)
	}
	less := func(a, b *ports.VulnerabilityObservation) bool {
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		if !a.ObservedAt.Equal(b.ObservedAt) {
			return a.ObservedAt.After(b.ObservedAt)
		}
		return a.ID > b.ID
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	page := &ports.VulnerabilityObservationPage{Observations: out}
	if len(out) > limit {
		page.Observations = out[:limit]
		page.NextCursor = encodeCursor(page.Observations[limit-1])
	}
	return page, nil
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func openStatus(status string) bool { return status == "open" || status == "in_progress" }

func (m *MemoryStore) GetVulnerabilityObservation(_ context.Context, tenantID string, observationID string) (*ports.VulnerabilityObservation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	observation, ok := m.observations[key(tenantID, observationID)]
	if !ok {
		return nil, ports.ErrVulnerabilityObservationNotFound
	}
	clone := *observation
	return &clone, nil
}

func (m *MemoryStore) SummarizeVulnerabilityObservations(_ context.Context, tenantID string) (*ports.VulnerabilitySummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	summary := &ports.VulnerabilitySummary{BySeverity: map[string]int{}, ByClass: map[string]int{}, ByStatus: map[string]int{}}
	sources := map[string]*ports.VulnerabilitySourceSummary{}
	distinct := map[string]bool{}
	sourcesByKey := map[string]map[string]bool{}
	for _, observation := range m.observations {
		if observation.TenantID != tenantID {
			continue
		}
		summary.Total++
		summary.ByStatus[observation.Status]++
		source := sources[observation.SourceID]
		if source == nil {
			source = &ports.VulnerabilitySourceSummary{SourceID: observation.SourceID, BySeverity: map[string]int{}}
			sources[observation.SourceID] = source
		}
		source.Total++
		if source.LastIngestAt == nil || observation.IngestedAt.After(*source.LastIngestAt) {
			at := observation.IngestedAt.UTC()
			source.LastIngestAt = &at
		}
		if !openStatus(observation.Status) {
			continue
		}
		summary.Open++
		summary.BySeverity[observation.Severity]++
		summary.ByClass[observation.Class]++
		source.Open++
		source.BySeverity[observation.Severity]++
		vulnKey := observation.PrimaryVulnerabilityID
		if vulnKey == "" {
			vulnKey = observation.CorrelationKey
		}
		distinct[vulnKey] = true
		if sourcesByKey[observation.CorrelationKey] == nil {
			sourcesByKey[observation.CorrelationKey] = map[string]bool{}
		}
		sourcesByKey[observation.CorrelationKey][observation.SourceID] = true
		if first := observation.FirstSeenAt; first != nil && (summary.OldestOpenSeenAt == nil || first.Before(*summary.OldestOpenSeenAt)) {
			at := first.UTC()
			summary.OldestOpenSeenAt = &at
		}
	}
	summary.DistinctOpenVulns = len(distinct)
	for _, ids := range sourcesByKey {
		if len(ids) > 1 {
			summary.MultiSourceOpen++
		}
	}
	for _, source := range sources {
		summary.BySource = append(summary.BySource, *source)
	}
	sort.Slice(summary.BySource, func(i, j int) bool { return summary.BySource[i].SourceID < summary.BySource[j].SourceID })
	return summary, nil
}

func (m *MemoryStore) PutVulnerabilityIngestBatch(_ context.Context, batch *ports.VulnerabilityIngestBatch) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clone := *batch
	if existing, ok := m.batches[key(batch.TenantID, batch.ID)]; ok {
		clone.Transport, clone.ContentType, clone.ContentDigest = existing.Transport, existing.ContentType, existing.ContentDigest
		clone.IdempotencyKey, clone.FullSnapshot, clone.Actor = existing.IdempotencyKey, existing.FullSnapshot, existing.Actor
		clone.ReplayOf, clone.CreatedAt = existing.ReplayOf, existing.CreatedAt
	}
	m.batches[key(batch.TenantID, batch.ID)] = &clone
	m.pruneLocked(batch.TenantID, batch.ProfileID, batch.CreatedAt)
	return nil
}

func (m *MemoryStore) profileBatchesLocked(tenantID string, profileID string, status string) []*ports.VulnerabilityIngestBatch {
	out := []*ports.VulnerabilityIngestBatch{}
	for _, batch := range m.batches {
		if batch.TenantID == tenantID && batch.ProfileID == profileID && (status == "" || batch.Status == status) {
			out = append(out, batch)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out
}

func (m *MemoryStore) pruneLocked(tenantID string, profileID string, now time.Time) {
	all := m.profileBatchesLocked(tenantID, profileID, "")
	if len(all) > batchRetention {
		cutoff := all[batchRetention].CreatedAt
		for _, batch := range all {
			if batch.Status != "pending_mapping" && batch.Status != "processing" && batch.CreatedAt.Before(cutoff) {
				delete(m.batches, key(batch.TenantID, batch.ID))
			}
		}
	}
	retained := 0
	for position, batch := range m.profileBatchesLocked(tenantID, profileID, "pending_mapping") {
		retained += len(batch.RawPayload)
		if position >= heldBatchLimit || retained > heldBatchBytes || batch.CreatedAt.Before(now.Add(-heldBatchAge)) {
			batch.Status, batch.RawPayload, batch.Error = "expired", nil, heldExpiredMessage
		}
	}
	for id, observation := range m.observations {
		if observation.TenantID == tenantID && observation.ResolvedAt != nil && observation.ResolvedAt.Before(now.Add(-resolvedRetention)) {
			delete(m.observations, id)
		}
	}
}

func (m *MemoryStore) ReserveVulnerabilityIngestBatch(_ context.Context, batch *ports.VulnerabilityIngestBatch, staleBefore time.Time) (*ports.VulnerabilityIngestBatch, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.batches {
		if existing.TenantID != batch.TenantID || existing.ProfileID != batch.ProfileID || existing.IdempotencyKey != batch.IdempotencyKey {
			continue
		}
		stale := existing.Status == "processing" && existing.CreatedAt.Before(staleBefore)
		if existing.ContentDigest != batch.ContentDigest || (existing.Status != "failed" && !stale) {
			return copyBatch(existing), false, nil
		}
		existing.IdempotencyKey = ""
		if stale {
			existing.Status, existing.Error = "failed", "abandoned before completion; the delivery was retried"
		}
	}
	clone := *batch
	m.batches[key(batch.TenantID, batch.ID)] = &clone
	return nil, true, nil
}

func (m *MemoryStore) GetVulnerabilityIngestBatchByIdempotencyKey(_ context.Context, tenantID string, profileID string, idempotencyKey string) (*ports.VulnerabilityIngestBatch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, batch := range m.batches {
		if idempotencyKey != "" && batch.TenantID == tenantID && batch.ProfileID == profileID && batch.IdempotencyKey == idempotencyKey {
			return copyBatch(batch), nil
		}
	}
	return nil, ports.ErrVulnerabilityBatchNotFound
}

func (m *MemoryStore) ListVulnerabilityIngestBatches(_ context.Context, tenantID string, profileID string, status string, limit int) ([]*ports.VulnerabilityIngestBatch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 || limit > batchRetention {
		limit = 50
	}
	out := []*ports.VulnerabilityIngestBatch{}
	for _, batch := range m.profileBatchesLocked(tenantID, profileID, status) {
		if len(out) >= limit {
			break
		}
		out = append(out, copyBatch(batch))
	}
	return out, nil
}

func (m *MemoryStore) ListHeldVulnerabilityIngestBatches(_ context.Context, tenantID string, profileID string, limit int) ([]*ports.VulnerabilityIngestBatch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 || limit > batchRetention {
		limit = 50
	}
	held := m.profileBatchesLocked(tenantID, profileID, "pending_mapping")
	out := []*ports.VulnerabilityIngestBatch{}
	for index := len(held) - 1; index >= 0 && len(out) < limit; index-- {
		out = append(out, copyBatch(held[index]))
	}
	return out, nil
}

func (m *MemoryStore) GetVulnerabilityIngestBatchPayload(_ context.Context, tenantID string, batchID string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	batch, ok := m.batches[key(tenantID, batchID)]
	if !ok {
		return nil, ports.ErrVulnerabilityBatchNotFound
	}
	return append([]byte(nil), batch.RawPayload...), nil
}

func (m *MemoryStore) PutVulnerabilityQuarantineRecords(_ context.Context, records []*ports.VulnerabilityQuarantineRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	profiles := map[string][2]string{}
	for _, record := range records {
		if record == nil {
			continue
		}
		clone := *record
		m.quarantine = append(m.quarantine, &clone)
		profiles[key(record.TenantID, record.ProfileID)] = [2]string{record.TenantID, record.ProfileID}
	}
	for _, profile := range profiles {
		count := 0
		kept := []*ports.VulnerabilityQuarantineRecord{}
		for index := len(m.quarantine) - 1; index >= 0; index-- {
			record := m.quarantine[index]
			if record.TenantID == profile[0] && record.ProfileID == profile[1] {
				count++
				if count > quarantineRetention {
					continue
				}
			}
			kept = append(kept, record)
		}
		for left, right := 0, len(kept)-1; left < right; left, right = left+1, right-1 {
			kept[left], kept[right] = kept[right], kept[left]
		}
		m.quarantine = kept
	}
	return nil
}

func (m *MemoryStore) ListVulnerabilityQuarantineRecords(_ context.Context, tenantID string, profileID string, limit int) ([]*ports.VulnerabilityQuarantineRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	out := []*ports.VulnerabilityQuarantineRecord{}
	for index := len(m.quarantine) - 1; index >= 0 && len(out) < limit; index-- {
		record := m.quarantine[index]
		if record.TenantID == tenantID && record.ProfileID == profileID {
			clone := *record
			out = append(out, &clone)
		}
	}
	return out, nil
}

// Counts reports how many observations and batches the store holds.
func (m *MemoryStore) Counts() (observations int, batches int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.observations), len(m.batches)
}

// ObservationsFor returns every stored observation of one profile.
func (m *MemoryStore) ObservationsFor(profileID string) []*ports.VulnerabilityObservation {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []*ports.VulnerabilityObservation{}
	for _, observation := range m.observations {
		if observation.ProfileID == profileID {
			clone := *observation
			out = append(out, &clone)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SourceRecordID < out[j].SourceRecordID })
	return out
}

// severityRank mirrors vulnpipeline.SeverityRank; importing the pipeline here
// would create a cycle with its internal tests.
func severityRank(severity string) int {
	return map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[severity]
}
