// Package vulnpipelinetest provides an in-memory VulnerabilityPipelineStore
// for tests of the pipeline and its transports.
package vulnpipelinetest

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// MemoryStore is an in-memory VulnerabilityPipelineStore with the same
// semantics the Postgres store implements.
type MemoryStore struct {
	mu           sync.Mutex
	profiles     map[string]*ports.VulnerabilityProfile
	observations map[string]*ports.VulnerabilityObservation
	batches      map[string]*ports.VulnerabilityIngestBatch
	quarantine   []*ports.VulnerabilityQuarantineRecord
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		profiles:     map[string]*ports.VulnerabilityProfile{},
		observations: map[string]*ports.VulnerabilityObservation{},
		batches:      map[string]*ports.VulnerabilityIngestBatch{},
	}
}

func key(parts ...string) string { return strings.Join(parts, "\x00") }

func copyProfile(profile *ports.VulnerabilityProfile) *ports.VulnerabilityProfile {
	clone := *profile
	return &clone
}

func (m *MemoryStore) PutVulnerabilityProfile(_ context.Context, profile *ports.VulnerabilityProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.profiles[key(profile.TenantID, profile.ID)] = copyProfile(profile)
	return nil
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
	return nil
}

func (m *MemoryStore) SaveVulnerabilityProfileDraft(_ context.Context, tenantID string, profileID string, draft string, report string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	profile, ok := m.profiles[key(tenantID, profileID)]
	if !ok {
		return ports.ErrVulnerabilityProfileNotFound
	}
	profile.DraftMappingJSON, profile.DraftReportJSON, profile.DraftCreatedAt = draft, report, &at
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
	out := []*ports.VulnerabilityProfile{}
	for _, profile := range m.profiles {
		if len(out) >= limit {
			break
		}
		if !profile.Enabled || profile.PullKind == "" || profile.NextPullAt == nil || profile.NextPullAt.After(now) {
			continue
		}
		if profile.ClaimExpiresAt != nil && profile.ClaimExpiresAt.After(now) {
			continue
		}
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

func (m *MemoryStore) UpsertVulnerabilityObservations(_ context.Context, observations []*ports.VulnerabilityObservation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, observation := range observations {
		clone := *observation
		if existing, ok := m.observations[key(clone.TenantID, clone.ID)]; ok {
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
	}
	return nil
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

func (m *MemoryStore) ListVulnerabilityObservations(_ context.Context, filter ports.VulnerabilityObservationFilter) (*ports.VulnerabilityObservationPage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []*ports.VulnerabilityObservation{}
	for _, observation := range m.observations {
		if observation.TenantID != filter.TenantID {
			continue
		}
		if len(filter.SourceIDs) > 0 && !contains(filter.SourceIDs, observation.SourceID) {
			continue
		}
		if len(filter.Severities) > 0 && !contains(filter.Severities, observation.Severity) {
			continue
		}
		if len(filter.Statuses) > 0 && !contains(filter.Statuses, observation.Status) {
			continue
		}
		if filter.VulnerabilityID != "" && observation.PrimaryVulnerabilityID != filter.VulnerabilityID && !contains(observation.VulnerabilityIDs, filter.VulnerabilityID) {
			continue
		}
		if filter.Search != "" && !strings.Contains(strings.ToLower(observation.Title+" "+observation.AssetIdentifier+" "+observation.PackageName), strings.ToLower(filter.Search)) {
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
	if filter.Cursor != "" {
		for index, observation := range out {
			if observation.ID == filter.Cursor {
				out = out[index+1:]
				break
			}
		}
	}
	page := &ports.VulnerabilityObservationPage{Observations: out}
	if filter.Limit > 0 && len(out) > filter.Limit {
		page.Observations = out[:filter.Limit]
		page.NextCursor = page.Observations[filter.Limit-1].ID
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
		if observation.Status == "open" || observation.Status == "in_progress" {
			summary.Open++
			summary.BySeverity[observation.Severity]++
			summary.ByClass[observation.Class]++
			source.Open++
			source.BySeverity[observation.Severity]++
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
	m.batches[key(batch.TenantID, batch.ID)] = &clone
	return nil
}

func (m *MemoryStore) GetVulnerabilityIngestBatchByIdempotencyKey(_ context.Context, tenantID string, profileID string, idempotencyKey string) (*ports.VulnerabilityIngestBatch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, batch := range m.batches {
		if batch.TenantID == tenantID && batch.ProfileID == profileID && batch.IdempotencyKey == idempotencyKey {
			clone := *batch
			return &clone, nil
		}
	}
	return nil, ports.ErrVulnerabilityBatchNotFound
}

func (m *MemoryStore) ListVulnerabilityIngestBatches(_ context.Context, tenantID string, profileID string, status string, limit int) ([]*ports.VulnerabilityIngestBatch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []*ports.VulnerabilityIngestBatch{}
	for _, batch := range m.batches {
		if batch.TenantID == tenantID && batch.ProfileID == profileID && (status == "" || batch.Status == status) {
			clone := *batch
			out = append(out, &clone)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemoryStore) PutVulnerabilityQuarantineRecords(_ context.Context, records []*ports.VulnerabilityQuarantineRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.quarantine = append(m.quarantine, records...)
	return nil
}

func (m *MemoryStore) ListVulnerabilityQuarantineRecords(_ context.Context, tenantID string, profileID string, limit int) ([]*ports.VulnerabilityQuarantineRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []*ports.VulnerabilityQuarantineRecord{}
	for _, record := range m.quarantine {
		if record.TenantID == tenantID && record.ProfileID == profileID && len(out) < limit {
			out = append(out, record)
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
