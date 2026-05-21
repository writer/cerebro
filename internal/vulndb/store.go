package vulndb

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrSyncJobNotFound indicates that a persisted vulnerability sync job does not exist.
var ErrSyncJobNotFound = errors.New("vulndb sync job not found")

// Store persists normalized vulnerability advisory data.
type Store interface {
	UpsertVulnerability(context.Context, Vulnerability) error
	DeleteVulnerability(context.Context, string) error
	FindVulnerability(context.Context, string) (Vulnerability, bool, error)
	UpsertAffectedPackage(context.Context, AffectedPackage) error
	ReplaceAffectedPackages(context.Context, string, string, []AffectedPackage) error
	MoveAffectedPackages(context.Context, string, string) error
	CandidateAffectedPackages(context.Context, PackageQuery) ([]AffectedPackage, error)
	GetSyncState(context.Context, string) (SyncState, bool, error)
	PutSyncState(context.Context, SyncState) error
	Stats(context.Context) (Stats, error)
}

// SyncJobStore persists durable advisory feed synchronization jobs.
type SyncJobStore interface {
	PutSyncJob(context.Context, SyncJob) error
	GetSyncJob(context.Context, string) (SyncJob, bool, error)
	ListDueSyncJobs(context.Context, time.Time, int) ([]SyncJob, error)
	AcquireSyncJobLease(context.Context, string, string, time.Duration) (bool, error)
	ReleaseSyncJobLease(context.Context, string, string) error
	CompleteSyncJob(context.Context, string, string, time.Time) error
	FailSyncJob(context.Context, string, string, time.Time, error) error
}

// MemoryStore is a deterministic in-process Store useful for tests and local callers.
type MemoryStore struct {
	mu              sync.RWMutex
	vulnerabilities map[string]Vulnerability
	aliases         map[string]string
	affected        map[string]map[string]AffectedPackage
	syncStates      map[string]SyncState
	syncJobs        map[string]SyncJob
}

// NewMemoryStore constructs an empty in-memory vulnerability store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		vulnerabilities: map[string]Vulnerability{},
		aliases:         map[string]string{},
		affected:        map[string]map[string]AffectedPackage{},
		syncStates:      map[string]SyncState{},
		syncJobs:        map[string]SyncJob{},
	}
}

// UpsertVulnerability inserts or replaces a normalized advisory.
func (s *MemoryStore) UpsertVulnerability(ctx context.Context, v Vulnerability) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	v = cloneVulnerability(v)
	if v.ID == "" {
		return fmt.Errorf("vulnerability id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for alias, id := range s.aliases {
		if id == v.ID {
			delete(s.aliases, alias)
		}
	}
	s.vulnerabilities[v.ID] = v
	s.aliases[v.ID] = v.ID
	for _, alias := range v.Aliases {
		if alias != "" {
			s.aliases[alias] = v.ID
		}
	}
	return nil
}

// DeleteVulnerability removes an advisory, aliases, and affected package rows by canonical ID.
func (s *MemoryStore) DeleteVulnerability(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	id = NormalizeIdentifier(id)
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.vulnerabilities[id]; !ok {
		return nil
	}
	delete(s.vulnerabilities, id)
	for alias, vulnerabilityID := range s.aliases {
		if vulnerabilityID == id {
			delete(s.aliases, alias)
		}
	}
	for key, rows := range s.affected {
		for rowKey, row := range rows {
			if row.VulnerabilityID == id {
				delete(rows, rowKey)
			}
		}
		if len(rows) == 0 {
			delete(s.affected, key)
		}
	}
	return nil
}

// FindVulnerability returns an advisory by canonical ID or alias.
func (s *MemoryStore) FindVulnerability(ctx context.Context, idOrAlias string) (Vulnerability, bool, error) {
	if err := ctx.Err(); err != nil {
		return Vulnerability{}, false, err
	}
	lookup := NormalizeIdentifier(idOrAlias)
	if lookup == "" {
		return Vulnerability{}, false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.aliases[lookup]
	if !ok {
		return Vulnerability{}, false, nil
	}
	v, ok := s.vulnerabilities[id]
	if !ok {
		return Vulnerability{}, false, nil
	}
	return cloneVulnerability(v), true, nil
}

// UpsertAffectedPackage inserts or replaces an affected package row.
func (s *MemoryStore) UpsertAffectedPackage(ctx context.Context, pkg AffectedPackage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	pkg, err := normalizeAffectedPackage(pkg)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := packageKey(pkg.Ecosystem, pkg.PackageName)
	if s.affected[key] == nil {
		s.affected[key] = map[string]AffectedPackage{}
	}
	s.affected[key][affectedPackageKey(pkg)] = pkg
	return nil
}

// ReplaceAffectedPackages replaces all affected package rows for one vulnerability/source.
func (s *MemoryStore) ReplaceAffectedPackages(ctx context.Context, vulnerabilityID string, source string, packages []AffectedPackage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	vulnerabilityID = NormalizeIdentifier(vulnerabilityID)
	source = strings.TrimSpace(source)
	if vulnerabilityID == "" {
		return fmt.Errorf("affected package vulnerability id is required")
	}
	if source == "" {
		return fmt.Errorf("affected package source is required")
	}
	normalized := make([]AffectedPackage, 0, len(packages))
	for _, pkg := range packages {
		pkg.VulnerabilityID = vulnerabilityID
		pkg.Source = source
		row, err := normalizeAffectedPackage(pkg)
		if err != nil {
			return err
		}
		normalized = append(normalized, row)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, rows := range s.affected {
		for rowKey, row := range rows {
			if row.VulnerabilityID == vulnerabilityID && (strings.TrimSpace(row.Source) == source || strings.TrimSpace(row.Source) == "") {
				delete(rows, rowKey)
			}
		}
		if len(rows) == 0 {
			delete(s.affected, key)
		}
	}
	for _, pkg := range normalized {
		key := packageKey(pkg.Ecosystem, pkg.PackageName)
		if s.affected[key] == nil {
			s.affected[key] = map[string]AffectedPackage{}
		}
		s.affected[key][affectedPackageKey(pkg)] = pkg
	}
	return nil
}

// MoveAffectedPackages reassigns all affected package rows from one advisory ID to another.
func (s *MemoryStore) MoveAffectedPackages(ctx context.Context, fromID string, toID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fromID = NormalizeIdentifier(fromID)
	toID = NormalizeIdentifier(toID)
	if fromID == "" || toID == "" || fromID == toID {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, rows := range s.affected {
		moved := []AffectedPackage{}
		for rowKey, row := range rows {
			if row.VulnerabilityID != fromID {
				continue
			}
			delete(rows, rowKey)
			row.VulnerabilityID = toID
			moved = append(moved, row)
		}
		for _, row := range moved {
			rows[affectedPackageKey(row)] = row
		}
		if len(rows) == 0 {
			delete(s.affected, key)
		}
	}
	return nil
}

// CandidateAffectedPackages returns all advisory package rows for an ecosystem/name pair.
func (s *MemoryStore) CandidateAffectedPackages(ctx context.Context, query PackageQuery) ([]AffectedPackage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	names := PackageLookupNames(query.Ecosystem, query.Name)
	if len(names) == 0 {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	merged := map[string]AffectedPackage{}
	for _, name := range names {
		for rowKey, row := range s.affected[packageKey(query.Ecosystem, name)] {
			merged[rowKey] = row
		}
	}
	keys := make([]string, 0, len(merged))
	for rowKey := range merged {
		keys = append(keys, rowKey)
	}
	sort.Strings(keys)
	out := make([]AffectedPackage, 0, len(keys))
	for _, rowKey := range keys {
		out = append(out, merged[rowKey])
	}
	return out, nil
}

// GetSyncState returns feed synchronization progress by logical source label.
func (s *MemoryStore) GetSyncState(ctx context.Context, source string) (SyncState, bool, error) {
	if err := ctx.Err(); err != nil {
		return SyncState{}, false, err
	}
	source = normalizeSource(source)
	if source == "" {
		return SyncState{}, false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.syncStates[source]
	return state, ok, nil
}

// PutSyncState records feed synchronization progress by logical source label.
func (s *MemoryStore) PutSyncState(ctx context.Context, state SyncState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	state.Source = normalizeSource(state.Source)
	if state.Source == "" {
		return fmt.Errorf("sync state source is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncStates[state.Source] = state
	return nil
}

// Stats returns counts for persisted advisory data.
func (s *MemoryStore) Stats(ctx context.Context) (Stats, error) {
	if err := ctx.Err(); err != nil {
		return Stats{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, rows := range s.affected {
		count += len(rows)
	}
	return Stats{
		Vulnerabilities:  len(s.vulnerabilities),
		AffectedPackages: count,
		SyncSources:      len(s.syncStates),
		SyncJobs:         len(s.syncJobs),
	}, nil
}

// PutSyncJob upserts a durable advisory feed synchronization job.
func (s *MemoryStore) PutSyncJob(ctx context.Context, job SyncJob) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	job = normalizeSyncJob(job)
	if job.ID == "" {
		return fmt.Errorf("sync job id is required")
	}
	if job.Source == "" {
		return fmt.Errorf("sync job source is required")
	}
	if !IsSupportedFeedSource(job.Source) {
		return fmt.Errorf("unsupported vulndb feed source %q", job.Source)
	}
	if job.FeedURL == "" {
		return fmt.Errorf("sync job feed url is required")
	}
	if job.Interval <= 0 {
		return fmt.Errorf("sync job interval must be positive")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.syncJobs[job.ID]; ok {
		if job.LeaseOwner == "" {
			job.LeaseOwner = existing.LeaseOwner
			job.LeaseExpiresAt = existing.LeaseExpiresAt
		}
		if job.LastStartedAt.IsZero() {
			job.LastStartedAt = existing.LastStartedAt
		}
		if job.LastFinishedAt.IsZero() {
			job.LastFinishedAt = existing.LastFinishedAt
		}
		if job.LastSuccessAt.IsZero() {
			job.LastSuccessAt = existing.LastSuccessAt
		}
		if job.NextRunAt.IsZero() {
			job.NextRunAt = existing.NextRunAt
		}
		if job.LastError == "" {
			job.LastError = existing.LastError
		}
		if job.Runs == 0 {
			job.Runs = existing.Runs
		}
	}
	s.syncJobs[job.ID] = job
	return nil
}

// GetSyncJob returns a durable advisory feed synchronization job.
func (s *MemoryStore) GetSyncJob(ctx context.Context, id string) (SyncJob, bool, error) {
	if err := ctx.Err(); err != nil {
		return SyncJob{}, false, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return SyncJob{}, false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	job, ok := s.syncJobs[id]
	return job, ok, nil
}

// ListDueSyncJobs returns sync jobs whose next run is due and whose lease is free or expired.
func (s *MemoryStore) ListDueSyncJobs(ctx context.Context, now time.Time, limit int) ([]SyncJob, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	jobs := make([]SyncJob, 0, len(s.syncJobs))
	for _, job := range s.syncJobs {
		if !job.LeaseExpiresAt.IsZero() && job.LeaseExpiresAt.After(now) {
			continue
		}
		if !job.NextRunAt.IsZero() && job.NextRunAt.After(now) {
			continue
		}
		jobs = append(jobs, job)
	}
	sort.Slice(jobs, func(i, j int) bool {
		left := jobs[i]
		right := jobs[j]
		if left.NextRunAt.IsZero() != right.NextRunAt.IsZero() {
			return left.NextRunAt.IsZero()
		}
		if !left.NextRunAt.Equal(right.NextRunAt) {
			return left.NextRunAt.Before(right.NextRunAt)
		}
		return left.ID < right.ID
	})
	if limit > 0 && len(jobs) > limit {
		jobs = jobs[:limit]
	}
	return jobs, nil
}

// AcquireSyncJobLease leases a sync job for a worker.
func (s *MemoryStore) AcquireSyncJobLease(ctx context.Context, id string, owner string, ttl time.Duration) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	id = strings.TrimSpace(id)
	owner = strings.TrimSpace(owner)
	if id == "" {
		return false, fmt.Errorf("sync job id is required")
	}
	if owner == "" {
		return false, fmt.Errorf("sync job lease owner is required")
	}
	if ttl <= 0 {
		return false, fmt.Errorf("sync job lease ttl must be positive")
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.syncJobs[id]
	if !ok {
		return false, fmt.Errorf("%w: %s", ErrSyncJobNotFound, id)
	}
	if !job.LeaseExpiresAt.IsZero() && job.LeaseExpiresAt.After(now) && job.LeaseOwner != owner {
		return false, nil
	}
	job.LeaseOwner = owner
	job.LeaseExpiresAt = now.Add(ttl)
	job.LastStartedAt = now
	s.syncJobs[id] = job
	return true, nil
}

// ReleaseSyncJobLease releases a sync job lease held by owner.
func (s *MemoryStore) ReleaseSyncJobLease(ctx context.Context, id string, owner string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	owner = strings.TrimSpace(owner)
	if id == "" {
		return fmt.Errorf("sync job id is required")
	}
	if owner == "" {
		return fmt.Errorf("sync job lease owner is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.syncJobs[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrSyncJobNotFound, id)
	}
	if job.LeaseOwner == owner {
		job.LeaseOwner = ""
		job.LeaseExpiresAt = time.Time{}
		s.syncJobs[id] = job
	}
	return nil
}

// CompleteSyncJob records a successful sync job run.
func (s *MemoryStore) CompleteSyncJob(ctx context.Context, id string, owner string, nextRunAt time.Time) error {
	return s.finishSyncJob(ctx, id, owner, nextRunAt, nil)
}

// FailSyncJob records a failed sync job run.
func (s *MemoryStore) FailSyncJob(ctx context.Context, id string, owner string, nextRunAt time.Time, syncErr error) error {
	if syncErr == nil {
		syncErr = errors.New("sync job failed")
	}
	return s.finishSyncJob(ctx, id, owner, nextRunAt, syncErr)
}

func (s *MemoryStore) finishSyncJob(ctx context.Context, id string, owner string, nextRunAt time.Time, syncErr error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	owner = strings.TrimSpace(owner)
	if id == "" {
		return fmt.Errorf("sync job id is required")
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.syncJobs[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrSyncJobNotFound, id)
	}
	if job.LeaseOwner != "" && owner != "" && job.LeaseOwner != owner {
		return fmt.Errorf("sync job %q is leased by another owner", id)
	}
	job.LastFinishedAt = now
	job.Runs++
	if syncErr == nil {
		job.LastSuccessAt = now
		job.LastError = ""
	} else {
		job.LastError = syncErr.Error()
	}
	job.LeaseOwner = ""
	job.LeaseExpiresAt = time.Time{}
	if nextRunAt.IsZero() && job.Interval > 0 {
		nextRunAt = now.Add(job.Interval)
	}
	job.NextRunAt = nextRunAt
	s.syncJobs[id] = job
	return nil
}

func normalizeAffectedPackage(pkg AffectedPackage) (AffectedPackage, error) {
	pkg.VulnerabilityID = NormalizeIdentifier(pkg.VulnerabilityID)
	pkg.Source = strings.TrimSpace(pkg.Source)
	pkg.Ecosystem = normalizeEcosystem(pkg.Ecosystem)
	pkg.PackageName = strings.TrimSpace(pkg.PackageName)
	if pkg.VulnerabilityID == "" {
		return AffectedPackage{}, fmt.Errorf("affected package vulnerability id is required")
	}
	if pkg.Ecosystem == "" {
		return AffectedPackage{}, fmt.Errorf("affected package ecosystem is required")
	}
	if pkg.PackageName == "" {
		return AffectedPackage{}, fmt.Errorf("affected package name is required")
	}
	return pkg, nil
}

func affectedPackageKey(pkg AffectedPackage) string {
	parts := []string{
		pkg.VulnerabilityID,
		strings.TrimSpace(pkg.Source),
		normalizeEcosystem(pkg.Ecosystem),
		normalizePackageName(pkg.PackageName),
		strings.TrimSpace(pkg.RangeType),
		strings.TrimSpace(pkg.Introduced),
		strings.TrimSpace(pkg.IntroducedExclusive),
		strings.TrimSpace(pkg.Fixed),
		strings.TrimSpace(pkg.LastAffected),
		strings.TrimSpace(pkg.VulnerableVersion),
		strings.TrimSpace(pkg.DistroName),
		strings.TrimSpace(pkg.DistroVersion),
	}
	return strings.Join(parts, "\x00")
}
