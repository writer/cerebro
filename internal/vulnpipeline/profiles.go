package vulnpipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// PullInput configures the optional pull transport of a profile.
type PullInput struct {
	Kind            string            `json:"kind"`
	Config          map[string]string `json:"config,omitempty"`
	IntervalSeconds int64             `json:"interval_seconds,omitempty"`
}

// ProfileInput creates or updates a profile. Nil pointer fields keep the
// current value on update.
type ProfileInput struct {
	ID          string     `json:"id"`
	SourceID    string     `json:"source_id"`
	DisplayName *string    `json:"display_name,omitempty"`
	Description *string    `json:"description,omitempty"`
	Format      *string    `json:"format,omitempty"`
	Enabled     *bool      `json:"enabled,omitempty"`
	Mapping     *Mapping   `json:"mapping,omitempty"`
	Pull        *PullInput `json:"pull,omitempty"`
	RemovePull  bool       `json:"remove_pull,omitempty"`
}

// ProfileView is the API representation of a profile. Secret pull settings
// are reported only as configured key names.
type ProfileView struct {
	TenantID           string            `json:"tenant_id"`
	ID                 string            `json:"id"`
	SourceID           string            `json:"source_id"`
	DisplayName        string            `json:"display_name"`
	Description        string            `json:"description,omitempty"`
	Format             string            `json:"format"`
	Enabled            bool              `json:"enabled"`
	Mapping            *Mapping          `json:"mapping,omitempty"`
	MappingVersion     int               `json:"mapping_version"`
	MappingActivatedBy string            `json:"mapping_activated_by,omitempty"`
	MappingActivatedAt *time.Time        `json:"mapping_activated_at,omitempty"`
	DraftMapping       *DraftView        `json:"draft_mapping,omitempty"`
	DraftCreatedAt     *time.Time        `json:"draft_created_at,omitempty"`
	Transports         []string          `json:"transports"`
	PullKind           string            `json:"pull_kind,omitempty"`
	PullConfig         map[string]string `json:"pull_config,omitempty"`
	PullSecretKeys     []string          `json:"pull_secret_keys,omitempty"`
	PullInterval       int64             `json:"pull_interval_seconds,omitempty"`
	NextPullAt         *time.Time        `json:"next_pull_at,omitempty"`
	ProfileStatusView
}

// ProfileStatusView reports profile provenance and the last delivery
// outcome. Its fields are flattened into the profile JSON object.
type ProfileStatusView struct {
	LastIngestAt *time.Time `json:"last_ingest_at,omitempty"`
	LastStatus   string     `json:"last_status,omitempty"`
	LastError    string     `json:"last_error,omitempty"`
	CreatedBy    string     `json:"created_by,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// PullKinds lists the registered pull transports.
func (s *Service) PullKinds() []string {
	kinds := make([]string, 0, len(s.pullers))
	for kind := range s.pullers {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	return kinds
}

// CreateProfile registers a new source profile.
func (s *Service) CreateProfile(ctx context.Context, tenantID string, actor string, input ProfileInput) (*ProfileView, error) {
	if !s.Available() {
		return nil, ErrUnavailable
	}
	tenantID = strings.TrimSpace(tenantID)
	sourceID := strings.ToLower(strings.TrimSpace(input.SourceID))
	profileID := strings.ToLower(strings.TrimSpace(input.ID))
	if profileID == "" {
		profileID = sourceID
	}
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	if !identifierPattern.MatchString(sourceID) {
		return nil, fmt.Errorf("%w: source_id must match %s", ErrInvalidRequest, identifierPattern.String())
	}
	if !identifierPattern.MatchString(profileID) {
		return nil, fmt.Errorf("%w: id must match %s", ErrInvalidRequest, identifierPattern.String())
	}
	if _, err := s.store.GetVulnerabilityProfile(ctx, tenantID, profileID); err == nil {
		return nil, fmt.Errorf("%w: profile %q already exists", ErrConflict, profileID)
	} else if !errors.Is(err, ports.ErrVulnerabilityProfileNotFound) {
		return nil, err
	}
	now := s.clock()
	profile := &ports.VulnerabilityProfile{
		TenantID:  tenantID,
		ID:        profileID,
		SourceID:  sourceID,
		Format:    FormatAuto,
		Enabled:   true,
		CreatedBy: clean(actor, 240),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.applyProfileInput(ctx, profile, input, actor, now); err != nil {
		return nil, err
	}
	if profile.DisplayName == "" {
		profile.DisplayName = sourceID
	}
	if err := s.store.PutVulnerabilityProfile(ctx, profile); err != nil {
		return nil, err
	}
	return s.view(profile), nil
}

// UpdateProfile changes an existing profile. The source tag is immutable so
// observations never change attribution.
func (s *Service) UpdateProfile(ctx context.Context, tenantID string, profileID string, actor string, input ProfileInput) (*ProfileView, error) {
	if !s.Available() {
		return nil, ErrUnavailable
	}
	profile, err := s.profile(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(profileID))
	if err != nil {
		return nil, err
	}
	if sourceID := strings.ToLower(strings.TrimSpace(input.SourceID)); sourceID != "" && sourceID != profile.SourceID {
		return nil, fmt.Errorf("%w: source_id cannot change", ErrInvalidRequest)
	}
	now := s.clock()
	if err := s.applyProfileInput(ctx, profile, input, actor, now); err != nil {
		return nil, err
	}
	profile.UpdatedAt = now
	if err := s.store.PutVulnerabilityProfile(ctx, profile); err != nil {
		return nil, err
	}
	return s.view(profile), nil
}

func (s *Service) applyProfileInput(ctx context.Context, profile *ports.VulnerabilityProfile, input ProfileInput, actor string, now time.Time) error {
	if input.DisplayName != nil {
		profile.DisplayName = clean(*input.DisplayName, 128)
	}
	if input.Description != nil {
		profile.Description = clean(*input.Description, 1024)
	}
	if input.Format != nil {
		format := strings.TrimSpace(*input.Format)
		if !validFormat(format) {
			return fmt.Errorf("%w: unknown format %q", ErrInvalidRequest, format)
		}
		profile.Format = format
	}
	if input.Enabled != nil {
		profile.Enabled = *input.Enabled
	}
	if input.Mapping != nil {
		if err := input.Mapping.Validate(); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidRequest, err)
		}
		profile.MappingJSON = input.Mapping.JSON()
		profile.MappingVersion++
		profile.MappingActivatedBy = clean(actor, 240)
		profile.MappingActivatedAt = &now
	}
	if input.RemovePull {
		profile.PullKind, profile.PullConfigJSON, profile.PullCursor = "", "", ""
		profile.PullIntervalSeconds, profile.NextPullAt = 0, nil
	}
	if input.Pull != nil {
		if err := s.applyPull(ctx, profile, *input.Pull, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) applyPull(ctx context.Context, profile *ports.VulnerabilityProfile, input PullInput, now time.Time) error {
	kind := strings.TrimSpace(input.Kind)
	if kind == "" {
		kind = profile.PullKind
	}
	puller, ok := s.pullers[kind]
	if !ok {
		return fmt.Errorf("%w: unknown pull kind %q", ErrInvalidRequest, kind)
	}
	config := map[string]string{}
	previous := map[string]string{}
	if kind == profile.PullKind {
		_ = json.Unmarshal([]byte(profile.PullConfigJSON), &config)
		_ = json.Unmarshal([]byte(profile.PullConfigJSON), &previous)
	} else {
		profile.PullCursor = ""
	}
	for key, value := range input.Config {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if value == "" {
			delete(config, key)
			continue
		}
		config[key] = value
	}
	scopePullConfigChange(puller, previous, config, input.Config)
	for _, key := range puller.SecretKeys() {
		if value, ok := config[key]; ok && !s.isSecretReference(value) {
			return fmt.Errorf("%w: %w: pull config %q must be a credential or secret-store reference, not a raw secret", ErrInvalidRequest, ErrRawSecret, key)
		}
	}
	if err := puller.ValidateConfig(config); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	if s.authorizeConfig != nil {
		if err := s.authorizeConfig(ctx, profile, config); err != nil {
			return err
		}
	}
	interval := time.Duration(input.IntervalSeconds) * time.Second
	if input.IntervalSeconds == 0 {
		interval = time.Duration(profile.PullIntervalSeconds) * time.Second
	}
	if interval == 0 {
		interval = defaultPullInterval
	}
	if interval < minPullInterval || interval > maxPullInterval {
		return fmt.Errorf("%w: pull interval must be between %s and %s", ErrInvalidRequest, minPullInterval, maxPullInterval)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return err
	}
	profile.PullKind = kind
	profile.PullConfigJSON = string(encoded)
	profile.PullIntervalSeconds = int64(interval / time.Second)
	if profile.NextPullAt == nil {
		next := now
		profile.NextPullAt = &next
	}
	return nil
}

// GetProfile returns one profile.
func (s *Service) GetProfile(ctx context.Context, tenantID string, profileID string) (*ProfileView, error) {
	if !s.Available() {
		return nil, ErrUnavailable
	}
	profile, err := s.profile(ctx, tenantID, profileID)
	if err != nil {
		return nil, err
	}
	return s.view(profile), nil
}

// ListProfiles returns every profile of a tenant.
func (s *Service) ListProfiles(ctx context.Context, tenantID string) ([]*ProfileView, error) {
	if !s.Available() {
		return nil, ErrUnavailable
	}
	profiles, err := s.store.ListVulnerabilityProfiles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	views := make([]*ProfileView, 0, len(profiles))
	for _, profile := range profiles {
		views = append(views, s.view(profile))
	}
	return views, nil
}

// DeleteProfile removes a profile. Its observations remain as history.
func (s *Service) DeleteProfile(ctx context.Context, tenantID string, profileID string) error {
	if !s.Available() {
		return ErrUnavailable
	}
	if err := s.store.DeleteVulnerabilityProfile(ctx, tenantID, profileID); err != nil {
		if errors.Is(err, ports.ErrVulnerabilityProfileNotFound) {
			return fmt.Errorf("%w: profile %q", ErrNotFound, profileID)
		}
		return err
	}
	return nil
}

func (s *Service) view(profile *ports.VulnerabilityProfile) *ProfileView {
	view := &ProfileView{
		TenantID:           profile.TenantID,
		ID:                 profile.ID,
		SourceID:           profile.SourceID,
		DisplayName:        profile.DisplayName,
		Description:        profile.Description,
		Format:             profile.Format,
		Enabled:            profile.Enabled,
		MappingVersion:     profile.MappingVersion,
		MappingActivatedBy: profile.MappingActivatedBy,
		MappingActivatedAt: profile.MappingActivatedAt,
		DraftMapping:       draftFromProfile(profile),
		DraftCreatedAt:     profile.DraftCreatedAt,
		Transports:         []string{TransportPushAPI, TransportMCP},
		PullKind:           profile.PullKind,
		PullInterval:       profile.PullIntervalSeconds,
		NextPullAt:         profile.NextPullAt,
		ProfileStatusView: ProfileStatusView{
			LastIngestAt: profile.LastIngestAt,
			LastStatus:   profile.LastStatus,
			LastError:    profile.LastError,
			CreatedBy:    profile.CreatedBy,
			CreatedAt:    profile.CreatedAt,
			UpdatedAt:    profile.UpdatedAt,
		},
	}
	if mapping, err := activeMapping(profile); err == nil {
		view.Mapping = mapping
	}
	if profile.PullKind != "" {
		view.Transports = append(view.Transports, TransportPull+":"+profile.PullKind)
		config := map[string]string{}
		_ = json.Unmarshal([]byte(profile.PullConfigJSON), &config)
		secrets := map[string]bool{}
		if puller, ok := s.pullers[profile.PullKind]; ok {
			for _, key := range puller.SecretKeys() {
				secrets[key] = true
			}
		}
		view.PullConfig = map[string]string{}
		for _, key := range sortedStringKeys(config) {
			if secrets[key] {
				view.PullSecretKeys = append(view.PullSecretKeys, key)
				continue
			}
			view.PullConfig[key] = config[key]
		}
	}
	return view
}

// ActivationResult reports a mapping activation and the held deliveries it
// replayed.
type ActivationResult struct {
	Profile  *ProfileView    `json:"profile"`
	Replayed []*IngestResult `json:"replayed"`
}

// ActivateMapping promotes the draft (or a supplied, reviewed mapping) to the
// active mapping, then replays deliveries held while no mapping was active.
func (s *Service) ActivateMapping(ctx context.Context, tenantID string, profileID string, actor string, reviewed *Mapping) (*ActivationResult, error) {
	if !s.Available() {
		return nil, ErrUnavailable
	}
	profile, err := s.profile(ctx, tenantID, profileID)
	if err != nil {
		return nil, err
	}
	mapping := reviewed
	if mapping == nil {
		draft := draftFromProfile(profile)
		if draft == nil || draft.Mapping == nil {
			return nil, fmt.Errorf("%w: profile has no draft mapping to activate", ErrInvalidRequest)
		}
		mapping = draft.Mapping
	}
	if err := mapping.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	now := s.clock()
	profile.MappingJSON = mapping.JSON()
	profile.MappingVersion++
	profile.MappingActivatedBy = clean(actor, 240)
	profile.MappingActivatedAt = &now
	profile.DraftMappingJSON, profile.DraftReportJSON, profile.DraftCreatedAt = "", "", nil
	if profile.Format == FormatAuto {
		profile.Format = FormatGeneric
	}
	profile.UpdatedAt = now
	if err := s.store.PutVulnerabilityProfile(ctx, profile); err != nil {
		return nil, err
	}
	replayed, err := s.replayHeld(ctx, profile, actor)
	if err != nil {
		return nil, err
	}
	return &ActivationResult{Profile: s.view(profile), Replayed: replayed}, nil
}

// maxReplayPages bounds one activation's replay loop; the store caps held
// batches per profile well below maxReplayPages*maxReplayBatches.
const maxReplayPages = 10

// replayHeld replays every held delivery oldest first, so later deliveries
// win for repeated records, paging through the held set without loading more
// than one payload at a time. Held batches without a payload are expired.
func (s *Service) replayHeld(ctx context.Context, profile *ports.VulnerabilityProfile, actor string) ([]*IngestResult, error) {
	results := []*IngestResult{}
	for range maxReplayPages {
		held, err := s.store.ListHeldVulnerabilityIngestBatches(ctx, profile.TenantID, profile.ID, maxReplayBatches)
		if err != nil {
			return results, err
		}
		if len(held) == 0 {
			return results, nil
		}
		for _, original := range held {
			result, err := s.replayHeldBatch(ctx, profile, original, actor)
			if err != nil {
				return results, err
			}
			if result != nil {
				results = append(results, result)
			}
		}
	}
	return results, nil
}

func (s *Service) replayHeldBatch(ctx context.Context, profile *ports.VulnerabilityProfile, original *ports.VulnerabilityIngestBatch, actor string) (*IngestResult, error) {
	payload, err := s.store.GetVulnerabilityIngestBatchPayload(ctx, profile.TenantID, original.ID)
	if errors.Is(err, ports.ErrVulnerabilityBatchNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 {
		original.Status = BatchExpired
		original.RawPayload = nil
		if original.Error == "" {
			original.Error = "payload was not retained; resend the delivery"
		}
		return nil, s.store.PutVulnerabilityIngestBatch(ctx, original)
	}
	batch := &ports.VulnerabilityIngestBatch{
		TenantID:      profile.TenantID,
		ID:            newID("vbat"),
		ProfileID:     profile.ID,
		Transport:     TransportReplay,
		ContentType:   original.ContentType,
		ContentDigest: original.ContentDigest,
		FullSnapshot:  original.FullSnapshot,
		Actor:         clean(actor, 240),
		ReplayOf:      original.ID,
		CreatedAt:     s.clock(),
	}
	result, err := s.process(ctx, profile, batch, payload, "", original.FullSnapshot, batch.CreatedAt)
	if err != nil && result == nil {
		return nil, err
	}
	original.Status = BatchReplayed
	original.RawPayload = nil
	original.Error = ""
	if err := s.store.PutVulnerabilityIngestBatch(ctx, original); err != nil {
		return result, err
	}
	return result, nil
}

// BatchView is the API representation of an ingest batch.
type BatchView struct {
	ID             string     `json:"id"`
	ProfileID      string     `json:"profile_id"`
	Transport      string     `json:"transport"`
	Format         string     `json:"format"`
	Status         string     `json:"status"`
	FullSnapshot   bool       `json:"full_snapshot"`
	Received       int        `json:"received"`
	Accepted       int        `json:"accepted"`
	Quarantined    int        `json:"quarantined"`
	Resolved       int        `json:"resolved"`
	DriftRatio     float64    `json:"drift_ratio"`
	Error          string     `json:"error,omitempty"`
	ContentDigest  string     `json:"content_digest"`
	IdempotencyKey string     `json:"idempotency_key,omitempty"`
	ReplayOf       string     `json:"replay_of,omitempty"`
	Actor          string     `json:"actor,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

// ListBatches returns recent deliveries for a profile.
func (s *Service) ListBatches(ctx context.Context, tenantID string, profileID string, status string, limit int) ([]BatchView, error) {
	if !s.Available() {
		return nil, ErrUnavailable
	}
	if _, err := s.profile(ctx, tenantID, profileID); err != nil {
		return nil, err
	}
	batches, err := s.store.ListVulnerabilityIngestBatches(ctx, tenantID, profileID, strings.TrimSpace(status), boundedLimit(limit, 50, 200))
	if err != nil {
		return nil, err
	}
	views := make([]BatchView, 0, len(batches))
	for _, batch := range batches {
		views = append(views, BatchView{
			ID: batch.ID, ProfileID: batch.ProfileID, Transport: batch.Transport, Format: batch.Format, Status: batch.Status,
			FullSnapshot: batch.FullSnapshot, Received: batch.Received, Accepted: batch.Accepted, Quarantined: batch.Quarantined,
			Resolved: batch.Resolved, DriftRatio: batch.DriftRatio, Error: batch.Error, ContentDigest: batch.ContentDigest,
			IdempotencyKey: batch.IdempotencyKey, ReplayOf: batch.ReplayOf, Actor: batch.Actor, CreatedAt: batch.CreatedAt, CompletedAt: batch.CompletedAt,
		})
	}
	return views, nil
}

// ListQuarantine returns records that failed normalization for a profile.
func (s *Service) ListQuarantine(ctx context.Context, tenantID string, profileID string, limit int) ([]*ports.VulnerabilityQuarantineRecord, error) {
	if !s.Available() {
		return nil, ErrUnavailable
	}
	if _, err := s.profile(ctx, tenantID, profileID); err != nil {
		return nil, err
	}
	return s.store.ListVulnerabilityQuarantineRecords(ctx, tenantID, profileID, boundedLimit(limit, 50, 200))
}

func boundedLimit(value int, fallback int, maximum int) int {
	if value <= 0 {
		return fallback
	}
	return min(value, maximum)
}
