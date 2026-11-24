// Package vulnpipeline normalizes vulnerability data from any scanner into one
// observation shape, tagged with the source that reported it.
//
// Every transport (push API, MCP, S3, scheduled API pulls) hands raw payloads
// to the same Service.Ingest path. Well-known formats use builtin adapters;
// anything else goes through a per-profile declarative mapping that the
// pipeline learns from the first delivery and an operator activates.
package vulnpipeline

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// Transports that deliver payloads into the pipeline.
const (
	TransportPushAPI = "push_api"
	TransportMCP     = "mcp"
	TransportPull    = "pull"
	TransportReplay  = "replay"
)

// Batch statuses.
const (
	BatchCompleted      = "completed"
	BatchPartial        = "partial"
	BatchQuarantined    = "quarantined"
	BatchPendingMapping = "pending_mapping"
	BatchFailed         = "failed"
	BatchReplayed       = "replayed"
)

// Profile ingest statuses.
const (
	ProfileStatusHealthy        = "healthy"
	ProfileStatusDrift          = "drift"
	ProfileStatusPendingMapping = "pending_mapping"
	ProfileStatusFailed         = "failed"
)

const (
	// MaxPayloadBytes bounds one delivery from any transport.
	MaxPayloadBytes = 32 << 20
	// maxRetainedPayloadBytes bounds payloads kept for replay while a learned
	// mapping waits for activation.
	maxRetainedPayloadBytes = 8 << 20
	maxNDJSONLines          = 200000
	maxQuarantinePerBatch   = 200
	maxQuarantineRecord     = 16 * 1024
	upsertChunk             = 500
	driftThreshold          = 0.2
	maxProblemSamples       = 5
	maxReplayBatches        = 50
	defaultPullInterval     = time.Hour
	minPullInterval         = 5 * time.Minute
	maxPullInterval         = 7 * 24 * time.Hour
	claimTTL                = 30 * time.Minute
	claimBatch              = 10
)

var (
	// ErrUnavailable reports that no vulnerability store is configured.
	ErrUnavailable = errors.New("vulnerability pipeline is not configured")
	// ErrInvalidRequest reports a caller error.
	ErrInvalidRequest = errors.New("invalid vulnerability pipeline request")
	// ErrInvalidPayload reports a payload that could not be decoded.
	ErrInvalidPayload = errors.New("invalid vulnerability payload")
	// ErrConflict reports an idempotency key reused with a different payload,
	// or a duplicate profile.
	ErrConflict = errors.New("vulnerability pipeline conflict")
	// ErrNotFound reports a missing profile, observation, or batch.
	ErrNotFound = errors.New("vulnerability pipeline record not found")
	// ErrRawSecret reports pull config that carries a secret value instead of
	// a credential or secret-store reference.
	ErrRawSecret = errors.New("pull config secrets must be references")
	// ErrUnsafePageURL reports a pull pagination URL that leaves the
	// configured API origin.
	ErrUnsafePageURL = errors.New("pull page url leaves the configured origin")

	identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,63}$`)
)

// ConfigResolver resolves credential and secret references in pull config.
type ConfigResolver func(ctx context.Context, profile *ports.VulnerabilityProfile, values map[string]string) (map[string]string, error)

// ConfigAuthorizer checks that the caller may store the given pull config,
// for example that a tenant-scoped caller does not reference process secrets.
type ConfigAuthorizer func(ctx context.Context, profile *ports.VulnerabilityProfile, values map[string]string) error

// SecretScopeSourceID is the source ID pull credentials are scoped to in
// secret stores; the profile ID is the runtime ID.
const SecretScopeSourceID = "vulnerability-pull"

// Options configures a Service.
type Options struct {
	Now               func() time.Time
	Pullers           []Puller
	ResolveConfig     ConfigResolver
	AuthorizeConfig   ConfigAuthorizer
	IsSecretReference func(string) bool
}

// Service is the vulnerability normalization pipeline.
type Service struct {
	store             ports.VulnerabilityPipelineStore
	now               func() time.Time
	pullers           map[string]Puller
	resolveConfig     ConfigResolver
	authorizeConfig   ConfigAuthorizer
	isSecretReference func(string) bool
}

// NewService builds a pipeline over the optional store capability. A nil
// store yields a service whose operations return ErrUnavailable.
func NewService(store ports.VulnerabilityPipelineStore, options Options) *Service {
	service := &Service{
		store:             store,
		now:               options.Now,
		pullers:           map[string]Puller{},
		resolveConfig:     options.ResolveConfig,
		authorizeConfig:   options.AuthorizeConfig,
		isSecretReference: options.IsSecretReference,
	}
	if service.now == nil {
		service.now = time.Now
	}
	if service.isSecretReference == nil {
		service.isSecretReference = func(string) bool { return false }
	}
	for _, puller := range options.Pullers {
		if puller != nil {
			service.pullers[puller.Kind()] = puller
		}
	}
	return service
}

// Available reports whether the pipeline has a store.
func (s *Service) Available() bool {
	return s != nil && s.store != nil
}

func (s *Service) clock() time.Time {
	return s.now().UTC()
}

// IngestRequest is one delivery from any transport.
type IngestRequest struct {
	TenantID       string
	ProfileID      string
	Transport      string
	ContentType    string
	IdempotencyKey string
	Actor          string
	Format         string
	FullSnapshot   bool
	Payload        []byte
}

// IngestResult summarizes one processed delivery.
type IngestResult struct {
	BatchID      string     `json:"batch_id"`
	ProfileID    string     `json:"profile_id"`
	SourceID     string     `json:"source_id"`
	Format       string     `json:"format"`
	Status       string     `json:"status"`
	Received     int        `json:"received"`
	Accepted     int        `json:"accepted"`
	Quarantined  int        `json:"quarantined"`
	Resolved     int        `json:"resolved"`
	DriftRatio   float64    `json:"drift_ratio"`
	Replayed     bool       `json:"idempotent_replay"`
	Problems     []string   `json:"problems,omitempty"`
	DraftMapping *DraftView `json:"draft_mapping,omitempty"`
	Error        string     `json:"error,omitempty"`
}

// DraftView is a learned mapping awaiting review.
type DraftView struct {
	Mapping *Mapping        `json:"mapping"`
	Report  InferenceReport `json:"report"`
}

// Ingest normalizes one delivery and persists its observations.
func (s *Service) Ingest(ctx context.Context, request IngestRequest) (*IngestResult, error) {
	if !s.Available() {
		return nil, ErrUnavailable
	}
	tenantID := strings.TrimSpace(request.TenantID)
	profileID := strings.TrimSpace(request.ProfileID)
	if tenantID == "" || profileID == "" {
		return nil, fmt.Errorf("%w: tenant_id and profile_id are required", ErrInvalidRequest)
	}
	if err := validatePayload(request); err != nil {
		return nil, err
	}
	profile, err := s.profile(ctx, tenantID, profileID)
	if err != nil {
		return nil, err
	}
	return s.ingest(ctx, profile, request)
}

func validatePayload(request IngestRequest) error {
	if len(request.Payload) == 0 {
		return fmt.Errorf("%w: payload is empty", ErrInvalidPayload)
	}
	if len(request.Payload) > MaxPayloadBytes {
		return fmt.Errorf("%w: payload exceeds %d bytes", ErrInvalidPayload, MaxPayloadBytes)
	}
	if request.Format != "" && !validFormat(request.Format) {
		return fmt.Errorf("%w: unknown format %q", ErrInvalidRequest, request.Format)
	}
	return nil
}

func (s *Service) ingest(ctx context.Context, profile *ports.VulnerabilityProfile, request IngestRequest) (*IngestResult, error) {
	if err := validatePayload(request); err != nil {
		return nil, err
	}
	tenantID, profileID := profile.TenantID, profile.ID
	key := clean(request.IdempotencyKey, 200)
	if !profile.Enabled {
		return nil, fmt.Errorf("%w: profile %q is disabled", ErrInvalidRequest, profileID)
	}
	digest := payloadDigest(request.Payload)
	if key != "" {
		existing, err := s.store.GetVulnerabilityIngestBatchByIdempotencyKey(ctx, tenantID, profileID, key)
		switch {
		case err == nil && existing != nil:
			if existing.ContentDigest != digest {
				return nil, fmt.Errorf("%w: idempotency key was used with a different payload", ErrConflict)
			}
			result := resultFromBatch(existing, profile)
			result.Replayed = true
			return result, nil
		case err != nil && !errors.Is(err, ports.ErrVulnerabilityBatchNotFound):
			return nil, err
		}
	}
	transport := request.Transport
	if transport == "" {
		transport = TransportPushAPI
	}
	batch := &ports.VulnerabilityIngestBatch{
		TenantID:       tenantID,
		ID:             newID("vbat"),
		ProfileID:      profileID,
		Transport:      transport,
		ContentType:    clean(request.ContentType, 128),
		ContentDigest:  digest,
		IdempotencyKey: key,
		FullSnapshot:   request.FullSnapshot,
		Actor:          clean(request.Actor, 240),
		CreatedAt:      s.clock(),
	}
	return s.process(ctx, profile, batch, request.Payload, request.Format, request.FullSnapshot, batch.CreatedAt)
}

func (s *Service) process(ctx context.Context, profile *ports.VulnerabilityProfile, batch *ports.VulnerabilityIngestBatch, payload []byte, formatOverride string, fullSnapshot bool, ingestedAt time.Time) (*IngestResult, error) {
	document, err := decodeDocument(payload, batch.ContentType)
	if err != nil {
		return s.failBatch(ctx, profile, batch, fmt.Errorf("%w: %w", ErrInvalidPayload, err))
	}
	format := chooseFormat(profile.Format, formatOverride, document)
	batch.Format = format
	var drafts []Draft
	mappingVersion := 0
	if format == FormatGeneric {
		mapping, err := activeMapping(profile)
		if err != nil {
			return s.failBatch(ctx, profile, batch, err)
		}
		if mapping == nil {
			return s.holdForMapping(ctx, profile, batch, document, payload)
		}
		drafts = mapping.apply(document)
		mappingVersion = profile.MappingVersion
	} else {
		drafts, err = normalizeBuiltin(format, document)
		if err != nil {
			return s.failBatch(ctx, profile, batch, fmt.Errorf("%w: %w", ErrInvalidPayload, err))
		}
	}

	finalize := finalizeContext{
		TenantID:       profile.TenantID,
		ProfileID:      profile.ID,
		SourceID:       profile.SourceID,
		Format:         format,
		BatchID:        batch.ID,
		MappingVersion: mappingVersion,
		IngestedAt:     ingestedAt,
	}
	observations := []*ports.VulnerabilityObservation{}
	byID := map[string]int{}
	quarantine := []*ports.VulnerabilityQuarantineRecord{}
	problems := []string{}
	for _, draft := range drafts {
		observation, problem := finalizeDraft(draft, finalize)
		if problem != "" {
			batch.Quarantined++
			if len(problems) < maxProblemSamples {
				problems = append(problems, problem)
			}
			if len(quarantine) < maxQuarantinePerBatch {
				quarantine = append(quarantine, &ports.VulnerabilityQuarantineRecord{
					TenantID: profile.TenantID, ID: newID("vqr"), BatchID: batch.ID, ProfileID: profile.ID,
					Reason: problem, RecordJSON: rawRecordJSON(draft.Raw), CreatedAt: ingestedAt,
				})
			}
			continue
		}
		// A delivery can repeat one source record; the last copy wins.
		if index, seen := byID[observation.ID]; seen {
			observations[index] = observation
			continue
		}
		byID[observation.ID] = len(observations)
		observations = append(observations, observation)
	}
	batch.Received = len(drafts)
	batch.Accepted = len(observations)
	if batch.Received > 0 {
		batch.DriftRatio = round2(float64(batch.Quarantined) / float64(batch.Received))
	}
	for start := 0; start < len(observations); start += upsertChunk {
		end := min(start+upsertChunk, len(observations))
		if err := s.store.UpsertVulnerabilityObservations(ctx, observations[start:end]); err != nil {
			return s.failBatch(ctx, profile, batch, fmt.Errorf("persist observations: %w", err))
		}
	}
	if len(quarantine) > 0 {
		if err := s.store.PutVulnerabilityQuarantineRecords(ctx, quarantine); err != nil {
			return s.failBatch(ctx, profile, batch, fmt.Errorf("persist quarantine: %w", err))
		}
	}
	// A snapshot that normalized nothing from a learned mapping more likely
	// means the mapping broke than that every vulnerability was fixed.
	snapshotTrusted := batch.Accepted > 0 || (batch.Received == 0 && format != FormatGeneric)
	if fullSnapshot && snapshotTrusted {
		resolved, err := s.store.ResolveAbsentVulnerabilityObservations(ctx, profile.TenantID, profile.ID, ingestedAt, ingestedAt)
		if err != nil {
			return s.failBatch(ctx, profile, batch, fmt.Errorf("resolve absent observations: %w", err))
		}
		batch.Resolved = resolved
	} else if fullSnapshot {
		problems = append(problems, "full snapshot did not resolve absent observations because no record normalized")
	}
	switch {
	case batch.Received > 0 && batch.Accepted == 0:
		batch.Status = BatchQuarantined
	case batch.Quarantined > 0:
		batch.Status = BatchPartial
	default:
		batch.Status = BatchCompleted
	}
	completed := s.clock()
	batch.CompletedAt = &completed
	if err := s.store.PutVulnerabilityIngestBatch(ctx, batch); err != nil {
		return nil, err
	}
	status := ProfileStatusHealthy
	if format == FormatGeneric && batch.DriftRatio > driftThreshold {
		status = ProfileStatusDrift
	}
	if err := s.store.RecordVulnerabilityProfileIngest(ctx, profile.TenantID, profile.ID, ports.VulnerabilityProfileIngestUpdate{At: completed, Status: status}); err != nil {
		return nil, err
	}
	result := resultFromBatch(batch, profile)
	result.Problems = problems
	return result, nil
}

func (s *Service) holdForMapping(ctx context.Context, profile *ports.VulnerabilityProfile, batch *ports.VulnerabilityIngestBatch, document any, payload []byte) (*IngestResult, error) {
	mapping, report := inferMapping(document)
	draft := &DraftView{Mapping: mapping, Report: report}
	if existing := draftFromProfile(profile); existing != nil && existing.Report.Confidence >= report.Confidence {
		draft = existing
	} else {
		reportJSON, _ := json.Marshal(report)
		if err := s.store.SaveVulnerabilityProfileDraft(ctx, profile.TenantID, profile.ID, mapping.JSON(), string(reportJSON), batch.CreatedAt); err != nil {
			return nil, err
		}
	}
	batch.Status = BatchPendingMapping
	batch.Format = FormatGeneric
	if len(payload) <= maxRetainedPayloadBytes {
		batch.RawPayload = payload
	} else {
		batch.Error = "payload is too large to retain until the mapping is activated; resend it after activation"
	}
	completed := s.clock()
	batch.CompletedAt = &completed
	if err := s.store.PutVulnerabilityIngestBatch(ctx, batch); err != nil {
		return nil, err
	}
	if err := s.store.RecordVulnerabilityProfileIngest(ctx, profile.TenantID, profile.ID, ports.VulnerabilityProfileIngestUpdate{At: completed, Status: ProfileStatusPendingMapping}); err != nil {
		return nil, err
	}
	result := resultFromBatch(batch, profile)
	result.DraftMapping = draft
	return result, nil
}

func (s *Service) failBatch(ctx context.Context, profile *ports.VulnerabilityProfile, batch *ports.VulnerabilityIngestBatch, cause error) (*IngestResult, error) {
	batch.Status = BatchFailed
	batch.Error = truncate(cause.Error(), 1024)
	completed := s.clock()
	batch.CompletedAt = &completed
	if err := s.store.PutVulnerabilityIngestBatch(ctx, batch); err != nil {
		return nil, errors.Join(cause, err)
	}
	if err := s.store.RecordVulnerabilityProfileIngest(ctx, profile.TenantID, profile.ID, ports.VulnerabilityProfileIngestUpdate{At: completed, Status: ProfileStatusFailed, Error: batch.Error}); err != nil {
		return nil, errors.Join(cause, err)
	}
	result := resultFromBatch(batch, profile)
	return result, cause
}

func resultFromBatch(batch *ports.VulnerabilityIngestBatch, profile *ports.VulnerabilityProfile) *IngestResult {
	return &IngestResult{
		BatchID:     batch.ID,
		ProfileID:   batch.ProfileID,
		SourceID:    profile.SourceID,
		Format:      batch.Format,
		Status:      batch.Status,
		Received:    batch.Received,
		Accepted:    batch.Accepted,
		Quarantined: batch.Quarantined,
		Resolved:    batch.Resolved,
		DriftRatio:  batch.DriftRatio,
		Error:       batch.Error,
	}
}

func chooseFormat(profileFormat string, override string, document any) string {
	for _, candidate := range []string{override, profileFormat} {
		if candidate != "" && candidate != FormatAuto {
			return candidate
		}
	}
	return detectFormat(document)
}

func activeMapping(profile *ports.VulnerabilityProfile) (*Mapping, error) {
	if strings.TrimSpace(profile.MappingJSON) == "" {
		return nil, nil
	}
	return ParseMapping(profile.MappingJSON)
}

func draftFromProfile(profile *ports.VulnerabilityProfile) *DraftView {
	if strings.TrimSpace(profile.DraftMappingJSON) == "" {
		return nil
	}
	mapping, err := ParseMapping(profile.DraftMappingJSON)
	if err != nil {
		var loose Mapping
		if json.Unmarshal([]byte(profile.DraftMappingJSON), &loose) != nil {
			return nil
		}
		mapping = &loose
	}
	view := &DraftView{Mapping: mapping}
	_ = json.Unmarshal([]byte(profile.DraftReportJSON), &view.Report)
	return view
}

// decodeDocument parses a JSON document, or newline-delimited JSON into an
// array, preserving numbers exactly.
func decodeDocument(payload []byte, contentType string) (any, error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return nil, errors.New("payload is empty")
	}
	lowerType := strings.ToLower(contentType)
	ndjson := strings.Contains(lowerType, "ndjson") || strings.Contains(lowerType, "jsonl") || strings.Contains(lowerType, "json-seq")
	if !ndjson {
		decoder := json.NewDecoder(bytes.NewReader(trimmed))
		decoder.UseNumber()
		var document any
		if err := decoder.Decode(&document); err == nil {
			if _, err := decoder.Token(); errors.Is(err, io.EOF) {
				return document, nil
			}
		} else if !bytes.Contains(trimmed, []byte("\n")) {
			return nil, fmt.Errorf("payload is not valid JSON: %w", err)
		}
	}
	scanner := bufio.NewScanner(bytes.NewReader(trimmed))
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	records := []any{}
	line := 0
	for scanner.Scan() {
		line++
		if line > maxNDJSONLines {
			return nil, fmt.Errorf("payload exceeds %d lines", maxNDJSONLines)
		}
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var record any
		if err := decoder.Decode(&record); err != nil {
			return nil, fmt.Errorf("line %d is not valid JSON: %w", line, err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func rawRecordJSON(raw any) string {
	payload, err := json.Marshal(raw)
	if err != nil {
		return ""
	}
	if len(payload) > maxQuarantineRecord {
		return truncate(string(payload), maxQuarantineRecord)
	}
	return string(payload)
}

func payloadDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func newID(prefix string) string {
	var buffer [12]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	}
	return prefix + "_" + hex.EncodeToString(buffer[:])
}

func (s *Service) profile(ctx context.Context, tenantID string, profileID string) (*ports.VulnerabilityProfile, error) {
	profile, err := s.store.GetVulnerabilityProfile(ctx, tenantID, profileID)
	if err != nil {
		if errors.Is(err, ports.ErrVulnerabilityProfileNotFound) {
			return nil, fmt.Errorf("%w: profile %q", ErrNotFound, profileID)
		}
		return nil, err
	}
	return profile, nil
}

// PreviewRequest asks the pipeline how a sample would normalize without
// persisting anything.
type PreviewRequest struct {
	Payload     []byte
	ContentType string
	Format      string
	MappingJSON string
}

// PreviewResult shows the detected format, the mapping applied (learned or
// supplied), and the first normalized observations.
type PreviewResult struct {
	Format       string                            `json:"format"`
	Mapping      *Mapping                          `json:"mapping,omitempty"`
	Report       *InferenceReport                  `json:"report,omitempty"`
	Received     int                               `json:"received"`
	Accepted     int                               `json:"accepted"`
	Quarantined  int                               `json:"quarantined"`
	Problems     []string                          `json:"problems,omitempty"`
	Observations []*ports.VulnerabilityObservation `json:"-"`
}

const maxPreviewObservations = 10

// Preview detects, learns or applies a mapping, and normalizes a sample.
func (s *Service) Preview(request PreviewRequest) (*PreviewResult, error) {
	if len(request.Payload) == 0 || len(request.Payload) > MaxPayloadBytes {
		return nil, fmt.Errorf("%w: payload must be between 1 and %d bytes", ErrInvalidPayload, MaxPayloadBytes)
	}
	if request.Format != "" && !validFormat(request.Format) {
		return nil, fmt.Errorf("%w: unknown format %q", ErrInvalidRequest, request.Format)
	}
	document, err := decodeDocument(request.Payload, request.ContentType)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPayload, err)
	}
	result := &PreviewResult{}
	var drafts []Draft
	switch {
	case strings.TrimSpace(request.MappingJSON) != "":
		mapping, err := ParseMapping(request.MappingJSON)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
		}
		result.Format = FormatGeneric
		result.Mapping = mapping
		drafts = mapping.apply(document)
	default:
		result.Format = chooseFormat("", request.Format, document)
		if result.Format == FormatGeneric {
			mapping, report := inferMapping(document)
			result.Mapping, result.Report = mapping, &report
			drafts = mapping.apply(document)
		} else {
			drafts, err = normalizeBuiltin(result.Format, document)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrInvalidPayload, err)
			}
		}
	}
	now := s.clock()
	result.Received = len(drafts)
	for _, draft := range drafts {
		observation, problem := finalizeDraft(draft, finalizeContext{TenantID: "preview", ProfileID: "preview", SourceID: "preview", Format: result.Format, IngestedAt: now})
		if problem != "" {
			result.Quarantined++
			if len(result.Problems) < maxProblemSamples {
				result.Problems = append(result.Problems, problem)
			}
			continue
		}
		result.Accepted++
		if len(result.Observations) < maxPreviewObservations {
			result.Observations = append(result.Observations, observation)
		}
	}
	return result, nil
}
