package organizationalgraph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	projectionAuthorityLegacy = "legacy"
	projectionAuthorityRust   = "rust"
)

var (
	ErrSourceCollectionNotFound           = errors.New("source collection receipt not found")
	ErrSourceCollectionProvenanceMismatch = errors.New("source collection receipt provenance mismatch")
	ErrProjectionAuthorityUnavailable     = errors.New("rust projection authority client is required")
	ErrProjectionAuthorityScopeMismatch   = errors.New("rust projection authority response scope does not match the request")
)

// ProjectionClient talks only to the Rust projection authority boundary.
type ProjectionClient struct {
	baseURL string
	client  *http.Client
	auth    tenantAuthenticator
}

func NewProjectionClient(baseURL, sharedSecret string, timeout time.Duration) (*ProjectionClient, error) {
	baseURL, err := normalizeBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		return nil, errors.New("rust organizational graph timeout must be positive")
	}
	auth, err := newTenantAuthenticator(sharedSecret)
	if err != nil {
		return nil, err
	}
	return &ProjectionClient{baseURL: baseURL, client: &http.Client{Timeout: timeout}, auth: auth}, nil
}

func normalizeBaseURL(raw string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	parsed, err := url.Parse(raw)
	if err != nil ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.Host == "" ||
		parsed.User != nil ||
		parsed.Opaque != "" ||
		parsed.Path != "" ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return "", errors.New("rust organizational graph URL must be an HTTP or HTTPS origin without credentials, path, query, or fragment")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

type legacyProjectedEntity struct {
	URN                    string            `json:"urn"`
	TenantID               string            `json:"tenant_id"`
	ApplicationWorkspaceID string            `json:"application_workspace_id"`
	SourceID               string            `json:"source_id"`
	RuntimeID              string            `json:"runtime_id"`
	EntityType             string            `json:"entity_type"`
	Label                  string            `json:"label"`
	Attributes             map[string]string `json:"attributes"`
}

type legacyProjectedLink struct {
	TenantID               string            `json:"tenant_id"`
	ApplicationWorkspaceID string            `json:"application_workspace_id"`
	SourceID               string            `json:"source_id"`
	RuntimeID              string            `json:"runtime_id"`
	FromURN                string            `json:"from_urn"`
	ToURN                  string            `json:"to_urn"`
	Relation               string            `json:"relation"`
	Attributes             map[string]string `json:"attributes"`
}

type legacyCleanupRequest struct {
	TenantID     string   `json:"tenant_id"`
	SourceID     string   `json:"source_id"`
	RuntimeID    string   `json:"runtime_id"`
	FindingID    string   `json:"finding_id"`
	EntityTypes  []string `json:"entity_types"`
	URNPrefixes  []string `json:"urn_prefixes"`
	OnlyIsolated bool     `json:"only_isolated"`
	Limit        uint32   `json:"limit"`
	DryRun       bool     `json:"dry_run"`
}

type legacyProjectionDelta struct {
	Entities          []legacyProjectedEntity `json:"entities"`
	Links             []legacyProjectedLink   `json:"links"`
	EntityRetractions []string                `json:"entity_retractions"`
	LinkRetractions   []legacyProjectedLink   `json:"link_retractions"`
	CleanupRequests   []legacyCleanupRequest  `json:"cleanup_requests"`
}

type legacyProjectionRequest struct {
	TenantID           string                `json:"tenant_id"`
	SourceRuntimeID    string                `json:"source_runtime_id"`
	SourceID           string                `json:"source_id"`
	FamilyID           string                `json:"family_id"`
	EventID            string                `json:"event_id"`
	ObservedAtUnixMS   int64                 `json:"observed_at_unix_ms"`
	AppendLogCommitted bool                  `json:"append_log_committed"`
	Delta              legacyProjectionDelta `json:"delta"`
}

type legacyProjectionResponse struct {
	Recorded    bool   `json:"recorded"`
	DeltaDigest string `json:"delta_digest"`
}

type sourceCollectionRequest struct {
	CollectionID          string   `json:"collection_id"`
	TenantID              string   `json:"tenant_id"`
	SourceID              string   `json:"source_id"`
	SourceRuntimeID       string   `json:"source_runtime_id"`
	StartedAtUnixMS       int64    `json:"started_at_unix_ms"`
	CompletedAtUnixMS     int64    `json:"completed_at_unix_ms"`
	Status                string   `json:"status"`
	IncompletenessReasons []string `json:"incompleteness_reasons"`
	ExpectedFamilyIDs     []string `json:"expected_family_ids"`
	ObservedFamilyIDs     []string `json:"observed_family_ids"`
	PagesRead             uint32   `json:"pages_read"`
	RecordsScanned        uint32   `json:"records_scanned"`
	RecordsAccepted       uint32   `json:"records_accepted"`
	RecordsRejected       uint32   `json:"records_rejected"`
	EntitiesProjected     uint32   `json:"entities_projected"`
	LinksProjected        uint32   `json:"links_projected"`
}

type sourceCollectionResponse struct {
	Recorded       bool   `json:"recorded"`
	ManifestDigest string `json:"manifest_digest"`
}

type sourceCollectionManifestResponse = sourceCollectionRequest

type authorityResponse struct {
	TenantID         string `json:"tenant_id"`
	SourceID         string `json:"source_id"`
	FamilyID         string `json:"family_id"`
	Authority        string `json:"authority"`
	EvidenceDigest   string `json:"evidence_digest"`
	PromotedAtUnixMS *int64 `json:"promoted_at_unix_ms"`
}

func (c *ProjectionClient) recordLegacyProjection(ctx context.Context, event *cerebrov1.EventEnvelope, delta ports.SourceProjectionDelta) error {
	familyID, err := eventFamily(event)
	if err != nil {
		return err
	}
	observedAt, err := observedAtUnixMS(event.GetOccurredAt())
	if err != nil {
		return err
	}
	runtimeID := strings.TrimSpace(event.GetAttributes()[ports.EventAttributeSourceRuntimeID])
	requestBody, err := json.Marshal(legacyProjectionRequest{
		TenantID:           strings.TrimSpace(event.GetTenantId()),
		SourceRuntimeID:    runtimeID,
		SourceID:           strings.TrimSpace(event.GetSourceId()),
		FamilyID:           familyID,
		EventID:            strings.TrimSpace(event.GetId()),
		ObservedAtUnixMS:   observedAt,
		AppendLogCommitted: true,
		Delta:              legacyDeltaRequest(delta),
	})
	if err != nil {
		return fmt.Errorf("encode Rust legacy projection request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/projections/legacy-deltas", bytes.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("build Rust legacy projection request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if err := c.auth.authorize(request, event.GetTenantId()); err != nil {
		return err
	}
	var response legacyProjectionResponse
	if err := c.doJSON(request, &response); err != nil {
		return err
	}
	if !response.Recorded || strings.TrimSpace(response.DeltaDigest) == "" {
		return errors.New("rust legacy projection receipt was not committed")
	}
	return nil
}

func (c *ProjectionClient) recordSourceCollection(ctx context.Context, manifest ports.SourceCollectionManifest) error {
	requestBody, err := json.Marshal(sourceCollectionRequest{
		CollectionID:          manifest.CollectionID,
		TenantID:              manifest.TenantID,
		SourceID:              manifest.SourceID,
		SourceRuntimeID:       manifest.RuntimeID,
		StartedAtUnixMS:       manifest.StartedAtUnixMS,
		CompletedAtUnixMS:     manifest.CompletedAtUnixMS,
		Status:                manifest.Status,
		IncompletenessReasons: stringListRequest(manifest.IncompletenessReasons),
		ExpectedFamilyIDs:     stringListRequest(manifest.ExpectedFamilyIDs),
		ObservedFamilyIDs:     stringListRequest(manifest.ObservedFamilyIDs),
		PagesRead:             manifest.PagesRead,
		RecordsScanned:        manifest.RecordsScanned,
		RecordsAccepted:       manifest.RecordsAccepted,
		RecordsRejected:       manifest.RecordsRejected,
		EntitiesProjected:     manifest.EntitiesProjected,
		LinksProjected:        manifest.LinksProjected,
	})
	if err != nil {
		return fmt.Errorf("encode Rust source collection request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/projections/collections", bytes.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("build Rust source collection request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if err := c.auth.authorize(request, manifest.TenantID); err != nil {
		return err
	}
	var response sourceCollectionResponse
	if err := c.doJSON(request, &response); err != nil {
		return err
	}
	if !response.Recorded || strings.TrimSpace(response.ManifestDigest) == "" {
		return errors.New("rust source collection receipt was not committed")
	}
	return nil
}

// GetSourceCollection loads one exact final collection manifest from the Rust
// projection ledger. It does not infer completeness from graph coverage.
func (c *ProjectionClient) GetSourceCollection(ctx context.Context, tenantID, runtimeID, collectionID string) (manifest ports.SourceCollectionManifest, err error) {
	tenantID = strings.TrimSpace(tenantID)
	runtimeID = strings.TrimSpace(runtimeID)
	collectionID = strings.TrimSpace(collectionID)
	if tenantID == "" || runtimeID == "" || collectionID == "" {
		return manifest, errors.New("tenant id, source runtime id, and source collection id are required")
	}
	query := url.Values{
		"tenant_id":         {tenantID},
		"source_runtime_id": {runtimeID},
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		c.baseURL+"/v1/projections/collections/"+url.PathEscape(collectionID)+"?"+query.Encode(),
		nil,
	)
	if err != nil {
		return manifest, fmt.Errorf("build Rust source collection read: %w", err)
	}
	if err := c.auth.authorize(request, tenantID); err != nil {
		return manifest, err
	}
	// #nosec G704 -- NewProjectionClient validates and freezes the HTTP(S)
	// origin; the collection ID is one escaped path segment.
	response, err := c.client.Do(request)
	if err != nil {
		return manifest, fmt.Errorf("call Rust projection: %w", err)
	}
	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()
	if response.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return manifest, ErrSourceCollectionNotFound
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return manifest, fmt.Errorf("rust projection returned %s", response.Status)
	}
	var decoded sourceCollectionManifestResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return manifest, fmt.Errorf("decode Rust source collection response: %w", err)
	}
	if strings.TrimSpace(decoded.TenantID) != tenantID ||
		strings.TrimSpace(decoded.SourceRuntimeID) != runtimeID ||
		strings.TrimSpace(decoded.CollectionID) != collectionID {
		return manifest, fmt.Errorf("%w: response does not match the requested tenant, runtime, and collection", ErrSourceCollectionProvenanceMismatch)
	}
	return ports.SourceCollectionManifest{
		CollectionID:          decoded.CollectionID,
		TenantID:              decoded.TenantID,
		SourceID:              decoded.SourceID,
		RuntimeID:             decoded.SourceRuntimeID,
		StartedAtUnixMS:       decoded.StartedAtUnixMS,
		CompletedAtUnixMS:     decoded.CompletedAtUnixMS,
		Status:                decoded.Status,
		IncompletenessReasons: append([]string(nil), decoded.IncompletenessReasons...),
		ExpectedFamilyIDs:     append([]string(nil), decoded.ExpectedFamilyIDs...),
		ObservedFamilyIDs:     append([]string(nil), decoded.ObservedFamilyIDs...),
		PagesRead:             decoded.PagesRead,
		RecordsScanned:        decoded.RecordsScanned,
		RecordsAccepted:       decoded.RecordsAccepted,
		RecordsRejected:       decoded.RecordsRejected,
		EntitiesProjected:     decoded.EntitiesProjected,
		LinksProjected:        decoded.LinksProjected,
	}, nil
}

func (c *ProjectionClient) authority(ctx context.Context, event *cerebrov1.EventEnvelope) (string, error) {
	if event == nil {
		return "", errors.New("source event is required")
	}
	if strings.TrimSpace(event.GetAttributes()[ports.EventAttributeSourceRuntimeID]) == "" {
		return "", errors.New("source event runtime ID is required")
	}
	if payload := event.GetPayload(); len(payload) > 0 && !json.Valid(payload) {
		return "", errors.New("source event payload must be valid JSON")
	}
	if _, err := observedAtUnixMS(event.GetOccurredAt()); err != nil {
		return "", err
	}
	familyID, err := eventFamily(event)
	if err != nil {
		return "", err
	}
	tenantID := strings.TrimSpace(event.GetTenantId())
	sourceID := strings.TrimSpace(event.GetSourceId())
	query := url.Values{
		"tenant_id": {tenantID},
		"source_id": {sourceID},
		"family_id": {familyID},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/projections/authority?"+query.Encode(), nil)
	if err != nil {
		return "", fmt.Errorf("build Rust projection authority request: %w", err)
	}
	if err := c.auth.authorize(request, event.GetTenantId()); err != nil {
		return "", err
	}
	var response authorityResponse
	if err := c.doJSON(request, &response); err != nil {
		return "", err
	}
	if strings.TrimSpace(response.TenantID) != tenantID ||
		strings.TrimSpace(response.SourceID) != sourceID ||
		strings.TrimSpace(response.FamilyID) != familyID {
		return "", ErrProjectionAuthorityScopeMismatch
	}
	if response.Authority != projectionAuthorityLegacy && response.Authority != projectionAuthorityRust {
		return "", fmt.Errorf("rust projection returned invalid authority %q", response.Authority)
	}
	return response.Authority, nil
}

func (c *ProjectionClient) doJSON(request *http.Request, target any) (err error) {
	// #nosec G704 -- NewProjectionClient validates and freezes the HTTP(S)
	// origin; request paths and query keys are constants in this package.
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("call Rust projection: %w", err)
	}
	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return fmt.Errorf("rust projection returned %s", response.Status)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode Rust projection response: %w", err)
	}
	return nil
}

// AppendLogProjector is called only after the source event has been committed
// to the append log. Go projects legacy families and records their parity
// delta. Rust-authoritative events are consumed and projected directly from
// JetStream by the Rust runtime; this path cannot submit their payload.
type AppendLogProjector struct {
	legacy            ports.SourceProjector
	rust              *ProjectionClient
	recordLegacyDelta bool
}

func NewAppendLogProjector(legacy ports.SourceProjector, rust *ProjectionClient) *AppendLogProjector {
	return &AppendLogProjector{legacy: legacy, rust: rust, recordLegacyDelta: true}
}

// NewLegacyWriteGuard prevents replay/refetch jobs from restoring a Go write
// path after a family has moved to Rust, without recording another parity delta.
func NewLegacyWriteGuard(legacy ports.SourceProjector, rust *ProjectionClient) *AppendLogProjector {
	return &AppendLogProjector{legacy: legacy, rust: rust}
}

// RecordSourceCollection retains coverage and completeness after the final
// page of a bounded sync run is committed.
func (p *AppendLogProjector) RecordSourceCollection(ctx context.Context, manifest ports.SourceCollectionManifest) error {
	if p == nil || p.rust == nil {
		return errors.New("rust projection client is required")
	}
	return p.rust.recordSourceCollection(ctx, manifest)
}

func (p *AppendLogProjector) Project(ctx context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	if p == nil || p.rust == nil {
		return ports.ProjectionResult{}, ErrProjectionAuthorityUnavailable
	}
	authority, err := p.rust.authority(ctx, event)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	if authority == projectionAuthorityRust {
		return ports.ProjectionResult{}, nil
	}
	if p.legacy == nil {
		return ports.ProjectionResult{}, nil
	}
	if projector, ok := p.legacy.(ports.SourceProjectorWithDelta); ok && p.recordLegacyDelta {
		result, delta, err := projector.ProjectWithDelta(ctx, event)
		if err != nil {
			return ports.ProjectionResult{}, err
		}
		if err := p.rust.recordLegacyProjection(ctx, event, delta); err != nil {
			return ports.ProjectionResult{}, err
		}
		return result, nil
	}
	return p.legacy.Project(ctx, event)
}

func eventFamily(event *cerebrov1.EventEnvelope) (string, error) {
	sourceID := strings.TrimSpace(event.GetSourceId())
	kind := strings.TrimSpace(event.GetKind())
	prefix := sourceID + "."
	if sourceID == "" || !strings.HasPrefix(kind, prefix) || len(kind) == len(prefix) {
		return "", fmt.Errorf("source event kind %q does not belong to source %q", kind, sourceID)
	}
	return strings.TrimPrefix(kind, prefix), nil
}

func observedAtUnixMS(value *timestamppb.Timestamp) (int64, error) {
	if value == nil || !value.IsValid() {
		return 0, errors.New("source event occurrence time is required")
	}
	observedAt := value.AsTime().UnixMilli()
	if observedAt <= 0 {
		return 0, errors.New("source event occurrence time must be positive")
	}
	return observedAt, nil
}

func cloneAttributes(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

// stringListRequest keeps an optional string list encoding as [] rather than
// null. Every such field on the Rust projection API is a `#[serde(default)]
// Vec<String>`, which accepts an absent field or [] but rejects null, and axum
// reports that rejection as 422 Unprocessable Entity.
func stringListRequest(values []string) []string {
	result := make([]string, 0, len(values))
	return append(result, values...)
}

func legacyDeltaRequest(delta ports.SourceProjectionDelta) legacyProjectionDelta {
	result := legacyProjectionDelta{
		Entities:          make([]legacyProjectedEntity, 0, len(delta.Entities)),
		Links:             make([]legacyProjectedLink, 0, len(delta.Links)),
		EntityRetractions: stringListRequest(delta.EntityRetractions),
		LinkRetractions:   make([]legacyProjectedLink, 0, len(delta.LinkRetractions)),
		CleanupRequests:   make([]legacyCleanupRequest, 0, len(delta.CleanupRequests)),
	}
	for _, entity := range delta.Entities {
		if entity == nil {
			continue
		}
		result.Entities = append(result.Entities, legacyProjectedEntity{
			URN:                    entity.URN,
			TenantID:               entity.TenantID,
			ApplicationWorkspaceID: entity.ApplicationWorkspaceID,
			SourceID:               entity.SourceID,
			RuntimeID:              entity.RuntimeID,
			EntityType:             entity.EntityType,
			Label:                  entity.Label,
			Attributes:             cloneAttributes(entity.Attributes),
		})
	}
	for _, link := range delta.Links {
		if link != nil {
			result.Links = append(result.Links, legacyLinkRequest(link))
		}
	}
	for _, link := range delta.LinkRetractions {
		if link != nil {
			result.LinkRetractions = append(result.LinkRetractions, legacyLinkRequest(link))
		}
	}
	for _, cleanup := range delta.CleanupRequests {
		result.CleanupRequests = append(result.CleanupRequests, legacyCleanupRequest{
			TenantID:     cleanup.TenantID,
			SourceID:     cleanup.SourceID,
			RuntimeID:    cleanup.RuntimeID,
			FindingID:    cleanup.FindingID,
			EntityTypes:  stringListRequest(cleanup.EntityTypes),
			URNPrefixes:  stringListRequest(cleanup.URNPrefixes),
			OnlyIsolated: cleanup.OnlyIsolated,
			Limit:        cleanup.Limit,
			DryRun:       cleanup.DryRun,
		})
	}
	return result
}

func legacyLinkRequest(link *ports.ProjectedLink) legacyProjectedLink {
	return legacyProjectedLink{
		TenantID:               link.TenantID,
		ApplicationWorkspaceID: link.ApplicationWorkspaceID,
		SourceID:               link.SourceID,
		RuntimeID:              link.RuntimeID,
		FromURN:                link.FromURN,
		ToURN:                  link.ToURN,
		Relation:               link.Relation,
		Attributes:             cloneAttributes(link.Attributes),
	}
}
