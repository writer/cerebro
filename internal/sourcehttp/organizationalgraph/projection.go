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

// ProjectionClient talks only to the Rust projection authority boundary.
type ProjectionClient struct {
	baseURL string
	client  *http.Client
}

func NewProjectionClient(baseURL string, timeout time.Duration) (*ProjectionClient, error) {
	baseURL, err := normalizeBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		return nil, errors.New("rust organizational graph timeout must be positive")
	}
	return &ProjectionClient{baseURL: baseURL, client: &http.Client{Timeout: timeout}}, nil
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

type projectEventRequest struct {
	TenantID           string            `json:"tenant_id"`
	SourceRuntimeID    string            `json:"source_runtime_id"`
	SourceID           string            `json:"source_id"`
	FamilyID           string            `json:"family_id"`
	EventID            string            `json:"event_id"`
	ObservedAtUnixMS   int64             `json:"observed_at_unix_ms"`
	AppendLogCommitted bool              `json:"append_log_committed"`
	Attributes         map[string]string `json:"attributes"`
	Payload            json.RawMessage   `json:"payload"`
}

type projectEventResponse struct {
	Authority          string  `json:"authority"`
	Projected          bool    `json:"projected"`
	GraphRevision      *uint64 `json:"graph_revision"`
	EntitiesUpserted   uint32  `json:"entities_upserted"`
	AssertionsUpserted uint32  `json:"assertions_upserted"`
}

type authorityResponse struct {
	Authority string `json:"authority"`
}

func (c *ProjectionClient) project(ctx context.Context, event *cerebrov1.EventEnvelope) (projectEventResponse, error) {
	if event == nil {
		return projectEventResponse{}, errors.New("source event is required")
	}
	runtimeID := strings.TrimSpace(event.GetAttributes()[ports.EventAttributeSourceRuntimeID])
	if runtimeID == "" {
		return projectEventResponse{}, errors.New("source event runtime ID is required")
	}
	familyID, err := eventFamily(event)
	if err != nil {
		return projectEventResponse{}, err
	}
	payload := json.RawMessage(event.GetPayload())
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	} else if !json.Valid(payload) {
		return projectEventResponse{}, errors.New("source event payload must be valid JSON")
	}
	observedAt, err := observedAtUnixMS(event.GetOccurredAt())
	if err != nil {
		return projectEventResponse{}, err
	}
	requestBody, err := json.Marshal(projectEventRequest{
		TenantID:           strings.TrimSpace(event.GetTenantId()),
		SourceRuntimeID:    runtimeID,
		SourceID:           strings.TrimSpace(event.GetSourceId()),
		FamilyID:           familyID,
		EventID:            strings.TrimSpace(event.GetId()),
		ObservedAtUnixMS:   observedAt,
		AppendLogCommitted: true,
		Attributes:         cloneAttributes(event.GetAttributes()),
		Payload:            payload,
	})
	if err != nil {
		return projectEventResponse{}, fmt.Errorf("encode Rust projection request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/projections/events", bytes.NewReader(requestBody))
	if err != nil {
		return projectEventResponse{}, fmt.Errorf("build Rust projection request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	var response projectEventResponse
	if err := c.doJSON(request, &response); err != nil {
		return projectEventResponse{}, err
	}
	if response.Authority != projectionAuthorityLegacy && response.Authority != projectionAuthorityRust {
		return projectEventResponse{}, fmt.Errorf("rust projection returned invalid authority %q", response.Authority)
	}
	return response, nil
}

func (c *ProjectionClient) authority(ctx context.Context, event *cerebrov1.EventEnvelope) (string, error) {
	if event == nil {
		return "", errors.New("source event is required")
	}
	familyID, err := eventFamily(event)
	if err != nil {
		return "", err
	}
	query := url.Values{
		"tenant_id": {strings.TrimSpace(event.GetTenantId())},
		"source_id": {strings.TrimSpace(event.GetSourceId())},
		"family_id": {familyID},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/projections/authority?"+query.Encode(), nil)
	if err != nil {
		return "", fmt.Errorf("build Rust projection authority request: %w", err)
	}
	var response authorityResponse
	if err := c.doJSON(request, &response); err != nil {
		return "", err
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
// to the append log. Rust handles authoritative families; Go handles legacy
// families. A Rust-authoritative failure never falls back to a second writer.
type AppendLogProjector struct {
	legacy ports.SourceProjector
	rust   *ProjectionClient
}

func NewAppendLogProjector(legacy ports.SourceProjector, rust *ProjectionClient) *AppendLogProjector {
	return &AppendLogProjector{legacy: legacy, rust: rust}
}

func (p *AppendLogProjector) Project(ctx context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	response, err := p.rust.project(ctx, event)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	if response.Authority == projectionAuthorityRust {
		if !response.Projected || response.GraphRevision == nil {
			return ports.ProjectionResult{}, errors.New("rust-authoritative projection did not commit")
		}
		return ports.ProjectionResult{
			EntitiesProjected: response.EntitiesUpserted,
			LinksProjected:    response.AssertionsUpserted,
		}, nil
	}
	if p.legacy == nil {
		return ports.ProjectionResult{}, nil
	}
	return p.legacy.Project(ctx, event)
}

// LegacyWriteGuard prevents replay/refetch jobs from restoring a Go write path
// after a family has moved to Rust.
type LegacyWriteGuard struct {
	legacy ports.SourceProjector
	rust   *ProjectionClient
}

func NewLegacyWriteGuard(legacy ports.SourceProjector, rust *ProjectionClient) *LegacyWriteGuard {
	return &LegacyWriteGuard{legacy: legacy, rust: rust}
}

func (p *LegacyWriteGuard) Project(ctx context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
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
