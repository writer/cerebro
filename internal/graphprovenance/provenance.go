package graphprovenance

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/projectionmeta"
	cerebrourn "github.com/writer/cerebro/internal/urn"
)

type Request struct {
	URN string
}

type Response struct {
	URN              string            `json:"urn"`
	TenantID         string            `json:"tenant_id"`
	EntityType       string            `json:"entity_type"`
	Label            string            `json:"label,omitempty"`
	SourceID         string            `json:"source_id,omitempty"`
	RuntimeID        string            `json:"runtime_id,omitempty"`
	ProjectionClass  string            `json:"projection_class"`
	ProjectionReason string            `json:"projection_reason"`
	Attributes       map[string]string `json:"attributes,omitempty"`
	Provenance       Provenance        `json:"provenance"`
}

type Provenance struct {
	Surface          string   `json:"surface"`
	Scope            string   `json:"scope"`
	SourceURNs       []string `json:"source_urns"`
	CitationStatus   string   `json:"citation_status"`
	FreshnessSignals []string `json:"freshness_signals,omitempty"`
}

type Service struct {
	store ports.GraphQueryStore
}

func New(store ports.GraphQueryStore) *Service {
	return &Service{store: store}
}

func (s *Service) Get(ctx context.Context, request Request) (Response, error) {
	urn := strings.TrimSpace(request.URN)
	if urn == "" || TenantIDFromURN(urn) == "" {
		return Response{}, fmt.Errorf("%w: urn is required", graphquery.ErrInvalidRequest)
	}
	if s == nil || s.store == nil {
		return Response{}, graphquery.ErrRuntimeUnavailable
	}
	tenantID := TenantIDFromURN(urn)
	store, ok := s.store.(ports.EntityCatalogStore)
	if !ok {
		return Response{}, ports.ErrGraphTypedOperationRequired
	}
	page, err := store.ListEntities(ctx, ports.EntityCatalogPageRequest{Filter: ports.EntityCatalogFilter{TenantID: tenantID, ExactAgentKey: urn}, Limit: 1})
	if err != nil {
		return Response{}, err
	}
	if page == nil || page.TenantID != tenantID {
		return Response{}, graphquery.ErrRuntimeUnavailable
	}
	if len(page.Entities) == 0 {
		return Response{}, ports.ErrGraphEntityNotFound
	}
	entity := page.Entities[0]
	attributesJSON, err := json.Marshal(entity.Attributes)
	if err != nil {
		return Response{}, err
	}
	return fromRow(ports.CypherRow{Values: map[string]any{"urn": entity.URN, "tenant_id": entity.TenantID, "entity_type": entity.EntityType, "label": entity.Label, "source_id": entity.SourceID, "runtime_id": entity.RuntimeID, "attributes_json": string(attributesJSON)}})
}

func TenantIDFromURN(urn string) string {
	parsed, err := cerebrourn.Parse(urn)
	if err != nil || len(parsed.Parts) == 0 {
		return ""
	}
	return parsed.TenantID
}

func fromRow(row ports.CypherRow) (Response, error) {
	values := row.Values
	attributes, err := attributesFromRow(values["attributes_json"])
	if err != nil {
		return Response{}, err
	}
	entityType := stringValue(values["entity_type"])
	classification := projectionmeta.ClassifyEntity(entityType, attributes)
	urn := stringValue(values["urn"])
	sourceURNs := []string{urn}
	if sourceEventID := strings.TrimSpace(firstNonEmpty(attributes["source_event_id"], attributes["event_id"])); sourceEventID != "" {
		sourceURNs = append(sourceURNs, "event:"+sourceEventID)
	}
	response := Response{
		URN:              urn,
		TenantID:         stringValue(values["tenant_id"]),
		EntityType:       entityType,
		Label:            stringValue(values["label"]),
		SourceID:         stringValue(values["source_id"]),
		RuntimeID:        stringValue(values["runtime_id"]),
		ProjectionClass:  firstNonEmpty(attributes[projectionmeta.AttributeProjectionClass], classification.Class),
		ProjectionReason: firstNonEmpty(attributes[projectionmeta.AttributeProjectionReason], classification.Reason),
		Attributes:       attributes,
		Provenance: Provenance{
			Surface:        "graph-provenance",
			Scope:          firstNonEmpty(stringValue(values["tenant_id"]), TenantIDFromURN(urn)),
			SourceURNs:     sourceURNs,
			CitationStatus: "valid",
		},
	}
	response.Provenance.FreshnessSignals = freshnessSignals(attributes)
	return response, nil
}

func attributesFromRow(value any) (map[string]string, error) {
	raw := strings.TrimSpace(stringValue(value))
	if raw == "" {
		return map[string]string{}, nil
	}
	decoded := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil, fmt.Errorf("%w: decode graph attributes: %w", graphquery.ErrInvalidRequest, err)
	}
	return decoded, nil
}

func freshnessSignals(attributes map[string]string) []string {
	keys := []string{"observed_at", "last_observed_at", "at", "updated_at"}
	signals := make([]string, 0, len(keys))
	for _, key := range keys {
		if value := strings.TrimSpace(attributes[key]); value != "" {
			signals = append(signals, key+"="+value)
		}
	}
	return signals
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
