package backstage

import (
	"context"
	"embed"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID       = "backstage"
	defaultFamily  = familyComponent
	defaultBaseURL = ""

	familyComponent = "component"
)

// Source reads Backstage catalog entities.
type Source struct {
	inner *jsonapi.Source
}

// New constructs the Backstage source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  defaultBaseURL,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		TokenScheme:     "Bearer",
		Families: []jsonapi.Family{
			{
				Name:      familyComponent,
				Path:      "/api/catalog/entities/by-query",
				URNKind:   "backstage_component",
				RequireID: true,
				IDKeys:    []string{"metadata.uid", "metadata.name", "name"},
				TimestampKeys: []string{
					"updated_at", "created_at",
				},
				Attributes: map[string]string{
					"uid":          "metadata.uid",
					"name":         "metadata.name|name",
					"namespace":    "metadata.namespace",
					"kind":         "kind",
					"type":         "spec.type|type",
					"lifecycle":    "spec.lifecycle|lifecycle",
					"owner":        "spec.owner|owner",
					"system":       "spec.system|system",
					"description":  "metadata.description|description",
					"repository":   "repository|repo",
					"entity_ref":   "entity_ref",
					"criticality":  "metadata.annotations.cerebro.io/criticality|criticality|tier",
					"data_class":   "metadata.annotations.cerebro.io/data-classification|data_class",
					"source_url":   "source_url",
					"scorecard":    "scorecard",
					"score_grade":  "score_grade|grade",
					"dora_service": "dora_service",
				},
				StaticAttributes: map[string]string{"source_product": "backstage"},
				StaticQuery:      map[string]string{"filter": "kind=component"},
				PageSizeParams:   []string{"limit"},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

// Spec returns static Backstage source metadata.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Spec()
}

// Check validates that the configured Backstage catalog family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.inner.Check(ctx, cfg)
}

// Discover returns Backstage URNs for the configured family.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.inner.Discover(ctx, cfg)
}

// Read pages Backstage catalog records and emits backstage.* events.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.inner.Read(ctx, cfg, cursor)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
	}
}
