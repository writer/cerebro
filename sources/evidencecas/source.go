package evidencecas

import (
	"context"
	"embed"
	"fmt"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID      = "evidence_cas"
	defaultFamily = familyObject

	familyObject = "object"
)

type Source struct {
	inner *jsonapi.Source
}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		TokenScheme:     "Bearer",
		Families: []jsonapi.Family{
			{
				Name:    familyObject,
				Path:    "/v1/b/cases/refs",
				URNKind: "runtime_evidence",
				IDKeys:  []string{"uri", "digest"},
				TimestampKeys: []string{
					"updated_at",
				},
				Attributes: map[string]string{
					"evidence_id":                   "metadata.evidence_id|uri|key",
					"evidence_type":                 "metadata.evidence_type",
					"resource_urn":                  "metadata.resource_urn|metadata.case_urn",
					"observed_at":                   "updated_at",
					"case_id":                       "metadata.case_id",
					"evidence_cas_uri":              "uri",
					"evidence_cas_digest":           "digest",
					"evidence_cas_manifest_version": "manifest_version",
					"evidence_cas_merkle_root":      "merkle_root",
					"evidence_cas_commit_id":        "commit_id",
					"evidence_cas_content_type":     "content_type",
					"evidence_cas_size_bytes":       "size",
					"evidence_cas_blocks_count":     "blocks_count",
					"evidence_cas_ref_type":         "ref_type",
				},
				StaticAttributes: map[string]string{
					"source_product": "evidence_cas",
					"evidence_type":  "evidence_cas.artifact",
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Spec()
}

func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.inner.Check(ctx, cfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.inner.Discover(ctx, cfg)
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.inner.Read(ctx, cfg, cursor)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	specBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	spec, err := sourcecdk.LoadCatalog(specBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	return spec, nil
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
	}
}
