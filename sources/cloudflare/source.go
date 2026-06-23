package cloudflare

import (
	"context"
	"embed"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const sourceID = "cloudflare"

type Source struct{ inner *jsonapi.Source }

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  "https://api.cloudflare.com/client/v4",
		DefaultFamily:   "account",
		RequireTenantID: true,
		TokenScheme:     "Bearer",
		Families:        cloudflareFamilies(),
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.inner.Spec() }
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
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func cloudflareFamilies() []jsonapi.Family {
	var families []jsonapi.Family
	families = append(families, accountFamilies()...)
	families = append(families, networkFamilies()...)
	families = append(families, accessFamilies()...)
	for i := range families {
		families[i].CursorParam = "page"
		families[i].PageSizeParams = []string{"per_page"}
	}
	return families
}

func cloudflareResultListKeys() []string {
	return []string{"result"}
}

func cloudflareStaticAttributes() map[string]string {
	return map[string]string{"source_product": "cloudflare"}
}
