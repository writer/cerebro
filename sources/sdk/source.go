package sdk

import (
	"context"
	"embed"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const inventoryURNsKey = "inventory_urns"

// Source is the builtin push-oriented source used by SDK onboarders.
type Source struct {
	spec *cerebrov1.SourceSpec
}

// New constructs the SDK push source.
func New() (*Source, error) {
	specBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	spec, err := sourcecdk.LoadCatalog(specBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	return &Source{spec: spec}, nil
}

// Spec returns static metadata for the SDK push source.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

// Check validates that the SDK runtime declares an integration name.
func (s *Source) Check(_ context.Context, cfg sourcecdk.Config) error {
	if integration, ok := cfg.Lookup("integration"); !ok || strings.TrimSpace(integration) == "" {
		return fmt.Errorf("%w: sdk integration is required", sourcecdk.ErrInvalidConfig)
	}
	if _, err := inventoryURNs(cfg); err != nil {
		return err
	}
	return nil
}

// Discover returns optional inventory URNs declared by the SDK runtime config.
func (s *Source) Discover(_ context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return inventoryURNs(cfg)
}

// Read returns an empty pull because SDK runtimes push directly into the write surface.
func (s *Source) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return sourcecdk.Pull{}, nil
}

func inventoryURNs(cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	raw, _ := cfg.Lookup(inventoryURNsKey)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\t'
	})
	urns := make([]sourcecdk.URN, 0, len(fields))
	seen := map[sourcecdk.URN]struct{}{}
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		urn, err := sourcecdk.ParseURN(field)
		if err != nil {
			return nil, fmt.Errorf("%w: sdk %s contains invalid urn %q: %w", sourcecdk.ErrInvalidConfig, inventoryURNsKey, field, err)
		}
		if _, ok := seen[urn]; ok {
			continue
		}
		seen[urn] = struct{}{}
		urns = append(urns, urn)
	}
	return urns, nil
}
