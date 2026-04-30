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
	return nil
}

// Discover returns no URNs because SDK runtimes push directly into the write surface.
func (s *Source) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

// Read returns an empty pull because SDK runtimes push directly into the write surface.
func (s *Source) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return sourcecdk.Pull{}, nil
}
