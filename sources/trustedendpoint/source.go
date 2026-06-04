package trustedendpoint

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

// Source is the push-oriented Trusted Endpoint source. Endpoint control planes
// write runtime-scoped claims and telemetry; Cerebro does not poll agents.
type Source struct {
	spec *cerebrov1.SourceSpec
}

// New constructs the Trusted Endpoint source.
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

// Spec returns static Trusted Endpoint source metadata.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

// Check validates the optional integration marker on push runtimes.
func (s *Source) Check(_ context.Context, cfg sourcecdk.Config) error {
	if integration, ok := cfg.Lookup("integration"); ok {
		switch strings.TrimSpace(integration) {
		case "", "trusted-endpoint", "trusted_endpoint":
		default:
			return fmt.Errorf("%w: integration must be trusted-endpoint", sourcecdk.ErrInvalidConfig)
		}
	}
	return nil
}

// Discover returns no URNs because Trusted Endpoint runtimes push claims.
func (s *Source) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

// Read returns an empty pull because Trusted Endpoint runtimes push claims.
func (s *Source) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return sourcecdk.Pull{}, nil
}
