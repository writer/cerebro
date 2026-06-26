package grc

import (
	"context"
	"embed"
	"net"
	"net/http"
	"sync"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID           = "grc"
	defaultProvider    = "vanta"
	defaultBaseURL     = "https://api.vanta.com"
	defaultReadScope   = "vanta-api.all:read"
	defaultPageSize    = 10
	maxPageSize        = 100
	httpTimeout        = 30 * time.Second
	maxBodyBytes       = 8 << 20
	tokenRefreshLeeway = time.Minute
)

// Source emits provider-neutral canonical GRC events from configured families.
type Source struct {
	spec                 *cerebrov1.SourceSpec
	client               *http.Client
	families             *sourcecdk.FamilyEngine[settings]
	allowLoopbackBaseURL bool
	lookupIPAddrs        func(context.Context, string) ([]net.IPAddr, error)
	tokenRetryBackoffs   []time.Duration
	mu                   sync.Mutex
	tokenKey             string
	accessToken          string
	tokenExpiresAt       time.Time
}

// New constructs the GRC source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	source := &Source{
		spec:          spec,
		lookupIPAddrs: net.DefaultResolver.LookupIPAddr,
	}
	source.families, err = source.newFamilyEngine()
	if err != nil {
		return nil, err
	}
	return source, nil
}

// Spec returns static metadata for the GRC source.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

// Check validates that the configured GRC family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

// Discover returns canonical GRC URNs for one configured family page.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read pages provider records and emits canonical grc.* events.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}
