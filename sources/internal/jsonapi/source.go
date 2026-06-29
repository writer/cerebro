package jsonapi

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

// Family describes one JSON API collection exposed by a first-class source.
type Family struct {
	Name                  string
	Path                  string
	DetailPath            string
	AllowBareDetailRecord bool
	PathParams            []string
	CursorParam           string
	NextCursorKeys        []string
	HasMoreKey            string
	LinkHeader            string
	PageFirstCursor       string
	URNKind               string
	IDKeys                []string
	TimestampKeys         []string
	Attributes            map[string]string
	StaticAttributes      map[string]string
	Config                FamilyConfig
	PageSizeParams        []string
	DisablePageSize       bool
	ListKeys              []string
	MapRecords            map[string]string
	Singleton             bool
	RequireID             bool
	IncrementalWatermark  bool
	Method                string
}

// FamilyConfig groups request and event bindings that are derived from family
// configuration rather than directly from provider records.
type FamilyConfig struct {
	StaticQuery      map[string]string
	ConfigQuery      map[string]string
	ConfigAttributes map[string]string
	EncodeURNID      bool
	ResourceURNKind  string
	TotalKeys        []string
	OffsetKeys       []string
	LimitKeys        []string
}

// MergeStaticAttributes adds provider-specific static event attributes while
// preserving the source adapter's base static attributes.
func MergeStaticAttributes(f *Family, extra map[string]string) {
	if f == nil || len(extra) == 0 {
		return
	}
	merged := make(map[string]string, len(f.StaticAttributes)+len(extra))
	for key, value := range f.StaticAttributes {
		merged[key] = value
	}
	for key, value := range extra {
		merged[key] = value
	}
	f.StaticAttributes = merged
}

// Options configures a JSON API-backed source adapter.
type Options struct {
	SourceID                          string
	DefaultBaseURL                    string
	DefaultFamily                     string
	RequireTenantID                   bool
	AuthModel                         string
	TokenScheme                       string
	TokenHeader                       string
	OAuthTokenURL                     string
	OAuthScopes                       []string
	OAuthTokenParams                  map[string]string
	OAuthTokenRequestAuthMethod       string
	ConfigurableAuthModels            []string
	StaticHeaders                     map[string]string
	ConfigHeaders                     map[string]string
	DiscoverURNScope                  string
	PrivateEndpointAllowlistConfigKey string
	ResponseError                     func([]byte) error
	Families                          []Family
}

// Source is a small, safe JSON API source implementation used by endpoint
// adapters whose APIs expose paged REST collections.
type Source struct {
	spec                 *cerebrov1.SourceSpec
	options              Options
	client               *http.Client
	families             *sourcecdk.FamilyEngine[settings]
	AllowLoopbackBaseURL bool
	lookupIPAddrs        func(context.Context, string) ([]net.IPAddr, error)
	oauthTokenMu         sync.Mutex
	oauthTokens          map[string]cachedOAuthToken
}

// New constructs a JSON API-backed source.
func New(spec *cerebrov1.SourceSpec, options Options) (*Source, error) {
	if spec == nil {
		return nil, fmt.Errorf("source spec is required")
	}
	if strings.TrimSpace(options.SourceID) == "" {
		return nil, fmt.Errorf("source id is required")
	}
	source := &Source{
		spec:          spec,
		options:       options,
		lookupIPAddrs: net.DefaultResolver.LookupIPAddr,
		oauthTokens:   map[string]cachedOAuthToken{},
	}
	families, err := source.newFamilyEngine()
	if err != nil {
		return nil, err
	}
	source.families = families
	return source, nil
}

// Spec returns static source metadata.
func (s *Source) Spec() *cerebrov1.SourceSpec { return s.spec }

// Check validates that the configured family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

// CheckPath validates a specific provider path using the source's configured auth.
func (s *Source) CheckPath(ctx context.Context, cfg sourcecdk.Config, path string, expectStatuses []int) error {
	settings, err := s.parseSettings(cfg)
	if err != nil {
		return err
	}
	path = firstNonEmpty(path, settings.path)
	path, err = resolveConfigTemplate(s.options.SourceID, path, cfg)
	if err != nil {
		return err
	}
	normalizedPath, query, err := normalizeRequestPathWithQuery(s.options.SourceID, path)
	if err != nil {
		return err
	}
	_, err = s.doRequest(ctx, settings, normalizedPath, query, nil, expectStatuses)
	return err
}

// Discover returns URNs for the configured family.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read pages records for the configured family.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

// ReadWithCheckpoint pages records for the configured family and applies any
// family-level checkpoint policy.
func (s *Source) ReadWithCheckpoint(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	return s.families.ReadWithCheckpoint(ctx, cfg, cursor, checkpoint)
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	families := make([]sourcecdk.Family[settings], 0, len(s.options.Families))
	for _, family := range s.options.Families {
		family := family
		if strings.TrimSpace(family.Name) == "" {
			return nil, fmt.Errorf("family name is required")
		}
		families = append(families, sourcecdk.Family[settings]{
			Name:                 family.Name,
			IncrementalWatermark: family.IncrementalWatermark,
			Check: func(ctx context.Context, settings settings) error {
				_, _, err := s.list(ctx, family, settings, "", 1)
				return err
			},
			Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
				records, _, err := s.list(ctx, family, settings, "", settings.perPage)
				if err != nil {
					return nil, err
				}
				return urnsFor(settings, family, records)
			},
			Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
				records, next, err := s.list(ctx, family, settings, sourcecdk.CursorToken(cursor), settings.perPage)
				if err != nil {
					return sourcecdk.Pull{}, err
				}
				return pullFromRecords(s.options.SourceID, settings, family, records, next)
			},
		})
	}
	return sourcecdk.NewFamilyEngineWithSourceID(s.options.SourceID, s.parseSettings, func(settings settings) string { return settings.family }, families...)
}
