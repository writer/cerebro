// Package panopticon implements the Cerebro source for Panopticon events.
package panopticon

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourcehttp"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID = "panopticon"

	defaultPageSize, maxPageSize, maxEventsPerPull = 100, 1000, 1000
	cursorSourceAPI, modeAPI                       = "panopticon/api/v1", "api"

	familyAlert, familyCase, familyIOC          = "alert", "case", "ioc"
	schemaRefAlert, schemaRefCase, schemaRefIOC = "panopticon/alert/v1", "panopticon/case/v1", "panopticon/ioc/v1"
	kindAlert, kindCase, kindIOC                = "panopticon.alert", "panopticon.case", "panopticon.ioc"
	urnPrefixAlert, urnPrefixCase, urnPrefixIOC = "urn:cerebro:panopticon:alert:", "urn:cerebro:panopticon:case:", "urn:cerebro:panopticon:ioc:"
)

var (
	ErrInvalidPageSize, ErrTenantIDRequired  = errors.New("invalid page_size"), errors.New("tenant_id is required")
	ErrUnsupportedFamily, ErrBaseURLRequired = errors.New("unsupported family"), errors.New("base_url is required")
	ErrTokenRequired, ErrUnsupportedMode     = errors.New("token is required"), errors.New("unsupported mode")
)

type Source struct {
	spec                 *cerebrov1.SourceSpec
	client               *http.Client
	families             *sourcecdk.FamilyEngine[settings]
	allowLoopbackBaseURL bool
	lookupIPAddrs        func(context.Context, string) ([]net.IPAddr, error)
}

type settings struct {
	family, baseURL, apiPath   string
	token, tenantID, runtimeID string
	privateEndpointAllowlist   []string
	perPage                    int32
}

type panopticonRecord struct {
	ID         string                 `json:"id"`
	TenantID   string                 `json:"tenant_id"`
	SourceID   string                 `json:"source_id"`
	Kind       string                 `json:"kind"`
	OccurredAt time.Time              `json:"occurred_at"`
	SchemaRef  string                 `json:"schema_ref"`
	Payload    map[string]interface{} `json:"payload"`
	Attributes map[string]string      `json:"attributes"`
}

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

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.spec }

func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	families := []sourcecdk.Family[settings]{
		s.familyFor(familyAlert, kindAlert, schemaRefAlert, urnPrefixAlert),
		s.familyFor(familyCase, kindCase, schemaRefCase, urnPrefixCase),
		s.familyFor(familyIOC, kindIOC, schemaRefIOC, urnPrefixIOC),
	}
	return sourcecdk.NewFamilyEngine[settings](
		func(cfg sourcecdk.Config) (settings, error) {
			if s != nil && s.allowLoopbackBaseURL {
				return parseSettingsWithLoopback(cfg, true)
			}
			return parseSettings(cfg)
		},
		func(st settings) string { return st.family },
		families...,
	)
}

func (s *Source) familyFor(family, kind, schemaRef, urnPrefix string) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: family,
		Check: func(ctx context.Context, st settings) error {
			return s.checkAPI(ctx, st)
		},
		Discover: func(ctx context.Context, st settings) ([]sourcecdk.URN, error) {
			return discoverAPIFamily(st, urnPrefix)
		},
		Read: func(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			return s.readAPIFamily(ctx, st, cursor, kind, schemaRef)
		},
	}
}

func parseSettings(cfg sourcecdk.Config) (settings, error) {
	return parseSettingsWithLoopback(cfg, false)
}

func parseSettingsWithLoopback(cfg sourcecdk.Config, allowLoopback bool) (settings, error) {
	mode := strings.ToLower(strings.TrimSpace(sourcecdk.ConfigValue(cfg, "mode")))
	if mode != "" && mode != modeAPI {
		return settings{}, fmt.Errorf("%w: %q", ErrUnsupportedMode, mode)
	}
	tenantID := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "tenant_id"))
	if runtimeTenantID := strings.TrimSpace(sourcecdk.ConfigValue(cfg, sourceconfig.RuntimeTenantIDKey)); runtimeTenantID != "" {
		tenantID = runtimeTenantID
	}
	st := settings{
		family:    strings.TrimSpace(sourcecdk.ConfigValue(cfg, "family")),
		baseURL:   strings.TrimSpace(sourcecdk.ConfigValue(cfg, "base_url")),
		apiPath:   strings.TrimSpace(sourcecdk.ConfigValue(cfg, "path")),
		token:     strings.TrimSpace(firstConfigValue(cfg, "token", "api_key")),
		tenantID:  tenantID,
		runtimeID: strings.TrimSpace(firstConfigValue(cfg, "runtime_id", "source_runtime_id")),
		perPage:   defaultPageSize,
	}
	if st.family == "" {
		st.family = familyCase
	}
	if st.tenantID == "" {
		return settings{}, ErrTenantIDRequired
	}
	if rawPageSize := strings.TrimSpace(firstConfigValue(cfg, "per_page", "page_size")); rawPageSize != "" {
		size, err := strconv.ParseInt(rawPageSize, 10, 32)
		if err != nil {
			return settings{}, fmt.Errorf("%w: %w", ErrInvalidPageSize, err)
		}
		if size < 1 {
			return settings{}, fmt.Errorf("%w: must be >= 1", ErrInvalidPageSize)
		}
		if size > int64(maxPageSize) {
			size = int64(maxPageSize)
		}
		st.perPage = int32(size) // #nosec G109 G115 -- ParseInt bitSize 32 and maxPageSize bound ensure this conversion is safe.
	}
	if !isKnownFamily(st.family) {
		return settings{}, fmt.Errorf("%w: %q", ErrUnsupportedFamily, st.family)
	}
	if st.baseURL == "" {
		return settings{}, ErrBaseURLRequired
	}
	if st.token == "" {
		return settings{}, ErrTokenRequired
	}
	privateEndpointAllowlist, err := sourcehttp.ParsePrivateEndpointAllowlist(sourceID, sourcecdk.ConfigValue(cfg, "private_endpoint_allowlist"))
	if err != nil {
		return settings{}, err
	}
	baseURL, _, err := sourcehttp.NormalizeBaseURLWithOptions(sourceID, st.baseURL, sourcehttp.URLValidationOptions{
		AllowLoopback:            allowLoopback,
		PrivateEndpointAllowlist: privateEndpointAllowlist,
	})
	if err != nil {
		return settings{}, err
	}
	st.baseURL = baseURL
	st.privateEndpointAllowlist = privateEndpointAllowlist
	if st.apiPath == "" {
		st.apiPath = apiPathForFamily(st.family)
	}
	apiPath, err := sourcehttp.NormalizeRequestPath(sourceID, st.apiPath)
	if err != nil {
		return settings{}, err
	}
	st.apiPath = apiPath
	return st, nil
}

func isKnownFamily(name string) bool {
	switch name {
	case familyAlert, familyCase, familyIOC:
		return true
	}
	return false
}

func firstConfigValue(cfg sourcecdk.Config, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(sourcecdk.ConfigValue(cfg, key)); value != "" {
			return value
		}
	}
	return ""
}
