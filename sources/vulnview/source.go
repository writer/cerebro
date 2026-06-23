package vulnview

import (
	"context"
	"embed"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID = "vulnview"

	familySite          = "site"
	familyScan          = "scan"
	familyVulnerability = "vulnerability"
	familyAsset         = "asset"
	familyDNSAlert      = "dns_alert"
)

// Source reads VulnView attack-surface and vulnerability data.
type Source struct {
	spec                 *cerebrov1.SourceSpec
	client               *http.Client
	families             *sourcecdk.FamilyEngine[settings]
	allowLoopbackBaseURL bool
	lookupIPAddrs        func(context.Context, string) ([]net.IPAddr, error)
	mu                   sync.Mutex
	tokenKey             string
	accessToken          string
	tokenExpiresAt       time.Time
}

// New constructs the VulnView source.
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

// Spec returns static VulnView source metadata.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

// Check validates that the configured VulnView family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

// Discover returns canonical VulnView URNs for one configured page.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read pages VulnView records and emits vulnview.* events.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	return sourcecdk.NewFamilyEngine(s.parseSettings, func(settings settings) string {
		return settings.family
	},
		s.family(familySite, "/sites"),
		s.family(familyScan, "/scans"),
		s.family(familyVulnerability, "/vulnerabilities"),
		s.family(familyAsset, "/assets"),
		s.dnsAlertFamily(),
	)
}

func (s *Source) family(name string, path string) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: name,
		Check: func(ctx context.Context, settings settings) error {
			_, _, err := s.list(ctx, settings, path, "", 1)
			if err != nil {
				return fmt.Errorf("vulnview %s: %w", name, err)
			}
			return nil
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			records, _, err := s.list(ctx, settings, path, "", settings.perPage)
			if err != nil {
				return nil, fmt.Errorf("vulnview %s: %w", name, err)
			}
			return urnsFor(settings, name, records)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			records, next, err := s.list(ctx, settings, path, strings.TrimSpace(cursor.GetOpaque()), settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("vulnview %s: %w", name, err)
			}
			return pullFromRecords(settings, name, records, next)
		},
	}
}

func (s *Source) list(ctx context.Context, settings settings, path string, cursor string, pageSize int) ([]record, string, error) {
	var response listResponse
	query := settings.query()
	query.Set("limit", strconv.Itoa(pageSize))
	sourcecdk.AddQueryParam(query, "cursor", cursor)
	if err := s.getJSON(ctx, settings, path, query, &response); err != nil {
		return nil, "", err
	}
	records := make([]record, 0, len(response.Items))
	for _, item := range response.Items {
		rec, err := recordFromRaw(settings.family, item)
		if err != nil {
			return nil, "", err
		}
		if rec.ID == "" {
			continue
		}
		records = append(records, rec)
	}
	if serverPaged(cursor, pageSize, len(records), response.NextCursor) {
		return records, strings.TrimSpace(response.NextCursor), nil
	}
	return sourcecdk.PageByOffset(records, cursor, pageSize)
}
