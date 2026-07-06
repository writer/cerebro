package digitalocean

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/digitalocean/godo"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID        = "digitalocean"
	defaultFamily   = familyDroplets
	familyDroplets  = "droplets"
	familyVPCs      = "vpcs"
	familyFirewalls = "firewalls"
	defaultPageSize = 50
)

type settings struct {
	tenantID string
	family   string
	token    string
	baseURL  string
	pageSize int
}

// clientOptions carries test-only overrides for the outbound HTTP client. In
// production every field is zero, which yields a fully hardened client that
// blocks loopback, private, and link-local targets.
type clientOptions struct {
	allowLoopback bool
	lookupIPAddrs func(context.Context, string) ([]net.IPAddr, error)
}

// Source reads DigitalOcean droplets, VPCs, and firewalls through the official
// godo SDK and normalizes them into the Cerebro append-log.
type Source struct {
	engine *sourcecdk.FamilyEngine[settings]
	spec   *cerebrov1.SourceSpec
}

// New builds the DigitalOcean source with one godo-backed page reader per family.
func New() (*Source, error) {
	return newSource(clientOptions{})
}

func newSource(opts clientOptions) (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	clients := func(ctx context.Context, s settings) (*godo.Client, error) {
		return newClient(ctx, s, opts)
	}
	pageSize := func(s settings) int { return s.pageSize }
	engine, err := sourcecdk.NewFamilyEngineWithSourceID(
		sourceID,
		parseSettings,
		func(s settings) string { return s.family },
		sourcecdk.FamilyFromPageReader(sourcecdk.PageReader[settings, *godo.Client, godo.Droplet]{
			SourceID: sourceID, Family: familyDroplets, Label: "digitalocean droplets",
			Clients:  clients,
			List:     listDroplets,
			Event:    dropletEvent,
			URN:      dropletURN,
			PageSize: pageSize,
		}),
		sourcecdk.FamilyFromPageReader(sourcecdk.PageReader[settings, *godo.Client, *godo.VPC]{
			SourceID: sourceID, Family: familyVPCs, Label: "digitalocean vpcs",
			Clients:  clients,
			List:     listVPCs,
			Event:    vpcEvent,
			URN:      vpcURN,
			PageSize: pageSize,
		}),
		sourcecdk.FamilyFromPageReader(sourcecdk.PageReader[settings, *godo.Client, godo.Firewall]{
			SourceID: sourceID, Family: familyFirewalls, Label: "digitalocean firewalls",
			Clients:  clients,
			List:     listFirewalls,
			Event:    firewallEvent,
			URN:      firewallURN,
			PageSize: pageSize,
		}),
	)
	if err != nil {
		return nil, err
	}
	return &Source{engine: engine, spec: spec}, nil
}

// Spec returns the source specification loaded from the embedded catalog.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	if s == nil {
		return nil
	}
	return s.spec
}

// Check verifies connectivity and credentials by listing the configured family.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	if _, err := s.engine.Discover(ctx, cfg); err != nil {
		return err
	}
	return nil
}

// Discover lists provider URNs for the configured family.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.engine.Discover(ctx, cfg)
}

// Read pulls one page of events for the configured family.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.engine.Read(ctx, cfg, cursor)
}

func parseSettings(cfg sourcecdk.Config) (settings, error) {
	tenantID, err := sourcecdk.RequiredConfigValue(sourceID, cfg, "tenant_id")
	if err != nil {
		return settings{}, err
	}
	token, err := sourcecdk.RequiredConfigValue(sourceID, cfg, "token")
	if err != nil {
		return settings{}, err
	}
	family := sourcecdk.ConfigValue(cfg, "family")
	if family == "" {
		family = defaultFamily
	}
	return settings{
		tenantID: tenantID,
		family:   family,
		token:    token,
		baseURL:  sourcecdk.ConfigValue(cfg, "base_url"),
		pageSize: parsePageSize(sourcecdk.ConfigValue(cfg, "per_page")),
	}, nil
}

func parsePageSize(raw string) int {
	if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && n > 0 {
		return n
	}
	return defaultPageSize
}

// newClient builds a godo client whose outbound requests flow through the
// shared sourcehttp SafeRoundTripper (SSRF/DNS-rebinding guards, response body
// limits, timeout, no redirects). The oauth2 bearer transport wraps the safe
// transport so credentials are attached before the safety layer inspects and
// pins the request host.
func newClient(ctx context.Context, s settings, opts clientOptions) (*godo.Client, error) {
	safe := sourcehttp.NewClient(sourcehttp.ClientOptions{
		SourceID:      sourceID,
		AllowLoopback: opts.allowLoopback,
		LookupIPAddrs: opts.lookupIPAddrs,
	})
	ctx = context.WithValue(ctx, oauth2.HTTPClient, safe)
	httpClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: s.token}))
	clientOpts := make([]godo.ClientOpt, 0, 1)
	if base := strings.TrimSpace(s.baseURL); base != "" {
		clientOpts = append(clientOpts, godo.SetBaseURL(base))
	}
	client, err := godo.New(httpClient, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("%s: build client: %w", sourceID, err)
	}
	return client, nil
}

func listDroplets(ctx context.Context, c *godo.Client, _ settings, token string, pageSize int) ([]godo.Droplet, string, error) {
	droplets, resp, err := c.Droplets.List(ctx, listOptions(token, pageSize))
	if err != nil {
		return nil, "", err
	}
	return droplets, nextPageToken(resp, token), nil
}

func listVPCs(ctx context.Context, c *godo.Client, _ settings, token string, pageSize int) ([]*godo.VPC, string, error) {
	vpcs, resp, err := c.VPCs.List(ctx, listOptions(token, pageSize))
	if err != nil {
		return nil, "", err
	}
	return vpcs, nextPageToken(resp, token), nil
}

func listFirewalls(ctx context.Context, c *godo.Client, _ settings, token string, pageSize int) ([]godo.Firewall, string, error) {
	firewalls, resp, err := c.Firewalls.List(ctx, listOptions(token, pageSize))
	if err != nil {
		return nil, "", err
	}
	return firewalls, nextPageToken(resp, token), nil
}

func listOptions(token string, pageSize int) *godo.ListOptions {
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	return &godo.ListOptions{Page: pageFromToken(token), PerPage: pageSize}
}

func pageFromToken(token string) int {
	if n, err := strconv.Atoi(strings.TrimSpace(token)); err == nil && n > 0 {
		return n
	}
	return 1
}

func nextPageToken(resp *godo.Response, token string) string {
	if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
		return ""
	}
	return strconv.Itoa(pageFromToken(token) + 1)
}

func dropletEvent(s settings, d godo.Droplet) (*primitives.Event, error) {
	id := strconv.Itoa(d.ID)
	urn, err := dropletURN(s, d)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]any{
		"id":         d.ID,
		"name":       d.Name,
		"status":     d.Status,
		"region":     regionSlug(d.Region),
		"vpc_uuid":   d.VPCUUID,
		"created_at": d.Created,
	})
	if err != nil {
		return nil, err
	}
	attrs := map[string]string{
		"tenant_id":       s.tenantID,
		"source_event_id": id,
		"resource_id":     id,
		"resource_type":   "droplet",
		"resource_urn":    urn.String(),
		"resource_name":   d.Name,
		"record_class":    "asset",
		"region":          regionSlug(d.Region),
	}
	if vpc := strings.TrimSpace(d.VPCUUID); vpc != "" {
		attrs["vpc_uuid"] = vpc
	}
	return newEvent(s, familyDroplets, "digitalocean.droplets", "digitalocean/droplets/v1", id, d.Created, attrs, payload), nil
}

func vpcEvent(s settings, v *godo.VPC) (*primitives.Event, error) {
	if v == nil {
		return nil, nil
	}
	urn, err := vpcURN(s, v)
	if err != nil {
		return nil, err
	}
	created := v.CreatedAt.UTC().Format(time.RFC3339)
	payload, err := json.Marshal(map[string]any{
		"id":         v.ID,
		"name":       v.Name,
		"ip_range":   v.IPRange,
		"region":     v.RegionSlug,
		"default":    v.Default,
		"created_at": created,
	})
	if err != nil {
		return nil, err
	}
	attrs := map[string]string{
		"tenant_id":       s.tenantID,
		"source_event_id": v.ID,
		"resource_id":     v.ID,
		"resource_type":   "vpc",
		"resource_urn":    urn.String(),
		"resource_name":   v.Name,
		"record_class":    "asset",
		"region":          v.RegionSlug,
	}
	return newEvent(s, familyVPCs, "digitalocean.vpcs", "digitalocean/vpcs/v1", v.ID, created, attrs, payload), nil
}

func firewallEvent(s settings, f godo.Firewall) (*primitives.Event, error) {
	urn, err := firewallURN(s, f)
	if err != nil {
		return nil, err
	}
	dropletIDs := make([]string, 0, len(f.DropletIDs))
	for _, id := range f.DropletIDs {
		dropletIDs = append(dropletIDs, strconv.Itoa(id))
	}
	public := firewallHasPublicIngress(f)
	payload, err := json.Marshal(map[string]any{
		"id":          f.ID,
		"name":        f.Name,
		"status":      f.Status,
		"droplet_ids": f.DropletIDs,
		"public":      public,
		"created_at":  f.Created,
	})
	if err != nil {
		return nil, err
	}
	attrs := map[string]string{
		"tenant_id":       s.tenantID,
		"source_event_id": f.ID,
		"resource_id":     f.ID,
		"resource_type":   "firewall",
		"resource_urn":    urn.String(),
		"resource_name":   f.Name,
		"record_class":    "asset",
		"public_ingress":  strconv.FormatBool(public),
	}
	if len(dropletIDs) > 0 {
		attrs["droplet_ids"] = strings.Join(dropletIDs, ",")
	}
	return newEvent(s, familyFirewalls, "digitalocean.firewalls", "digitalocean/firewalls/v1", f.ID, f.Created, attrs, payload), nil
}

func dropletURN(s settings, d godo.Droplet) (sourcecdk.URN, error) {
	return sourcecdk.URNFor(s.tenantID, "digitalocean_droplets", strconv.Itoa(d.ID))
}

func vpcURN(s settings, v *godo.VPC) (sourcecdk.URN, error) {
	if v == nil {
		return "", fmt.Errorf("%s: vpc record is nil", sourceID)
	}
	return sourcecdk.URNFor(s.tenantID, "digitalocean_vpcs", v.ID)
}

func firewallURN(s settings, f godo.Firewall) (sourcecdk.URN, error) {
	return sourcecdk.URNFor(s.tenantID, "digitalocean_firewalls", f.ID)
}

func firewallHasPublicIngress(f godo.Firewall) bool {
	for _, rule := range f.InboundRules {
		if rule.Sources == nil {
			continue
		}
		for _, addr := range rule.Sources.Addresses {
			switch strings.TrimSpace(addr) {
			case "0.0.0.0/0", "::/0":
				return true
			}
		}
	}
	return false
}

func regionSlug(region *godo.Region) string {
	if region == nil {
		return ""
	}
	return strings.TrimSpace(region.Slug)
}

func newEvent(s settings, family string, kind string, schemaRef string, providerID string, occurred string, attrs map[string]string, payload []byte) *primitives.Event {
	return &primitives.Event{
		Id:         sourcecdk.EventID(sourceID, family, providerID),
		TenantId:   s.tenantID,
		SourceId:   sourceID,
		Kind:       kind,
		SchemaRef:  schemaRef,
		OccurredAt: timestamppb.New(parseTimestamp(occurred)),
		Attributes: attrs,
		Payload:    payload,
	}
}

func parseTimestamp(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Unix(0, 0).UTC()
	}
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		return parsed.UTC()
	}
	return time.Unix(0, 0).UTC()
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
