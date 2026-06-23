// Package emaildomainhealth probes SPF/DKIM/DMARC/MX posture for tenant
// mail domains and emits one email_domain_health.health event per domain
// per Read. Protocol logic lives in sources/internal/emaildns; this file
// owns only configuration parsing, event assembly, and CDK wiring.
package emaildomainhealth

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/sources/internal/emaildns"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID             = "email_domain_health"
	familyHealth         = "health"
	kindHealth           = "email_domain_health.health"
	schemaHealth         = "email_domain_health/health/v1"
	defaultLookupTimeout = 6 * time.Second
)

var (
	ErrTenantRequired  = errors.New("tenant_id is required")
	ErrDomainsRequired = errors.New("domains is required")
	ErrInvalidDomain   = errors.New("invalid domain")
)

type Source struct {
	spec         *cerebrov1.SourceSpec
	families     *sourcecdk.FamilyEngine[settings]
	resolver     emaildns.Resolver
	now          func() time.Time
	lookupBudget time.Duration
}

type settings struct {
	family        string
	tenantID      string
	runtimeID     string
	domains       []string
	dkimSelectors []string
}

func New() (*Source, error) {
	specBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	spec, err := sourcecdk.LoadCatalog(specBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	source := &Source{
		spec:         spec,
		resolver:     emaildns.NetResolver{},
		now:          time.Now,
		lookupBudget: defaultLookupTimeout,
	}
	source.families, err = sourcecdk.NewFamilyEngine[settings](parseSettings, func(s settings) string { return s.family },
		sourcecdk.Family[settings]{
			Name:     familyHealth,
			Check:    func(context.Context, settings) error { return nil },
			Discover: source.discover,
			Read: func(ctx context.Context, st settings, _ *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
				return source.read(ctx, st)
			},
		})
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

func (s *Source) discover(_ context.Context, st settings) ([]sourcecdk.URN, error) {
	out := make([]sourcecdk.URN, 0, len(st.domains))
	for _, domain := range st.domains {
		urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:email_domain:%s", st.tenantID, domain))
		if err != nil {
			return nil, err
		}
		out = append(out, urn)
	}
	return out, nil
}

func (s *Source) read(ctx context.Context, st settings) (sourcecdk.Pull, error) {
	pull := sourcecdk.Pull{Events: make([]*primitives.Event, 0, len(st.domains))}
	for _, domain := range st.domains {
		domainCtx, cancel := context.WithTimeout(ctx, s.lookupBudget)
		health := emaildns.Evaluate(domainCtx, s.resolver, domain, st.dkimSelectors)
		cancel()
		event, err := buildHealthEvent(st, health, s.now().UTC())
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		pull.Events = append(pull.Events, event)
	}
	return pull, nil
}

func parseSettings(cfg sourcecdk.Config) (settings, error) {
	tenantID := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "tenant_id"))
	if runtimeTenant := strings.TrimSpace(sourcecdk.ConfigValue(cfg, sourceconfig.RuntimeTenantIDKey)); runtimeTenant != "" {
		tenantID = runtimeTenant
	}
	if tenantID == "" {
		return settings{}, ErrTenantRequired
	}
	domains, err := parseDomainsList(sourcecdk.ConfigValue(cfg, "domains"))
	if err != nil {
		return settings{}, err
	}
	if len(domains) == 0 {
		return settings{}, ErrDomainsRequired
	}
	dkimSelectors := parseSelectorList(sourcecdk.ConfigValue(cfg, "dkim_selectors"))
	family := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "family"))
	if family == "" {
		family = familyHealth
	}
	if family != familyHealth {
		return settings{}, fmt.Errorf("%w: unsupported family %q", sourcecdk.ErrInvalidConfig, family)
	}
	return settings{
		family:        family,
		tenantID:      tenantID,
		runtimeID:     firstNonEmpty(sourcecdk.ConfigValue(cfg, "runtime_id"), sourcecdk.ConfigValue(cfg, "source_runtime_id")),
		domains:       domains,
		dkimSelectors: dkimSelectors,
	}, nil
}

func parseDomainsList(raw string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, 4)
	for _, candidate := range strings.FieldsFunc(raw, listSplit) {
		domain := emaildns.NormalizeDomain(candidate)
		if domain == "" {
			if strings.TrimSpace(candidate) == "" {
				continue
			}
			return nil, fmt.Errorf("%w: %q", ErrInvalidDomain, candidate)
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		out = append(out, domain)
	}
	sort.Strings(out)
	return out, nil
}

func parseSelectorList(raw string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 4)
	for _, candidate := range strings.FieldsFunc(raw, listSplit) {
		selector := strings.ToLower(strings.TrimSpace(candidate))
		if selector == "" {
			continue
		}
		if _, ok := seen[selector]; ok {
			continue
		}
		seen[selector] = struct{}{}
		out = append(out, selector)
	}
	sort.Strings(out)
	return out
}

func listSplit(r rune) bool {
	return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == ';'
}

func buildHealthEvent(st settings, health emaildns.Health, observedAt time.Time) (*primitives.Event, error) {
	if emaildns.NormalizeDomain(health.Domain) != health.Domain {
		return nil, fmt.Errorf("%w: %q", ErrInvalidDomain, health.Domain)
	}
	payload, err := json.Marshal(health)
	if err != nil {
		return nil, fmt.Errorf("marshal email domain health payload: %w", err)
	}
	hash := sha256.Sum256(payload)
	event := &cerebrov1.EventEnvelope{
		Id:         "email-domain-health-" + st.tenantID + "-" + health.Domain + "-" + hex.EncodeToString(hash[:8]),
		TenantId:   st.tenantID,
		SourceId:   sourceID,
		Kind:       kindHealth,
		OccurredAt: timestamppb.New(observedAt),
		SchemaRef:  schemaHealth,
		Payload:    payload,
		Attributes: healthAttributes(st, health, observedAt),
	}
	if err := sourcecdk.ValidateEventEnvelope(event); err != nil {
		return nil, err
	}
	return event, nil
}

func healthAttributes(st settings, health emaildns.Health, observedAt time.Time) map[string]string {
	issueCodes := make([]string, 0, len(health.Issues))
	failingCodes := make([]string, 0, len(health.Issues))
	highest := ""
	for _, issue := range health.Issues {
		if code := strings.TrimSpace(issue.Code); code != "" {
			issueCodes = append(issueCodes, code)
			if emaildns.SeverityRank(issue.Severity) >= 3 {
				failingCodes = append(failingCodes, code)
			}
		}
		if emaildns.SeverityRank(issue.Severity) > emaildns.SeverityRank(highest) {
			highest = issue.Severity
		}
	}
	sort.Strings(issueCodes)
	sort.Strings(failingCodes)
	attributes := map[string]string{
		"event_type":          "email_domain_health",
		"outcome_result":      strings.ToLower(health.Status),
		"resource_type":       "email_domain",
		"resource_id":         health.Domain,
		"domain":              health.Domain,
		"status":              health.Status,
		"score":               fmt.Sprintf("%d", health.Score),
		"spf_status":          health.SPFStatus,
		"dkim_status":         health.DKIMStatus,
		"dmarc_status":        health.DMARCStatus,
		"issue_count":         fmt.Sprintf("%d", health.IssueCount),
		"failing_issue_count": fmt.Sprintf("%d", health.FailingIssueCount),
		"observed_at":         observedAt.UTC().Format(time.RFC3339),
		"source_runtime_id":   st.runtimeID,
		"highest_severity":    strings.ToUpper(highest),
	}
	if len(issueCodes) > 0 {
		attributes["issue_codes"] = strings.Join(issueCodes, ",")
	}
	if len(failingCodes) > 0 {
		attributes["failing_issue_codes"] = strings.Join(failingCodes, ",")
	}
	for key, value := range attributes {
		if strings.TrimSpace(value) == "" {
			delete(attributes, key)
		}
	}
	return attributes
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
