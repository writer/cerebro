package emaildomainhealth

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/sources/internal/emaildns"
)

type fakeResolver struct {
	txt    map[string][]string
	txtErr map[string]error
	mx     map[string][]*net.MX
	mxErr  map[string]error
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if err, ok := f.txtErr[name]; ok {
		return nil, err
	}
	return f.txt[name], nil
}

func (f fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if err, ok := f.mxErr[name]; ok {
		return nil, err
	}
	return f.mx[name], nil
}

func TestSourceSpec(t *testing.T) {
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if src.Spec().GetId() != sourceID {
		t.Fatalf("source id = %q", src.Spec().GetId())
	}
	if got, want := src.Spec().GetEmittedKinds(), []string{kindHealth}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("emitted kinds = %v, want %v", got, want)
	}
}

func TestParseSettings(t *testing.T) {
	tests := []struct {
		name    string
		values  map[string]string
		wantErr error
		want    settings
	}{
		{
			name: "defaults",
			values: map[string]string{
				"tenant_id": "writer",
				"domains":   "Example.com, Other.example.com",
			},
			want: settings{
				family:   familyHealth,
				tenantID: "writer",
				domains:  []string{"example.com", "other.example.com"},
			},
		},
		{
			name: "selectors-and-runtime-tenant",
			values: map[string]string{
				sourceconfig.RuntimeTenantIDKey: "writer",
				"domains":                       "example.com",
				"dkim_selectors":                "google, default ; selector1",
				"runtime_id":                    "writer-email-domain-health",
			},
			want: settings{
				family:        familyHealth,
				tenantID:      "writer",
				runtimeID:     "writer-email-domain-health",
				domains:       []string{"example.com"},
				dkimSelectors: []string{"default", "google", "selector1"},
			},
		},
		{
			name:    "missing-tenant",
			values:  map[string]string{"domains": "example.com"},
			wantErr: ErrTenantRequired,
		},
		{
			name:    "missing-domains",
			values:  map[string]string{"tenant_id": "writer"},
			wantErr: ErrDomainsRequired,
		},
		{
			name:    "invalid-domain",
			values:  map[string]string{"tenant_id": "writer", "domains": "not-a-domain"},
			wantErr: ErrInvalidDomain,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSettings(sourcecdk.NewConfig(tc.values))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("parseSettings() error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSettings() error = %v", err)
			}
			if got.family != tc.want.family ||
				got.tenantID != tc.want.tenantID ||
				got.runtimeID != tc.want.runtimeID ||
				!stringSlicesEqual(got.domains, tc.want.domains) ||
				!stringSlicesEqual(got.dkimSelectors, tc.want.dkimSelectors) {
				t.Fatalf("parseSettings() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestReadEmitsOneEventPerDomainAndDetectsIssues(t *testing.T) {
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	healthyKey := base64.StdEncoding.EncodeToString(make([]byte, 256))
	src.resolver = fakeResolver{
		txt: map[string][]string{
			"healthy.example.com": {"v=spf1 include:_spf.google.com -all"},
			"_dmarc.healthy.example.com": {
				"v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@healthy.example.com",
			},
			"default._domainkey.healthy.example.com": {"v=DKIM1; k=rsa; p=" + healthyKey},
			"risky.example.com":                      {"v=spf1 +all"},
			"default._domainkey.risky.example.com":   {"v=DKIM1; p=" + base64.StdEncoding.EncodeToString(make([]byte, 64))},
		},
		txtErr: map[string]error{
			"_dmarc.risky.example.com": errors.New("not found"),
		},
		mx: map[string][]*net.MX{
			"healthy.example.com": {{Host: "aspmx.l.google.com.", Pref: 1}},
			"risky.example.com":   {},
		},
	}
	src.now = func() time.Time { return time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC) }

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"domains":   "healthy.example.com, risky.example.com",
	})
	pull, err := src.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("events = %d, want 2", len(pull.Events))
	}
	byDomain := map[string]map[string]string{}
	for _, event := range pull.Events {
		if event.GetSourceId() != sourceID || event.GetKind() != kindHealth || event.GetSchemaRef() != schemaHealth {
			t.Fatalf("event scope = %q/%q/%q", event.GetSourceId(), event.GetKind(), event.GetSchemaRef())
		}
		if err := sourcecdk.ValidateEventEnvelope(event); err != nil {
			t.Fatalf("ValidateEventEnvelope(%s): %v", event.GetId(), err)
		}
		byDomain[event.GetAttributes()["domain"]] = event.GetAttributes()
	}
	healthy := byDomain["healthy.example.com"]
	if healthy == nil {
		t.Fatalf("healthy.example.com event missing: %v", byDomain)
	}
	if healthy["status"] != emaildns.StatusHealthy {
		t.Fatalf("healthy.example.com status = %q, want HEALTHY", healthy["status"])
	}
	if healthy["spf_status"] != emaildns.StatusHealthy || healthy["dkim_status"] != emaildns.StatusHealthy || healthy["dmarc_status"] != emaildns.StatusHealthy {
		t.Fatalf("healthy per-protocol = %+v", healthy)
	}
	risky := byDomain["risky.example.com"]
	if risky == nil {
		t.Fatalf("risky.example.com event missing")
	}
	if risky["status"] != emaildns.StatusFailing {
		t.Fatalf("risky.example.com status = %q, want FAILING", risky["status"])
	}
	if !strings.Contains(risky["failing_issue_codes"], "spf_permissive_all") {
		t.Fatalf("risky failing codes = %q, missing spf_permissive_all", risky["failing_issue_codes"])
	}
	if !strings.Contains(risky["failing_issue_codes"], "dmarc_missing") {
		t.Fatalf("risky failing codes = %q, missing dmarc_missing", risky["failing_issue_codes"])
	}
	if !strings.Contains(risky["failing_issue_codes"], "dkim_weak_key") {
		t.Fatalf("risky failing codes = %q, missing dkim_weak_key", risky["failing_issue_codes"])
	}
	if risky["highest_severity"] != emaildns.SeverityCrit {
		t.Fatalf("risky highest_severity = %q, want CRITICAL", risky["highest_severity"])
	}
}

func TestNormalizeDomainCandidate(t *testing.T) {
	cases := map[string]string{
		"example.com":                    "example.com",
		"Security@Example.COM":           "example.com",
		"https://mail.example.com/admin": "mail.example.com",
		"www.example.com":                "example.com",
		"tenant-id-without-dot":          "",
		"192.168.0.1":                    "",
		"":                               "",
		"local.local":                    "",
	}
	for input, want := range cases {
		if got := emaildns.NormalizeDomain(input); got != want {
			t.Fatalf("emaildns.NormalizeDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
