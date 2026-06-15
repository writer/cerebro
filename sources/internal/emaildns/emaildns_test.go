package emaildns

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"testing"
)

type fakeResolver struct {
	txt    map[string][]string
	txtErr map[string]error
	mx     map[string][]*net.MX
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if err, ok := f.txtErr[name]; ok {
		return nil, err
	}
	return f.txt[name], nil
}

func (f fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return f.mx[name], nil
}

func TestNormalizeDomainAcceptsCanonicalForms(t *testing.T) {
	cases := map[string]string{
		"example.com":              "example.com",
		"Security@Example.COM":     "example.com",
		"https://mail.Example.com": "mail.example.com",
		"www.Example.com:443":      "example.com",
		"":                         "",
		"local.local":              "",
		"10.0.0.1":                 "",
	}
	for input, want := range cases {
		if got := NormalizeDomain(input); got != want {
			t.Fatalf("NormalizeDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestEvaluateClassifiesFailingDomain(t *testing.T) {
	resolver := fakeResolver{
		txt: map[string][]string{
			"failing.example.com":                    {"v=spf1 +all"},
			"default._domainkey.failing.example.com": {"v=DKIM1; p=" + base64.StdEncoding.EncodeToString(make([]byte, 64))},
		},
		txtErr: map[string]error{
			"_dmarc.failing.example.com": errors.New("not found"),
		},
	}
	health := Evaluate(context.Background(), resolver, "failing.example.com", nil)
	if health.Status != StatusFailing {
		t.Fatalf("Status = %q, want FAILING", health.Status)
	}
	if health.SPFPolicy != "+all" {
		t.Fatalf("SPFPolicy = %q", health.SPFPolicy)
	}
	codes := map[string]bool{}
	for _, issue := range health.Issues {
		codes[issue.Code] = true
	}
	for _, expected := range []string{"spf_permissive_all", "dmarc_missing", "dkim_weak_key"} {
		if !codes[expected] {
			t.Fatalf("expected issue code %q in %+v", expected, codes)
		}
	}
	if !strings.EqualFold(health.SPFStatus, StatusFailing) {
		t.Fatalf("SPFStatus = %q", health.SPFStatus)
	}
}

func TestSeverityRankOrders(t *testing.T) {
	if SeverityRank(SeverityCrit) <= SeverityRank(SeverityHigh) {
		t.Fatalf("CRITICAL rank must exceed HIGH rank")
	}
	if SeverityRank("unknown") != 0 {
		t.Fatalf("unknown severity should rank 0")
	}
}
