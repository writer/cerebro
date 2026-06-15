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
		"www.www.Example.com":      "example.com",
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

func TestEvaluateDoesNotMarkPermissiveSPFAsHealthy(t *testing.T) {
	resolver := fakeResolver{
		txt: map[string][]string{
			"neutral.example.com":                    {"v=spf1 ?all"},
			"_dmarc.neutral.example.com":             {"v=DMARC1; p=reject; rua=mailto:dmarc@neutral.example.com"},
			"default._domainkey.neutral.example.com": {"v=DKIM1; p=" + base64.StdEncoding.EncodeToString(make([]byte, 256))},
		},
		mx: map[string][]*net.MX{"neutral.example.com": {{Host: "mx.example.com.", Pref: 10}}},
	}
	health := Evaluate(context.Background(), resolver, "neutral.example.com", nil)
	if health.Status == StatusHealthy {
		t.Fatalf("Status = HEALTHY for SPF ?all; want WARNING or FAILING")
	}
	if !findIssueCode(health.Issues, "spf_neutral_all") {
		t.Fatalf("expected spf_neutral_all issue; got %+v", health.Issues)
	}
}

func TestEvaluateAcceptsSPFRedirectPolicy(t *testing.T) {
	resolver := fakeResolver{
		txt: map[string][]string{
			"redirect.example.com":                    {"v=spf1 redirect=_spf.example.net"},
			"_dmarc.redirect.example.com":             {"v=DMARC1; p=reject; rua=mailto:dmarc@redirect.example.com"},
			"default._domainkey.redirect.example.com": {"v=DKIM1; p=" + base64.StdEncoding.EncodeToString(make([]byte, 256))},
		},
		mx: map[string][]*net.MX{"redirect.example.com": {{Host: "mx.example.com.", Pref: 10}}},
	}
	health := Evaluate(context.Background(), resolver, "redirect.example.com", nil)
	if health.Status != StatusHealthy {
		t.Fatalf("Status = %q for SPF redirect policy, want HEALTHY; issues=%+v", health.Status, health.Issues)
	}
	if health.SPFPolicy != "redirect" {
		t.Fatalf("SPFPolicy = %q, want redirect", health.SPFPolicy)
	}
	if findIssueCode(health.Issues, "spf_no_terminal_policy") {
		t.Fatalf("SPF redirect policy should not receive spf_no_terminal_policy; issues=%+v", health.Issues)
	}
	if health.SPFLookupCount != 1 {
		t.Fatalf("SPFLookupCount = %d, want redirect lookup counted", health.SPFLookupCount)
	}
}

func TestEvaluateRejectsInvalidDMARCPolicyValue(t *testing.T) {
	resolver := fakeResolver{
		txt: map[string][]string{
			"badp.example.com":                    {"v=spf1 -all"},
			"_dmarc.badp.example.com":             {"v=DMARC1; p=definitely-not-valid; rua=mailto:dmarc@badp.example.com"},
			"default._domainkey.badp.example.com": {"v=DKIM1; p=" + base64.StdEncoding.EncodeToString(make([]byte, 256))},
		},
		mx: map[string][]*net.MX{"badp.example.com": {{Host: "mx.example.com.", Pref: 10}}},
	}
	health := Evaluate(context.Background(), resolver, "badp.example.com", nil)
	if health.Status == StatusHealthy {
		t.Fatalf("Status = HEALTHY for DMARC p=invalid; want WARNING or FAILING")
	}
	if !findIssueCode(health.Issues, "dmarc_policy_invalid") {
		t.Fatalf("expected dmarc_policy_invalid issue; got %+v", health.Issues)
	}
}

func TestEvaluateFlagsInvalidDKIMKeyMaterial(t *testing.T) {
	resolver := fakeResolver{
		txt: map[string][]string{
			"baddkim.example.com":                    {"v=spf1 -all"},
			"_dmarc.baddkim.example.com":             {"v=DMARC1; p=reject; rua=mailto:dmarc@baddkim.example.com"},
			"default._domainkey.baddkim.example.com": {"v=DKIM1; k=rsa; p=not-valid-base64!!!"},
		},
		mx: map[string][]*net.MX{"baddkim.example.com": {{Host: "mx.example.com.", Pref: 10}}},
	}
	health := Evaluate(context.Background(), resolver, "baddkim.example.com", nil)
	if health.Status == StatusHealthy {
		t.Fatalf("Status = HEALTHY for invalid DKIM key; want WARNING or FAILING")
	}
	if !findIssueCode(health.Issues, "dkim_invalid_key") {
		t.Fatalf("expected dkim_invalid_key issue; got %+v", health.Issues)
	}
	if len(health.DKIMSelectors) == 0 || health.DKIMSelectors[0].Status != StatusFailing {
		t.Fatalf("DKIM selector status = %+v, want FAILING", health.DKIMSelectors)
	}
}

func TestEvaluateAcceptsEd25519DKIMKeyMaterial(t *testing.T) {
	ed25519Key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	resolver := fakeResolver{
		txt: map[string][]string{
			"ed25519.example.com":                    {"v=spf1 -all"},
			"_dmarc.ed25519.example.com":             {"v=DMARC1; p=reject; rua=mailto:dmarc@ed25519.example.com"},
			"default._domainkey.ed25519.example.com": {"v=DKIM1; k=ed25519; p=" + ed25519Key},
		},
		mx: map[string][]*net.MX{"ed25519.example.com": {{Host: "mx.example.com.", Pref: 10}}},
	}
	health := Evaluate(context.Background(), resolver, "ed25519.example.com", nil)
	if health.Status != StatusHealthy {
		t.Fatalf("Status = %q for valid Ed25519 DKIM key, want HEALTHY; issues=%+v", health.Status, health.Issues)
	}
	if findIssueCode(health.Issues, "dkim_weak_key") || findIssueCode(health.Issues, "dkim_key_short") {
		t.Fatalf("valid Ed25519 key should not receive RSA strength issue; issues=%+v", health.Issues)
	}
	if len(health.DKIMSelectors) == 0 || health.DKIMSelectors[0].Status != StatusHealthy || health.DKIMSelectors[0].KeyBits != 256 {
		t.Fatalf("DKIM selector = %+v, want healthy 256-bit Ed25519 selector", health.DKIMSelectors)
	}
}

func findIssueCode(issues []Issue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
