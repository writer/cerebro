package identitysso

import (
	"strings"
	"testing"
)

const validBootstrap = `{"tenantId":"tenant-a","connection":{"id":"okta","name":"Okta","protocol":"oidc","domains":["Example.com"],` +
	`"oidc":{"issuer":"https://example.okta.com","clientId":"client-1","clientSecretRef":"env:CEREBRO_SSO_OKTA_CLIENT_SECRET"},` +
	`"defaultRoles":["cerebro.admin"],"jitProvisioning":true},"policy":{"enforced":true}}`

func TestParseBootstrap(t *testing.T) {
	bootstrap, err := ParseBootstrap([]byte(validBootstrap))
	if err != nil {
		t.Fatalf("ParseBootstrap: %v", err)
	}
	if bootstrap.TenantID != "tenant-a" || bootstrap.Connection.ID != "okta" || bootstrap.Connection.Status != StatusActive {
		t.Fatalf("bootstrap = %+v", bootstrap)
	}
	if got := bootstrap.Connection.Domains; len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("domains = %v", got)
	}
	if !bootstrap.ManagesConnection("tenant-a", "okta") || bootstrap.ManagesConnection("tenant-b", "okta") || bootstrap.ManagesConnection("tenant-a", "other") {
		t.Fatal("ManagesConnection matched the wrong tenant or connection")
	}
	if !bootstrap.EnforcesPolicy("tenant-a") || bootstrap.EnforcesPolicy("tenant-b") {
		t.Fatal("EnforcesPolicy matched the wrong tenant")
	}
	var unset *Bootstrap
	if unset.ManagesConnection("tenant-a", "okta") || unset.EnforcesPolicy("tenant-a") {
		t.Fatal("nil bootstrap claimed ownership")
	}
}

func TestParseBootstrapRejects(t *testing.T) {
	cases := map[string]string{
		"not json":           `{`,
		"two documents":      validBootstrap + validBootstrap,
		"missing tenant":     strings.Replace(validBootstrap, `"tenantId":"tenant-a",`, ``, 1),
		"missing connection": `{"tenantId":"tenant-a"}`,
		"bad id":             strings.Replace(validBootstrap, `"id":"okta"`, `"id":"../okta"`, 1),
		"raw secret field":   strings.Replace(validBootstrap, `"clientId":"client-1"`, `"clientId":"client-1","clientSecret":"hunter2"`, 1),
		"raw secret value":   strings.Replace(validBootstrap, `env:CEREBRO_SSO_OKTA_CLIENT_SECRET`, `hunter2`, 1),
		"unknown role":       strings.Replace(validBootstrap, `"cerebro.admin"`, `"root"`, 1),
		"draft status":       strings.Replace(validBootstrap, `"name":"Okta"`, `"name":"Okta","status":"draft"`, 1),
		"bad policy":         strings.Replace(validBootstrap, `{"enforced":true}`, `{"sessionMaxLifetimeMinutes":-5}`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBootstrap([]byte(raw)); err == nil {
				t.Fatalf("ParseBootstrap accepted %s", raw)
			}
		})
	}
}
