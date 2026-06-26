package grc

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.Spec().Id != "grc" {
		t.Fatalf("Spec().Id = %q, want grc", source.Spec().Id)
	}
	if source.Spec().Name != "GRC" {
		t.Fatalf("Spec().Name = %q, want GRC", source.Spec().Name)
	}
}

func TestParseSettingsRequiresTenant(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"client_id":     testClientID,
		"client_secret": testClientSecret,
		"family":        familyVendor,
	}))
	if err == nil {
		t.Fatal("Check() error = nil, want tenant_id error")
	}
}

func TestParseSettingsUsesRuntimeTenantFallback(t *testing.T) {
	settings, err := parseSettings(sourcecdk.NewConfig(map[string]string{
		"client_id":                     testClientID,
		"client_secret":                 testClientSecret,
		"family":                        familyVendor,
		sourceconfig.RuntimeTenantIDKey: "writer",
	}), true)
	if err != nil {
		t.Fatalf("parseSettings() error = %v", err)
	}
	if settings.tenantID != "writer" {
		t.Fatalf("tenantID = %q, want writer", settings.tenantID)
	}
}

func TestParseSettingsRejectsUnknownProvider(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"client_id":     testClientID,
		"client_secret": testClientSecret,
		"family":        familyVendor,
		"provider":      "drata",
		"tenant_id":     "writer",
	}))
	if err == nil {
		t.Fatal("Check() error = nil, want unknown provider error")
	}
}

func TestParseSettingsRejectsUntrustedVantaHosts(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	base := map[string]string{
		"client_id":     testClientID,
		"client_secret": testClientSecret,
		"family":        familyVendor,
		"provider":      "vanta",
		"tenant_id":     "writer",
	}
	cases := map[string]map[string]string{
		"base url":  {"base_url": "https://attacker.example"},
		"token url": {"token_url": "https://attacker.example/oauth/token"}, // #nosec G101 -- key name is a URL fixture, not credential material.
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			values := map[string]string{}
			for key, value := range base {
				values[key] = value
			}
			for key, value := range overrides {
				values[key] = value
			}
			err := source.Check(context.Background(), sourcecdk.NewConfig(values))
			if err == nil {
				t.Fatal("Check() error = nil, want untrusted host error")
			}
		})
	}
}
