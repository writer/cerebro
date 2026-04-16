package agents

import (
	"encoding/json"
	"testing"
	"time"
)

func TestRemoteToolProviderConfigWithDefaults(t *testing.T) {
	cfg := (RemoteToolProviderConfig{}).withDefaults()
	if len(cfg.URLs) == 0 {
		t.Fatal("expected default URLs")
	}
	if cfg.ManifestSubject == "" || cfg.RequestPrefix == "" {
		t.Fatal("expected default manifest subject and request prefix")
	}
	if cfg.DiscoverTimeout <= 0 || cfg.RequestTimeout <= 0 {
		t.Fatal("expected positive default timeouts")
	}
}

func TestRemoteToolProviderConfigValidate(t *testing.T) {
	valid := (RemoteToolProviderConfig{
		Enabled:         true,
		URLs:            []string{"nats://127.0.0.1:4222"},
		ManifestSubject: "ensemble.tools.manifest",
		RequestPrefix:   "ensemble.tools.request",
		AuthMode:        "none",
	}).withDefaults()
	if err := valid.validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}

	invalidAuth := valid
	invalidAuth.AuthMode = "unknown"
	if err := invalidAuth.validate(); err == nil {
		t.Fatal("expected validation error for unknown auth mode")
		return
	}

	missingUserPass := valid
	missingUserPass.AuthMode = "userpass"
	missingUserPass.Username = ""
	missingUserPass.Password = ""
	if err := missingUserPass.validate(); err == nil {
		t.Fatal("expected validation error for missing userpass credentials")
		return
	}
}

func TestRemoteToolProviderConfigRejectsInsecureTLSWithoutOverride(t *testing.T) {
	cfg := (RemoteToolProviderConfig{
		Enabled:               true,
		URLs:                  []string{"nats://127.0.0.1:4222"},
		ManifestSubject:       "ensemble.tools.manifest",
		RequestPrefix:         "ensemble.tools.request",
		TLSEnabled:            true,
		TLSInsecureSkipVerify: true,
	}).withDefaults()

	if _, err := cfg.natsOptions(); err == nil {
		t.Fatal("expected insecure TLS override error")
	}
}

func TestRemoteToolProviderConfigAllowsInsecureTLSWithExplicitOverride(t *testing.T) {
	cfg := (RemoteToolProviderConfig{
		Enabled:               true,
		URLs:                  []string{"nats://127.0.0.1:4222"},
		ManifestSubject:       "ensemble.tools.manifest",
		RequestPrefix:         "ensemble.tools.request",
		TLSEnabled:            true,
		TLSInsecureSkipVerify: true,
		AllowInsecureTLS:      true,
	}).withDefaults()

	if _, err := cfg.natsOptions(); err != nil {
		t.Fatalf("expected explicit insecure TLS override to succeed, got %v", err)
	}
}

func TestDecodeRemoteManifest(t *testing.T) {
	asArray := []byte(`[
	  {"name":"hubspot_get_company","description":"Get company","parameters":{"type":"object"},"requires_approval":false}
	]`)
	arrayTools, err := decodeRemoteManifest(asArray)
	if err != nil {
		t.Fatalf("decode array manifest: %v", err)
	}
	if len(arrayTools) != 1 || arrayTools[0].Name != "hubspot_get_company" {
		t.Fatalf("unexpected array decode result: %#v", arrayTools)
	}

	asWrapped := []byte(`{
	  "tools": [
	    {"name":"zendesk_search_tickets","description":"Search tickets","parameters":{"type":"object"},"requires_approval":true}
	  ]
	}`)
	wrappedTools, err := decodeRemoteManifest(asWrapped)
	if err != nil {
		t.Fatalf("decode wrapped manifest: %v", err)
	}
	if len(wrappedTools) != 1 || wrappedTools[0].Name != "zendesk_search_tickets" {
		t.Fatalf("unexpected wrapped decode result: %#v", wrappedTools)
	}

	if _, err := decodeRemoteManifest([]byte(`{"invalid":true}`)); err == nil {
		t.Fatal("expected decode error for invalid manifest payload")
		return
	}
}

func TestMergeToolsSkipsDuplicates(t *testing.T) {
	base := []Tool{
		{Name: "list_findings"},
		{Name: "query_assets"},
	}
	extras := []Tool{
		{Name: "query_assets"},
		{Name: "hubspot_get_company"},
	}
	merged := MergeTools(base, extras)
	if len(merged) != 3 {
		t.Fatalf("expected 3 tools after merge, got %d", len(merged))
	}
	if merged[2].Name != "hubspot_get_company" {
		t.Fatalf("expected last tool to be hubspot_get_company, got %s", merged[2].Name)
	}
}

func TestRemoteToolEnvelopePassThroughData(t *testing.T) {
	envelope := remoteToolEnvelope{
		Status: "ok",
		Data:   json.RawMessage(`{"result":"success"}`),
	}
	if len(envelope.Data) == 0 {
		t.Fatal("expected data payload")
	}
}

func TestRemoteManifestToolTimeoutDefaulting(t *testing.T) {
	cfg := (RemoteToolProviderConfig{
		Enabled: true,
	}).withDefaults()
	if cfg.RequestTimeout != 30*time.Second {
		t.Fatalf("request timeout = %s, want 30s", cfg.RequestTimeout)
	}
}
