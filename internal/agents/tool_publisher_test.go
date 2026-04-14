package agents

import (
	"encoding/json"
	"testing"
	"time"
)

func TestToolPublisherConfigWithDefaults(t *testing.T) {
	cfg := (ToolPublisherConfig{}).withDefaults()
	if len(cfg.URLs) == 0 {
		t.Fatal("expected default URLs")
	}
	if cfg.ManifestSubject == "" || cfg.RequestPrefix == "" {
		t.Fatal("expected default manifest subject and request prefix")
	}
	if cfg.RequestTimeout <= 0 {
		t.Fatal("expected positive default request timeout")
	}
}

func TestToolPublisherConfigValidate(t *testing.T) {
	valid := (ToolPublisherConfig{
		Enabled:         true,
		URLs:            []string{"nats://127.0.0.1:4222"},
		ManifestSubject: "cerebro.tools.manifest",
		RequestPrefix:   "cerebro.tools.request",
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

func TestDecodeToolInvocationRequest_WrappedArguments(t *testing.T) {
	req, args, err := decodeToolInvocationRequest([]byte(`{"tool":"cerebro.blast_radius","arguments":{"principal_id":"user:1","max_depth":4}}`))
	if err != nil {
		t.Fatalf("decode wrapped request: %v", err)
	}
	if req.Tool != "cerebro.blast_radius" {
		t.Fatalf("tool = %q, want cerebro.blast_radius", req.Tool)
	}
	if !json.Valid(args) {
		t.Fatalf("expected valid args JSON, got %q", string(args))
	}
}

func TestDecodeToolInvocationRequest_RawArguments(t *testing.T) {
	req, args, err := decodeToolInvocationRequest([]byte(`{"principal_id":"user:1"}`))
	if err != nil {
		t.Fatalf("decode raw request: %v", err)
	}
	if req.Tool != "" {
		t.Fatalf("tool = %q, want empty", req.Tool)
	}
	if string(args) != `{"principal_id":"user:1"}` {
		t.Fatalf("args = %q, want raw object", string(args))
	}
}

func TestDecodeToolInvocationRequest_RawNonObjectArguments(t *testing.T) {
	req, args, err := decodeToolInvocationRequest([]byte(`["a","b"]`))
	if err != nil {
		t.Fatalf("decode raw non-object request: %v", err)
	}
	if req.Tool != "" {
		t.Fatalf("tool = %q, want empty", req.Tool)
	}
	if string(args) != `["a","b"]` {
		t.Fatalf("args = %q, want raw array", string(args))
	}
}

func TestDecodeToolInvocationRequest_ArgumentsRawFallback(t *testing.T) {
	_, args, err := decodeToolInvocationRequest([]byte(`{"tool":"cerebro.findings","arguments_raw":"status=open"}`))
	if err != nil {
		t.Fatalf("decode arguments_raw request: %v", err)
	}
	if string(args) != `"status=open"` {
		t.Fatalf("args = %q, want quoted string", string(args))
	}
}

func TestDecodeToolInvocationRequest_InvalidPayload(t *testing.T) {
	if _, _, err := decodeToolInvocationRequest([]byte("not-json")); err == nil {
		t.Fatal("expected decode error for invalid payload")
		return
	}
}

func TestExtractToolNameFromSubject(t *testing.T) {
	got := extractToolNameFromSubject("cerebro.tools.request", "cerebro.tools.request.cerebro.simulate")
	if got != "cerebro.simulate" {
		t.Fatalf("tool name = %q, want cerebro.simulate", got)
	}
	if extractToolNameFromSubject("cerebro.tools.request", "ensemble.tools.request.any") != "" {
		t.Fatal("expected empty tool name for non-matching subject")
	}
}

func TestEncodeToolSuccessPayload_EmbedsJSON(t *testing.T) {
	payload := encodeToolSuccessPayload(`{"ok":true}`)
	var envelope remoteToolEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if envelope.Status != "ok" {
		t.Fatalf("status = %q, want ok", envelope.Status)
	}
	if string(envelope.Data) != `{"ok":true}` {
		t.Fatalf("data = %q, want JSON object", string(envelope.Data))
	}
}

func TestToolPublisherManifestTimeoutDefaulting(t *testing.T) {
	cfg := (ToolPublisherConfig{Enabled: true}).withDefaults()
	if cfg.RequestTimeout != 30*time.Second {
		t.Fatalf("request timeout = %s, want 30s", cfg.RequestTimeout)
	}
}
