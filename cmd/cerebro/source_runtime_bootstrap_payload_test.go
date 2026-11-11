package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func gzipBase64BootstrapValue(t *testing.T, document []byte) string {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(document); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return sourceRuntimeBootstrapGzipBase64Prefix + base64.StdEncoding.EncodeToString(compressed.Bytes())
}

func TestParseSourceRuntimeBootstrapArgsReadsCompressedEnvDocument(t *testing.T) {
	plan := `{"scope":"example","targets":[{"name":"cluster-a","note":"quoted \"value\" and \\ backslash"}]}`
	quotedPlan, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("json.Marshal(plan) error = %v", err)
	}
	document := `{"runtimes":[{"id":"example-cohort","source_id":"github","tenant_id":"example","config":{"scan_plan":` + string(quotedPlan) + `,"token":"env:EXAMPLE_TOKEN"}}]}`
	t.Setenv("CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON", gzipBase64BootstrapValue(t, []byte(document)))

	runtimes, err := parseSourceRuntimeBootstrapArgs([]string{"env=CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON"})
	if err != nil {
		t.Fatalf("parseSourceRuntimeBootstrapArgs() error = %v", err)
	}
	if len(runtimes) != 1 || runtimes[0].GetId() != "example-cohort" || runtimes[0].GetSourceId() != "github" {
		t.Fatalf("runtimes = %#v", runtimes)
	}
	if got := runtimes[0].GetConfig()["scan_plan"]; got != plan {
		t.Fatalf("scan_plan = %q, want byte-identical %q", got, plan)
	}
	if got := runtimes[0].GetConfig()["token"]; got != "env:EXAMPLE_TOKEN" {
		t.Fatalf("token = %q, want env ref", got)
	}
}

func TestDecodeSourceRuntimeBootstrapPayloadEnforcesDecodedSizeLimit(t *testing.T) {
	atLimit := bytes.Repeat([]byte(" "), maxSourceRuntimeBootstrapPayloadBytes)
	decoded, err := decodeSourceRuntimeBootstrapPayload(gzipBase64BootstrapValue(t, atLimit))
	if err != nil {
		t.Fatalf("decodeSourceRuntimeBootstrapPayload(at limit) error = %v", err)
	}
	if decoded != string(atLimit) {
		t.Fatalf("decoded at-limit document has %d bytes, want byte-identical %d", len(decoded), len(atLimit))
	}

	overLimit := bytes.Repeat([]byte(" "), maxSourceRuntimeBootstrapPayloadBytes+1)
	decoded, err = decodeSourceRuntimeBootstrapPayload(gzipBase64BootstrapValue(t, overLimit))
	if err == nil {
		t.Fatal("decodeSourceRuntimeBootstrapPayload(over limit) error = nil, want rejection")
	}
	if decoded != "" {
		t.Fatalf("decodeSourceRuntimeBootstrapPayload(over limit) returned %d bytes, want none", len(decoded))
	}
}

func TestDecodeSourceRuntimeBootstrapPayloadRejectsCorruptEncoding(t *testing.T) {
	validGzip := gzipBase64BootstrapValue(t, []byte(`{"runtimes":[]}`))
	truncatedGzip := validGzip[:len(validGzip)-8]
	for name, value := range map[string]string{
		"invalid base64":  sourceRuntimeBootstrapGzipBase64Prefix + "%%%",
		"not gzip":        sourceRuntimeBootstrapGzipBase64Prefix + base64.StdEncoding.EncodeToString([]byte(`{"runtimes":[]}`)),
		"truncated gzip":  truncatedGzip,
		"missing payload": sourceRuntimeBootstrapGzipBase64Prefix,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeSourceRuntimeBootstrapPayload(value); err == nil {
				t.Fatal("decodeSourceRuntimeBootstrapPayload() error = nil, want non-nil")
			}
		})
	}
}
