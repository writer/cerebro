package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace/noop"
)

func TestEventEmitsParseableJSONLineOnStderr(t *testing.T) {
	stdout, stderr := captureOutput(t, func() {
		Event(context.Background(), "test.event", Attrs(Field{Key: "value", Value: 42}))
	})
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	line := strings.TrimSpace(stderr)
	if !strings.HasPrefix(line, "{") {
		t.Fatalf("telemetry line = %q, want JSON object without log prefix", line)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		t.Fatalf("telemetry line is not JSON: %v", err)
	}
	if got := payload["kind"]; got != "event" {
		t.Fatalf("kind = %v, want event", got)
	}
	if got := payload["name"]; got != "test.event" {
		t.Fatalf("name = %v, want test.event", got)
	}
}

func TestTelemetryFieldsDoNotUseRawErrorKey(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	patterns := []struct {
		name string
		re   *regexp.Regexp
	}{
		{name: `telemetry.Field Key "error"`, re: regexp.MustCompile(`telemetry\.Field\s*\{[\s\S]{0,240}?Key:\s*"error"`)},
		{name: `withTelemetryField key "error"`, re: regexp.MustCompile(`withTelemetryField\s*\([\s\S]{0,240}?"error"\s*,`)},
		{name: `telemetry.Field Value err.Error()`, re: regexp.MustCompile(`telemetry\.Field\s*\{[\s\S]{0,240}?Value:\s*[^}\n]*\.Error\s*\(`)},
		{name: `withTelemetryField err.Error()`, re: regexp.MustCompile(`withTelemetryField\s*\([\s\S]{0,240}?\.Error\s*\(`)},
	}
	var matches []string
	err := filepath.WalkDir(repoRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".idea", ".vscode", "bin", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		if filepath.Clean(path) == filepath.Clean(currentFile) {
			return nil
		}
		contents, err := os.ReadFile(path) // #nosec G304 G122 -- path comes from WalkDir under the repository root in a repository-static lint test.
		if err != nil {
			return err
		}
		for _, pattern := range patterns {
			if pattern.re.Match(contents) {
				rel, err := filepath.Rel(repoRoot, path)
				if err != nil {
					rel = path
				}
				matches = append(matches, rel+" ("+pattern.name+")")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("telemetry raw error field is forbidden; use bounded error_kind instead: %s", strings.Join(matches, ", "))
	}
}

func TestTelemetryFieldsDoNotEmitRawUserAgent(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	patterns := []struct {
		name string
		re   *regexp.Regexp
	}{
		{name: `raw user-agent telemetry key`, re: regexp.MustCompile(`Key:\s*"(http\.request\.header\.user_agent|http\.user_agent)"`)},
	}
	var matches []string
	err := filepath.WalkDir(repoRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".idea", ".vscode", "bin", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		if filepath.Clean(path) == filepath.Clean(currentFile) {
			return nil
		}
		contents, err := os.ReadFile(path) // #nosec G304 G122 -- path comes from WalkDir under the repository root in a repository-static lint test.
		if err != nil {
			return err
		}
		for _, pattern := range patterns {
			if pattern.re.Match(contents) {
				rel, err := filepath.Rel(repoRoot, path)
				if err != nil {
					rel = path
				}
				matches = append(matches, rel+" ("+pattern.name+")")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("telemetry raw user-agent fields are forbidden; emit presence/family only: %s", strings.Join(matches, ", "))
	}
}

func TestParseTraceParentValidatesTraceFlags(t *testing.T) {
	traceID, spanID, ok := ParseTraceParent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	if !ok {
		t.Fatal("valid traceparent was rejected")
	}
	if traceID != "4bf92f3577b34da6a3ce929d0e0e4736" || spanID != "00f067aa0ba902b7" {
		t.Fatalf("traceparent parsed as traceID=%q spanID=%q", traceID, spanID)
	}
	for _, header := range []string{
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-001",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-zz",
	} {
		if _, _, ok := ParseTraceParent(header); ok {
			t.Fatalf("malformed traceparent flags accepted: %q", header)
		}
	}
}

func TestEnsureTraceContextSeedsTraceParentWithoutSpan(t *testing.T) {
	ctx := EnsureTraceContext(context.Background())
	traceparent := TraceParent(ctx)
	traceID, spanID, ok := ParseTraceParent(traceparent)
	if !ok {
		t.Fatalf("TraceParent() = %q, want valid traceparent", traceparent)
	}
	if traceID == "" || spanID == "" {
		t.Fatalf("empty trace context from %q", traceparent)
	}
}

func TestStartAndEventBridgeToOpenTelemetry(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	oldProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		otel.SetTracerProvider(oldProvider)
		_ = provider.Shutdown(context.Background())
	})

	ctx, span := Start(context.Background(), "test.span", Attrs(Field{Key: "source_id", Value: "github"}))
	Event(ctx, "test.event", Attrs(Field{Key: "events_processed", Value: 3}))
	End(span, "completed", Attrs(Field{Key: "status_detail", Value: "ok"}))

	ended := recorder.Ended()
	if len(ended) != 1 {
		t.Fatalf("ended spans = %d, want 1", len(ended))
	}
	if ended[0].Name() != "test.span" {
		t.Fatalf("span name = %q, want test.span", ended[0].Name())
	}
	if len(ended[0].Events()) != 1 || ended[0].Events()[0].Name != "test.event" {
		t.Fatalf("span events = %#v, want test.event", ended[0].Events())
	}
}

func TestStartMainAccumulatesWideEventAnnotations(t *testing.T) {
	_, stderr := captureOutput(t, func() {
		ctx, span := StartMain(context.Background(), "test.main", Attrs(
			Field{Key: "tenant_id", Value: "tenant-1"},
			Field{Key: "auth.credential_tier", Value: "production"},
			Field{Key: "credential_id", Value: "cred-secret"},
			Field{Key: "oversized", Value: strings.Repeat("x", maxAttributeStringLength+256)},
		))
		AnnotateMain(ctx, Attrs(Field{Key: "cache.redis.last_status", Value: "hit"}))
		AnnotateMainIfAbsent(ctx, Attrs(Field{Key: "first.error_stage", Value: "sync"}))
		AnnotateMainIfAbsent(ctx, Attrs(
			Field{Key: "first.error_stage", Value: "graph_ingest"},
			Field{Key: "first.error_kind", Value: "context_deadline_exceeded"},
		))
		IncrementMain(ctx, "cache.redis.hit.count", 1)
		IncrementMain(ctx, "cache.redis.hit.count", 2)
		MaxMain(ctx, "cache.redis.max_latency_ms", 5)
		MaxMain(ctx, "cache.redis.max_latency_ms", 3)
		End(span, "completed", Attrs(Field{Key: "explicit_end_attr", Value: "kept"}))
	})
	payload := telemetrySpanEndPayloadByName(t, stderr, "test.main")
	if payload["main"] != true || payload["wide_event"] != true {
		t.Fatalf("main span flags missing: %#v", payload)
	}
	if got := payload["tenant_id"]; got != "tenant-1" {
		t.Fatalf("tenant_id = %#v, want tenant-1; payload=%#v", got, payload)
	}
	if got := payload["auth.credential_tier"]; got != "production" {
		t.Fatalf("credential tier was unexpectedly redacted: %#v", payload)
	}
	if got := payload["credential_id"]; got != "[redacted]" {
		t.Fatalf("credential_id = %#v, want redacted; payload=%#v", got, payload)
	}
	if got := payload["cache.redis.last_status"]; got != "hit" {
		t.Fatalf("late annotation missing: %#v", payload)
	}
	if got := payload["cache.redis.hit.count"]; got != float64(3) {
		t.Fatalf("incremented count = %#v, want 3; payload=%#v", got, payload)
	}
	if got := payload["cache.redis.max_latency_ms"]; got != float64(5) {
		t.Fatalf("max value = %#v, want 5; payload=%#v", got, payload)
	}
	if got := payload["first.error_stage"]; got != "sync" {
		t.Fatalf("first-if-absent attr = %#v, want sync; payload=%#v", got, payload)
	}
	if got := payload["first.error_kind"]; got != "context_deadline_exceeded" {
		t.Fatalf("first-if-absent new attr = %#v, want context_deadline_exceeded; payload=%#v", got, payload)
	}
	if got := payload["explicit_end_attr"]; got != "kept" {
		t.Fatalf("explicit end attr missing: %#v", payload)
	}
	for key, want := range map[string]any{
		"telemetry.schema.version":  wideEventSchemaVersion,
		"wide_event.schema.version": wideEventSchemaVersion,
		"event.dataset":             "cerebro.wide_events",
		"telemetry.signal.kind":     "span",
		"event.category":            "operation",
		"event.type":                "end",
		"event.outcome":             "success",
		"operation.name":            "test.main",
		"operation.status":          "completed",
		"process.runtime.name":      "go",
		"process.gomaxprocs":        float64(runtime.GOMAXPROCS(0)),
		"process.cpu.count":         float64(runtime.NumCPU()),
	} {
		if got := payload[key]; got != want {
			t.Fatalf("%s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	for _, key := range []string{
		"duration.bucket",
		"process.uptime_ms",
		"go.goroutine.count",
	} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("%s missing from wide event payload=%#v", key, payload)
		}
	}
	oversized, ok := payload["oversized"].(string)
	if !ok || len(oversized) > maxAttributeStringLength+3 || !strings.HasSuffix(oversized, "...") {
		t.Fatalf("oversized attribute was not bounded: len=%d value=%q", len(oversized), oversized)
	}
	if got := payload["service.name"]; got != "cerebro" {
		t.Fatalf("runtime service attr = %#v, want cerebro; payload=%#v", got, payload)
	}
}

func TestBoundStringPreservesUTF8(t *testing.T) {
	got := boundString("aaébb", 3)
	if !utf8.ValidString(got) {
		t.Fatalf("boundString returned invalid UTF-8: %q", got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("boundString(%q) = %q, want ellipsis suffix", "aaébb", got)
	}
}

func TestRuntimeAttributesUseECSAndOTELResourceEnvironment(t *testing.T) {
	previous := configuredRuntimeMetadata()
	ConfigureRuntimeMetadata(RuntimeMetadata{
		ServiceName:           "cerebro-api",
		DeploymentEnvironment: "sec-dev",
		CloudRegion:           "us-east-1",
		ContainerID:           "task-hostname",
		ECSCluster:            "cerebro-sec-dev-cluster",
		ECSServiceName:        "cerebro-sec-dev-api",
		ECSTaskFamily:         "cerebro-sec-dev",
		ECSTaskRevision:       "362",
		ResourceAttributes:    "service.namespace=cerebro,cloud.provider=gcp,cloud.region=europe-west1,cloud.availability_zone=us-east-1a,container.id=otel-container,deployment.environment.name=ignored-by-cerebro-env",
	})
	t.Cleanup(func() {
		ConfigureRuntimeMetadata(previous)
	})

	_, stderr := captureOutput(t, func() {
		_, span := StartMain(context.Background(), "test.runtime", Attrs())
		End(span, "completed", Attrs())
	})
	payload := telemetrySpanEndPayloadByName(t, stderr, "test.runtime")
	for key, want := range map[string]any{
		"service.name":                "cerebro-api",
		"service.namespace":           "cerebro",
		"deployment.environment":      "sec-dev",
		"deployment.environment.name": "sec-dev",
		"cloud.provider":              "aws",
		"cloud.region":                "us-east-1",
		"cloud.platform":              "aws_ecs",
		"cloud.availability_zone":     "us-east-1a",
		"container.id":                "task-hostname",
		"aws.ecs.cluster.name":        "cerebro-sec-dev-cluster",
		"aws.ecs.service.name":        "cerebro-sec-dev-api",
		"aws.ecs.task.family":         "cerebro-sec-dev",
		"aws.ecs.task.revision":       "362",
	} {
		if got := payload[key]; got != want {
			t.Fatalf("%s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
}

func TestMainSpanDependencyAndPhaseRollups(t *testing.T) {
	_, stderr := captureOutput(t, func() {
		ctx, span := StartMain(context.Background(), "test.rollups", Attrs())
		AnnotateMainDependency(ctx, "db.postgres", "statestore.postgres", "query", "completed", Attrs(
			Field{Key: "db.system.name", Value: "postgresql"},
		))
		AnnotateMainDependency(ctx, "outbound.http", "sourcehttp", "round_trip", "failed", Attrs(
			Field{Key: "http.response.status_class", Value: "5xx"},
		))
		AnnotateMainPhase(ctx, "source_runtime.sync", "failed", Attrs(
			Field{Key: "source_id", Value: "github"},
		))
		End(span, "failed", Attrs(Field{Key: "error_kind", Value: "boom_kind"}))
	})
	payload := telemetrySpanEndPayloadByName(t, stderr, "test.rollups")
	expected := map[string]any{
		"event.outcome":                            "failure",
		"operation.status":                         "failed",
		"dependency.operation.count":               float64(2),
		"dependency.error.count":                   float64(1),
		"dependency.db_postgres.operation.count":   float64(1),
		"dependency.outbound_http.operation.count": float64(1),
		"dependency.outbound_http.error.count":     float64(1),
		"dependency.last_system":                   "outbound_http",
		"dependency.last_component":                "sourcehttp",
		"dependency.last_operation":                "round_trip",
		"dependency.last_status":                   "failed",
		"dependency.outbound_http.last_status":     "failed",
		"phase.count":                              float64(1),
		"phase.error.count":                        float64(1),
		"phase.source_runtime_sync.count":          float64(1),
		"phase.source_runtime_sync.error.count":    float64(1),
		"phase.last_name":                          "source_runtime.sync",
		"phase.last_status":                        "failed",
		"phase.source_runtime_sync.status":         "failed",
		"http.response.status_class":               "5xx",
		"source_id":                                "github",
		"error_kind":                               "boom_kind",
	}
	for key, want := range expected {
		if got := payload[key]; got != want {
			t.Fatalf("%s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
}

func TestRuntimeAttributesDoNotInferAWSFromOTELCloudRegion(t *testing.T) {
	previous := configuredRuntimeMetadata()
	ConfigureRuntimeMetadata(RuntimeMetadata{
		ResourceAttributes: "cloud.region=europe-west1,container.id=otel-container",
	})
	t.Cleanup(func() {
		ConfigureRuntimeMetadata(previous)
	})

	_, stderr := captureOutput(t, func() {
		_, span := StartMain(context.Background(), "test.runtime.otel-region", Attrs())
		End(span, "completed", Attrs())
	})
	payload := telemetrySpanEndPayloadByName(t, stderr, "test.runtime.otel-region")
	for key, want := range map[string]any{
		"cloud.provider": "unknown",
		"cloud.region":   "europe-west1",
		"container.id":   "otel-container",
	} {
		if got := payload[key]; got != want {
			t.Fatalf("%s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
}

func TestParseResourceAttributesHandlesEscapedSeparators(t *testing.T) {
	got := parseResourceAttributes(`service.namespace=cerebro,custom.note=hello\,world,custom.expression=a\=b,custom.path=c:\\tmp`)
	for key, want := range map[string]string{
		"service.namespace": "cerebro",
		"custom.note":       "hello,world",
		"custom.expression": "a=b",
		"custom.path":       `c:\tmp`,
	} {
		if got[key] != want {
			t.Fatalf("%s = %q, want %q; attrs=%#v", key, got[key], want, got)
		}
	}
}

func TestEndMapsErrorStatusesToOpenTelemetryErrors(t *testing.T) {
	for _, status := range []string{"failed", "error"} {
		t.Run(status, func(t *testing.T) {
			recorder := tracetest.NewSpanRecorder()
			provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
			oldProvider := otel.GetTracerProvider()
			otel.SetTracerProvider(provider)
			t.Cleanup(func() {
				otel.SetTracerProvider(oldProvider)
				_ = provider.Shutdown(context.Background())
			})

			_, span := Start(context.Background(), "test.span", Attrs())
			End(span, status, Attrs())

			ended := recorder.Ended()
			if len(ended) != 1 {
				t.Fatalf("ended spans = %d, want 1", len(ended))
			}
			if got := ended[0].Status().Code; got != codes.Error {
				t.Fatalf("span status code = %v, want Error", got)
			}
		})
	}
}

func TestCaptureErrorEmitsFingerprintWithoutRawMessage(t *testing.T) {
	_, stderr := captureOutput(t, func() {
		ctx, span := Start(context.Background(), "test.operation", Attrs(Field{Key: "component", Value: "test"}))
		CaptureError(ctx, "test.error", errors.New("secret-token-shaped raw message"), Attrs(
			Field{Key: "component", Value: "test"},
			Field{Key: "operation", Value: "fetch"},
		))
		End(span, "failed", Attrs())
	})
	if strings.Contains(stderr, "secret-token-shaped raw message") {
		t.Fatalf("raw error message leaked into telemetry: %s", stderr)
	}
	if !strings.Contains(stderr, `"name":"test.error"`) {
		t.Fatalf("capture event missing from stderr: %s", stderr)
	}
	if !strings.Contains(stderr, `"error_kind":"error"`) || !strings.Contains(stderr, `"error_fingerprint"`) {
		t.Fatalf("bounded error fields missing from stderr: %s", stderr)
	}
}

func TestCaptureErrorMarksActiveOpenTelemetrySpanErrored(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	oldProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		otel.SetTracerProvider(oldProvider)
		_ = provider.Shutdown(context.Background())
	})

	ctx, span := Start(context.Background(), "test.operation", Attrs())
	CaptureError(ctx, "test.error", context.DeadlineExceeded, Attrs(Field{Key: "component", Value: "test"}))
	End(span, "failed", Attrs())

	ended := recorder.Ended()
	if len(ended) != 1 {
		t.Fatalf("ended spans = %d, want 1", len(ended))
	}
	if ended[0].Status().Code != codes.Error {
		t.Fatalf("span status = %v, want error", ended[0].Status())
	}
	events := ended[0].Events()
	if len(events) != 1 || events[0].Name != "test.error" {
		t.Fatalf("span events = %#v, want test.error", events)
	}
}

func TestConfigureOpenTelemetryDisabledLeavesNoopProviderUsable(t *testing.T) {
	oldProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(noop.NewTracerProvider())
	t.Cleanup(func() { otel.SetTracerProvider(oldProvider) })

	shutdown, err := ConfigureOpenTelemetry(context.Background(), OpenTelemetryOptions{})
	if err != nil {
		t.Fatalf("ConfigureOpenTelemetry() error = %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown() error = %v", err)
	}
	_, span := Start(context.Background(), "noop.span", Attrs())
	End(span, "completed", Attrs())
}

func telemetrySpanEndPayloadByName(t *testing.T, stderr string, name string) map[string]any {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(line), &payload); err != nil {
			t.Fatalf("unmarshal telemetry payload %q: %v", line, err)
		}
		if payload["kind"] == "span_end" && payload["name"] == name {
			return payload
		}
	}
	t.Fatalf("telemetry span_end payload name=%q not found in stderr: %s", name, stderr)
	return nil
}

func captureOutput(t *testing.T, fn func()) (string, string) {
	t.Helper()
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe stdout: %v", err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe stderr: %v", err)
	}
	os.Stdout = stdoutWriter
	os.Stderr = stderrWriter
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
	}()

	fn()
	if err := stdoutWriter.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	if err := stderrWriter.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	stdout, err := io.ReadAll(stdoutReader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	stderr, err := io.ReadAll(stderrReader)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(stdout), string(stderr)
}
