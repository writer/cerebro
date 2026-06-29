package sourceops

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	auth0source "github.com/writer/cerebro/sources/auth0"
	githubsource "github.com/writer/cerebro/sources/github"
	googleworkspacesource "github.com/writer/cerebro/sources/googleworkspace"
	oktasource "github.com/writer/cerebro/sources/okta"
	slacksource "github.com/writer/cerebro/sources/slack"
)

func TestList(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	service := New(registry)
	response := service.List()
	if len(response.Sources) != 5 {
		t.Fatalf("len(List().Sources) = %d, want 5", len(response.Sources))
	}
}

func TestCheckDiscoverAndRead(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	service := New(registry)
	ctx := context.Background()

	checkResp, err := service.Check(ctx, &cerebrov1.CheckSourceRequest{
		SourceId: "github",
		Config:   map[string]string{"token": "test"},
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if checkResp.Status != "ok" {
		t.Fatalf("Check().Status = %q, want %q", checkResp.Status, "ok")
	}

	discoverResp, err := service.Discover(ctx, &cerebrov1.DiscoverSourceRequest{
		SourceId: "github",
		Config:   map[string]string{"token": "test"},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(discoverResp.Urns) != 1 {
		t.Fatalf("len(Discover().Urns) = %d, want 1", len(discoverResp.Urns))
	}
	if got := discoverResp.Urns[0]; got != "urn:cerebro:writer:repo:writer/cerebro" {
		t.Fatalf("Discover().Urns[0] = %q, want default GitHub repository URN", got)
	}

	readResp, err := service.Read(ctx, &cerebrov1.ReadSourceRequest{
		SourceId: "github",
		Config:   map[string]string{"token": "test"},
	})
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(readResp.Events) != 1 {
		t.Fatalf("len(Read().Events) = %d, want 1", len(readResp.Events))
	}
	if readResp.NextCursor == nil {
		t.Fatal("Read().NextCursor = nil, want non-nil")
	}
	if len(readResp.PreviewEvents) != 1 {
		t.Fatalf("len(Read().PreviewEvents) = %d, want 1", len(readResp.PreviewEvents))
	}
	if readResp.PreviewEvents[0].EventId != readResp.Events[0].Id {
		t.Fatalf("Read().PreviewEvents[0].EventId = %q, want %q", readResp.PreviewEvents[0].EventId, readResp.Events[0].Id)
	}
	if readResp.PreviewEvents[0].GetEvent().GetId() != readResp.Events[0].GetId() {
		t.Fatalf("Read().PreviewEvents[0].Event.Id = %q, want %q", readResp.PreviewEvents[0].GetEvent().GetId(), readResp.Events[0].GetId())
	}
	if !readResp.PreviewEvents[0].PayloadDecoded {
		t.Fatal("Read().PreviewEvents[0].PayloadDecoded = false, want true")
	}
}

func TestReadEmitsSourceOperationTelemetry(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	service := New(registry)

	stderr := captureSourceOpsStderr(t, func() {
		_, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{
			SourceId: "github",
			Config:   map[string]string{"token": "test"},
		})
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}
	})

	payload := sourceOpsTelemetryPayload(t, stderr, "source.read")
	for key, want := range map[string]any{
		"kind":                "span_end",
		"name":                "source.read",
		"status":              "completed",
		"source_id":           "github",
		"event_count":         float64(1),
		"preview_event_count": float64(1),
		"has_next_cursor":     true,
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	if _, ok := payload["duration_ms"].(float64); !ok {
		t.Fatalf("telemetry duration_ms = %#v, want number; payload=%#v", payload["duration_ms"], payload)
	}
}

func TestSourceOperationTelemetryRecordsFailures(t *testing.T) {
	service := New(nil)

	stderr := captureSourceOpsStderr(t, func() {
		_, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "missing"})
		if !errors.Is(err, ErrSourceNotFound) {
			t.Fatalf("Check() error = %v, want ErrSourceNotFound", err)
		}
	})

	payload := sourceOpsTelemetryPayload(t, stderr, "source.check")
	for key, want := range map[string]any{
		"kind":       "span_end",
		"name":       "source.check",
		"status":     "failed",
		"source_id":  "missing",
		"error_kind": "source_not_found",
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
}

func TestSourceOperationTelemetryUsesSourceErrorKind(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(&errorSource{err: sourcecdk.WrapSourceError(sourcecdk.ErrorKindRateLimited, "failing", "read", errors.New("slow down"))})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := New(registry)

	stderr := captureSourceOpsStderr(t, func() {
		_, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "failing"})
		if err == nil {
			t.Fatal("Check() error = nil, want source error")
		}
	})

	payload := sourceOpsTelemetryPayload(t, stderr, "source.check")
	if got := payload["error_kind"]; got != string(sourcecdk.ErrorKindRateLimited) {
		t.Fatalf("error_kind = %#v, want %q; payload=%#v", got, sourcecdk.ErrorKindRateLimited, payload)
	}
}

func TestCheckRejectsInternalRuntimeConfigKeys(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	service := New(registry)

	_, err = service.Check(context.Background(), &cerebrov1.CheckSourceRequest{
		SourceId: "github",
		Config: map[string]string{
			"token":                                "test",
			sourceconfig.RuntimeTenantIDKey:        "writer",
			sourceconfig.AWSAssumeRoleAllowlistKey: "writer=arn:aws:iam::123456789012:role/cerebro-org-scan-role",
		},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Check() error = %v, want ErrInvalidRequest", err)
	}
}

func TestPreviewRejectsServerLocalSourceConfig(t *testing.T) {
	kubernetes := &recordingSource{id: "kubernetes"}
	trivy := &recordingSource{id: "trivy"}
	registry, err := sourcecdk.NewRegistry(kubernetes, trivy)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := New(registry)

	for _, tt := range []struct {
		name     string
		sourceID string
		config   map[string]string
	}{
		{
			name:     "kubernetes in cluster",
			sourceID: "kubernetes",
			config:   map[string]string{"tenant_id": "writer", "in_cluster": "true"},
		},
		{
			name:     "kubernetes kubeconfig path",
			sourceID: "kubernetes",
			config:   map[string]string{"tenant_id": "writer", "kubeconfig_path": "/var/run/cerebro/kubeconfig"},
		},
		{
			name:     "kubernetes kubeconfig alias",
			sourceID: "kubernetes",
			config:   map[string]string{"tenant_id": "writer", "kubeconfig": "/var/run/cerebro/kubeconfig"},
		},
		{
			name:     "trivy path",
			sourceID: "trivy",
			config:   map[string]string{"tenant_id": "writer", "path": "/var/lib/cerebro/report.json"},
		},
		{
			name:     "trivy report path",
			sourceID: "trivy",
			config:   map[string]string{"tenant_id": "writer", "report_path": "/var/lib/cerebro/report.json"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			beforeCalls := kubernetes.calls + trivy.calls
			if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: tt.sourceID, Config: tt.config}); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Check() error = %v, want ErrInvalidRequest", err)
			}
			if _, err := service.Discover(context.Background(), &cerebrov1.DiscoverSourceRequest{SourceId: tt.sourceID, Config: tt.config}); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Discover() error = %v, want ErrInvalidRequest", err)
			}
			if _, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: tt.sourceID, Config: tt.config}); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Read() error = %v, want ErrInvalidRequest", err)
			}
			if got := kubernetes.calls + trivy.calls; got != beforeCalls {
				t.Fatalf("source calls = %d, want %d", got, beforeCalls)
			}
		})
	}
}

func TestPreviewAllowsServerLocalSourceConfigForInternalRuntime(t *testing.T) {
	trivy := &recordingSource{id: "trivy"}
	registry, err := sourcecdk.NewRegistry(trivy)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := New(registry).WithInternalConfigAllowed()

	if _, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{
		SourceId: "trivy",
		Config: map[string]string{
			"tenant_id":   "writer",
			"report_path": "/var/lib/cerebro/report.json",
		},
	}); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if trivy.calls != 1 {
		t.Fatalf("trivy calls = %d, want 1", trivy.calls)
	}
}

func TestCheckDiscoverAndReadOkta(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	service := New(registry)
	ctx := context.Background()

	config := map[string]string{
		"domain": "writer.okta.com",
		"family": "user",
		"token":  "test",
	}

	checkResp, err := service.Check(ctx, &cerebrov1.CheckSourceRequest{
		SourceId: "okta",
		Config:   config,
	})
	if err != nil {
		t.Fatalf("Check(okta) error = %v", err)
	}
	if checkResp.Status != "ok" {
		t.Fatalf("Check(okta).Status = %q, want %q", checkResp.Status, "ok")
	}

	discoverResp, err := service.Discover(ctx, &cerebrov1.DiscoverSourceRequest{
		SourceId: "okta",
		Config:   config,
	})
	if err != nil {
		t.Fatalf("Discover(okta) error = %v", err)
	}
	if len(discoverResp.Urns) != 2 {
		t.Fatalf("len(Discover(okta).Urns) = %d, want 2", len(discoverResp.Urns))
	}

	readResp, err := service.Read(ctx, &cerebrov1.ReadSourceRequest{
		SourceId: "okta",
		Config:   config,
	})
	if err != nil {
		t.Fatalf("Read(okta) error = %v", err)
	}
	if len(readResp.Events) != 1 {
		t.Fatalf("len(Read(okta).Events) = %d, want 1", len(readResp.Events))
	}
	if len(readResp.PreviewEvents) != 1 {
		t.Fatalf("len(Read(okta).PreviewEvents) = %d, want 1", len(readResp.PreviewEvents))
	}
	if !readResp.PreviewEvents[0].PayloadDecoded {
		t.Fatal("Read(okta).PreviewEvents[0].PayloadDecoded = false, want true")
	}
}

func TestCheckDiscoverAndReadGoogleWorkspace(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	service := New(registry)
	ctx := context.Background()

	config := map[string]string{
		"domain":   "writer.com",
		"family":   "user",
		"token":    "test-token",
		"per_page": "1",
	}
	checkResp, err := service.Check(ctx, &cerebrov1.CheckSourceRequest{
		SourceId: "google_workspace",
		Config:   config,
	})
	if err != nil {
		t.Fatalf("Check(google_workspace) error = %v", err)
	}
	if checkResp.Status != "ok" {
		t.Fatalf("Check(google_workspace).Status = %q, want ok", checkResp.Status)
	}
	discoverResp, err := service.Discover(ctx, &cerebrov1.DiscoverSourceRequest{
		SourceId: "google_workspace",
		Config:   config,
	})
	if err != nil {
		t.Fatalf("Discover(google_workspace) error = %v", err)
	}
	if len(discoverResp.Urns) != 2 {
		t.Fatalf("len(Discover(google_workspace).Urns) = %d, want 2", len(discoverResp.Urns))
	}
	readResp, err := service.Read(ctx, &cerebrov1.ReadSourceRequest{
		SourceId: "google_workspace",
		Config:   config,
	})
	if err != nil {
		t.Fatalf("Read(google_workspace) error = %v", err)
	}
	if len(readResp.Events) != 1 {
		t.Fatalf("len(Read(google_workspace).Events) = %d, want 1", len(readResp.Events))
	}
	if got := readResp.Events[0].GetKind(); got != "google_workspace.user" {
		t.Fatalf("Read(google_workspace).Events[0].Kind = %q, want google_workspace.user", got)
	}
}

func TestUnknownSource(t *testing.T) {
	service := New(nil)
	_, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "github"})
	if !errors.Is(err, ErrSourceNotFound) {
		t.Fatalf("Check() error = %v, want ErrSourceNotFound", err)
	}
}

func TestEmptySourceIDIsInvalidRequest(t *testing.T) {
	service := New(nil)
	_, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Check() error = %v, want ErrInvalidRequest", err)
	}
}

func TestSourceValidationErrorsAreInvalidRequests(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	service := New(registry)
	if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "github"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Check() error = %v, want ErrInvalidRequest", err)
	}
	if _, err := service.Discover(context.Background(), &cerebrov1.DiscoverSourceRequest{SourceId: "github"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Discover() error = %v, want ErrInvalidRequest", err)
	}
	if _, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: "github"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Read() error = %v, want ErrInvalidRequest", err)
	}
}

func TestSourceOperationErrorsAreNotInvalidRequests(t *testing.T) {
	upstreamErr := errors.New("upstream timeout")
	registry, err := sourcecdk.NewRegistry(&errorSource{err: upstreamErr})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := New(registry)
	if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "failing"}); !errors.Is(err, upstreamErr) || errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Check() error = %v, want upstream error without ErrInvalidRequest", err)
	}
	if _, err := service.Discover(context.Background(), &cerebrov1.DiscoverSourceRequest{SourceId: "failing"}); !errors.Is(err, upstreamErr) || errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Discover() error = %v, want upstream error without ErrInvalidRequest", err)
	}
	if _, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: "failing"}); !errors.Is(err, upstreamErr) || errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Read() error = %v, want upstream error without ErrInvalidRequest", err)
	}
}

type errorSource struct {
	err error
}

func (s *errorSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "failing", Name: "Failing"}
}

func (s *errorSource) Check(context.Context, sourcecdk.Config) error {
	return s.err
}

func (s *errorSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, s.err
}

func (s *errorSource) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return sourcecdk.Pull{}, s.err
}

type recordingSource struct {
	id    string
	calls int
}

func (s *recordingSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: s.id, Name: "Recording " + s.id}
}

func (s *recordingSource) Check(context.Context, sourcecdk.Config) error {
	s.calls++
	return nil
}

func (s *recordingSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	s.calls++
	return nil, nil
}

func (s *recordingSource) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	s.calls++
	return sourcecdk.Pull{}, nil
}

func newFixtureRegistry() (*sourcecdk.Registry, error) {
	source, err := githubsource.NewFixture()
	if err != nil {
		return nil, err
	}
	auth0, err := auth0source.NewFixture()
	if err != nil {
		return nil, err
	}
	okta, err := oktasource.NewFixture()
	if err != nil {
		return nil, err
	}
	googleWorkspace, err := googleworkspacesource.NewFixture()
	if err != nil {
		return nil, err
	}
	slack, err := slacksource.NewFixture()
	if err != nil {
		return nil, err
	}
	return sourcecdk.NewRegistry(source, auth0, googleWorkspace, okta, slack)
}

func captureSourceOpsStderr(t *testing.T, fn func()) string {
	t.Helper()
	oldStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe stderr: %v", err)
	}
	os.Stderr = writer
	defer func() {
		os.Stderr = oldStderr
	}()
	fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	payload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(payload)
}

func sourceOpsTelemetryPayload(t *testing.T, stderr string, name string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		payload := map[string]any{}
		if err := json.Unmarshal([]byte(lines[i]), &payload); err != nil {
			t.Fatalf("unmarshal telemetry payload %q: %v", lines[i], err)
		}
		if payload["kind"] == "span_end" && payload["name"] == name {
			return payload
		}
	}
	t.Fatalf("telemetry span_end %q not found in stderr: %s", name, stderr)
	return nil
}
