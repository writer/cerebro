package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceruntime"
)

func TestRunRejectsUnsupportedCommand(t *testing.T) {
	err := run([]string{"unsupported"})
	var usage usageError
	if !errors.As(err, &usage) {
		t.Fatalf("run(unsupported) error = %v, want usageError", err)
	}
}

func TestParseSourceRuntimePutArgsSeparatesTenantID(t *testing.T) {
	t.Setenv("CEREBRO_TEST_TOKEN", "test")
	runtime, err := parseSourceRuntimePutArgs([]string{
		"writer-okta-users",
		"okta",
		"tenant_id=writer",
		"domain=writer.okta.com",
		"family=user",
		"token=env:CEREBRO_TEST_TOKEN",
	})
	if err != nil {
		t.Fatalf("parseSourceRuntimePutArgs() error = %v", err)
	}
	if got := runtime.GetTenantId(); got != "writer" {
		t.Fatalf("runtime.TenantId = %q, want %q", got, "writer")
	}
	if got := runtime.GetConfig()["domain"]; got != "writer.okta.com" {
		t.Fatalf("runtime.Config[domain] = %q, want %q", got, "writer.okta.com")
	}
	if _, ok := runtime.GetConfig()["tenant_id"]; ok {
		t.Fatal("runtime.Config[tenant_id] present, want omitted")
	}
}

func TestParseSourceCommandArgsRejectsLiteralSensitiveValues(t *testing.T) {
	for _, arg := range []string{
		"token=test-token",
		"clientSecret=test-secret",
		"apiKey=test-key",
		"privateKey=test-key",
	} {
		t.Run(arg, func(t *testing.T) {
			_, _, _, err := parseSourceCommandArgs([]string{"github", arg})
			if err == nil {
				t.Fatal("parseSourceCommandArgs() error = nil, want non-nil")
			}
			if strings.Contains(fmt.Sprint(err), "test-") {
				t.Fatalf("parseSourceCommandArgs() error leaked literal value: %v", err)
			}
		})
	}
}

func TestParseSourceArgsAllowNonSecretAccessKeyID(t *testing.T) {
	_, config, _, err := parseSourceCommandArgs([]string{"aws", "access_key_id=access-key-id"})
	if err != nil {
		t.Fatalf("parseSourceCommandArgs() error = %v", err)
	}
	if got := config["access_key_id"]; got != "access-key-id" {
		t.Fatalf("config[access_key_id] = %q, want access-key-id", got)
	}
	runtime, err := parseSourceRuntimePutArgs([]string{"writer-aws", "aws", "access_key_id=access-key-id"})
	if err != nil {
		t.Fatalf("parseSourceRuntimePutArgs() error = %v", err)
	}
	if got := runtime.GetConfig()["access_key_id"]; got != "access-key-id" {
		t.Fatalf("runtime config[access_key_id] = %q, want access-key-id", got)
	}
}

func TestParseSourceCommandArgsPreservesSensitiveEnvReferences(t *testing.T) {
	t.Setenv("CEREBRO_TEST_TOKEN", "test-token")
	sourceID, config, cursor, err := parseSourceCommandArgs([]string{
		"github",
		"token=env:CEREBRO_TEST_TOKEN",
		"lookup_key=email",
		"cursor=opaque",
	})
	if err != nil {
		t.Fatalf("parseSourceCommandArgs() error = %v", err)
	}
	if sourceID != "github" {
		t.Fatalf("sourceID = %q, want github", sourceID)
	}
	if got := config["token"]; got != "env:CEREBRO_TEST_TOKEN" {
		t.Fatalf("config[token] = %q, want env reference", got)
	}
	if got := config["lookup_key"]; got != "email" {
		t.Fatalf("config[lookup_key] = %q, want email", got)
	}
	if cursor.GetOpaque() != "opaque" {
		t.Fatalf("cursor = %q, want opaque", cursor.GetOpaque())
	}
}

func TestParseSourceCommandArgsPreservesEnvPrefixForNonSensitiveValues(t *testing.T) {
	t.Setenv("prod", "from-env")
	_, config, _, err := parseSourceCommandArgs([]string{"github", "phrase=env:prod"})
	if err != nil {
		t.Fatalf("parseSourceCommandArgs() error = %v", err)
	}
	if got := config["phrase"]; got != "env:prod" {
		t.Fatalf("config[phrase] = %q, want literal env:prod", got)
	}
}

func TestParseSourceCommandArgsPreservesEnvReferencesForNonSensitiveValues(t *testing.T) {
	t.Setenv("CEREBRO_TEST_OKTA_DOMAIN", "writer.okta.com")
	_, config, _, err := parseSourceCommandArgs([]string{"okta", "domain=env:CEREBRO_TEST_OKTA_DOMAIN"})
	if err != nil {
		t.Fatalf("parseSourceCommandArgs() error = %v", err)
	}
	if got := config["domain"]; got != "env:CEREBRO_TEST_OKTA_DOMAIN" {
		t.Fatalf("config[domain] = %q, want env reference", got)
	}
}

func TestConfigureSourceRuntimeCommandServiceResolvesEnvReferences(t *testing.T) {
	source := &commandTokenSource{}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &commandRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-command-token": {
			Id:       "writer-command-token",
			SourceId: "command_token",
			Config:   map[string]string{"token": "env:CEREBRO_SOURCE_COMMAND_TOKEN_TOKEN"},
		},
	}}
	t.Setenv("CEREBRO_SOURCE_COMMAND_TOKEN_TOKEN", "resolved-token")

	service := configureSourceRuntimeCommandService(sourceruntime.New(registry, store, &commandAppendLog{}, nil))
	if _, err := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "writer-command-token"}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if source.readToken != "resolved-token" {
		t.Fatalf("source read token = %q, want resolved-token", source.readToken)
	}
}

func TestParseSourceCommandArgsAllowsUnsetSensitiveEnvReference(t *testing.T) {
	_, _, _, err := parseSourceCommandArgs([]string{"github", "token=env:CEREBRO_MISSING_TOKEN"})
	if err != nil {
		t.Fatalf("parseSourceCommandArgs() error = %v", err)
	}
}

type commandTokenSource struct {
	readToken string
}

func (s *commandTokenSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "command_token", Name: "Command token"}
}

func (s *commandTokenSource) Check(context.Context, sourcecdk.Config) error {
	return nil
}

func (s *commandTokenSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (s *commandTokenSource) Read(_ context.Context, config sourcecdk.Config, _ *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	s.readToken, _ = config.Lookup("token")
	return sourcecdk.Pull{Events: []*primitives.Event{}}, nil
}

type commandRuntimeStore struct {
	runtimes map[string]*cerebrov1.SourceRuntime
}

func (s *commandRuntimeStore) Ping(context.Context) error {
	return nil
}

func (s *commandRuntimeStore) PutSourceRuntime(_ context.Context, runtime *cerebrov1.SourceRuntime) error {
	s.runtimes[runtime.GetId()] = runtime
	return nil
}

func (s *commandRuntimeStore) GetSourceRuntime(_ context.Context, id string) (*cerebrov1.SourceRuntime, error) {
	runtime, ok := s.runtimes[id]
	if !ok {
		return nil, ports.ErrSourceRuntimeNotFound
	}
	return runtime, nil
}

type commandAppendLog struct{}

func (l *commandAppendLog) Ping(context.Context) error {
	return nil
}

func (l *commandAppendLog) Append(context.Context, *cerebrov1.EventEnvelope) error {
	return nil
}

func TestParseSourceRuntimeListArgs(t *testing.T) {
	filter, err := parseSourceRuntimeListArgs([]string{"tenant_id=writer", "source_id=github", "limit=5"})
	if err != nil {
		t.Fatalf("parseSourceRuntimeListArgs() error = %v", err)
	}
	if filter.TenantID != "writer" || filter.SourceID != "github" || filter.Limit != 5 {
		t.Fatalf("filter = %#v, want writer/github/5", filter)
	}
}

func TestParseSourceRuntimeListArgsRejectsZeroLimit(t *testing.T) {
	if _, err := parseSourceRuntimeListArgs([]string{"limit=0"}); err == nil {
		t.Fatal("parseSourceRuntimeListArgs(limit=0) error = nil, want error")
	}
}

func TestParseOrchestratorOptions(t *testing.T) {
	options, err := parseOrchestratorOptions([]string{"tenant_id=writer", "source_id=github", "limit=2", "page_limit=3", "event_limit=4", "graph_page_limit=5"})
	if err != nil {
		t.Fatalf("parseOrchestratorOptions() error = %v", err)
	}
	if options.Filter.TenantID != "writer" || options.Filter.SourceID != "github" || options.Filter.Limit != 2 || options.PageLimit != 3 || options.EventLimit != 4 || options.GraphPageLimit != 5 {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseOrchestratorOptionsNumericIterationsClearsForever(t *testing.T) {
	options, err := parseOrchestratorOptions([]string{"iterations=forever", "iterations=1"})
	if err != nil {
		t.Fatalf("parseOrchestratorOptions() error = %v", err)
	}
	if options.RunForever || options.Iterations != 1 {
		t.Fatalf("options = %#v, want finite single iteration", options)
	}
}
