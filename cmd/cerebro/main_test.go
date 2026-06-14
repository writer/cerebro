package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/bootstrap"
	appconfig "github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphagent"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceruntime"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRunRejectsUnsupportedCommand(t *testing.T) {
	err := run([]string{"unsupported"})
	var usage usageError
	if !errors.As(err, &usage) {
		t.Fatalf("run(unsupported) error = %v, want usageError", err)
	}
}

func TestRunDeployRejectsUnsupportedSubcommand(t *testing.T) {
	err := run([]string{"deploy", "bogus"})
	var usage usageError
	if !errors.As(err, &usage) {
		t.Fatalf("run(deploy bogus) error = %v, want usageError", err)
	}
}

func TestValidateServeConfigRequiresAuthMaterial(t *testing.T) {
	err := validateServeConfig(appconfig.Config{
		Auth:      appconfig.AuthConfig{Enabled: true},
		RateLimit: appconfig.RateLimitConfig{Enabled: true},
	})
	if !errors.Is(err, errServeAuthMaterialRequired) {
		t.Fatalf("validateServeConfig() error = %v, want errServeAuthMaterialRequired", err)
	}
}

func TestValidateServeConfigRejectsDisabledRateLimitOutsideDevMode(t *testing.T) {
	err := validateServeConfig(appconfig.Config{
		Auth: appconfig.AuthConfig{
			Enabled: true,
			APIKeys: []appconfig.APIKey{{
				Key:       "token",
				Principal: "ci",
				TenantID:  "writer",
			}},
		},
		RateLimit: appconfig.RateLimitConfig{Enabled: false},
	})
	if !errors.Is(err, errServeRateLimitDisabled) {
		t.Fatalf("validateServeConfig() error = %v, want errServeRateLimitDisabled", err)
	}
}

func TestValidateServeConfigAllowsDevModeOptOut(t *testing.T) {
	err := validateServeConfig(appconfig.Config{DevMode: true})
	if err != nil {
		t.Fatalf("validateServeConfig(dev mode) error = %v", err)
	}
}

func TestWritePreflightReceiptJSONRedactsToBoundedDetail(t *testing.T) {
	receipt := preflightReceipt{
		Kind:   "cerebro.deploy_preflight",
		Status: "fail",
		Checks: []preflightCheck{{
			Name:   "graph_agent_llm.probe",
			Status: "fail",
			Detail: preflightErrorDetail(fmt.Errorf("openrouter failed: %s", strings.Repeat("x", 400))),
		}},
	}
	var buf strings.Builder
	if err := writePreflightReceipt(&buf, receipt, "json"); err != nil {
		t.Fatalf("writePreflightReceipt() error = %v", err)
	}
	if strings.Contains(buf.String(), strings.Repeat("x", 260)) {
		t.Fatalf("preflight detail was not bounded: %s", buf.String())
	}
	var decoded preflightReceipt
	if err := json.Unmarshal([]byte(buf.String()), &decoded); err != nil {
		t.Fatalf("preflight JSON invalid: %v", err)
	}
	if decoded.Status != "fail" || len(decoded.Checks) != 1 {
		t.Fatalf("decoded receipt = %#v", decoded)
	}
}

func TestExecuteDeployPreflightReportsDependencyCloseFailure(t *testing.T) {
	closeErr := errors.New("close failed")
	receipt := executeDeployPreflightWith(context.Background(), preflightRuntime{
		loadConfig: func() (appconfig.Config, error) {
			return appconfig.Config{}, nil
		},
		openDependencies: func(context.Context, appconfig.Config) (bootstrap.Dependencies, func() error, error) {
			return bootstrap.Dependencies{}, func() error { return closeErr }, nil
		},
		probeLLM: func(context.Context, graphagent.LLMClient) error {
			return nil
		},
	})

	if receipt.Status != "fail" {
		t.Fatalf("receipt status = %q, want fail", receipt.Status)
	}
	if got := len(receipt.Checks); got != 4 {
		t.Fatalf("check count = %d, want 4: %#v", got, receipt.Checks)
	}
	closeCheck := receipt.Checks[3]
	if closeCheck.Name != "dependencies.close" || closeCheck.Status != "fail" || closeCheck.Detail == "" {
		t.Fatalf("close check = %#v, want failed dependencies.close detail", closeCheck)
	}
}

func TestSourceRuntimeCommandSignalsIncludeSIGTERM(t *testing.T) {
	signals := sourceRuntimeCommandSignals()
	if len(signals) != 2 || signals[0] != os.Interrupt || signals[1] != syscall.SIGTERM {
		t.Fatalf("sourceRuntimeCommandSignals() = %#v, want interrupt and SIGTERM", signals)
	}
}

func TestSourceRuntimeCommandContextCanBeCanceled(t *testing.T) {
	ctx, cancel := sourceRuntimeCommandContext()
	cancel()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("source runtime command context did not cancel")
	}
}

func TestStartFindingRiskBackfillDoesNotBlockStartup(t *testing.T) {
	backfiller := &blockingFindingRiskBackfiller{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := startFindingRiskBackfill(ctx, backfiller, func(string, ...any) {})
	select {
	case <-backfiller.started:
	case <-time.After(time.Second):
		t.Fatal("backfill did not start")
	}
	select {
	case <-done:
		t.Fatal("backfill completed while still blocked")
	default:
	}

	close(backfiller.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("backfill did not finish after release")
	}
}

func TestWaitForStartupJobsWaitsForCompletion(t *testing.T) {
	done := make(chan struct{})
	waited := make(chan struct{})
	go func() {
		waitForStartupJobs(context.Background(), done)
		close(waited)
	}()
	select {
	case <-waited:
		t.Fatal("waitForStartupJobs returned before job completed")
	default:
	}
	close(done)
	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("waitForStartupJobs did not return after job completed")
	}
}

func TestStartFindingRiskBackfillLogsErrors(t *testing.T) {
	backfiller := &errorFindingRiskBackfiller{err: errors.New("boom")}
	logged := make(chan string, 1)
	done := startFindingRiskBackfill(context.Background(), backfiller, func(format string, args ...any) {
		logged <- fmt.Sprintf(format, args...)
	})
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("backfill did not finish")
	}
	select {
	case message := <-logged:
		if !strings.Contains(message, "boom") {
			t.Fatalf("logged message = %q, want boom", message)
		}
	default:
		t.Fatal("backfill error was not logged")
	}
}

func TestStartFindingRiskBackfillEmitsTelemetry(t *testing.T) {
	backfiller := &errorFindingRiskBackfiller{}
	stderr := captureCommandStderr(t, func() {
		done := startFindingRiskBackfill(context.Background(), backfiller, func(string, ...any) {})
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("finding risk backfill did not finish")
		}
	})

	payload := lastCommandTelemetryPayload(t, stderr)
	if got := payload["name"]; got != "finding.risk_backfill" {
		t.Fatalf("telemetry name = %#v, want finding.risk_backfill; payload=%#v", got, payload)
	}
	if got := payload["status"]; got != "completed" {
		t.Fatalf("telemetry status = %#v, want completed; payload=%#v", got, payload)
	}
	if got := payload["backfiller_present"]; got != true {
		t.Fatalf("telemetry backfiller_present = %#v, want true; payload=%#v", got, payload)
	}
	if _, ok := payload["duration_ms"].(float64); !ok {
		t.Fatalf("telemetry duration_ms = %#v, want number; payload=%#v", payload["duration_ms"], payload)
	}
}

func TestStartFindingRiskBackfillTelemetryRecordsFailures(t *testing.T) {
	backfiller := &errorFindingRiskBackfiller{err: errors.New("boom")}
	stderr := captureCommandStderr(t, func() {
		done := startFindingRiskBackfill(context.Background(), backfiller, func(string, ...any) {})
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("finding risk backfill did not finish")
		}
	})

	payload := lastCommandTelemetryPayload(t, stderr)
	if got := payload["status"]; got != "failed" {
		t.Fatalf("telemetry status = %#v, want failed; payload=%#v", got, payload)
	}
	if got := payload["error_kind"]; got != "finding_risk_backfill_failed" {
		t.Fatalf("telemetry error_kind = %#v, want finding_risk_backfill_failed; payload=%#v", got, payload)
	}
	if strings.Contains(stderr, "boom") {
		t.Fatalf("backfill telemetry leaked raw error: %s", stderr)
	}
}

func TestPrepareGRCReadModelsSkipsStoresWithoutPreparer(t *testing.T) {
	if err := prepareGRCReadModels(context.Background(), &basicStateStore{}); err != nil {
		t.Fatalf("prepareGRCReadModels() error = %v", err)
	}
}

func TestPrepareGRCReadModelsCallsPreparer(t *testing.T) {
	store := &preparingStateStore{}
	if err := prepareGRCReadModels(context.Background(), store); err != nil {
		t.Fatalf("prepareGRCReadModels() error = %v", err)
	}
	if store.calls != 1 {
		t.Fatalf("PrepareGRCReadModels calls = %d, want 1", store.calls)
	}
}

func TestPrepareGRCReadModelsWrapsErrors(t *testing.T) {
	boom := errors.New("boom")
	store := &preparingStateStore{err: boom}
	err := prepareGRCReadModels(context.Background(), store)
	if err == nil {
		t.Fatal("prepareGRCReadModels() error = nil, want error")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("prepareGRCReadModels() error = %v, want wrapped boom", err)
	}
}

func TestStartGRCReadModelWarmupDoesNotBlockStartup(t *testing.T) {
	store := &blockingPreparingStateStore{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := startGRCReadModelWarmup(ctx, store, func(string, ...any) {})
	select {
	case <-store.started:
	case <-time.After(time.Second):
		t.Fatal("GRC read-model warmup did not start")
	}
	select {
	case <-done:
		t.Fatal("GRC read-model warmup completed while still blocked")
	default:
	}

	close(store.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("GRC read-model warmup did not finish after release")
	}
}

func TestStartGRCReadModelWarmupLogsErrors(t *testing.T) {
	store := &preparingStateStore{err: errors.New("boom")}
	logged := make(chan string, 1)

	done := startGRCReadModelWarmup(context.Background(), store, func(format string, args ...any) {
		logged <- fmt.Sprintf(format, args...)
	})
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("GRC read-model warmup did not finish")
	}
	select {
	case message := <-logged:
		if !strings.Contains(message, "prepare grc read models: boom") {
			t.Fatalf("logged message = %q, want wrapped warmup error", message)
		}
	default:
		t.Fatal("GRC read-model warmup error was not logged")
	}
}

func TestStartGRCReadModelWarmupEmitsTelemetry(t *testing.T) {
	store := &preparingStateStore{}
	stderr := captureCommandStderr(t, func() {
		done := startGRCReadModelWarmup(context.Background(), store, func(string, ...any) {})
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("GRC read-model warmup did not finish")
		}
	})

	payload := lastCommandTelemetryPayload(t, stderr)
	if got := payload["kind"]; got != "span_end" {
		t.Fatalf("telemetry kind = %#v, want span_end; payload=%#v", got, payload)
	}
	if got := payload["name"]; got != "grc.read_model_warmup" {
		t.Fatalf("telemetry name = %#v, want grc.read_model_warmup; payload=%#v", got, payload)
	}
	if got := payload["status"]; got != "completed" {
		t.Fatalf("telemetry status = %#v, want completed; payload=%#v", got, payload)
	}
	if got := payload["preparer_present"]; got != true {
		t.Fatalf("telemetry preparer_present = %#v, want true; payload=%#v", got, payload)
	}
	if _, ok := payload["duration_ms"].(float64); !ok {
		t.Fatalf("telemetry duration_ms = %#v, want number; payload=%#v", payload["duration_ms"], payload)
	}
}

func TestStartGRCReadModelWarmupTelemetryRecordsFailures(t *testing.T) {
	store := &preparingStateStore{err: errors.New("boom")}
	stderr := captureCommandStderr(t, func() {
		done := startGRCReadModelWarmup(context.Background(), store, func(string, ...any) {})
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("GRC read-model warmup did not finish")
		}
	})

	payload := lastCommandTelemetryPayload(t, stderr)
	if got := payload["status"]; got != "failed" {
		t.Fatalf("telemetry status = %#v, want failed; payload=%#v", got, payload)
	}
	if got := payload["error_kind"]; got != "grc_read_model_warmup_failed" {
		t.Fatalf("telemetry error_kind = %#v, want grc_read_model_warmup_failed; payload=%#v", got, payload)
	}
	if strings.Contains(stderr, "boom") {
		t.Fatalf("GRC read-model warmup telemetry leaked raw error: %s", stderr)
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
			Config:   map[string]string{"token": "env:CEREBRO_SOURCE_COMMAND_TOKEN_TOKEN"}, // #nosec G101 -- env-reference test fixture, not credential material.
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

func TestSourceRuntimeCommandSyncUsesLeaseStore(t *testing.T) {
	source := &commandTokenSource{}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &commandRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-command-token": {
			Id:       "writer-command-token",
			SourceId: "command_token",
			Config:   map[string]string{"token": "inline-token"},
		},
	}}

	service := configureSourceRuntimeCommandService(sourceruntime.New(registry, store, &commandAppendLog{}, nil))
	if _, err := service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "writer-command-token"}, sourceruntime.SyncWithLeaseOptions{
		LeaseStore: sourceRuntimeCommandLeaseStore(store),
		LeaseOwner: "cli-test-owner",
		LeaseTTL:   time.Hour,
	}); err != nil {
		t.Fatalf("SyncWithLease() error = %v", err)
	}
	if store.leaseID != "writer-command-token" || store.releaseID != "writer-command-token" {
		t.Fatalf("lease/release = %q/%q, want writer-command-token/writer-command-token", store.leaseID, store.releaseID)
	}
	if store.leaseOwner != "cli-test-owner" || store.releaseOwner != "cli-test-owner" {
		t.Fatalf("lease owners = %q/%q, want cli-test-owner", store.leaseOwner, store.releaseOwner)
	}
}

func TestSourceRuntimeCommandLeaseOwnerIdentifiesCLI(t *testing.T) {
	if owner := sourceRuntimeCommandLeaseOwner(); !strings.HasPrefix(owner, "cerebro-cli:") {
		t.Fatalf("sourceRuntimeCommandLeaseOwner() = %q, want cerebro-cli prefix", owner)
	}
}

func TestParseSourceCommandArgsAllowsUnsetSensitiveEnvReference(t *testing.T) {
	_, _, _, err := parseSourceCommandArgs([]string{"github", "token=env:CEREBRO_MISSING_TOKEN"})
	if err != nil {
		t.Fatalf("parseSourceCommandArgs() error = %v", err)
	}
}

func TestParseSourceRuntimeBootstrapArgsReadsEnvDocument(t *testing.T) {
	t.Setenv("CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON", `{
		"runtimes": [
			{
				"id": " writer-okta-users ",
				"source_id": " okta ",
				"tenant_id": " writer ",
				"config": {
					"domain": "env:OKTA_DOMAIN",
					"family": "user",
					"token": "env:OKTA_API_TOKEN"
				},
				"next_cursor": {"opaque": "ignored"}
			}
		]
	}`)
	runtimes, err := parseSourceRuntimeBootstrapArgs([]string{"env=CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON"})
	if err != nil {
		t.Fatalf("parseSourceRuntimeBootstrapArgs() error = %v", err)
	}
	if len(runtimes) != 1 {
		t.Fatalf("len(runtimes) = %d, want 1", len(runtimes))
	}
	runtime := runtimes[0]
	if runtime.GetId() != "writer-okta-users" || runtime.GetSourceId() != "okta" || runtime.GetTenantId() != "writer" {
		t.Fatalf("runtime identity = (%q, %q, %q)", runtime.GetId(), runtime.GetSourceId(), runtime.GetTenantId())
	}
	if got := runtime.GetConfig()["token"]; got != "env:OKTA_API_TOKEN" {
		t.Fatalf("runtime.Config[token] = %q, want env ref", got)
	}
	if runtime.GetNextCursor() != nil {
		t.Fatal("runtime.NextCursor present, want ignored bootstrap progress")
	}
}

func TestParseSourceRuntimeBootstrapJSONAcceptsArray(t *testing.T) {
	runtimes, err := parseSourceRuntimeBootstrapJSON(`[{"id":"runtime-1","sourceId":"github","config":{"owner":"writer","repo":"cerebro"}}]`)
	if err != nil {
		t.Fatalf("parseSourceRuntimeBootstrapJSON() error = %v", err)
	}
	if len(runtimes) != 1 || runtimes[0].GetSourceId() != "github" {
		t.Fatalf("runtimes = %#v", runtimes)
	}
}

func TestParseSourceRuntimeBootstrapRejectsLiteralSensitiveValues(t *testing.T) {
	_, err := parseSourceRuntimeBootstrapJSON(`{"runtimes":[{"id":"runtime-1","source_id":"github","config":{"token":"test-token"}}]}`)
	if err == nil {
		t.Fatal("parseSourceRuntimeBootstrapJSON() error = nil, want non-nil")
	}
	if strings.Contains(fmt.Sprint(err), "test-token") {
		t.Fatalf("parseSourceRuntimeBootstrapJSON() error leaked literal value: %v", err)
	}
}

func TestParseSourceRuntimeBootstrapRejectsDuplicateRuntimeIDs(t *testing.T) {
	_, err := parseSourceRuntimeBootstrapJSON(`{"runtimes":[{"id":"runtime-1","source_id":"github"},{"id":"runtime-1","source_id":"okta"}]}`)
	if err == nil {
		t.Fatal("parseSourceRuntimeBootstrapJSON() error = nil, want non-nil")
	}
	if !strings.Contains(fmt.Sprint(err), "duplicate runtime id") {
		t.Fatalf("parseSourceRuntimeBootstrapJSON() error = %v, want duplicate runtime id", err)
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
	runtimes     map[string]*cerebrov1.SourceRuntime
	leaseID      string
	leaseOwner   string
	releaseID    string
	releaseOwner string
}

type basicStateStore struct{}

type preparingStateStore struct {
	basicStateStore
	calls int
	err   error
}

type blockingPreparingStateStore struct {
	basicStateStore
	started chan struct{}
	release chan struct{}
}

type blockingFindingRiskBackfiller struct {
	started chan struct{}
	release chan struct{}
}

func (b *blockingFindingRiskBackfiller) BackfillFindingRisk(context.Context) error {
	close(b.started)
	<-b.release
	return nil
}

type errorFindingRiskBackfiller struct {
	err error
}

func (b *errorFindingRiskBackfiller) BackfillFindingRisk(context.Context) error {
	return b.err
}

func (s *commandRuntimeStore) Ping(context.Context) error {
	return nil
}

func (s *basicStateStore) Ping(context.Context) error {
	return nil
}

func (s *preparingStateStore) PrepareGRCReadModels(context.Context) error {
	s.calls++
	return s.err
}

//nolint:unparam // Test fake implements the state-store interface, including the error result.
func (s *blockingPreparingStateStore) PrepareGRCReadModels(context.Context) error {
	close(s.started)
	<-s.release
	return nil
}

func captureCommandStderr(t *testing.T, fn func()) string {
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

func lastCommandTelemetryPayload(t *testing.T, stderr string) map[string]any {
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
		return payload
	}
	t.Fatal("telemetry stderr is empty")
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

//nolint:unparam // Test fake implements the runtime-store lease interface, including the error result.
func (s *commandRuntimeStore) AcquireSourceRuntimeLease(_ context.Context, runtimeID string, owner string, _ time.Duration) (bool, error) {
	s.leaseID = runtimeID
	s.leaseOwner = owner
	return true, nil
}

func (s *commandRuntimeStore) RenewSourceRuntimeLease(context.Context, string, string, time.Duration) (bool, error) {
	return true, nil
}

//nolint:unparam // Test fake implements the runtime-store lease interface, including the error result.
func (s *commandRuntimeStore) ReleaseSourceRuntimeLease(_ context.Context, runtimeID string, owner string) error {
	s.releaseID = runtimeID
	s.releaseOwner = owner
	return nil
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

func TestSourceRuntimeListJSONUsesProtoJSON(t *testing.T) {
	payload, err := sourceRuntimeListJSON([]*cerebrov1.SourceRuntime{
		{Id: "runtime-1", LastSyncedAt: timestamppb.Now()},
	})
	if err != nil {
		t.Fatalf("sourceRuntimeListJSON() error = %v", err)
	}
	rendered := string(payload["runtimes"][0])
	if !strings.Contains(rendered, `"last_synced_at":"`) {
		t.Fatalf("runtime JSON = %s, want proto JSON timestamp string", rendered)
	}
	if strings.Contains(rendered, `"seconds"`) {
		t.Fatalf("runtime JSON = %s, want no struct-style seconds field", rendered)
	}
}

func TestParseOrchestratorOptions(t *testing.T) {
	options, err := parseOrchestratorOptions([]string{"tenant_id=writer", "source_id=github", "limit=2", "page_limit=3", "event_limit=4", "graph_page_limit=5", "phase_timeout=10m", "graph_timeout=45m"})
	if err != nil {
		t.Fatalf("parseOrchestratorOptions() error = %v", err)
	}
	if options.Filter.TenantID != "writer" || options.Filter.SourceID != "github" || options.Filter.Limit != 2 || options.PageLimit != 3 || options.EventLimit != 4 || options.GraphPageLimit != 5 {
		t.Fatalf("options = %#v", options)
	}
	if options.PhaseTimeout != 10*time.Minute || options.GraphTimeout != 45*time.Minute {
		t.Fatalf("timeouts = %v/%v, want 10m/45m", options.PhaseTimeout, options.GraphTimeout)
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
