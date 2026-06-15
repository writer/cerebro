package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/findings"
)

const closeoutTenant = "tenant-a"

type fakeCloseoutBackend struct {
	mu                sync.Mutex
	supports          bool
	supportsErr       error
	closeoutErr       error
	closeoutResult    *findings.CloseoutResult
	closeoutHook      func(req findings.CloseoutRequest) (*findings.CloseoutResult, error)
	receivedRequests  []findings.CloseoutRequest
	calls             []string
	afterRunIDs       []string
	afterSummaryKeys  []string
	afterSummaryErrs  []error
	afterCloseoutErr  error
	supportsCallCount int
	closeoutCallCount int
}

func (f *fakeCloseoutBackend) SupportsTombstones(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "SupportsTombstones")
	f.supportsCallCount++
	return f.supports, f.supportsErr
}

func (f *fakeCloseoutBackend) Closeout(_ context.Context, req findings.CloseoutRequest) (*findings.CloseoutResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "Closeout")
	f.closeoutCallCount++
	f.receivedRequests = append(f.receivedRequests, req)
	if f.closeoutHook != nil {
		return f.closeoutHook(req)
	}
	if f.closeoutResult == nil {
		return &findings.CloseoutResult{RunID: req.RunID}, f.closeoutErr
	}
	result := *f.closeoutResult
	if result.RunID == "" {
		result.RunID = req.RunID
	}
	return &result, f.closeoutErr
}

func (f *fakeCloseoutBackend) AfterCloseoutSummary(_ context.Context, runID, key string, summaryErr error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "AfterCloseoutSummary")
	f.afterRunIDs = append(f.afterRunIDs, runID)
	f.afterSummaryKeys = append(f.afterSummaryKeys, key)
	f.afterSummaryErrs = append(f.afterSummaryErrs, summaryErr)
	return f.afterCloseoutErr
}

type fakeSummaryWriter struct {
	mu        sync.Mutex
	err       error
	calls     []fakeSummaryCall
	callOrder *[]string
}

type fakeSummaryCall struct {
	Bucket string
	Key    string
	Body   []byte
}

func (f *fakeSummaryWriter) PutCloseoutSummary(_ context.Context, bucket, key string, body []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fakeSummaryCall{Bucket: bucket, Key: key, Body: append([]byte(nil), body...)})
	if f.callOrder != nil {
		*f.callOrder = append(*f.callOrder, "PutCloseoutSummary")
	}
	return f.err
}

func newCloseoutTestEnv(t *testing.T) (*closeoutEnv, *fakeCloseoutBackend, *fakeSummaryWriter, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	backend := &fakeCloseoutBackend{
		supports:       true,
		closeoutResult: &findings.CloseoutResult{},
	}
	writer := &fakeSummaryWriter{}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	envVars := map[string]string{}
	env := &closeoutEnv{
		Stdout:   stdout,
		Stderr:   stderr,
		Getenv:   func(k string) string { return envVars[k] },
		Now:      func() time.Time { return time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC) },
		NewRunID: func() string { return "00000000-0000-4000-8000-000000000001" },
		Backend:  backend,
		Summary:  writer,
		LookupSTS: func(context.Context) (closeoutSTSIdentity, error) {
			return closeoutSTSIdentity{}, nil
		},
	}
	t.Cleanup(func() {})
	envVars[closeoutEnvTenantID] = closeoutTenant
	return env, backend, writer, stdout, stderr
}

func withEnv(env *closeoutEnv, kv map[string]string) {
	previous := env.Getenv
	env.Getenv = func(k string) string {
		if v, ok := kv[k]; ok {
			return v
		}
		return previous(k)
	}
}

func captureProcessStdout(t *testing.T, run func() error) (string, error) {
	t.Helper()
	previous := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = previous }()

	runErr := run()
	if closeErr := writer.Close(); closeErr != nil {
		t.Fatalf("close stdout writer: %v", closeErr)
	}
	out, readErr := io.ReadAll(reader)
	if readErr != nil {
		t.Fatalf("read stdout pipe: %v", readErr)
	}
	if closeErr := reader.Close(); closeErr != nil {
		t.Fatalf("close stdout reader: %v", closeErr)
	}
	return string(out), runErr
}

func TestRunCloseout_HelpDoesNotInitDeps(t *testing.T) {
	previousFactory := defaultCloseoutEnvFactory
	depsInitCalled := false
	defaultCloseoutEnvFactory = func() (*closeoutEnv, func(), error) {
		depsInitCalled = true
		return nil, func() {}, errors.New("dependency initialization should not run for --help")
	}
	t.Cleanup(func() { defaultCloseoutEnvFactory = previousFactory })

	stdout, err := captureProcessStdout(t, func() error {
		return runCloseout([]string{"--help"})
	})
	if err != nil {
		t.Fatalf("runCloseout(--help) error = %v", err)
	}
	if depsInitCalled {
		t.Fatal("defaultCloseoutEnv was called for --help")
	}
	if !strings.Contains(stdout, "cerebro closeout") {
		t.Fatalf("stdout should contain closeout help text, got:\n%s", stdout)
	}
}

func TestRunCloseout_ValidationErrorDoesNotInitDeps(t *testing.T) {
	t.Setenv(closeoutEnvTenantID, "")
	previousFactory := defaultCloseoutEnvFactory
	depsInitCalled := false
	defaultCloseoutEnvFactory = func() (*closeoutEnv, func(), error) {
		depsInitCalled = true
		return nil, func() {}, errors.New("dependency initialization should not run for local validation errors")
	}
	t.Cleanup(func() { defaultCloseoutEnvFactory = previousFactory })

	err := runCloseout([]string{
		"--rule-id", "r1",
		"--reason", "cleanup",
		"--tenant-id", "",
	})
	if err == nil {
		t.Fatal("expected local tenant validation to fail")
	}
	if !errors.Is(err, ErrCloseoutTenantIDRequired) {
		t.Fatalf("error %v should match ErrCloseoutTenantIDRequired", err)
	}
	if depsInitCalled {
		t.Fatal("defaultCloseoutEnv was called for a local validation error")
	}
}

func TestCloseoutHelp(t *testing.T) {
	env, _, _, stdout, _ := newCloseoutTestEnv(t)
	if err := runCloseoutWithEnv([]string{"--help"}, env); err != nil {
		t.Fatalf("runCloseoutWithEnv(--help) error = %v", err)
	}
	help := stdout.String()
	required := []string{
		"--rule-id",
		"--rule-id-file",
		"--source",
		"--older-than",
		"--status-filter",
		"--max-batch-size",
		"--dry-run",
		"--apply",
		"--reason",
		"--run-id",
		"--actor",
		"--change-ticket",
		"--allow-env",
		"--audit-s3-bucket",
	}
	for _, flag := range required {
		if !strings.Contains(help, flag) {
			t.Errorf("help missing flag %q\n---\n%s", flag, help)
		}
	}
	golden, err := os.ReadFile(filepath.Join("testdata", "closeout-help.txt"))
	if err != nil {
		t.Fatalf("read golden help text: %v", err)
	}
	if string(golden) != help {
		t.Errorf("help text mismatch with golden\n--- got:\n%s\n--- want:\n%s", help, string(golden))
	}
}

func TestValidateCloseoutFlags_ReasonRequiredAlways(t *testing.T) {
	for _, apply := range []bool{false, true} {
		t.Run(map[bool]string{false: "dry-run", true: "apply"}[apply], func(t *testing.T) {
			env, _, _, _, _ := newCloseoutTestEnv(t)
			withEnv(env, map[string]string{closeoutEnvAllow: closeoutEnvSecDev})
			flags := closeoutFlags{
				RuleIDs:       []string{"r1"},
				Apply:         apply,
				Reason:        "",
				AllowEnv:      closeoutEnvSecDev,
				AuditS3Bucket: "example-sec-dev-audit",
				TenantID:      closeoutTenant,
			}
			err := validateCloseoutFlags(&flags, env)
			if err == nil {
				t.Fatalf("expected empty --reason to fail when apply=%v", apply)
			}
			if !errors.Is(err, ErrCloseoutReasonRequired) {
				t.Fatalf("error %v should match ErrCloseoutReasonRequired", err)
			}
		})
	}
}

func TestCloseoutApplyRequiresReason(t *testing.T) {
	env, backend, _, _, _ := newCloseoutTestEnv(t)
	withEnv(env, map[string]string{closeoutEnvAllow: "sec-dev"})
	err := runCloseoutWithEnv([]string{
		"--rule-id", "r1",
		"--apply",
		"--allow-env", "sec-dev",
		"--audit-s3-bucket", "example-sec-dev-audit",
	}, env)
	if err == nil {
		t.Fatal("expected --apply without --reason to fail")
	}
	if !errors.Is(err, ErrCloseoutReasonRequired) {
		t.Errorf("error %v should match ErrCloseoutReasonRequired", err)
	}
	if backend.supportsCallCount != 0 || backend.closeoutCallCount != 0 {
		t.Errorf("backend should not be called on validation failure: supports=%d closeout=%d",
			backend.supportsCallCount, backend.closeoutCallCount)
	}
}

func TestRunCloseoutWithEnv_TenantIDValidatedBeforeBackend(t *testing.T) {
	env, backend, writer, _, _ := newCloseoutTestEnv(t)
	withEnv(env, map[string]string{closeoutEnvTenantID: ""})
	err := runCloseoutWithEnv([]string{
		"--rule-id", "r1",
		"--reason", "cleanup",
		"--tenant-id", "",
	}, env)
	if err == nil {
		t.Fatal("expected empty tenant id to fail validation")
	}
	if !errors.Is(err, ErrCloseoutTenantIDRequired) {
		t.Fatalf("error %v should match ErrCloseoutTenantIDRequired", err)
	}
	if !strings.Contains(string(ErrCloseoutTenantIDRequired), "--tenant-id") ||
		!strings.Contains(string(ErrCloseoutTenantIDRequired), closeoutEnvTenantID) {
		t.Fatalf("tenant validation sentinel should name --tenant-id and %s, got %q",
			closeoutEnvTenantID, string(ErrCloseoutTenantIDRequired))
	}
	if backend.supportsCallCount != 0 || backend.closeoutCallCount != 0 {
		t.Fatalf("backend invoked before tenant validation: supports=%d closeout=%d",
			backend.supportsCallCount, backend.closeoutCallCount)
	}
	if len(writer.calls) != 0 {
		t.Fatalf("summary writer invoked before tenant validation: %d", len(writer.calls))
	}
}

func TestRunCloseoutWithEnv_DryRunFalseHonored(t *testing.T) {
	env, backend, writer, _, _ := newCloseoutTestEnv(t)
	err := runCloseoutWithEnv([]string{
		"--rule-id", "r1",
		"--reason", "cleanup",
		"--dry-run=false",
	}, env)
	if err == nil {
		t.Fatal("expected --dry-run=false without --apply to fail")
	}
	if !errors.Is(err, ErrCloseoutDryRunFalseRequiresApply) {
		t.Fatalf("error %v should match ErrCloseoutDryRunFalseRequiresApply", err)
	}
	if backend.supportsCallCount != 0 || backend.closeoutCallCount != 0 {
		t.Fatalf("backend invoked despite --dry-run=false conflict: supports=%d closeout=%d",
			backend.supportsCallCount, backend.closeoutCallCount)
	}
	if len(writer.calls) != 0 {
		t.Fatalf("summary writer invoked despite --dry-run=false conflict: %d", len(writer.calls))
	}
}

func TestCloseoutGoProdRequiresChangeTicket(t *testing.T) {
	env, backend, _, _, _ := newCloseoutTestEnv(t)
	withEnv(env, map[string]string{closeoutEnvAllow: "go-prod"})
	err := runCloseoutWithEnv([]string{
		"--rule-id", "r1",
		"--apply",
		"--allow-env", "go-prod",
		"--reason", "cleanup",
		"--audit-s3-bucket", "example-go-prod-audit",
	}, env)
	if err == nil {
		t.Fatal("expected --apply go-prod without --change-ticket to fail")
	}
	if !errors.Is(err, ErrCloseoutChangeTicketRequired) {
		t.Errorf("error %v should match ErrCloseoutChangeTicketRequired", err)
	}
	if backend.closeoutCallCount != 0 {
		t.Errorf("backend.Closeout should not be called: %d", backend.closeoutCallCount)
	}

	// With --change-ticket, validation passes.
	if err := runCloseoutWithEnv([]string{
		"--rule-id", "r1",
		"--apply",
		"--allow-env", "go-prod",
		"--reason", "cleanup",
		"--change-ticket", "CHG-1",
		"--audit-s3-bucket", "example-go-prod-audit",
	}, env); err != nil {
		t.Fatalf("apply with change-ticket should succeed, got %v", err)
	}
}

func TestCloseoutAllowEnvGate(t *testing.T) {
	cases := []struct {
		name     string
		envValue string
		allowEnv string
		wantErr  error
	}{
		{name: "unset", envValue: "", allowEnv: "sec-dev", wantErr: ErrCloseoutAllowEnvMismatch},
		{name: "mismatch", envValue: "go-prod", allowEnv: "sec-dev", wantErr: ErrCloseoutAllowEnvMismatch},
		{name: "match", envValue: "sec-dev", allowEnv: "sec-dev", wantErr: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, _, _, _, _ := newCloseoutTestEnv(t)
			withEnv(env, map[string]string{closeoutEnvAllow: tc.envValue})
			err := runCloseoutWithEnv([]string{
				"--rule-id", "r1",
				"--apply",
				"--reason", "cleanup",
				"--allow-env", tc.allowEnv,
				"--audit-s3-bucket", "example-sec-dev-audit",
			}, env)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatal("expected validation error")
				}
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("error %v should match %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCloseoutAutogeneratesRunID(t *testing.T) {
	env, _, _, stdout, _ := newCloseoutTestEnv(t)
	if err := runCloseoutWithEnv([]string{"--rule-id", "r1", "--reason", "cleanup"}, env); err != nil {
		t.Fatalf("dry-run error = %v", err)
	}
	uuidPattern := regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`)
	if !uuidPattern.MatchString(stdout.String()) {
		t.Errorf("stdout should contain a UUIDv4; got:\n%s", stdout.String())
	}

	// Two consecutive runs (via the production generator) produce distinct UUIDs.
	first := newCloseoutRunID()
	second := newCloseoutRunID()
	if first == second {
		t.Errorf("expected distinct run ids, got %q twice", first)
	}
	if !uuidPattern.MatchString(first) {
		t.Errorf("newCloseoutRunID() returned %q, not RFC4122 v4", first)
	}
}

func TestCloseoutPropagatesRunID(t *testing.T) {
	env, backend, writer, _, _ := newCloseoutTestEnv(t)
	backend.closeoutResult = &findings.CloseoutResult{AppliedCount: 0, ProposedCount: 0}
	withEnv(env, map[string]string{closeoutEnvAllow: "sec-dev"})
	args := []string{
		"--rule-id", "r1",
		"--apply",
		"--reason", "cleanup",
		"--allow-env", "sec-dev",
		"--run-id", "run-fixed-1",
		"--audit-s3-bucket", "example-sec-dev-audit",
	}
	if err := runCloseoutWithEnv(args, env); err != nil {
		t.Fatalf("runCloseoutWithEnv() = %v", err)
	}
	if len(backend.receivedRequests) != 1 {
		t.Fatalf("backend received %d requests, want 1", len(backend.receivedRequests))
	}
	got := backend.receivedRequests[0]
	if got.RunID != "run-fixed-1" {
		t.Errorf("CloseoutRequest.RunID = %q, want run-fixed-1", got.RunID)
	}
	if len(writer.calls) != 1 {
		t.Fatalf("summary writer called %d times, want 1", len(writer.calls))
	}
	if writer.calls[0].Key != "closeout/run-fixed-1.json" {
		t.Errorf("summary key = %q, want closeout/run-fixed-1.json", writer.calls[0].Key)
	}
}

func TestCloseoutRuleIDFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.txt")
	contents := `# header comment
github-webhook-modified

# blank line above ignored
github-critical-resource-deleted
github-webhook-modified
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write rule id file: %v", err)
	}
	env, backend, _, _, _ := newCloseoutTestEnv(t)
	if err := runCloseoutWithEnv([]string{
		"--rule-id-file", path,
		"--rule-id", "identity-stale-privileged-account",
		"--reason", "cleanup",
	}, env); err != nil {
		t.Fatalf("rule-id-file dry-run error = %v", err)
	}
	if len(backend.receivedRequests) != 1 {
		t.Fatalf("backend not invoked")
	}
	got := backend.receivedRequests[0].Selector.RuleIDs
	want := map[string]bool{
		"github-webhook-modified":           true,
		"github-critical-resource-deleted":  true,
		"identity-stale-privileged-account": true,
	}
	if len(got) != len(want) {
		t.Fatalf("rule ids = %v, want %v", got, want)
	}
	for _, id := range got {
		if !want[id] {
			t.Errorf("unexpected rule id %q", id)
		}
	}
}

func TestCloseoutSelectorBySource(t *testing.T) {
	env, backend, _, _, _ := newCloseoutTestEnv(t)
	if err := runCloseoutWithEnv([]string{
		"--rule-id", "rule-one",
		"--source", "github",
		"--source", "okta",
		"--reason", "cleanup",
	}, env); err != nil {
		t.Fatalf("dry-run error = %v", err)
	}
	if len(backend.receivedRequests) != 1 {
		t.Fatalf("backend not invoked")
	}
	gotSources := backend.receivedRequests[0].Selector.Sources
	wantSources := []string{"github", "okta"}
	if !equalStringSlices(gotSources, wantSources) {
		t.Errorf("selector.Sources = %v, want %v", gotSources, wantSources)
	}
}

func TestCloseoutSelectorOlderThan(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want time.Duration
	}{
		{name: "days", raw: "7d", want: 7 * 24 * time.Hour},
		{name: "hours", raw: "24h", want: 24 * time.Hour},
		{name: "mixed", raw: "1h30m", want: 90 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, backend, _, _, _ := newCloseoutTestEnv(t)
			if err := runCloseoutWithEnv([]string{
				"--rule-id", "r1",
				"--reason", "cleanup",
				"--older-than", tc.raw,
			}, env); err != nil {
				t.Fatalf("dry-run error = %v", err)
			}
			if len(backend.receivedRequests) == 0 {
				t.Fatalf("backend.Closeout not called")
			}
			got := backend.receivedRequests[0].Selector.OlderThan
			if got != tc.want {
				t.Errorf("OlderThan = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCloseoutApplyRequiresAuditBucket(t *testing.T) {
	cases := []struct {
		name      string
		flag      string
		envVarVal string
		dryRun    bool
		wantErr   bool
	}{
		{name: "apply+flag", flag: "example-sec-dev-audit", wantErr: false},
		{name: "apply+env", envVarVal: "example-sec-dev-audit", wantErr: false},
		{name: "apply+neither", wantErr: true},
		{name: "dryrun+neither", dryRun: true, wantErr: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, backend, _, _, stderr := newCloseoutTestEnv(t)
			extra := map[string]string{closeoutEnvAllow: "sec-dev"}
			if tc.envVarVal != "" {
				extra[closeoutEnvAuditBucket] = tc.envVarVal
			}
			withEnv(env, extra)
			args := []string{
				"--rule-id", "r1",
				"--reason", "cleanup",
				"--allow-env", "sec-dev",
			}
			if !tc.dryRun {
				args = append(args, "--apply")
			}
			if tc.flag != "" {
				args = append(args, "--audit-s3-bucket", tc.flag)
			}
			err := runCloseoutWithEnv(args, env)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error; stderr=%q", stderr.String())
				}
				if !errors.Is(err, ErrCloseoutAuditBucketRequired) {
					t.Errorf("error %v should match ErrCloseoutAuditBucketRequired", err)
				}
				if backend.closeoutCallCount != 0 {
					t.Errorf("backend.Closeout invoked despite failed validation")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCloseoutInsertsRunRowFirst(t *testing.T) {
	env, backend, writer, _, _ := newCloseoutTestEnv(t)
	withEnv(env, map[string]string{closeoutEnvAllow: "sec-dev"})
	args := []string{
		"--rule-id", "r1",
		"--apply",
		"--reason", "cleanup",
		"--allow-env", "sec-dev",
		"--audit-s3-bucket", "example-sec-dev-audit",
	}
	if err := runCloseoutWithEnv(args, env); err != nil {
		t.Fatalf("apply run error = %v", err)
	}
	if len(backend.calls) < 2 {
		t.Fatalf("expected at least SupportsTombstones and Closeout calls, got %v", backend.calls)
	}
	if backend.calls[0] != "SupportsTombstones" {
		t.Errorf("first backend call = %q, want SupportsTombstones (gate runs before any DB write)", backend.calls[0])
	}
	if backend.calls[1] != "Closeout" {
		t.Errorf("second backend call = %q, want Closeout (closeout_run row insertion is the very first DB write inside Closeout)", backend.calls[1])
	}
	if len(writer.calls) != 1 {
		t.Errorf("S3 summary writer should be invoked exactly once on apply, got %d calls", len(writer.calls))
	}
}

func TestCloseoutActorResolution(t *testing.T) {
	cases := []struct {
		name         string
		flagActor    string
		github       string
		stsPrincipal string
		stsRole      string
		user         string
		want         string
		wantRole     string
	}{
		{name: "flag-override", flagActor: "alice", github: "gh-user", stsPrincipal: "sts", user: "u", want: "alice"},
		{name: "github", github: "gh-user", stsPrincipal: "sts", user: "u", want: "gh-user"},
		{name: "sts", stsPrincipal: "sts:role/arn", stsRole: "arn:role", user: "u", want: "sts:role/arn", wantRole: "arn:role"},
		{name: "user", user: "u", want: "u"},
		{name: "unknown", want: closeoutActorUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, backend, _, _, _ := newCloseoutTestEnv(t)
			env.LookupSTS = func(context.Context) (closeoutSTSIdentity, error) {
				return closeoutSTSIdentity{Principal: tc.stsPrincipal, RoleARN: tc.stsRole}, nil
			}
			withEnv(env, map[string]string{
				closeoutEnvGithubActor: tc.github,
				closeoutEnvUser:        tc.user,
			})
			args := []string{"--rule-id", "r1", "--reason", "cleanup"}
			if tc.flagActor != "" {
				args = append(args, "--actor", tc.flagActor)
			}
			if err := runCloseoutWithEnv(args, env); err != nil {
				t.Fatalf("dry-run error = %v", err)
			}
			if len(backend.receivedRequests) == 0 {
				t.Fatalf("backend.Closeout not called")
			}
			got := backend.receivedRequests[0].Actor
			if got != tc.want {
				t.Errorf("actor = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCloseoutDryRunExitCode(t *testing.T) {
	cases := []struct {
		name     string
		proposed int
	}{
		{name: "zero", proposed: 0},
		{name: "many", proposed: 47},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, backend, _, _, _ := newCloseoutTestEnv(t)
			backend.closeoutResult = &findings.CloseoutResult{ProposedCount: tc.proposed}
			if err := runCloseoutWithEnv([]string{"--rule-id", "r1", "--reason", "cleanup"}, env); err != nil {
				t.Fatalf("dry-run with proposed=%d error = %v", tc.proposed, err)
			}
		})
	}
}

func TestCloseout_OlderThanRejectsInvalid(t *testing.T) {
	cases := []string{"abc", "-3d", "0d", "106752d"}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			env, backend, _, _, _ := newCloseoutTestEnv(t)
			err := runCloseoutWithEnv([]string{
				"--rule-id", "r1",
				"--older-than", raw,
			}, env)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, ErrCloseoutOlderThanInvalid) {
				t.Errorf("error %v should match ErrCloseoutOlderThanInvalid", err)
			}
			if backend.closeoutCallCount != 0 {
				t.Errorf("backend.Closeout should not be called: %d", backend.closeoutCallCount)
			}
		})
	}
}

func TestCloseout_MaxBatchSizeBounds(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{name: "zero", args: []string{"--rule-id", "r1", "--reason", "cleanup", "--max-batch-size", "0"}, wantErr: true},
		{name: "negative", args: []string{"--rule-id", "r1", "--reason", "cleanup", "--max-batch-size", "-1"}, wantErr: true},
		{name: "not-int", args: []string{"--rule-id", "r1", "--reason", "cleanup", "--max-batch-size", "abc"}, wantErr: true},
		{name: "default", args: []string{"--rule-id", "r1", "--reason", "cleanup"}, wantErr: false},
		{name: "positive", args: []string{"--rule-id", "r1", "--reason", "cleanup", "--max-batch-size", "250"}, wantErr: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, backend, _, _, _ := newCloseoutTestEnv(t)
			err := runCloseoutWithEnv(tc.args, env)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if !errors.Is(err, ErrCloseoutMaxBatchSizeInvalid) {
					t.Errorf("error %v should match ErrCloseoutMaxBatchSizeInvalid", err)
				}
				if backend.closeoutCallCount != 0 {
					t.Errorf("backend.Closeout invoked despite failed validation")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(backend.receivedRequests) == 0 {
				t.Fatalf("expected backend.Closeout to be called")
			}
			batch := backend.receivedRequests[0].MaxBatchSize
			if tc.name == "default" && batch != closeoutDefaultBatchSize {
				t.Errorf("default batch size = %d, want %d", batch, closeoutDefaultBatchSize)
			}
			if tc.name == "positive" && batch != 250 {
				t.Errorf("batch size = %d, want 250", batch)
			}
		})
	}
}

func TestCloseout_RuleIDFileNotReadable(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T) string
	}{
		{
			name: "missing",
			setup: func(*testing.T) string {
				return filepath.Join(os.TempDir(), "definitely-missing-rule-id-file.txt")
			},
		},
		{
			name: "is-directory",
			setup: func(t *testing.T) string {
				return t.TempDir()
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, backend, _, _, _ := newCloseoutTestEnv(t)
			err := runCloseoutWithEnv([]string{
				"--rule-id-file", tc.setup(t),
			}, env)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, ErrCloseoutRuleIDFileUnreadable) {
				t.Errorf("error %v should match ErrCloseoutRuleIDFileUnreadable", err)
			}
			if backend.closeoutCallCount != 0 {
				t.Errorf("backend.Closeout invoked despite failed validation")
			}
		})
	}
}

func TestCloseout_S3SummaryFailureMarksFailed(t *testing.T) {
	env, backend, writer, stdout, stderr := newCloseoutTestEnv(t)
	putErr := errors.New("AccessDenied: not authorized to PutObject")
	writer.err = putErr
	backend.closeoutResult = &findings.CloseoutResult{
		AppliedCount:  3,
		ProposedCount: 3,
		BatchSizes:    []int{3},
	}
	withEnv(env, map[string]string{
		closeoutEnvAllow:       "sec-dev",
		closeoutEnvGithubActor: "alice@writer.com",
	})
	err := runCloseoutWithEnv([]string{
		"--rule-id", "r1",
		"--apply",
		"--reason", "cleanup",
		"--allow-env", "sec-dev",
		"--audit-s3-bucket", "example-sec-dev-audit",
		"--run-id", "run-s3-fail-1",
	}, env)
	if err == nil {
		t.Fatal("expected non-zero exit when S3 put fails")
	}
	if !errors.Is(err, ErrCloseoutSummaryPutFailed) {
		t.Errorf("error %v should wrap ErrCloseoutSummaryPutFailed", err)
	}
	if !errors.Is(err, putErr) {
		t.Errorf("error %v should wrap the underlying put error", err)
	}
	if stderr.Len() == 0 {
		t.Errorf("expected stderr to describe the S3 failure; got empty buffer")
	}
	if len(backend.afterSummaryKeys) != 1 {
		t.Fatalf("expected AfterCloseoutSummary to be called once, got %d", len(backend.afterSummaryKeys))
	}
	if backend.afterSummaryKeys[0] != "closeout/run-s3-fail-1.json" {
		t.Errorf("summary key = %q, want closeout/run-s3-fail-1.json", backend.afterSummaryKeys[0])
	}
	if backend.afterSummaryErrs[0] == nil {
		t.Error("AfterCloseoutSummary should receive the S3 error so it can mark the run failed")
	}
	if backend.closeoutCallCount != 1 {
		t.Errorf("backend.Closeout call count = %d, want 1 (tombstones must NOT roll back on S3 failure)", backend.closeoutCallCount)
	}

	var endEntries []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || !strings.HasPrefix(trimmed, "{") {
			continue
		}
		var entry map[string]any
		if jsonErr := json.Unmarshal([]byte(trimmed), &entry); jsonErr != nil {
			continue
		}
		if event, _ := entry["event"].(string); event == closeoutEventEnd {
			endEntries = append(endEntries, entry)
		}
	}
	if len(endEntries) != 1 {
		t.Fatalf("expected exactly one closeout.end log line on the S3-failure exit path, got %d (stdout:\n%s)",
			len(endEntries), stdout.String())
	}
	endEntry := endEntries[0]
	wantStrings := map[string]string{
		"run_id": "run-s3-fail-1",
		"actor":  "alice@writer.com",
		"env":    "sec-dev",
		"status": "failed",
	}
	for key, want := range wantStrings {
		got, _ := endEntry[key].(string)
		if got != want {
			t.Errorf("closeout.end[%q] = %q, want %q (entry: %v)", key, got, want, endEntry)
		}
	}
	if dryRun, ok := endEntry["dry_run"].(bool); !ok || dryRun {
		t.Errorf("closeout.end dry_run = %v, want false (entry: %v)", endEntry["dry_run"], endEntry)
	}
	errMsg, _ := endEntry["error"].(string)
	if !strings.Contains(errMsg, "AccessDenied") {
		t.Errorf("closeout.end error = %q, want it to contain the underlying S3 error message", errMsg)
	}
	for _, key := range []string{"batch_count", "applied_count"} {
		if _, ok := endEntry[key]; !ok {
			t.Errorf("closeout.end missing key %q (entry: %v)", key, endEntry)
		}
	}
	if applied, ok := endEntry["applied_count"].(float64); !ok || int(applied) != 3 {
		t.Errorf("closeout.end applied_count = %v, want 3", endEntry["applied_count"])
	}
	if batchCount, ok := endEntry["batch_count"].(float64); !ok || int(batchCount) != 1 {
		t.Errorf("closeout.end batch_count = %v, want 1", endEntry["batch_count"])
	}
}

func TestCloseout_PostCloseoutErrorUsesFailedEndLog(t *testing.T) {
	env, backend, writer, stdout, _ := newCloseoutTestEnv(t)
	const closeoutErrMessage = "backend closeout failed after run row insert"
	closeoutErr := errors.New(closeoutErrMessage)
	backend.closeoutErr = closeoutErr
	backend.closeoutResult = &findings.CloseoutResult{
		RunID:         "run-closeout-error-1",
		ProposedCount: 5,
		AppliedCount:  3,
		BatchSizes:    []int{2, 1},
	}

	err := runCloseoutWithEnv([]string{
		"--rule-id", "r1",
		"--reason", "cleanup",
		"--actor", "alice@writer.com",
		"--run-id", "run-closeout-error-1",
	}, env)
	if err == nil {
		t.Fatal("expected closeout error")
	}
	if !errors.Is(err, closeoutErr) {
		t.Fatalf("error %v should wrap closeoutErr", err)
	}
	if len(writer.calls) != 0 {
		t.Fatalf("summary writer called on direct closeout error: %d", len(writer.calls))
	}
	if len(backend.afterSummaryKeys) != 0 {
		t.Fatalf("AfterCloseoutSummary called on direct closeout error: %d", len(backend.afterSummaryKeys))
	}

	endEntries := closeoutEndLogEntries(t, stdout.String())
	if len(endEntries) != 1 {
		t.Fatalf("closeout.end entries = %d, want 1 (stdout:\n%s)", len(endEntries), stdout.String())
	}
	entry := endEntries[0]
	if got, _ := entry["status"].(string); got != "failed" {
		t.Fatalf("status = %q, want failed (entry: %v)", got, entry)
	}
	if got, _ := entry["error"].(string); !strings.Contains(got, closeoutErrMessage) {
		t.Fatalf("error = %q, want it to contain %q", got, closeoutErrMessage)
	}
	if got, _ := entry["reason"].(string); got != "closeout_failed" {
		t.Fatalf("reason = %q, want closeout_failed", got)
	}
	if got, ok := entry["batch_count"].(float64); !ok || int(got) != 2 {
		t.Fatalf("batch_count = %v, want 2", entry["batch_count"])
	}
	if got, ok := entry["applied_count"].(float64); !ok || int(got) != 3 {
		t.Fatalf("applied_count = %v, want 3", entry["applied_count"])
	}
	if _, ok := entry["proposed_count"]; ok {
		t.Fatalf("legacy proposed_count key appeared in failed end log: %v", entry)
	}
}

func TestRunCloseoutWithEnv_DryRunPersistsS3SummaryKey(t *testing.T) {
	env, backend, writer, stdout, _ := newCloseoutTestEnv(t)
	backend.closeoutResult = &findings.CloseoutResult{
		RunID:         "run-dry-summary-1",
		ProposedCount: 4,
		AppliedCount:  0,
	}

	err := runCloseoutWithEnv([]string{
		"--rule-id", "r1",
		"--reason", "cleanup",
		"--audit-s3-bucket", "example-sec-dev-audit",
		"--run-id", "run-dry-summary-1",
	}, env)
	if err != nil {
		t.Fatalf("dry-run with audit bucket error = %v", err)
	}
	if len(writer.calls) != 1 {
		t.Fatalf("summary writer calls = %d, want 1", len(writer.calls))
	}
	if writer.calls[0].Key != "closeout/run-dry-summary-1.json" {
		t.Fatalf("summary key = %q, want closeout/run-dry-summary-1.json", writer.calls[0].Key)
	}
	if len(backend.afterSummaryKeys) != 1 {
		t.Fatalf("AfterCloseoutSummary calls = %d, want 1", len(backend.afterSummaryKeys))
	}
	if backend.afterSummaryKeys[0] != "closeout/run-dry-summary-1.json" {
		t.Fatalf("AfterCloseoutSummary key = %q, want closeout/run-dry-summary-1.json", backend.afterSummaryKeys[0])
	}
	if backend.afterSummaryErrs[0] != nil {
		t.Fatalf("AfterCloseoutSummary error = %v, want nil", backend.afterSummaryErrs[0])
	}

	endEntries := closeoutEndLogEntries(t, stdout.String())
	if len(endEntries) != 1 {
		t.Fatalf("closeout.end entries = %d, want 1 (stdout:\n%s)", len(endEntries), stdout.String())
	}
	if got, _ := endEntries[0]["s3_summary_key"].(string); got != "closeout/run-dry-summary-1.json" {
		t.Fatalf("s3_summary_key = %q, want closeout/run-dry-summary-1.json", got)
	}
}

func TestRunCloseoutWithEnv_DuplicateRunPreservesExistingSummary(t *testing.T) {
	env, backend, writer, stdout, _ := newCloseoutTestEnv(t)
	withEnv(env, map[string]string{closeoutEnvAllow: "sec-dev"})
	backend.closeoutResult = &findings.CloseoutResult{
		RunID:         "run-existing-summary-1",
		ProposedCount: 8,
		AppliedCount:  8,
		BatchSizes:    []int{8},
		S3SummaryKey:  "closeout/run-existing-summary-1.json",
	}

	err := runCloseoutWithEnv([]string{
		"--rule-id", "r1",
		"--apply",
		"--reason", "cleanup",
		"--allow-env", "sec-dev",
		"--audit-s3-bucket", "example-sec-dev-audit",
		"--run-id", "run-existing-summary-1",
	}, env)
	if err != nil {
		t.Fatalf("duplicate apply with persisted summary key error = %v", err)
	}
	if len(writer.calls) != 0 {
		t.Fatalf("summary writer calls = %d, want 0 so existing S3 body is not clobbered", len(writer.calls))
	}
	if len(backend.afterSummaryKeys) != 0 {
		t.Fatalf("AfterCloseoutSummary calls = %d, want 0 on already-persisted summary", len(backend.afterSummaryKeys))
	}

	endEntries := closeoutEndLogEntries(t, stdout.String())
	if len(endEntries) != 1 {
		t.Fatalf("closeout.end entries = %d, want 1 (stdout:\n%s)", len(endEntries), stdout.String())
	}
	if got, _ := endEntries[0]["s3_summary_key"].(string); got != "closeout/run-existing-summary-1.json" {
		t.Fatalf("s3_summary_key = %q, want closeout/run-existing-summary-1.json", got)
	}
	if got, ok := endEntries[0]["applied_count"].(float64); !ok || int(got) != 8 {
		t.Fatalf("applied_count = %v, want 8", endEntries[0]["applied_count"])
	}
}

func TestCloseout_ApplyZeroCandidates(t *testing.T) {
	env, backend, writer, stdout, _ := newCloseoutTestEnv(t)
	backend.closeoutResult = &findings.CloseoutResult{ProposedCount: 0, AppliedCount: 0}
	withEnv(env, map[string]string{closeoutEnvAllow: "sec-dev"})
	args := []string{
		"--rule-id", "r1",
		"--apply",
		"--reason", "cleanup",
		"--allow-env", "sec-dev",
		"--audit-s3-bucket", "example-sec-dev-audit",
		"--run-id", "run-zero-1",
	}
	if err := runCloseoutWithEnv(args, env); err != nil {
		t.Fatalf("apply with zero candidates error = %v", err)
	}
	if backend.closeoutCallCount != 1 {
		t.Fatalf("backend.Closeout calls = %d, want 1", backend.closeoutCallCount)
	}
	if len(writer.calls) != 1 {
		t.Fatalf("S3 summary should be written once even when applied_count=0; got %d", len(writer.calls))
	}
	if writer.calls[0].Key != "closeout/run-zero-1.json" {
		t.Errorf("summary key = %q, want closeout/run-zero-1.json", writer.calls[0].Key)
	}
	var doc closeoutSummaryDocument
	if err := json.Unmarshal(writer.calls[0].Body, &doc); err != nil {
		t.Fatalf("summary JSON parse error = %v", err)
	}
	if doc.AppliedCount != 0 || doc.ProposedCount != 0 {
		t.Errorf("summary counts = (proposed=%d applied=%d), want (0,0)", doc.ProposedCount, doc.AppliedCount)
	}
	if doc.RunID != "run-zero-1" {
		t.Errorf("summary run_id = %q, want run-zero-1", doc.RunID)
	}
	if !strings.Contains(stdout.String(), `"event":"closeout.end"`) {
		t.Error("expected closeout.end structured log on apply success")
	}
}

func TestCloseout_RefusesWithoutTombstoneSchema(t *testing.T) {
	env, backend, writer, stdout, stderr := newCloseoutTestEnv(t)
	backend.supports = false
	err := runCloseoutWithEnv([]string{"--rule-id", "r1", "--reason", "cleanup"}, env)
	if err == nil {
		t.Fatal("expected non-zero exit when tombstone schema missing")
	}
	if !strings.Contains(stderr.String(), "tombstone schema") {
		t.Errorf("stderr should mention tombstone schema; got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), `"event":"closeout.refused"`) {
		t.Errorf("expected structured log event=closeout.refused; got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"reason":"tombstone_schema_missing"`) {
		t.Errorf("expected structured log reason=tombstone_schema_missing; got %q", stdout.String())
	}
	if backend.closeoutCallCount != 0 {
		t.Errorf("backend.Closeout invoked despite missing schema")
	}
	if len(writer.calls) != 0 {
		t.Errorf("S3 writer invoked despite missing schema: %d", len(writer.calls))
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func closeoutEndLogEntries(t *testing.T, stdout string) []map[string]any {
	t.Helper()
	var entries []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || !strings.HasPrefix(trimmed, "{") {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(trimmed), &entry); err != nil {
			t.Fatalf("parse log line %q: %v", trimmed, err)
		}
		if event, _ := entry["event"].(string); event == closeoutEventEnd {
			entries = append(entries, entry)
		}
	}
	return entries
}

// ensureCloseoutFlagsHelpStartsCleanly is a smoke test confirming the help
// text begins on a meaningful header so golden-file regressions surface
// quickly. It guards against accidental leading whitespace creeping in.
func TestCloseoutHelpStartsWithHeader(t *testing.T) {
	if !strings.HasPrefix(closeoutHelpText, "cerebro closeout") {
		t.Fatalf("help text should start with 'cerebro closeout'; got %q", closeoutHelpText[:32])
	}
}

// TestCloseoutBatchLogShape asserts that a dry-run emits a structured
// closeout.start log line at the run boundary with the pinned event
// vocabulary and the run-level identifying fields (run_id, actor, env,
// dry_run). The vocabulary is fixed to {closeout.start, closeout.batch,
// closeout.end, closeout.refused}; every log line emitted by the CLI must
// carry one of those values in its "event" field.
func TestCloseoutBatchLogShape(t *testing.T) {
	env, backend, _, stdout, _ := newCloseoutTestEnv(t)
	backend.closeoutResult = &findings.CloseoutResult{ProposedCount: 3, AppliedCount: 0}

	if err := runCloseoutWithEnv([]string{
		"--rule-id", "r1",
		"--reason", "cleanup",
		"--actor", "alice@writer.com",
	}, env); err != nil {
		t.Fatalf("dry-run error = %v", err)
	}

	pinned := map[string]bool{
		"closeout.start":   true,
		"closeout.batch":   true,
		"closeout.end":     true,
		"closeout.refused": true,
	}

	var startEntry map[string]any
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || !strings.HasPrefix(trimmed, "{") {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(trimmed), &entry); err != nil {
			continue
		}
		raw, ok := entry["event"]
		if !ok {
			continue
		}
		event, ok := raw.(string)
		if !ok {
			t.Fatalf("event field is not a string: %v", raw)
		}
		if !pinned[event] {
			t.Errorf("log line emits event %q outside pinned vocabulary %v: %s", event, pinned, trimmed)
		}
		if event == "closeout.start" {
			startEntry = entry
		}
	}
	if startEntry == nil {
		t.Fatalf("no closeout.start structured log line found in stdout:\n%s", stdout.String())
	}
	for _, key := range []string{"run_id", "actor", "env", "dry_run"} {
		if _, ok := startEntry[key]; !ok {
			t.Errorf("closeout.start entry missing key %q: %v", key, startEntry)
		}
	}
	if got, _ := startEntry["actor"].(string); got != "alice@writer.com" {
		t.Errorf("closeout.start actor = %q, want alice@writer.com", got)
	}
	if got, _ := startEntry["dry_run"].(bool); got != true {
		t.Errorf("closeout.start dry_run = %v, want true", startEntry["dry_run"])
	}
	if runID, _ := startEntry["run_id"].(string); strings.TrimSpace(runID) == "" {
		t.Errorf("closeout.start run_id is empty: %v", startEntry)
	}
}

// TestCloseout_ApplyAndDryRunMutuallyExclusive locks in that --apply and an
// explicit --dry-run=true exit non-zero with the typed sentinel BEFORE any
// backend invocation. The error wording must name both flags so operators can
// disambiguate, but the assertion is on the typed sentinel (the structural
// noerrstringmatch lint forbids matching against err.Error() content).
func TestCloseout_ApplyAndDryRunMutuallyExclusive(t *testing.T) {
	env, backend, _, _, _ := newCloseoutTestEnv(t)
	withEnv(env, map[string]string{closeoutEnvAllow: "sec-dev"})
	err := runCloseoutWithEnv([]string{
		"--rule-id", "r1",
		"--apply",
		"--dry-run=true",
		"--reason", "cleanup",
		"--allow-env", "sec-dev",
		"--audit-s3-bucket", "example-sec-dev-audit",
	}, env)
	if err == nil {
		t.Fatal("expected error when --apply and --dry-run=true are combined")
	}
	if !errors.Is(err, ErrCloseoutApplyDryRunConflict) {
		t.Errorf("error %v should match ErrCloseoutApplyDryRunConflict", err)
	}
	if backend.supportsCallCount != 0 || backend.closeoutCallCount != 0 {
		t.Errorf("backend invoked despite conflict: supports=%d closeout=%d",
			backend.supportsCallCount, backend.closeoutCallCount)
	}
	if !strings.Contains(string(ErrCloseoutApplyDryRunConflict), "--apply") ||
		!strings.Contains(string(ErrCloseoutApplyDryRunConflict), "--dry-run") {
		t.Errorf("sentinel error message %q must name both --apply and --dry-run",
			string(ErrCloseoutApplyDryRunConflict))
	}
}

// TestCloseout_RequiresAtLeastOneRuleSource locks in that invocations with
// neither --rule-id nor --rule-id-file exit non-zero before any DB or S3
// write, including the case where --rule-id-file points at a file that
// resolves to zero rule ids. The sentinel message names both flags.
func TestCloseout_RequiresAtLeastOneRuleSource(t *testing.T) {
	t.Run("neither_flag", func(t *testing.T) {
		env, backend, writer, _, _ := newCloseoutTestEnv(t)
		err := runCloseoutWithEnv([]string{}, env)
		if err == nil {
			t.Fatal("expected error when no rule sources are provided")
		}
		if !errors.Is(err, ErrCloseoutRuleSelectorRequired) {
			t.Errorf("error %v should match ErrCloseoutRuleSelectorRequired", err)
		}
		if backend.supportsCallCount != 0 || backend.closeoutCallCount != 0 {
			t.Errorf("backend invoked despite missing selector: supports=%d closeout=%d",
				backend.supportsCallCount, backend.closeoutCallCount)
		}
		if len(writer.calls) != 0 {
			t.Errorf("summary writer invoked despite missing selector: %d", len(writer.calls))
		}
	})
	t.Run("empty_rule_id_file", func(t *testing.T) {
		env, backend, _, _, _ := newCloseoutTestEnv(t)
		path := filepath.Join(t.TempDir(), "empty-rules.txt")
		if err := os.WriteFile(path, []byte("# only comments\n\n"), 0o600); err != nil {
			t.Fatalf("write empty rule id file: %v", err)
		}
		err := runCloseoutWithEnv([]string{"--rule-id-file", path}, env)
		if err == nil {
			t.Fatal("expected error when --rule-id-file resolves to zero rule ids")
		}
		if !errors.Is(err, ErrCloseoutRuleSelectorRequired) {
			t.Errorf("error %v should match ErrCloseoutRuleSelectorRequired", err)
		}
		if backend.closeoutCallCount != 0 {
			t.Errorf("backend.Closeout invoked despite empty rule-id-file: %d", backend.closeoutCallCount)
		}
	})
	t.Run("source_only_insufficient", func(t *testing.T) {
		env, backend, writer, _, _ := newCloseoutTestEnv(t)
		// Confirm the parser DOES recognize --source so the precondition
		// rejection below is provably because --source fails to satisfy
		// the rule-selector contract (not because the flag was dropped).
		parsed, _, parseErr := parseCloseoutFlags([]string{"--source", "github"}, env)
		if parseErr != nil {
			t.Fatalf("parseCloseoutFlags(--source github) error = %v", parseErr)
		}
		if len(parsed.Sources) != 1 || parsed.Sources[0] != "github" {
			t.Fatalf("expected --source github to populate Sources, got %v", parsed.Sources)
		}
		if len(parsed.RuleIDs) != 0 || parsed.RuleIDFile != "" {
			t.Fatalf("expected no rule selector to be set, got rule_ids=%v rule_id_file=%q",
				parsed.RuleIDs, parsed.RuleIDFile)
		}

		err := runCloseoutWithEnv([]string{"--source", "github"}, env)
		if err == nil {
			t.Fatal("expected error when only --source is provided")
		}
		if !errors.Is(err, ErrCloseoutRuleSelectorRequired) {
			t.Errorf("error %v should match ErrCloseoutRuleSelectorRequired", err)
		}
		if backend.supportsCallCount != 0 || backend.closeoutCallCount != 0 {
			t.Errorf("backend invoked despite source-only selector: supports=%d closeout=%d",
				backend.supportsCallCount, backend.closeoutCallCount)
		}
		if len(writer.calls) != 0 {
			t.Errorf("summary writer invoked despite source-only selector: %d", len(writer.calls))
		}
	})

	if !strings.Contains(string(ErrCloseoutRuleSelectorRequired), "--rule-id") ||
		!strings.Contains(string(ErrCloseoutRuleSelectorRequired), "--rule-id-file") {
		t.Errorf("sentinel error message %q must name both --rule-id and --rule-id-file",
			string(ErrCloseoutRuleSelectorRequired))
	}
}
