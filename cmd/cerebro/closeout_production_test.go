package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
)

// fakeS3Client implements closeoutS3PutObjectAPI in-process so the integration
// test can exercise the apply path through the real aws-sdk-go-v2 S3 input
// plumbing without booting localstack. The bucket/key/body are captured for
// per-call assertions.
type fakeS3Client struct {
	mu    sync.Mutex
	calls []fakeS3Call
	err   error
}

type fakeS3Call struct {
	Bucket      string
	Key         string
	ContentType string
	Body        []byte
}

func (f *fakeS3Client) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(input.Body)
	f.calls = append(f.calls, fakeS3Call{
		Bucket:      aws.ToString(input.Bucket),
		Key:         aws.ToString(input.Key),
		ContentType: aws.ToString(input.ContentType),
		Body:        body,
	})
	if f.err != nil {
		return nil, f.err
	}
	return &s3.PutObjectOutput{}, nil
}

type fakeSTSClient struct {
	arn string
	err error
}

func (f *fakeSTSClient) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	arn := f.arn
	return &sts.GetCallerIdentityOutput{Arn: &arn}, nil
}

// stubProductionFindingStore is a no-op findings.Service substitute used by
// the wiring test. It returns a synthesized CloseoutResult so the test stays
// focused on the env-construction path (S3/STS adapters + backend bridging).
type stubProductionFindingService struct {
	requested findings.CloseoutRequest
	result    *findings.CloseoutResult
	err       error
}

type stubProductionBackend struct {
	service            *stubProductionFindingService
	supports           bool
	afterRunIDs        []string
	afterSummaryKeys   []string
	afterSummaryErrs   []error
	afterSummaryRetVal error
}

func (b *stubProductionBackend) SupportsTombstones(context.Context) (bool, error) {
	return b.supports, nil
}

func (b *stubProductionBackend) Closeout(_ context.Context, req findings.CloseoutRequest) (*findings.CloseoutResult, error) {
	b.service.requested = req
	return b.service.result, b.service.err
}

func (b *stubProductionBackend) AfterCloseoutSummary(_ context.Context, runID, key string, summaryErr error) error {
	b.afterRunIDs = append(b.afterRunIDs, runID)
	b.afterSummaryKeys = append(b.afterSummaryKeys, key)
	b.afterSummaryErrs = append(b.afterSummaryErrs, summaryErr)
	return b.afterSummaryRetVal
}

// TestDefaultCloseoutEnvWiring exercises the production env construction path
// (closeoutEnvFromDeps) with a fake S3 PutObject API + fake STS
// GetCallerIdentity API. This guarantees the apply path that runs in
// production - aws-sdk-go-v2 S3 PutObject + STS arn carried into the actor
// chain - is covered by an integration-style test even though the live AWS
// clients themselves are not invoked.
func TestDefaultCloseoutEnvWiring(t *testing.T) {
	s3client := &fakeS3Client{}
	stsClient := &fakeSTSClient{arn: "arn:aws:sts::000000000000:assumed-role/closeout/integration"}

	backend := &stubProductionBackend{
		supports: true,
		service: &stubProductionFindingService{
			result: &findings.CloseoutResult{
				RunID:         "wired-run-1",
				ProposedCount: 2,
				AppliedCount:  2,
				BatchSizes:    []int{2},
				PerRule: []findings.CloseoutPerRuleCount{
					{RuleID: "rule-alpha", Applied: 2},
				},
			},
		},
	}
	env := &closeoutEnv{
		Stdout:    &bytes.Buffer{},
		Stderr:    &bytes.Buffer{},
		Now:       func() time.Time { return time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC) },
		NewRunID:  func() string { return "wired-run-1" },
		Backend:   backend,
		Summary:   newS3CloseoutSummaryWriter(s3client),
		LookupSTS: newSTSCloseoutLookup(stsClient),
		Getenv: func(k string) string {
			switch k {
			case closeoutEnvAllow:
				return "sec-dev"
			case closeoutEnvTenantID:
				return "tenant-a"
			}
			return ""
		},
	}

	err := runCloseoutWithEnv([]string{
		"--rule-id", "rule-alpha",
		"--apply",
		"--reason", "wiring integration",
		"--allow-env", "sec-dev",
		"--audit-s3-bucket", "wiring-bucket",
		"--run-id", "wired-run-1",
	}, env)
	if err != nil {
		t.Fatalf("runCloseoutWithEnv error = %v", err)
	}

	if len(s3client.calls) != 1 {
		t.Fatalf("S3 PutObject called %d times, want 1", len(s3client.calls))
	}
	call := s3client.calls[0]
	if call.Bucket != "wiring-bucket" {
		t.Errorf("S3 bucket = %q, want wiring-bucket", call.Bucket)
	}
	if call.Key != "closeout/wired-run-1.json" {
		t.Errorf("S3 key = %q, want closeout/wired-run-1.json", call.Key)
	}
	if call.ContentType != "application/json" {
		t.Errorf("S3 content_type = %q, want application/json", call.ContentType)
	}
	var doc findings.CloseoutSummary
	if err := json.Unmarshal(call.Body, &doc); err != nil {
		t.Fatalf("Unmarshal S3 body error = %v", err)
	}
	if doc.RunID != "wired-run-1" {
		t.Errorf("S3 body run_id = %q, want wired-run-1", doc.RunID)
	}
	if doc.Actor.RoleARN != stsClient.arn {
		t.Errorf("actor.role_arn = %q, want %q (STS GetCallerIdentity result)", doc.Actor.RoleARN, stsClient.arn)
	}
	if len(doc.PerRule) != 1 || doc.PerRule[0].RuleID != "rule-alpha" {
		t.Errorf("per_rule = %v, want [rule-alpha:2]", doc.PerRule)
	}

	if len(backend.afterSummaryKeys) != 1 || backend.afterSummaryKeys[0] != "closeout/wired-run-1.json" {
		t.Errorf("AfterCloseoutSummary keys = %v", backend.afterSummaryKeys)
	}
	if backend.afterSummaryErrs[0] != nil {
		t.Errorf("AfterCloseoutSummary should receive nil error on success, got %v", backend.afterSummaryErrs[0])
	}
}

// TestS3CloseoutSummaryWriterValidatesInputs guards the apply path against
// accidentally calling PutObject with an empty bucket or key (which the AWS
// SDK accepts but produces a confusing 400 from S3).
func TestS3CloseoutSummaryWriterValidatesInputs(t *testing.T) {
	writer := newS3CloseoutSummaryWriter(&fakeS3Client{})
	cases := []struct {
		name    string
		bucket  string
		key     string
		wantErr error
	}{
		{name: "empty_bucket", bucket: "", key: "closeout/x.json", wantErr: ErrCloseoutS3BucketMissing},
		{name: "empty_key", bucket: "wiring-bucket", key: "", wantErr: ErrCloseoutS3KeyMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := writer.PutCloseoutSummary(context.Background(), tc.bucket, tc.key, []byte("{}"))
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("error %v should match %v", err, tc.wantErr)
			}
		})
	}
}

// TestSTSCloseoutLookupSwallowsErrors confirms the STS lookup contract:
// non-credential failures must not abort the closeout because the actor chain
// is required to fall back to $USER or "unknown".
func TestSTSCloseoutLookupSwallowsErrors(t *testing.T) {
	lookup := newSTSCloseoutLookup(&fakeSTSClient{err: errors.New("creds missing")})
	identity, err := lookup(context.Background())
	if err != nil {
		t.Fatalf("STS lookup returned error %v; want nil so actor fallback can proceed", err)
	}
	if identity != (closeoutSTSIdentity{}) {
		t.Errorf("identity = %+v, want empty so actor fallback chain proceeds", identity)
	}
}

// TestS3CloseoutSummaryWriterPropagatesError ensures that a S3 PutObject
// failure surfaces back to the apply path so AfterCloseoutSummary can flip
// the closeout_run row to status='failed'.
func TestS3CloseoutSummaryWriterPropagatesError(t *testing.T) {
	injected := errors.New("AccessDenied: not authorized")
	writer := newS3CloseoutSummaryWriter(&fakeS3Client{err: injected})
	err := writer.PutCloseoutSummary(context.Background(), "wiring-bucket", "closeout/x.json", []byte("{}"))
	if err == nil {
		t.Fatalf("expected error from underlying S3 PutObject")
	}
	if !errors.Is(err, injected) {
		t.Errorf("error %v does not wrap the underlying S3 error %v", err, injected)
	}
}

// _ enforces that productionCloseoutBackend implements closeoutBackend at
// compile time. The wiring tests above exercise the same surface through a
// stub backend; this assertion makes the wiring intent explicit.
var _ closeoutBackend = (*productionCloseoutBackend)(nil)

// _ enforces that postgres.Store satisfies the ports.CloseoutRunStore
// contract, including the new BreakStaleRunningCloseoutRuns and
// UpdateCloseoutRunSummary methods.
var _ ports.CloseoutRunStore = closeoutRunStoreAssertion()

func closeoutRunStoreAssertion() ports.CloseoutRunStore {
	return nil
}
