package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/writer/cerebro/internal/bootstrap"
	appconfig "github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/statestore/postgres"
)

// closeoutS3PutObjectAPI is the minimum surface of the aws-sdk-go-v2 S3 client
// required by the apply path. It is declared here so tests can substitute a
// fake S3 implementation that observes the PutObject call without touching
// real AWS endpoints.
type closeoutS3PutObjectAPI interface {
	PutObject(ctx context.Context, input *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// closeoutSTSGetCallerIdentityAPI is the minimum STS surface used by the actor
// resolver. Tests inject a fake to avoid hitting real STS endpoints.
type closeoutSTSGetCallerIdentityAPI interface {
	GetCallerIdentity(ctx context.Context, input *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// s3CloseoutSummaryWriter persists the per-run audit summary via S3 PutObject.
// The interface keeps the apply path testable without exercising real AWS.
type s3CloseoutSummaryWriter struct {
	client closeoutS3PutObjectAPI
}

func newS3CloseoutSummaryWriter(client closeoutS3PutObjectAPI) *s3CloseoutSummaryWriter {
	return &s3CloseoutSummaryWriter{client: client}
}

// ErrCloseoutS3ClientMissing indicates the apply path was invoked without a
// configured S3 client (production wiring did not load).
var ErrCloseoutS3ClientMissing = errors.New("closeout: s3 client is not configured")

// ErrCloseoutS3BucketMissing indicates that the apply path was invoked with
// an empty bucket name.
var ErrCloseoutS3BucketMissing = errors.New("closeout: s3 bucket is required")

// ErrCloseoutS3KeyMissing indicates that the apply path was invoked with an
// empty object key.
var ErrCloseoutS3KeyMissing = errors.New("closeout: s3 key is required")

func (w *s3CloseoutSummaryWriter) PutCloseoutSummary(ctx context.Context, bucket, key string, body []byte) error {
	if w == nil || w.client == nil {
		return ErrCloseoutS3ClientMissing
	}
	bucket = strings.TrimSpace(bucket)
	key = strings.TrimSpace(key)
	if bucket == "" {
		return ErrCloseoutS3BucketMissing
	}
	if key == "" {
		return ErrCloseoutS3KeyMissing
	}
	_, err := w.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return fmt.Errorf("s3 PutObject s3://%s/%s: %w", bucket, key, err)
	}
	return nil
}

// newSTSCloseoutLookup wraps an STS client into the actor-resolution callback.
// A non-nil STS error is swallowed (the function returns an empty identity so
// the actor fallback chain can proceed to $USER or "unknown"), matching the
// contract documented on closeoutSTSLookup.
func newSTSCloseoutLookup(client closeoutSTSGetCallerIdentityAPI) closeoutSTSLookup {
	return func(ctx context.Context) (closeoutSTSIdentity, error) {
		if client == nil {
			return closeoutSTSIdentity{}, nil
		}
		out, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			return closeoutSTSIdentity{}, nil //nolint:nilerr // STS lookup failures intentionally fall back to local actor resolution.
		}
		arn := strings.TrimSpace(aws.ToString(out.Arn))
		return closeoutSTSIdentity{Principal: arn, RoleARN: arn}, nil
	}
}

// productionCloseoutBackend bridges postgres.Store, findings.Service, and the
// closeout_run lifecycle hooks. It is the live counterpart of the
// notWiredCloseoutBackend scaffold and is exercised by defaultCloseoutEnv.
type productionCloseoutBackend struct {
	store   *postgres.Store
	service *findings.Service
}

func newProductionCloseoutBackend(store *postgres.Store, service *findings.Service) *productionCloseoutBackend {
	return &productionCloseoutBackend{store: store, service: service}
}

func (b *productionCloseoutBackend) SupportsTombstones(ctx context.Context) (bool, error) {
	if b == nil || b.store == nil {
		return false, errors.New("closeout: postgres store is not configured")
	}
	return b.store.SupportsTombstones(ctx)
}

func (b *productionCloseoutBackend) Closeout(ctx context.Context, req findings.CloseoutRequest) (*findings.CloseoutResult, error) {
	if b == nil || b.service == nil {
		return nil, errors.New("closeout: findings service is not configured")
	}
	return b.service.TombstoneFindingsBulk(ctx, req)
}

func (b *productionCloseoutBackend) AfterCloseoutSummary(ctx context.Context, runID, summaryKey string, summaryErr error) error {
	if b == nil || b.store == nil {
		return errors.New("closeout: postgres store is not configured")
	}
	return b.store.UpdateCloseoutRunSummary(ctx, runID, summaryKey, summaryErr)
}

// closeoutProductionDeps groups every external boundary required by
// defaultCloseoutEnv. Production wires them via OpenCloseoutProductionDeps;
// the wiring integration test calls newClosingCloseoutEnvFromDeps directly
// with a fake S3 client + fake STS client.
type closeoutProductionDeps struct {
	Store     *postgres.Store
	Findings  *findings.Service
	S3Client  closeoutS3PutObjectAPI
	STSClient closeoutSTSGetCallerIdentityAPI
	Cleanup   func()
}

// openCloseoutProductionDeps assembles the live wiring around bootstrap +
// AWS SDK v2. It is split out from defaultCloseoutEnv so the wiring layer can
// be exercised by an integration-style test that swaps the S3/STS clients
// without re-implementing the dep graph.
func openCloseoutProductionDeps(ctx context.Context) (*closeoutProductionDeps, error) {
	cfg, err := appconfig.Load()
	if err != nil {
		return nil, fmt.Errorf("closeout: load config: %w", err)
	}
	closeTelemetry, err := configureOpenTelemetry(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("closeout: configure telemetry: %w", err)
	}
	deps, closeDeps, err := bootstrap.OpenDependencies(ctx, cfg)
	if err != nil {
		shutdownTelemetry(ctx, closeTelemetry, cfg.ShutdownTimeout)
		return nil, fmt.Errorf("closeout: open dependencies: %w", err)
	}
	store, ok := deps.StateStore.(*postgres.Store)
	if !ok || store == nil {
		_ = closeDeps()
		shutdownTelemetry(ctx, closeTelemetry, cfg.ShutdownTimeout)
		return nil, errors.New("closeout: postgres state store is required")
	}
	service := buildCloseoutFindingService(store, deps.AppendLog, deps.GraphStore)

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		_ = closeDeps()
		shutdownTelemetry(ctx, closeTelemetry, cfg.ShutdownTimeout)
		return nil, fmt.Errorf("closeout: load aws config: %w", err)
	}
	return &closeoutProductionDeps{
		Store:     store,
		Findings:  service,
		S3Client:  s3.NewFromConfig(awsCfg),
		STSClient: sts.NewFromConfig(awsCfg),
		Cleanup: func() {
			if cerr := closeDeps(); cerr != nil {
				log.Printf("close dependencies: %v", cerr)
			}
			shutdownTelemetry(ctx, closeTelemetry, cfg.ShutdownTimeout)
		},
	}, nil
}

// buildCloseoutFindingService composes the findings.Service for the closeout
// CLI. It wires the runtime/event/finding/run/evidence/claim ports that
// TombstoneFindingsBulk needs plus the closeout_run + tombstone audit stores.
func buildCloseoutFindingService(store *postgres.Store, appendLog ports.AppendLog, graphStore ports.GraphStore) *findings.Service {
	var (
		runtimeStore ports.SourceRuntimeStore = store
		findingStore ports.FindingStore       = store
		runStore     ports.FindingEvaluationRunStore
		evidence     ports.FindingEvidenceStore
		claims       ports.ClaimStore
		replayer     ports.EventReplayer
	)
	if rs, ok := any(store).(ports.FindingEvaluationRunStore); ok {
		runStore = rs
	}
	if es, ok := any(store).(ports.FindingEvidenceStore); ok {
		evidence = es
	}
	if cs, ok := any(store).(ports.ClaimStore); ok {
		claims = cs
	}
	if rp, ok := any(appendLog).(ports.EventReplayer); ok {
		replayer = rp
	}
	service := findings.New(runtimeStore, replayer, findingStore, runStore, evidence, claims)
	service = service.
		WithAppendLog(appendLog).
		WithGraphStore(sourceProjectionGraphStore(graphStore)).
		WithCloseoutStore(store).
		WithFindingTombstoneEventStore(store)
	return service
}

// closeoutEnvFromDeps wraps the production dependency graph into the closeoutEnv
// surface consumed by runCloseoutWithEnv. The wiring integration test calls
// this helper directly with a fake S3 client + fake STS client, while
// defaultCloseoutEnv calls it with live aws-sdk-go-v2 clients.
func closeoutEnvFromDeps(deps *closeoutProductionDeps) *closeoutEnv {
	if deps == nil {
		return nil
	}
	backend := newProductionCloseoutBackend(deps.Store, deps.Findings)
	summary := newS3CloseoutSummaryWriter(deps.S3Client)
	lookup := newSTSCloseoutLookup(deps.STSClient)
	return &closeoutEnv{
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
		Getenv:    os.Getenv,
		Now:       func() time.Time { return time.Now().UTC() },
		NewRunID:  newCloseoutRunID,
		Backend:   backend,
		Summary:   summary,
		LookupSTS: lookup,
	}
}
