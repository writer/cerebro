package app

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/dspm"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/notifications"
	"github.com/writer/cerebro/internal/remediation"
	"github.com/writer/cerebro/internal/testutil"
	"github.com/writer/cerebro/internal/ticketing"
	"github.com/writer/cerebro/internal/webhooks"
)

func TestScanAndPersistDSPMFindings_PersistsAndRemediates(t *testing.T) {
	logger := testutil.Logger()
	findingStore := findings.NewStore()
	remediationEngine := remediation.NewEngine(logger)
	app := &App{
		Logger:        logger,
		Findings:      findingStore,
		Remediation:   remediationEngine,
		Notifications: notifications.NewManager(),
		Ticketing:     ticketing.NewService(),
		Webhooks:      webhooks.NewServiceForTesting(),
	}
	app.RemediationExecutor = remediation.NewExecutor(app.Remediation, app.Ticketing, app.Notifications, app.Findings, app.Webhooks)

	err := app.Remediation.AddRule(remediation.Rule{
		ID:          "test-dspm-resolve",
		Name:        "Resolve DSPM finding",
		Description: "test",
		Enabled:     true,
		Trigger: remediation.Trigger{
			Type:     remediation.TriggerFindingCreated,
			PolicyID: dspm.PolicyIDRestrictedDataUnencrypted,
		},
		Actions: []remediation.Action{
			{Type: remediation.ActionResolveFinding},
		},
	})
	if err != nil {
		t.Fatalf("add remediation rule: %v", err)
	}

	fetcher := &stubDSPMFetcher{
		samples: []dspm.DataSample{
			{ObjectKey: "sample-1", Data: []byte("4111-1111-1111-1111")},
		},
	}
	app.DSPM = dspm.NewScanner(fetcher, logger, dspm.DefaultScannerConfig())

	assets := []map[string]interface{}{
		{
			"_cq_id":          "bucket-1",
			"_cq_source_name": "aws",
			"name":            "customer-card-bucket",
			"arn":             "arn:aws:s3:::customer-card-bucket",
			"is_public":       true,
			"is_encrypted":    false,
			"region":          "us-west-2",
		},
	}

	count := app.scanAndPersistDSPMFindings(context.Background(), "aws_s3_buckets", assets)
	if count < 3 {
		t.Fatalf("expected at least 3 DSPM findings persisted, got %d", count)
	}
	if fetcher.fetchCalls != 1 {
		t.Fatalf("expected one DSPM fetch call, got %d", fetcher.fetchCalls)
	}

	restricted := app.Findings.List(findings.FindingFilter{PolicyID: dspm.PolicyIDRestrictedDataUnencrypted})
	if len(restricted) == 0 {
		t.Fatal("expected restricted-unencrypted DSPM finding")
	}
	if restricted[0].Status != "RESOLVED" {
		t.Fatalf("expected restricted-unencrypted finding to be auto-resolved by remediation rule, got %s", restricted[0].Status)
	}
}

func TestScanAndPersistDSPMFindings_SkipsNonScannableTables(t *testing.T) {
	fetcher := &stubDSPMFetcher{
		samples: []dspm.DataSample{
			{ObjectKey: "sample-1", Data: []byte("4111-1111-1111-1111")},
		},
	}

	app := &App{
		Logger:   testutil.Logger(),
		Findings: findings.NewStore(),
		DSPM:     dspm.NewScanner(fetcher, testutil.Logger(), dspm.DefaultScannerConfig()),
	}

	count := app.scanAndPersistDSPMFindings(context.Background(), "aws_iam_users", []map[string]interface{}{
		{"id": "user-1", "name": "alice"},
	})
	if count != 0 {
		t.Fatalf("expected zero findings for non-DSPM table, got %d", count)
	}
	if fetcher.fetchCalls != 0 {
		t.Fatalf("expected no DSPM fetch calls for non-DSPM table, got %d", fetcher.fetchCalls)
	}
}

type stubDSPMFetcher struct {
	samples    []dspm.DataSample
	fetchCalls int
}

func (s *stubDSPMFetcher) FetchSample(_ context.Context, _ *dspm.ScanTarget, _ int64) ([]dspm.DataSample, error) {
	s.fetchCalls++
	return s.samples, nil
}

func (s *stubDSPMFetcher) ListObjects(_ context.Context, _ *dspm.ScanTarget, _ int) ([]dspm.ObjectInfo, error) {
	return nil, nil
}
